//! Load test: many clients against one server at the same time.
//!
//! Each client runs on its own thread with its own key, login and database, and uses SQLite3 Multiple Ciphers on top
//! of the VFS. All clients connect first and then start at the same time. After the run, each client opens its
//! database with a new VFS and checks that the server has exactly the commits it acknowledged. This detects lost
//! commits, which a throughput measurement alone would not.
//!
//! Two modes:
//!
//! - `--rate 0` (default): each client commits as fast as it can. Measures the server's maximum throughput and the
//!   latency at saturation.
//! - `--rate r`: each client commits r times per second, e.g. `--rate 0.5` is one commit every two seconds. Latency is
//!   measured from the time a commit was due, so time spent waiting behind a slow server counts as latency.

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use rusqlite::Connection;
use sqlite_remote_vfs::{Config, RemoteVfs};

use crate::rng::Rng;
use crate::workload;

const DB: &str = "load";
/// Size of the keystore row in bytes. Roughly the group state of an end-to-end encrypted group with five to ten
/// members.
const KEYSTORE_STATE_BYTES: i64 = 8_000;
/// Number of conversations. Messages are spread over them, so index inserts do not all go to the end of the index.
const CONVERSATIONS: u64 = 20;

/// What a client writes in each commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Overwrites one row of 8,000 bytes. Models the group state in the keystore of an end-to-end encrypted
    /// messenger, which changes with every incoming message.
    Keystore,
    /// Inserts one row with a random primary key into an indexed table. Models a growing message history.
    Message,
}

impl std::str::FromStr for Kind {
    type Err = String;

    fn from_str(value: &str) -> Result<Kind, String> {
        match value {
            "keystore" => Ok(Kind::Keystore),
            "message" => Ok(Kind::Message),
            other => Err(format!("--kind must be keystore or message, got {other}")),
        }
    }
}

/// Parameters of a load run.
pub struct Plan {
    pub url: String,
    pub clients: usize,
    pub seconds: u64,
    /// Commits per second per client. 0 means as fast as possible.
    pub rate: f64,
    pub kind: Kind,
    pub seed: u64,
}

/// Result of one client.
struct Outcome {
    /// Time from the client's start until its database was open, including the login.
    ready_in: Duration,
    latencies: Vec<Duration>,
    acknowledged: u64,
    /// Error of the first failed commit, or of connecting. The client stops at the first failure.
    failed: Option<String>,
    /// Whether the client logged in and opened its database. A client that did not has written nothing, so its
    /// failure does not count as data loss.
    connected: bool,
    /// Result of checking, with a new VFS, that the server has exactly the acknowledged commits.
    verified: Result<(), String>,
}

pub fn run(plan: &Plan) -> Result<(), String> {
    let pace = if plan.rate > 0.0 {
        format!("{} commits per second per client", plan.rate)
    } else {
        "as fast as possible".into()
    };
    eprintln!(
        "load: {} clients, {:?}, {pace}, {} s, connecting",
        plan.clients, plan.kind, plan.seconds
    );

    // All clients connect and open their database first, then start together at the barrier. The main thread also
    // waits at the barrier, to know when the run starts.
    let start = Arc::new(Barrier::new(plan.clients + 1));
    let mut handles = Vec::with_capacity(plan.clients);
    for index in 0..plan.clients {
        let url = plan.url.clone();
        let start = Arc::clone(&start);
        let (seconds, rate, kind) = (plan.seconds, plan.rate, plan.kind);
        let seed = plan.seed.wrapping_mul(1_000_003).wrapping_add(index as u64);
        let handle = thread::Builder::new()
            .name(format!("load-{index}"))
            .spawn(move || client(&url, seconds, rate, kind, seed, &start))
            .map_err(|err| format!("starting client {index}: {err}"))?;
        handles.push(handle);
    }

    start.wait();
    let began = Instant::now();
    eprintln!("load: all connected, running");

    let outcomes: Vec<Outcome> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap_or_else(|_| panicked()))
        .collect();
    let wall = began.elapsed();

    report(plan, &outcomes, wall);

    // A client that never connected wrote nothing and cannot have lost data. It is reported separately, so an
    // unreachable server is not reported as a server that loses commits.
    let never = outcomes.iter().filter(|o| !o.connected).count();
    let lost = outcomes.iter().filter(|o| o.connected && o.verified.is_err()).count();
    for outcome in outcomes.iter().filter(|o| o.connected && o.verified.is_err()).take(5) {
        eprintln!("  lost: {}", outcome.verified.as_ref().unwrap_err());
    }
    if let Some(outcome) = outcomes.iter().find(|o| !o.connected) {
        eprintln!("  never connected: {}", outcome.failed.as_deref().unwrap_or("?"));
    }
    match (never, lost) {
        (0, 0) => Ok(()),
        (never, 0) => Err(format!("{never} of {} clients could not connect", plan.clients)),
        (_, lost) => Err(format!(
            "{lost} of {} clients found a different number of commits on the server than acknowledged",
            plan.clients
        )),
    }
}

fn panicked() -> Outcome {
    Outcome {
        ready_in: Duration::ZERO,
        latencies: Vec::new(),
        acknowledged: 0,
        failed: Some("the client thread panicked".into()),
        // The number of acknowledged commits is unknown, so a panic counts as possible data loss.
        connected: true,
        verified: Err("the client thread panicked".into()),
    }
}

/// Runs one client: connect, wait at the barrier, commit until the time is up, then check the server's data.
fn client(url: &str, seconds: u64, rate: f64, kind: Kind, seed: u64, start: &Barrier) -> Outcome {
    let key = crate::key::new();
    let began = Instant::now();
    let opened = open(url, &key).and_then(|(vfs, conn)| {
        create(&conn, kind)?;
        Ok((vfs, conn))
    });
    let ready_in = began.elapsed();

    // Wait at the barrier even after a failure. Otherwise the other clients would wait forever.
    start.wait();
    let (vfs, conn) = match opened {
        Ok(opened) => opened,
        Err(err) => {
            return Outcome {
                ready_in,
                latencies: Vec::new(),
                acknowledged: 0,
                failed: Some(format!("connecting: {err}")),
                connected: false,
                verified: Err(format!("never connected: {err}")),
            };
        }
    };

    let mut rng = Rng::new(seed);
    let from = Instant::now();
    let until = from + Duration::from_secs(seconds);
    let mut latencies = Vec::new();
    let mut acknowledged = 0u64;
    let mut failed = None;

    if rate > 0.0 {
        // Due times are fixed in advance. Each client has a random phase, so the clients do not all commit at the
        // same moment. If a commit starts late because the previous one took long, the delay counts as latency.
        let interval = Duration::from_secs_f64(1.0 / rate);
        let phase = interval.mul_f64(rng.between(0, 1_000_000) as f64 / 1_000_000.0);
        loop {
            let due = from + phase + interval.mul_f64(acknowledged as f64);
            if due >= until {
                // No further commit is due. The client stays connected until the end of the run, like an idle user
                // with the app open. Otherwise a run with a low rate would not measure the cost of idle clients.
                if let Some(rest) = until.checked_duration_since(Instant::now()) {
                    thread::sleep(rest);
                }
                break;
            }
            if let Some(wait) = due.checked_duration_since(Instant::now()) {
                thread::sleep(wait);
            }
            if let Err(err) = commit(&conn, kind, acknowledged + 1, &mut rng) {
                failed = Some(err);
                break;
            }
            latencies.push(due.elapsed());
            acknowledged += 1;
        }
    } else {
        while Instant::now() < until {
            let at = Instant::now();
            if let Err(err) = commit(&conn, kind, acknowledged + 1, &mut rng) {
                failed = Some(err);
                break;
            }
            latencies.push(at.elapsed());
            acknowledged += 1;
        }
    }

    // Check the server's data with a new VFS that has nothing in memory.
    drop(conn);
    drop(vfs);
    let verified = verify(url, &key, kind, acknowledged, failed.is_some());

    Outcome {
        ready_in,
        latencies,
        acknowledged,
        failed,
        connected: true,
        verified,
    }
}

fn open(url: &str, key: &str) -> Result<(RemoteVfs, Connection), String> {
    let mut config = Config::new(url, crate::key::signer(key)?);
    config.takeover = true;
    // Many simultaneous logins can be slow. A long timeout lets the run report slow logins instead of failing.
    config.timeout = Duration::from_secs(30);
    config.reconnect_timeout = Duration::from_secs(30);
    let vfs = crate::register_vfs(config)?;
    let conn = workload::open(&vfs, DB).map_err(|err| err.to_string())?;
    Ok((vfs, conn))
}

fn create(conn: &Connection, kind: Kind) -> Result<(), String> {
    let schema = match kind {
        Kind::Keystore => "CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY, n INTEGER NOT NULL, blob BLOB)",
        Kind::Message => {
            "CREATE TABLE IF NOT EXISTS msg (id TEXT PRIMARY KEY, conv INTEGER NOT NULL, t INTEGER NOT NULL, body TEXT);
             CREATE INDEX IF NOT EXISTS msg_by_conv ON msg (conv, t);"
        }
    };
    conn.execute_batch(schema).map_err(|err| err.to_string())
}

/// Runs the `n`th commit of this client.
fn commit(conn: &Connection, kind: Kind, n: u64, rng: &mut Rng) -> Result<(), String> {
    match kind {
        Kind::Keystore => conn
            .execute(
                "INSERT INTO state (id, n, blob) VALUES (1, ?1, randomblob(?2))
                 ON CONFLICT (id) DO UPDATE SET n = excluded.n, blob = excluded.blob",
                (n as i64, KEYSTORE_STATE_BYTES),
            )
            .map(|_| ())
            .map_err(|err| format!("commit {n}: {err}")),
        Kind::Message => {
            // Random primary key, like real message ids. New rows are spread over the whole table.
            let id = format!("{:016x}{:016x}", rng.next(), rng.next());
            conn.execute(
                "INSERT INTO msg (id, conv, t, body) VALUES (?1, ?2, ?3, ?4)",
                (id, (n % CONVERSATIONS) as i64, n as i64, body(n)),
            )
            .map(|_| ())
            .map_err(|err| format!("commit {n}: {err}"))
        }
    }
}

fn body(n: u64) -> String {
    let words = [
        "hello", "thanks", "tomorrow", "meeting", "please", "update", "photo", "later",
    ];
    (0..30)
        .map(|i| words[((n + i) % words.len() as u64) as usize])
        .collect::<Vec<_>>()
        .join(" ")
}

/// Opens the database with a new VFS and checks that the server has exactly the acknowledged commits.
///
/// A failed commit may or may not have been applied. After a failure the server may therefore have one commit more
/// than acknowledged, but never fewer.
fn verify(url: &str, key: &str, kind: Kind, acknowledged: u64, stopped_on_failure: bool) -> Result<(), String> {
    let (vfs, conn) = open(url, key).map_err(|err| format!("reopening to check: {err}"))?;
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|err| format!("integrity check: {err}"))?;
    if integrity != "ok" {
        return Err(format!("integrity check failed: {integrity}"));
    }
    let found: u64 = match kind {
        Kind::Keystore => conn.query_row("SELECT coalesce(max(n), 0) FROM state", [], |row| row.get::<_, i64>(0)),
        Kind::Message => conn.query_row("SELECT count(*) FROM msg", [], |row| row.get::<_, i64>(0)),
    }
    .map_err(|err| format!("counting: {err}"))? as u64;
    drop(conn);
    drop(vfs);

    let fine = found == acknowledged || (stopped_on_failure && found == acknowledged + 1);
    if fine {
        Ok(())
    } else {
        Err(format!("acknowledged {acknowledged}, the server has {found}"))
    }
}

fn report(plan: &Plan, outcomes: &[Outcome], wall: Duration) {
    let mut latencies: Vec<Duration> = outcomes.iter().flat_map(|o| o.latencies.iter().copied()).collect();
    latencies.sort_unstable();
    let mut ready: Vec<Duration> = outcomes.iter().map(|o| o.ready_in).collect();
    ready.sort_unstable();
    let commits: u64 = outcomes.iter().map(|o| o.acknowledged).sum();
    let failed = outcomes.iter().filter(|o| o.failed.is_some()).count();
    let verified = outcomes.iter().filter(|o| o.verified.is_ok()).count();
    let at = |times: &[Duration], q: f64| -> Duration {
        let last = times.len().saturating_sub(1);
        times
            .get(((times.len() as f64 * q) as usize).min(last))
            .copied()
            .unwrap_or_default()
    };
    let ms = |d: Duration| format!("{:.1}", d.as_secs_f64() * 1000.0);
    let rate = if plan.rate > 0.0 {
        format!("{}/s", plan.rate)
    } else {
        "max".into()
    };

    println!(
        "| {} | {:?} | {rate} | {commits} | {:.0} | {} | {} | {} | {} | {} | {} | {} | {failed} | {verified}/{} |",
        plan.clients,
        plan.kind,
        commits as f64 / plan.seconds as f64,
        ms(at(&latencies, 0.50)),
        ms(at(&latencies, 0.90)),
        ms(at(&latencies, 0.99)),
        ms(at(&latencies, 0.999)),
        ms(latencies.last().copied().unwrap_or_default()),
        ms(at(&ready, 0.50)),
        ms(at(&ready, 0.99)),
        plan.clients,
    );
    for outcome in outcomes.iter().filter(|o| o.failed.is_some()).take(3) {
        eprintln!("  failed: {}", outcome.failed.as_ref().unwrap());
    }
    eprintln!(
        "load: {:.1} s from start until the last client finished, including checks",
        wall.as_secs_f64()
    );
}
