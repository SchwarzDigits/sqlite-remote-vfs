//! Test tool for sqlite-remote-vfs. Runs against a server that is already running.
//!
//! ```text
//! sqlite-remote-harness crash    --url … [--iterations 30] [--seed 1] [--min-ms 50] [--max-ms 800] [--local path]
//! sqlite-remote-harness faults   --url … [--transactions 1500] [--seed 1]
//! sqlite-remote-harness load     --url … [--clients 10] [--seconds 20] [--rate 0] [--kind keystore|message] [--seed 1]
//! sqlite-remote-harness measure  --url … [--transactions 300] [--delays-ms 0,25,50] [--sizes-mb 1,10,50]
//! sqlite-remote-harness proxy    --url … [--port 18190] [--delay-ms 25] [--mbit 20]
//! sqlite-remote-harness workload --url … --key … [--db messages] [--local path]
//! ```
//!
//! `--url` is the server's WebSocket URL, e.g. `ws://localhost:8080/v1/ws`.
//!
//! - `crash` runs `workload` in a child process and kills it with SIGKILL after a random delay. It then opens the
//!   database and checks that every acknowledged transaction is on the server, that at most the one in flight was
//!   applied in addition, and that no transaction was applied partially.
//! - `faults` runs the workload through a proxy that cuts connections in the middle of frames and delays answers
//!   beyond the client's timeout. It runs the same checks after every failure and at the end.
//! - `load` runs many clients at once and then checks each client's data. See `load.rs`.
//! - `measure` runs the measurements and prints them as Markdown tables. See `measure.rs`.
//! - `proxy` adds a fixed delay and an optional bandwidth limit in front of the server, for measuring other clients,
//!   e.g. a browser.
//! - `workload` is the child process of `crash`. It commits transactions until it is killed.

mod key;
mod load;
mod measure;
mod proxy;
mod rng;
mod workload;

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use rusqlite::Connection;
use sqlite_remote_vfs::{Config, RemoteVfs, Stats};

use crate::measure::host_of;
use crate::proxy::{Policy, Proxy};
use crate::rng::Rng;

const DB: &str = "messages";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        eprintln!(
            "usage: sqlite-remote-harness crash|faults|load|measure|proxy|workload --url ws://host:port/v1/ws [options]"
        );
        return ExitCode::from(2);
    };
    let result = Options::parse(args).and_then(|options| match command.as_str() {
        "crash" => {
            options.only(&["url", "iterations", "seed", "min-ms", "max-ms", "local"])?;
            crash(&options)
        }
        "faults" => {
            options.only(&["url", "transactions", "seed"])?;
            faults(&options)
        }
        "proxy" => {
            options.only(&["url", "port", "delay-ms", "mbit"])?;
            proxy_command(&options)
        }
        "measure" => {
            options.only(&["url", "transactions", "delays-ms", "sizes-mb"])?;
            measure(&options)
        }
        "load" => {
            options.only(&["url", "clients", "seconds", "rate", "kind", "seed"])?;
            load::run(&load::Plan {
                url: options.get("url")?.to_string(),
                clients: options.get_or("clients", 10)?,
                seconds: options.get_or("seconds", 20)?,
                rate: options.get_or("rate", 0.0)?,
                kind: options.get_or("kind", load::Kind::Keystore)?,
                seed: options.get_or("seed", 1)?,
            })
        }
        "workload" => {
            options.only(&["url", "key", "db", "local"])?;
            workload_process(&options)
        }
        other => Err(format!("unknown command {other}")),
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

struct Options(HashMap<String, String>);

impl Options {
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut options = HashMap::new();
        while let Some(name) = args.next() {
            let name = name
                .strip_prefix("--")
                .ok_or_else(|| format!("expected an option, got {name}"))?
                .to_string();
            let value = args.next().ok_or_else(|| format!("--{name} needs a value"))?;
            options.insert(name, value);
        }
        Ok(Options(options))
    }

    /// Rejects options not in `known`. Without this check, a mistyped option would be ignored and its default used.
    fn only(&self, known: &[&str]) -> Result<(), String> {
        match self.0.keys().find(|name| !known.contains(&name.as_str())) {
            Some(name) => Err(format!("--{name} is not an option of this command")),
            None => Ok(()),
        }
    }

    fn get(&self, name: &str) -> Result<&str, String> {
        self.0
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| format!("--{name} is required"))
    }

    fn get_or<T: std::str::FromStr>(&self, name: &str, default: T) -> Result<T, String> {
        match self.0.get(name) {
            Some(value) => value.parse().map_err(|_| format!("--{name}: invalid value {value}")),
            None => Ok(default),
        }
    }
}

fn register(url: &str, key: &str, timeout: Duration) -> Result<RemoteVfs, String> {
    register_with(url, key, timeout, None)
}

fn register_with(url: &str, key: &str, timeout: Duration, local: Option<&str>) -> Result<RemoteVfs, String> {
    let mut config = Config::new(url, key::signer(key)?);
    if let Some(path) = local {
        config.local = sqlite_remote_vfs::Local::File(path.into());
    }
    // A killed or failed previous process may still hold the lease.
    config.takeover = true;
    config.timeout = timeout;
    config.reconnect_timeout = Duration::from_secs(20);
    register_vfs(config)
}

/// Registers a VFS under a name that is unique within this process.
fn register_vfs(config: Config) -> Result<RemoteVfs, String> {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let name = format!(
        "harness-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    RemoteVfs::register(&name, config).map_err(|err| err.to_string())
}

/// Opens the database with a new VFS, checks it and returns the number of the last transaction.
fn verify_on_server(url: &str, key: &str, local: Option<&str>) -> Result<u64, String> {
    let vfs = register_with(url, key, Duration::from_secs(10), local)?;
    let conn = workload::open(&vfs, DB).map_err(|err| format!("opening for the check: {err}"))?;
    workload::verify(&conn)
}

/// Starts a proxy with a fixed delay and an optional bandwidth limit in front of the server and runs until killed.
/// Used to measure clients outside this program, e.g. a browser.
fn proxy_command(options: &Options) -> Result<(), String> {
    let url = options.get("url")?;
    let port: u16 = options.get_or("port", 0)?;
    let delay: u64 = options.get_or("delay-ms", 25)?;
    let mbit: f64 = options.get_or("mbit", 0.0)?;
    let mut policy = Policy::delay_only(Duration::from_millis(delay));
    if mbit > 0.0 {
        policy.rate = Some((mbit * 1_000_000.0 / 8.0) as u64);
    }
    let proxy = Proxy::start_on(&host_of(url)?, port, policy, 1).map_err(|err| err.to_string())?;
    let width = if mbit > 0.0 {
        format!(", {mbit} Mbit/s")
    } else {
        String::new()
    };
    println!(
        "proxy with {} ms round trip{width} to {url}: {}",
        delay * 2,
        proxy.url()
    );
    println!("press Ctrl-C to stop");
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

/// Runs the measurements and prints them as Markdown tables.
fn measure(options: &Options) -> Result<(), String> {
    let settings = measure::Settings {
        url: options.get("url")?.to_string(),
        transactions: options.get_or("transactions", 300)?,
        delays_ms: numbers(options, "delays-ms", &[0, 25, 50])?,
        sizes_mb: numbers(options, "sizes-mb", &[1, 10, 50])?,
    };
    measure::run(&settings)
}

/// Reads a comma-separated list of numbers, e.g. `--delays-ms 0,25`.
fn numbers(options: &Options, name: &str, default: &[u64]) -> Result<Vec<u64>, String> {
    let Some(value) = options.0.get(name) else {
        return Ok(default.to_vec());
    };
    value
        .split(',')
        .map(|part| {
            part.trim()
                .parse()
                .map_err(|_| format!("--{name}: invalid value {part}"))
        })
        .collect()
}

/// Child process of the crash test. Commits transactions until it is killed and prints `committed k` to stdout after
/// each commit SQLite reported as done.
fn workload_process(options: &Options) -> Result<(), String> {
    let vfs = register_with(
        options.get("url")?,
        options.get("key")?,
        Duration::from_secs(10),
        options.0.get("local").map(String::as_str),
    )?;
    let db = options.get_or("db", DB.to_string())?;
    let conn = workload::open(&vfs, &db).map_err(|err| err.to_string())?;
    workload::create_schema(&conn).map_err(|err| err.to_string())?;
    let mut k = workload::last_txid(&conn).map_err(|err| err.to_string())? + 1;
    let mut out = io::stdout().lock();
    loop {
        workload::transaction(&conn, k).map_err(|err| format!("transaction {k}: {err}"))?;
        writeln!(out, "committed {k}")
            .and_then(|()| out.flush())
            .map_err(|err| err.to_string())?;
        k += 1;
    }
}

fn crash(options: &Options) -> Result<(), String> {
    let url = options.get("url")?;
    let local = options.0.get("local").cloned();
    let iterations: u64 = options.get_or("iterations", 30)?;
    let seed: u64 = options.get_or("seed", 1)?;
    let min_ms: u64 = options.get_or("min-ms", 50)?;
    let max_ms: u64 = options.get_or("max-ms", 800)?;
    let key = key::new();
    let exe = std::env::current_exe().map_err(|err| err.to_string())?;
    let mut rng = Rng::new(seed);
    let mut on_server = 0u64;
    println!(
        "crash test: {iterations} kills, seed {seed}, subject {}",
        key::describe(&key)
    );

    for iteration in 1..=iterations {
        let mut child = Command::new(&exe)
            .args(["workload", "--url", url, "--key", &key])
            .args(local.iter().flat_map(|path| ["--local", path.as_str()]))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| err.to_string())?;
        let stdout = child.stdout.take().expect("piped stdout");
        let acknowledged_by_child = thread::spawn(move || {
            BufReader::new(stdout)
                .lines()
                .map_while(Result::ok)
                .filter_map(|line| line.strip_prefix("committed ").and_then(|k| k.parse::<u64>().ok()))
                .max()
        });

        let wait = rng.between(min_ms, max_ms);
        thread::sleep(Duration::from_millis(wait));
        let _ = child.kill();
        let status = child.wait().map_err(|err| err.to_string())?;
        let last = acknowledged_by_child.join().expect("reader thread");
        if status.code().is_some() {
            let mut stderr = String::new();
            let _ = child.stderr.take().expect("piped stderr").read_to_string(&mut stderr);
            return Err(format!("the workload process exited on its own ({status}): {stderr}"));
        }

        let acknowledged = last.unwrap_or(0).max(on_server);
        let found =
            verify_on_server(url, &key, local.as_deref()).map_err(|err| format!("iteration {iteration}: {err}"))?;
        if found < acknowledged {
            return Err(format!(
                "iteration {iteration}: transaction {acknowledged} was acknowledged, the server has only {found}"
            ));
        }
        if found > acknowledged + 1 {
            return Err(format!(
                "iteration {iteration}: the server has {found}, more than acknowledged ({acknowledged}) plus the one in flight"
            ));
        }
        let in_flight = if found == acknowledged + 1 {
            " (+1 in flight)"
        } else {
            ""
        };
        println!(
            "iteration {iteration:>3}: killed after {wait:>4} ms, {:>4} acknowledged in this run, {found:>6} on the server{in_flight}",
            last.map_or(0, |last| last.saturating_sub(on_server))
        );
        on_server = found;
    }
    println!(
        "crash test passed: {iterations} kills, {on_server} transactions on the server, none lost, \
         none partially applied"
    );
    Ok(())
}

fn faults(options: &Options) -> Result<(), String> {
    let url = options.get("url")?;
    let transactions: u64 = options.get_or("transactions", 1500)?;
    let seed: u64 = options.get_or("seed", 1)?;
    let target = url
        .strip_prefix("ws://")
        .and_then(|rest| rest.split('/').next())
        .ok_or_else(|| format!("{url}: expected ws://host:port/…"))?;
    let proxy = Proxy::start(
        target,
        Policy {
            early_cut_probability: 0.7,
            early_cut: (4 * 1024, 256 * 1024),
            late_cut: (256 * 1024, 8 * 1024 * 1024),
            stall_probability: 0.3,
            stall_after: (1, 512),
            stall: Duration::from_millis(1500),
            delay: Duration::ZERO,
            rate: None,
        },
        seed,
    )
    .map_err(|err| err.to_string())?;
    let key = key::new();
    // Shorter than the proxy's stall, so the client treats a delayed answer as lost.
    let timeout = Duration::from_millis(500);
    println!(
        "fault test: {transactions} transactions through a faulty proxy, seed {seed}, subject {}",
        key::describe(&key)
    );

    let started = Instant::now();
    let mut totals = Stats::default();
    let (mut vfs, mut conn) = reopen(&proxy.url(), &key, timeout, &mut totals)?;
    let mut acknowledged = 0u64;
    let mut failures = 0u64;
    let mut k = 1u64;
    while k <= transactions {
        match workload::transaction(&conn, k) {
            Ok(()) => {
                acknowledged = k;
                k += 1;
                if acknowledged.is_multiple_of(100) {
                    let stats = vfs.stats();
                    println!(
                        "{acknowledged:>6} transactions after {:>6.1} s: {} reconnects, {} cuts, {} stalls, \
                         {} blocks per commit, longest commit {:?}",
                        started.elapsed().as_secs_f64(),
                        totals.reconnects + stats.reconnects,
                        proxy.stats.cuts.load(Ordering::Relaxed),
                        proxy.stats.stalls.load(Ordering::Relaxed),
                        stats.committed_blocks / stats.commits.max(1),
                        stats.max_commit_time,
                    );
                }
            }
            Err(err) => {
                failures += 1;
                println!("transaction {k} failed: {err}. Reopening the database.");
                drop(conn);
                add(&mut totals, vfs.stats());
                (vfs, conn) = reopen(&proxy.url(), &key, timeout, &mut totals)?;
                let found = workload::verify(&conn)?;
                if found < acknowledged || found > acknowledged + 1 {
                    return Err(format!(
                        "after transaction {k} failed: the server has {found} transactions, \
                         {acknowledged} were acknowledged"
                    ));
                }
                acknowledged = found;
                k = found + 1;
            }
        }
    }
    drop(conn);
    add(&mut totals, vfs.stats());

    let found = verify_on_server(url, &key, None)?;
    if found != acknowledged {
        return Err(format!(
            "the server has {found} transactions, {acknowledged} were acknowledged"
        ));
    }
    let stats = &proxy.stats;
    if stats.cuts.load(Ordering::Relaxed) == 0 || stats.stalls.load(Ordering::Relaxed) == 0 {
        return Err(
            "inconclusive: the proxy has to cut a connection and delay an answer at least once each. \
             Use more transactions."
                .into(),
        );
    }
    println!(
        "fault test passed in {:.1} s: {transactions} transactions, {failures} failed and were repeated after \
         reopening. Proxy: {} of {} connections cut, answers delayed on {} connections. VFS: {} reconnects, \
         {} found applied after a lost acknowledgement, {} sent again",
        started.elapsed().as_secs_f64(),
        stats.cuts.load(Ordering::Relaxed),
        stats.connections.load(Ordering::Relaxed),
        stats.stalls.load(Ordering::Relaxed),
        totals.reconnects,
        commits(totals.recovered_commits),
        commits(totals.resent_commits)
    );
    Ok(())
}

/// Formats a number of commits with the correct plural.
fn commits(n: u64) -> String {
    match n {
        1 => "1 commit".into(),
        n => format!("{n} commits"),
    }
}

/// Registers a new VFS and opens the database. Retries up to 50 times, because the proxy also breaks these attempts.
fn reopen(url: &str, key: &str, timeout: Duration, totals: &mut Stats) -> Result<(RemoteVfs, Connection), String> {
    let mut last_error = String::new();
    for _ in 0..50 {
        let vfs = match register(url, key, timeout) {
            Ok(vfs) => vfs,
            Err(err) => {
                last_error = err;
                continue;
            }
        };
        let opened = workload::open(&vfs, DB).and_then(|conn| workload::create_schema(&conn).map(|()| conn));
        match opened {
            Ok(conn) => return Ok((vfs, conn)),
            Err(err) => {
                add(totals, vfs.stats());
                last_error = err.to_string();
            }
        }
    }
    Err(format!("could not open the database through the proxy: {last_error}"))
}

fn add(totals: &mut Stats, stats: Stats) {
    totals.reconnects += stats.reconnects;
    totals.commits += stats.commits;
    totals.recovered_commits += stats.recovered_commits;
    totals.resent_commits += stats.resent_commits;
}
