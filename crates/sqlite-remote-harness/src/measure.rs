//! Measurements, printed as Markdown tables.
//!
//! Each scenario uses new keys, so it does not see databases from earlier runs and can be repeated. Times are taken
//! around the whole transaction as the application sees it, including the time the VFS waits for the server. Network
//! latency is added by the proxy, which delays every chunk in both directions, so a round trip takes twice the delay.

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use rusqlite::Connection;
use sqlite_remote_vfs::{Config, Load, RemoteVfs, Stats};

use crate::proxy::{Policy, Proxy};
use crate::workload;

/// Size of a filler row in bytes.
const FILLER_ROW_BYTES: usize = 3000;
const FILLER_ROWS_PER_TRANSACTION: usize = 512;

/// Parameters of a measurement run.
pub struct Settings {
    pub url: String,
    /// Transactions per scenario. Some scenarios use a fraction of it.
    pub transactions: u64,
    /// One-way delays to measure, in milliseconds. A round trip takes twice the delay.
    pub delays_ms: Vec<u64>,
    /// Database sizes for the preload measurement, in MB.
    pub sizes_mb: Vec<u64>,
}

/// Runs all scenarios and prints the report to stdout.
pub fn run(settings: &Settings) -> Result<(), String> {
    let mut report = String::new();
    commit_cost(settings, &mut report)?;
    local_copy(settings, &mut report)?;
    commit_cost_over_latency(settings, &mut report)?;
    preload_by_size(settings, &mut report)?;
    fetching_by_access_pattern(settings, &mut report)?;
    bulk_insert_throughput(settings, &mut report)?;
    page_sizes(settings, &mut report)?;
    print!("{report}");
    Ok(())
}

// -------------------------------------------------------------------------------------------------------------------
// The scenarios
// -------------------------------------------------------------------------------------------------------------------

/// Measures commit latency and size for a message, a read followed by a message, and a bulk insert of 512 rows.
fn commit_cost(settings: &Settings, report: &mut String) -> Result<(), String> {
    heading(report, "Commit: latency and size per transaction type");
    let mut table = Table::new(&[
        "Transaction type",
        "Transactions",
        "p50",
        "p90",
        "p99",
        "max",
        "Blocks/commit",
        "Bytes/commit",
    ]);

    for (name, kind) in [
        ("Message", Kind::Message),
        ("Message after a read", Kind::ReadThenWrite),
        ("Bulk write, 512 rows", Kind::Bulk),
    ] {
        let subject = settings.subject("commit");
        let (vfs, conn) = open_fresh(&settings.url, &subject, 4096, Load::Preload)?;
        workload::create_schema(&conn).map_err(err)?;
        create_filler(&conn)?;
        let before = vfs.stats();

        let count = match kind {
            Kind::Bulk => settings.transactions / 10,
            _ => settings.transactions,
        };
        let times = run_transactions(&conn, kind, count)?;
        let stats = delta(before, vfs.stats());
        let p = Percentiles::of(times);
        table.row(&[
            name.to_string(),
            count.to_string(),
            ms(p.p50),
            ms(p.p90),
            ms(p.p99),
            ms(p.max),
            per_commit(stats.committed_blocks, stats.commits),
            per_commit(stats.committed_bytes, stats.commits),
        ]);
    }
    table.write(report);
    Ok(())
}

/// Measures commit latency with and without a local copy, and the time to open the database again afterwards.
fn local_copy(settings: &Settings, report: &mut String) -> Result<(), String> {
    heading(report, "With and without a local copy");
    let mut table = Table::new(&["Local copy", "p50 commit", "p99 commit", "Reopen", "Fetches on reopen"]);

    for (label, with_copy) in [("no", false), ("yes", true)] {
        let subject = settings.subject("copy");
        let path = std::env::temp_dir().join(format!("{subject}.copy"));
        let _ = std::fs::remove_file(&path);
        let signer = crate::key::signer(&subject)?;
        let make = |load: Load| {
            let mut config = Config::new(&settings.url, signer.clone());
            config.load = load;
            config.takeover = true;
            if with_copy {
                config.local = sqlite_remote_vfs::Local::File(path.clone());
            }
            config
        };

        let vfs = crate::register_vfs(make(Load::Preload))?;
        let conn = workload::open(&vfs, "db").map_err(err)?;
        workload::create_schema(&conn).map_err(err)?;
        let times = run_transactions(&conn, Kind::Message, settings.transactions)?;
        let p = Percentiles::of(times);
        drop(conn);
        drop(vfs);

        let opened = Instant::now();
        let again = crate::register_vfs(make(Load::Preload))?;
        let conn = workload::open(&again, "db").map_err(err)?;
        let _ = workload::last_txid(&conn).map_err(err)?;
        let elapsed = opened.elapsed();
        let stats = again.stats();
        let _ = std::fs::remove_file(&path);

        table.row(&[
            label.to_string(),
            ms(p.p50),
            ms(p.p99),
            ms(elapsed),
            stats.fetches.to_string(),
        ]);
    }
    table.write(report);
    Ok(())
}

/// Measures the message transaction through the proxy, for each configured delay.
fn commit_cost_over_latency(settings: &Settings, report: &mut String) -> Result<(), String> {
    heading(report, "Commit over network latency, transaction type: message");
    let mut table = Table::new(&[
        "Round trip",
        "Transactions",
        "p50",
        "p90",
        "p99",
        "Waiting for server",
        "Transactions/s",
    ]);

    for &delay_ms in &settings.delays_ms {
        let proxy = Proxy::start(
            &host_of(&settings.url)?,
            Policy::delay_only(Duration::from_millis(delay_ms)),
            1,
        )
        .map_err(err)?;
        let subject = settings.subject("latency");
        let (vfs, conn) = open_fresh(&proxy.url(), &subject, 4096, Load::Preload)?;
        workload::create_schema(&conn).map_err(err)?;
        let before = vfs.stats();

        // A third of the configured count, at least 20, because every transaction costs at least one round trip.
        let count = (settings.transactions / 3).max(20);
        let started = Instant::now();
        let times = run_transactions(&conn, Kind::Message, count)?;
        let elapsed = started.elapsed();
        let stats = delta(before, vfs.stats());
        let p = Percentiles::of(times);
        table.row(&[
            format!("{} ms", delay_ms * 2),
            count.to_string(),
            ms(p.p50),
            ms(p.p90),
            ms(p.p99),
            ms(stats.commit_time / stats.commits.max(1) as u32),
            format!("{:.0}", count as f64 / elapsed.as_secs_f64()),
        ]);
    }
    table.write(report);
    Ok(())
}

/// Measures the time to open a database with `Load::Preload`, for each configured database size.
fn preload_by_size(settings: &Settings, report: &mut String) -> Result<(), String> {
    heading(report, "Preload on open, by database size");
    let mut table = Table::new(&["Size", "Blocks", "Open", "Fetches", "Blocks/s"]);

    for &size_mb in &settings.sizes_mb {
        let subject = settings.subject("preload");
        let (_vfs, conn) = open_fresh(&settings.url, &subject, 4096, Load::Preload)?;
        workload::create_schema(&conn).map_err(err)?;
        create_filler(&conn)?;
        fill_to(&conn, size_mb * 1024 * 1024)?;
        let pages = page_count(&conn)?;
        drop(conn);

        let opened = Instant::now();
        let vfs = register(&settings.url, &subject, 4096, Load::Preload)?;
        let conn = workload::open(&vfs, "db").map_err(err)?;
        let elapsed = opened.elapsed();
        let stats = vfs.stats();
        // Query the database once to confirm that it is usable after opening.
        let _ = page_count(&conn)?;

        table.row(&[
            format!("{size_mb} MB"),
            pages.to_string(),
            ms(elapsed),
            stats.fetches.to_string(),
            format!("{:.0}", pages as f64 / elapsed.as_secs_f64()),
        ]);
    }
    table.write(report);
    Ok(())
}

/// Measures fetched blocks, fetches and time with `Load::OnDemand` for four read patterns.
fn fetching_by_access_pattern(settings: &Settings, report: &mut String) -> Result<(), String> {
    heading(report, "On-demand loading, by access pattern");
    let mut table = Table::new(&["Access pattern", "Blocks", "Fetches", "Time", "Share of DB"]);

    let subject = settings.subject("ondemand");
    let (_vfs, conn) = open_fresh(&settings.url, &subject, 4096, Load::Preload)?;
    workload::create_schema(&conn).map_err(err)?;
    // At least 2000 transactions, so a full scan costs clearly more than a single lookup.
    for k in 1..=settings.transactions.max(2000) {
        workload::transaction(&conn, k).map_err(err)?;
    }
    let pages = page_count(&conn)?;
    drop(conn);

    for (name, pattern) in [
        ("Latest 50 of a conversation", Pattern::Recent),
        ("One message by key", Pattern::ByKey),
        ("Full-text search", Pattern::FullText),
        ("Full scan", Pattern::FullScan),
    ] {
        // A new VFS for each pattern, so each one starts with no blocks in memory.
        let vfs = register(&settings.url, &subject, 4096, Load::OnDemand { blocks_per_fetch: 16 })?;
        let conn = workload::open(&vfs, "db").map_err(err)?;
        let started = Instant::now();
        run_pattern(&conn, pattern)?;
        let elapsed = started.elapsed();
        let stats = vfs.stats();
        table.row(&[
            name.to_string(),
            stats.fetched_blocks.to_string(),
            stats.fetches.to_string(),
            ms(elapsed),
            format!("{:.0} %", 100.0 * stats.fetched_blocks as f64 / pages as f64),
        ]);
    }
    table.write(report);
    write!(report, "The database has {pages} pages.\n\n").unwrap();
    Ok(())
}

/// Measures insert throughput for 20,000 filler rows: in one transaction, in transactions of 512 rows, and one row
/// per transaction.
fn bulk_insert_throughput(settings: &Settings, report: &mut String) -> Result<(), String> {
    heading(report, "Bulk insert");
    let mut table = Table::new(&["Batching", "Rows", "Data", "Time", "Rows/s", "MB/s"]);

    let rows = 20_000usize;
    for (name, per_transaction) in [
        ("One transaction", rows),
        ("512 rows each", FILLER_ROWS_PER_TRANSACTION),
        ("1 row each", 1),
    ] {
        // One row per transaction is slow, so this case writes a twentieth of the rows.
        let rows = if per_transaction == 1 { rows / 20 } else { rows };
        let subject = settings.subject("bulk");
        let (_vfs, conn) = open_fresh(&settings.url, &subject, 4096, Load::Preload)?;
        create_filler(&conn)?;

        let started = Instant::now();
        let mut written = 0;
        while written < rows {
            let batch = per_transaction.min(rows - written);
            insert_filler(&conn, batch)?;
            written += batch;
        }
        let elapsed = started.elapsed();
        let bytes = (rows * FILLER_ROW_BYTES) as f64;
        table.row(&[
            name.to_string(),
            rows.to_string(),
            format!("{:.0} MB", bytes / (1024.0 * 1024.0)),
            ms(elapsed),
            format!("{:.0}", rows as f64 / elapsed.as_secs_f64()),
            format!("{:.1}", bytes / (1024.0 * 1024.0) / elapsed.as_secs_f64()),
        ]);
    }
    table.write(report);
    Ok(())
}

/// Measures the message transaction with page sizes of 4, 16 and 64 KiB. Larger pages need fewer fetches but write
/// more bytes per commit.
fn page_sizes(settings: &Settings, report: &mut String) -> Result<(), String> {
    heading(report, "Page size");
    let mut table = Table::new(&[
        "Page size",
        "p50",
        "p99",
        "Blocks/commit",
        "Bytes/commit",
        "Bytes total",
        "DB pages",
    ]);

    for page_size in [4096u32, 16384, 65536] {
        let subject = settings.subject("pagesize");
        let vfs = register(&settings.url, &subject, page_size, Load::Preload)?;
        let conn = workload::open_with_page_size(&vfs, "db", Some(page_size)).map_err(err)?;
        let actual: u32 = conn.query_row("PRAGMA page_size", [], |row| row.get(0)).map_err(err)?;
        if actual != page_size {
            return Err(format!("asked for page size {page_size}, the database uses {actual}"));
        }
        workload::create_schema(&conn).map_err(err)?;
        let before = vfs.stats();

        let times = run_transactions(&conn, Kind::Message, settings.transactions)?;
        let stats = delta(before, vfs.stats());
        let p = Percentiles::of(times);
        table.row(&[
            format!("{} KiB", page_size / 1024),
            ms(p.p50),
            ms(p.p99),
            per_commit(stats.committed_blocks, stats.commits),
            per_commit(stats.committed_bytes, stats.commits),
            format!("{:.1} MB", stats.committed_bytes as f64 / (1024.0 * 1024.0)),
            page_count(&conn)?.to_string(),
        ]);
    }
    table.write(report);
    Ok(())
}

// -------------------------------------------------------------------------------------------------------------------
// Workload
// -------------------------------------------------------------------------------------------------------------------

/// Kind of transaction in a measurement.
#[derive(Clone, Copy)]
enum Kind {
    /// One transaction of the message workload.
    Message,
    /// Reads the 50 newest messages of a conversation, then runs a message transaction.
    ReadThenWrite,
    /// Inserts 512 filler rows.
    Bulk,
}

/// Read pattern for the on-demand measurement.
#[derive(Clone, Copy)]
enum Pattern {
    /// The 50 newest messages of one conversation.
    Recent,
    /// One message by primary key.
    ByKey,
    /// A full-text search.
    FullText,
    /// Reads every message.
    FullScan,
}

fn run_transactions(conn: &Connection, kind: Kind, count: u64) -> Result<Vec<Duration>, String> {
    let mut times = Vec::with_capacity(count as usize);
    for k in 1..=count {
        let started = Instant::now();
        match kind {
            Kind::Message => workload::transaction(conn, k).map_err(err)?,
            Kind::ReadThenWrite => {
                read_recent(conn)?;
                workload::transaction(conn, k).map_err(err)?;
            }
            Kind::Bulk => insert_filler(conn, FILLER_ROWS_PER_TRANSACTION)?,
        }
        times.push(started.elapsed());
    }
    Ok(times)
}

fn run_pattern(conn: &Connection, pattern: Pattern) -> Result<(), String> {
    match pattern {
        Pattern::Recent => {
            read_recent(conn)?;
        }
        Pattern::ByKey => {
            let _: Option<String> = conn
                .query_row("SELECT body FROM messages WHERE id = 1", [], |row| row.get(0))
                .map_err(err)?;
        }
        Pattern::FullText => {
            let _: i64 = conn
                .query_row(
                    "SELECT count(*) FROM messages_fts WHERE messages_fts MATCH 'foxtrot'",
                    [],
                    |row| row.get(0),
                )
                .map_err(err)?;
        }
        Pattern::FullScan => {
            let _: i64 = conn
                .query_row("SELECT count(*), sum(length(body)) FROM messages", [], |row| row.get(0))
                .map_err(err)?;
        }
    }
    Ok(())
}

fn read_recent(conn: &Connection) -> Result<usize, String> {
    let mut stmt = conn
        .prepare("SELECT body FROM messages WHERE conv = 1 ORDER BY id DESC LIMIT 50")
        .map_err(err)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(err)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(err)?;
    Ok(rows.len())
}

fn create_filler(conn: &Connection) -> Result<(), String> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS filler (id INTEGER PRIMARY KEY, payload BLOB NOT NULL)")
        .map_err(err)
}

fn insert_filler(conn: &Connection, rows: usize) -> Result<(), String> {
    let tx = conn.unchecked_transaction().map_err(err)?;
    {
        let mut stmt = tx
            .prepare("INSERT INTO filler (payload) VALUES (randomblob(?1))")
            .map_err(err)?;
        for _ in 0..rows {
            stmt.execute([FILLER_ROW_BYTES as i64]).map_err(err)?;
        }
    }
    tx.commit().map_err(err)
}

/// Inserts filler rows until the database file is at least `bytes` long.
fn fill_to(conn: &Connection, bytes: u64) -> Result<(), String> {
    let page_size = page_size(conn)?;
    while page_count(conn)? * page_size < bytes {
        insert_filler(conn, FILLER_ROWS_PER_TRANSACTION)?;
    }
    Ok(())
}

// -------------------------------------------------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------------------------------------------------

impl Settings {
    /// Returns a new key. Every call returns a different key, so a scenario that reopens a database has to keep the
    /// key it got.
    fn subject(&self, _scenario: &str) -> String {
        crate::key::new()
    }
}

fn register(url: &str, key: &str, page_size: u32, load: Load) -> Result<RemoteVfs, String> {
    let mut config = Config::new(url, crate::key::signer(key)?);
    config.page_size = page_size;
    config.load = load;
    config.takeover = true;
    crate::register_vfs(config)
}

/// Registers a new VFS for `subject` and opens the database with the given page size.
fn open_fresh(url: &str, subject: &str, page_size: u32, load: Load) -> Result<(RemoteVfs, Connection), String> {
    let vfs = register(url, subject, page_size, load)?;
    let conn = workload::open_with_page_size(&vfs, "db", Some(page_size)).map_err(err)?;
    Ok((vfs, conn))
}

fn page_count(conn: &Connection) -> Result<u64, String> {
    conn.query_row("PRAGMA page_count", [], |row| row.get::<_, i64>(0))
        .map(|n| n as u64)
        .map_err(err)
}

fn page_size(conn: &Connection) -> Result<u64, String> {
    conn.query_row("PRAGMA page_size", [], |row| row.get::<_, i64>(0))
        .map(|n| n as u64)
        .map_err(err)
}

/// Returns `host:port` of a `ws://` URL, for the proxy. The port defaults to 80.
pub(crate) fn host_of(url: &str) -> Result<String, String> {
    let rest = url
        .strip_prefix("ws://")
        .ok_or_else(|| format!("{url}: only ws:// is supported"))?;
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.contains(':') {
        Ok(authority.to_string())
    } else {
        Ok(format!("{authority}:80"))
    }
}

fn delta(before: Stats, after: Stats) -> Stats {
    Stats {
        commits: after.commits - before.commits,
        commit_frames: after.commit_frames - before.commit_frames,
        committed_blocks: after.committed_blocks - before.committed_blocks,
        committed_bytes: after.committed_bytes - before.committed_bytes,
        commit_time: after.commit_time - before.commit_time,
        max_commit_time: after.max_commit_time,
        fetches: after.fetches - before.fetches,
        fetched_blocks: after.fetched_blocks - before.fetched_blocks,
        fetch_time: after.fetch_time - before.fetch_time,
        reconnects: after.reconnects - before.reconnects,
        local_writes: after.local_writes - before.local_writes,
        local_blocks_written: after.local_blocks_written - before.local_blocks_written,
        local_reads: after.local_reads - before.local_reads,
        local_blocks_read: after.local_blocks_read - before.local_blocks_read,
        local_misses: after.local_misses - before.local_misses,
        local_failures: after.local_failures - before.local_failures,
        caught_up: after.caught_up - before.caught_up,
        forgotten_blocks: after.forgotten_blocks - before.forgotten_blocks,
        evicted_blocks: after.evicted_blocks - before.evicted_blocks,
        // A gauge: the current value, not a difference.
        held_blocks: after.held_blocks,
        recovered_commits: after.recovered_commits - before.recovered_commits,
        resent_commits: after.resent_commits - before.resent_commits,
    }
}

struct Percentiles {
    p50: Duration,
    p90: Duration,
    p99: Duration,
    max: Duration,
}

impl Percentiles {
    fn of(mut times: Vec<Duration>) -> Percentiles {
        times.sort_unstable();
        let at = |q: f64| {
            let last = times.len().saturating_sub(1);
            times.get(((times.len() as f64 * q) as usize).min(last)).copied()
        };
        Percentiles {
            p50: at(0.50).unwrap_or_default(),
            p90: at(0.90).unwrap_or_default(),
            p99: at(0.99).unwrap_or_default(),
            max: times.last().copied().unwrap_or_default(),
        }
    }
}

fn ms(d: Duration) -> String {
    format!("{:.2} ms", d.as_secs_f64() * 1000.0)
}

fn per_commit(total: u64, commits: u64) -> String {
    if commits == 0 {
        return "–".into();
    }
    format!("{:.1}", total as f64 / commits as f64)
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn heading(report: &mut String, title: &str) {
    write!(report, "**{title}**\n\n").unwrap();
}

struct Table {
    columns: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    fn new(columns: &[&str]) -> Table {
        Table {
            columns: columns.iter().map(|c| c.to_string()).collect(),
            rows: Vec::new(),
        }
    }

    fn row(&mut self, cells: &[String]) {
        self.rows.push(cells.to_vec());
    }

    fn write(&self, report: &mut String) {
        writeln!(report, "| {} |", self.columns.join(" | ")).unwrap();
        writeln!(report, "|{}", "---|".repeat(self.columns.len())).unwrap();
        for row in &self.rows {
            writeln!(report, "| {} |", row.join(" | ")).unwrap();
        }
        report.push('\n');
    }
}
