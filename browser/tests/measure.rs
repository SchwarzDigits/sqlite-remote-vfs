//! Measurements of the local copy and the memory limit in the browser. The results are printed as Markdown tables.
//! Run with `-- --nocapture` to see them:
//!
//! ```text
//! CHROMEDRIVER=… SQLITE_REMOTE_TEST_URL=ws://127.0.0.1:18090/v1/ws ./test.sh --chrome -- --nocapture
//! ```

#![cfg(target_arch = "wasm32")]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rusqlite::{Connection, OpenFlags};
use sqlite_remote_vfs::{Config, Load, Local, Memory, RemoteVfs, Signer};
use sqlite_wasm_rs as _;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::{WorkerGlobalScope, console};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const KEY: [u8; 32] = [0x11; 32];
const SERVER: Option<&str> = option_env!("SQLITE_REMOTE_TEST_URL");
/// Optional URL of the same server behind a proxy that adds latency: `SQLITE_REMOTE_TEST_SLOW_URL`.
const SLOW: Option<&str> = option_env!("SQLITE_REMOTE_TEST_SLOW_URL");
/// Number of rows to write, from `SQLITE_REMOTE_TEST_ROWS`, default 500. Each commit costs one round trip, so use
/// fewer rows against a server with real latency, e.g. `SQLITE_REMOTE_TEST_ROWS=60`.
fn rows() -> i64 {
    option_env!("SQLITE_REMOTE_TEST_ROWS")
        .and_then(|rows| rows.parse().ok())
        .unwrap_or(500)
}
const ROW_BYTES: i64 = 4000;

fn now() -> f64 {
    let scope: WorkerGlobalScope = js_sys::global().unchecked_into();
    scope.performance().expect("performance in the worker scope").now()
}

fn unique(prefix: &str) -> String {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let mut random = [0u8; 4];
    getrandom::fill(&mut random).unwrap();
    let hex: String = random.iter().map(|b| format!("{b:02x}")).collect();
    format!("{prefix}-{hex}-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

async fn register(url: &str, subject: &Arc<dyn Signer>, local: Local) -> RemoteVfs {
    let mut config = Config::new(url, subject.clone());
    config.takeover = true;
    config.load = Load::Preload;
    config.local = local;
    RemoteVfs::register_async(&unique("vfs"), config)
        .await
        .expect("register the VFS")
}

fn open(vfs: &RemoteVfs) -> Connection {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags_and_vfs("db", flags, vfs.encrypted_name().as_str()).expect("open");
    let hex: String = KEY.iter().map(|b| format!("{b:02x}")).collect();
    conn.pragma_update(None, "key", format!("x'{hex}'")).expect("key");
    let _: String = conn
        .query_row("PRAGMA journal_mode = MEMORY", [], |row| row.get(0))
        .expect("journal in memory");
    conn
}

fn percentile(times: &mut [f64], q: f64) -> f64 {
    times.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    times[((times.len() as f64 * q) as usize).min(times.len() - 1)]
}

#[wasm_bindgen_test]
async fn measure_commit_and_reopen_with_local_copy() {
    let Some(url) = SERVER else { return };
    console::log_1(&"| Local copy | p50 commit | p99 commit | DB | Pages | Reopen | Fetches |".into());
    console::log_1(&"|---|---|---|---|---|---|---|".into());

    for (label, local) in [("no", Local::None), ("yes", Local::Browser)] {
        let subject = common::key();
        let vfs = register(url, &subject, local.clone()).await;
        let conn = open(&vfs);
        conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, payload BLOB)")
            .expect("create");

        let rows_to_write = rows();
        let mut times = Vec::with_capacity(rows_to_write as usize);
        for id in 1..=rows_to_write {
            let started = now();
            conn.execute("INSERT INTO t VALUES (?1, randomblob(?2))", (id, ROW_BYTES))
                .expect("insert");
            times.push(now() - started);
        }
        let pages: i64 = conn.query_row("PRAGMA page_count", [], |row| row.get(0)).unwrap();
        let bytes = pages as f64 * 4096.0 / (1024.0 * 1024.0);
        drop(conn);
        drop(vfs);

        // Time to reopen: with a local copy the blocks come from IndexedDB, without one from the server.
        let opened = now();
        let again = register(url, &subject, local).await;
        let conn = open(&again);
        let rows: i64 = conn.query_row("SELECT count(*) FROM t", [], |row| row.get(0)).unwrap();
        let elapsed = now() - opened;
        assert_eq!(rows, rows_to_write);

        let stats = again.stats();
        console::log_1(
            &format!(
                "| {label} | {:.2} ms | {:.2} ms | {bytes:.1} MB | {pages} | {elapsed:.1} ms | {} |",
                percentile(&mut times, 0.5),
                percentile(&mut times, 0.99),
                stats.fetches,
            )
            .into(),
        );
    }
}

/// Measures reopening a larger database over the slow URL, with and without a local copy. The row count comes from
/// `SQLITE_REMOTE_TEST_BIG_ROWS`, default 2000. The database is written over the fast URL, because writing thousands
/// of blocks over the slow one would take minutes and show nothing new: each commit costs one round trip either way.
#[wasm_bindgen_test]
async fn measure_reopen_over_slow_line() {
    let (Some(url), Some(slow)) = (SERVER, SLOW) else {
        return;
    };
    console::log_1(&"| Local copy | DB | Pages | Reopen over slow line | Fetches |".into());
    console::log_1(&"|---|---|---|---|---|".into());

    for (label, local) in [("no", Local::None), ("yes", Local::Browser)] {
        let subject = common::key();
        let vfs = register(url, &subject, local.clone()).await;
        let conn = open(&vfs);
        conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, payload BLOB)")
            .expect("create");
        let big = option_env!("SQLITE_REMOTE_TEST_BIG_ROWS")
            .and_then(|rows| rows.parse().ok())
            .unwrap_or(2000i64);
        conn.execute_batch("BEGIN").expect("begin");
        for id in 1..=big {
            conn.execute("INSERT INTO t VALUES (?1, randomblob(?2))", (id, ROW_BYTES))
                .expect("insert");
        }
        conn.execute_batch("COMMIT").expect("commit");
        let pages: i64 = conn.query_row("PRAGMA page_count", [], |row| row.get(0)).unwrap();
        let bytes = pages as f64 * 4096.0 / (1024.0 * 1024.0);
        drop(conn);
        drop(vfs);

        let opened = now();
        let again = register(slow, &subject, local).await;
        let conn = open(&again);
        let rows: i64 = conn.query_row("SELECT count(*) FROM t", [], |row| row.get(0)).unwrap();
        let elapsed = now() - opened;
        assert_eq!(rows, big);

        console::log_1(
            &format!(
                "| {label} | {bytes:.1} MB | {pages} | {elapsed:.0} ms | {} |",
                again.stats().fetches
            )
            .into(),
        );
    }
}

/// Measures read latency under several memory limits. In the browser, evicted blocks are reloaded from IndexedDB.
/// Natively they come from a file within microseconds. IndexedDB is much slower.
#[wasm_bindgen_test]
async fn measure_reads_under_memory_limit() {
    let Some(url) = SERVER else { return };
    // SQLite's page size in this build is 8192, so with 4096-byte blocks every page spans two blocks. Both block sizes
    // are measured, because the difference affects every read and every commit.
    for block in [4096u32, 8192] {
        one_memory_limit_table(url, block).await;
    }
}

async fn one_memory_limit_table(url: &str, block: u32) {
    let subject = common::key();
    let count = 2000i64;

    // Build the database once, with a local copy, so every case below starts from the same complete local copy.
    let vfs = {
        let mut config = Config::new(url, subject.clone());
        config.takeover = true;
        config.load = Load::Preload;
        config.local = Local::Browser;
        config.page_size = block;
        RemoteVfs::register_async(&unique("vfs"), config)
            .await
            .expect("register the VFS")
    };
    let conn = open(&vfs);
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, payload BLOB)")
        .expect("create");
    conn.execute_batch("BEGIN").expect("begin");
    for id in 1..=count {
        conn.execute("INSERT INTO t VALUES (?1, randomblob(?2))", (id, ROW_BYTES))
            .expect("insert");
    }
    conn.execute_batch("COMMIT").expect("commit");
    let pages: i64 = conn.query_row("PRAGMA page_count", [], |row| row.get(0)).unwrap();
    let written: i64 = conn.query_row("SELECT count(*) FROM t", [], |row| row.get(0)).unwrap();
    let page_size: i64 = conn.query_row("PRAGMA page_size", [], |row| row.get(0)).unwrap();
    let payload: i64 = conn
        .query_row("SELECT sum(length(payload)) FROM t", [], |row| row.get(0))
        .unwrap();
    let held = vfs.stats().held_blocks;
    drop(conn);
    drop(vfs);

    console::log_1(
        &format!(
            "\nBlock size {block} B: {written} rows, {} KB payload, {pages} pages of {page_size} B ({} KB), \
             {held} blocks in memory.\n",
            payload / 1024,
            pages * page_size / 1024
        )
        .into(),
    );
    console::log_1(&"| Memory limit | Read p50 | p90 | p99 | Held | Server fetches | Blocks from local copy |".into());
    console::log_1(&"|---|---|---|---|---|---|---|".into());

    let per_mb = (1024 * 1024 / block) as u64;
    for (label, memory) in [
        ("unlimited", Memory::Unlimited),
        ("8 MB", Memory::Blocks(8 * per_mb)),
        ("2 MB", Memory::Blocks(2 * per_mb)),
        ("512 KB", Memory::Blocks(per_mb / 2)),
    ] {
        let mut config = Config::new(url, subject.clone());
        config.takeover = true;
        config.load = Load::OnDemand { blocks_per_fetch: 16 };
        config.local = Local::Browser;
        config.memory = memory;
        config.page_size = block;
        let vfs = RemoteVfs::register_async(&unique("vfs"), config)
            .await
            .expect("register the VFS");
        let conn = open(&vfs);

        // Point reads spread over the whole table, the access pattern of a client that reads its message history.
        let mut times = Vec::new();
        for n in 0..200i64 {
            let id = (n * 7919) % count + 1;
            let started = now();
            let length: i64 = conn
                .query_row("SELECT length(payload) FROM t WHERE id = ?1", [id], |row| row.get(0))
                .expect("read a row");
            assert_eq!(length, ROW_BYTES);
            times.push(now() - started);
        }
        let stats = vfs.stats();
        console::log_1(
            &format!(
                "| {label} | {:.2} ms | {:.2} ms | {:.2} ms | {} KB | {} | {} |",
                percentile(&mut times.clone(), 0.5),
                percentile(&mut times.clone(), 0.9),
                percentile(&mut times.clone(), 0.99),
                stats.held_blocks * block as u64 / 1024,
                stats.fetches,
                stats.local_blocks_read,
            )
            .into(),
        );
        drop(conn);
        drop(vfs);
    }
}
