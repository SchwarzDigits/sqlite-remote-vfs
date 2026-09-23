//! End-to-end tests in the browser. SQLite runs in this worker and encrypts with SQLite3 Multiple Ciphers. The
//! database file is on the page server. The connection worker holds the WebSocket.
//!
//! Requires a page server and `SQLITE_REMOTE_TEST_URL` at compile time, e.g.
//! `SQLITE_REMOTE_TEST_URL=ws://127.0.0.1:18090/v1/ws ./test.sh`. Without it the tests return immediately and pass,
//! like skipped native tests. The test page is served from 127.0.0.1, so the server must allow that origin.

#![cfg(target_arch = "wasm32")]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rusqlite::{Connection, OpenFlags};
use sqlite_remote_vfs::{Config, Load, RemoteVfs, Signer};
// SQLite compiled to WebAssembly with SQLite3 Multiple Ciphers. Imported so that it is linked.
use sqlite_wasm_rs as _;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

// A commit waits in `Atomics.wait`, which browsers do not allow on the main thread. SQLite therefore runs in a
// dedicated worker.
wasm_bindgen_test_configure!(run_in_dedicated_worker);

const KEY: [u8; 32] = [0x11; 32];
const SERVER: Option<&str> = option_env!("SQLITE_REMOTE_TEST_URL");

fn unique(prefix: &str) -> String {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let mut random = [0u8; 4];
    getrandom::fill(&mut random).unwrap();
    let hex: String = random.iter().map(|b| format!("{b:02x}")).collect();
    format!("{prefix}-{hex}-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

async fn register(url: &str, subject: &Arc<dyn Signer>) -> RemoteVfs {
    let mut config = Config::new(url, subject.clone());
    // An earlier test may still hold the lease if its connection has not closed yet.
    config.takeover = true;
    config.load = Load::Preload;
    // The connection runs in the connection worker. Starting a worker needs the event loop, so registration is async.
    RemoteVfs::register_async(&unique("vfs"), config)
        .await
        .expect("register the VFS")
}

fn open(vfs: &RemoteVfs, db: &str) -> rusqlite::Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags_and_vfs(db, flags, vfs.encrypted_name().as_str())?;
    let hex: String = KEY.iter().map(|b| format!("{b:02x}")).collect();
    conn.pragma_update(None, "key", format!("x'{hex}'"))?;
    let mode: String = conn.query_row("PRAGMA journal_mode = MEMORY", [], |row| row.get(0))?;
    assert_eq!(mode, "memory");
    Ok(conn)
}

fn count(conn: &Connection) -> i64 {
    conn.query_row("SELECT count(*) FROM t", [], |row| row.get(0)).unwrap()
}

#[wasm_bindgen_test]
async fn database_reopens_from_server() {
    let Some(url) = SERVER else { return };
    let subject = common::key();

    let vfs = register(url, &subject).await;
    let conn = open(&vfs, "db").expect("open the database");
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, body TEXT)")
        .expect("create");
    for id in 1..=20 {
        conn.execute("INSERT INTO t (id, body) VALUES (?1, ?2)", (id, format!("row {id}")))
            .expect("insert");
    }
    assert_eq!(count(&conn), 20);
    drop(conn);

    // The browser stores nothing of the database. A new VFS reads it from the server.
    let reader = register(url, &subject).await;
    let conn = open(&reader, "db").expect("reopen");
    assert_eq!(count(&conn), 20, "all rows must be read back from the server");
    let body: String = conn
        .query_row("SELECT body FROM t WHERE id = 7", [], |row| row.get(0))
        .expect("read");
    assert_eq!(body, "row 7");
    let integrity: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0)).unwrap();
    assert_eq!(integrity, "ok");
}

#[wasm_bindgen_test]
async fn each_insert_is_one_commit() {
    let Some(url) = SERVER else { return };
    let subject = common::key();

    let vfs = register(url, &subject).await;
    let conn = open(&vfs, "db").expect("open the database");
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)")
        .expect("create");

    let before = vfs.stats();
    for id in 1..=5 {
        conn.execute("INSERT INTO t VALUES (?1)", [id]).expect("insert");
    }
    let stats = vfs.stats();
    assert_eq!(
        stats.commits,
        before.commits + 5,
        "each autocommit INSERT must be one acknowledged commit"
    );
    assert!(stats.committed_blocks > before.committed_blocks);
    // A commit is counted only after the server acknowledged it, so the count above shows that all five reached the
    // server. The commit time must be measured too. A commit to a server on the same machine can take less than a
    // millisecond, so this needs a clock with sub-millisecond resolution.
    assert!(stats.commit_time > before.commit_time, "commit time must be measured");
}
