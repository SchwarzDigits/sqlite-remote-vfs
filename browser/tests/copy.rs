//! Local copy in IndexedDB. The connection worker writes the acknowledged blocks to it. Reads are served from it, so
//! reopening a database with an up-to-date local copy fetches nothing from the server.
//!
//! Requires a page server and `SQLITE_REMOTE_TEST_URL` at compile time, see `remote.rs`.

#![cfg(target_arch = "wasm32")]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rusqlite::{Connection, OpenFlags};
use sqlite_remote_vfs::{Config, Load, Local, Memory, RemoteVfs, Signer};
use sqlite_wasm_rs as _;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

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

fn count(conn: &Connection) -> i64 {
    conn.query_row("SELECT count(*) FROM t", [], |row| row.get(0)).unwrap()
}

#[wasm_bindgen_test]
async fn current_local_copy_avoids_fetches() {
    let Some(url) = SERVER else { return };
    let subject = common::key();

    let vfs = register(url, &subject, Local::Browser).await;
    let conn = open(&vfs);
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, body TEXT)")
        .expect("create");
    for id in 1..=30 {
        conn.execute("INSERT INTO t VALUES (?1, ?2)", (id, format!("row {id}")))
            .expect("insert");
    }
    assert_eq!(count(&conn), 30);
    assert!(vfs.stats().local_writes > 0, "local copy must have been written");
    drop(conn);
    drop(vfs);

    // Same database again. The local copy holds every block.
    let again = register(url, &subject, Local::Browser).await;
    let conn = open(&again);
    assert_eq!(count(&conn), 30, "all rows must be read back");
    let integrity: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0)).unwrap();
    assert_eq!(integrity, "ok");

    let stats = again.stats();
    assert_eq!(stats.fetches, 0, "no fetch expected with an up-to-date local copy");
    assert!(stats.local_blocks_read > 0, "blocks must be read from the local copy");
    assert_eq!(stats.local_failures, 0);
}

#[wasm_bindgen_test]
async fn local_copy_of_other_subject_is_ignored() {
    let Some(url) = SERVER else { return };

    let vfs = register(url, &common::key(), Local::Browser).await;
    let conn = open(&vfs);
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)")
        .expect("create");
    conn.execute_batch("INSERT INTO t VALUES (1), (2), (3)")
        .expect("insert");
    drop(conn);
    drop(vfs);

    // Another subject has its own local copy. None of the first subject's rows may appear.
    let elsewhere = register(url, &common::key(), Local::Browser).await;
    let conn = open(&elsewhere);
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)")
        .expect("create");
    assert_eq!(count(&conn), 0, "new subject must start with an empty table");
}

#[wasm_bindgen_test]
async fn reopen_without_local_copy_fetches_from_server() {
    let Some(url) = SERVER else { return };
    let subject = common::key();

    let vfs = register(url, &subject, Local::None).await;
    let conn = open(&vfs);
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)")
        .expect("create");
    conn.execute_batch("INSERT INTO t VALUES (1), (2)").expect("insert");
    drop(conn);
    drop(vfs);

    let again = register(url, &subject, Local::None).await;
    let conn = open(&again);
    assert_eq!(count(&conn), 2);
    assert!(again.stats().fetches > 0, "blocks must be fetched from the server");
    assert_eq!(again.stats().local_blocks_read, 0);
}

/// Registers a VFS with a local copy, on-demand loading and a memory limit of `blocks` blocks. Nothing is preloaded.
/// Evicted blocks are reloaded from IndexedDB.
async fn register_capped(url: &str, subject: &Arc<dyn Signer>, blocks: u64) -> RemoteVfs {
    let mut config = Config::new(url, subject.clone());
    config.takeover = true;
    config.load = Load::OnDemand { blocks_per_fetch: 8 };
    config.local = Local::Browser;
    config.memory = Memory::Blocks(blocks);
    RemoteVfs::register_async(&unique("vfs"), config)
        .await
        .expect("register the VFS")
}

#[wasm_bindgen_test]
async fn evicted_blocks_reload_from_indexeddb() {
    let Some(url) = SERVER else { return };
    let subject = common::key();

    // Memory limit of 16 blocks. The database is many times larger.
    let vfs = register_capped(url, &subject, 16).await;
    let conn = open(&vfs);
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, payload BLOB)")
        .expect("create");
    conn.execute_batch("BEGIN").expect("begin");
    for id in 1..=300 {
        conn.execute("INSERT INTO t VALUES (?1, randomblob(400))", [id])
            .expect("insert");
    }
    conn.execute_batch("COMMIT").expect("commit");
    let written = vfs.stats();

    // A full table scan needs far more blocks than fit in memory, so most of them must be reloaded.
    assert_eq!(count(&conn), 300);
    let integrity: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0)).unwrap();
    assert_eq!(integrity, "ok");

    let stats = vfs.stats();
    assert!(stats.evicted_blocks > 0, "blocks must be evicted at this memory limit");
    assert!(
        stats.local_blocks_read > written.local_blocks_read,
        "evicted blocks must be reloaded from IndexedDB"
    );
    assert_eq!(stats.fetches, written.fetches, "no fetch from the server expected");
    assert_eq!(stats.local_failures, 0);
}

#[wasm_bindgen_test]
async fn evicted_block_reloads_as_committed() {
    // The local copy is written after the commit, and the commit does not wait for that write. If a read from the
    // local copy could overtake it, an evicted block would be reloaded with its content from before the commit.
    let Some(url) = SERVER else { return };
    let subject = common::key();

    let vfs = register_capped(url, &subject, 8).await;
    let conn = open(&vfs);
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, payload BLOB)")
        .expect("create");
    conn.execute_batch("BEGIN").expect("begin");
    for id in 1..=200 {
        conn.execute("INSERT INTO t VALUES (?1, randomblob(400))", [id])
            .expect("insert");
    }
    conn.execute_batch("COMMIT").expect("commit");

    for round in 1..=5i64 {
        conn.execute("UPDATE t SET payload = randomblob(?1) WHERE id = 1", [round * 100])
            .expect("change one row");
        // The table scan evicts the blocks that were just committed.
        assert_eq!(count(&conn), 200);
        let length: i64 = conn
            .query_row("SELECT length(payload) FROM t WHERE id = 1", [], |row| row.get(0))
            .expect("read it back");
        assert_eq!(length, round * 100, "reloaded block must have the committed content");
    }
    let integrity: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0)).unwrap();
    assert_eq!(integrity, "ok");
    assert!(
        vfs.stats().evicted_blocks > 0,
        "blocks must be evicted at this memory limit"
    );
}

#[wasm_bindgen_test]
async fn local_copy_fills_during_on_demand_loading() {
    let Some(url) = SERVER else { return };
    let subject = common::key();

    let vfs = register_capped(url, &subject, 64).await;
    let conn = open(&vfs);
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, body TEXT)")
        .expect("create");
    for id in 1..=60 {
        conn.execute("INSERT INTO t VALUES (?1, ?2)", (id, format!("row {id}")))
            .expect("insert");
    }
    assert_eq!(count(&conn), 60);
    drop(conn);
    drop(vfs);

    // Nothing was preloaded, but the local copy holds every committed block.
    let again = register_capped(url, &subject, 64).await;
    let conn = open(&again);
    assert_eq!(count(&conn), 60);
    let stats = again.stats();
    assert_eq!(stats.fetches, 0, "no fetch expected with a complete local copy");
    assert!(stats.local_blocks_read > 0, "blocks must be read from the local copy");
}

#[wasm_bindgen_test]
async fn stale_local_copy_is_caught_up() {
    let Some(url) = SERVER else { return };
    let subject = common::key();

    let vfs = register(url, &subject, Local::Browser).await;
    let conn = open(&vfs);
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, payload BLOB)")
        .expect("create");
    conn.execute_batch("BEGIN").expect("begin");
    for id in 1..=400 {
        conn.execute("INSERT INTO t VALUES (?1, randomblob(400))", [id])
            .expect("insert");
    }
    conn.execute_batch("COMMIT").expect("commit");
    drop(conn);
    drop(vfs);

    // A second VFS commits one row. It uses no local copy, so the copy in IndexedDB stays at the older version.
    let elsewhere = {
        let mut config = Config::new(url, subject.clone());
        config.takeover = true;
        RemoteVfs::register_async(&unique("vfs"), config)
            .await
            .expect("register the VFS")
    };
    let conn = open(&elsewhere);
    conn.execute("INSERT INTO t VALUES (9001, randomblob(400))", [])
        .expect("insert through the second VFS");
    drop(conn);
    drop(elsewhere);

    let again = register(url, &subject, Local::Browser).await;
    let conn = open(&again);
    assert_eq!(count(&conn), 401, "row from the second VFS must be visible");
    let integrity: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0)).unwrap();
    assert_eq!(integrity, "ok");

    let stats = again.stats();
    assert_eq!(stats.caught_up, 1, "local copy must be caught up once");
    assert!(stats.forgotten_blocks > 0, "catch-up must remove the changed blocks");
    assert!(
        stats.fetched_blocks < stats.local_blocks_read / 4,
        "only changed blocks may be fetched: {} fetched, {} read from the local copy",
        stats.fetched_blocks,
        stats.local_blocks_read
    );
}
