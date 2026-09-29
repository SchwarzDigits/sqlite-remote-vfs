//! Local databases (`Store::Local`): kept only in this browser, in IndexedDB, without a server. SQLite runs in this
//! worker and encrypts with SQLite3 Multiple Ciphers.
//!
//! Each test uses its own namespace, so tests do not see each other's databases. The test that copies a local
//! database to a server needs `SQLITE_REMOTE_TEST_URL` at compile time, see `remote.rs`; all others need no server.

#![cfg(target_arch = "wasm32")]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};

use rusqlite::backup::{Backup, StepResult};
use rusqlite::{Connection, ErrorCode, OpenFlags};
use sqlite_remote_vfs::{Config, Load, Memory, RemoteVfs};
use sqlite_wasm_rs as _;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const KEY: [u8; 32] = [0x22; 32];
const SERVER: Option<&str> = option_env!("SQLITE_REMOTE_TEST_URL");

fn unique(prefix: &str) -> String {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let mut random = [0u8; 4];
    getrandom::fill(&mut random).unwrap();
    let hex: String = random.iter().map(|b| format!("{b:02x}")).collect();
    format!("{prefix}-{hex}-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

async fn local(namespace: &str) -> RemoteVfs {
    register(Config::local(namespace)).await
}

async fn register(config: Config) -> RemoteVfs {
    RemoteVfs::register_async(&unique("vfs"), config)
        .await
        .expect("register the VFS")
}

fn open(vfs: &RemoteVfs, db: &str) -> rusqlite::Result<Connection> {
    open_with(vfs, db, OpenFlags::SQLITE_OPEN_CREATE, &KEY)
}

fn open_with(vfs: &RemoteVfs, db: &str, extra: OpenFlags, key: &[u8]) -> rusqlite::Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX | extra;
    let conn = Connection::open_with_flags_and_vfs(db, flags, vfs.encrypted_name().as_str())?;
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    conn.pragma_update(None, "key", format!("x'{hex}'"))?;
    let _: String = conn.query_row("PRAGMA journal_mode = MEMORY", [], |row| row.get(0))?;
    Ok(conn)
}

fn insert(conn: &Connection, first: i64, count: i64, bytes: i64) {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY, payload BLOB)")
        .expect("create");
    conn.execute_batch("BEGIN").expect("begin");
    for id in first..first + count {
        conn.execute("INSERT INTO t VALUES (?1, randomblob(?2))", (id, bytes))
            .expect("insert");
    }
    conn.execute_batch("COMMIT").expect("commit");
}

fn count(conn: &Connection) -> i64 {
    conn.query_row("SELECT count(*) FROM t", [], |row| row.get(0)).unwrap()
}

fn integrity(conn: &Connection) -> String {
    conn.query_row("PRAGMA integrity_check", [], |row| row.get(0)).unwrap()
}

fn is_busy(err: &rusqlite::Error) -> bool {
    matches!(
        err.sqlite_error_code(),
        Some(ErrorCode::DatabaseBusy | ErrorCode::CannotOpen)
    )
}

#[wasm_bindgen_test]
async fn commits_survive_a_new_vfs() {
    let namespace = unique("ns");
    let vfs = local(&namespace).await;
    let conn = open(&vfs, "db").expect("open");
    insert(&conn, 0, 100, 300);
    insert(&conn, 100, 20, 300);
    assert_eq!(count(&conn), 120);
    let stats = vfs.stats();
    assert!(stats.commits >= 2, "{stats:?}");
    assert_eq!(stats.fetches, 0, "a local database fetches nothing");
    drop(conn);
    drop(vfs);

    let again = local(&namespace).await;
    let conn = open(&again, "db").expect("reopen");
    assert_eq!(count(&conn), 120);
    assert_eq!(integrity(&conn), "ok");
    assert!(again.stats().local_blocks_read > 0, "the blocks come from IndexedDB");
}

#[wasm_bindgen_test]
async fn wrong_key_cannot_read() {
    let namespace = unique("ns");
    let vfs = local(&namespace).await;
    let conn = open(&vfs, "db").expect("open");
    insert(&conn, 0, 10, 100);
    drop(conn);

    let err = open_with(&vfs, "db", OpenFlags::empty(), &[0x33; 32])
        .and_then(|conn| conn.query_row("SELECT count(*) FROM t", [], |row| row.get::<_, i64>(0)))
        .expect_err("a wrong key must not read the database");
    assert_eq!(err.sqlite_error_code(), Some(ErrorCode::NotADatabase), "{err}");
}

#[wasm_bindgen_test]
async fn second_instance_is_busy_until_the_first_closes() {
    let namespace = unique("ns");
    let first = local(&namespace).await;
    let conn = open(&first, "db").expect("open");
    insert(&conn, 0, 5, 100);

    let second = local(&namespace).await;
    let err = open(&second, "db").expect_err("the first instance holds the database");
    assert!(is_busy(&err), "{err}");

    // Closing releases the lock.
    drop(conn);
    let conn = open(&second, "db").expect("open after the first closed");
    assert_eq!(count(&conn), 5);
}

#[wasm_bindgen_test]
async fn takeover_fences_the_first_instance() {
    let namespace = unique("ns");
    let first = local(&namespace).await;
    let first_conn = open(&first, "db").expect("open");
    insert(&first_conn, 0, 50, 200);

    let mut config = Config::local(&namespace);
    config.takeover = true;
    let second = register(config).await;
    let second_conn = open(&second, "db").expect("take over");
    assert_eq!(count(&second_conn), 50);

    // The first instance no longer holds the database, so its next commit must fail and change nothing.
    let err = first_conn
        .execute("INSERT INTO t VALUES (1000, x'00')", [])
        .expect_err("the first instance was taken over");
    assert_eq!(err.sqlite_error_code(), Some(ErrorCode::SystemIoFailure), "{err}");
    insert(&second_conn, 50, 10, 200);
    drop(second_conn);
    drop(first_conn);

    let third = local(&namespace).await;
    let conn = open(&third, "db").expect("reopen");
    assert_eq!(count(&conn), 60);
    let lost: i64 = conn
        .query_row("SELECT count(*) FROM t WHERE id = 1000", [], |row| row.get(0))
        .unwrap();
    assert_eq!(lost, 0, "the fenced commit must not be stored");
    assert_eq!(integrity(&conn), "ok");
}

#[wasm_bindgen_test]
async fn missing_database_is_not_created_without_the_create_flag() {
    let namespace = unique("ns");
    let vfs = local(&namespace).await;
    let err = open_with(&vfs, "db", OpenFlags::empty(), &KEY).expect_err("the database does not exist");
    assert_eq!(err.sqlite_error_code(), Some(ErrorCode::CannotOpen), "{err}");

    let name = format!("sqlite-remote-vfs-local/{namespace}/db");
    if let Ok(names) = common::indexed_databases().await {
        assert!(!names.contains(&name), "{name} must not be left behind: {names:?}");
    }
}

#[wasm_bindgen_test]
async fn delete_removes_the_database() {
    let namespace = unique("ns");
    let vfs = local(&namespace).await;
    let conn = open(&vfs, "db").expect("open");
    insert(&conn, 0, 10, 100);
    drop(conn);

    let name = format!("sqlite-remote-vfs-local/{namespace}/db");
    if let Ok(names) = common::indexed_databases().await {
        assert!(names.contains(&name), "{name} must exist: {names:?}");
    }
    vfs.delete_database("db").expect("delete");
    if let Ok(names) = common::indexed_databases().await {
        assert!(!names.contains(&name), "{name} must be deleted: {names:?}");
    }
    let err = open_with(&vfs, "db", OpenFlags::empty(), &KEY).expect_err("the database was deleted");
    assert_eq!(err.sqlite_error_code(), Some(ErrorCode::CannotOpen), "{err}");

    // Opening with SQLITE_OPEN_CREATE creates it empty.
    let conn = open(&vfs, "db").expect("create again");
    let tables: i64 = conn
        .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
        .unwrap();
    assert_eq!(tables, 0);
}

#[wasm_bindgen_test]
async fn delete_needs_takeover_while_another_instance_holds_the_database() {
    let namespace = unique("ns");
    let holder = local(&namespace).await;
    let conn = open(&holder, "db").expect("open");
    insert(&conn, 0, 10, 100);

    let deleter = local(&namespace).await;
    let err = deleter
        .delete_database("db")
        .expect_err("the holder has the database open");
    assert!(err.to_string().contains("another instance"), "{err}");

    let mut config = Config::local(&namespace);
    config.takeover = true;
    let deleter = register(config).await;
    deleter.delete_database("db").expect("delete with takeover");

    // The holder was taken over, so its next commit fails.
    let err = conn
        .execute("INSERT INTO t VALUES (1000, x'00')", [])
        .expect_err("the holder was taken over");
    assert_eq!(err.sqlite_error_code(), Some(ErrorCode::SystemIoFailure), "{err}");
}

#[wasm_bindgen_test]
async fn databases_and_namespaces_are_separate() {
    let first_namespace = unique("ns");
    let second_namespace = unique("ns");
    let first = local(&first_namespace).await;
    let second = local(&first_namespace).await;
    let other = local(&second_namespace).await;

    let a = open(&first, "a").expect("open a");
    insert(&a, 0, 3, 100);
    let b = open(&second, "b").expect("open b");
    insert(&b, 0, 7, 100);
    let a_elsewhere = open(&other, "a").expect("open a in another namespace");
    insert(&a_elsewhere, 0, 11, 100);

    assert_eq!(count(&a), 3);
    assert_eq!(count(&b), 7);
    assert_eq!(count(&a_elsewhere), 11);
}

#[wasm_bindgen_test]
async fn memory_limit_reloads_blocks_from_indexeddb() {
    let namespace = unique("ns");
    let configure = || {
        let mut config = Config::local(&namespace);
        config.load = Load::OnDemand { blocks_per_fetch: 4 };
        config.memory = Memory::Blocks(16);
        config
    };
    let vfs = register(configure()).await;
    let conn = open(&vfs, "db").expect("open");
    insert(&conn, 0, 400, 1000);
    let written: i64 = conn
        .query_row("SELECT sum(length(payload)) FROM t", [], |row| row.get(0))
        .unwrap();
    drop(conn);
    assert!(vfs.stats().evicted_blocks > 0, "{:?}", vfs.stats());

    let again = register(configure()).await;
    let conn = open(&again, "db").expect("reopen");
    let read: i64 = conn
        .query_row("SELECT sum(length(payload)) FROM t", [], |row| row.get(0))
        .unwrap();
    assert_eq!(read, written);
    assert_eq!(integrity(&conn), "ok");
    let stats = again.stats();
    assert!(stats.evicted_blocks > 0, "{stats:?}");
    assert!(stats.held_blocks <= 16, "{stats:?}");
}

#[wasm_bindgen_test]
async fn large_commits_and_preloads_are_split() {
    // 8192-byte blocks: a preload of more than 255 blocks does not fit one answer of the bridge, and a commit of
    // more than 2 MiB does not fit one request.
    let namespace = unique("ns");
    let configure = || {
        let mut config = Config::local(&namespace);
        config.page_size = 8192;
        config
    };
    let vfs = register(configure()).await;
    let conn = open(&vfs, "db").expect("open");
    insert(&conn, 0, 3000, 1000);
    let pages: i64 = conn.query_row("PRAGMA page_count", [], |row| row.get(0)).unwrap();
    assert!(
        pages > 300,
        "the database must exceed one bridge buffer, has {pages} pages"
    );
    drop(conn);

    let again = register(configure()).await;
    let conn = open(&again, "db").expect("reopen");
    assert_eq!(count(&conn), 3000);
    assert_eq!(integrity(&conn), "ok");
    assert!(again.stats().local_reads >= 2, "{:?}", again.stats());
}

#[wasm_bindgen_test]
async fn backup_copies_a_local_database_to_the_server() {
    let Some(url) = SERVER else { return };
    let namespace = unique("ns");
    let source_vfs = local(&namespace).await;
    let source = open(&source_vfs, "db").expect("open the local database");
    insert(&source, 0, 500, 500);

    let subject = common::key();
    let target_vfs = register(Config::server(url, subject.clone())).await;
    let mut target = open(&target_vfs, "db").expect("open the server database");
    {
        // In steps of 16 pages. Between steps the source can be used.
        let backup = Backup::new(&source, &mut target).expect("start the backup");
        while backup.step(16).expect("backup step") != StepResult::Done {}
    }
    drop(target);
    drop(target_vfs);

    let check_vfs = register(Config::server(url, subject)).await;
    let conn = open(&check_vfs, "db").expect("reopen on the server");
    assert_eq!(count(&conn), 500);
    assert_eq!(integrity(&conn), "ok");
}

#[wasm_bindgen_test]
async fn namespace_is_checked() {
    for namespace in ["", "a/b"] {
        let err = RemoteVfs::register_async(&unique("vfs"), Config::local(namespace))
            .await
            .err()
            .expect("invalid namespace");
        assert!(err.to_string().contains("namespace"), "{err}");
    }
}

#[wasm_bindgen_test]
fn synchronous_registration_is_refused() {
    let err = RemoteVfs::register(&unique("vfs"), Config::local("ns"))
        .err()
        .expect("local databases need register_async");
    assert!(err.to_string().contains("register_async"), "{err}");
}
