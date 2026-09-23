//! Browser version of the native spike test. Checks the same assumptions on `wasm32-unknown-unknown`, with the
//! in-memory VFS from `src/lib.rs`:
//!
//! - SQLite3 Multiple Ciphers encrypts above a VFS written in Rust. The VFS receives only ciphertext.
//! - A database can be read with its key and not with another key.
//! - The VFS has no shared memory, so SQLite refuses WAL and uses a rollback journal.
//! - The main database file and its journal are stored in the VFS. Temporary files are not.
//!
//! Run with `./test.sh`.

#![cfg(target_arch = "wasm32")]

use std::sync::atomic::{AtomicUsize, Ordering};

use rusqlite::{Connection, OpenFlags};
use sqlite_remote_vfs_browser::BrowserVfs;
// SQLite compiled to WebAssembly with SQLite3 Multiple Ciphers. Imported so that it is linked. rusqlite and the VFS
// call it through its C symbols.
use sqlite_wasm_rs as _;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

const KEY: [u8; 32] = [0x11; 32];
const OTHER_KEY: [u8; 32] = [0x22; 32];
const MARKER: &str = "plaintext marker 4711";

fn register() -> BrowserVfs {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let name = format!("browser-spike-{}", NEXT.fetch_add(1, Ordering::Relaxed));
    BrowserVfs::register(&name).expect("register the VFS")
}

fn raw_key(key: &[u8; 32]) -> String {
    let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("x'{hex}'")
}

fn open(vfs: &BrowserVfs, file: &str, key: &[u8; 32]) -> rusqlite::Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags_and_vfs(file, flags, vfs.encrypted_name().as_str())?;
    conn.pragma_update(None, "key", raw_key(key))?;
    Ok(conn)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

fn integrity(conn: &Connection) -> String {
    conn.query_row("PRAGMA integrity_check", [], |row| row.get(0)).unwrap()
}

#[wasm_bindgen_test]
fn sqlite_runs_on_rust_vfs() {
    let vfs = register();
    let conn = open(&vfs, "plain.db", &KEY).expect("open the database");
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, body TEXT); INSERT INTO t (body) VALUES ('hello')")
        .expect("write");

    let body: String = conn
        .query_row("SELECT body FROM t WHERE id = 1", [], |row| row.get(0))
        .expect("read");
    assert_eq!(body, "hello");
    assert_eq!(integrity(&conn), "ok");
    assert!(vfs.file_names().contains(&"plain.db".to_string()));
}

#[wasm_bindgen_test]
fn vfs_sees_only_ciphertext() {
    let vfs = register();
    let conn = open(&vfs, "secret.db", &KEY).expect("open the database");
    conn.execute_batch(&format!(
        "CREATE TABLE notes (body TEXT); INSERT INTO notes (body) VALUES ('{MARKER}')"
    ))
    .expect("write");
    drop(conn);

    let bytes = vfs.file_bytes("secret.db").expect("secret.db in the VFS");
    assert!(!bytes.is_empty(), "secret.db must not be empty");
    assert!(
        !contains(&bytes, MARKER.as_bytes()),
        "plaintext marker found in the stored file"
    );
    assert!(
        !contains(&bytes, b"SQLite format 3"),
        "plaintext SQLite header found in the stored file"
    );
    assert!(
        !contains(&bytes, b"notes"),
        "plaintext table name found in the stored file"
    );
}

#[wasm_bindgen_test]
fn database_opens_only_with_its_key() {
    let vfs = register();
    let conn = open(&vfs, "reopen.db", &KEY).expect("open the database");
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY); INSERT INTO t VALUES (7)")
        .expect("write");
    drop(conn);

    let again = open(&vfs, "reopen.db", &KEY).expect("open again");
    let id: i64 = again
        .query_row("SELECT id FROM t", [], |row| row.get(0))
        .expect("read back");
    assert_eq!(id, 7);
    assert_eq!(integrity(&again), "ok");
    drop(again);

    let wrong = open(&vfs, "reopen.db", &OTHER_KEY).expect("open with the wrong key");
    assert!(
        wrong
            .query_row("SELECT id FROM t", [], |row| row.get::<_, i64>(0))
            .is_err(),
        "reading with another key must fail"
    );
}

#[wasm_bindgen_test]
fn wal_refused_without_shared_memory() {
    let vfs = register();
    let conn = open(&vfs, "wal.db", &KEY).expect("open the database");
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)")
        .expect("write");

    let mode: String = conn
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .expect("ask for WAL");
    assert_ne!(mode, "wal", "WAL must be refused without shared memory");

    conn.execute_batch("INSERT INTO t VALUES (1)")
        .expect("write after WAL was refused");
    assert_eq!(integrity(&conn), "ok");
}

#[wasm_bindgen_test]
fn rollback_journal_is_stored_in_vfs() {
    let vfs = register();
    let conn = open(&vfs, "journal.db", &KEY).expect("open the database");
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)")
        .expect("write");

    conn.execute_batch("BEGIN").expect("begin");
    for id in 1..200 {
        conn.execute("INSERT INTO t VALUES (?1)", [id]).expect("insert");
    }
    let names = vfs.file_names();
    conn.execute_batch("ROLLBACK").expect("roll back");

    let left: i64 = conn.query_row("SELECT count(*) FROM t", [], |row| row.get(0)).unwrap();
    assert_eq!(left, 0, "rollback must remove all inserted rows");
    assert_eq!(integrity(&conn), "ok");
    assert!(
        names.iter().any(|name| name.contains("journal.db")),
        "expected journal.db and its journal in the VFS, got {names:?}"
    );
}
