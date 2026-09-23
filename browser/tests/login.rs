//! Login with a signer in the browser.
//!
//! The VFS receives a `Signer` and never holds key material. The application chooses the login key and the database
//! key.
//!
//! Requires a page server and `SQLITE_REMOTE_TEST_URL` at compile time, see `remote.rs`.

#![cfg(target_arch = "wasm32")]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rusqlite::{Connection, OpenFlags};
use sqlite_remote_vfs::{Config, RemoteVfs, Signer};
use sqlite_wasm_rs as _;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const SERVER: Option<&str> = option_env!("SQLITE_REMOTE_TEST_URL");

fn unique(prefix: &str) -> String {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let mut random = [0u8; 4];
    getrandom::fill(&mut random).unwrap();
    let hex: String = random.iter().map(|b| format!("{b:02x}")).collect();
    format!("{prefix}-{hex}-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

async fn register(url: &str, key: &Arc<dyn Signer>) -> Result<RemoteVfs, sqlite_remote_vfs::Error> {
    let mut config = Config::new(url, key.clone());
    config.takeover = true;
    RemoteVfs::register_async(&unique("vfs"), config).await
}

/// Database key for SQLite3 Multiple Ciphers. The tests use a constant.
const KEY: [u8; 32] = [0x11; 32];

fn open(vfs: &RemoteVfs, create: bool) -> rusqlite::Result<Connection> {
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    if create {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    let conn = Connection::open_with_flags_and_vfs("db", flags, vfs.encrypted_name().as_str())?;
    let hex: String = KEY.iter().map(|b| format!("{b:02x}")).collect();
    conn.pragma_update(None, "key", format!("x'{hex}'"))?;
    let _: String = conn.query_row("PRAGMA journal_mode = MEMORY", [], |row| row.get(0))?;
    Ok(conn)
}

#[wasm_bindgen_test]
async fn same_key_reopens_its_database() {
    let Some(url) = SERVER else { return };
    let mine = common::key();

    let vfs = register(url, &mine).await.expect("log in");
    let conn = open(&vfs, true).expect("open");
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, body TEXT)")
        .expect("create");
    for id in 1..=20 {
        conn.execute("INSERT INTO t VALUES (?1, ?2)", (id, format!("row {id}")))
            .expect("insert");
    }
    let rows: i64 = conn.query_row("SELECT count(*) FROM t", [], |row| row.get(0)).unwrap();
    assert_eq!(rows, 20);
    drop(conn);
    drop(vfs);

    // Same key again: the server derives the same subject and finds the database.
    let again = register(url, &mine).await.expect("log in again");
    let conn = open(&again, false).expect("reopen");
    let rows: i64 = conn.query_row("SELECT count(*) FROM t", [], |row| row.get(0)).unwrap();
    assert_eq!(rows, 20);
    let integrity: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0)).unwrap();
    assert_eq!(integrity, "ok");
}

#[wasm_bindgen_test]
async fn other_key_cannot_open_database() {
    let Some(url) = SERVER else { return };
    let mine = common::key();
    let theirs = common::key();
    assert_ne!(sqlite_remote_vfs::subject(&*mine), sqlite_remote_vfs::subject(&*theirs));

    let vfs = register(url, &mine).await.expect("log in");
    let conn = open(&vfs, true).expect("open");
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)")
        .expect("create");
    conn.execute("INSERT INTO t VALUES (1)", []).expect("insert");
    drop(conn);
    drop(vfs);

    // Under another key the same name refers to a database of another subject. That database does not exist.
    let other = register(url, &theirs).await.expect("log in with another key");
    assert!(open(&other, false).is_err(), "opening with another key must fail");
}
