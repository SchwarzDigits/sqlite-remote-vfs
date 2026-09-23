//! Checks that the browser stores no data of the database when the VFS has no local copy.
//!
//! Browser storage (IndexedDB, the origin private file system, caches) is deleted when the user clears the browsing
//! data or uses a profile that is not persisted. The test writes a database of more than 2 MiB through the remote VFS.
//! The browser's storage estimate must not grow, and IndexedDB must stay empty.
//!
//! Requires a page server and `SQLITE_REMOTE_TEST_URL` at compile time, see `remote.rs`.

#![cfg(target_arch = "wasm32")]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};

use rusqlite::{Connection, OpenFlags};
use sqlite_remote_vfs::{Config, Load, RemoteVfs};
use sqlite_wasm_rs as _;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::{StorageEstimate, WorkerGlobalScope, console};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const KEY: [u8; 32] = [0x11; 32];
const SERVER: Option<&str> = option_env!("SQLITE_REMOTE_TEST_URL");

/// Payload size per row. `ROWS` rows of this size make a database of more than 2 MiB.
const ROW_BYTES: i64 = 4000;
const ROWS: i64 = 512;

fn unique(prefix: &str) -> String {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let mut random = [0u8; 4];
    getrandom::fill(&mut random).unwrap();
    let hex: String = random.iter().map(|b| format!("{b:02x}")).collect();
    format!("{prefix}-{hex}-{}", NEXT.fetch_add(1, Ordering::Relaxed))
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

/// Bytes the browser reports as used by this origin, across IndexedDB, the origin private file system and caches.
async fn stored_bytes() -> Result<f64, String> {
    let scope: WorkerGlobalScope = js_sys::global().unchecked_into();
    let storage = scope.navigator().storage();
    let promise = storage.estimate().map_err(|err| format!("estimate: {err:?}"))?;
    let estimate = JsFuture::from(promise)
        .await
        .map_err(|err| format!("estimate: {err:?}"))?;
    let estimate: StorageEstimate = estimate.unchecked_into();
    estimate
        .get_usage()
        .ok_or_else(|| "no usage in the estimate".to_string())
}

#[wasm_bindgen_test]
async fn browser_storage_stays_empty() {
    let Some(url) = SERVER else { return };
    let subject = common::key();

    let before = stored_bytes().await;

    let mut config = Config::new(url, subject.clone());
    config.takeover = true;
    config.load = Load::Preload;
    let vfs = RemoteVfs::register_async(&unique("vfs"), config)
        .await
        .expect("register the VFS");
    let conn = open(&vfs);
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, payload BLOB)")
        .expect("create");
    conn.execute_batch("BEGIN").expect("begin");
    for id in 1..=ROWS {
        conn.execute("INSERT INTO t VALUES (?1, randomblob(?2))", (id, ROW_BYTES))
            .expect("insert");
    }
    conn.execute_batch("COMMIT").expect("commit");

    let pages: i64 = conn.query_row("PRAGMA page_count", [], |row| row.get(0)).unwrap();
    let page_size: i64 = conn.query_row("PRAGMA page_size", [], |row| row.get(0)).unwrap();
    let database_bytes = (pages * page_size) as f64;
    assert!(
        database_bytes > 2.0 * 1024.0 * 1024.0,
        "database must be larger than 2 MiB, is {database_bytes} bytes"
    );
    assert!(vfs.stats().committed_bytes > 0);
    drop(conn);

    // Every storage check the browser supports must show no data. If it supports none, the test fails, because it
    // would check nothing.
    let mut checked = 0;
    match (before, stored_bytes().await) {
        (Ok(before), Ok(after)) => {
            let grew = after - before;
            console::log_1(&format!("database {database_bytes} bytes, browser storage grew by {grew}").into());
            // Measured in Firefox: the database is larger than 2 MiB and the estimate does not grow at all. The 64 KiB
            // bound leaves room for an estimate that is rounded or includes unrelated data.
            assert!(
                grew < 64.0 * 1024.0,
                "browser storage grew by {grew} bytes for a database of {database_bytes} bytes, expected no growth"
            );
            checked += 1;
        }
        (before, after) => console::log_1(&format!("no storage estimate: {before:?} / {after:?}").into()),
    }
    match common::indexed_databases().await {
        Ok(names) => {
            console::log_1(&format!("IndexedDB holds {names:?}").into());
            assert!(names.is_empty(), "IndexedDB must be empty, found {names:?}");
            checked += 1;
        }
        Err(reason) => console::log_1(&format!("cannot look into IndexedDB: {reason}").into()),
    }
    assert!(
        checked > 0,
        "browser supports neither a storage estimate nor indexedDB.databases(), nothing was checked"
    );

    // The data is on the server. A second VFS reads it back.
    let reader = RemoteVfs::register_async(&unique("vfs"), {
        let mut config = Config::new(url, subject.clone());
        config.takeover = true;
        config
    })
    .await
    .expect("register a second VFS");
    let conn = open(&reader);
    let rows: i64 = conn.query_row("SELECT count(*) FROM t", [], |row| row.get(0)).unwrap();
    assert_eq!(rows, ROWS, "all rows must be read back from the server");
}
