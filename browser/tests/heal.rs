//! A database that broke because the server could not be reached heals in the browser, on the same connection:
//! the connection worker notices in the background that the server is back, and the next access resumes the lease.
//!
//! Requires, at compile time, the page server in `SQLITE_REMOTE_TEST_URL` and the relay from `relay.py` in front of
//! it: its WebSocket URL in `SQLITE_REMOTE_TEST_RELAY_URL` and its control URL in `SQLITE_REMOTE_TEST_RELAY_CONTROL`.
//! Without them the tests return immediately and pass.

#![cfg(target_arch = "wasm32")]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use js_sys::{Function, Promise, Reflect};
use rusqlite::{Connection, OpenFlags};
use sqlite_remote_vfs::{Cache, Failure, RemoteVfs};
// SQLite compiled to WebAssembly with SQLite3 Multiple Ciphers. Imported so that it is linked.
use sqlite_wasm_rs as _;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

// A commit waits in `Atomics.wait`, which browsers do not allow on the main thread.
wasm_bindgen_test_configure!(run_in_dedicated_worker);

const KEY: [u8; 32] = [0x11; 32];
const SERVER: Option<&str> = option_env!("SQLITE_REMOTE_TEST_URL");
const RELAY: Option<&str> = option_env!("SQLITE_REMOTE_TEST_RELAY_URL");
const RELAY_CONTROL: Option<&str> = option_env!("SQLITE_REMOTE_TEST_RELAY_CONTROL");

fn unique(prefix: &str) -> String {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let mut random = [0u8; 4];
    getrandom::fill(&mut random).unwrap();
    let hex: String = random.iter().map(|b| format!("{b:02x}")).collect();
    format!("{prefix}-{hex}-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

/// Opens a database with SQLite's default journal mode, `DELETE`: the journal is a file on the VFS.
fn open(vfs: &RemoteVfs, db: &str) -> Connection {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags_and_vfs(db, flags, vfs.encrypted_name().as_str()).expect("open");
    let hex: String = KEY.iter().map(|b| format!("{b:02x}")).collect();
    conn.pragma_update(None, "key", format!("x'{hex}'")).expect("key");
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .expect("journal mode");
    assert_eq!(mode, "delete");
    conn
}

fn count(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT count(*) FROM t", [], |row| row.get(0))
}

fn insert(conn: &Connection, id: i64) -> rusqlite::Result<usize> {
    conn.execute("INSERT INTO t (id, body) VALUES (?1, 'row')", [id])
}

/// Calls a function of the worker's global scope and awaits the promise it returns.
async fn call_global(name: &str, args: &[JsValue]) -> JsValue {
    let scope: JsValue = js_sys::global().into();
    let function: Function = Reflect::get(&scope, &name.into()).unwrap().dyn_into().unwrap();
    let array: js_sys::Array = args.iter().collect();
    let promise: Promise = function.apply(&scope, &array).unwrap().dyn_into().unwrap();
    JsFuture::from(promise).await.expect(name)
}

/// Stops or resumes the relay.
async fn relay(command: &str) {
    let control = RELAY_CONTROL.expect("relay control URL");
    call_global("fetch", &[format!("{control}/{command}").into()]).await;
}

async fn sleep(duration: Duration) {
    let promise = Promise::new(&mut |resolve, _| {
        let scope: JsValue = js_sys::global().into();
        let set_timeout: Function = Reflect::get(&scope, &"setTimeout".into()).unwrap().dyn_into().unwrap();
        set_timeout
            .call2(&scope, &resolve, &JsValue::from(duration.as_millis() as u32))
            .unwrap();
    });
    JsFuture::from(promise).await.unwrap();
}

#[wasm_bindgen_test]
async fn unreachable_database_heals_on_the_same_connection() {
    let (Some(url), Some(relay_url)) = (SERVER, RELAY) else {
        return;
    };
    let subject = common::key();
    let mut config = common::config(relay_url, &subject, Cache::None);
    if let sqlite_remote_vfs::Store::Server(server) = &mut config.store {
        server.reconnect_timeout = Duration::from_millis(500);
    }
    let vfs = RemoteVfs::register_async(&unique("vfs"), config)
        .await
        .expect("register the VFS");
    let conn = open(&vfs, "db");
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, body TEXT)")
        .expect("create");
    for id in 0..10 {
        insert(&conn, id).expect("insert");
    }

    relay("stop").await;
    insert(&conn, 10).expect_err("the server is gone");
    assert_eq!(vfs.failure(), Some(Failure::Unreachable));
    // While the server is gone, accesses fail at once.
    count(&conn).expect_err("the server is still gone");
    assert_eq!(vfs.failure(), Some(Failure::Unreachable));

    relay("resume").await;
    // The check an application makes before using a database that failed as unreachable. Between the attempts the
    // event loop runs, as it would in an application.
    let mut healed = false;
    for _ in 0..150 {
        let read = conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get::<_, i64>(0));
        if read.is_ok() {
            healed = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert!(healed, "not healed after 15 s: {:?}", vfs.failure());
    assert_eq!(vfs.failure(), None);
    assert_eq!(vfs.stats().healed, 1);
    // The commit that failed is rolled back, and the database takes writes again.
    assert_eq!(count(&conn), Ok(10));
    for id in 100..105 {
        insert(&conn, id).expect("insert after healing");
    }
    drop(conn);

    let reader = RemoteVfs::register_async(&unique("vfs"), common::config(url, &subject, Cache::None))
        .await
        .expect("register the reader");
    let conn = open(&reader, "db");
    assert_eq!(count(&conn), Ok(15));
}
