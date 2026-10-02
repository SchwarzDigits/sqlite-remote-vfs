//! Takeovers and idle connections in the browser. The connection worker hands a `LeaseRevoked` over as soon as it
//! arrives, and keeps an idle connection open with pings.
//!
//! Requires `SQLITE_REMOTE_TEST_URL` at compile time, see `remote.rs`. Without it the tests return immediately and
//! pass.

#![cfg(target_arch = "wasm32")]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OpenFlags};
use sqlite_remote_vfs::{Config, Failure, RemoteVfs, Server, Signer, Store};
use sqlite_wasm_rs as _;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::WorkerGlobalScope;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const SERVER: Option<&str> = option_env!("SQLITE_REMOTE_TEST_URL");

fn unique(prefix: &str) -> String {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let mut random = [0u8; 4];
    getrandom::fill(&mut random).unwrap();
    let hex: String = random.iter().map(|b| format!("{b:02x}")).collect();
    format!("{prefix}-{hex}-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

async fn register(config: Config) -> RemoteVfs {
    RemoteVfs::register_async(&unique("vfs"), config)
        .await
        .expect("register the VFS")
}

fn open(vfs: &RemoteVfs) -> Connection {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags_and_vfs("db", flags, vfs.name()).expect("open");
    let _: String = conn
        .query_row("PRAGMA journal_mode = MEMORY", [], |row| row.get(0))
        .unwrap();
    conn
}

async fn sleep(ms: i32) {
    let promise = js_sys::Promise::new(&mut |resolve, _| {
        let scope: WorkerGlobalScope = js_sys::global().unchecked_into();
        scope
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms)
            .unwrap();
    });
    JsFuture::from(promise).await.unwrap();
}

#[wasm_bindgen_test]
async fn takeover_is_reported_without_a_request() {
    let Some(url) = SERVER else { return };
    let subject: Arc<dyn Signer> = common::key();
    let reported = Arc::new(Mutex::new(Vec::<String>::new()));
    let mut server = Server::new(url, Arc::clone(&subject));
    let sink = Arc::clone(&reported);
    server.on_takeover = Some(Arc::new(move |db: &str| sink.lock().unwrap().push(db.to_string())));
    let holder = register(Config::new(Store::Server(server))).await;
    let conn = open(&holder);
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)").unwrap();

    let mut config = Config::server(url, Arc::clone(&subject));
    config.takeover = true;
    let other = register(config).await;
    let _other_conn = open(&other);

    // The holder makes no request. Its connection worker hands the LeaseRevoked over while this worker is idle.
    for _ in 0..50 {
        if !reported.lock().unwrap().is_empty() {
            break;
        }
        sleep(100).await;
    }
    assert_eq!(*reported.lock().unwrap(), ["db"]);
    assert_eq!(holder.failure(), Some(Failure::TakenOver));
    conn.execute("INSERT INTO t VALUES (1)", [])
        .expect_err("the holder no longer writes");
}

#[wasm_bindgen_test]
async fn idle_connection_stays_open() {
    let Some(url) = SERVER else { return };
    let vfs = register(Config::server(url, common::key())).await;
    let conn = open(&vfs);
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)").unwrap();
    let before = vfs.stats().reconnects;

    // The server closes a connection without a frame for three ping intervals, 30 s by default. The connection worker
    // pings in between.
    sleep(35_000).await;
    conn.execute("INSERT INTO t VALUES (1)", []).unwrap();
    assert_eq!(vfs.stats().reconnects, before, "the connection stayed open");
}
