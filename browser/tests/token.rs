//! Access tokens in the browser, against a server that admits only clients with one. The token is sent by the
//! connection worker's connection; a rejected token and a renewal reopen that connection through the bridge.
//!
//! Requires `SQLITE_REMOTE_TEST_GATED_URL` at compile time, a server set up as described in
//! `crates/sqlite-remote-vfs/tests/token.rs`. Without it the tests return immediately and pass.

#![cfg(target_arch = "wasm32")]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::Signer as _;
use rusqlite::{Connection, OpenFlags};
use sqlite_remote_vfs::{Config, RemoteVfs, Server, Signer, Store, TokenSource, Zeroizing};
use sqlite_wasm_rs as _;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::WorkerGlobalScope;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const GATED: Option<&str> = option_env!("SQLITE_REMOTE_TEST_GATED_URL");
/// Private key of the test token service. Its public key is in `crates/sqlite-remote-vfs/tests/data/token-jwks.json`.
const SERVICE_SEED: [u8; 32] = [0x7a; 32];

fn now() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

fn token_for(url: &str, client: &[u8], expires: u64) -> String {
    let header = r#"{"alg":"EdDSA","kid":"test","typ":"JWT"}"#;
    let claims = format!(
        r#"{{"iss":"sqlite-remote-vfs-tests","aud":"{url}","sub":"user@example.test","nbf":{},"exp":{expires},"cnf":{{"jwk":{{"kty":"OKP","crv":"Ed25519","x":"{}"}}}}}}"#,
        now() - 10,
        URL_SAFE_NO_PAD.encode(client),
    );
    let signed = format!("{}.{}", URL_SAFE_NO_PAD.encode(header), URL_SAFE_NO_PAD.encode(claims));
    let signature = ed25519_dalek::SigningKey::from_bytes(&SERVICE_SEED)
        .sign(signed.as_bytes())
        .to_bytes();
    format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature))
}

struct Tokens<F> {
    calls: AtomicUsize,
    next: F,
}

impl<F: Fn(usize) -> String> TokenSource for Tokens<F> {
    fn token(&self) -> Result<Zeroizing<String>, String> {
        Ok(Zeroizing::new((self.next)(self.calls.fetch_add(1, Ordering::SeqCst))))
    }
}

fn tokens<F: Fn(usize) -> String + 'static>(next: F) -> Arc<Tokens<F>> {
    Arc::new(Tokens {
        calls: AtomicUsize::new(0),
        next,
    })
}

async fn register(
    url: &str,
    signer: &Arc<dyn Signer>,
    source: Option<Arc<dyn TokenSource>>,
) -> Result<RemoteVfs, sqlite_remote_vfs::Error> {
    let mut server = Server::new(url, signer.clone());
    server.token = source;
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).unwrap();
    let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
    RemoteVfs::register_async(&format!("gated-{name}"), Config::new(Store::Server(server))).await
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
async fn token_admits_the_client_and_missing_token_is_denied() {
    let Some(url) = GATED else { return };
    let signer = common::key();
    let public = signer.public_key();
    let valid = tokens(move |_| token_for(url, &public, now() + 3600));
    let vfs = register(url, &signer, Some(valid))
        .await
        .expect("register with a token");
    let conn = open(&vfs);
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)").unwrap();
    conn.execute("INSERT INTO t VALUES (1)", []).unwrap();

    let err = register(url, &common::key(), None).await.err().expect("no token");
    assert!(err.is_access_denied(), "{err}");
}

#[wasm_bindgen_test]
async fn rejected_token_is_asked_for_once_more() {
    let Some(url) = GATED else { return };
    let signer = common::key();
    let public = signer.public_key();
    // The first token has just expired. The client reopens the connection through the bridge and sends the second.
    let source = tokens(move |call| {
        let expires = if call == 0 { now() - 60 } else { now() + 3600 };
        token_for(url, &public, expires)
    });
    register(url, &signer, Some(source.clone()))
        .await
        .expect("the second token is accepted");
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
}

#[wasm_bindgen_test]
async fn connection_is_renewed_before_the_token_expires() {
    let Some(url) = GATED else { return };
    let signer = common::key();
    let public = signer.public_key();
    let source = tokens(move |_| token_for(url, &public, now() + 4));
    let vfs = register(url, &signer, Some(source.clone())).await.unwrap();
    let conn = open(&vfs);
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)").unwrap();
    for id in 0..2 {
        sleep(2500).await;
        conn.execute("INSERT INTO t VALUES (?1)", [id])
            .expect("commit after the renewal");
    }
    let count: i64 = conn.query_row("SELECT count(*) FROM t", [], |row| row.get(0)).unwrap();
    assert_eq!(count, 2);
    assert!(
        source.calls.load(Ordering::SeqCst) >= 3,
        "a new token for every renewal"
    );
}
