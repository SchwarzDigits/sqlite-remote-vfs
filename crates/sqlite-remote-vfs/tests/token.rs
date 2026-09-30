//! Access tokens against a server that admits only clients with one. They need `SQLITE_REMOTE_TEST_GATED_URL`, a
//! server started with the JWKS in `tests/data/token-jwks.json`, the issuer `sqlite-remote-vfs-tests` and a token
//! leeway of 1 s, and are skipped without it:
//!
//! ```sh
//! SQLITE_REMOTE_PORT=18091 SQLITE_REMOTE_SERVER_ID=ws://127.0.0.1:18091/v1/ws SQLITE_REMOTE_STORE=memory \
//!   SQLITE_REMOTE_TOKEN_JWKS_FILE=crates/sqlite-remote-vfs/tests/data/token-jwks.json \
//!   SQLITE_REMOTE_TOKEN_ISSUER=sqlite-remote-vfs-tests SQLITE_REMOTE_TOKEN_LEEWAY=1s sqlite-remote-server
//! ```
//!
//! The tests sign the tokens themselves, with the key whose public half is in the JWKS.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::Signer as _;
use rusqlite::{Connection, ErrorCode, OpenFlags};
use sqlite_remote_vfs::{Algorithm, Config, Failure, RemoteVfs, Server, Signer, Store, TokenSource, Zeroizing};

/// Private key of the test token service. Its public key is in `tests/data/token-jwks.json`.
const SERVICE_SEED: [u8; 32] = [0x7a; 32];
const ISSUER: &str = "sqlite-remote-vfs-tests";

fn gated_url() -> Option<String> {
    let url = std::env::var("SQLITE_REMOTE_TEST_GATED_URL").ok();
    if url.is_none() {
        eprintln!("skipped: SQLITE_REMOTE_TEST_GATED_URL is not set");
    }
    url
}

struct Key(ed25519_dalek::SigningKey);

impl Key {
    fn fresh() -> Arc<Key> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        Arc::new(Key(ed25519_dalek::SigningKey::from_bytes(&seed)))
    }
}

impl Signer for Key {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }

    fn public_key(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.0.sign(message).to_bytes().to_vec()
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Returns a token for `client` from the test token service, valid from 10 s ago until `expires` (Unix seconds).
fn token_for(url: &str, client: &[u8], expires: u64) -> String {
    let header = r#"{"alg":"EdDSA","kid":"test","typ":"JWT"}"#;
    let claims = format!(
        r#"{{"iss":"{ISSUER}","aud":"{url}","sub":"user@example.test","nbf":{},"exp":{expires},"cnf":{{"jwk":{{"kty":"OKP","crv":"Ed25519","x":"{}"}}}}}}"#,
        now() - 10,
        URL_SAFE_NO_PAD.encode(client),
    );
    let signed = format!("{}.{}", URL_SAFE_NO_PAD.encode(header), URL_SAFE_NO_PAD.encode(claims));
    let service = ed25519_dalek::SigningKey::from_bytes(&SERVICE_SEED);
    let signature = service.sign(signed.as_bytes()).to_bytes();
    format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature))
}

/// Token source for the tests. `next` gets the number of the call, from 0, and returns the token.
struct Tokens<F> {
    calls: AtomicUsize,
    next: F,
}

impl<F: Fn(usize) -> Result<String, String> + Send + Sync> TokenSource for Tokens<F> {
    fn token(&self) -> Result<Zeroizing<String>, String> {
        (self.next)(self.calls.fetch_add(1, Ordering::SeqCst)).map(Zeroizing::new)
    }
}

fn tokens<F: Fn(usize) -> Result<String, String> + Send + Sync + 'static>(next: F) -> Arc<Tokens<F>> {
    Arc::new(Tokens {
        calls: AtomicUsize::new(0),
        next,
    })
}

fn register(
    url: &str,
    key: &Arc<Key>,
    source: Option<Arc<dyn TokenSource>>,
) -> Result<RemoteVfs, sqlite_remote_vfs::Error> {
    let mut server = Server::new(url, key.clone());
    server.token = source;
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).unwrap();
    let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
    RemoteVfs::register(&format!("gated-{name}"), Config::new(Store::Server(server)))
}

fn open(vfs: &RemoteVfs) -> rusqlite::Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags_and_vfs("db", flags, vfs.name())?;
    let _: String = conn.query_row("PRAGMA journal_mode = MEMORY", [], |row| row.get(0))?;
    Ok(conn)
}

fn count(conn: &Connection) -> i64 {
    conn.query_row("SELECT count(*) FROM t", [], |row| row.get(0)).unwrap()
}

#[test]
fn token_admits_the_client_of_its_key() {
    let Some(url) = gated_url() else { return };
    let key = Key::fresh();
    let public = key.public_key();
    let valid = {
        let url = url.clone();
        tokens(move |_| Ok(token_for(&url, &public, now() + 3600)))
    };
    let vfs = register(&url, &key, Some(valid.clone())).expect("register with a token");
    let conn = open(&vfs).unwrap();
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)").unwrap();
    conn.execute("INSERT INTO t VALUES (1)", []).unwrap();
    drop(conn);
    drop(vfs);

    let again = register(&url, &key, Some(valid)).expect("register again");
    assert_eq!(count(&open(&again).unwrap()), 1);
}

#[test]
fn missing_token_is_access_denied() {
    let Some(url) = gated_url() else { return };
    let err = register(&url, &Key::fresh(), None).err().expect("no token");
    assert!(err.is_access_denied(), "{err}");
    assert!(err.to_string().contains("ACCESS_DENIED"), "{err}");
}

#[test]
fn token_of_another_key_is_access_denied() {
    let Some(url) = gated_url() else { return };
    let other = Key::fresh().public_key();
    let stolen = {
        let url = url.clone();
        tokens(move |_| Ok(token_for(&url, &other, now() + 3600)))
    };
    let err = register(&url, &Key::fresh(), Some(stolen))
        .err()
        .expect("a token of another key");
    assert!(err.is_access_denied(), "{err}");
}

#[test]
fn rejected_token_is_asked_for_once_more() {
    let Some(url) = gated_url() else { return };
    let key = Key::fresh();
    let public = key.public_key();
    // The first token has just expired, as can happen right before a login. The second is valid.
    let source = {
        let url = url.clone();
        tokens(move |call| {
            let expires = if call == 0 { now() - 60 } else { now() + 3600 };
            Ok(token_for(&url, &public, expires))
        })
    };
    register(&url, &key, Some(source.clone())).expect("the second token is accepted");
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);

    // Only once: a source that returns rejected tokens fails the registration after two tries.
    let public = key.public_key();
    let expired = {
        let url = url.clone();
        tokens(move |_| Ok(token_for(&url, &public, now() - 60)))
    };
    let err = register(&url, &key, Some(expired.clone()))
        .err()
        .expect("expired tokens");
    assert!(err.is_access_denied(), "{err}");
    assert_eq!(expired.calls.load(Ordering::SeqCst), 2);
}

#[test]
fn connection_is_renewed_before_the_token_expires() {
    let Some(url) = gated_url() else { return };
    let key = Key::fresh();
    let public = key.public_key();
    // Tokens valid for 4 s. The client reconnects after 2 s, half the lifetime.
    let source = {
        let url = url.clone();
        tokens(move |_| Ok(token_for(&url, &public, now() + 4)))
    };
    let vfs = register(&url, &key, Some(source.clone())).unwrap();
    let conn = open(&vfs).unwrap();
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)").unwrap();
    for id in 0..3 {
        std::thread::sleep(Duration::from_millis(2500));
        conn.execute("INSERT INTO t VALUES (?1)", [id])
            .expect("commit after the renewal");
    }
    assert_eq!(count(&conn), 3);
    assert!(
        source.calls.load(Ordering::SeqCst) >= 4,
        "a new token for every renewal"
    );
    assert!(vfs.stats().reconnects >= 3, "{:?}", vfs.stats());
}

#[test]
fn commit_without_a_token_fails_with_sqlite_auth() {
    let Some(url) = gated_url() else { return };
    let key = Key::fresh();
    let public = key.public_key();
    // The token service becomes unavailable after the first token, which is valid for 4 s.
    let source = {
        let url = url.clone();
        tokens(move |call| match call {
            0 => Ok(token_for(&url, &public, now() + 4)),
            _ => Err("token service unavailable".into()),
        })
    };
    let vfs = register(&url, &key, Some(source)).unwrap();
    let conn = open(&vfs).unwrap();
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)").unwrap();

    std::thread::sleep(Duration::from_millis(2500));
    let err = conn
        .execute("INSERT INTO t VALUES (1)", [])
        .expect_err("no token for the reconnect");
    assert_eq!(
        err.sqlite_error_code(),
        Some(ErrorCode::AuthorizationForStatementDenied),
        "{err}"
    );
    assert_eq!(vfs.failure(), Some(Failure::Denied));
}

#[test]
fn open_after_the_token_expired_reconnects_first() {
    // An Open that the server closes the connection on is not repeated, unlike a commit. The client must reconnect
    // with a new token before it sends the Open.
    let Some(url) = gated_url() else { return };
    let key = Key::fresh();
    let public = key.public_key();
    let source = {
        let url = url.clone();
        tokens(move |_| Ok(token_for(&url, &public, now() + 3)))
    };
    let vfs = register(&url, &key, Some(source)).unwrap();
    let conn = open(&vfs).unwrap();
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)").unwrap();
    drop(conn);

    // Past the expiry and the server's leeway of 1 s.
    std::thread::sleep(Duration::from_millis(5000));
    let conn = open(&vfs).expect("open with a new token");
    assert_eq!(count(&conn), 0);
}
