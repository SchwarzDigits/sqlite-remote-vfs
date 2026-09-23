//! sqlite-remote-vfs with SQLCipher instead of SQLite3 Multiple Ciphers.
//!
//! SQLCipher encrypts in SQLite's pager, before pages reach any VFS. A database is opened through the VFS name
//! itself, not through a `multipleciphers-` name, and the key is set with `PRAGMA key`.
//!
//! `pages_are_encrypted_before_the_vfs` needs no server. `database_on_server_is_encrypted` needs
//! `SQLITE_REMOTE_TEST_URL` and is skipped without it.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rusqlite::{Connection, OpenFlags};
use sqlite_remote_vfs::{Algorithm, Config, Local, RemoteVfs, Signer};

const KEY: &str = "x'1111111111111111111111111111111111111111111111111111111111111111'";
const MARKER: &[u8] = b"sqlcipher-marker-7f3a9c";
const ROWS: i64 = 200;

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

fn temp_path(name: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    std::env::temp_dir().join(format!(
        "sqlcipher-{}-{}-{name}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

fn write_rows(conn: &Connection) {
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, data BLOB)")
        .expect("create table");
    for id in 0..ROWS {
        conn.execute("INSERT INTO t (id, data) VALUES (?1, ?2)", (id, MARKER))
            .expect("insert");
    }
}

#[test]
fn sqlcipher_is_linked() {
    let conn = Connection::open_in_memory().unwrap();
    let version: String = conn
        .query_row("PRAGMA cipher_version", [], |row| row.get(0))
        .expect("PRAGMA cipher_version exists only in SQLCipher");
    assert!(!version.is_empty(), "cipher_version must be set");
}

#[test]
fn pages_are_encrypted_before_the_vfs() {
    // The default VFS writes exactly the bytes the pager passes to it, which is what any VFS receives.
    let path = temp_path("marker.db");
    {
        let conn = Connection::open(&path).expect("open");
        conn.pragma_update(None, "key", KEY).expect("key");
        write_rows(&conn);
    }
    let bytes = std::fs::read(&path).expect("read database file");
    std::fs::remove_file(&path).ok();
    assert!(
        !bytes.starts_with(b"SQLite format 3\0"),
        "file must not start with the SQLite header"
    );
    assert!(!contains(&bytes, MARKER), "file must not contain the plaintext marker");
}

fn server_url() -> Option<String> {
    let url = std::env::var("SQLITE_REMOTE_TEST_URL").ok();
    if url.is_none() {
        eprintln!("skipped: SQLITE_REMOTE_TEST_URL is not set");
    }
    url
}

struct TestSigner(ed25519_dalek::SigningKey);

impl Signer for TestSigner {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }

    fn public_key(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer as _;
        self.0.sign(message).to_bytes().to_vec()
    }
}

fn key() -> Arc<dyn Signer> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    Arc::new(TestSigner(ed25519_dalek::SigningKey::from_bytes(&seed)))
}

fn register(config: Config) -> RemoteVfs {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let name = format!(
        "sqlcipher-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    RemoteVfs::register(&name, config).expect("register the VFS")
}

/// Opens the database through the VFS itself: SQLCipher needs no shim VFS.
fn open(vfs: &RemoteVfs, key: Option<&str>) -> Connection {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE;
    let conn = Connection::open_with_flags_and_vfs("db", flags, vfs.name()).expect("open");
    if let Some(key) = key {
        conn.pragma_update(None, "key", key).expect("key");
    }
    conn
}

#[test]
fn database_on_server_is_encrypted() {
    let Some(url) = server_url() else { return };
    let signer = key();
    let copy = temp_path("local.copy");

    // Write with a local copy. The local copy holds exactly the blocks the server acknowledged.
    let mut config = Config::new(&url, signer.clone());
    config.local = Local::File(copy.clone());
    let vfs = register(config);
    let conn = open(&vfs, Some(KEY));
    write_rows(&conn);
    drop(conn);
    drop(vfs);

    let stored = std::fs::read(&copy).expect("read local copy");
    std::fs::remove_file(&copy).ok();
    assert!(
        !contains(&stored, b"SQLite format 3\0"),
        "stored blocks must not contain the SQLite header"
    );
    assert!(
        !contains(&stored, MARKER),
        "stored blocks must not contain the plaintext marker"
    );

    // Reopen from the server, without a local copy.
    let vfs = register(Config::new(&url, signer.clone()));
    let conn = open(&vfs, Some(KEY));
    let rows: i64 = conn
        .query_row("SELECT count(*) FROM t", [], |row| row.get(0))
        .expect("count rows");
    assert_eq!(rows, ROWS, "all rows must be read back from the server");
    drop(conn);
    drop(vfs);

    // Without the key the database cannot be read.
    let vfs = register(Config::new(&url, signer));
    let conn = open(&vfs, None);
    let result = conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get::<_, i64>(0));
    assert!(result.is_err(), "reading without the key must fail");
}
