//! `wss://` tests: the VFS over TLS, and the certificates it must reject.
//!
//! The server speaks plain WebSocket and relies on an ingress or load balancer in front of it for TLS. These tests
//! start their own TLS terminator in front of the server, with certificates from a test CA that only the client is
//! configured to trust. No system settings are changed.
//!
//! Like the other server tests, they need `SQLITE_REMOTE_TEST_URL` and are skipped without it.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use rusqlite::{Connection, OpenFlags};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use sqlite_remote_vfs::{Algorithm, Config, RemoteVfs, Signer};

const KEY: [u8; 32] = [0x11; 32];

fn server_url() -> Option<String> {
    let url = std::env::var("SQLITE_REMOTE_TEST_URL").ok();
    if url.is_none() {
        eprintln!("skipped: SQLITE_REMOTE_TEST_URL is not set");
    }
    url
}

/// Test CA that issues server certificates. Only these tests trust it.
struct Authority {
    der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
}

impl Authority {
    fn new(name: &str) -> Authority {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name.push(DnType::CommonName, name);
        let key = KeyPair::generate().unwrap();
        let der = params.self_signed(&key).unwrap().der().clone();
        Authority {
            der,
            issuer: Issuer::new(params, key),
        }
    }

    /// Issues a server certificate for `name` and returns it with its private key.
    fn certify(&self, name: &str) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate().unwrap();
        let der = params.signed_by(&key, &self.issuer).unwrap().der().clone();
        (der, PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())))
    }
}

/// Starts a TLS terminator on a free local port that forwards decrypted traffic to `backend`, like an ingress.
/// Returns the port.
fn terminate(backend: &str, certificate: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> u16 {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = Arc::new(
        ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)
            .unwrap(),
    );
    let listener = TcpListener::bind("localhost:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let backend = backend.to_string();
    thread::spawn(move || {
        for client in listener.incoming().flatten() {
            let (config, backend) = (Arc::clone(&config), backend.clone());
            thread::spawn(move || forward(client, &backend, config));
        }
    });
    port
}

/// Copies bytes in both directions until either side closes. A single thread alternates between the two sockets. A
/// 2 ms read timeout on both keeps it from blocking on the idle side.
fn forward(client: TcpStream, backend: &str, config: Arc<ServerConfig>) {
    let Ok(connection) = ServerConnection::new(config) else {
        return;
    };
    let Ok(mut server) = TcpStream::connect(backend) else {
        return;
    };
    let quick = Some(Duration::from_millis(2));
    if client.set_read_timeout(quick).is_err() || server.set_read_timeout(quick).is_err() {
        return;
    }
    let mut tls = StreamOwned::new(connection, client);
    let mut buf = vec![0u8; 64 * 1024];
    let idle = |err: &std::io::Error| matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut);
    loop {
        match tls.read(&mut buf) {
            Ok(0) => return,
            Ok(n) if server.write_all(&buf[..n]).is_err() => return,
            Ok(_) => {}
            Err(err) if idle(&err) => {}
            Err(_) => return,
        }
        match server.read(&mut buf) {
            Ok(0) => return,
            Ok(n) if tls.write_all(&buf[..n]).and_then(|()| tls.flush()).is_err() => return,
            Ok(_) => {}
            Err(err) if idle(&err) => {}
            Err(_) => return,
        }
    }
}

/// Returns the `host:port` part of a WebSocket URL.
fn backend(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    rest.split('/').next().unwrap_or(rest).to_string()
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

fn register(config: Config) -> Result<RemoteVfs, sqlite_remote_vfs::Error> {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    RemoteVfs::register(
        &format!("tls-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)),
        config,
    )
}

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

#[test]
fn database_round_trips_over_wss() {
    let Some(url) = server_url() else { return };
    let authority = Authority::new("sqlite-remote-vfs test CA");
    let (certificate, private) = authority.certify("localhost");
    let port = terminate(&backend(&url), certificate, private);
    let wss = format!("wss://localhost:{port}/v1/ws");
    let me = key();

    let mut config = Config::new(&wss, me.clone());
    config.extra_roots = vec![authority.der.to_vec()];
    let vfs = register(config).expect("connect over wss://");
    let conn = open(&vfs, true).expect("open database");
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, body TEXT)")
        .unwrap();
    for id in 1..=50 {
        conn.execute("INSERT INTO t VALUES (?1, ?2)", (id, format!("row {id}")))
            .unwrap();
    }
    drop(conn);
    drop(vfs);

    // A new VFS instance reads the data back from the server over TLS.
    let mut config = Config::new(&wss, me);
    config.extra_roots = vec![authority.der.to_vec()];
    let again = register(config).expect("reconnect over wss://");
    let conn = open(&again, false).expect("reopen database");
    let rows: i64 = conn.query_row("SELECT count(*) FROM t", [], |row| row.get(0)).unwrap();
    assert_eq!(rows, 50);
    let integrity: String = conn.query_row("PRAGMA integrity_check", [], |row| row.get(0)).unwrap();
    assert_eq!(integrity, "ok");
}

#[test]
fn rejects_certificate_from_unknown_ca() {
    // The certificate is valid and issued for the right host, but by a CA the client does not trust. A
    // man-in-the-middle would present such a certificate.
    let Some(url) = server_url() else { return };
    let authority = Authority::new("untrusted test CA");
    let (certificate, private) = authority.certify("localhost");
    let port = terminate(&backend(&url), certificate, private);

    let refused = register(Config::new(format!("wss://localhost:{port}/v1/ws"), key()));
    let reason = refused
        .err()
        .expect("certificate from an unknown CA must be rejected")
        .to_string();
    assert!(
        reason.contains("UnknownIssuer"),
        "expected an UnknownIssuer error: {reason}"
    );
}

#[test]
fn rejects_certificate_for_other_host() {
    // The CA is trusted and the certificate is valid, but for a different host name. Accepting it would let any
    // server with a certificate from that CA impersonate this one.
    let Some(url) = server_url() else { return };
    let authority = Authority::new("sqlite-remote-vfs test CA");
    let (certificate, private) = authority.certify("someone-else.test");
    let port = terminate(&backend(&url), certificate, private);

    let mut config = Config::new(format!("wss://localhost:{port}/v1/ws"), key());
    config.extra_roots = vec![authority.der.to_vec()];
    let refused = register(config);
    let reason = refused
        .err()
        .expect("certificate for another host must be rejected")
        .to_string();
    assert!(
        reason.contains("not valid for name"),
        "expected a host name mismatch error: {reason}"
    );
}
