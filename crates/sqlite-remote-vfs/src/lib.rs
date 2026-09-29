//! SQLite VFS that stores the database file on a remote page server. In a browser it can also keep databases only in
//! IndexedDB, without a server (`Store::Local`, browser only).
//!
//! The VFS keeps the blocks of the database in memory. At `SQLITE_FCNTL_SYNC` it sends the blocks modified by the
//! transaction to the server and blocks until the server acknowledges the commit. If the server rejects the commit,
//! the sync fails and SQLite rolls the transaction back, as on a failing disk. A commit that returned successfully is
//! stored on the server.
//!
//! The VFS does not encrypt. Encryption above it keeps plaintext away from the server: with SQLite3 Multiple Ciphers,
//! open databases through [`RemoteVfs::encrypted_name`] (`multipleciphers-<name>`); with SQLCipher, through
//! [`RemoteVfs::name`]. In both cases the key is set with `PRAGMA key`.
//!
//! The client logs in with a [`Signer`]: it signs the server's challenge, and the server derives the subject that owns
//! the databases from the public key. The client cannot choose the subject.
//!
//! The connection uses `wss://` or `ws://`. For `wss://` the client trusts the certificate authorities of the
//! operating system and those in `Server::extra_roots`.
//!
//! Current limits: one database per registered VFS, one connection per database.

// The unit tests link SQLite from the dev-dependency. The MSVC linker requires every SQLite function that rsqlite-vfs
// declares, also when no test calls it.
#[cfg(test)]
use libsqlite3_sys as _;

mod client;
mod database;
mod identity;
mod local;
#[cfg(target_arch = "wasm32")]
mod local_database;
mod pages;
mod platform;
mod transport;
mod vfs;

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rsqlite_vfs::{register_vfs, registered_vfs};

pub use crate::identity::{Algorithm, Shared, Signer, TokenSource, subject};
pub use zeroize::Zeroizing;

use crate::client::{Client, ClientConfig, ClientError};
use crate::vfs::{Backend, Files, Inner, Io, ServerBackend, Vfs, lock};

/// When blocks are loaded from the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Load {
    /// Load all blocks when the database is opened.
    Preload,
    /// Load a block when SQLite first reads it. Each fetch loads `blocks_per_fetch` consecutive blocks.
    OnDemand { blocks_per_fetch: u64 },
}

/// Limit on the number of blocks kept in memory.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Memory {
    /// No limit. Every block that was read or written stays in memory.
    #[default]
    Unlimited,
    /// Keep at most this many blocks in memory. Beyond that, the least recently used blocks are evicted and
    /// reloaded on access: with a server from the [`Cache`] or the server, locally from IndexedDB. Blocks modified
    /// since the last commit are never evicted.
    ///
    /// With a server, most useful together with a [`Cache`], which reloads a block in a fraction of a millisecond.
    Blocks(u64),
}

/// Optional cache of the server's database on this device. Reads it can serve need no network round trip.
///
/// The server is authoritative. Blocks are written to the cache only after the server has acknowledged the commit. A
/// missing, outdated or damaged cache therefore only causes additional fetches from the server.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Cache {
    /// No cache. Every block is fetched from the server.
    #[default]
    None,
    /// Cache in this file.
    #[cfg(not(target_arch = "wasm32"))]
    File(std::path::PathBuf),
    /// Cache in IndexedDB, managed by the connection worker: one IndexedDB database per database, named
    /// `sqlite-remote-vfs-cache-<subject>/<database>`.
    #[cfg(target_arch = "wasm32")]
    Browser,
}

/// Where the databases of a [`RemoteVfs`] are stored.
#[derive(Clone, Debug)]
pub enum Store {
    /// On a page server, which is authoritative.
    Server(Server),
    /// Only in this browser, in IndexedDB, without a server. For development, demos, tests and deployments without a
    /// server. The data is lost when the user clears the site data, and the browser may evict it under storage
    /// pressure unless the application obtained persistent storage (`navigator.storage.persist()`).
    ///
    /// Each database is an IndexedDB database named `sqlite-remote-vfs-local/<namespace>/<database>`. The namespace
    /// keeps the databases of different applications or users apart and must not be empty or contain `/`.
    ///
    /// A commit returns when its IndexedDB transaction is complete. It is requested with durability `strict`; whether
    /// it survives a crash of the operating system depends on the browser. A failed commit leaves the stored database
    /// unchanged: SQLite gets `SQLITE_FULL` if the storage quota is exhausted, otherwise `SQLITE_IOERR_FSYNC`, and the
    /// database accepts no more writes until it is opened again.
    ///
    /// Only one instance can have a database open, also across tabs: opening takes a Web Lock named after the
    /// database, and a second instance gets `SQLITE_BUSY`. With [`Config::takeover`] it takes the database over, and
    /// the first instance can no longer commit. Web Locks need a secure context.
    #[cfg(target_arch = "wasm32")]
    Local { namespace: String },
}

/// Connection to the page server.
#[derive(Clone, Debug)]
pub struct Server {
    /// WebSocket URL of the page server, e.g. `wss://vfs.example/v1/ws`. `ws://` is for a server on the same machine
    /// or behind a proxy that terminates TLS.
    pub url: String,
    /// Signer for the login. The server derives the subject that owns the databases from its public key.
    pub signer: Arc<dyn Signer>,
    /// Access token source, for a server that admits only clients with a token. `None` sends no token. A rejected
    /// token fails the registration with [`Error::is_access_denied`], and a database operation with `SQLITE_AUTH`.
    pub token: Option<Arc<dyn TokenSource>>,
    /// Identifier of this client instance. Random if `None`.
    pub instance_id: Option<[u8; 16]>,
    /// Optional cache on this device. It may be incomplete: blocks it does not have are fetched from the server and
    /// then added to it.
    pub cache: Cache,
    /// How long a commit tries to reconnect before it fails.
    pub reconnect_timeout: Duration,
    /// Record the block ranges of every fetch, readable with [`RemoteVfs::fetch_trace`]. Useful for analysing the
    /// round trips of a query. The list grows for the lifetime of the VFS.
    pub trace_fetches: bool,
    /// Additional DER-encoded CA certificates to trust for `wss://`, on top of those of the operating system. Needed
    /// when the server certificate is issued by a CA the system does not know, for example an organisation's
    /// internal CA. Not available in a browser, where the browser decides which CAs to trust.
    #[cfg(not(target_arch = "wasm32"))]
    pub extra_roots: Vec<Vec<u8>>,
}

impl Server {
    /// Returns server settings with the defaults: no access token, no cache, a random instance identifier, 10 s
    /// reconnect timeout.
    pub fn new(url: impl Into<String>, signer: Arc<dyn Signer>) -> Self {
        Server {
            url: url.into(),
            signer,
            token: None,
            instance_id: None,
            cache: Cache::None,
            reconnect_timeout: Duration::from_secs(10),
            trace_fetches: false,
            #[cfg(not(target_arch = "wasm32"))]
            extra_roots: Vec::new(),
        }
    }
}

/// Configuration for [`RemoteVfs`].
#[derive(Clone, Debug)]
pub struct Config {
    /// Where the databases are stored.
    pub store: Store,
    /// Page size for new databases. SQLite3 Multiple Ciphers uses 4096 in SQLCipher format.
    pub page_size: u32,
    /// When blocks are loaded: from the server, or locally from IndexedDB.
    pub load: Load,
    /// Limit on the number of blocks kept in memory.
    pub memory: Memory,
    /// Open a database even if another instance has it open. With a server, the lease is taken over; locally, the
    /// lock is. The other instance can then no longer commit.
    pub takeover: bool,
    /// Timeout for connecting and for each response of the server, or of the connection worker in a browser.
    pub timeout: Duration,
}

impl Config {
    /// Returns a configuration with the defaults: page size 4096, preload, no memory limit, no takeover, 10 s timeout.
    pub fn new(store: Store) -> Self {
        Config {
            store,
            page_size: 4096,
            load: Load::Preload,
            memory: Memory::Unlimited,
            takeover: false,
            timeout: Duration::from_secs(10),
        }
    }

    /// Configuration for databases on a page server, with the defaults of [`Config::new`] and [`Server::new`].
    pub fn server(url: impl Into<String>, signer: Arc<dyn Signer>) -> Self {
        Config::new(Store::Server(Server::new(url, signer)))
    }

    /// Configuration for databases kept only in this browser, with the defaults of [`Config::new`]. See
    /// [`Store::Local`].
    #[cfg(target_arch = "wasm32")]
    pub fn local(namespace: impl Into<String>) -> Self {
        Config::new(Store::Local {
            namespace: namespace.into(),
        })
    }
}

/// Counters for measurements, totals since registration.
///
/// With `Store::Local`, the commit counters count commits to IndexedDB, `local_reads` and `local_blocks_read` count
/// reads from it, and the counters for the server and the cache stay zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub commits: u64,
    pub commit_frames: u64,
    pub committed_blocks: u64,
    pub committed_bytes: u64,
    /// Time commits spent waiting for the server: total, and the longest single commit.
    pub commit_time: Duration,
    pub max_commit_time: Duration,
    pub fetches: u64,
    pub fetched_blocks: u64,
    pub fetch_time: Duration,
    pub reconnects: u64,
    /// Local copy: writes and blocks written, reads and blocks read, reads it could not serve, and failures. After
    /// the first failure the local copy is not used for the rest of the session.
    pub local_writes: u64,
    pub local_blocks_written: u64,
    pub local_reads: u64,
    pub local_blocks_read: u64,
    pub local_misses: u64,
    pub local_failures: u64,
    /// Outdated local copies that were caught up instead of discarded, and the blocks removed from them to do so.
    pub caught_up: u64,
    pub forgotten_blocks: u64,
    /// Blocks evicted from memory because of the memory limit.
    pub evicted_blocks: u64,
    /// Number of blocks currently in memory. The only field that can decrease.
    pub held_blocks: u64,
    /// Commits whose acknowledgement was lost and that, according to the server's state after reconnecting, were
    /// applied.
    pub recovered_commits: u64,
    /// Commits that had not reached the server when the connection broke and were sent again.
    pub resent_commits: u64,
}

/// Error returned when registering a VFS or deleting a database fails.
#[derive(Debug)]
pub struct Error {
    message: String,
    access_denied: bool,
}

impl Error {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Error {
            message: message.into(),
            access_denied: false,
        }
    }

    /// An error of the client, prefixed with `context`.
    pub(crate) fn client(context: &str, err: ClientError) -> Self {
        Error {
            message: format!("{context}: {err}"),
            access_denied: err.is_access_denied(),
        }
    }

    /// Whether the server rejected the access token, or the [`TokenSource`] returned none.
    pub fn is_access_denied(&self) -> bool {
        self.access_denied
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

/// A registered remote VFS. With SQLite3 Multiple Ciphers, open databases through [`RemoteVfs::encrypted_name`].
/// Otherwise open them through [`RemoteVfs::name`]: unencrypted with plain SQLite, encrypted with SQLCipher.
pub struct RemoteVfs {
    name: String,
    inner: Arc<Inner>,
}

impl RemoteVfs {
    /// Connects to the page server, logs in, and registers the VFS with SQLite under `name`.
    pub fn register(name: &str, config: Config) -> Result<Self, Error> {
        check_name(name)?;
        let settings = match &config.store {
            Store::Server(settings) => settings.clone(),
            #[cfg(target_arch = "wasm32")]
            Store::Local { .. } => return Err(Error::new("local databases need RemoteVfs::register_async")),
        };
        let client_config = client_config(&settings, config.timeout);
        let client = Client::connect(client_config).map_err(|err| Error::client(&settings.url, err))?;
        Self::finish(name, config, server_backend(settings, client, None))
    }

    /// Browser variant of `register`. Starts the connection worker. With a server, also connects and logs in.
    ///
    /// Starting a worker needs a running event loop. Call this before opening a database: while SQLite runs, the
    /// SQLite worker is blocked and cannot start a worker.
    #[cfg(target_arch = "wasm32")]
    pub async fn register_async(name: &str, config: Config) -> Result<Self, Error> {
        check_name(name)?;
        match &config.store {
            Store::Server(settings) => {
                let settings = settings.clone();
                let client_config = client_config(&settings, config.timeout);
                let url = settings.url.clone();
                let (transport, cache) = crate::transport::start(&client_config)
                    .await
                    .map_err(|err| Error::new(format!("{url}: {err}")))?;
                let client =
                    Client::with_transport(transport, client_config).map_err(|err| Error::client(&url, err))?;
                Self::finish(name, config, server_backend(settings, client, Some(cache)))
            }
            Store::Local { namespace } => {
                if namespace.is_empty() || namespace.contains('/') {
                    return Err(Error::new(format!(
                        "invalid namespace {namespace:?}: it must not be empty or contain '/'"
                    )));
                }
                let bridge = crate::transport::start_local(namespace, config.timeout)
                    .await
                    .map_err(Error::new)?;
                Self::finish(name, config, Backend::Local(bridge))
            }
        }
    }

    /// Creates the shared state, registers the VFS with SQLite and starts the ping thread.
    fn finish(name: &str, config: Config, backend: Backend) -> Result<Self, Error> {
        // In a browser `Inner` is used by a single worker, and its transport holds JavaScript values, which are
        // neither `Send` nor `Sync`.
        #[cfg_attr(target_arch = "wasm32", allow(clippy::arc_with_non_send_sync))]
        let inner = Arc::new(Inner {
            config,
            backend,
            files: Mutex::new(Files::default()),
            stats: Mutex::new(Stats::default()),
            closed: AtomicBool::new(false),
        });
        // SAFETY: `Io`, `Vfs` and their callbacks agree on the VFS version, the file layout and the app data type.
        // `into_raw` keeps the VFS registered for the rest of the process, because SQLite may still hold open files.
        // The app data therefore outlives every open file.
        unsafe { register_vfs::<Io, Vfs>(name, Arc::clone(&inner), false) }
            .map_err(|err| Error::new(err.to_string()))?
            .into_raw();
        spawn_pinger(Arc::clone(&inner));
        Ok(RemoteVfs {
            name: name.into(),
            inner,
        })
    }

    /// Name of the VFS in SQLite. SQLite itself does not encrypt; SQLCipher encrypts databases opened with this name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Name of the encrypting VFS that SQLite3 Multiple Ciphers creates above this VFS on first use. Works only if
    /// the linked SQLite is SQLite3 Multiple Ciphers.
    pub fn encrypted_name(&self) -> String {
        format!("multipleciphers-{}", self.name)
    }

    /// Block ranges fetched from the server so far, in order. Empty unless [`Server::trace_fetches`] is set.
    pub fn fetch_trace(&self) -> Vec<(u64, u64)> {
        match &self.inner.backend {
            Backend::Server(server) => lock(&server.client).fetch_trace(),
            #[cfg(target_arch = "wasm32")]
            Backend::Local(_) => Vec::new(),
        }
    }

    /// Returns the current counters.
    pub fn stats(&self) -> Stats {
        *lock(&self.inner.stats)
    }

    /// Deletes the database `name`: on the server together with its cache, or locally. The database must not be open
    /// on this VFS.
    ///
    /// While another instance has it open, deleting fails unless [`Config::takeover`] is set; that instance then can
    /// no longer commit. Deleting a database that does not exist succeeds. Opening `name` again with
    /// `SQLITE_OPEN_CREATE` creates it empty, and it may then use another page size and another key.
    pub fn delete_database(&self, name: &str) -> Result<(), Error> {
        crate::vfs::delete_database(&self.inner, name)
    }

    /// Marks the connection to the server as broken, as after a network failure. The next request reconnects. For
    /// tests.
    #[doc(hidden)]
    pub fn drop_connection(&self) {
        match &self.inner.backend {
            Backend::Server(server) => lock(&server.client).disconnect(),
            #[cfg(target_arch = "wasm32")]
            Backend::Local(_) => {}
        }
    }
}

impl Drop for RemoteVfs {
    /// Stops the ping thread. The VFS stays registered, because SQLite may still use it.
    fn drop(&mut self) {
        self.inner.closed.store(true, Ordering::Relaxed);
    }
}

/// Rejects a name SQLite already knows.
fn check_name(name: &str) -> Result<(), Error> {
    // SAFETY: the lookup only reads SQLite's list of VFSes. The caller registers a VFS once, from one thread, so the
    // lookup does not run concurrently with a registration.
    if unsafe { registered_vfs(name) }
        .map_err(|err| Error::new(err.to_string()))?
        .is_some()
    {
        return Err(Error::new(format!("a VFS named {name} is already registered")));
    }
    Ok(())
}

/// Client settings for a server, with a random instance identifier unless one is set.
fn client_config(settings: &Server, timeout: Duration) -> ClientConfig {
    let instance_id = settings.instance_id.unwrap_or_else(|| {
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).expect("OS randomness");
        id
    });
    ClientConfig {
        url: settings.url.clone(),
        signer: Arc::clone(&settings.signer),
        token: settings.token.clone(),
        instance_id,
        timeout,
        trace_fetches: settings.trace_fetches,
        #[cfg(not(target_arch = "wasm32"))]
        extra_roots: settings.extra_roots.clone(),
    }
}

fn server_backend(settings: Server, client: Client, cache: Option<Box<dyn crate::local::LocalStore>>) -> Backend {
    Backend::Server(ServerBackend {
        settings,
        client: Mutex::new(client),
        browser_cache: Mutex::new(cache),
    })
}

/// Starts a thread that pings the server while SQLite is idle, to keep the connection and the leases alive.
///
/// Native only. In a browser the connection worker sends the pings.
#[cfg(not(target_arch = "wasm32"))]
fn spawn_pinger(inner: Arc<Inner>) {
    use sqlite_remote_protocol::v1 as pb;

    let spawned = std::thread::Builder::new()
        .name("sqlite-remote-vfs-ping".into())
        .spawn(move || {
            let server = inner.server();
            while !inner.closed.load(Ordering::Relaxed) {
                let interval = lock(&server.client).limits().ping_interval;
                platform::sleep(interval / 2);
                let mut client = lock(&server.client);
                if client.is_open() && client.idle_for() >= interval / 2 {
                    let now = platform::epoch_millis().max(0) as u64;
                    // A failed ping marks the connection as broken. The next commit reconnects and resumes the
                    // databases.
                    let _ = client.call(pb::client_frame::Body::Ping(pb::Ping { client_time_ms: now }));
                }
            }
        });
    // If the thread cannot be started, there are no pings. Commits still renew the leases.
    drop(spawned);
}

#[cfg(target_arch = "wasm32")]
fn spawn_pinger(_inner: Arc<Inner>) {}
