//! SQLite VFS that stores the database file on a remote page server.
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
//! operating system and those in `Config::extra_roots`.
//!
//! Current limits: one database per registered VFS, one connection per database.

mod client;
mod database;
mod identity;
mod local;
mod platform;
mod transport;
mod vfs;

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rsqlite_vfs::{register_vfs, registered_vfs};

pub use crate::identity::{Algorithm, Shared, Signer, subject};

use crate::client::{Client, ClientConfig};
use crate::vfs::{Files, Inner, Io, Vfs, lock};

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
    /// reloaded on demand from the local copy, or from the server if the local copy does not have them. Blocks
    /// modified since the last commit are never evicted, because the server does not have them yet.
    ///
    /// Most useful together with a [`Local`] copy, which reloads a block in a fraction of a millisecond.
    Blocks(u64),
}

/// Optional local copy of the database. Reads it can serve need no network round trip.
///
/// The server is authoritative. Blocks are written to the local copy only after the server has acknowledged the
/// commit. A missing, outdated or damaged local copy therefore only causes additional fetches from the server.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Local {
    /// No local copy. Every block is fetched from the server.
    #[default]
    None,
    /// Local copy in this file.
    #[cfg(not(target_arch = "wasm32"))]
    File(std::path::PathBuf),
    /// Local copy in IndexedDB, managed by the connection worker.
    #[cfg(target_arch = "wasm32")]
    Browser,
}

/// Configuration for [`RemoteVfs`].
#[derive(Clone, Debug)]
pub struct Config {
    /// WebSocket URL of the page server, e.g. `wss://vfs.example/v1/ws`. `ws://` is for a server on the same machine
    /// or behind a proxy that terminates TLS.
    pub url: String,
    /// Signer for the login. The server derives the subject that owns the databases from its public key.
    pub signer: Arc<dyn Signer>,
    /// Identifier of this client instance. Random if `None`.
    pub instance_id: Option<[u8; 16]>,
    /// Page size for new databases. SQLite3 Multiple Ciphers uses 4096 in SQLCipher format.
    pub page_size: u32,
    /// When blocks are loaded from the server.
    pub load: Load,
    /// Optional local copy. It may be incomplete: blocks it does not have are fetched from the server and then added
    /// to it.
    pub local: Local,
    /// Limit on the number of blocks kept in memory.
    pub memory: Memory,
    /// Take the lease even if another instance holds it.
    pub takeover: bool,
    /// Record the block ranges of every fetch, readable with [`RemoteVfs::fetch_trace`]. Useful for analysing the
    /// round trips of a query. The list grows for the lifetime of the VFS.
    pub trace_fetches: bool,
    /// Timeout for connecting and for each response.
    pub timeout: Duration,
    /// How long a commit tries to reconnect before it fails.
    pub reconnect_timeout: Duration,
    /// Additional DER-encoded CA certificates to trust for `wss://`, on top of those of the operating system. Needed
    /// when the server certificate is issued by a CA the system does not know, for example an organisation's
    /// internal CA. Not available in a browser, where the browser decides which CAs to trust.
    #[cfg(not(target_arch = "wasm32"))]
    pub extra_roots: Vec<Vec<u8>>,
}

impl Config {
    /// Returns a configuration with the defaults: page size 4096, preload, no local copy, no memory limit, no
    /// takeover, 10 s timeout and 10 s reconnect timeout.
    pub fn new(url: impl Into<String>, signer: Arc<dyn Signer>) -> Self {
        Config {
            url: url.into(),
            signer,
            instance_id: None,
            page_size: 4096,
            load: Load::Preload,
            local: Local::None,
            memory: Memory::Unlimited,
            takeover: false,
            trace_fetches: false,
            timeout: Duration::from_secs(10),
            reconnect_timeout: Duration::from_secs(10),
            #[cfg(not(target_arch = "wasm32"))]
            extra_roots: Vec::new(),
        }
    }
}

/// Counters for measurements, totals since registration.
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
pub struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
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
        let client_config = Self::prepare(name, &config)?;
        let url = config.url.clone();
        let client = Client::connect(client_config).map_err(|err| Error(format!("{url}: {err}")))?;
        Self::finish(name, config, client, None)
    }

    /// Browser variant of `register`. Starts the connection worker, connects and logs in.
    ///
    /// Starting a worker needs a running event loop. Call this before opening a database: while SQLite runs, the
    /// SQLite worker is blocked and cannot start a worker.
    #[cfg(target_arch = "wasm32")]
    pub async fn register_async(name: &str, config: Config) -> Result<Self, Error> {
        let client_config = Self::prepare(name, &config)?;
        let url = config.url.clone();
        let (transport, local) = crate::transport::start(&client_config)
            .await
            .map_err(|err| Error(format!("{url}: {err}")))?;
        let client = Client::with_transport(transport, client_config).map_err(|err| Error(format!("{url}: {err}")))?;
        Self::finish(name, config, client, Some(local))
    }

    /// Rejects a name SQLite already knows and chooses the instance identifier.
    fn prepare(name: &str, config: &Config) -> Result<ClientConfig, Error> {
        // SAFETY: the lookup only reads SQLite's list of VFSes. The caller registers a VFS once, from one thread, so
        // the lookup does not run concurrently with a registration.
        if unsafe { registered_vfs(name) }
            .map_err(|err| Error(err.to_string()))?
            .is_some()
        {
            return Err(Error(format!("a VFS named {name} is already registered")));
        }
        let instance_id = config.instance_id.unwrap_or_else(|| {
            let mut id = [0u8; 16];
            getrandom::fill(&mut id).expect("OS randomness");
            id
        });
        Ok(ClientConfig {
            url: config.url.clone(),
            signer: Arc::clone(&config.signer),
            instance_id,
            timeout: config.timeout,
            trace_fetches: config.trace_fetches,
            #[cfg(not(target_arch = "wasm32"))]
            extra_roots: config.extra_roots.clone(),
        })
    }

    /// Creates the shared state, registers the VFS with SQLite and starts the ping thread.
    fn finish(
        name: &str,
        config: Config,
        client: Client,
        local: Option<Box<dyn crate::local::LocalStore>>,
    ) -> Result<Self, Error> {
        // In a browser `Inner` is used by a single worker, and its transport holds JavaScript values, which are
        // neither `Send` nor `Sync`.
        #[cfg_attr(target_arch = "wasm32", allow(clippy::arc_with_non_send_sync))]
        let inner = Arc::new(Inner {
            config,
            client: Mutex::new(client),
            files: Mutex::new(Files::default()),
            stats: Mutex::new(Stats::default()),
            browser_local: Mutex::new(local),
            closed: AtomicBool::new(false),
        });
        // SAFETY: `Io`, `Vfs` and their callbacks agree on the VFS version, the file layout and the app data type.
        // `into_raw` keeps the VFS registered for the rest of the process, because SQLite may still hold open files.
        // The app data therefore outlives every open file.
        unsafe { register_vfs::<Io, Vfs>(name, Arc::clone(&inner), false) }
            .map_err(|err| Error(err.to_string()))?
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

    /// Block ranges fetched so far, in order. Empty unless [`Config::trace_fetches`] is set.
    pub fn fetch_trace(&self) -> Vec<(u64, u64)> {
        lock(&self.inner.client).fetch_trace()
    }

    /// Returns the current counters.
    pub fn stats(&self) -> Stats {
        *lock(&self.inner.stats)
    }

    /// Deletes the database `name` on the server, and its local copy. The database must not be open on this VFS.
    ///
    /// While another instance holds an unexpired lease on it, deleting fails unless [`Config::takeover`] is set; that
    /// instance then can no longer commit. Deleting a database that does not exist succeeds. Opening `name` again
    /// with `SQLITE_OPEN_CREATE` creates it empty, and it may then use another page size and another key.
    pub fn delete_database(&self, name: &str) -> Result<(), Error> {
        crate::vfs::delete_database(&self.inner, name).map_err(Error)
    }

    /// Marks the connection as broken, as after a network failure. The next request reconnects. For tests.
    #[doc(hidden)]
    pub fn drop_connection(&self) {
        lock(&self.inner.client).disconnect();
    }
}

impl Drop for RemoteVfs {
    /// Stops the ping thread. The VFS stays registered, because SQLite may still use it.
    fn drop(&mut self) {
        self.inner.closed.store(true, Ordering::Relaxed);
    }
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
            while !inner.closed.load(Ordering::Relaxed) {
                let interval = lock(&inner.client).limits().ping_interval;
                platform::sleep(interval / 2);
                let mut client = lock(&inner.client);
                if client.is_connected() && client.idle_for() >= interval / 2 {
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
