//! SQLite VFS built on rsqlite-vfs. The main database file is a [`Database`] on the page server or, in a browser, a
//! local database in IndexedDB. Journals and temporary files are kept in memory.
//!
//! SQLite holds a file handle from `xOpen` until `xClose`. The handle of the main database file carries the shared
//! VFS state and the database. The commit runs in `xFileControl` on `SQLITE_FCNTL_SYNC`.

#![allow(non_snake_case)] // SQLite's callback names

use std::collections::BTreeMap;
use std::ffi::{c_int, c_void};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use rsqlite_vfs::ffi::{SQLITE_FCNTL_SYNC, SQLITE_IOERR_FSYNC, SQLITE_NOTFOUND, SQLITE_OK, sqlite3_file};
use rsqlite_vfs::{
    AccessMode, FileKind, LockLevel, MemChunksFile, OpenOptions as FileOptions, OpenRequest, OpenedFile, OsCallback,
    SQLiteIoMethods, SQLiteVfs, SQLiteVfsFile, SyncOptions, VfsError, VfsErrorCode, VfsFile, VfsResult, VfsStore,
};

use crate::client::Client;
use crate::database::{Broken, Database, OpenOptions};
#[cfg(target_arch = "wasm32")]
use crate::local_database::{LocalDatabase, LocalOptions};
use crate::platform;
use crate::{Cache, Config, Failure, Load, Memory, Server, Stats};

pub(crate) struct Inner {
    pub config: Config,
    pub backend: Backend,
    pub files: Mutex<Files>,
    pub stats: Mutex<Stats>,
    /// Why the open database broke, if it did. Set after a failed operation, cleared when a database is opened.
    pub failure: Mutex<Option<Failure>>,
    pub closed: AtomicBool,
}

/// Where the databases of a VFS are stored.
pub(crate) enum Backend {
    Server(ServerBackend),
    /// Only in this browser, in IndexedDB.
    #[cfg(target_arch = "wasm32")]
    Local(crate::transport::LocalBridge),
}

/// Connection to the page server.
pub(crate) struct ServerBackend {
    pub settings: Server,
    pub client: Mutex<Client>,
    /// Cache held by the connection worker, in a browser only. It is passed to the database when it is opened.
    /// Natively, the cache is the file named in `Server::cache`.
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    pub browser_cache: Mutex<Option<Box<dyn crate::local::LocalStore>>>,
}

impl Inner {
    /// The server backend. Only files and operations of a VFS with a server call this.
    pub fn server(&self) -> &ServerBackend {
        match &self.backend {
            Backend::Server(server) => server,
            #[cfg(target_arch = "wasm32")]
            Backend::Local(_) => unreachable!("a VFS for local databases has no server"),
        }
    }
}

/// Files open on this VFS.
///
/// Lock order for the mutexes in `Inner`: `files`, then `client`, then `stats`. The ping thread locks only `client`.
#[derive(Default)]
pub(crate) struct Files {
    /// Name of the open main database. A VFS can have only one database open.
    database: Option<String>,
    /// Journals and temporary files by name. Open handles hold their own `Arc`, so a name can be reused while a
    /// handle to the old file is still open.
    temps: BTreeMap<String, Arc<Mutex<MemChunksFile>>>,
}

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) type AppData = Arc<Inner>;

fn io_error(code: VfsErrorCode, message: impl Into<String>) -> VfsError {
    VfsError::new(code, message.into().into())
}

/// The error SQLite gets for a failed read or write: `SQLITE_PERM` for refused plaintext, otherwise `code`.
fn broken_error(broken: &Broken, code: VfsErrorCode) -> VfsError {
    match broken {
        Broken::Plaintext => io_error(
            VfsErrorCode::Permission,
            "plaintext refused: page 1 carries an unencrypted SQLite header, see Config::refuse_plaintext",
        ),
        other => io_error(code, format!("{other:?}")),
    }
}

/// Whether `page` starts with an unencrypted SQLite file header: the magic string, the fixed bytes 21 to 23 and the
/// 20 reserved bytes from 72 on, which are zero. Encryption above the VFS leaves none of these intact: SQLCipher and
/// SQLite3 Multiple Ciphers replace the magic string with a salt or encrypt from byte 24 on at the latest. Only a
/// plaintext header (`cipher_plaintext_header_size`) of 96 bytes or more would pass as plaintext, which is nothing
/// a database that is meant to be encrypted uses.
fn plaintext_header(page: &[u8]) -> bool {
    page.len() >= 92
        && page.starts_with(b"SQLite format 3\0")
        && page[21..24] == [64, 32, 32]
        && page[72..92].iter().all(|&byte| byte == 0)
}

// -------------------------------------------------------------------------------------------------------------------
// Files
// -------------------------------------------------------------------------------------------------------------------

/// A file opened by SQLite: the main database on the page server, or a journal or temporary file in memory.
pub(crate) enum RemoteFile {
    Main(Box<MainFile>),
    Temp(Arc<Mutex<MemChunksFile>>),
}

/// The main database file. Holds the shared VFS state, so that every callback can reach the client and the stats.
pub(crate) struct MainFile {
    inner: Arc<Inner>,
    db: Db,
}

/// An open main database. `Db::Server` exists only on a VFS with a server.
enum Db {
    Server(Database),
    #[cfg(target_arch = "wasm32")]
    Local(LocalDatabase),
}

impl MainFile {
    /// Commits the transaction. On failure, SQLite gets `SQLITE_IOERR_FSYNC`, `SQLITE_FULL` if the storage quota is
    /// exhausted, or `SQLITE_AUTH` if the server rejects the access token, and rolls back, as on a failing disk.
    fn commit(&mut self) -> Result<(), Broken> {
        self.heal();
        let result = match &mut self.db {
            Db::Server(db) => {
                let server = self.inner.server();
                db.commit(
                    &mut lock(&server.client),
                    server.settings.reconnect_timeout,
                    &mut lock(&self.inner.stats),
                )
            }
            #[cfg(target_arch = "wasm32")]
            Db::Local(db) => db.commit(&mut lock(&self.inner.stats)),
        };
        self.record(result)
    }

    fn read(&mut self, buf: &mut [u8], offset: u64) -> Result<bool, Broken> {
        self.heal();
        let result = match &mut self.db {
            Db::Server(db) => db.read(
                &mut lock(&self.inner.server().client),
                buf,
                offset,
                &mut lock(&self.inner.stats),
            ),
            #[cfg(target_arch = "wasm32")]
            Db::Local(db) => db.read(buf, offset, &mut lock(&self.inner.stats)),
        };
        if result.is_ok() && offset == 0 && self.refuses_plaintext(buf) {
            return Err(Broken::Plaintext);
        }
        self.record(result)
    }

    fn write(&mut self, data: &[u8], offset: u64) -> Result<(), Broken> {
        // Before the write reaches the blocks in memory, so that a commit cannot send it.
        if offset == 0 && self.refuses_plaintext(data) {
            return Err(Broken::Plaintext);
        }
        self.heal();
        let result = match &mut self.db {
            Db::Server(db) => db.write(
                &mut lock(&self.inner.server().client),
                data,
                offset,
                &mut lock(&self.inner.stats),
            ),
            #[cfg(target_arch = "wasm32")]
            Db::Local(db) => db.write(data, offset, &mut lock(&self.inner.stats)),
        };
        self.record(result)
    }

    fn truncate(&mut self, size: u64) -> Result<(), Broken> {
        self.heal();
        let result = match &mut self.db {
            Db::Server(db) => db.truncate(size),
            #[cfg(target_arch = "wasm32")]
            Db::Local(db) => db.truncate(size),
        };
        self.record(result)
    }

    /// Makes the database usable again if it broke because the server could not be reached, and the server has
    /// accepted a connection since. Otherwise leaves it broken, and the operation fails at once. Called before every
    /// operation on the database file, so that the first access after the server is back succeeds.
    fn heal(&mut self) {
        if let Db::Server(db) = &mut self.db
            && db.is_unreachable()
        {
            let mut client = lock(&self.inner.server().client);
            if !client.reachable() {
                return;
            }
            let healed = db.heal(&mut client, &mut lock(&self.inner.stats));
            drop(client);
            *lock(&self.inner.failure) = healed.err().as_ref().map(failure_of);
        }
    }

    /// With [`Config::refuse_plaintext`], whether `page1` carries an unencrypted SQLite header. If so, the failure
    /// is recorded for [`RemoteVfs::failure`]. The page is page 1 whenever the offset is 0: SQLite reads its header
    /// and writes it as a whole page.
    fn refuses_plaintext(&self, page1: &[u8]) -> bool {
        let refused = self.inner.config.refuse_plaintext && plaintext_header(page1);
        if refused {
            *lock(&self.inner.failure) = Some(Failure::Plaintext);
        }
        refused
    }

    /// Records why the database broke, if the operation that returned `result` broke it.
    fn record<T>(&self, result: Result<T, Broken>) -> Result<T, Broken> {
        if result.is_err() {
            let broken = match &self.db {
                Db::Server(db) => db.broken(),
                #[cfg(target_arch = "wasm32")]
                Db::Local(db) => db.broken(),
            };
            if let Some(broken) = broken {
                *lock(&self.inner.failure) = Some(failure_of(broken));
            }
        }
        result
    }

    fn file_size(&self) -> u64 {
        match &self.db {
            Db::Server(db) => db.file_size(),
            #[cfg(target_arch = "wasm32")]
            Db::Local(db) => db.file_size(),
        }
    }
}

impl VfsFile for RemoteFile {
    fn read(&mut self, buf: &mut [u8], offset: u64) -> VfsResult<usize> {
        match self {
            RemoteFile::Main(main) => {
                let full = main
                    .read(buf, offset)
                    .map_err(|broken| broken_error(&broken, VfsErrorCode::IoRead))?;
                if full {
                    return Ok(buf.len());
                }
                // Short read past the end of the file. `buf` is zero-filled from there. Return the bytes read.
                let available = main.file_size().saturating_sub(offset).min(buf.len() as u64);
                Ok(available as usize)
            }
            RemoteFile::Temp(temp) => lock(temp).read(buf, offset),
        }
    }

    fn write(&mut self, buf: &[u8], offset: u64) -> VfsResult<()> {
        match self {
            RemoteFile::Main(main) => main
                .write(buf, offset)
                .map_err(|broken| broken_error(&broken, VfsErrorCode::IoWrite)),
            RemoteFile::Temp(temp) => lock(temp).write(buf, offset),
        }
    }

    fn truncate(&mut self, size: u64) -> VfsResult<()> {
        match self {
            RemoteFile::Main(main) => main
                .truncate(size)
                .map_err(|broken| io_error(VfsErrorCode::IoTruncate, format!("{broken:?}"))),
            RemoteFile::Temp(temp) => lock(temp).truncate(size),
        }
    }

    /// No-op for the main database file. The commit happens on `SQLITE_FCNTL_SYNC`, which SQLite sends before `xSync`
    /// and also with `synchronous=OFF`.
    fn sync(&mut self, options: SyncOptions) -> VfsResult<()> {
        match self {
            RemoteFile::Main(_) => Ok(()),
            RemoteFile::Temp(temp) => lock(temp).sync(options),
        }
    }

    fn size(&self) -> VfsResult<u64> {
        match self {
            RemoteFile::Main(main) => Ok(main.file_size()),
            RemoteFile::Temp(temp) => lock(temp).size(),
        }
    }

    // Only one connection per database is supported, so the main database file needs no locking.
    fn lock(&mut self, level: LockLevel) -> VfsResult<()> {
        match self {
            RemoteFile::Main(_) => Ok(()),
            RemoteFile::Temp(temp) => lock(temp).lock(level),
        }
    }

    fn unlock(&mut self, level: LockLevel) -> VfsResult<()> {
        match self {
            RemoteFile::Main(_) => Ok(()),
            RemoteFile::Temp(temp) => lock(temp).unlock(level),
        }
    }

    fn check_reserved_lock(&self) -> VfsResult<bool> {
        match self {
            RemoteFile::Main(_) => Ok(false),
            RemoteFile::Temp(temp) => lock(temp).check_reserved_lock(),
        }
    }
}

// -------------------------------------------------------------------------------------------------------------------
// VfsStore
// -------------------------------------------------------------------------------------------------------------------

pub(crate) struct Store;

impl VfsStore for Store {
    type File = RemoteFile;
    type AppData = AppData;

    fn open_file(data: &AppData, request: OpenRequest<'_>) -> VfsResult<OpenedFile<RemoteFile>> {
        let options = request.options;
        let Some(filename) = request.filename else {
            // Anonymous temporary file, kept in memory.
            return Ok(OpenedFile {
                file: RemoteFile::Temp(Arc::new(Mutex::new(MemChunksFile::default()))),
                access: options.access(),
            });
        };
        let name = filename.path();

        if options.kind() == Some(FileKind::MainDb) {
            let db = open_database(data, name, options.create())?;
            return Ok(OpenedFile {
                file: RemoteFile::Main(Box::new(MainFile {
                    inner: Arc::clone(data),
                    db,
                })),
                access: options.access(),
            });
        }

        let mut files = lock(&data.files);
        let temp = match files.temps.get(name) {
            Some(_) if options.exclusive() => {
                return Err(io_error(VfsErrorCode::CantOpen, format!("{name} already exists")));
            }
            Some(temp) => Arc::clone(temp),
            None if options.create() => {
                let temp = Arc::new(Mutex::new(MemChunksFile::default()));
                files.temps.insert(name.into(), Arc::clone(&temp));
                temp
            }
            None => return Err(io_error(VfsErrorCode::CantOpen, format!("{name} does not exist"))),
        };
        Ok(OpenedFile {
            file: RemoteFile::Temp(temp),
            access: options.access(),
        })
    }

    fn close_file(data: &AppData, name: Option<&str>, file: RemoteFile, options: FileOptions) -> VfsResult<()> {
        match file {
            RemoteFile::Main(main) => {
                match main.db {
                    #[cfg_attr(not(target_arch = "wasm32"), allow(unused_mut))]
                    Db::Server(mut db) => {
                        db.close(&mut lock(&data.server().client));
                        // In a browser the cache store exists once per VFS. Hand it back for the next database.
                        #[cfg(target_arch = "wasm32")]
                        if let Some(mut store) = db.take_local() {
                            // The connection worker confirms cache writes before it stores them. Wait for them, so
                            // that another VFS that opens the database next finds the cache complete.
                            let _ = store.flush();
                            *lock(&data.server().browser_cache) = Some(store);
                        }
                    }
                    #[cfg(target_arch = "wasm32")]
                    Db::Local(db) => db.close(),
                }
                lock(&data.files).database = None;
            }
            RemoteFile::Temp(temp) => {
                if options.delete_on_close()
                    && let Some(name) = name
                {
                    let mut files = lock(&data.files);
                    // Do not delete a file that was created under the same name in the meantime.
                    if files.temps.get(name).is_some_and(|current| Arc::ptr_eq(current, &temp)) {
                        files.temps.remove(name);
                    }
                }
            }
        }
        Ok(())
    }

    fn access(data: &AppData, name: &str, _mode: AccessMode) -> VfsResult<bool> {
        let files = lock(&data.files);
        Ok(files.database.as_deref() == Some(name) || files.temps.contains_key(name))
    }

    /// Returns the name unchanged. The VFS has a flat namespace.
    fn full_pathname(_data: &AppData, name: &str) -> VfsResult<String> {
        Ok(name.into())
    }

    fn delete_file(data: &AppData, name: &str, _sync_dir: bool) -> VfsResult<()> {
        match lock(&data.files).temps.remove(name) {
            Some(_) => Ok(()),
            None => Err(io_error(VfsErrorCode::IoDelete, format!("{name} cannot be deleted"))),
        }
    }
}

pub(crate) struct Io;

impl SQLiteIoMethods for Io {
    type Store = Store;

    /// Commits on `SQLITE_FCNTL_SYNC`. Returns `SQLITE_NOTFOUND` for all other operations, so that SQLite uses its
    /// defaults.
    unsafe extern "C" fn xFileControl(pFile: *mut sqlite3_file, op: c_int, _pArg: *mut c_void) -> c_int {
        if op != SQLITE_FCNTL_SYNC {
            return SQLITE_NOTFOUND;
        }
        // SAFETY: SQLite passes a file opened by `xOpen`, whose handle is a `RemoteFile`.
        let file = unsafe { (*SQLiteVfsFile::from_file(pFile)).handle_mut::<RemoteFile>() };
        let RemoteFile::Main(main) = file else {
            return SQLITE_NOTFOUND;
        };
        match main.commit() {
            Ok(()) => SQLITE_OK,
            #[cfg(target_arch = "wasm32")]
            Err(Broken::Full(_)) => rsqlite_vfs::ffi::SQLITE_FULL,
            Err(Broken::Denied(_)) => rsqlite_vfs::ffi::SQLITE_AUTH,
            Err(_) => SQLITE_IOERR_FSYNC,
        }
    }
}

// -------------------------------------------------------------------------------------------------------------------
// VFS and OS callbacks
// -------------------------------------------------------------------------------------------------------------------

/// OS callbacks for SQLite: sleep, randomness and time. See [`crate::platform`] for the browser implementation.
pub(crate) struct Os;

static OS: Os = Os;

impl OsCallback for Os {
    fn sleep(&self, dur: Duration) {
        platform::sleep(dur);
    }

    fn random(&self, buf: &mut [u8]) -> usize {
        getrandom::fill(buf).expect("OS randomness");
        buf.len()
    }

    fn epoch_timestamp_in_ms(&self) -> VfsResult<i64> {
        Ok(platform::epoch_millis())
    }
}

pub(crate) struct Vfs;

impl SQLiteVfs<Io> for Vfs {
    type Os = Os;

    fn os(_data: &AppData) -> &Self::Os {
        &OS
    }
}

/// Creates the cache store configured in `Server::cache` and selects database `name` in it.
fn cache_store(data: &AppData, name: &str) -> Option<Box<dyn crate::local::LocalStore>> {
    let server = data.server();
    let mut store: Box<dyn crate::local::LocalStore> = match &server.settings.cache {
        Cache::None => return None,
        #[cfg(not(target_arch = "wasm32"))]
        Cache::File(path) => Box::new(crate::local::FileStore::new(path)),
        // Held by the connection worker. It was passed in when the VFS was registered and keeps one IndexedDB database
        // per database name.
        #[cfg(target_arch = "wasm32")]
        Cache::Browser => lock(&server.browser_cache).take()?,
    };
    match store.select(name) {
        Ok(()) => Some(store),
        // Without a cache the database is read from the server.
        Err(_) => {
            #[cfg(target_arch = "wasm32")]
            {
                *lock(&server.browser_cache) = Some(store);
            }
            None
        }
    }
}

/// Deletes a database. Fails if the database is open on this VFS.
pub(crate) fn delete_database(data: &AppData, name: &str) -> Result<(), crate::Error> {
    // Held throughout, so that the database cannot be opened while it is being deleted.
    let files = lock(&data.files);
    if files.database.as_deref() == Some(name) {
        return Err(crate::Error::new(format!(
            "{name} is open; close it before deleting it"
        )));
    }
    match &data.backend {
        Backend::Server(_) => delete_on_server(data, name),
        #[cfg(target_arch = "wasm32")]
        Backend::Local(bridge) => bridge
            .delete(name, data.config.takeover)
            .map_err(|refusal| crate::Error::new(format!("deleting {name}: {refusal}"))),
    }
}

/// Releases the owner's slot and deletes all databases of the key on the server. Fails if a database is open on this
/// VFS.
pub(crate) fn delete_slot(data: &AppData) -> Result<(), crate::Error> {
    // Held throughout, so that no database can be opened meanwhile.
    let files = lock(&data.files);
    if let Some(open) = &files.database {
        return Err(crate::Error::new(format!(
            "{open} is open; close it before deleting the slot"
        )));
    }
    with_client(data, "deleting the slot", Client::delete_slot)
}

/// Deletes a database on the page server, then its cache if the cache belongs to it.
fn delete_on_server(data: &AppData, name: &str) -> Result<(), crate::Error> {
    let server = data.server();
    {
        let mut client = lock(&server.client);
        if !client.is_connected() {
            client
                .reconnect()
                .map_err(|err| crate::Error::client("connecting", err))?;
        }
        client
            .delete(name, data.config.takeover)
            .map_err(|err| crate::Error::client(&format!("deleting {name}"), err))?;
    }

    let Some(mut store) = cache_store(data, name) else {
        return Ok(());
    };
    let subject = crate::subject(&*server.settings.signer);
    let result = match store.head() {
        Ok(Some(head)) if head.subject == subject && head.db_id == name => store.clear(),
        Ok(_) => Ok(()),
        Err(err) => Err(err),
    };
    #[cfg(target_arch = "wasm32")]
    {
        *lock(&server.browser_cache) = Some(store);
    }
    result.map_err(|err| {
        crate::Error::new(format!(
            "{name} was deleted on the server, but its cache was not: {err}"
        ))
    })
}

/// Reports the takeovers the client has learned of since the last call: if the database open on this VFS was taken
/// over, sets the failure to `TakenOver` and calls the listener. Takes the locks one after the other, never nested, and
/// calls the listener without holding any.
pub(crate) fn report_takeovers(data: &Inner) {
    let (revoked, listener) = match &data.backend {
        Backend::Server(server) => (
            lock(&server.client).take_unreported(),
            server.settings.on_takeover.clone(),
        ),
        #[cfg(target_arch = "wasm32")]
        Backend::Local(_) => return,
    };
    if revoked.is_empty() {
        return;
    }
    let open = lock(&data.files).database.clone();
    for db_id in revoked {
        if open.as_deref() != Some(db_id.as_str()) {
            continue;
        }
        *lock(&data.failure) = Some(Failure::TakenOver);
        if let Some(listener) = &listener {
            listener.taken_over(&db_id);
        }
    }
}

/// Handles a frame that the connection worker handed over as soon as it arrived. Browser only.
#[cfg(target_arch = "wasm32")]
pub(crate) fn on_push(data: &Inner, frame: &[u8]) {
    use prost::Message as _;
    use sqlite_remote_protocol::v1 as pb;

    let Ok(frame) = pb::ServerFrame::decode(frame) else {
        return;
    };
    if let Some(pb::server_frame::Body::LeaseRevoked(revoked)) = frame.body {
        lock(&data.server().client).note_revoked(revoked);
    }
    report_takeovers(data);
}

/// Runs `call` on the connection to the server, after reconnecting if it is broken. For requests that concern the
/// key rather than one database.
pub(crate) fn with_client<T>(
    data: &AppData,
    what: &str,
    call: impl FnOnce(&mut Client) -> Result<T, crate::client::ClientError>,
) -> Result<T, crate::Error> {
    match &data.backend {
        Backend::Server(server) => {
            let mut client = lock(&server.client);
            if !client.is_connected() {
                client
                    .reconnect()
                    .map_err(|err| crate::Error::client("connecting", err))?;
            }
            call(&mut client).map_err(|err| crate::Error::client(what, err))
        }
        #[cfg(target_arch = "wasm32")]
        Backend::Local(_) => Err(crate::Error::new(format!("{what}: local databases have no server"))),
    }
}

/// Opens the database on the page server or locally. Fails if this VFS already has a database open.
///
/// SQLite gets `SQLITE_CANTOPEN` only if the database does not exist and `create` is false, `SQLITE_BUSY` if another
/// instance has it open, `SQLITE_AUTH` if the server rejects the access token, and `SQLITE_PERM` if another key holds
/// the owner's slot. Every other failure, e.g. of the connection, is `SQLITE_IOERR`, so that an application can tell a
/// missing database from one it cannot reach.
fn open_database(data: &AppData, name: &str, create: bool) -> VfsResult<Db> {
    let mut files = lock(&data.files);
    if let Some(open) = &files.database {
        let reason = if open == name {
            format!("{name} is already open; only one connection per database is supported")
        } else {
            format!("{open} is already open on this VFS; only one database per VFS is supported")
        };
        return Err(io_error(VfsErrorCode::CantOpen, reason));
    }
    let db = match &data.backend {
        Backend::Server(server) => Db::Server(open_on_server(data, server, name, create)?),
        #[cfg(target_arch = "wasm32")]
        Backend::Local(bridge) => Db::Local(open_locally(data, bridge, name, create)?),
    };
    files.database = Some(name.into());
    *lock(&data.failure) = None;
    Ok(db)
}

/// The public reason for an internal one.
fn failure_of(broken: &Broken) -> Failure {
    match broken {
        Broken::Fenced => Failure::TakenOver,
        Broken::Uncertain(_) => Failure::Unreachable,
        Broken::Denied(_) => Failure::Denied,
        Broken::Diverged(_) | Broken::Refused(_) => Failure::Rejected,
        #[cfg(target_arch = "wasm32")]
        Broken::Full(_) => Failure::Full,
        Broken::Plaintext => Failure::Plaintext,
    }
}

fn blocks_per_fetch(config: &Config) -> Option<u64> {
    match config.load {
        Load::Preload => None,
        Load::OnDemand { blocks_per_fetch } => Some(blocks_per_fetch.max(1)),
    }
}

fn cap(config: &Config) -> Option<u64> {
    match config.memory {
        Memory::Unlimited => None,
        Memory::Blocks(blocks) => Some(blocks),
    }
}

fn open_on_server(data: &AppData, server: &ServerBackend, name: &str, create: bool) -> VfsResult<Database> {
    let mut client = lock(&server.client);
    if !client.is_connected() {
        client.reconnect().map_err(|err| {
            let code = if err.is_access_denied() {
                VfsErrorCode::Auth
            } else {
                VfsErrorCode::Io
            };
            io_error(code, err.to_string())
        })?;
    }
    let options = OpenOptions {
        page_size: data.config.page_size,
        create,
        takeover: data.config.takeover,
        blocks_per_fetch: blocks_per_fetch(&data.config),
        cap: cap(&data.config),
        subject: crate::subject(&*server.settings.signer),
        local: cache_store(data, name),
    };
    match Database::open(&mut client, name, options, &mut lock(&data.stats)) {
        Ok(db) => Ok(db),
        Err(err) if err.is_lease_held() => Err(io_error(VfsErrorCode::Busy, err.to_string())),
        Err(err) if err.is_slot_taken() => Err(io_error(VfsErrorCode::Permission, err.to_string())),
        Err(err) if err.is_not_found() => Err(io_error(VfsErrorCode::CantOpen, err.to_string())),
        Err(err) => Err(io_error(VfsErrorCode::Io, err.to_string())),
    }
}

#[cfg(target_arch = "wasm32")]
fn open_locally(
    data: &AppData,
    bridge: &crate::transport::LocalBridge,
    name: &str,
    create: bool,
) -> VfsResult<LocalDatabase> {
    use crate::transport::Refusal;

    let options = LocalOptions {
        page_size: data.config.page_size,
        create,
        takeover: data.config.takeover,
        blocks_per_fetch: blocks_per_fetch(&data.config),
        cap: cap(&data.config),
    };
    LocalDatabase::open(bridge.clone(), name, options, &mut lock(&data.stats)).map_err(|refusal| {
        let code = match refusal {
            Refusal::Busy => VfsErrorCode::Busy,
            Refusal::Missing => VfsErrorCode::CantOpen,
            _ => VfsErrorCode::Io,
        };
        io_error(code, format!("{name}: {refusal}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_reason_has_a_public_failure() {
        assert_eq!(failure_of(&Broken::Fenced), Failure::TakenOver);
        assert_eq!(failure_of(&Broken::Uncertain("gone".into())), Failure::Unreachable);
        assert_eq!(failure_of(&Broken::Denied("token".into())), Failure::Denied);
        assert_eq!(failure_of(&Broken::Diverged("version".into())), Failure::Rejected);
        assert_eq!(failure_of(&Broken::Plaintext), Failure::Plaintext);
        assert_eq!(failure_of(&Broken::Refused("too large".into())), Failure::Rejected);
    }

    /// Page 1 of an empty plain SQLite database with 4096-byte pages, as SQLite writes it.
    fn plain_page1() -> Vec<u8> {
        let mut page = vec![0u8; 4096];
        page[..16].copy_from_slice(b"SQLite format 3\0");
        page[16..18].copy_from_slice(&4096u16.to_be_bytes());
        page[18] = 1; // write version
        page[19] = 1; // read version
        page[21..24].copy_from_slice(&[64, 32, 32]);
        page[28..32].copy_from_slice(&1u32.to_be_bytes()); // page count
        page[47] = 4; // schema format
        page[59] = 1; // text encoding
        page[96..100].copy_from_slice(&3_050_000u32.to_be_bytes());
        page
    }

    #[test]
    fn plain_header_is_detected() {
        let page = plain_page1();
        assert!(plaintext_header(&page));
        assert!(plaintext_header(&page[..100]), "the 100-byte header read at open");
        assert!(!plaintext_header(&page[..91]), "too short to tell");
    }

    #[test]
    fn encrypted_headers_are_not_plaintext() {
        // SQLCipher and SQLite3 Multiple Ciphers with their default ciphers: a salt instead of the magic string.
        let mut salted = plain_page1();
        salted[..16].copy_from_slice(&[0x9a; 16]);
        assert!(!plaintext_header(&salted));

        // A cipher that keeps the first 24 bytes and encrypts the rest, as SQLite3 Multiple Ciphers' ChaCha20 does
        // from byte 24 on: the reserved bytes are not zero.
        let mut from_24 = plain_page1();
        for (index, byte) in from_24[24..].iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(31).wrapping_add(7);
        }
        assert!(!plaintext_header(&from_24));

        // A plaintext header of 32 bytes (`cipher_plaintext_header_size`): the reserved bytes are encrypted.
        let mut header_32 = from_24.clone();
        header_32[..32].copy_from_slice(&plain_page1()[..32]);
        assert!(!plaintext_header(&header_32));

        // Fully encrypted, including the magic string.
        let mut all = plain_page1();
        for (index, byte) in all.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(17).wrapping_add(3);
        }
        assert!(!plaintext_header(&all));
    }

    #[test]
    fn other_pages_and_zero_pages_are_not_plaintext() {
        assert!(!plaintext_header(&[0u8; 4096]), "a page that was never written");
        let mut page2 = vec![0u8; 4096];
        page2[0] = 13; // a leaf table b-tree page
        assert!(!plaintext_header(&page2));
    }
}
