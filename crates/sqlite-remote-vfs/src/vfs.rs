//! SQLite VFS built on rsqlite-vfs. The main database file is a [`Database`] on the page server. Journals and
//! temporary files are kept in memory.
//!
//! SQLite holds a file handle from `xOpen` until `xClose`. The handle of the main database file carries the shared
//! VFS state and the `Database`. The commit runs in `xFileControl` on `SQLITE_FCNTL_SYNC`.

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
use crate::database::{Database, OpenOptions};
use crate::platform;
use crate::{Config, Load, Local, Memory, Stats};

pub(crate) struct Inner {
    pub config: Config,
    /// Local copy held by the connection worker, in a browser only. It is passed to the database when it is opened.
    /// Natively, the local copy is the file named in `Config::local`.
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    pub browser_local: Mutex<Option<Box<dyn crate::local::LocalStore>>>,
    pub client: Mutex<Client>,
    pub files: Mutex<Files>,
    pub stats: Mutex<Stats>,
    pub closed: AtomicBool,
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
    db: Database,
}

impl MainFile {
    /// Commits the transaction to the server. On failure, SQLite gets `SQLITE_IOERR_FSYNC` and rolls back, as on a
    /// failing disk.
    fn commit(&mut self) -> VfsResult<()> {
        let timeout = self.inner.config.reconnect_timeout;
        self.db
            .commit(&mut lock(&self.inner.client), timeout, &mut lock(&self.inner.stats))
            .map_err(|broken| io_error(VfsErrorCode::IoSync, format!("commit failed: {broken:?}")))
    }
}

impl VfsFile for RemoteFile {
    fn read(&mut self, buf: &mut [u8], offset: u64) -> VfsResult<usize> {
        match self {
            RemoteFile::Main(main) => {
                let full = main
                    .db
                    .read(&mut lock(&main.inner.client), buf, offset, &mut lock(&main.inner.stats))
                    .map_err(|broken| io_error(VfsErrorCode::IoRead, format!("{broken:?}")))?;
                if full {
                    return Ok(buf.len());
                }
                // Short read past the end of the file. `buf` is zero-filled from there. Return the bytes read.
                let available = main.db.file_size().saturating_sub(offset).min(buf.len() as u64);
                Ok(available as usize)
            }
            RemoteFile::Temp(temp) => lock(temp).read(buf, offset),
        }
    }

    fn write(&mut self, buf: &[u8], offset: u64) -> VfsResult<()> {
        match self {
            RemoteFile::Main(main) => main
                .db
                .write(&mut lock(&main.inner.client), buf, offset, &mut lock(&main.inner.stats))
                .map_err(|broken| io_error(VfsErrorCode::IoWrite, format!("{broken:?}"))),
            RemoteFile::Temp(temp) => lock(temp).write(buf, offset),
        }
    }

    fn truncate(&mut self, size: u64) -> VfsResult<()> {
        match self {
            RemoteFile::Main(main) => main
                .db
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
            RemoteFile::Main(main) => Ok(main.db.file_size()),
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
                main.db.close(&mut lock(&main.inner.client));
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

/// Creates the local copy store configured in `Config::local`.
fn local_store(data: &AppData) -> Option<Box<dyn crate::local::LocalStore>> {
    match &data.config.local {
        Local::None => None,
        #[cfg(not(target_arch = "wasm32"))]
        Local::File(path) => Some(Box::new(crate::local::FileStore::new(path))),
        // Held by the connection worker. It was passed in when the VFS was registered.
        #[cfg(target_arch = "wasm32")]
        Local::Browser => lock(&data.browser_local).take(),
    }
}

/// Opens the database on the page server. Fails if this VFS already has a database open.
fn open_database(data: &AppData, name: &str, create: bool) -> VfsResult<Database> {
    let mut files = lock(&data.files);
    if let Some(open) = &files.database {
        let reason = if open == name {
            format!("{name} is already open; only one connection per database is supported")
        } else {
            format!("{open} is already open on this VFS; only one database per VFS is supported")
        };
        return Err(io_error(VfsErrorCode::CantOpen, reason));
    }

    let mut client = lock(&data.client);
    if !client.is_connected() {
        client
            .reconnect()
            .map_err(|err| io_error(VfsErrorCode::CantOpen, err.to_string()))?;
    }
    let options = OpenOptions {
        page_size: data.config.page_size,
        create,
        takeover: data.config.takeover,
        blocks_per_fetch: match data.config.load {
            Load::Preload => None,
            Load::OnDemand { blocks_per_fetch } => Some(blocks_per_fetch.max(1)),
        },
        cap: match data.config.memory {
            Memory::Unlimited => None,
            Memory::Blocks(blocks) => Some(blocks),
        },
        subject: crate::subject(&*data.config.signer),
        local: local_store(data),
    };
    match Database::open(&mut client, name, options, &mut lock(&data.stats)) {
        Ok(db) => {
            files.database = Some(name.into());
            Ok(db)
        }
        Err(err) if err.is_lease_held() => Err(io_error(VfsErrorCode::Busy, err.to_string())),
        Err(err) => Err(io_error(VfsErrorCode::CantOpen, err.to_string())),
    }
}
