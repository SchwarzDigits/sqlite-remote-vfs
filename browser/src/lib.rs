//! In-memory VFS for the browser tests.
//!
//! Keeps every file in memory, like the VFS in the native spike test. Tests read the stored bytes to check that
//! SQLite3 Multiple Ciphers encrypts everything that reaches the VFS.
//!
//! Differences from the native build:
//!
//! - **No threads.** SQLite is compiled single-threaded. A `JsValue` cannot be sent to another worker.
//! - **No sleep.** Blocking requires shared memory, so `xSleep` returns immediately.
//! - **No clock from `std`.** `SystemTime::now` panics on this target. The time comes from `Date.now()`.
//!
//! Random bytes come from the browser's Web Crypto API.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::Duration;

use rsqlite_vfs::{
    AccessMode, FileKind, LockLevel, MemChunksFile, OpenOptions, OpenRequest, OpenedFile, OsCallback, SQLiteIoMethods,
    SQLiteVfs, SyncOptions, VfsError, VfsErrorCode, VfsFile, VfsResult, VfsStore, register_vfs,
};

/// All files of the VFS, by name. The VFS runs on a single thread, so `Rc<RefCell<_>>` is sufficient.
#[derive(Default)]
struct State {
    files: BTreeMap<String, Rc<RefCell<MemChunksFile>>>,
}

type AppData = Rc<RefCell<State>>;

/// A file opened by SQLite.
struct BrowserFile {
    file: Rc<RefCell<MemChunksFile>>,
}

impl VfsFile for BrowserFile {
    fn read(&mut self, buf: &mut [u8], offset: u64) -> VfsResult<usize> {
        self.file.borrow_mut().read(buf, offset)
    }

    fn write(&mut self, buf: &[u8], offset: u64) -> VfsResult<()> {
        self.file.borrow_mut().write(buf, offset)
    }

    fn truncate(&mut self, size: u64) -> VfsResult<()> {
        self.file.borrow_mut().truncate(size)
    }

    fn sync(&mut self, options: SyncOptions) -> VfsResult<()> {
        self.file.borrow_mut().sync(options)
    }

    fn size(&self) -> VfsResult<u64> {
        self.file.borrow().size()
    }

    // Each database has a single connection, so locks need no coordination between connections.
    fn lock(&mut self, level: LockLevel) -> VfsResult<()> {
        self.file.borrow_mut().lock(level)
    }

    fn unlock(&mut self, level: LockLevel) -> VfsResult<()> {
        self.file.borrow_mut().unlock(level)
    }

    fn check_reserved_lock(&self) -> VfsResult<bool> {
        self.file.borrow().check_reserved_lock()
    }
}

struct Store;

impl VfsStore for Store {
    type File = BrowserFile;
    type AppData = AppData;

    fn open_file(data: &AppData, request: OpenRequest<'_>) -> VfsResult<OpenedFile<BrowserFile>> {
        let options = request.options;
        let Some(filename) = request.filename else {
            return Ok(OpenedFile {
                file: BrowserFile {
                    file: Rc::new(RefCell::new(MemChunksFile::default())),
                },
                access: options.access(),
            });
        };
        let name = filename.path();
        let mut state = data.borrow_mut();
        let file = match state.files.get(name) {
            Some(_) if options.exclusive() => {
                return Err(VfsError::new(VfsErrorCode::CantOpen, format!("{name} exists").into()));
            }
            Some(file) => Rc::clone(file),
            None if options.create() => {
                // `waiting_for_write` takes the chunk size from the first write. SQLite writes whole pages to the
                // main database, so the chunk size equals the page size.
                let file = Rc::new(RefCell::new(if options.kind() == Some(FileKind::MainDb) {
                    MemChunksFile::waiting_for_write()
                } else {
                    MemChunksFile::default()
                }));
                state.files.insert(name.into(), Rc::clone(&file));
                file
            }
            None => {
                return Err(VfsError::new(
                    VfsErrorCode::CantOpen,
                    format!("{name} does not exist").into(),
                ));
            }
        };
        Ok(OpenedFile {
            file: BrowserFile { file },
            access: options.access(),
        })
    }

    fn close_file(data: &AppData, name: Option<&str>, file: BrowserFile, options: OpenOptions) -> VfsResult<()> {
        if options.delete_on_close()
            && let Some(name) = name
        {
            let mut state = data.borrow_mut();
            // Remove the entry only if it is still this file. Another file may have been created under the same
            // name since.
            if state
                .files
                .get(name)
                .is_some_and(|current| Rc::ptr_eq(current, &file.file))
            {
                state.files.remove(name);
            }
        }
        Ok(())
    }

    fn access(data: &AppData, name: &str, _mode: AccessMode) -> VfsResult<bool> {
        Ok(data.borrow().files.contains_key(name))
    }

    fn full_pathname(_data: &AppData, name: &str) -> VfsResult<String> {
        Ok(name.into())
    }

    fn delete_file(data: &AppData, name: &str, _sync_dir: bool) -> VfsResult<()> {
        match data.borrow_mut().files.remove(name) {
            Some(_) => Ok(()),
            None => Err(VfsError::new(
                VfsErrorCode::IoDelete,
                format!("{name} not found").into(),
            )),
        }
    }
}

struct Io;

impl SQLiteIoMethods for Io {
    type Store = Store;
}

/// Platform functions for the VFS in the browser.
struct Os;

impl OsCallback for Os {
    /// Returns immediately. Blocking requires shared memory, and busy-waiting would block the tab. SQLite sleeps only
    /// while it waits for a lock, and with one connection per database there is no lock to wait for.
    fn sleep(&self, _dur: Duration) {}

    /// Fills `buf` from the Web Crypto API through `getrandom`.
    fn random(&self, buf: &mut [u8]) -> usize {
        getrandom::fill(buf).expect("browser randomness");
        buf.len()
    }

    fn epoch_timestamp_in_ms(&self) -> VfsResult<i64> {
        Ok(js_sys::Date::now() as i64)
    }
}

struct Vfs;

impl SQLiteVfs<Io> for Vfs {
    type Os = Os;

    fn os(_data: &AppData) -> &Self::Os {
        &Os
    }
}

/// A registered in-memory VFS. Gives tests access to the stored files.
pub struct BrowserVfs {
    name: String,
    state: AppData,
}

impl BrowserVfs {
    /// Registers the VFS with SQLite under `name`. It is never unregistered, because SQLite may keep files open for
    /// the lifetime of the page.
    pub fn register(name: &str) -> Result<Self, String> {
        let state: AppData = Rc::new(RefCell::new(State::default()));
        // SAFETY: `Io`, `Vfs` and their callbacks use the same versions, file type and app data. The page runs on a
        // single thread, so no other registration runs at the same time. The state lives as long as the page.
        unsafe { register_vfs::<Io, Vfs>(name, Rc::clone(&state), false) }
            .map_err(|err| err.to_string())?
            .into_raw();
        Ok(BrowserVfs {
            name: name.into(),
            state,
        })
    }

    /// The name SQLite knows this VFS by, without encryption.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The name to open databases with so that SQLite3 Multiple Ciphers encrypts on top of this VFS.
    pub fn encrypted_name(&self) -> String {
        format!("multipleciphers-{}", self.name)
    }

    /// Names of all files in the VFS.
    pub fn file_names(&self) -> Vec<String> {
        self.state.borrow().files.keys().cloned().collect()
    }

    /// Content of a file as SQLite wrote it, or `None` if there is no such file.
    pub fn file_bytes(&self, name: &str) -> Option<Vec<u8>> {
        let state = self.state.borrow();
        let mut file = state.files.get(name)?.borrow_mut();
        let mut bytes = vec![0; file.size().ok()? as usize];
        file.read(&mut bytes, 0).ok()?;
        Some(bytes)
    }
}
