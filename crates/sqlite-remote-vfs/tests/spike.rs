//! Spike: checks the SQLite behaviour the remote VFS relies on, using an in-memory VFS that records the calls it
//! receives.
//!
//! - SQLite3 Multiple Ciphers encrypts above a custom VFS, so the VFS sees only ciphertext.
//! - Each commit reaches the VFS as exactly one commit point (`SQLITE_FCNTL_COMMIT_PHASETWO`). A rolled-back
//!   transaction produces none.
//! - `SQLITE_FCNTL_SYNC` on the main file is sent before the commit is final, also with `synchronous=OFF`. An error
//!   there fails the commit, and SQLite rolls back as it would on a failing disk.
//! - A rollback undoes pages written before the commit point (cache spill). It writes the original pages back and
//!   syncs them, so it reaches the VFS as a commit point of its own.
//! - Without shared memory, SQLite refuses WAL and keeps a rollback journal.
//! - Only the main file and its journal reach the VFS. Temporary files stay in memory.
//! - A copy of the main file opens in a new VFS instance. Preloading from the server relies on this.
//! - A rekey rewrites the whole file in one transaction.
//! - A connection can move to another thread.
//!
//! Run `cargo test --test spike -- --nocapture` to print the recorded calls.

#![allow(non_snake_case)] // SQLite's callback names

use std::collections::BTreeMap;
use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rsqlite_vfs::ffi::{
    SQLITE_FCNTL_COMMIT_PHASETWO, SQLITE_FCNTL_SYNC, SQLITE_IOERR, SQLITE_NOTFOUND, SQLITE_OPEN_MAIN_DB,
    SQLITE_OPEN_MAIN_JOURNAL, sqlite3_file,
};
use rsqlite_vfs::{
    AccessMode, FileKind, LockLevel, MemChunksFile, OpenOptions, OpenRequest, OpenedFile, OsCallback, SQLiteIoMethods,
    SQLiteVfs, SQLiteVfsFile, SyncOptions, VfsError, VfsErrorCode, VfsFile, VfsResult, VfsStore, register_vfs,
};
use rusqlite::{Connection, OpenFlags};

const PAGE_SIZE: usize = 4096;
const KEY: [u8; 32] = [0x11; 32];
const OTHER_KEY: [u8; 32] = [0x22; 32];
const MARKER: &[u8] = b"plaintext marker 4711";

// ---------------------------------------------------------------------------------------------------------------
// Recording in-memory VFS
// ---------------------------------------------------------------------------------------------------------------

/// A recorded VFS call. Reads are not recorded because they do not change any file.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Open { file: String, flags: i32 },
    Write { file: String, offset: usize, len: usize },
    Truncate { file: String, size: usize },
    Sync { file: String },
    FileControl { file: String, op: i32 },
    Delete { file: String },
}

/// State of the recording VFS: its files and the recorded calls.
#[derive(Default)]
struct State {
    files: BTreeMap<String, Arc<Mutex<MemChunksFile>>>,
    calls: Vec<Call>,
    /// If set, `SQLITE_FCNTL_SYNC` on the main file returns an error.
    fail_sync: bool,
}

/// Shared by the VFS and the test. Thread-safe because one test moves a connection to another thread.
type AppData = Arc<Mutex<State>>;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A file opened through the recording VFS. It stores its name so each call can be recorded with it.
struct TestFile {
    name: String,
    is_main: bool,
    chunks: Arc<Mutex<MemChunksFile>>,
    state: AppData,
}

impl TestFile {
    fn record(&self, call: Call) {
        lock(&self.state).calls.push(call);
    }
}

impl VfsFile for TestFile {
    fn read(&mut self, buf: &mut [u8], offset: u64) -> VfsResult<usize> {
        lock(&self.chunks).read(buf, offset)
    }

    fn write(&mut self, buf: &[u8], offset: u64) -> VfsResult<()> {
        self.record(Call::Write {
            file: self.name.clone(),
            offset: offset as usize,
            len: buf.len(),
        });
        lock(&self.chunks).write(buf, offset)
    }

    fn truncate(&mut self, size: u64) -> VfsResult<()> {
        self.record(Call::Truncate {
            file: self.name.clone(),
            size: size as usize,
        });
        lock(&self.chunks).truncate(size)
    }

    fn sync(&mut self, options: SyncOptions) -> VfsResult<()> {
        self.record(Call::Sync {
            file: self.name.clone(),
        });
        lock(&self.chunks).sync(options)
    }

    fn size(&self) -> VfsResult<u64> {
        lock(&self.chunks).size()
    }

    fn lock(&mut self, level: LockLevel) -> VfsResult<()> {
        lock(&self.chunks).lock(level)
    }

    fn unlock(&mut self, level: LockLevel) -> VfsResult<()> {
        lock(&self.chunks).unlock(level)
    }

    fn check_reserved_lock(&self) -> VfsResult<bool> {
        lock(&self.chunks).check_reserved_lock()
    }
}

struct Store;

impl VfsStore for Store {
    type File = TestFile;
    type AppData = AppData;

    fn open_file(data: &AppData, request: OpenRequest<'_>) -> VfsResult<OpenedFile<TestFile>> {
        let options = request.options;
        let is_main = options.kind() == Some(FileKind::MainDb);
        let name = request
            .filename
            .map_or_else(|| "<temp>".to_string(), |f| f.path().to_string());
        let mut state = lock(data);
        state.calls.push(Call::Open {
            file: name.clone(),
            flags: options.raw_flags(),
        });

        let chunks = match state.files.get(&name) {
            Some(_) if options.exclusive() => {
                return Err(VfsError::new(VfsErrorCode::CantOpen, format!("{name} exists").into()));
            }
            Some(chunks) => Arc::clone(chunks),
            None => {
                // A main file takes its chunk size from the first write, which SQLite always makes page-sized.
                let chunks = Arc::new(Mutex::new(if is_main {
                    MemChunksFile::waiting_for_write()
                } else {
                    MemChunksFile::default()
                }));
                state.files.insert(name.clone(), Arc::clone(&chunks));
                chunks
            }
        };
        drop(state);
        Ok(OpenedFile {
            file: TestFile {
                name,
                is_main,
                chunks,
                state: Arc::clone(data),
            },
            access: options.access(),
        })
    }

    fn close_file(data: &AppData, name: Option<&str>, file: TestFile, options: OpenOptions) -> VfsResult<()> {
        if options.delete_on_close()
            && let Some(name) = name
        {
            let mut state = lock(data);
            // Keep a file that was created under the same name after this one was opened.
            if state
                .files
                .get(name)
                .is_some_and(|current| Arc::ptr_eq(current, &file.chunks))
            {
                state.files.remove(name);
            }
        }
        Ok(())
    }

    fn access(data: &AppData, name: &str, _mode: AccessMode) -> VfsResult<bool> {
        Ok(lock(data).files.contains_key(name))
    }

    fn full_pathname(_data: &AppData, name: &str) -> VfsResult<String> {
        Ok(name.into())
    }

    fn delete_file(data: &AppData, name: &str, _sync_dir: bool) -> VfsResult<()> {
        let mut state = lock(data);
        state.calls.push(Call::Delete { file: name.into() });
        match state.files.remove(name) {
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

    unsafe extern "C" fn xFileControl(pFile: *mut sqlite3_file, op: c_int, _pArg: *mut c_void) -> c_int {
        // SAFETY: SQLite passes a file opened by `xOpen`, whose handle is a `TestFile`.
        let file = unsafe { (*SQLiteVfsFile::from_file(pFile)).handle_mut::<TestFile>() };
        file.record(Call::FileControl {
            file: file.name.clone(),
            op,
        });
        // Simulates a server that rejects the commit.
        if op == SQLITE_FCNTL_SYNC && file.is_main && lock(&file.state).fail_sync {
            return SQLITE_IOERR;
        }
        // SQLite handles all other file controls itself, including pragmas.
        SQLITE_NOTFOUND
    }
}

struct Os;

static OS: Os = Os;

impl OsCallback for Os {
    fn sleep(&self, dur: Duration) {
        std::thread::sleep(dur);
    }

    fn random(&self, buf: &mut [u8]) -> usize {
        getrandom::fill(buf).expect("OS randomness");
        buf.len()
    }

    fn epoch_timestamp_in_ms(&self) -> VfsResult<i64> {
        Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after 1970")
            .as_millis() as i64)
    }
}

struct Vfs;

impl SQLiteVfs<Io> for Vfs {
    type Os = Os;

    fn os(_data: &AppData) -> &Self::Os {
        &OS
    }
}

/// A registered recording VFS. Each test registers its own instance.
struct TestVfs {
    name: String,
    state: AppData,
}

impl TestVfs {
    fn register() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let name = format!("spike-{}", NEXT.fetch_add(1, Ordering::Relaxed));
        let state: AppData = Arc::new(Mutex::new(State::default()));
        // SAFETY: `Io`, `Vfs` and their callbacks agree on versions, file layout and app data. The registration is
        // leaked with `into_raw`, so the VFS and its state stay valid until the process exits.
        unsafe { register_vfs::<Io, Vfs>(&name, Arc::clone(&state), false) }
            .expect("register VFS")
            .into_raw();
        Self { name, state }
    }

    /// Opens `file` through SQLite3 Multiple Ciphers. The VFS name `multipleciphers-<name>` puts its encryption
    /// layer above this VFS.
    fn open(&self, file: &str, key: &[u8; 32]) -> Connection {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let vfs_name = format!("multipleciphers-{}", self.name);
        let conn = Connection::open_with_flags_and_vfs(file, flags, vfs_name.as_str()).expect("open database");
        conn.pragma_update(None, "key", raw_key(key)).expect("set key");
        conn
    }

    fn calls(&self) -> Vec<Call> {
        lock(&self.state).calls.clone()
    }

    fn clear_calls(&self) {
        lock(&self.state).calls.clear();
    }

    fn set_fail_sync(&self, fail: bool) {
        lock(&self.state).fail_sync = fail;
    }

    fn file_names(&self) -> Vec<String> {
        lock(&self.state).files.keys().cloned().collect()
    }

    fn file_bytes(&self, file: &str) -> Option<Vec<u8>> {
        let state = lock(&self.state);
        let mut file = lock(state.files.get(file)?);
        let mut bytes = vec![0; file.size().ok()? as usize];
        file.read(&mut bytes, 0).ok()?;
        Some(bytes)
    }

    /// Stores `bytes` as the main file `file`, as a preload from the server does.
    fn import(&self, file: &str, bytes: &[u8]) {
        let mut chunks = MemChunksFile::new(PAGE_SIZE);
        chunks.write(bytes, 0).expect("write file");
        lock(&self.state)
            .files
            .insert(file.into(), Arc::new(Mutex::new(chunks)));
    }
}

fn raw_key(key: &[u8; 32]) -> String {
    let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("x'{hex}'")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

fn count_file_control(calls: &[Call], file: &str, wanted: i32) -> usize {
    calls
        .iter()
        .filter(|call| matches!(call, Call::FileControl { file: f, op } if f == file && *op == wanted))
        .count()
}

fn count_writes(calls: &[Call], file: &str) -> usize {
    calls
        .iter()
        .filter(|call| matches!(call, Call::Write { file: f, .. } if f == file))
        .count()
}

fn integrity_check(conn: &Connection) -> String {
    conn.query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .expect("integrity_check")
}

fn row_count(conn: &Connection) -> i64 {
    conn.query_row("SELECT count(*) FROM t", [], |row| row.get(0))
        .expect("count rows")
}

// ---------------------------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn vfs_sees_only_ciphertext() {
    let vfs = TestVfs::register();
    let conn = vfs.open("marker.db", &KEY);
    conn.execute_batch("CREATE TABLE marker (data BLOB)").unwrap();
    conn.execute("INSERT INTO marker (data) VALUES (?1)", [MARKER]).unwrap();
    let read: Vec<u8> = conn.query_row("SELECT data FROM marker", [], |row| row.get(0)).unwrap();
    assert_eq!(read, MARKER);
    drop(conn);

    let bytes = vfs.file_bytes("marker.db").expect("main file");
    println!("main file: {} bytes, first 16 bytes {:02x?}", bytes.len(), &bytes[..16]);
    assert_eq!(bytes.len() % PAGE_SIZE, 0);
    assert!(
        !bytes.starts_with(b"SQLite format 3\0"),
        "main file must not start with the plaintext SQLite header"
    );
    for name in vfs.file_names() {
        let content = vfs.file_bytes(&name).unwrap();
        assert!(!contains(&content, MARKER), "{name} contains the plaintext marker");
    }

    let wrong_key = vfs.open("marker.db", &OTHER_KEY);
    let result = wrong_key.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get::<_, i64>(0));
    println!("with the wrong key: {result:?}");
    assert!(result.is_err());
}

#[test]
fn each_commit_is_one_commit_point() {
    let vfs = TestVfs::register();
    let conn = vfs.open("commit.db", &KEY);
    conn.execute_batch("CREATE TABLE t (x INTEGER)").unwrap();

    vfs.clear_calls();
    conn.execute_batch("BEGIN; INSERT INTO t VALUES (1); INSERT INTO t VALUES (2); COMMIT;")
        .unwrap();
    let calls = vfs.calls();
    println!("explicit transaction: {calls:#?}");
    assert_eq!(count_file_control(&calls, "commit.db", SQLITE_FCNTL_COMMIT_PHASETWO), 1);
    let commit_point = calls
        .iter()
        .position(|call| {
            matches!(call, Call::FileControl { file, op } if file == "commit.db" && *op == SQLITE_FCNTL_COMMIT_PHASETWO)
        })
        .unwrap();
    assert_eq!(
        count_writes(&calls[commit_point..], "commit.db"),
        0,
        "no writes to the main file expected after the commit point"
    );
    println!(
        "SQLITE_FCNTL_SYNC on the main file: {}",
        count_file_control(&calls, "commit.db", SQLITE_FCNTL_SYNC)
    );

    vfs.clear_calls();
    conn.execute("INSERT INTO t VALUES (3)", []).unwrap();
    assert_eq!(
        count_file_control(&vfs.calls(), "commit.db", SQLITE_FCNTL_COMMIT_PHASETWO),
        1,
        "autocommit statement must be one commit point"
    );

    vfs.clear_calls();
    conn.execute_batch("BEGIN; INSERT INTO t VALUES (4); ROLLBACK;")
        .unwrap();
    let calls = vfs.calls();
    println!("rolled back: {calls:#?}");
    assert_eq!(count_file_control(&calls, "commit.db", SQLITE_FCNTL_COMMIT_PHASETWO), 0);
    assert_eq!(count_writes(&calls, "commit.db"), 0);
    assert_eq!(row_count(&conn), 3);
}

#[test]
fn rollback_undoes_spilled_pages() {
    let vfs = TestVfs::register();
    let conn = vfs.open("spill.db", &KEY);
    conn.execute_batch("PRAGMA cache_size = 16; CREATE TABLE t (x BLOB)")
        .unwrap();
    let before = vfs.file_bytes("spill.db").unwrap();

    vfs.clear_calls();
    conn.execute_batch("BEGIN").unwrap();
    for _ in 0..200 {
        conn.execute("INSERT INTO t VALUES (randomblob(4000))", []).unwrap();
    }
    let spilled = count_writes(&vfs.calls(), "spill.db");
    let syncs = count_file_control(&vfs.calls(), "spill.db", SQLITE_FCNTL_SYNC);
    println!("inside the open transaction (cache spill): {spilled} writes, {syncs} SQLITE_FCNTL_SYNC");
    assert!(spilled > 0, "16-page cache must spill into the main file");
    assert_eq!(syncs, 0, "no sync expected inside the open transaction");

    conn.execute_batch("ROLLBACK").unwrap();
    let calls = vfs.calls();
    assert_eq!(count_file_control(&calls, "spill.db", SQLITE_FCNTL_COMMIT_PHASETWO), 0);
    let after = vfs.file_bytes("spill.db").unwrap();
    println!(
        "size before {} / after {} bytes, byte-identical: {}",
        before.len(),
        after.len(),
        before == after
    );
    assert_eq!(before.len(), after.len());
    assert_eq!(row_count(&conn), 0);
    assert_eq!(integrity_check(&conn), "ok");

    // The same transaction again, this time committed.
    conn.execute_batch("BEGIN").unwrap();
    for _ in 0..200 {
        conn.execute("INSERT INTO t VALUES (randomblob(4000))", []).unwrap();
    }
    conn.execute_batch("COMMIT").unwrap();
    assert_eq!(row_count(&conn), 200);
    assert_eq!(integrity_check(&conn), "ok");
}

#[test]
fn wal_refused_without_shared_memory() {
    let vfs = TestVfs::register();
    let conn = vfs.open("wal.db", &KEY);
    conn.execute_batch("CREATE TABLE t (x INTEGER)").unwrap();

    let mode: String = conn
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .unwrap();
    println!("journal_mode after asking for WAL: {mode}");
    assert_ne!(mode.to_ascii_lowercase(), "wal");
    conn.execute("INSERT INTO t VALUES (1)", []).unwrap();
    assert!(
        !vfs.file_names()
            .iter()
            .any(|name| name.ends_with("-wal") || name.ends_with("-shm")),
        "{:?}",
        vfs.file_names()
    );

    let mode: String = conn
        .query_row("PRAGMA journal_mode = MEMORY", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "memory");
    vfs.clear_calls();
    conn.execute_batch("BEGIN; INSERT INTO t VALUES (2); COMMIT;").unwrap();
    let calls = vfs.calls();
    println!("journal_mode=MEMORY: {calls:#?}");
    assert!(
        !calls
            .iter()
            .any(|call| matches!(call, Call::Open { file, .. } if file.ends_with("-journal")))
    );
    assert_eq!(count_file_control(&calls, "wal.db", SQLITE_FCNTL_COMMIT_PHASETWO), 1);
    assert_eq!(row_count(&conn), 2);
}

#[test]
fn only_main_file_and_journal_reach_vfs() {
    let vfs = TestVfs::register();
    let conn = vfs.open("files.db", &KEY);
    conn.execute_batch("CREATE TABLE t (a INTEGER, b TEXT); BEGIN").unwrap();
    for i in 0..1000 {
        conn.execute("INSERT INTO t VALUES (?1, ?2)", (i, format!("row {i:04}")))
            .unwrap();
    }
    conn.execute_batch("COMMIT").unwrap();
    // A sort without an index, which needs a temporary b-tree.
    let sorted: i64 = conn
        .query_row("SELECT count(*) FROM (SELECT b FROM t ORDER BY b DESC)", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(sorted, 1000);

    let opens: Vec<(String, i32)> = vfs
        .calls()
        .into_iter()
        .filter_map(|call| match call {
            Call::Open { file, flags } => Some((file, flags)),
            _ => None,
        })
        .collect();
    println!("opened: {opens:#x?}");
    for (file, flags) in &opens {
        let main = file == "files.db" && flags & SQLITE_OPEN_MAIN_DB != 0;
        let journal = file == "files.db-journal" && flags & SQLITE_OPEN_MAIN_JOURNAL != 0;
        assert!(main || journal, "unexpected file {file} with flags {flags:#x}");
    }
    assert_eq!(
        vfs.file_names(),
        ["files.db"],
        "journal must be deleted after the commit"
    );
}

#[test]
fn copied_main_file_opens_in_new_vfs() {
    let source = TestVfs::register();
    let conn = source.open("copy.db", &KEY);
    conn.execute_batch("CREATE TABLE t (a INTEGER, b BLOB); BEGIN").unwrap();
    for i in 0..500 {
        conn.execute("INSERT INTO t VALUES (?1, randomblob(300))", [i]).unwrap();
    }
    conn.execute_batch("COMMIT").unwrap();
    drop(conn);
    let bytes = source.file_bytes("copy.db").unwrap();
    println!("copied {} bytes ({} pages)", bytes.len(), bytes.len() / PAGE_SIZE);

    let target = TestVfs::register();
    target.import("copy.db", &bytes);
    let conn = target.open("copy.db", &KEY);
    assert_eq!(row_count(&conn), 500);
    assert_eq!(integrity_check(&conn), "ok");
}

#[test]
fn rekey_rewrites_file_in_one_transaction() {
    let vfs = TestVfs::register();
    let conn = vfs.open("rekey.db", &KEY);
    conn.execute_batch("CREATE TABLE t (a INTEGER, b BLOB); BEGIN").unwrap();
    for i in 0..300 {
        conn.execute("INSERT INTO t VALUES (?1, randomblob(300))", [i]).unwrap();
    }
    conn.execute_batch("COMMIT").unwrap();
    let pages = vfs.file_bytes("rekey.db").unwrap().len() / PAGE_SIZE;

    vfs.clear_calls();
    conn.pragma_update(None, "rekey", raw_key(&OTHER_KEY)).unwrap();
    let calls = vfs.calls();
    let writes = count_writes(&calls, "rekey.db");
    let commits = count_file_control(&calls, "rekey.db", SQLITE_FCNTL_COMMIT_PHASETWO);
    println!("rekey: {pages} pages, {writes} writes to the main file, {commits} commit points");
    assert!(writes >= pages, "rekey must rewrite every page");
    assert_eq!(commits, 1);
    drop(conn);

    assert_eq!(row_count(&vfs.open("rekey.db", &OTHER_KEY)), 300);
    let old_key = vfs.open("rekey.db", &KEY);
    assert!(
        old_key
            .query_row("SELECT count(*) FROM t", [], |row| row.get::<_, i64>(0))
            .is_err()
    );
}

#[test]
fn connection_can_move_to_other_thread() {
    let vfs = TestVfs::register();
    let conn = vfs.open("thread.db", &KEY);
    conn.execute_batch("CREATE TABLE t (x INTEGER); INSERT INTO t VALUES (1)")
        .unwrap();
    // Only one thread uses the connection at a time, so the VFS state is never accessed concurrently.
    let count = std::thread::spawn(move || {
        conn.execute("INSERT INTO t VALUES (2)", []).unwrap();
        row_count(&conn)
    })
    .join()
    .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn sync_file_control_sent_with_synchronous_off() {
    let vfs = TestVfs::register();
    let conn = vfs.open("nosync.db", &KEY);
    let mode: String = conn
        .query_row("PRAGMA journal_mode = MEMORY", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "memory");
    conn.pragma_update(None, "synchronous", "OFF").unwrap();
    conn.execute_batch("CREATE TABLE t (x INTEGER)").unwrap();

    vfs.clear_calls();
    conn.execute("INSERT INTO t VALUES (1)", []).unwrap();
    let calls = vfs.calls();
    println!("synchronous=OFF: {calls:#?}");
    assert_eq!(count_file_control(&calls, "nosync.db", SQLITE_FCNTL_SYNC), 1);
    assert!(
        !calls.iter().any(|call| matches!(call, Call::Sync { .. })),
        "no xSync expected with synchronous=OFF"
    );
    assert_eq!(count_file_control(&calls, "nosync.db", SQLITE_FCNTL_COMMIT_PHASETWO), 1);
}

#[test]
fn failed_sync_fails_commit_and_rolls_back() {
    for journal_mode in ["delete", "memory"] {
        let vfs = TestVfs::register();
        let conn = vfs.open("refused.db", &KEY);
        let mode: String = conn
            .query_row(&format!("PRAGMA journal_mode = {journal_mode}"), [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode, journal_mode);
        conn.execute_batch("CREATE TABLE t (x INTEGER); INSERT INTO t VALUES (1)")
            .unwrap();

        vfs.set_fail_sync(true);
        vfs.clear_calls();
        let result = conn.execute_batch("BEGIN; INSERT INTO t VALUES (2); INSERT INTO t VALUES (3); COMMIT;");
        println!(
            "journal_mode={journal_mode}: commit with failing sync: {result:?}, autocommit afterwards: {}",
            conn.is_autocommit()
        );
        assert!(result.is_err());
        assert_eq!(
            count_file_control(&vfs.calls(), "refused.db", SQLITE_FCNTL_COMMIT_PHASETWO),
            0
        );
        if !conn.is_autocommit() {
            conn.execute_batch("ROLLBACK").unwrap();
        }
        vfs.set_fail_sync(false);
        assert_eq!(
            row_count(&conn),
            1,
            "journal_mode={journal_mode}: rows of the failed commit must not be visible"
        );
        assert_eq!(integrity_check(&conn), "ok");

        // After reopening, the file holds the state from before the failed commit.
        drop(conn);
        let conn = vfs.open("refused.db", &KEY);
        assert_eq!(row_count(&conn), 1, "journal_mode={journal_mode}: after reopening");
        assert_eq!(integrity_check(&conn), "ok");
    }
}

/// Repeats the cache spill check with `journal_mode=MEMORY`, the mode the remote VFS uses.
#[test]
fn memory_journal_spill_is_no_commit_point() {
    let vfs = TestVfs::register();
    let conn = vfs.open("spill-memory.db", &KEY);
    let mode: String = conn
        .query_row("PRAGMA journal_mode = MEMORY", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "memory");
    conn.execute_batch("PRAGMA cache_size = 16; CREATE TABLE t (x BLOB)")
        .unwrap();

    vfs.clear_calls();
    conn.execute_batch("BEGIN").unwrap();
    for _ in 0..200 {
        conn.execute("INSERT INTO t VALUES (randomblob(4000))", []).unwrap();
    }
    let calls = vfs.calls();
    let spilled = count_writes(&calls, "spill-memory.db");
    let syncs = count_file_control(&calls, "spill-memory.db", SQLITE_FCNTL_SYNC);
    println!("journal in memory, inside the open transaction: {spilled} writes, {syncs} SQLITE_FCNTL_SYNC");
    assert!(spilled > 0, "16-page cache must spill into the main file");
    assert_eq!(syncs, 0, "no sync expected inside the open transaction");

    // The rollback writes the original pages back and syncs them, so it reaches the VFS as a commit point.
    vfs.clear_calls();
    conn.execute_batch("ROLLBACK").unwrap();
    let syncs = count_file_control(&vfs.calls(), "spill-memory.db", SQLITE_FCNTL_SYNC);
    println!("the rollback itself: {syncs} SQLITE_FCNTL_SYNC");
    assert_eq!(syncs, 1, "rollback after a spill must sync once");

    assert_eq!(row_count(&conn), 0);
    assert_eq!(integrity_check(&conn), "ok");
}
