//! Shared by the tests: a login key with a C sign function, and a C configuration built from it.

#![allow(dead_code)]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};

use ed25519_dalek::SigningKey;
use sqlite_remote_vfs_ffi::{ED25519, SqliteRemoteVfsConfig};

pub fn server_url() -> Option<String> {
    let url = std::env::var("SQLITE_REMOTE_TEST_URL").ok();
    if url.is_none() {
        eprintln!("skipped: SQLITE_REMOTE_TEST_URL is not set");
    }
    url
}

/// A VFS name that no other test in this process uses.
pub fn unique(prefix: &str) -> CString {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    CString::new(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
    .unwrap()
}

/// `sqlite_remote_vfs_sign_fn` for a `SigningKey` passed as context.
///
/// # Safety
/// As in the header. `context` points to a `SigningKey`.
pub unsafe extern "C" fn sign(
    context: *mut c_void,
    message: *const u8,
    message_len: usize,
    signature: *mut u8,
    signature_capacity: usize,
    signature_len: *mut usize,
) -> c_int {
    use ed25519_dalek::Signer as _;
    // SAFETY: the context is a `SigningKey` leaked by `Login::new`.
    let key = unsafe { &*context.cast::<SigningKey>() };
    // SAFETY: `message_len` readable bytes, per the header.
    let message = unsafe { std::slice::from_raw_parts(message, message_len) };
    let bytes = key.sign(message).to_bytes();
    if signature_capacity < bytes.len() {
        return 1;
    }
    // SAFETY: `signature` holds `signature_capacity` bytes, per the header.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), signature, bytes.len());
        *signature_len = bytes.len();
    }
    0
}

/// A login key and the strings a configuration points to.
pub struct Login {
    key: &'static SigningKey,
    public_key: [u8; 32],
    url: CString,
}

impl Login {
    /// A fresh random key. It is leaked, because the VFS may sign with it for the life of the process.
    pub fn new(url: &str) -> Login {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        let key: &'static SigningKey = Box::leak(Box::new(SigningKey::from_bytes(&seed)));
        Login {
            key,
            public_key: key.verifying_key().to_bytes(),
            url: CString::new(url).unwrap(),
        }
    }

    /// A configuration with defaults. Its pointers are valid while `self` lives.
    pub fn config(&self) -> SqliteRemoteVfsConfig {
        SqliteRemoteVfsConfig {
            struct_size: size_of::<SqliteRemoteVfsConfig>(),
            url: self.url.as_ptr(),
            algorithm: ED25519,
            public_key: self.public_key.as_ptr(),
            public_key_len: self.public_key.len(),
            sign: Some(sign),
            sign_context: std::ptr::from_ref(self.key).cast_mut().cast(),
            local_copy_path: std::ptr::null(),
            memory_blocks: 0,
            blocks_per_fetch: 0,
            page_size: 0,
            timeout_ms: 2000,
            reconnect_timeout_ms: 0,
            takeover: 0,
            extra_roots: std::ptr::null(),
            extra_root_lens: std::ptr::null(),
            extra_roots_count: 0,
        }
    }
}

/// Signature of `sqlite_remote_vfs_register`.
pub type RegisterFn = unsafe extern "C" fn(*const c_char, *const SqliteRemoteVfsConfig, *mut *mut c_char) -> c_int;
/// Signature of `sqlite_remote_vfs_free`.
pub type FreeFn = unsafe extern "C" fn(*mut c_char);
/// Signature of `sqlite_remote_vfs_delete_database`.
pub type DeleteFn = unsafe extern "C" fn(*const c_char, *const c_char, *mut *mut c_char) -> c_int;

/// Calls a register function and returns its result code and error message.
pub fn call(
    register: RegisterFn,
    free: FreeFn,
    name: &CStr,
    config: &SqliteRemoteVfsConfig,
) -> (c_int, Option<String>) {
    let mut error: *mut c_char = std::ptr::null_mut();
    // SAFETY: valid name and config, and a writable error pointer.
    let rc = unsafe { register(name.as_ptr(), config, &mut error) };
    let message = (!error.is_null()).then(|| {
        // SAFETY: a NUL-terminated message from the library.
        let text = unsafe { CStr::from_ptr(error) }.to_string_lossy().into_owned();
        // SAFETY: returned by the register function and released once.
        unsafe { free(error) };
        text
    });
    (rc, message)
}

/// Whether `name` is registered with the SQLite linked into this test.
pub fn registered(name: &CStr) -> bool {
    // SAFETY: a valid NUL-terminated name.
    !unsafe { rusqlite::ffi::sqlite3_vfs_find(name.as_ptr()) }.is_null()
}

/// Writes rows through the VFS `name`, then reads them back through a second VFS registered with `reregister`,
/// which starts with nothing in memory.
pub fn round_trip(name: &CStr, reregister: impl FnOnce() -> CString) {
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_CREATE;
    let conn = rusqlite::Connection::open_with_flags_and_vfs("db", flags, name.to_str().unwrap()).expect("open");
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, body TEXT)")
        .expect("create table");
    for id in 0..100 {
        conn.execute("INSERT INTO t VALUES (?1, ?2)", (id, format!("row {id}")))
            .expect("insert");
    }
    drop(conn);

    let again = reregister();
    let conn = rusqlite::Connection::open_with_flags_and_vfs("db", flags, again.to_str().unwrap()).expect("reopen");
    let rows: i64 = conn
        .query_row("SELECT count(*) FROM t", [], |row| row.get(0))
        .expect("count rows");
    assert_eq!(rows, 100, "all rows must be read back from the server");
}

/// Calls a delete function and returns its result code and error message.
pub fn call_delete(delete: DeleteFn, free: FreeFn, vfs: &CStr, db: &CStr) -> (c_int, Option<String>) {
    let mut error: *mut c_char = std::ptr::null_mut();
    // SAFETY: valid names and a writable error pointer.
    let rc = unsafe { delete(vfs.as_ptr(), db.as_ptr(), &mut error) };
    let message = (!error.is_null()).then(|| {
        // SAFETY: a NUL-terminated message from the library.
        let text = unsafe { CStr::from_ptr(error) }.to_string_lossy().into_owned();
        // SAFETY: returned by the delete function and released once.
        unsafe { free(error) };
        text
    });
    (rc, message)
}

fn connect(vfs: &CStr) -> rusqlite::Connection {
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_CREATE;
    rusqlite::Connection::open_with_flags_and_vfs("db", flags, vfs.to_str().unwrap()).expect("open")
}

/// Creates table `t` with a few rows in database `db` of the VFS, then closes the database.
pub fn write_rows(vfs: &CStr) {
    let conn = connect(vfs);
    conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)")
        .expect("create table");
    conn.execute_batch("INSERT INTO t VALUES (1), (2), (3)")
        .expect("insert");
}

/// Number of tables in database `db` of the VFS. Opening creates the database if it does not exist.
pub fn tables(vfs: &CStr) -> i64 {
    connect(vfs)
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
        .expect("count tables")
}
