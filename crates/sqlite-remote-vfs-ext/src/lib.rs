//! sqlite-remote-vfs as a loadable SQLite extension.
//!
//! Load it with `sqlite3_load_extension()` or `load_extension()` in SQL, then register a VFS with
//! `sqlite_remote_vfs_register()` from the same library, declared in `sqlite_remote_vfs.h`.
//!
//! The extension contains no SQLite. The VFS calls six SQLite functions. This library defines them itself and
//! forwards each call through the API table that SQLite passes to the entry point. So the VFS always uses the SQLite
//! that loaded the extension: plain SQLite, SQLite3 Multiple Ciphers, SQLCipher or any other build.

use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicPtr, Ordering};

pub use sqlite_remote_vfs_ffi::{
    sqlite_remote_vfs_delete_database, sqlite_remote_vfs_free, sqlite_remote_vfs_register,
};

const SQLITE_ERROR: c_int = 1;
const SQLITE_MISUSE: c_int = 21;
/// Keeps the library loaded after the connection that loaded it closes. The registered VFS points into it.
const SQLITE_OK_LOAD_PERMANENTLY: c_int = 256;

/// 3.14.0, the first version that knows `SQLITE_OK_LOAD_PERMANENTLY`. Its API table has all entries below.
const MIN_VERSION: c_int = 3_014_000;

// Positions in `struct sqlite3_api_routines` (sqlite3ext.h). All entries are function pointers, and SQLite only ever
// appends entries, so a position never changes.
const LIBVERSION_NUMBER: usize = 67;
const MALLOC: usize = 68;
const VFS_FIND: usize = 141;
const VFS_REGISTER: usize = 142;
const VFS_UNREGISTER: usize = 143;
const URI_BOOLEAN: usize = 187;
const URI_INT64: usize = 188;
const URI_PARAMETER: usize = 189;

/// The API table of the SQLite that loaded the extension. NULL until the entry point has run.
static API: AtomicPtr<*const c_void> = AtomicPtr::new(std::ptr::null_mut());

/// Returns entry `index` of `api`, or NULL.
///
/// # Safety
/// `api` is NULL or an API table with more than `index` entries.
unsafe fn entry(api: *const *const c_void, index: usize) -> *const c_void {
    if api.is_null() {
        return std::ptr::null();
    }
    // SAFETY: the table has more than `index` entries per the caller's contract.
    unsafe { *api.add(index) }
}

/// Returns entry `index` of the stored API table as a function of type `F`, or `None` before the entry point ran.
///
/// # Safety
/// `F` is the function pointer type of that entry.
unsafe fn function<F: Copy>(index: usize) -> Option<F> {
    // SAFETY: the stored table passed the version check, so it has all entries used here.
    let ptr = unsafe { entry(API.load(Ordering::Acquire), index) };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: `F` is a function pointer type of the same size, per the caller's contract.
    Some(unsafe { std::mem::transmute_copy::<*const c_void, F>(&ptr) })
}

/// Sets the error message of the entry point. SQLite releases it with `sqlite3_free`, so it is allocated with
/// SQLite's `malloc`.
///
/// # Safety
/// `api` has at least the entries up to `MALLOC`. `error` is NULL or writable.
unsafe fn set_error(api: *const *const c_void, error: *mut *mut c_char, message: &str) {
    if error.is_null() {
        return;
    }
    // SAFETY: per the caller's contract.
    let malloc = unsafe { entry(api, MALLOC) };
    if malloc.is_null() {
        return;
    }
    // SAFETY: entry MALLOC is `void *(*)(int)`.
    let malloc: unsafe extern "C" fn(c_int) -> *mut c_void = unsafe { std::mem::transmute(malloc) };
    let Ok(size) = c_int::try_from(message.len() + 1) else {
        return;
    };
    // SAFETY: SQLite's malloc, called with a positive size.
    let buffer = unsafe { malloc(size) }.cast::<u8>();
    if buffer.is_null() {
        return;
    }
    // SAFETY: `buffer` holds message.len() + 1 bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(message.as_ptr(), buffer, message.len());
        *buffer.add(message.len()) = 0;
        *error = buffer.cast();
    }
}

/// Entry point, called by SQLite when it loads the extension. Stores the API table. Registers no VFS: that needs a
/// configuration and a sign function, passed to `sqlite_remote_vfs_register()`.
///
/// # Safety
/// Called by SQLite with a valid API table.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sqlite3_sqliteremotevfsext_init(
    _db: *mut c_void,
    error: *mut *mut c_char,
    api: *const *const c_void,
) -> c_int {
    if api.is_null() {
        return SQLITE_ERROR;
    }
    // SAFETY: every SQLite that supports loadable extensions has entry LIBVERSION_NUMBER.
    let libversion = unsafe { entry(api, LIBVERSION_NUMBER) };
    // SAFETY: entry LIBVERSION_NUMBER is `int (*)(void)`.
    let libversion: unsafe extern "C" fn() -> c_int = unsafe { std::mem::transmute(libversion) };
    // SAFETY: SQLite's own function.
    let version = unsafe { libversion() };
    if version < MIN_VERSION {
        // SAFETY: entry MALLOC directly follows LIBVERSION_NUMBER and exists wherever that one does.
        unsafe {
            set_error(
                api,
                error,
                &format!("sqlite-remote-vfs needs SQLite 3.14.0 or later, found {version}"),
            )
        };
        return SQLITE_ERROR;
    }
    let previous = API.compare_exchange(
        std::ptr::null_mut(),
        api.cast_mut(),
        Ordering::AcqRel,
        Ordering::Acquire,
    );
    if let Err(existing) = previous
        && existing != api.cast_mut()
    {
        // A second SQLite in the same process loaded the same library. Its VFS registrations would go to the
        // first SQLite.
        // SAFETY: the version check passed.
        unsafe {
            set_error(
                api,
                error,
                "sqlite-remote-vfs is already loaded by another SQLite in this process",
            )
        };
        return SQLITE_ERROR;
    }
    SQLITE_OK_LOAD_PERMANENTLY
}

// The six SQLite functions the VFS calls, forwarded through the API table. Before the entry point has run they
// return NULL, SQLITE_MISUSE or the default value.

/// # Safety
/// As `sqlite3_vfs_find`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sqlite3_vfs_find(name: *const c_char) -> *mut c_void {
    // SAFETY: entry VFS_FIND is `sqlite3_vfs *(*)(const char *)`.
    match unsafe { function::<unsafe extern "C" fn(*const c_char) -> *mut c_void>(VFS_FIND) } {
        // SAFETY: forwarded unchanged.
        Some(find) => unsafe { find(name) },
        None => std::ptr::null_mut(),
    }
}

/// # Safety
/// As `sqlite3_vfs_register`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sqlite3_vfs_register(vfs: *mut c_void, make_default: c_int) -> c_int {
    // SAFETY: entry VFS_REGISTER is `int (*)(sqlite3_vfs *, int)`.
    match unsafe { function::<unsafe extern "C" fn(*mut c_void, c_int) -> c_int>(VFS_REGISTER) } {
        // SAFETY: forwarded unchanged.
        Some(register) => unsafe { register(vfs, make_default) },
        None => SQLITE_MISUSE,
    }
}

/// # Safety
/// As `sqlite3_vfs_unregister`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sqlite3_vfs_unregister(vfs: *mut c_void) -> c_int {
    // SAFETY: entry VFS_UNREGISTER is `int (*)(sqlite3_vfs *)`.
    match unsafe { function::<unsafe extern "C" fn(*mut c_void) -> c_int>(VFS_UNREGISTER) } {
        // SAFETY: forwarded unchanged.
        Some(unregister) => unsafe { unregister(vfs) },
        None => SQLITE_MISUSE,
    }
}

/// # Safety
/// As `sqlite3_uri_parameter`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sqlite3_uri_parameter(filename: *const c_char, key: *const c_char) -> *const c_char {
    // SAFETY: entry URI_PARAMETER is `const char *(*)(const char *, const char *)`.
    match unsafe { function::<unsafe extern "C" fn(*const c_char, *const c_char) -> *const c_char>(URI_PARAMETER) } {
        // SAFETY: forwarded unchanged.
        Some(parameter) => unsafe { parameter(filename, key) },
        None => std::ptr::null(),
    }
}

/// # Safety
/// As `sqlite3_uri_boolean`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sqlite3_uri_boolean(filename: *const c_char, key: *const c_char, default: c_int) -> c_int {
    // SAFETY: entry URI_BOOLEAN is `int (*)(const char *, const char *, int)`.
    match unsafe { function::<unsafe extern "C" fn(*const c_char, *const c_char, c_int) -> c_int>(URI_BOOLEAN) } {
        // SAFETY: forwarded unchanged.
        Some(boolean) => unsafe { boolean(filename, key, default) },
        None => default,
    }
}

/// # Safety
/// As `sqlite3_uri_int64`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sqlite3_uri_int64(filename: *const c_char, key: *const c_char, default: i64) -> i64 {
    // SAFETY: entry URI_INT64 is `sqlite3_int64 (*)(const char *, const char *, sqlite3_int64)`.
    match unsafe { function::<unsafe extern "C" fn(*const c_char, *const c_char, i64) -> i64>(URI_INT64) } {
        // SAFETY: forwarded unchanged.
        Some(int64) => unsafe { int64(filename, key, default) },
        None => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The positions above must match `struct sqlite3_api_routines` in the SQLite headers of this repository.
    #[test]
    fn api_table_positions_match_sqlite3ext_h() {
        let header = include_str!("../../../vendor/libsqlite3-sys/sqlite3mc/sqlite3ext.h");
        let start = header.find("struct sqlite3_api_routines {").expect("struct in header");
        let body = &header[start..];
        let body = &body[body.find('{').unwrap() + 1..body.find("};").unwrap()];
        let names: Vec<String> = body
            .split(';')
            .map(|member| {
                let member = member.trim();
                match member.find("(*") {
                    Some(at) => member[at + 2..].split(')').next().unwrap().trim().to_string(),
                    None => member.rsplit(' ').next().unwrap_or("").to_string(),
                }
            })
            .filter(|name| !name.is_empty())
            .collect();
        let position = |name: &str| names.iter().position(|n| n == name).expect(name);
        assert_eq!(position("libversion_number"), LIBVERSION_NUMBER);
        assert_eq!(position("malloc"), MALLOC);
        assert_eq!(position("vfs_find"), VFS_FIND);
        assert_eq!(position("vfs_register"), VFS_REGISTER);
        assert_eq!(position("vfs_unregister"), VFS_UNREGISTER);
        assert_eq!(position("uri_boolean"), URI_BOOLEAN);
        assert_eq!(position("uri_int64"), URI_INT64);
        assert_eq!(position("uri_parameter"), URI_PARAMETER);
    }

    unsafe extern "C" fn version_3_50() -> c_int {
        3_050_000
    }

    unsafe extern "C" fn version_3_13() -> c_int {
        3_013_000
    }

    /// Stands in for SQLite's malloc. The test never frees, so leaking is fine.
    unsafe extern "C" fn leaking_malloc(size: c_int) -> *mut c_void {
        let buffer = vec![0u8; usize::try_from(size).unwrap()].into_boxed_slice();
        Box::leak(buffer).as_mut_ptr().cast()
    }

    /// An API table with a version and a malloc, and every other entry NULL. It lives for the rest of the process,
    /// because the entry point may keep it.
    fn table(version: unsafe extern "C" fn() -> c_int) -> *const *const c_void {
        let mut entries = vec![std::ptr::null::<c_void>(); URI_PARAMETER + 1];
        entries[LIBVERSION_NUMBER] = version as *const c_void;
        entries[MALLOC] = leaking_malloc as *const c_void;
        Box::leak(entries.into_boxed_slice()).as_ptr()
    }

    /// Calls the entry point and returns its result code and error message.
    fn init(api: *const *const c_void) -> (c_int, Option<String>) {
        let mut error: *mut c_char = std::ptr::null_mut();
        // SAFETY: `api` is NULL or a table from `table`, whose entries the entry point reads.
        let rc = unsafe { sqlite3_sqliteremotevfsext_init(std::ptr::null_mut(), &mut error, api) };
        // SAFETY: NULL or a NUL-terminated message written by `set_error`.
        let message = (!error.is_null()).then(|| unsafe { std::ffi::CStr::from_ptr(error) }.to_string_lossy().into());
        (rc, message)
    }

    /// One test, because the entry point stores the table in a process-wide static: the steps depend on each other.
    #[test]
    fn entry_point_checks_version_and_keeps_the_library_loaded() {
        // Before loading, the forwarders do nothing.
        // SAFETY: the forwarders do not dereference their arguments while no table is stored.
        unsafe {
            assert!(sqlite3_vfs_find(std::ptr::null()).is_null());
            assert_eq!(sqlite3_vfs_register(std::ptr::null_mut(), 0), SQLITE_MISUSE);
            assert_eq!(sqlite3_uri_boolean(std::ptr::null(), std::ptr::null(), 7), 7);
        }

        assert_eq!(
            init(std::ptr::null()).0,
            SQLITE_ERROR,
            "a missing table must be rejected"
        );

        let (rc, error) = init(table(version_3_13));
        assert_eq!(rc, SQLITE_ERROR, "SQLite before 3.14.0 must be rejected");
        assert!(error.unwrap().contains("3.14.0"));
        assert!(
            API.load(Ordering::Acquire).is_null(),
            "a rejected table must not be stored"
        );

        // SQLite unloads an extension when the loading connection closes, unless the entry point returns
        // SQLITE_OK_LOAD_PERMANENTLY. The registered VFS points into this library, so that return value is required.
        let first = table(version_3_50);
        assert_eq!(init(first).0, SQLITE_OK_LOAD_PERMANENTLY);
        assert_eq!(
            init(first).0,
            SQLITE_OK_LOAD_PERMANENTLY,
            "the same SQLite may load the extension again"
        );

        let (rc, error) = init(table(version_3_50));
        assert_eq!(rc, SQLITE_ERROR, "a second SQLite in the same process must be rejected");
        assert!(error.unwrap().contains("another SQLite"));
    }
}
