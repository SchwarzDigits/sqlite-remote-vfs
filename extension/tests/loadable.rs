//! The loadable extension, loaded into plain SQLite.
//!
//! Needs the built library: `cargo build -p sqlite-remote-vfs-ext` in the main workspace. `SQLITE_REMOTE_VFS_EXT`
//! overrides its path. `extension_registers_with_the_loading_sqlite` needs `SQLITE_REMOTE_TEST_URL` and is skipped
//! without it.

mod common;

use std::ffi::{c_char, c_void};
use std::path::PathBuf;

use common::{DeleteFn, FreeFn, Login, RegisterFn, call, registered, unique};
use libloading::Library;
use rusqlite::Connection;

const SQLITE_ERROR: i32 = 1;

/// Path of the built extension.
fn library_path() -> PathBuf {
    let path = std::env::var_os("SQLITE_REMOTE_VFS_EXT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let file = if cfg!(target_os = "macos") {
                "libsqlite_remote_vfs_ext.dylib"
            } else {
                "libsqlite_remote_vfs_ext.so"
            };
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../target/debug")
                .join(file)
        });
    assert!(
        path.exists(),
        "{} not found: run `cargo build -p sqlite-remote-vfs-ext` in the main workspace",
        path.display()
    );
    path
}

/// Loads the extension into the SQLite linked into this test, through a connection that is closed right after.
fn load() -> PathBuf {
    let path = library_path();
    let conn = Connection::open_in_memory().unwrap();
    // SAFETY: loads the library built from this repository.
    unsafe {
        conn.load_extension_enable().unwrap();
        conn.load_extension(&path, None::<&str>).expect("load the extension");
    }
    conn.load_extension_disable().unwrap();
    drop(conn);
    path
}

/// The library, opened again to call its C interface. It is the image SQLite already loaded.
fn open(path: &PathBuf) -> (Library, RegisterFn, FreeFn) {
    // SAFETY: the library built from this repository.
    let library = unsafe { Library::new(path) }.expect("open the library");
    // SAFETY: the symbols have these signatures, as declared in the header.
    let (register, free) = unsafe {
        (
            *library.get::<RegisterFn>(b"sqlite_remote_vfs_register").unwrap(),
            *library.get::<FreeFn>(b"sqlite_remote_vfs_free").unwrap(),
        )
    };
    (library, register, free)
}

#[test]
fn extension_works_after_its_connection_closes() {
    let path = load();
    let (library, _, _) = open(&path);
    // The library's own sqlite3_vfs_find forwards through the API table it received when it was loaded, so it only
    // finds the default VFS if the library is still loaded and initialised. Whether SQLite would unload it without
    // SQLITE_OK_LOAD_PERMANENTLY depends on the platform, so that return value is checked by a unit test of the
    // extension instead.
    // SAFETY: the forwarder has the signature of sqlite3_vfs_find. NULL asks for the default VFS.
    let default_vfs = unsafe {
        let find = library
            .get::<unsafe extern "C" fn(*const c_char) -> *mut c_void>(b"sqlite3_vfs_find")
            .unwrap();
        find(std::ptr::null())
    };
    assert!(
        !default_vfs.is_null(),
        "the extension must still be loaded and initialised"
    );
}

#[test]
fn registration_without_server_fails_cleanly() {
    let path = load();
    let (_library, register, free) = open(&path);
    let login = Login::new("ws://127.0.0.1:1/v1/ws");
    let name = unique("ext-offline");
    let (rc, error) = call(register, free, &name, &login.config());
    assert_eq!(rc, SQLITE_ERROR);
    let error = error.expect("error message");
    assert!(error.contains("127.0.0.1:1"), "message must name the server: {error}");
    assert!(!registered(&name));
}

#[test]
fn extension_registers_with_the_loading_sqlite() {
    let Some(url) = common::server_url() else { return };
    let path = load();
    let (_library, register, free) = open(&path);
    let login = Login::new(&url);
    let name = unique("ext");
    let (rc, error) = call(register, free, &name, &login.config());
    assert_eq!(rc, 0, "register: {error:?}");
    assert!(
        registered(&name),
        "the VFS must be registered with the SQLite that loaded the extension"
    );

    common::round_trip(&name, || {
        let again = unique("ext-again");
        let (rc, error) = call(register, free, &again, &login.config());
        assert_eq!(rc, 0, "register again: {error:?}");
        again
    });
}

#[test]
fn database_deletes_through_extension() {
    let Some(url) = common::server_url() else { return };
    let path = load();
    let (library, register, free) = open(&path);
    // SAFETY: the symbol has this signature, as declared in the header.
    let delete = unsafe { *library.get::<DeleteFn>(b"sqlite_remote_vfs_delete_database").unwrap() };
    let login = Login::new(&url);
    let name = unique("ext-delete");
    let (rc, error) = call(register, free, &name, &login.config());
    assert_eq!(rc, 0, "register: {error:?}");
    common::write_rows(&name);

    let (rc, error) = common::call_delete(delete, free, &name, c"db");
    assert_eq!(rc, 0, "delete: {error:?}");
    assert_eq!(common::tables(&name), 0, "the database must come back empty");
}
