//! The static library: the C interface linked into a program together with plain SQLite.
//!
//! `database_round_trips_with_plain_sqlite` needs `SQLITE_REMOTE_TEST_URL` and is skipped without it.

mod common;

use std::ffi::c_char;

use common::{Login, call, registered, unique};
use sqlite_remote_vfs_ffi::{sqlite_remote_vfs_free, sqlite_remote_vfs_register};

const SQLITE_ERROR: i32 = 1;
const SQLITE_MISUSE: i32 = 21;

#[test]
fn registration_without_server_fails_cleanly() {
    let login = Login::new("ws://127.0.0.1:1/v1/ws");
    let name = unique("static-offline");
    let (rc, error) = call(
        sqlite_remote_vfs_register,
        sqlite_remote_vfs_free,
        &name,
        &login.config(),
    );
    assert_eq!(rc, SQLITE_ERROR);
    let error = error.expect("error message");
    assert!(error.contains("127.0.0.1:1"), "message must name the server: {error}");
    assert!(!registered(&name), "a failed registration must not leave a VFS behind");
}

#[test]
fn invalid_arguments_are_misuse() {
    let login = Login::new("ws://127.0.0.1:1/v1/ws");
    let name = unique("static-misuse");

    let mut config = login.config();
    config.struct_size -= 1;
    let (rc, error) = call(sqlite_remote_vfs_register, sqlite_remote_vfs_free, &name, &config);
    assert_eq!(rc, SQLITE_MISUSE);
    assert!(error.unwrap().contains("struct_size"));

    let mut config = login.config();
    config.sign = None;
    let (rc, error) = call(sqlite_remote_vfs_register, sqlite_remote_vfs_free, &name, &config);
    assert_eq!(rc, SQLITE_MISUSE);
    assert!(error.unwrap().contains("sign"));

    let mut config = login.config();
    config.algorithm = 99;
    let (rc, error) = call(sqlite_remote_vfs_register, sqlite_remote_vfs_free, &name, &config);
    assert_eq!(rc, SQLITE_MISUSE);
    assert!(error.unwrap().contains("algorithm"));

    // SAFETY: a NULL name is allowed and rejected. NULL error pointer: no message.
    let rc = unsafe { sqlite_remote_vfs_register(std::ptr::null(), &login.config(), std::ptr::null_mut()) };
    assert_eq!(rc, SQLITE_MISUSE);
    // SAFETY: NULL is allowed.
    unsafe { sqlite_remote_vfs_free(std::ptr::null_mut::<c_char>()) };
}

#[test]
fn database_round_trips_with_plain_sqlite() {
    let Some(url) = common::server_url() else { return };
    let login = Login::new(&url);
    let name = unique("static");
    let (rc, error) = call(
        sqlite_remote_vfs_register,
        sqlite_remote_vfs_free,
        &name,
        &login.config(),
    );
    assert_eq!(rc, 0, "register: {error:?}");
    assert!(registered(&name), "the VFS must be registered with the linked SQLite");

    common::round_trip(&name, || {
        let again = unique("static-again");
        let (rc, error) = call(
            sqlite_remote_vfs_register,
            sqlite_remote_vfs_free,
            &again,
            &login.config(),
        );
        assert_eq!(rc, 0, "register again: {error:?}");
        again
    });
}
