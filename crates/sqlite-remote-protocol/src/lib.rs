//! Protocol messages between the VFS client and the page server, generated with prost from
//! `proto/sqlite_remote/v1/sqlite_remote.proto`.

/// Version 1 of the protocol.
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/sqlite_remote.v1.rs"));
}
