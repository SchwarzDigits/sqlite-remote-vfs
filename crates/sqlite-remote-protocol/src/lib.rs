//! Protocol messages between the VFS client and the page server, generated with prost from
//! `proto/sqlite_remote/v1/sqlite_remote.proto`.
//!
//! The generated code is checked in as `src/sqlite_remote.v1.rs`, so building this crate runs no code generator.
//! `tests/generated.rs` checks that it matches the .proto file.

/// Version 1 of the protocol.
pub mod v1 {
    include!("sqlite_remote.v1.rs");
}
