//! The C struct in the header and the Rust struct in sqlite-remote-vfs-ffi must have the same layout.

use std::ffi::c_int;
use std::mem::offset_of;

use sqlite_remote_vfs_ffi::SqliteRemoteVfsConfig as Config;
// Links SQLite, which this test does not use otherwise: the MSVC linker requires every SQLite function that
// rsqlite-vfs declares.
use rusqlite as _;
// Links this package's library, which carries c/layout.c compiled by build.rs.
use sqlite_remote_vfs_extension_tests as _;

unsafe extern "C" {
    // From c/layout.c, compiled against the header by build.rs.
    fn layout_size() -> usize;
    fn layout_offset(field: c_int) -> usize;
}

#[test]
fn config_layout_matches_header() {
    let rust = [
        offset_of!(Config, struct_size),
        offset_of!(Config, url),
        offset_of!(Config, algorithm),
        offset_of!(Config, public_key),
        offset_of!(Config, public_key_len),
        offset_of!(Config, sign),
        offset_of!(Config, sign_context),
        offset_of!(Config, local_copy_path),
        offset_of!(Config, memory_blocks),
        offset_of!(Config, blocks_per_fetch),
        offset_of!(Config, page_size),
        offset_of!(Config, timeout_ms),
        offset_of!(Config, reconnect_timeout_ms),
        offset_of!(Config, takeover),
        offset_of!(Config, extra_roots),
        offset_of!(Config, extra_root_lens),
        offset_of!(Config, extra_roots_count),
    ];
    // SAFETY: plain functions without arguments that need care.
    unsafe {
        assert_eq!(layout_size(), size_of::<Config>(), "sizeof(sqlite_remote_vfs_config)");
        for (field, offset) in rust.iter().enumerate() {
            assert_eq!(layout_offset(field as c_int), *offset, "offset of field {field}");
        }
        assert_eq!(
            layout_offset(rust.len() as c_int),
            usize::MAX,
            "the header has more fields than the Rust struct"
        );
    }
}
