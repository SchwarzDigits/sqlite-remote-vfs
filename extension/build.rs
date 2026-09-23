// Compiles c/layout.c against the public header. The layout test compares the C struct with the Rust one, and the
// strict flags fail the build if the header does not compile cleanly.
fn main() {
    println!("cargo:rerun-if-changed=c/layout.c");
    println!("cargo:rerun-if-changed=../crates/sqlite-remote-vfs-ffi/include/sqlite_remote_vfs.h");
    cc::Build::new()
        .file("c/layout.c")
        .include("../crates/sqlite-remote-vfs-ffi/include")
        .flag_if_supported("-std=c99")
        .flag_if_supported("-Wall")
        .flag_if_supported("-Wextra")
        .flag_if_supported("-Wpedantic")
        .warnings_into_errors(true)
        .compile("layout");
}
