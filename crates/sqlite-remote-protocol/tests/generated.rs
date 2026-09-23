//! Generates the protocol code from `proto/sqlite_remote/v1/sqlite_remote.proto` and compares it with the checked-in
//! `src/sqlite_remote.v1.rs`.
//!
//! After changing the .proto file, run
//! `SQLITE_REMOTE_UPDATE_GENERATED=1 cargo test -p sqlite-remote-protocol --test generated` to rewrite the file.

use std::path::PathBuf;

#[test]
fn generated_code_matches_proto_file() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest.join("../../proto");
    let descriptors =
        protox::compile([root.join("sqlite_remote/v1/sqlite_remote.proto")], [&root]).expect("compile the .proto file");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("sqlite-remote-protocol-generated");
    std::fs::create_dir_all(&out).unwrap();
    prost_build::Config::new()
        .out_dir(&out)
        .compile_fds(descriptors)
        .expect("generate the code");
    let generated = std::fs::read_to_string(out.join("sqlite_remote.v1.rs")).unwrap();

    let checked_in = manifest.join("src/sqlite_remote.v1.rs");
    if std::env::var_os("SQLITE_REMOTE_UPDATE_GENERATED").is_some_and(|value| value == "1") {
        std::fs::write(&checked_in, &generated).unwrap();
    }
    let current = std::fs::read_to_string(&checked_in).unwrap_or_default();
    assert!(
        current == generated,
        "src/sqlite_remote.v1.rs does not match the .proto file. Run with SQLITE_REMOTE_UPDATE_GENERATED=1 to rewrite it."
    );
}
