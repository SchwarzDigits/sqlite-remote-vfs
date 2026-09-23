use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../proto");
    let file = root.join("sqlite_remote/v1/sqlite_remote.proto");
    println!("cargo:rerun-if-changed={}", file.display());

    let descriptors = protox::compile([&file], [&root])?;
    prost_build::Config::new().compile_fds(descriptors)?;
    Ok(())
}
