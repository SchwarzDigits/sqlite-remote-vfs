fn main() {
    // On Linux, calls inside the library to its own exported functions can be resolved to a function of the same name
    // in the program or in another library (symbol interposition). -Bsymbolic binds them to the library's own
    // definitions, so the SQLite functions below always go through the API table of the SQLite that loaded it.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-Bsymbolic");
    }
}
