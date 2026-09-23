# sqlite-remote-vfs

[![CI](https://github.com/SchwarzDigits/sqlite-remote-vfs/actions/workflows/ci.yml/badge.svg)](https://github.com/SchwarzDigits/sqlite-remote-vfs/actions/workflows/ci.yml)

A SQLite VFS that stores the database file on a remote server instead of the local disk. SQLite runs unchanged in
the client process. A commit returns only after the server has stored it. With encryption above the VFS, such as
SQLite3 Multiple Ciphers or SQLCipher, the server stores only encrypted pages.

Runs natively and in the browser (`wasm32-unknown-unknown`).

Status: works and is tested, not yet in production use. Versions are 0.x: the protocol and the API can still change.

## Features

- **Durable commits.** At `SQLITE_FCNTL_SYNC` the VFS sends all blocks changed by the transaction to the server and
  waits for the acknowledgement. The server applies a commit atomically. After a connection loss the VFS reconnects
  and checks whether the last commit was applied before it sends the commit again.
- **Encryption above the VFS.** The VFS itself does not encrypt and depends on no encryption library. Encryption that
  runs above it keeps plaintext and the database key away from the server. Tested with SQLite3 Multiple Ciphers
  (open through `RemoteVfs::encrypted_name()`) and SQLCipher (open through `RemoteVfs::name()`), in both cases with
  `PRAGMA key`. With plain SQLite the server stores plaintext.
- **Login by signature.** The application passes a `Signer`: an algorithm, a public key and a sign function. The
  server sends a challenge, verifies the signature and derives the client's subject from the public key. A client
  can only open databases under its own subject. The VFS holds no key material. Supported algorithm: Ed25519.
  The signature is not bound to the connection, so a server the client connects to could relay another server's
  challenge. Use a separate key for each server.
- **One writer per database.** Opening a database acquires a lease. A newer lease has a higher epoch and fences off
  all older ones, so an outdated client cannot overwrite newer data.
- **Local copy (optional).** A file natively, IndexedDB in the browser. Reads are served from it without a round
  trip. It contains only data the server has acknowledged and may be incomplete; missing blocks are fetched from the
  server. A stale copy is brought up to date from the server's change log: only the blocks changed since its version
  are discarded.
- **Memory limit (optional).** `Memory::Blocks(n)` keeps at most `n` blocks in memory and evicts the least recently
  used. Blocks modified since the last commit are never evicted.
- **Loading.** `Load::Preload` (default) reads the whole database when it is opened. `Load::OnDemand` fetches blocks
  when SQLite first reads them.
- **TLS.** `wss://` natively via rustls, trusting the operating system's certificate store and the CAs in
  `Config::extra_roots`. In the browser, the browser handles TLS. `ws://` is supported for local servers and servers
  behind a TLS-terminating proxy.

## Example

```rust
use std::sync::Arc;

use rusqlite::{Connection, OpenFlags};
use sqlite_remote_vfs::{Algorithm, Config, RemoteVfs, Signer};

struct Key(ed25519_dalek::SigningKey);

impl Signer for Key {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }

    fn public_key(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer as _;
        self.0.sign(message).to_bytes().to_vec()
    }
}

let signer: Arc<dyn Signer> = Arc::new(Key(signing_key));
let vfs = RemoteVfs::register("remote", Config::new("wss://server.example/v1/ws", signer))?;

let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE;
let conn = Connection::open_with_flags_and_vfs("app.db", flags, vfs.encrypted_name().as_str())?;
conn.pragma_update(None, "key", database_key)?;
// From here on, use SQLite as usual.
```

The example uses SQLite3 Multiple Ciphers. With SQLCipher, open through `vfs.name()` instead.

`Config` also sets the page size (default 4096), the local copy, the memory limit, the loading mode, timeouts and
lease takeover. `vfs.stats()` returns counters for commits, fetches, the local copy and evictions.

### In the browser

- Register with `RemoteVfs::register_async` instead of `register`.
- SQLite and the VFS must run in a dedicated worker. The VFS blocks with `Atomics.wait`, which browsers do not allow
  on the main thread.
- The page must be cross-origin isolated (`Cross-Origin-Opener-Policy: same-origin`,
  `Cross-Origin-Embedder-Policy: require-corp`), because the VFS uses `SharedArrayBuffer`.
- The VFS starts a second worker that holds the WebSocket connection.
- `Local::Browser` keeps the local copy in IndexedDB.

`browser/` builds SQLite with SQLite3 Multiple Ciphers for the browser and contains the browser tests.

## Other languages

`sqlite-remote-vfs-ext` builds the VFS as a loadable SQLite extension with a C interface. It contains no SQLite: it
uses the SQLite that loads it, whether plain SQLite, SQLite3 Multiple Ciphers, SQLCipher or another build (3.14.0 or
later, with extension loading enabled). `sqlite-remote-vfs-ffi` builds the same interface as a static library for
programs that link SQLite themselves.

```sh
cargo build --release -p sqlite-remote-vfs-ext   # target/release/libsqlite_remote_vfs_ext.so or .dylib
cargo build --release -p sqlite-remote-vfs-ffi   # target/release/libsqlite_remote_vfs_ffi.a
```

The interface is declared in `crates/sqlite-remote-vfs-ffi/include/sqlite_remote_vfs.h`:

1. Load the extension with `sqlite3_load_extension()` or `load_extension()`. With the static library, skip this step.
2. Call `sqlite_remote_vfs_register()` with a name and a configuration: URL, public key and a sign function. With the
   extension, call it from the loaded library: link against it or look it up with `dlsym`. The private key stays in
   the calling program; the sign function is called at every login.
3. Open databases through the VFS name, or through `multipleciphers-<name>` with SQLite3 Multiple Ciphers.

A program that links the static library also links SQLite and the system libraries that
`cargo rustc -p sqlite-remote-vfs-ffi --crate-type staticlib -- --print native-static-libs` lists.

```c
sqlite_remote_vfs_config config = {
    .struct_size = sizeof config,
    .url = "wss://vfs.example/v1/ws",
    .algorithm = SQLITE_REMOTE_VFS_ED25519,
    .public_key = public_key,
    .public_key_len = 32,
    .sign = sign,              /* signs with the application's Ed25519 key */
    .sign_context = key,
};
char *error = NULL;
if (sqlite_remote_vfs_register("remote", &config, &error) != SQLITE_OK) {
    fprintf(stderr, "%s\n", error);
    sqlite_remote_vfs_free(error);
}
sqlite3_open_v2("app.db", &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, "remote");
```

`examples/python/remote_vfs.py` does the same from Python with the `sqlite3` and `ctypes` modules.

## How it works

The server stores the main database file as numbered blocks of the page size, plus a version number per database
that increases with every commit. Journals and temporary files stay in the client's memory. WAL mode is not
available, because the VFS provides no shared memory.

Client and server exchange Protocol Buffers messages over a WebSocket, one binary frame per message. The protocol is
defined in `proto/sqlite_remote/v1/sqlite_remote.proto`. `proto/testdata/v1/` contains one encoded sample of every
message; a server implementation can check that it decodes and encodes them identically.

The server is [sqlite-remote-server](https://github.com/SchwarzDigits/sqlite-remote-server), written in Go, with an
in-memory store and a PostgreSQL store.

## Not there yet

- One database per registered VFS, one connection per database.
- Recovery after the server was restored from a backup: a client that has seen commits the restored server no
  longer has is not handled yet. The protocol reserves a field number for it.
- CI runs all tests against [sqlite-remote-server](https://github.com/SchwarzDigits/sqlite-remote-server):
  natively on Linux and macOS, against PostgreSQL on Linux, and in Firefox, Chrome, Edge and Safari. Not yet tested
  on Windows.
- The extension and the static library are tested on Linux and macOS, not yet on Windows.

## Layout

| Path | Content |
|---|---|
| `proto/sqlite_remote/v1/sqlite_remote.proto` | protocol definition |
| `proto/testdata/v1/` | one encoded sample of every message |
| `crates/sqlite-remote-protocol` | Rust types for the protocol (prost, protox) and the test that writes and checks the samples |
| `crates/sqlite-remote-vfs` | the VFS. `tests/remote.rs` runs against a server, `tests/tls.rs` over `wss://` through a TLS terminator started by the test, `tests/spike.rs` checks SQLite's VFS behaviour with an in-memory VFS |
| `crates/sqlite-remote-vfs-ffi` | C interface and header, built as a static library |
| `crates/sqlite-remote-vfs-ext` | the loadable extension: the C interface plus the entry point, using the SQLite that loads it |
| `crates/sqlite-remote-harness` | test tool: crash test, fault injection, measurements, latency proxy, load test |
| `browser/` | separate workspace for `wasm32-unknown-unknown` with the browser tests, see `browser/README.md` |
| `extension/` | separate workspace that tests the extension and the static library with plain SQLite |
| `examples/python/` | the extension used from Python |
| `sqlcipher/` | separate workspace that tests the VFS with SQLCipher instead of SQLite3 Multiple Ciphers |
| `vendor/libsqlite3-sys` | libsqlite3-sys 0.36.0 with SQLite3 Multiple Ciphers for native builds, see `vendor/libsqlite3-sys/sqlite3mc/README.md` |

## Build and test

Requires rustup. `rust-toolchain.toml` pins Rust 1.97.1. `protoc` and `buf` are not needed: `protox` compiles the
`.proto` file in the build script.

```sh
cargo test
cargo test --test spike -- --nocapture                               # also prints the recorded VFS calls
SQLITE_REMOTE_UPDATE_GOLDEN=1 cargo test -p sqlite-remote-protocol    # rewrites proto/testdata after a protocol change
SQLITE_REMOTE_TEST_URL=ws://localhost:8080/v1/ws cargo test -p sqlite-remote-vfs --test remote --test tls
```

The native tests use SQLite3 Multiple Ciphers. The tests with SQLCipher are a separate workspace, because one build
links exactly one SQLite. They build SQLCipher and OpenSSL from source:

```sh
cd sqlcipher && cargo test          # with SQLITE_REMOTE_TEST_URL also against a server
```

The tests of the extension and the static library are a separate workspace too, with plain SQLite. They load the
extension from `target/debug`:

```sh
cargo build -p sqlite-remote-vfs-ext && (cd extension && cargo test)
```

The tests in `remote.rs` and `tls.rs` need a running
[sqlite-remote-server](https://github.com/SchwarzDigits/sqlite-remote-server) and are skipped without
`SQLITE_REMOTE_TEST_URL`. The server's `SQLITE_REMOTE_SERVER_ID` must equal that URL. The tests log in with random
keys. The TLS tests create their own CA and certificates and start a TLS terminator in front of
the server, so no system configuration is needed.

## Harness

Runs against a server that is already running.

```sh
sqlite-remote-harness crash   --url ws://… [--iterations 30]        # kills a writer at random, checks that no acknowledged commit is lost
sqlite-remote-harness faults  --url ws://… [--transactions 1500]    # breaks the connection during commits, via a proxy
sqlite-remote-harness load    --url ws://… [--clients 10] [--seconds 20] [--rate 0] [--kind keystore|message]
sqlite-remote-harness measure --url ws://… [--delays-ms 0,25,50]    # prints the measurements as Markdown tables
sqlite-remote-harness proxy   --url ws://… [--port 18190] [--delay-ms 25] [--mbit 20]
```

`load` runs many clients in parallel. Afterwards each client reopens its database from the server and checks that it
contains exactly the acknowledged commits. `--rate` is commits per second per client; `0` means as fast as possible.
With a rate, latency is measured from the time a commit was due, so a server that falls behind shows up as latency.

## License

Apache License 2.0, see [`LICENSE`](LICENSE).

`vendor/libsqlite3-sys` contains third-party code under its own licenses: libsqlite3-sys under the MIT license
(`vendor/libsqlite3-sys/LICENSE`), SQLite3 Multiple Ciphers under the MIT license
(`vendor/libsqlite3-sys/sqlite3mc/LICENSE`), and SQLite in the public domain.
