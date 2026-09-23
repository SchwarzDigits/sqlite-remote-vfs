# sqlite-remote-vfs

[![CI](https://github.com/SchwarzDigits/sqlite-remote-vfs/actions/workflows/ci.yml/badge.svg)](https://github.com/SchwarzDigits/sqlite-remote-vfs/actions/workflows/ci.yml)

A SQLite VFS that stores the database file on a remote server instead of the local disk. SQLite runs unchanged in
the client process. A commit returns only after the server has stored it. With SQLite3 Multiple Ciphers on top, the
server stores only encrypted pages.

Runs natively and in the browser (`wasm32-unknown-unknown`).

Status: works and is tested, not yet in production use. Versions are 0.x: the protocol and the API can still change.

## Features

- **Durable commits.** At `SQLITE_FCNTL_SYNC` the VFS sends all blocks changed by the transaction to the server and
  waits for the acknowledgement. The server applies a commit atomically. After a connection loss the VFS reconnects
  and checks whether the last commit was applied before it sends the commit again.
- **Encryption.** Databases opened through `RemoteVfs::encrypted_name()` are encrypted by SQLite3 Multiple Ciphers
  before the pages reach the VFS. The server never receives plaintext or the database key.
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

## How it works

The server stores the main database file as numbered blocks of the page size, plus a version number per database
that increases with every commit. Journals and temporary files stay in the client's memory. WAL mode is not
available, because the VFS provides no shared memory.

Client and server exchange Protocol Buffers messages over a WebSocket, one binary frame per message. The protocol is
defined in `proto/sqlite_remote/v1/sqlite_remote.proto`. `proto/testdata/v1/` contains one encoded sample of every
message; a server implementation can check that it decodes and encodes them identically.

A server implementation is not part of this repository.

## Not there yet

- One database per registered VFS, one connection per database.
- Recovery after the server was restored from a backup: a client that has seen commits the restored server no
  longer has is not handled yet. The protocol reserves a field number for it.
- CI runs the tests that need no server natively on Linux and macOS and in Firefox, Chrome, Edge and Safari. The
  tests against a server have so far run only locally: natively on macOS and in Firefox and Chrome. Not yet tested
  on Windows.

## Layout

| Path | Content |
|---|---|
| `proto/sqlite_remote/v1/sqlite_remote.proto` | protocol definition |
| `proto/testdata/v1/` | one encoded sample of every message |
| `crates/sqlite-remote-protocol` | Rust types for the protocol (prost, protox) and the test that writes and checks the samples |
| `crates/sqlite-remote-vfs` | the VFS. `tests/remote.rs` runs against a server, `tests/tls.rs` over `wss://` through a TLS terminator started by the test, `tests/spike.rs` checks SQLite's VFS behaviour with an in-memory VFS |
| `crates/sqlite-remote-harness` | test tool: crash test, fault injection, measurements, latency proxy, load test |
| `browser/` | separate workspace for `wasm32-unknown-unknown` with the browser tests, see `browser/README.md` |
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

The tests in `remote.rs` and `tls.rs` need a running server and are skipped without `SQLITE_REMOTE_TEST_URL`. They
log in with random keys. The TLS tests create their own CA and certificates and start a TLS terminator in front of
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
