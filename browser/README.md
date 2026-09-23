# Browser build and tests

This workspace builds the VFS for `wasm32-unknown-unknown` and runs its tests in a browser. SQLite is compiled to
WebAssembly with SQLite3 Multiple Ciphers.

## Tests

| File | Checks |
|---|---|
| `spike.rs` | With the in-memory VFS in `src/lib.rs`: SQLite3 Multiple Ciphers encrypts above a Rust VFS, the VFS stores only ciphertext, a database opens only with its key, WAL is refused, the rollback journal is stored in the VFS |
| `shared_memory.rs` | `SharedArrayBuffer` and `Atomics` work in a dedicated worker |
| `wakeup.rs` | A worker blocked in `Atomics.wait` is woken by a second worker. The bridge between the SQLite worker and the connection worker is built on this |
| `quota.rs` | The browser's storage quota for the origin is larger than 512 MiB |
| `remote.rs` | A database written through the remote VFS is read back from the server, and each autocommit statement is one commit |
| `login.rs` | The same key opens the same database again. Another key cannot open it |
| `copy.rs` | Local copy in IndexedDB: reopening without fetches, catching up a stale copy, memory limit with reloads from IndexedDB |
| `nothing_stored.rs` | Without a local copy the browser stores nothing of the database |
| `measure.rs` | Commit latency, reopening time and read latency under memory limits, printed as Markdown tables |

`spike.rs`, `shared_memory.rs`, `wakeup.rs` and `quota.rs` need no server. All other tests need a page server.

## Running

```sh
./test.sh              # headless Firefox
./test.sh --chrome     # any browser flag of wasm-pack
```

The tests that need a server read its URL at compile time. Without `SQLITE_REMOTE_TEST_URL` they return immediately
and pass.

```sh
SQLITE_REMOTE_TEST_URL=ws://127.0.0.1:8080/v1/ws ./test.sh
```

The test page is served from `127.0.0.1`. The server must allow this origin in its `ALLOWED_ORIGINS` setting.

Variables for `measure.rs`, all read at compile time:

| Variable | Default | Meaning |
|---|---|---|
| `SQLITE_REMOTE_TEST_SLOW_URL` | not set | the same server behind a proxy that adds latency. Without it, the reopening measurement over a slow line is skipped |
| `SQLITE_REMOTE_TEST_ROWS` | 500 | rows written for the commit measurement. Use fewer against a server with real latency, e.g. 60 |
| `SQLITE_REMOTE_TEST_BIG_ROWS` | 2000 | rows written for the reopening measurement over the slow line |

Arguments after `--` go to `cargo test`, and arguments after a second `--` go to the tests. To see the tables:

```sh
SQLITE_REMOTE_TEST_URL=ws://127.0.0.1:8080/v1/ws ./test.sh --firefox -- --test measure -- --nocapture
```

**Timeout.** `test.sh` sets `WASM_BINDGEN_TEST_TIMEOUT` to 180 s unless it is already set. The measurement tests take
longer than the runner's default of 20 s, in Firefox much longer, because its IndexedDB is slower.

**Drivers.** wasm-pack downloads its own chromedriver and ignores `CHROMEDRIVER`, and that chromedriver can be a
version ahead of the installed Chrome. With `CHROMEDRIVER` (for `--chrome`) or `GECKODRIVER` (for `--firefox`) set,
`test.sh` does not use wasm-pack and runs the tests with `wasm-bindgen-test-runner` and that driver. It takes the
runner from `PATH` or from wasm-pack's cache. The runner's version must match the `wasm-bindgen` version in
`Cargo.lock`.

**llvm-ar.** SQLite's C code is compiled to WebAssembly and packed into a static archive. The macOS system `ar` cannot
index WebAssembly objects, so the linker finds no symbols in the archive. `test.sh` looks for `llvm-ar` in `PATH`,
also under a versioned name such as `llvm-ar-18`, and in Homebrew's LLVM. To use another one, set
`AR_wasm32_unknown_unknown`.

## Differences from the native build

- **No threads.** SQLite is compiled single-threaded. A JavaScript value cannot be sent to another worker.
- **No sleep.** Blocking requires shared memory, so `xSleep` returns immediately.
- **No clock from `std`.** `SystemTime::now` panics on this target. The time comes from JavaScript.
- **No WAL.** The VFS provides no shared memory, as in the native build.

Random bytes come from the browser's Web Crypto API, without a fallback.

## Dependencies

- `sqlite-wasm-rs` 0.5.5 with the `sqlite3mc` feature is pinned. An application that uses this VFS links its own
  SQLite, and that should be the build the VFS was tested with.
- This is a separate workspace. The native workspace patches `libsqlite3-sys` to a vendored copy, which this target
  does not use. Here `rusqlite` binds to `sqlite-wasm-rs`, with a different `rusqlite` version than the native tests.
