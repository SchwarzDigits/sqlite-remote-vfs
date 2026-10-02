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
| `copy.rs` | Cache in IndexedDB: reopening without fetches, catching up a stale cache, memory limit with reloads from IndexedDB |
| `nothing_stored.rs` | Without a cache the browser stores nothing of the database |
| `heal.rs` | A database that failed because the server was unreachable heals on the same connection once the server is back, and the failed commit is rolled back. Needs the relay, see below |
| `token.rs` | Access tokens: a missing token is denied, a rejected token is asked for once more, and the connection is renewed with a new token before the old one expires. Slots: claiming replaces the other key, which can no longer write, and deleting releases the slot. Needs `SQLITE_REMOTE_TEST_GATED_URL`, see `crates/sqlite-remote-vfs/tests/token.rs` |
| `local.rs` | Local databases without a server: commits survive a new VFS, a second instance is busy, a takeover fences the first instance, deletion, namespaces, memory limit, commits and preloads larger than the bridge buffer, and the backup of a local database to a server |
| `measure.rs` | Commit latency, reopening time and read latency under memory limits, printed as Markdown tables |

`spike.rs`, `shared_memory.rs`, `wakeup.rs`, `quota.rs` and `local.rs` need no server, except the backup test in
`local.rs`. All other tests need a page server.

## Running

```sh
./test.sh                                              # headless Firefox
./test.sh --chrome                                     # headless Chrome
SAFARIDRIVER=/usr/bin/safaridriver ./test.sh --safari  # Safari, in a window
MSEDGEDRIVER=/path/to/msedgedriver ./test.sh --edge    # headless Edge
```

Safari accepts WebDriver sessions only after remote automation is enabled once with `sudo safaridriver --enable`.
Safari has no headless mode.

The tests that need a server read its URL at compile time. Without `SQLITE_REMOTE_TEST_URL` they return immediately
and pass.

```sh
SQLITE_REMOTE_TEST_URL=ws://127.0.0.1:8080/v1/ws ./test.sh
```

The test page is served from `127.0.0.1`. The server must allow this origin in its `ALLOWED_ORIGINS` setting.

`heal.rs` also needs `relay.py` in front of the server, which the test stops and resumes through a control port:

```sh
python3 relay.py 127.0.0.1:8080 8082 8083 &
SQLITE_REMOTE_TEST_URL=ws://127.0.0.1:8080/v1/ws SQLITE_REMOTE_TEST_RELAY_URL=ws://127.0.0.1:8082/v1/ws \
  SQLITE_REMOTE_TEST_RELAY_CONTROL=http://127.0.0.1:8083 ./test.sh
```

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

**Drivers.** wasm-pack downloads its own chromedriver and ignores `CHROMEDRIVER`, that chromedriver can be a version
ahead of the installed Chrome, and wasm-pack does not support Edge. If the driver variable of the chosen browser is
set (`GECKODRIVER`, `CHROMEDRIVER`, `SAFARIDRIVER` or `MSEDGEDRIVER`), `test.sh` does not use wasm-pack and runs the
tests with `wasm-bindgen-test-runner` and that driver. It takes the runner from `PATH` or from wasm-pack's cache. The
runner's version must match the `wasm-bindgen` version in `Cargo.lock`. CI runs the tests in Firefox, Chrome and Edge
on Linux and in Safari on macOS.

**LLVM.** SQLite's C code is compiled to WebAssembly and packed into a static archive. The macOS system `ar` cannot
index WebAssembly objects, so the linker finds no symbols in the archive, and Apple's clang has a WebAssembly target
only in recent Xcode versions. `test.sh` looks for `llvm-ar` in `PATH`, also under a versioned name such as
`llvm-ar-18`, and in Homebrew's LLVM, and uses the `clang` from the same directory if there is one. To use others,
set `AR_wasm32_unknown_unknown` and `CC_wasm32_unknown_unknown`.

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
