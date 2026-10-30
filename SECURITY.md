# Security Policy

sqlite-remote-vfs follows the security policy of the Schwarz Digits open-source program:
<https://github.com/SchwarzDigits/.github/blob/main/SECURITY.md>. Report vulnerabilities privately to
<opensource@digits.schwarz>, not in a public issue, discussion or pull request. The policy says what to include, how we
respond, and how the coordinated disclosure within 90 days works.

## What this project adds

- **Scope.** Versions are 0.x and not in production use; fixes land on `main`, the only supported line. Name the
  component you observed the problem in: the VFS (`crates/sqlite-remote-vfs`), the protocol (`proto/`,
  `crates/sqlite-remote-protocol`), the C interface (`crates/sqlite-remote-vfs-ffi`, `crates/sqlite-remote-vfs-ext`)
  or the browser build (`browser/`).
- **What counts.** The [README](README.md) states what the VFS guarantees and what it leaves to the application:
  encryption runs above the VFS and the VFS holds no key material, the server derives the subject from the public key
  and a client cannot choose it, an access token is bound to the client's key, one writer per database, and an
  acknowledged commit is stored. A report that breaks a stated guarantee is a vulnerability. The limits the README
  names, such as the login signature not being bound to the connection, are accepted by design: a report that
  confirms one is welcome as an ordinary issue, a report that shows one to be worse than stated is a vulnerability.
- **Not here.** The server is [sqlite-remote-server](https://github.com/SchwarzDigits/sqlite-remote-server), a
  repository of its own under the same policy; report findings in it there. Findings in SQLite, SQLite3 Multiple
  Ciphers or SQLCipher belong to those projects. The copy under `vendor/libsqlite3-sys` is updated from upstream.
- **Credit.** Reports are credited in the release notes unless you prefer otherwise.
