/*
 * C interface to sqlite-remote-vfs: a SQLite VFS that stores the database file on a remote page server.
 *
 * Two ways to use it:
 *
 * - Loadable extension: load libsqlite_remote_vfs_ext with sqlite3_load_extension() (or load_extension() in SQL),
 *   then call sqlite_remote_vfs_register() from the same library. The extension uses the SQLite that loaded it.
 * - Static library: link libsqlite_remote_vfs_ffi into a program that links SQLite itself, then call
 *   sqlite_remote_vfs_register().
 *
 * After registration, open databases through the VFS name: with SQLite3 Multiple Ciphers through
 * "multipleciphers-<name>", otherwise through "<name>". The VFS does not encrypt. Without encryption above it, the
 * server stores plaintext.
 */
#ifndef SQLITE_REMOTE_VFS_H
#define SQLITE_REMOTE_VFS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Signature algorithm of the login key. */
#define SQLITE_REMOTE_VFS_ED25519 1

/*
 * Signs a login transcript. Writes the signature to `signature`, which holds `signature_capacity` bytes, and its
 * length to `*signature_len`. Returns 0 on success. On failure the login fails.
 *
 * Called whenever the VFS logs in, which includes reconnects, possibly from different threads. It must be
 * thread-safe, and `context` must stay valid for the life of the process.
 */
typedef int (*sqlite_remote_vfs_sign_fn)(void *context, const uint8_t *message, size_t message_len,
                                         uint8_t *signature, size_t signature_capacity, size_t *signature_len);

typedef struct sqlite_remote_vfs_config {
    /* Must be sizeof(sqlite_remote_vfs_config). */
    size_t struct_size;
    /* WebSocket URL of the page server, e.g. "wss://vfs.example/v1/ws". Required. */
    const char *url;
    /* Login key: algorithm (SQLITE_REMOTE_VFS_ED25519), public key and sign function. Required. */
    int algorithm;
    const uint8_t *public_key;
    size_t public_key_len;
    sqlite_remote_vfs_sign_fn sign;
    void *sign_context;
    /* Path of the local copy file. NULL: no local copy. */
    const char *local_copy_path;
    /* Maximum number of blocks kept in memory. 0: no limit. */
    uint64_t memory_blocks;
    /* 0: load all blocks when a database is opened. n > 0: load blocks on first read, n consecutive blocks per
     * fetch. */
    uint64_t blocks_per_fetch;
    /* Page size of new databases. 0: 4096. */
    uint32_t page_size;
    /* Timeout for connecting and for each response, in milliseconds. 0: 10000. */
    uint32_t timeout_ms;
    /* How long a commit tries to reconnect before it fails, in milliseconds. 0: 10000. */
    uint32_t reconnect_timeout_ms;
    /* Nonzero: take the lease of a database even if another instance holds it. */
    int takeover;
    /* Additional DER-encoded CA certificates for wss://, trusted besides those of the operating system. */
    const uint8_t *const *extra_roots;
    const size_t *extra_root_lens;
    size_t extra_roots_count;
} sqlite_remote_vfs_config;

/*
 * Connects to the server, logs in and registers the VFS with SQLite under `name`. The VFS stays registered for the
 * life of the process.
 *
 * Returns 0 on success. On failure returns a nonzero SQLite result code and, if `error` is not NULL, sets `*error` to
 * a message that the caller releases with sqlite_remote_vfs_free().
 */
int sqlite_remote_vfs_register(const char *name, const sqlite_remote_vfs_config *config, char **error);

/* Releases a message returned by sqlite_remote_vfs_register(). NULL is allowed. */
void sqlite_remote_vfs_free(char *message);

#ifdef __cplusplus
}
#endif

#endif /* SQLITE_REMOTE_VFS_H */
