"""sqlite-remote-vfs from Python: loads the extension into Python's own SQLite and uses it with the sqlite3 module.

Needs the `cryptography` package for the Ed25519 key, a page server, and the built extension:

    cargo build --release -p sqlite-remote-vfs-ext
    python remote_vfs.py target/release/libsqlite_remote_vfs_ext.so wss://vfs.example/v1/ws

Python's SQLite does not encrypt, so the server stores plaintext here. With an encrypting SQLite build, open through
"multipleciphers-<name>" (SQLite3 Multiple Ciphers) or set `PRAGMA key` (SQLCipher).
"""

import ctypes
import sqlite3
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

LIBRARY, URL = sys.argv[1], sys.argv[2]

# Load the extension into Python's SQLite. The connection may be closed afterwards; the extension stays loaded.
loader = sqlite3.connect(":memory:")
loader.enable_load_extension(True)
loader.load_extension(LIBRARY)
loader.enable_load_extension(False)
loader.close()

# The C interface of the same library, as declared in sqlite_remote_vfs.h.
library = ctypes.CDLL(LIBRARY)
SignFn = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
)


class Config(ctypes.Structure):
    """sqlite_remote_vfs_config."""

    _fields_ = [
        ("struct_size", ctypes.c_size_t),
        ("url", ctypes.c_char_p),
        ("algorithm", ctypes.c_int),
        ("public_key", ctypes.POINTER(ctypes.c_uint8)),
        ("public_key_len", ctypes.c_size_t),
        ("sign", SignFn),
        ("sign_context", ctypes.c_void_p),
        ("local_copy_path", ctypes.c_char_p),
        ("memory_blocks", ctypes.c_uint64),
        ("blocks_per_fetch", ctypes.c_uint64),
        ("page_size", ctypes.c_uint32),
        ("timeout_ms", ctypes.c_uint32),
        ("reconnect_timeout_ms", ctypes.c_uint32),
        ("takeover", ctypes.c_int),
        ("extra_roots", ctypes.c_void_p),
        ("extra_root_lens", ctypes.c_void_p),
        ("extra_roots_count", ctypes.c_size_t),
    ]


library.sqlite_remote_vfs_register.argtypes = [ctypes.c_char_p, ctypes.POINTER(Config), ctypes.POINTER(ctypes.c_void_p)]
library.sqlite_remote_vfs_free.argtypes = [ctypes.c_void_p]

# The login key stays in Python. The VFS only receives signatures.
key = Ed25519PrivateKey.generate()
public_key = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


@SignFn
def sign(_context, message, message_len, signature, capacity, signature_len):
    data = key.sign(ctypes.string_at(message, message_len))
    if capacity < len(data):
        return 1
    ctypes.memmove(signature, data, len(data))
    signature_len[0] = len(data)
    return 0


public_key_buffer = (ctypes.c_uint8 * len(public_key)).from_buffer_copy(public_key)
# `sign` and `public_key_buffer` must stay referenced for as long as the VFS may log in.
config = Config(
    struct_size=ctypes.sizeof(Config),
    url=URL.encode(),
    algorithm=1,  # SQLITE_REMOTE_VFS_ED25519
    public_key=public_key_buffer,
    public_key_len=len(public_key),
    sign=sign,
)


def register(name):
    error = ctypes.c_void_p()
    if library.sqlite_remote_vfs_register(name.encode(), ctypes.byref(config), ctypes.byref(error)) != 0:
        message = ctypes.string_at(error.value).decode()
        library.sqlite_remote_vfs_free(error)
        raise SystemExit(f"registering {name} failed: {message}")


register("remote")
db = sqlite3.connect("file:app.db?vfs=remote", uri=True)
db.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, text TEXT)")
db.executemany("INSERT INTO notes (text) VALUES (?)", [(f"note {i}",) for i in range(50)])
db.commit()
db.close()

# A second VFS starts with nothing in memory, so this reads from the server.
register("remote-again")
db = sqlite3.connect("file:app.db?vfs=remote-again", uri=True)
print("rows:", db.execute("SELECT count(*) FROM notes").fetchone()[0])
