/* Size and field offsets of sqlite_remote_vfs_config as a C compiler lays it out, for the layout test. */
#include <stddef.h>

#include "sqlite_remote_vfs.h"

size_t layout_size(void) { return sizeof(sqlite_remote_vfs_config); }

/* Offsets in field order. Returns (size_t)-1 past the last field. */
size_t layout_offset(int field) {
    switch (field) {
    case 0: return offsetof(sqlite_remote_vfs_config, struct_size);
    case 1: return offsetof(sqlite_remote_vfs_config, url);
    case 2: return offsetof(sqlite_remote_vfs_config, algorithm);
    case 3: return offsetof(sqlite_remote_vfs_config, public_key);
    case 4: return offsetof(sqlite_remote_vfs_config, public_key_len);
    case 5: return offsetof(sqlite_remote_vfs_config, sign);
    case 6: return offsetof(sqlite_remote_vfs_config, sign_context);
    case 7: return offsetof(sqlite_remote_vfs_config, local_copy_path);
    case 8: return offsetof(sqlite_remote_vfs_config, memory_blocks);
    case 9: return offsetof(sqlite_remote_vfs_config, blocks_per_fetch);
    case 10: return offsetof(sqlite_remote_vfs_config, page_size);
    case 11: return offsetof(sqlite_remote_vfs_config, timeout_ms);
    case 12: return offsetof(sqlite_remote_vfs_config, reconnect_timeout_ms);
    case 13: return offsetof(sqlite_remote_vfs_config, takeover);
    case 14: return offsetof(sqlite_remote_vfs_config, extra_roots);
    case 15: return offsetof(sqlite_remote_vfs_config, extra_root_lens);
    case 16: return offsetof(sqlite_remote_vfs_config, extra_roots_count);
    default: return (size_t)-1;
    }
}

