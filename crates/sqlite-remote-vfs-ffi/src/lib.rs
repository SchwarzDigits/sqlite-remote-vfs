//! C interface to sqlite-remote-vfs, declared in `include/sqlite_remote_vfs.h`.
//!
//! Linked statically into a program that links SQLite itself, or wrapped by `sqlite-remote-vfs-ext` as a loadable
//! SQLite extension. The layout of [`SqliteRemoteVfsConfig`] must match `sqlite_remote_vfs_config` in the header.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sqlite_remote_vfs::{Algorithm, Config, Load, Local, Memory, RemoteVfs, Signer};

/// `SQLITE_REMOTE_VFS_ED25519` in the header.
pub const ED25519: c_int = 1;

const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
const SQLITE_MISUSE: c_int = 21;

/// Buffer size for a signature. Ed25519 needs 64 bytes.
const SIGNATURE_CAPACITY: usize = 1024;

/// `sqlite_remote_vfs_sign_fn` in the header.
pub type SignFn = unsafe extern "C" fn(
    context: *mut c_void,
    message: *const u8,
    message_len: usize,
    signature: *mut u8,
    signature_capacity: usize,
    signature_len: *mut usize,
) -> c_int;

/// `sqlite_remote_vfs_config` in the header.
#[repr(C)]
pub struct SqliteRemoteVfsConfig {
    pub struct_size: usize,
    pub url: *const c_char,
    pub algorithm: c_int,
    pub public_key: *const u8,
    pub public_key_len: usize,
    pub sign: Option<SignFn>,
    pub sign_context: *mut c_void,
    pub local_copy_path: *const c_char,
    pub memory_blocks: u64,
    pub blocks_per_fetch: u64,
    pub page_size: u32,
    pub timeout_ms: u32,
    pub reconnect_timeout_ms: u32,
    pub takeover: c_int,
    pub extra_roots: *const *const u8,
    pub extra_root_lens: *const usize,
    pub extra_roots_count: usize,
}

/// A [`Signer`] that calls the application's sign function.
struct CallbackSigner {
    algorithm: Algorithm,
    public_key: Vec<u8>,
    sign: SignFn,
    context: *mut c_void,
}

// SAFETY: the header requires the sign function to be thread-safe and its context to stay valid for the life of the
// process.
unsafe impl Send for CallbackSigner {}
// SAFETY: see above.
unsafe impl Sync for CallbackSigner {}

impl Signer for CallbackSigner {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    /// Returns an empty signature if the sign function fails. The server then rejects the login.
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut signature = vec![0u8; SIGNATURE_CAPACITY];
        let mut len = 0usize;
        // SAFETY: the buffers are valid for the given lengths. The contract of the sign function is in the header.
        let rc = unsafe {
            (self.sign)(
                self.context,
                message.as_ptr(),
                message.len(),
                signature.as_mut_ptr(),
                signature.len(),
                &mut len,
            )
        };
        if rc != 0 || len > signature.len() {
            return Vec::new();
        }
        signature.truncate(len);
        signature
    }
}

/// An error with the SQLite result code to return.
struct Failure(c_int, String);

fn misuse(message: impl Into<String>) -> Failure {
    Failure(SQLITE_MISUSE, message.into())
}

/// Reads a C string argument.
///
/// # Safety
/// `ptr` is NULL or points to a NUL-terminated string.
unsafe fn string(ptr: *const c_char, what: &str) -> Result<String, Failure> {
    if ptr.is_null() {
        return Err(misuse(format!("{what} is NULL")));
    }
    // SAFETY: not NULL, and NUL-terminated per the caller's contract.
    let text = unsafe { CStr::from_ptr(ptr) };
    text.to_str()
        .map(str::to_owned)
        .map_err(|_| misuse(format!("{what} is not valid UTF-8")))
}

/// Reads a byte array argument.
///
/// # Safety
/// `ptr` is NULL or points to `len` readable bytes.
unsafe fn bytes(ptr: *const u8, len: usize, what: &str) -> Result<Vec<u8>, Failure> {
    if ptr.is_null() || len == 0 {
        return Err(misuse(format!("{what} is empty")));
    }
    // SAFETY: not NULL, and `len` bytes per the caller's contract.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec())
}

/// Builds the Rust configuration from the C one.
///
/// # Safety
/// All pointers in `c` follow the contract in the header.
unsafe fn config(c: &SqliteRemoteVfsConfig) -> Result<Config, Failure> {
    if c.struct_size != size_of::<SqliteRemoteVfsConfig>() {
        return Err(misuse("struct_size must be sizeof(sqlite_remote_vfs_config)"));
    }
    // SAFETY: per the header.
    let url = unsafe { string(c.url, "url") }?;
    let algorithm = match c.algorithm {
        ED25519 => Algorithm::Ed25519,
        other => return Err(misuse(format!("unsupported algorithm {other}"))),
    };
    // SAFETY: per the header.
    let public_key = unsafe { bytes(c.public_key, c.public_key_len, "public_key") }?;
    let sign = c.sign.ok_or_else(|| misuse("sign is NULL"))?;
    let signer = CallbackSigner {
        algorithm,
        public_key,
        sign,
        context: c.sign_context,
    };

    let mut config = Config::new(url, Arc::new(signer));
    if !c.local_copy_path.is_null() {
        // SAFETY: per the header.
        let path = unsafe { string(c.local_copy_path, "local_copy_path") }?;
        config.local = Local::File(PathBuf::from(path));
    }
    if c.memory_blocks > 0 {
        config.memory = Memory::Blocks(c.memory_blocks);
    }
    if c.blocks_per_fetch > 0 {
        config.load = Load::OnDemand {
            blocks_per_fetch: c.blocks_per_fetch,
        };
    }
    if c.page_size > 0 {
        config.page_size = c.page_size;
    }
    if c.timeout_ms > 0 {
        config.timeout = Duration::from_millis(c.timeout_ms.into());
    }
    if c.reconnect_timeout_ms > 0 {
        config.reconnect_timeout = Duration::from_millis(c.reconnect_timeout_ms.into());
    }
    config.takeover = c.takeover != 0;
    if c.extra_roots_count > 0 {
        if c.extra_roots.is_null() || c.extra_root_lens.is_null() {
            return Err(misuse(
                "extra_roots and extra_root_lens are required with extra_roots_count",
            ));
        }
        for i in 0..c.extra_roots_count {
            // SAFETY: both arrays have extra_roots_count elements per the header.
            let (ptr, len) = unsafe { (*c.extra_roots.add(i), *c.extra_root_lens.add(i)) };
            // SAFETY: per the header.
            config
                .extra_roots
                .push(unsafe { bytes(ptr, len, "extra_roots entry") }?);
        }
    }
    Ok(config)
}

/// Registers the VFS. Returns a failure instead of panicking across the C boundary.
///
/// # Safety
/// Arguments follow the contract in the header.
unsafe fn register(name: *const c_char, config_ptr: *const SqliteRemoteVfsConfig) -> Result<(), Failure> {
    // SAFETY: per the header.
    let name = unsafe { string(name, "name") }?;
    if config_ptr.is_null() {
        return Err(misuse("config is NULL"));
    }
    // SAFETY: not NULL, and points to a config per the header.
    let config = unsafe { config(&*config_ptr) }?;
    let vfs = RemoteVfs::register(&name, config).map_err(|err| Failure(SQLITE_ERROR, err.to_string()))?;
    // The VFS stays registered for the life of the process, so its handle, and with it the ping thread, is kept.
    std::mem::forget(vfs);
    Ok(())
}

/// `sqlite_remote_vfs_register` in the header.
///
/// # Safety
/// Arguments follow the contract in the header.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sqlite_remote_vfs_register(
    name: *const c_char,
    config: *const SqliteRemoteVfsConfig,
    error: *mut *mut c_char,
) -> c_int {
    // SAFETY: per the header.
    let result = catch_unwind(AssertUnwindSafe(|| unsafe { register(name, config) }));
    let Failure(code, message) = match result {
        Ok(Ok(())) => return SQLITE_OK,
        Ok(Err(failure)) => failure,
        Err(_) => Failure(SQLITE_ERROR, "internal error: the VFS panicked".into()),
    };
    if !error.is_null() {
        let message = CString::new(message.replace('\0', " ")).unwrap_or_default();
        // SAFETY: `error` is not NULL and points to a `char *` per the header.
        unsafe { *error = message.into_raw() };
    }
    code
}

/// `sqlite_remote_vfs_free` in the header.
///
/// # Safety
/// `message` is NULL or was returned by [`sqlite_remote_vfs_register`] and not yet released.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sqlite_remote_vfs_free(message: *mut c_char) {
    if !message.is_null() {
        // SAFETY: created by `CString::into_raw` in `sqlite_remote_vfs_register`.
        drop(unsafe { CString::from_raw(message) });
    }
}
