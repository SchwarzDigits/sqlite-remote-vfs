//! Test keys for the harness.
//!
//! A key is 32 random bytes, used directly as an Ed25519 private key and passed around as 64 hex digits. The crash
//! test passes the key to its child process on the command line, so the child logs in as the same subject. This is
//! a test fixture. Applications manage their keys themselves.

use std::sync::Arc;

use sqlite_remote_vfs::{Algorithm, Signer};

/// Returns a new random key. Each run uses new keys, so it does not see databases from earlier runs.
pub fn new() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS randomness");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Returns the signer for a key created by [`new`].
pub fn signer(key: &str) -> Result<Arc<dyn Signer>, String> {
    let bytes: Vec<u8> = (0..key.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(key.get(at..at + 2).unwrap_or(""), 16))
        .collect::<Result<_, _>>()
        .map_err(|_| format!("key must be 64 hex digits, got {key:?}"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("key must be 64 hex digits, got {}", key.len()))?;
    Ok(Arc::new(Key(ed25519_dalek::SigningKey::from_bytes(&bytes))))
}

/// Returns the subject of a key, for log output, so the key itself is never printed.
pub fn describe(key: &str) -> String {
    match signer(key) {
        Ok(signer) => sqlite_remote_vfs::subject(&*signer),
        Err(err) => err,
    }
}

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

#[cfg(test)]
mod tests {
    #[test]
    fn same_key_gives_same_subject() {
        let key = super::new();
        assert_eq!(super::describe(&key), super::describe(&key));
        assert_ne!(super::describe(&key), super::describe(&super::new()));
    }

    #[test]
    fn invalid_key_is_rejected() {
        assert!(super::signer("not hex").is_err());
        assert!(super::signer("abcd").is_err());
    }
}
