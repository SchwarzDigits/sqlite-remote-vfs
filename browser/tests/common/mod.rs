//! Helpers shared by the browser tests.
//!
//! The VFS receives a `Signer` and never holds key material. Where a real client gets its key from, for example a
//! seed, a key file or the browser's key store, is up to the application. The tests use random Ed25519 keys.

use std::sync::Arc;

use sqlite_remote_vfs::{Algorithm, Signer};

/// Returns a signer with a new random Ed25519 key. Each key maps to its own subject on the server, so a test never
/// sees data from an earlier run. A signer used twice logs in as the same subject both times.
pub fn key() -> Arc<dyn Signer> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    Arc::new(TestSigner(ed25519_dalek::SigningKey::from_bytes(&seed)))
}

struct TestSigner(ed25519_dalek::SigningKey);

impl Signer for TestSigner {
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
