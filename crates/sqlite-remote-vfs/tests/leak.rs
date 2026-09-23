//! Checks that the `Debug` output of a `Config` does not contain the signer's secret key. `Config` implements `Debug`,
//! so it can end up in a log.

use std::sync::Arc;

use sqlite_remote_vfs::{Algorithm, Config, Signer};

/// Test signer with a secret field. Like a real signer, it exposes only the public key.
struct Keeper {
    secret: [u8; 32],
    public: [u8; 32],
}

impl Signer for Keeper {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }

    fn public_key(&self) -> Vec<u8> {
        self.public.to_vec()
    }

    fn sign(&self, _message: &[u8]) -> Vec<u8> {
        let _ = self.secret;
        vec![0; 64]
    }
}

#[test]
fn config_debug_output_hides_secret() {
    let keeper = Keeper {
        secret: [0xab; 32],
        public: [0x7e; 32],
    };
    let config = Config::new("ws://server.test", Arc::new(keeper));
    let printed = format!("{config:?}");

    // The repeated secret byte 0xab in decimal, lowercase hex, uppercase hex and base64.
    for shape in ["171, 171, 171", "abababab", "ABABABAB", "q6ur"] {
        assert!(!printed.contains(shape), "secret appears as {shape}: {printed}");
    }
    assert!(
        printed.contains("Ed25519"),
        "algorithm missing from Debug output: {printed}"
    );
}
