//! Helpers shared by the browser tests.
//!
//! The VFS receives a `Signer` and never holds key material. Where a real client gets its key from, for example a
//! seed, a key file or the browser's key store, is up to the application. The tests use random Ed25519 keys.

use std::sync::Arc;

use js_sys::{Array, Function, Promise, Reflect};
use sqlite_remote_vfs::{Algorithm, Signer};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

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

/// Names of the IndexedDB databases of this origin. Fails if the browser does not support
/// `indexedDB.databases()`.
#[allow(dead_code, reason = "not every test file lists IndexedDB databases")]
pub async fn indexed_databases() -> Result<Vec<String>, String> {
    let scope: JsValue = js_sys::global().into();
    let idb = Reflect::get(&scope, &"indexedDB".into()).map_err(|_| "no indexedDB".to_string())?;
    let function: Function = Reflect::get(&idb, &"databases".into())
        .map_err(|_| "no databases()".to_string())?
        .dyn_into()
        .map_err(|_| "databases() is not a function".to_string())?;
    let promise: Promise = function
        .call0(&idb)
        .map_err(|err| format!("databases(): {err:?}"))?
        .dyn_into()
        .map_err(|_| "databases() returned no promise".to_string())?;
    let list = JsFuture::from(promise)
        .await
        .map_err(|err| format!("databases(): {err:?}"))?;
    Ok(Array::from(&list)
        .iter()
        .filter_map(|entry| Reflect::get(&entry, &"name".into()).ok()?.as_string())
        .collect())
}
