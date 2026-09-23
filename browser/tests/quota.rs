//! Checks the storage quota the browser grants this origin. A local copy of the database in IndexedDB needs it.
#![cfg(target_arch = "wasm32")]

use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::{StorageEstimate, WorkerGlobalScope, console};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen_test]
async fn storage_quota_exceeds_512_mib() {
    let scope: WorkerGlobalScope = js_sys::global().unchecked_into();
    let promise = scope.navigator().storage().estimate().expect("call storage.estimate()");
    let estimate: StorageEstimate = JsFuture::from(promise)
        .await
        .expect("storage estimate")
        .unchecked_into();
    let quota = estimate.get_quota().expect("quota in the storage estimate");
    let gb = quota / (1024.0 * 1024.0 * 1024.0);
    console::log_1(&format!("QUOTA {quota} bytes, {gb:.1} GB").into());

    // A message database is tens of megabytes. A quota above 512 MiB leaves room for its local copy.
    assert!(
        quota > 512.0 * 1024.0 * 1024.0,
        "storage quota is {quota} bytes, expected more than 512 MiB"
    );
}
