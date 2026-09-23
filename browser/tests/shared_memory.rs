//! Checks that `SharedArrayBuffer` and `Atomics` work in a dedicated worker. The bridge depends on both.
//!
//! The test runs in a dedicated worker because browsers do not allow `Atomics.wait` on the main thread. For the same
//! reason SQLite runs in a dedicated worker.
#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen_test]
fn shared_memory_and_atomics_are_available() {
    let global = js_sys::global();
    let has_sab = js_sys::Reflect::get(&global, &"SharedArrayBuffer".into())
        .map(|value| !value.is_undefined())
        .unwrap_or(false);
    let isolated = js_sys::Reflect::get(&global, &"crossOriginIsolated".into())
        .ok()
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    web_sys::console::log_1(&format!("SharedArrayBuffer: {has_sab}, crossOriginIsolated: {isolated}").into());

    assert!(has_sab, "no SharedArrayBuffer: the page is not cross-origin isolated");

    // The buffer must also work with `Atomics`.
    let atomics = js_sys::Reflect::get(&global, &"Atomics".into()).expect("Atomics");
    let wait_async = js_sys::Reflect::get(&atomics, &"waitAsync".into())
        .map(|value| !value.is_undefined())
        .unwrap_or(false);
    web_sys::console::log_1(&format!("Atomics.waitAsync: {wait_async}").into());

    let buffer = js_sys::SharedArrayBuffer::new(16);
    let view = js_sys::Int32Array::new(&buffer);
    js_sys::Atomics::store(&view, 0, 42).expect("store");
    assert_eq!(js_sys::Atomics::load(&view, 0).expect("load"), 42);
    // `Atomics.wait` returns "not-equal" immediately if the slot does not hold the expected value.
    let waited = js_sys::Atomics::wait_with_timeout(&view, 0, 7, 0.0).expect("wait");
    assert_eq!(waited, "not-equal");
}
