//! Tests the mechanism of the bridge in isolation. This worker blocks in `Atomics.wait`. A second worker does the
//! asynchronous work and wakes it with `Atomics.notify`. This is how a synchronous commit waits for a network
//! response.
//!
//! The design follows SQLite's OPFS VFS and its asynchronous proxy worker: one shared buffer with one slot per
//! direction. The second worker is told about new work through a slot as well. Chrome does not deliver a message
//! that a worker posts right before it blocks in `Atomics.wait`. A slot in shared memory needs no delivery.

#![cfg(target_arch = "wasm32")]

use js_sys::{Array, Atomics, Int32Array, JsString, SharedArrayBuffer, Uint8Array};
use wasm_bindgen::prelude::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::{Blob, BlobPropertyBag, Url, Worker};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// Script of the second worker. It receives the shared buffer in one message, then waits for requests in slot 3. It
/// writes the answer into the data area, sets slot 0 and wakes the waiting worker. The answer is produced
/// asynchronously in the second worker's event loop, like a network response.
const COUNTERPART: &str = r#"
// The shared buffer arrives in one message, before the other worker blocks. After that, new work is signalled
// through slot 3. Chrome does not deliver a message that a worker posts right before it blocks in Atomics.wait.
let control = null;
let data = null;

function answer() {
  const length = Atomics.load(control, 1);
  for (let i = 0; i < length; i++) {
    data[i] = data[i] ^ 0xff;   // the answer only has to depend on the request
  }
  Atomics.store(control, 0, 1);
  Atomics.notify(control, 0);
}

function serve() {
  // Firefox ESR has no Atomics.waitAsync. There this worker polls the slot on a timer, as the connection worker
  // does.
  if (typeof Atomics.waitAsync !== "function") {
    if (Atomics.exchange(control, 3, 0) === 1) { answer(); }
    setTimeout(serve, 1);
    return;
  }
  const waited = Atomics.waitAsync(control, 3, 0);
  const done = () => {
    Atomics.store(control, 3, 0);
    answer();
    serve();
  };
  if (waited.async) { waited.value.then(done); } else { done(); }
}

self.onmessage = (event) => {
  const { buffer, controlSlots } = event.data;
  control = new Int32Array(buffer, 0, controlSlots);
  data = new Uint8Array(buffer, controlSlots * 4);
  // Slot 2 counts ticks, so the test can report whether this worker was running.
  setInterval(() => { Atomics.add(control, 2, 1); }, 10);
  serve();
  self.postMessage("ready");
};
"#;

/// Number of `i32` slots at the start of the shared buffer. Slot 0: answer ready. Slot 1: request length. Slot 2:
/// tick counter of the second worker. Slot 3: request pending. The data area follows the slots.
const CONTROL_SLOTS: u32 = 8;

fn start_counterpart() -> Worker {
    let parts = Array::new();
    parts.push(&JsString::from(COUNTERPART).into());
    let options = BlobPropertyBag::new();
    options.set_type("text/javascript");
    let blob = Blob::new_with_str_sequence_and_options(&parts, &options).expect("create the script blob");
    let url = Url::create_object_url_with_blob(&blob).expect("create the script URL");
    Worker::new(&url).expect("start the second worker")
}

/// Waits for the `ready` message of the second worker. Chrome does not start a worker while its parent is blocked in
/// `Atomics.wait`, so the second worker must be running before this worker blocks. Firefox has no such restriction.
async fn wait_until_running(worker: &Worker) {
    let ready = js_sys::Promise::new(&mut |resolve, _reject| {
        let handler = Closure::once_into_js(move |_event: web_sys::MessageEvent| {
            resolve.call0(&JsValue::NULL).unwrap();
        });
        worker.set_onmessage(Some(handler.unchecked_ref()));
    });
    wasm_bindgen_futures::JsFuture::from(ready).await.unwrap();
    worker.set_onmessage(None);
}

#[wasm_bindgen_test]
async fn worker_blocks_until_second_worker_answers() {
    let buffer = SharedArrayBuffer::new(CONTROL_SLOTS * 4 + 64);
    let control = Int32Array::new_with_byte_offset_and_length(&buffer, 0, CONTROL_SLOTS);
    let data = Uint8Array::new_with_byte_offset(&buffer, CONTROL_SLOTS * 4);

    let request = [1u8, 2, 3, 4, 5];
    for (i, byte) in request.iter().enumerate() {
        data.set_index(i as u32, *byte);
    }
    Atomics::store(&control, 0, 0).expect("clear the answer slot");
    Atomics::store(&control, 1, request.len() as i32).expect("store the request length");

    let worker = start_counterpart();
    let message = js_sys::Object::new();
    js_sys::Reflect::set(&message, &"buffer".into(), &buffer).unwrap();
    js_sys::Reflect::set(&message, &"controlSlots".into(), &JsValue::from(CONTROL_SLOTS)).unwrap();
    worker.post_message(&message).expect("post the buffer");
    // The buffer is posted while this worker still runs its event loop. It may block only after the second worker
    // waits on its slot.
    wait_until_running(&worker).await;

    // From here on, requests are signalled through shared memory only.
    Atomics::store(&control, 3, 1).expect("set the request slot");
    Atomics::notify(&control, 3).expect("notify the second worker");

    // This worker is now blocked. No event loop, timers or promises run until it is woken.
    let waited = Atomics::wait_with_timeout(&control, 0, 0, 5000.0).expect("wait");
    let ticks = Atomics::load(&control, 2).expect("load");
    assert_ne!(
        waited,
        "timed-out",
        "second worker did not answer within 5 s; it ticked {ticks} times, so it {} running",
        if ticks > 0 { "was" } else { "was not" }
    );
    assert_eq!(Atomics::load(&control, 0).expect("load"), 1, "answer slot must be set");

    let answer: Vec<u8> = (0..request.len()).map(|i| data.get_index(i as u32)).collect();
    let expected: Vec<u8> = request.iter().map(|byte| byte ^ 0xff).collect();
    assert_eq!(answer, expected, "answer must be the request with every byte inverted");

    worker.terminate();
}

#[wasm_bindgen_test]
fn wait_times_out_without_answer() {
    let buffer = SharedArrayBuffer::new(CONTROL_SLOTS * 4);
    let control = Int32Array::new_with_byte_offset_and_length(&buffer, 0, CONTROL_SLOTS);
    Atomics::store(&control, 0, 0).expect("clear the answer slot");

    // No second worker. The wait must end at its timeout, otherwise a lost connection would block the database
    // forever.
    let waited = Atomics::wait_with_timeout(&control, 0, 0, 20.0).expect("wait");
    assert_eq!(waited, "timed-out");
}
