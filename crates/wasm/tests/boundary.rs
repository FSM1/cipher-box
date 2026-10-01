//! Browser-shaped boundary tests (wasm32-unknown-unknown, under
//! wasm-bindgen-test-runner → Node.js): the getrandom → `crypto.getRandomValues`
//! worker-scope wiring and the node id handle (blueprint/web-client.md
//! "Boundary hygiene"). The command decode, the event encode and the view
//! encode have their own files (`commands.rs`, `events.rs`, `views.rs`).
//!
//! The whole file is gated to the browser target; native `cargo test` for this
//! crate runs the host conversion tests in `src/lib.rs` instead.
#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use cipherbox_wasm::NodeId;
use js_sys::{Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::wasm_bindgen_test;

/// getrandom's `wasm_js` backend must reach `crypto.getRandomValues` in the
/// worker/JS scope — the getrandom parity surface. A dependency-level need:
/// engine logic still takes injected entropy.
#[wasm_bindgen_test]
fn getrandom_wires_to_crypto_get_random_values() {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("crypto.getRandomValues must be wired in the worker scope");
    assert!(
        buf.iter().any(|&b| b != 0),
        "32 random bytes are all-zero with negligible probability"
    );
}

/// Binary payloads cross as a JS `Uint8Array`. Read the `bytes` getter through
/// the wasm-bindgen glue and assert the JS-observed type and contents; a
/// wrong-length constructor returns a `JsError` (surfaced as a JS throw at the
/// call site).
#[wasm_bindgen_test]
fn node_id_bytes_cross_as_uint8array_and_reject_bad_length() {
    let bytes: Vec<u8> = (0..16).collect();
    let node: JsValue = NodeId::from_bytes(&bytes)
        .expect("16 bytes is a valid node id")
        .into();
    let out = Reflect::get(&node, &JsValue::from_str("bytes")).expect("bytes getter is readable");

    assert!(
        out.is_instance_of::<Uint8Array>(),
        "node id bytes must cross as a Uint8Array"
    );
    assert_eq!(out.unchecked_into::<Uint8Array>().to_vec(), bytes);
    assert!(
        NodeId::from_bytes(&[0u8; 20]).is_err(),
        "a wrong-length node id must throw at the boundary"
    );
}
