//! Browser-shaped boundary tests (wasm32-unknown-unknown, under
//! wasm-bindgen-test-runner → Node.js). They exercise the two boundary risks
//! the WASM leg exists to cover (blueprint/web-client.md "Boundary hygiene"):
//! `u64`→`bigint` marshalling and the getrandom → `crypto.getRandomValues`
//! worker-scope wiring, plus the command/event surface shapes.
//!
//! The whole file is gated to the browser target; native `cargo test` for this
//! crate runs the host conversion tests in `src/lib.rs` instead.
#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use cipherbox_engine::facade;
use cipherbox_engine::seams::OpId;
use cipherbox_wasm::{Command, Event, NodeId, NodeKind, Permission, Staleness};
use js_sys::{BigInt, Reflect, Uint8Array};
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

/// A `u64` op id (> Number.MAX_SAFE_INTEGER) must survive the boundary as a
/// JS `bigint` — the u64/BigInt parity surface. Read through the generated
/// `#[wasm_bindgen(getter)]` glue (not the Rust field) so a wasm-bindgen ABI
/// regression that marshalled it as an f64 `number` — truncating at 2^53 — is
/// observed, not hidden.
#[wasm_bindgen_test]
fn op_id_u64_crosses_as_bigint() {
    let event: JsValue = Event::from_facade(facade::Event::DeadLetter {
        op_id: OpId(u64::MAX),
    })
    .into();
    let op_id = Reflect::get(&event, &JsValue::from_str("opId")).expect("opId getter is readable");

    assert_eq!(
        op_id.js_typeof(),
        JsValue::from_str("bigint"),
        "opId must cross as a JS bigint, never a number"
    );
    // A number (f64) marshalling would round u64::MAX to 2^64; assert the exact
    // value survived, in JS's own decimal rendering.
    let decimal = String::from(
        op_id
            .unchecked_into::<BigInt>()
            .to_string(10)
            .expect("bigint renders in base 10"),
    );
    assert_eq!(decimal, u64::MAX.to_string());
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

/// The command builders wrap engine intent and expose only the stable name.
#[wasm_bindgen_test]
fn command_builders_expose_stable_names() {
    let node = NodeId::from_bytes(&[0u8; 16]).expect("valid node id");
    assert_eq!(
        Command::create(
            &node,
            "photo.jpg".into(),
            NodeKind::File,
            Some(vec![1, 2, 3])
        )
        .name(),
        "create"
    );
    assert_eq!(
        Command::grant(&node, vec![0xAB; 32], Permission::Write).name(),
        "grant"
    );
    assert_eq!(Command::manual_refresh().name(), "manualRefresh");
}

/// Event getters return key-free view state, keyed off `kind`.
#[wasm_bindgen_test]
fn event_getters_map_variants() {
    let staleness = Event::from_facade(facade::Event::StalenessChanged {
        level: facade::Staleness::Stale,
    });
    assert_eq!(staleness.kind(), "stalenessChanged");
    assert_eq!(staleness.staleness(), Some(Staleness::Stale));
    assert!(staleness.op_id().is_none());

    let withheld = Event::from_facade(facade::Event::WithheldUpdateEscalation {
        ipns_name: vec![9, 8, 7],
    });
    assert_eq!(withheld.ipns_name(), Some(vec![9, 8, 7]));
}
