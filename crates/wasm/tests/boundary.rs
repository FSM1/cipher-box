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
/// `bigint` — the u64/BigInt parity surface.
#[wasm_bindgen_test]
fn op_id_u64_crosses_as_bigint() {
    let event = Event::from_facade(facade::Event::DeadLetter {
        op_id: OpId(u64::MAX),
    });
    assert_eq!(event.kind(), "deadLetter");
    assert_eq!(event.op_id(), Some(u64::MAX));
}

/// Binary payloads cross as `Uint8Array` in both directions.
#[wasm_bindgen_test]
fn node_id_bytes_round_trip_and_reject_bad_length() {
    let bytes: Vec<u8> = (0..16).collect();
    let node = NodeId::from_bytes(&bytes).expect("16 bytes is a valid node id");
    assert_eq!(node.bytes(), bytes);
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
