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
use cipherbox_wasm::{
    Command, Event, NodeId, NodeKind, OpPhase, Permission, SnapshotView, Staleness,
};
use js_sys::{Array, BigInt, Reflect, Uint8Array};
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

/// `opProgress` payload getters cross with boundary-correct JS shapes — op id
/// as `bigint`, node id as `Uint8Array` — and every getter is `undefined` both
/// off-variant and for an absent optional field.
#[wasm_bindgen_test]
fn op_progress_getters_cross_and_stay_undefined_off_variant() {
    let progress = Event::from_facade(facade::Event::OpProgress {
        op_id: Some(OpId(u64::MAX)),
        node: facade::NodeId([5u8; 16]),
        phase: facade::OpPhase::DownloadFailed,
        error: Some("unavailable".into()),
    });
    assert_eq!(progress.kind(), "opProgress");
    assert_eq!(progress.phase(), Some(OpPhase::DownloadFailed));
    assert_eq!(progress.error(), Some("unavailable".into()));

    let js: JsValue = progress.into();
    let op_id = Reflect::get(&js, &JsValue::from_str("opId")).expect("opId getter is readable");
    assert_eq!(op_id.js_typeof(), JsValue::from_str("bigint"));
    let node = Reflect::get(&js, &JsValue::from_str("node")).expect("node getter is readable");
    assert!(node.is_instance_of::<Uint8Array>());
    assert_eq!(node.unchecked_into::<Uint8Array>().to_vec(), vec![5u8; 16]);

    let op_less = Event::from_facade(facade::Event::OpProgress {
        op_id: None,
        node: facade::NodeId([0u8; 16]),
        phase: facade::OpPhase::DownloadStarted,
        error: None,
    });
    assert!(op_less.op_id().is_none());
    assert!(op_less.error().is_none());
    let js: JsValue = op_less.into();
    assert!(
        Reflect::get(&js, &JsValue::from_str("opId"))
            .expect("opId getter is readable")
            .is_undefined()
    );
    assert!(
        Reflect::get(&js, &JsValue::from_str("error"))
            .expect("error getter is readable")
            .is_undefined()
    );

    let other: JsValue = Event::from_facade(facade::Event::SnapshotUpdated).into();
    for key in ["node", "phase", "error", "opId"] {
        assert!(
            Reflect::get(&other, &JsValue::from_str(key))
                .expect("getter is readable")
                .is_undefined(),
            "{key} must be undefined off-variant"
        );
    }
}

/// The snapshot read surface crosses with boundary-correct JS shapes: node ids
/// as `Uint8Array`, `u64`s as `bigint`, absent projections as `undefined`, and
/// children/ancestors as JS arrays of the wrapped types.
#[wasm_bindgen_test]
fn snapshot_view_getters_cross_with_boundary_shapes() {
    let view: JsValue = SnapshotView::from_facade(facade::SnapshotView {
        root: facade::NodeId([1u8; 16]),
        folder: facade::NodeId([2u8; 16]),
        children: vec![
            facade::SnapshotChild {
                id: facade::NodeId([3u8; 16]),
                name: "photo.jpg".into(),
                kind: facade::NodeKind::File,
                size: Some(u64::MAX),
                mtime: Some(1_700_000_000_000),
                pending: true,
                dead_letter: false,
                content_version: 2,
            },
            facade::SnapshotChild {
                id: facade::NodeId([4u8; 16]),
                name: "docs".into(),
                kind: facade::NodeKind::Folder,
                size: None,
                mtime: None,
                pending: false,
                dead_letter: true,
                content_version: 0,
            },
        ],
        ancestors: vec![facade::Breadcrumb {
            id: facade::NodeId([1u8; 16]),
            name: String::new(),
        }],
        dead_letters: vec![OpId(9)],
        staleness: facade::Staleness::Fresh,
    })
    .into();

    let get = |target: &JsValue, key: &str| {
        Reflect::get(target, &JsValue::from_str(key)).expect("getter is readable")
    };

    let root = get(&view, "root");
    assert!(root.is_instance_of::<Uint8Array>());
    assert_eq!(root.unchecked_into::<Uint8Array>().to_vec(), vec![1u8; 16]);
    let folder = get(&view, "folder");
    assert_eq!(
        folder.unchecked_into::<Uint8Array>().to_vec(),
        vec![2u8; 16]
    );

    // Dead-letter op ids are u64s and must cross as bigints.
    let dead_letters = get(&view, "deadLetters");
    assert!(dead_letters.is_instance_of::<js_sys::BigUint64Array>());
    assert_eq!(
        dead_letters
            .unchecked_into::<js_sys::BigUint64Array>()
            .to_vec(),
        vec![9u64]
    );

    let children = get(&view, "children");
    assert!(children.is_instance_of::<Array>());
    let children = children.unchecked_into::<Array>();
    assert_eq!(children.length(), 2);

    let file = children.get(0);
    assert_eq!(get(&file, "name"), JsValue::from_str("photo.jpg"));
    let id = get(&file, "id");
    assert!(id.is_instance_of::<Uint8Array>());
    assert_eq!(id.unchecked_into::<Uint8Array>().to_vec(), vec![3u8; 16]);
    let size = get(&file, "size");
    assert_eq!(
        size.js_typeof(),
        JsValue::from_str("bigint"),
        "size must cross as a JS bigint, never a number"
    );
    let decimal = String::from(
        size.unchecked_into::<BigInt>()
            .to_string(10)
            .expect("bigint renders in base 10"),
    );
    assert_eq!(decimal, u64::MAX.to_string());
    assert_eq!(
        get(&file, "contentVersion").js_typeof(),
        JsValue::from_str("bigint")
    );
    assert_eq!(get(&file, "pending"), JsValue::TRUE);
    assert_eq!(get(&file, "deadLetter"), JsValue::FALSE);

    let folder_child = children.get(1);
    assert!(
        get(&folder_child, "size").is_undefined(),
        "an unprojected size must cross as undefined"
    );
    assert!(get(&folder_child, "mtime").is_undefined());
    assert_eq!(get(&folder_child, "deadLetter"), JsValue::TRUE);

    let ancestors = get(&view, "ancestors").unchecked_into::<Array>();
    assert_eq!(ancestors.length(), 1);
    let crumb = ancestors.get(0);
    assert_eq!(get(&crumb, "name"), JsValue::from_str(""));
    assert_eq!(
        get(&crumb, "id").unchecked_into::<Uint8Array>().to_vec(),
        vec![1u8; 16]
    );
}
