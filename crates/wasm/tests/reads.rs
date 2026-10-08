//! The read decode and the answer encode at the WASM boundary
//! (wasm32-unknown-unknown, under wasm-bindgen-test-runner → Node.js): the
//! shape tsify types for TS, the fail-closed refusals, and the zeroizing path
//! of the two reads that carry a secret. That every `Read` variant has a serve
//! arm is checked at compile time: the host's match has no wildcard arm.
#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use cipherbox_engine::facade::{NodeId, SiweIntent};
use cipherbox_engine::grants::MAX_FRAGMENT_TEXT_LEN;
use cipherbox_wasm::boundary::{
    decode_read, decode_rendezvous_step, decode_write_target, encode_view,
};
use cipherbox_wasm::read::{Read, ReadAnswer};
use cipherbox_wasm::read_unstarted;
use cipherbox_wasm::rendezvous::DeviceRendezvousStep;
use js_sys::{Function, Object, Reflect, Uint8Array};
use tsify::Ts;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::wasm_bindgen_test;
use zeroize::Zeroizing;

const FRAGMENT: &str = "ZnJhZ21lbnQtdGV4dA";

fn object(fields: &[(&str, JsValue)]) -> JsValue {
    let out = Object::new();
    for (key, value) in fields {
        Reflect::set(&out, &JsValue::from_str(key), value).expect("a plain object takes a field");
    }
    out.into()
}

fn bytes(value: &[u8]) -> JsValue {
    Uint8Array::from(value).into()
}

fn text(value: &str) -> JsValue {
    JsValue::from_str(value)
}

fn kind(value: &str) -> JsValue {
    object(&[("kind", text(value))])
}

fn refused(read: &JsValue) -> bool {
    decode_read(read).is_err()
}

#[wasm_bindgen_test]
fn a_read_decodes_from_its_generated_shape() {
    let snapshot = object(&[("kind", text("snapshot")), ("folder", bytes(&[7; 16]))]);
    assert!(matches!(
        decode_read(&snapshot).unwrap(),
        Read::Snapshot { folder: Some(node) } if node == NodeId([7; 16])
    ));
    let root = object(&[("kind", text("sharing")), ("scope", JsValue::NULL)]);
    assert!(matches!(
        decode_read(&root).unwrap(),
        Read::Sharing { scope: None }
    ));
    assert!(matches!(decode_read(&kind("bin")).unwrap(), Read::Bin));
    let siwe = object(&[("kind", text("siweChallenge")), ("intent", text("link"))]);
    assert!(matches!(
        decode_read(&siwe).unwrap(),
        Read::SiweChallenge {
            intent: SiweIntent::Link
        }
    ));
    let version = object(&[
        ("kind", text("downloadVersion")),
        ("node", bytes(&[3; 16])),
        ("contentCid", bytes(&[1, 2, 3])),
    ]);
    match decode_read(&version).unwrap() {
        Read::DownloadVersion { node, content_cid } => {
            assert_eq!(node, NodeId([3; 16]));
            assert_eq!(content_cid, vec![1, 2, 3]);
        }
        _ => panic!("a version download decodes as one"),
    }
}

#[wasm_bindgen_test]
fn an_unknown_kind_or_field_is_refused() {
    assert!(refused(&kind("noSuchRead")));
    assert!(refused(&JsValue::NULL));
    assert!(refused(&object(&[
        ("kind", text("bin")),
        ("folder", JsValue::NULL)
    ])));
    assert!(refused(&object(&[
        ("kind", text("download")),
        ("node", bytes(&[1; 16])),
        ("extra", text("x")),
    ])));
}

#[wasm_bindgen_test]
fn a_field_of_the_wrong_type_is_refused() {
    let short = object(&[("kind", text("download")), ("node", bytes(&[1; 15]))]);
    assert!(refused(&short));
    let named = object(&[
        ("kind", text("fileVersions")),
        ("node", text("sixteen-chars-id")),
    ]);
    assert!(refused(&named));
    let missing = kind("snapshot");
    assert!(refused(&missing));
    let key = object(&[
        ("kind", text("deviceRegistrationChallenge")),
        ("devicePublicKey", JsValue::from_f64(7.0)),
    ]);
    assert!(refused(&key));
    let pool = object(&[
        ("kind", text("siweChallenge")),
        ("intent", text("nonsense")),
    ]);
    assert!(refused(&pool));
}

#[wasm_bindgen_test]
fn an_invite_fragment_reaches_its_zeroizing_slot_verbatim() {
    let preview = object(&[
        ("kind", text("invitePreview")),
        ("fragment", text(FRAGMENT)),
    ]);
    match decode_read(&preview).unwrap() {
        Read::InvitePreview { fragment } => assert_eq!(fragment.as_str(), FRAGMENT),
        _ => panic!("a preview decodes as one"),
    }
}

#[wasm_bindgen_test]
fn an_invite_fragment_past_the_bound_or_not_text_is_refused() {
    let long = "x".repeat(MAX_FRAGMENT_TEXT_LEN + 1);
    assert!(refused(&object(&[
        ("kind", text("invitePreview")),
        ("fragment", text(&long)),
    ])));
    assert!(refused(&object(&[
        ("kind", text("invitePreview")),
        ("fragment", JsValue::from_f64(7.0)),
    ])));
}

#[wasm_bindgen_test]
fn a_rendezvous_read_takes_its_step_through_the_step_decode() {
    let step = object(&[
        ("kind", text("open")),
        ("devicePublicKey", text("cd11")),
        ("scalar", bytes(&[5; 32])),
    ]);
    let read = object(&[("kind", text("deviceRendezvous")), ("step", step.clone())]);
    match decode_read(&read).unwrap() {
        Read::DeviceRendezvous {
            step: DeviceRendezvousStep::Open { scalar, .. },
        } => assert_eq!(scalar.as_slice(), &[5; 32]),
        _ => panic!("a rendezvous read decodes its open step"),
    }
    let beside = object(&[
        ("kind", text("deviceRendezvous")),
        ("step", step),
        ("extra", text("x")),
    ]);
    assert!(refused(&beside));
    assert!(refused(&kind("deviceRendezvous")));
}

#[wasm_bindgen_test]
fn an_answer_crosses_under_the_kind_of_its_read() {
    let download = encode_view(&ReadAnswer::Download(Zeroizing::new(vec![1, 2, 3]))).unwrap();
    assert_eq!(
        Reflect::get(&download, &text("kind")).unwrap(),
        text("download")
    );
    let value = Reflect::get(&download, &text("value")).unwrap();
    let value = value
        .dyn_into::<Uint8Array>()
        .expect("a byte answer is a Uint8Array");
    assert_eq!(value.to_vec(), vec![1, 2, 3]);

    let nonce = encode_view(&ReadAnswer::SiweChallenge("n0nce".into())).unwrap();
    assert_eq!(
        Reflect::get(&nonce, &text("kind")).unwrap(),
        text("siweChallenge")
    );
    assert_eq!(Reflect::get(&nonce, &text("value")).unwrap(), text("n0nce"));
}

/// A SIWE nonce is minted for the pool the intent names, and for no other
/// spelling.
#[wasm_bindgen_test]
fn a_siwe_read_names_its_pool_and_refuses_any_other() {
    let siwe = |intent: JsValue| object(&[("kind", text("siweChallenge")), ("intent", intent)]);
    assert!(matches!(
        decode_read(&siwe(text("login"))).unwrap(),
        Read::SiweChallenge {
            intent: SiweIntent::Login
        }
    ));
    for intent in [
        text("Login"),
        text("admin"),
        JsValue::from_f64(0.0),
        JsValue::UNDEFINED,
    ] {
        assert!(refused(&siwe(intent)));
    }
}

/// Builds `(value, seen)`: `value` nests one object `depth` levels deep whose
/// `leaf` getter sets `seen.read` when anything reads it.
fn watched(depth: u32) -> (JsValue, JsValue) {
    let built = Function::new_with_args(
        "depth",
        "const seen = { read: false };
         let value = { get leaf() { seen.read = true; return 1; } };
         for (let i = 0; i < depth; i++) value = { inner: value };
         return { value, seen };",
    )
    .call1(&JsValue::NULL, &JsValue::from(depth))
    .expect("the builder runs");
    (
        Reflect::get(&built, &text("value")).unwrap(),
        Reflect::get(&built, &text("seen")).unwrap(),
    )
}

fn was_read(seen: &JsValue) -> bool {
    Reflect::get(seen, &text("read")).unwrap().is_truthy()
}

/// A port payload is untrusted, so a deep field is refused before the decode
/// walks it, as a command is.
#[wasm_bindgen_test]
fn a_read_that_nests_too_deep_is_refused_unwalked() {
    let (value, seen) = watched(16);
    assert!(refused(&object(&[("kind", text("bin")), ("x", value)])));
    assert!(!was_read(&seen));
}

#[wasm_bindgen_test]
fn a_rendezvous_step_that_nests_too_deep_is_refused_unwalked() {
    let (value, seen) = watched(16);
    let step = object(&[
        ("kind", text("deny")),
        ("devicePublicKey", text("cd11")),
        ("requestId", text("r")),
        ("ephemeralPublicKey", text("02beef")),
        ("x", value),
    ]);
    assert!(decode_rendezvous_step(&step).is_err());
    assert!(!was_read(&seen));
}

/// A structured clone keeps cycles, so a cyclic field is refused rather than
/// walked without end.
#[wasm_bindgen_test]
fn a_cyclic_read_is_refused() {
    let cycle = Object::new();
    Reflect::set(&cycle, &text("self"), &cycle).unwrap();
    assert!(refused(&object(&[
        ("kind", text("bin")),
        ("x", cycle.into())
    ])));
}

#[wasm_bindgen_test]
async fn a_read_that_needs_a_session_is_refused_before_one() {
    let refusal = JsFuture::from(read_unstarted(Ts::new_unchecked(kind("bin"))))
        .await
        .expect_err("no session serves the bin");
    assert_eq!(
        Reflect::get(&refusal, &text("code")).unwrap(),
        text("notStarted")
    );
}

async fn fingerprint(key: &[u8]) -> Result<JsValue, String> {
    let read = object(&[
        ("kind", text("identityFingerprint")),
        ("identityPublicKey", bytes(key)),
    ]);
    JsFuture::from(read_unstarted(Ts::new_unchecked(read)))
        .await
        .map_err(|error| {
            String::from(
                error
                    .dyn_into::<js_sys::Error>()
                    .expect("a refusal is an Error")
                    .message(),
            )
        })
}

/// The core KAT's primary vector (`contact/fingerprint.json`).
const IDENTITY_PK: &str = "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27";

#[wasm_bindgen_test]
async fn a_fingerprint_read_needs_no_session() {
    let key: Vec<u8> = (0..IDENTITY_PK.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&IDENTITY_PK[at..at + 2], 16).unwrap())
        .collect();
    let answer = fingerprint(&key).await.expect("a session-free read");
    assert_eq!(
        Reflect::get(&answer, &text("kind")).unwrap(),
        text("identityFingerprint")
    );
    assert_eq!(
        Reflect::get(&answer, &text("value")).unwrap(),
        text("e686 bdd6 b44e 05c4 4db0")
    );
    assert_eq!(
        fingerprint(&[2; 32]).await.unwrap_err(),
        "invalid identity public key"
    );
}

/// Builds `(value, seen)`: `value` is one object with `keys` keys whose last
/// key is a getter that sets `seen.read` when anything reads it.
fn wide(keys: u32) -> (JsValue, JsValue) {
    let built = Function::new_with_args(
        "keys",
        "const seen = { read: false };
         const value = {};
         for (let i = 0; i < keys - 1; i++) value['k' + i] = i;
         Object.defineProperty(value, 'last', {
           enumerable: true,
           get() { seen.read = true; return 1; },
         });
         return { value, seen };",
    )
    .call1(&JsValue::NULL, &JsValue::from(keys))
    .expect("the builder runs");
    (
        Reflect::get(&built, &text("value")).unwrap(),
        Reflect::get(&built, &text("seen")).unwrap(),
    )
}

/// Builds `(value, seen)`: a graph 4 levels deep where each level holds 10
/// references to one shared object below it, so a walk visits 10^4 values
/// in a value a structured clone carries in 40 objects. The top object's
/// last key is a getter that sets `seen.read`.
fn shared() -> (JsValue, JsValue) {
    let built = Function::new_no_args(
        "const seen = { read: false };
         let below = 0;
         for (let level = 0; level < 4; level++) {
           const next = {};
           for (let i = 0; i < 10; i++) next['k' + i] = below;
           below = next;
         }
         Object.defineProperty(below, 'last', {
           enumerable: true,
           get() { seen.read = true; return 1; },
         });
         return { value: below, seen };",
    )
    .call0(&JsValue::NULL)
    .expect("the builder runs");
    (
        Reflect::get(&built, &text("value")).unwrap(),
        Reflect::get(&built, &text("seen")).unwrap(),
    )
}

/// One object past the key cap is refused before any of its values is read.
#[wasm_bindgen_test]
fn a_read_with_too_many_keys_is_refused_unread() {
    let (value, seen) = wide(17);
    assert!(refused(&object(&[("kind", text("bin")), ("x", value)])));
    assert!(!was_read(&seen));
}

/// A shared graph passes every depth and key check, so the visit cap stops it
/// before the walk reaches the top object's last key.
#[wasm_bindgen_test]
fn a_read_past_the_visit_cap_is_refused_unread() {
    let (value, seen) = shared();
    assert!(refused(&object(&[("kind", text("bin")), ("x", value)])));
    assert!(!was_read(&seen));
}

#[wasm_bindgen_test]
fn a_cyclic_write_target_is_refused() {
    let target = object(&[("node", bytes(&[1; 16]))]);
    Reflect::set(&target, &text("self"), &target).unwrap();
    assert!(decode_write_target(target).is_err());
}
