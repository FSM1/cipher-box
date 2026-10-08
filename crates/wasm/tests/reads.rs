//! The read decode and the answer encode at the WASM boundary
//! (wasm32-unknown-unknown, under wasm-bindgen-test-runner → Node.js): the
//! shape tsify types for TS, the fail-closed refusals, and the zeroizing path
//! of the two reads that carry a secret. That every `Read` variant has a serve
//! arm is checked at compile time: the host's match has no wildcard arm.
#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use cipherbox_engine::facade::{NodeId, SiweIntent};
use cipherbox_engine::grants::MAX_FRAGMENT_TEXT_LEN;
use cipherbox_wasm::boundary::{decode_read, encode_view};
use cipherbox_wasm::read::{Read, ReadAnswer};
use cipherbox_wasm::rendezvous::DeviceRendezvousStep;
use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
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
    assert_eq!(value.unchecked_into::<Uint8Array>().to_vec(), vec![1, 2, 3]);

    let nonce = encode_view(&ReadAnswer::SiweChallenge("n0nce".into())).unwrap();
    assert_eq!(
        Reflect::get(&nonce, &text("kind")).unwrap(),
        text("siweChallenge")
    );
    assert_eq!(Reflect::get(&nonce, &text("value")).unwrap(), text("n0nce"));
}
