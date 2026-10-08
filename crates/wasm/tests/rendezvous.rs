//! The device-approval rendezvous at the WASM boundary (wasm32-unknown-unknown,
//! under wasm-bindgen-test-runner → Node.js): the step decode tsify types for
//! TS, its fail-closed refusals, and the result encode (ADR 0009).
#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_wasm::boundary::{decode_rendezvous_step, take_rendezvous_secrets};
use cipherbox_wasm::read_unstarted;
use cipherbox_wasm::rendezvous::{DeviceRendezvousStep, Secret};
use js_sys::{Object, Reflect, Uint8Array};
use tsify::Ts;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::wasm_bindgen_test;

const REQUESTER: &str = "cd11223344556677889900aabbccddeeff00112233445566778899aabbccddee";
const REQUEST: &str = "1b3d4c1a-0000-4000-8000-000000000001";
const FACTOR: &[u8] = b"a fresh factor";

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

fn get(value: &JsValue, key: &str) -> JsValue {
    Reflect::get(value, &JsValue::from_str(key)).expect("a field is readable")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Runs one step as the worker does before any session: a `deviceRendezvous`
/// read through `readUnstarted`.
async fn run(step: &JsValue) -> Result<JsValue, String> {
    let read = object(&[("kind", text("deviceRendezvous")), ("step", step.clone())]);
    let answer = JsFuture::from(read_unstarted(Ts::new_unchecked(read)))
        .await
        .map_err(|error| String::from(error.unchecked_into::<js_sys::Error>().message()))?;
    assert_eq!(get(&answer, "kind"), "deviceRendezvous");
    Ok(get(&answer, "value"))
}

fn open(scalar: &[u8]) -> JsValue {
    object(&[
        ("kind", text("open")),
        ("devicePublicKey", text(REQUESTER)),
        ("scalar", bytes(scalar)),
    ])
}

fn approve(approver: &str, ephemeral: &str, factor_key: JsValue) -> JsValue {
    object(&[
        ("kind", text("approve")),
        ("devicePublicKey", text(approver)),
        ("requestId", text(REQUEST)),
        ("requesterDevicePublicKey", text(REQUESTER)),
        ("ephemeralPublicKey", text(ephemeral)),
        ("sealScalar", bytes(&[9u8; 32])),
        ("factorKey", factor_key),
    ])
}

/// Open, approve, sign, open the factor: each step crosses as the generated
/// shape, and the requester ends holding the factor the approver sealed.
#[wasm_bindgen_test]
async fn a_signed_approval_hands_the_requester_its_factor() {
    let scalar = [4u8; 32];
    let opened = run(&open(&scalar)).await.expect("open");
    assert_eq!(get(&opened, "kind"), "opened");
    assert!(get(&opened, "requestPayload").is_instance_of::<Uint8Array>());
    assert!(get(&opened, "comparisonValue").is_string());
    let ephemeral = get(&opened, "ephemeralPublicKey")
        .as_string()
        .expect("the offered key is text");

    let signer = Ed25519Signer::from_seed([21u8; 32]);
    let approver = hex(&signer.verifying_key().to_bytes());
    let answer = run(&approve(&approver, &ephemeral, bytes(FACTOR)))
        .await
        .expect("approve");
    assert_eq!(get(&answer, "kind"), "response");
    let sealed = get(&answer, "sealedFactor");
    let payload = get(&answer, "payload")
        .unchecked_into::<Uint8Array>()
        .to_vec();
    let signature = hex(&signer.sign(&payload).to_bytes());

    let factor = run(&object(&[
        ("kind", text("openFactor")),
        ("sealedFactor", sealed),
        ("requestId", text(REQUEST)),
        ("requesterDevicePublicKey", text(REQUESTER)),
        ("responderDevicePublicKey", text(&approver)),
        ("responseSignature", text(&signature)),
        ("scalar", bytes(&scalar)),
    ]))
    .await
    .expect("open the factor");
    assert_eq!(get(&factor, "kind"), "factor");
    assert_eq!(
        get(&factor, "factorKey")
            .unchecked_into::<Uint8Array>()
            .to_vec(),
        FACTOR
    );
}

#[wasm_bindgen_test]
async fn a_denial_seals_nothing() {
    let opened = run(&open(&[4u8; 32])).await.expect("open");
    let denied = run(&object(&[
        ("kind", text("deny")),
        ("devicePublicKey", text(REQUESTER)),
        ("requestId", text(REQUEST)),
        ("ephemeralPublicKey", get(&opened, "ephemeralPublicKey")),
    ]))
    .await
    .expect("deny");
    assert_eq!(get(&denied, "kind"), "response");
    assert!(get(&denied, "sealedFactor").is_null());
    assert!(get(&denied, "payload").is_instance_of::<Uint8Array>());
}

/// Each secret is taken from the caller's own field after the placeholder
/// decode, so the decoded step holds the caller's bytes.
#[wasm_bindgen_test]
fn the_decoded_step_holds_the_secrets_the_caller_sent() {
    let step = approve(REQUESTER, "02beef", bytes(FACTOR));
    let Ok(DeviceRendezvousStep::Approve {
        seal_scalar,
        factor_key,
        ..
    }) = decode_rendezvous_step(&step)
    else {
        panic!("an approve step decodes");
    };
    assert_eq!(seal_scalar.as_slice(), [9u8; 32]);
    assert_eq!(factor_key.as_slice(), FACTOR);
    assert_eq!(
        get(&step, "factorKey")
            .unchecked_into::<Uint8Array>()
            .to_vec(),
        FACTOR,
        "the caller's step is left as it was"
    );
}

#[wasm_bindgen_test]
async fn a_step_off_the_generated_shape_is_refused() {
    for step in [
        JsValue::NULL,
        text("open"),
        object(&[("kind", text("bogus"))]),
        object(&[
            ("kind", text("open")),
            ("devicePublicKey", JsValue::from(42)),
            ("scalar", bytes(&[4u8; 32])),
        ]),
        object(&[
            ("kind", text("open")),
            ("devicePublicKey", text(REQUESTER)),
            ("scalar", text("thirty-two bytes")),
        ]),
        object(&[("kind", text("open")), ("devicePublicKey", text(REQUESTER))]),
        object(&[
            ("kind", text("open")),
            ("devicePublicKey", text(REQUESTER)),
            ("scalar", bytes(&[4u8; 32])),
            ("label", text("an unknown field")),
        ]),
        approve(REQUESTER, "02beef", JsValue::from(42)),
    ] {
        assert_eq!(
            run(&step).await.unwrap_err(),
            "the rendezvous step does not decode"
        );
    }
}

/// A secret field that skipped the placeholder would sit in serde's unwiped
/// buffer, so the step type itself refuses real bytes there.
#[wasm_bindgen_test]
fn a_secret_that_reaches_serde_unplaced_is_refused() {
    assert!(serde_wasm_bindgen::from_value::<DeviceRendezvousStep>(open(&[4u8; 32])).is_err());
    assert!(
        serde_wasm_bindgen::from_value::<DeviceRendezvousStep>(approve(
            REQUESTER,
            "02beef",
            bytes(FACTOR)
        ))
        .is_err()
    );
}

#[wasm_bindgen_test]
async fn a_scalar_of_the_wrong_length_is_refused() {
    assert_eq!(
        run(&open(&[4u8; 31])).await.unwrap_err(),
        "a rendezvous scalar is 32 bytes"
    );
}

/// An empty secret is the placeholder itself, so no step decodes with one.
#[wasm_bindgen_test]
fn an_empty_secret_is_refused() {
    assert!(decode_rendezvous_step(&approve(REQUESTER, "02beef", bytes(&[]))).is_err());
    assert!(decode_rendezvous_step(&open(&[])).is_err());
}

/// A slot list that drifts from the bytes fields of a step would leave a
/// secret slot holding the empty placeholder, so the take refuses it.
#[wasm_bindgen_test]
fn slots_that_drift_from_the_placeheld_fields_are_refused() {
    let step = approve(REQUESTER, "02beef", bytes(FACTOR));
    let placeheld = ["sealScalar".to_owned(), "factorKey".to_owned()];
    let (mut seal, mut factor) = (Secret::default(), Secret::default());

    assert!(take_rendezvous_secrets(&step, &placeheld, vec![("sealScalar", &mut seal)]).is_err());
    assert!(
        take_rendezvous_secrets(
            &step,
            &placeheld,
            vec![("sealScalar", &mut seal), ("sealScalar", &mut factor)]
        )
        .is_err()
    );
    assert!(
        take_rendezvous_secrets(
            &step,
            &placeheld,
            vec![("sealScalar", &mut seal), ("factorKey", &mut factor)]
        )
        .is_ok()
    );
    assert_eq!(factor.as_slice(), FACTOR);
}
