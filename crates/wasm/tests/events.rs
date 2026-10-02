//! The facade event encode at the WASM boundary (wasm32-unknown-unknown, under
//! wasm-bindgen-test-runner → Node.js): each field kind reaches JS as the type
//! the generated `Event` names.
#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use cipherbox_engine::facade::{
    BlockProgress, DeadLetterReason, Event, NodeId, OpPhase, OwedWorkClass, Staleness,
};
use cipherbox_engine::seams::OpId;
use cipherbox_wasm::boundary::encode_event;
use js_sys::{BigInt, Object, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::wasm_bindgen_test;

fn crossed(event: Event) -> JsValue {
    encode_event(&event).expect("every event encodes").into()
}

fn field(value: &JsValue, name: &str) -> JsValue {
    Reflect::get(value, &JsValue::from_str(name)).expect("a field is readable")
}

fn keys(value: &JsValue) -> Vec<String> {
    Object::keys(value.unchecked_ref::<Object>())
        .iter()
        .map(|key| key.as_string().expect("a key is a string"))
        .collect()
}

fn bytes(value: JsValue) -> Vec<u8> {
    assert!(
        value.is_instance_of::<Uint8Array>(),
        "bytes cross as a Uint8Array"
    );
    value.unchecked_into::<Uint8Array>().to_vec()
}

/// An op id past 2^53 survives as a `bigint`, which a `number` would round.
#[wasm_bindgen_test]
fn a_dead_letter_crosses_its_op_id_as_a_bigint_and_its_reason_as_a_name() {
    let dead = crossed(Event::DeadLetter {
        op_id: OpId(u64::MAX),
        reason: DeadLetterReason::GraftedScopeVaultSurface,
    });

    assert_eq!(field(&dead, "kind"), JsValue::from_str("deadLetter"));
    assert_eq!(field(&dead, "opId"), JsValue::from(BigInt::from(u64::MAX)));
    assert_eq!(
        field(&dead, "reason"),
        JsValue::from_str("graftedScopeVaultSurface")
    );
}

#[wasm_bindgen_test]
fn an_upload_progress_crosses_every_field_kind() {
    let progress = crossed(Event::OpProgress {
        op_id: Some(OpId(7)),
        node: NodeId([3; 16]),
        phase: OpPhase::UploadProgress,
        progress: Some(BlockProgress {
            confirmed: 2,
            total: 5,
        }),
        error: Some("unavailable".into()),
    });

    assert_eq!(field(&progress, "opId"), JsValue::from(BigInt::from(7u64)));
    assert_eq!(bytes(field(&progress, "node")), vec![3; 16]);
    assert_eq!(
        field(&progress, "phase"),
        JsValue::from_str("uploadProgress")
    );
    let blocks = field(&progress, "progress");
    assert_eq!(field(&blocks, "confirmed").as_f64(), Some(2.0));
    assert_eq!(field(&blocks, "total").as_f64(), Some(5.0));
    assert_eq!(field(&progress, "error"), JsValue::from_str("unavailable"));
}

/// The generated type names an absent field `T | null`, so it crosses as
/// `null`, never as `undefined` or a missing key.
#[wasm_bindgen_test]
fn an_absent_optional_field_crosses_as_null() {
    let op_less = crossed(Event::OpProgress {
        op_id: None,
        node: NodeId([0; 16]),
        phase: OpPhase::DownloadStarted,
        progress: None,
        error: None,
    });

    for name in ["opId", "progress", "error"] {
        assert!(field(&op_less, name).is_null(), "{name} crosses as null");
    }
    assert_eq!(
        keys(&op_less),
        ["kind", "opId", "node", "phase", "progress", "error"]
    );
}

#[wasm_bindgen_test]
fn the_byte_and_enum_payloads_cross_under_their_names() {
    let withheld = crossed(Event::WithheldUpdateEscalation {
        ipns_name: vec![9, 8, 7],
    });
    assert_eq!(bytes(field(&withheld, "ipnsName")), vec![9, 8, 7]);

    let stale = crossed(Event::StalenessChanged {
        level: Staleness::Offline,
    });
    assert_eq!(keys(&stale), ["kind", "staleness"]);
    assert_eq!(field(&stale, "staleness"), JsValue::from_str("offline"));

    let owed = crossed(Event::ScopeExitCutOwed {
        scope_root: NodeId([0x9e; 16]),
        detail: "publish-failed".into(),
    });
    assert_eq!(bytes(field(&owed, "scopeRoot")), vec![0x9e; 16]);

    let rotation_owed = crossed(Event::RotationWorkOwed {
        scope_root: NodeId([0x9f; 16]),
        detail: "rot-write-publish-failed".into(),
        retryable: false,
        class: OwedWorkClass::Trust,
    });
    assert_eq!(bytes(field(&rotation_owed, "scopeRoot")), vec![0x9f; 16]);
    assert_eq!(field(&rotation_owed, "retryable"), JsValue::FALSE);
    assert_eq!(field(&rotation_owed, "class"), JsValue::from_str("trust"));

    let unprovisioned = crossed(Event::VaultUnprovisioned {
        retryable: true,
        detail: "mint-stalled".into(),
    });
    assert_eq!(field(&unprovisioned, "retryable"), JsValue::TRUE);
}

/// Hosts switch on `kind`, so each variant crosses as its stable name, and a
/// variant with no payload carries nothing else.
#[wasm_bindgen_test]
fn each_event_kind_crosses_as_its_stable_name() {
    let node = NodeId([1; 16]);
    for (event, name, fields) in [
        (Event::SnapshotUpdated, "snapshotUpdated", 1),
        (
            Event::StalenessChanged {
                level: Staleness::Fresh,
            },
            "stalenessChanged",
            2,
        ),
        (
            Event::WithheldUpdateEscalation { ipns_name: vec![] },
            "withheldUpdateEscalation",
            2,
        ),
        (
            Event::DeadLetter {
                op_id: OpId(1),
                reason: DeadLetterReason::TargetGone,
            },
            "deadLetter",
            3,
        ),
        (Event::ParkedWritesUnreadable, "parkedWritesUnreadable", 1),
        (Event::RegistryDebtUnjournaled, "registryDebtUnjournaled", 1),
        (Event::GranteeNamesCleared, "granteeNamesCleared", 1),
        (
            Event::ConversionRecordUnreadable,
            "conversionRecordUnreadable",
            1,
        ),
        (Event::RefusedClaimDropped, "refusedClaimDropped", 1),
        (
            Event::AttributableAbuse {
                description: String::new(),
            },
            "attributableAbuse",
            2,
        ),
        (
            Event::SameSequenceFork {
                routing_key: String::new(),
            },
            "sameSequenceFork",
            2,
        ),
        (
            Event::RenewalFailed {
                routing_key: String::new(),
                detail: String::new(),
            },
            "renewalFailed",
            3,
        ),
        (
            Event::VaultUnprovisioned {
                retryable: false,
                detail: String::new(),
            },
            "vaultUnprovisioned",
            3,
        ),
        (Event::VaultSettingsChanged, "vaultSettingsChanged", 1),
        (
            Event::ScopeExitCutOwed {
                scope_root: node,
                detail: String::new(),
            },
            "scopeExitCutOwed",
            3,
        ),
        (
            Event::RotationWorkOwed {
                scope_root: node,
                detail: String::new(),
                retryable: true,
                class: OwedWorkClass::Availability,
            },
            "rotationWorkOwed",
            5,
        ),
        (
            Event::RotationWorkAbandoned {
                scope_root: node,
                detail: String::new(),
            },
            "rotationWorkAbandoned",
            3,
        ),
        (
            Event::WriteCutUnfinished { scope_root: node },
            "writeCutUnfinished",
            2,
        ),
        (
            Event::GranteeJoined {
                scope_root: node,
                name: String::new(),
                fingerprint: String::new(),
            },
            "granteeJoined",
            4,
        ),
        (
            Event::OpProgress {
                op_id: None,
                node,
                phase: OpPhase::DownloadStarted,
                progress: None,
                error: None,
            },
            "opProgress",
            6,
        ),
    ] {
        let js = crossed(event);
        assert_eq!(field(&js, "kind"), JsValue::from_str(name));
        assert_eq!(keys(&js).len(), fields, "{name}");
    }
}
