//! Browser-shaped boundary tests (wasm32-unknown-unknown, under
//! wasm-bindgen-test-runner → Node.js). They exercise the two boundary risks
//! the WASM leg exists to cover (blueprint/web-client.md "Boundary hygiene"):
//! `u64`→`bigint` marshalling and the getrandom → `crypto.getRandomValues`
//! worker-scope wiring, plus the view surface shapes. The command decode and
//! the event encode have their own files (`commands.rs`, `events.rs`).
//!
//! The whole file is gated to the browser target; native `cargo test` for this
//! crate runs the host conversion tests in `src/lib.rs` instead.
#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use cipherbox_engine::facade;
use cipherbox_engine::seams::OpId;
use cipherbox_wasm::{
    BinOriginKind, BinView, DeadLetterReason, InvitePreview, NodeId, NodeKind, PendingClass,
    Permission, SnapshotView,
};
use js_sys::{Array, BigInt, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::wasm_bindgen_test;

const IPNS_NAME: &str = "k51qzi5uqu5djmw2yvf8kk5cdjc1ddc00o4d5sjwi6f79xzcay9j3gkddw5uu4";

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

/// The bin read surface crosses with boundary-correct JS shapes: node ids as
/// `Uint8Array`, the deletion time as `bigint`, and the rows as a JS array. The
/// entry's bin-held key and its `ipnsName` have no getter, so a row carries
/// nothing a host could route or unseal with.
#[wasm_bindgen_test]
fn bin_view_getters_cross_with_boundary_shapes() {
    let view: JsValue = BinView::from_facade(facade::BinView {
        entries: vec![facade::BinRow {
            node: facade::NodeId([4u8; 16]),
            kind: facade::NodeKind::Folder,
            origin_parent: facade::NodeId([1u8; 16]),
            origin_name: "holiday".into(),
            origin_folder: facade::BinOrigin::Folder("trips".into()),
            deleted_at: u64::MAX,
            scope: facade::NodeId([2u8; 16]),
        }],
        origin: cipherbox_engine::SettingsOrigin::Stale,
    })
    .into();

    let get = |target: &JsValue, key: &str| {
        Reflect::get(target, &JsValue::from_str(key)).expect("getter is readable")
    };

    let entries = get(&view, "entries");
    assert!(entries.is_instance_of::<Array>());
    let entries = entries.unchecked_into::<Array>();
    assert_eq!(entries.length(), 1);

    let row = entries.get(0);
    for (key, byte) in [("node", 4u8), ("originParent", 1), ("scope", 2)] {
        let value = get(&row, key);
        assert!(value.is_instance_of::<Uint8Array>(), "{key} must be bytes");
        assert_eq!(
            value.unchecked_into::<Uint8Array>().to_vec(),
            vec![byte; 16]
        );
    }
    assert_eq!(
        get(&row, "originName").as_string().as_deref(),
        Some("holiday")
    );
    assert_eq!(
        get(&row, "originFolderName").as_string().as_deref(),
        Some("trips"),
        "the origin folder crosses under its own name"
    );
    assert_eq!(
        get(&row, "originFolderKind"),
        JsValue::from(BinOriginKind::Folder)
    );

    let deleted_at = get(&row, "deletedAt");
    assert_eq!(
        deleted_at.js_typeof(),
        JsValue::from_str("bigint"),
        "deletedAt must cross as a JS bigint, never a number"
    );
    let decimal = String::from(
        deleted_at
            .unchecked_into::<BigInt>()
            .to_string(10)
            .expect("bigint renders in base 10"),
    );
    assert_eq!(decimal, u64::MAX.to_string());

    for absent in ["heldKey", "ipnsName"] {
        assert!(
            get(&row, absent).is_undefined(),
            "{absent} must have no getter on the boundary"
        );
    }
}

/// The invite preview crosses with the names present together or absent
/// together, the state as its stable name, and the listing as a JS array of
/// names and kinds with no other field.
#[wasm_bindgen_test]
fn invite_preview_getters_cross_with_boundary_shapes() {
    let get = |target: &JsValue, key: &str| {
        Reflect::get(target, &JsValue::from_str(key)).expect("getter is readable")
    };
    let verified: JsValue = InvitePreview::from_facade(facade::InvitePreview {
        scope: facade::NodeId([7u8; 16]),
        names: Some(facade::PreviewNames {
            owner_name: "Ada".into(),
            folder_name: "trips".into(),
        }),
        permission: Some(facade::Permission::Write),
        state: facade::LinkPreviewState::Live,
        joined: true,
        listing: vec![facade::PreviewEntry {
            name: "notes.txt".into(),
            kind: facade::NodeKind::File,
        }],
    })
    .into();

    assert_eq!(
        get(&verified, "ownerName").as_string().as_deref(),
        Some("Ada")
    );
    assert_eq!(
        get(&verified, "folderName").as_string().as_deref(),
        Some("trips")
    );
    assert_eq!(
        get(&verified, "permission"),
        JsValue::from(Permission::Write)
    );
    assert_eq!(
        get(&verified, "scope")
            .unchecked_into::<Uint8Array>()
            .to_vec(),
        vec![7u8; 16]
    );
    assert_eq!(get(&verified, "state").as_string().as_deref(), Some("live"));
    assert_eq!(get(&verified, "joined").as_bool(), Some(true));
    let listing = get(&verified, "listing");
    assert!(listing.is_instance_of::<Array>());
    let entry = listing.unchecked_into::<Array>().get(0);
    assert_eq!(
        get(&entry, "name").as_string().as_deref(),
        Some("notes.txt")
    );
    assert_eq!(get(&entry, "kind"), JsValue::from(NodeKind::File));
    for absent in ["size", "id", "ipnsName"] {
        assert!(
            get(&entry, absent).is_undefined(),
            "{absent} must have no getter on the boundary"
        );
    }

    let unverified: JsValue = InvitePreview::from_facade(facade::InvitePreview {
        scope: facade::NodeId([8u8; 16]),
        names: None,
        permission: None,
        state: facade::LinkPreviewState::Unresolvable,
        joined: false,
        listing: Vec::new(),
    })
    .into();
    for absent in ["ownerName", "folderName", "permission"] {
        assert!(get(&unverified, absent).is_undefined(), "{absent}");
    }
    assert_eq!(
        get(&unverified, "state").as_string().as_deref(),
        Some("unresolvable")
    );
}

/// The snapshot read surface crosses with boundary-correct JS shapes: node ids
/// as `Uint8Array`, `u64`s as `bigint`, absent projections as `undefined`, and
/// children/ancestors as JS arrays of the wrapped types.
#[wasm_bindgen_test]
fn snapshot_view_getters_cross_with_boundary_shapes() {
    let view: JsValue = SnapshotView::from_facade(facade::SnapshotView {
        root: facade::NodeId([1u8; 16]),
        folder: facade::NodeId([2u8; 16]),
        folder_name: "holiday".into(),
        permission: facade::Permission::Write,
        received_share: true,
        children: vec![
            facade::SnapshotChild {
                id: facade::NodeId([3u8; 16]),
                name: "photo.jpg".into(),
                kind: facade::NodeKind::File,
                size: Some(u64::MAX),
                mtime: Some(1_700_000_000_000),
                pending: facade::PendingClass::Content,
                dead_letter: false,
                content_version: Some(2),
                content_cid: Some(vec![0xC1, 0xD0]),
                pending_invite_claims: 0,
                ipns_name: Some(IPNS_NAME.into()),
            },
            facade::SnapshotChild {
                id: facade::NodeId([4u8; 16]),
                name: "docs".into(),
                kind: facade::NodeKind::Folder,
                size: None,
                mtime: None,
                pending: facade::PendingClass::None,
                dead_letter: true,
                content_version: None,
                content_cid: None,
                pending_invite_claims: 2,
                ipns_name: None,
            },
        ],
        ancestors: vec![facade::Breadcrumb {
            id: facade::NodeId([1u8; 16]),
            name: String::new(),
        }],
        dead_letters: vec![facade::DeadLetter {
            op_id: OpId(9),
            reason: facade::DeadLetterReason::SuffixExhausted,
        }],
        queue_hold: Some(facade::QueueHold {
            op_id: OpId(12),
            node: facade::NodeId([6u8; 16]),
            reason: facade::QueueHoldReason::Quota {
                needed_bytes: u64::MAX,
            },
        }),
        retained_records: 0,
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

    assert_eq!(
        get(&view, "folderName").as_string().as_deref(),
        Some("holiday"),
        "folderName must cross under that JS name"
    );

    assert_eq!(
        get(&view, "permission"),
        JsValue::from(Permission::Write),
        "permission must cross under that JS name"
    );

    assert_eq!(
        get(&view, "receivedShare").as_bool(),
        Some(true),
        "receivedShare must cross under that JS name"
    );

    assert_eq!(
        get(&view, "retainedRecords").as_f64(),
        Some(0.0),
        "retainedRecords must cross under that JS name"
    );

    let dead_letters = get(&view, "deadLetters");
    assert!(dead_letters.is_instance_of::<Array>());
    let dead_letters = dead_letters.unchecked_into::<Array>();
    assert_eq!(dead_letters.length(), 1);
    let dead = dead_letters.get(0);
    let dead_op_id = get(&dead, "opId");
    assert_eq!(
        dead_op_id.js_typeof(),
        JsValue::from_str("bigint"),
        "a dead letter's opId must cross as a JS bigint, never a number"
    );
    assert_eq!(
        String::from(
            dead_op_id
                .unchecked_into::<BigInt>()
                .to_string(10)
                .expect("bigint renders in base 10")
        ),
        "9"
    );
    assert_eq!(
        get(&dead, "reason").as_f64(),
        Some(DeadLetterReason::SuffixExhausted as u32 as f64),
        "the reason crosses as its mirror-enum ordinal"
    );

    let hold = get(&view, "queueHold");
    assert_eq!(
        get(&hold, "opId").js_typeof(),
        JsValue::from_str("bigint"),
        "a held op's opId must cross as a JS bigint, never a number"
    );
    assert_eq!(
        get(&hold, "reason"),
        JsValue::from_str("quota"),
        "the host dispatches on the reason name"
    );
    let needed = get(&hold, "neededBytes");
    assert_eq!(
        needed.js_typeof(),
        JsValue::from_str("bigint"),
        "neededBytes must cross as a JS bigint, never a number"
    );
    assert_eq!(
        String::from(
            needed
                .unchecked_into::<BigInt>()
                .to_string(10)
                .expect("bigint renders in base 10")
        ),
        u64::MAX.to_string()
    );
    assert!(
        get(&hold, "check").is_undefined(),
        "a quota hold carries no check name"
    );
    assert_eq!(
        get(&hold, "node").unchecked_into::<Uint8Array>().to_vec(),
        vec![6u8; 16]
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
    let version = get(&file, "contentVersion");
    assert_eq!(
        version.js_typeof(),
        JsValue::from_str("bigint"),
        "the version count must cross as a JS bigint, never a number"
    );
    assert_eq!(
        String::from(
            version
                .unchecked_into::<BigInt>()
                .to_string(10)
                .expect("bigint renders in base 10")
        ),
        "2"
    );
    assert_eq!(
        get(&file, "pending").as_f64(),
        Some(PendingClass::Content as u32 as f64),
        "the pending class crosses as its enum value"
    );
    assert_eq!(get(&file, "deadLetter"), JsValue::FALSE);

    let folder_child = children.get(1);
    assert!(
        get(&folder_child, "size").is_undefined(),
        "an unprojected size must cross as undefined"
    );
    assert!(get(&folder_child, "mtime").is_undefined());
    assert!(
        get(&folder_child, "contentVersion").is_undefined(),
        "an unprojected version count must cross as undefined"
    );
    assert_eq!(get(&folder_child, "deadLetter"), JsValue::TRUE);
    assert_eq!(get(&file, "pendingInviteClaims").as_f64(), Some(0.0));
    assert_eq!(
        get(&folder_child, "pendingInviteClaims").as_f64(),
        Some(2.0)
    );
    assert_eq!(
        get(&file, "ipnsName").as_string().as_deref(),
        Some(IPNS_NAME),
        "ipnsName must cross as a string under that JS name"
    );
    assert!(get(&folder_child, "ipnsName").is_undefined());

    let ancestors = get(&view, "ancestors").unchecked_into::<Array>();
    assert_eq!(ancestors.length(), 1);
    let crumb = ancestors.get(0);
    assert_eq!(get(&crumb, "name"), JsValue::from_str(""));
    assert_eq!(
        get(&crumb, "id").unchecked_into::<Uint8Array>().to_vec(),
        vec![1u8; 16]
    );
}

/// A settings hold crosses with its check name and no byte figure: the host
/// renders the rule that refused, and nothing a quota hold would carry.
#[wasm_bindgen_test]
fn a_settings_queue_hold_crosses_with_its_check_and_no_byte_figure() {
    let view: JsValue = SnapshotView::from_facade(facade::SnapshotView {
        root: facade::NodeId([1u8; 16]),
        folder: facade::NodeId([1u8; 16]),
        folder_name: String::new(),
        permission: facade::Permission::Write,
        received_share: false,
        children: Vec::new(),
        ancestors: Vec::new(),
        dead_letters: Vec::new(),
        queue_hold: Some(facade::QueueHold {
            op_id: OpId(13),
            node: facade::NodeId([7u8; 16]),
            reason: facade::QueueHoldReason::Settings(cipherbox_engine::SettingsRefusal::Byo(
                cipherbox_engine::ProviderError::BlockedAddress,
            )),
        }),
        retained_records: 0,
        staleness: facade::Staleness::Fresh,
    })
    .into();

    let hold = Reflect::get(&view, &JsValue::from_str("queueHold")).expect("getter is readable");
    let get = |key: &str| Reflect::get(&hold, &JsValue::from_str(key)).expect("getter is readable");
    assert_eq!(get("reason"), JsValue::from_str("settings"));
    assert_eq!(
        get("check"),
        JsValue::from_str("byo-endpoint-blocked"),
        "the refusing rule crosses by its stable check name"
    );
    assert!(
        get("neededBytes").is_undefined(),
        "only a quota hold carries a byte figure"
    );
    assert_eq!(
        get("node").unchecked_into::<Uint8Array>().to_vec(),
        vec![7u8; 16]
    );
}

/// The `deadLetterReason` ordinals the TypeScript side decodes against
/// (`packages/client/src/testkit.ts`, and the raw numbers its unit tests feed).
/// A variant inserted mid-enum renumbers every one after it, and both sides go
/// on passing while production maps every later reason to the wrong string —
/// so the numbering is pinned here rather than left to append-only discipline.
#[wasm_bindgen_test]
fn every_dead_letter_reason_crosses_at_the_ordinal_typescript_decodes() {
    for (reason, ordinal) in [
        (facade::DeadLetterReason::TargetGone, 0),
        (facade::DeadLetterReason::DestinationGone, 1),
        (facade::DeadLetterReason::DestinationInsideTarget, 2),
        (facade::DeadLetterReason::SuffixExhausted, 3),
        (facade::DeadLetterReason::Undecodable, 4),
        (facade::DeadLetterReason::PayloadRefused, 5),
        (facade::DeadLetterReason::AttemptsExhausted, 6),
        (facade::DeadLetterReason::ContentUnrecoverable, 7),
        (facade::DeadLetterReason::BaseSuperseded, 8),
        (facade::DeadLetterReason::HeadTooLarge, 9),
        (facade::DeadLetterReason::PreservationRefused, 10),
        (facade::DeadLetterReason::AlreadyPublished, 11),
        (facade::DeadLetterReason::TargetStillLinked, 12),
        (facade::DeadLetterReason::ScopeRootNotResealable, 13),
        (facade::DeadLetterReason::BinIndexFull, 14),
        (facade::DeadLetterReason::CrossingUnauthorable, 15),
        (facade::DeadLetterReason::BinIndexStrandedMint, 16),
        (facade::DeadLetterReason::TargetLinkedAcrossScopes, 17),
        (facade::DeadLetterReason::GraftedScopeVaultSurface, 18),
    ] {
        assert_eq!(DeadLetterReason::from(reason) as u32, ordinal, "{reason:?}");
    }
}
