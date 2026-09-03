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
use cipherbox_engine::settings::MAX_BIN_RETENTION_DAYS;
use cipherbox_wasm::{
    BinOriginKind, BinView, ByoIpfsConfig, ByoKind, Command, DeadLetterReason, Event, NodeId,
    NodeKind, OpPhase, PendingClass, Permission, PinMode, SnapshotView, Staleness, VaultSettings,
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
        reason: facade::DeadLetterReason::Undecodable,
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
        Command::create(&node, "photo.jpg".into(), NodeKind::File).name(),
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
        progress: None,
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
        progress: None,
        error: None,
    });
    assert!(op_less.op_id().is_none());
    assert!(op_less.error().is_none());
    assert!(op_less.blocks_confirmed().is_none());
    assert!(op_less.blocks_total().is_none());
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
    for key in [
        "node",
        "phase",
        "error",
        "opId",
        "blocksConfirmed",
        "blocksTotal",
    ] {
        assert!(
            Reflect::get(&other, &JsValue::from_str(key))
                .expect("getter is readable")
                .is_undefined(),
            "{key} must be undefined off-variant"
        );
    }
}

/// An upload's progress crosses with its op id and its block counters: the id
/// as `bigint` (it is a `u64`), the counters as plain JS `number`s a host can do
/// progress arithmetic on without widening.
#[wasm_bindgen_test]
fn upload_progress_crosses_with_its_op_id_and_block_counters() {
    let event = Event::from_facade(facade::Event::OpProgress {
        op_id: Some(OpId(7)),
        node: facade::NodeId([3u8; 16]),
        phase: facade::OpPhase::UploadProgress,
        progress: Some(facade::BlockProgress {
            confirmed: 2,
            total: 5,
        }),
        error: None,
    });
    assert_eq!(event.phase(), Some(OpPhase::UploadProgress));
    assert_eq!(event.blocks_confirmed(), Some(2));
    assert_eq!(event.blocks_total(), Some(5));

    let js: JsValue = event.into();
    let confirmed = Reflect::get(&js, &JsValue::from_str("blocksConfirmed"))
        .expect("blocksConfirmed getter is readable");
    assert_eq!(confirmed.js_typeof(), JsValue::from_str("number"));
    assert_eq!(confirmed.as_f64(), Some(2.0));
    let total = Reflect::get(&js, &JsValue::from_str("blocksTotal"))
        .expect("blocksTotal getter is readable");
    assert_eq!(total.as_f64(), Some(5.0));
    assert_eq!(
        Reflect::get(&js, &JsValue::from_str("opId"))
            .expect("opId getter is readable")
            .js_typeof(),
        JsValue::from_str("bigint")
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

/// The snapshot read surface crosses with boundary-correct JS shapes: node ids
/// as `Uint8Array`, `u64`s as `bigint`, absent projections as `undefined`, and
/// children/ancestors as JS arrays of the wrapped types.
#[wasm_bindgen_test]
fn snapshot_view_getters_cross_with_boundary_shapes() {
    let view: JsValue = SnapshotView::from_facade(facade::SnapshotView {
        root: facade::NodeId([1u8; 16]),
        folder: facade::NodeId([2u8; 16]),
        folder_name: "holiday".into(),
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
        blocked: Some(facade::BlockedOp {
            op_id: OpId(12),
            node: facade::NodeId([6u8; 16]),
            needed_bytes: u64::MAX,
        }),
        settings_hold: Some(facade::SettingsHold {
            op_id: OpId(13),
            node: facade::NodeId([7u8; 16]),
            refusal: cipherbox_engine::SettingsRefusal::Byo(
                cipherbox_engine::ProviderError::BlockedAddress,
            ),
        }),
        bin_index_hold: Some(facade::BinIndexHold {
            op_id: OpId(14),
            node: facade::NodeId([8u8; 16]),
            reason: cipherbox_engine::DefaultsReason::Suppressed,
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

    let blocked = get(&view, "blocked");
    let needed = get(&blocked, "neededBytes");
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
    assert_eq!(
        get(&blocked, "node")
            .unchecked_into::<Uint8Array>()
            .to_vec(),
        vec![6u8; 16]
    );

    let held = get(&view, "settingsHold");
    assert_eq!(
        get(&held, "opId").js_typeof(),
        JsValue::from_str("bigint"),
        "a held op's opId must cross as a JS bigint, never a number"
    );
    assert_eq!(
        get(&held, "node").unchecked_into::<Uint8Array>().to_vec(),
        vec![7u8; 16]
    );
    assert_eq!(
        get(&held, "check"),
        JsValue::from_str("byo-endpoint-blocked"),
        "the refusing rule crosses by its stable check name"
    );

    let bin_held = get(&view, "binIndexHold");
    assert_eq!(
        get(&bin_held, "opId").js_typeof(),
        JsValue::from_str("bigint"),
        "a held op's opId must cross as a JS bigint, never a number"
    );
    assert_eq!(
        get(&bin_held, "node")
            .unchecked_into::<Uint8Array>()
            .to_vec(),
        vec![8u8; 16]
    );
    assert_eq!(
        get(&bin_held, "check"),
        JsValue::from_str("suppressed"),
        "the load outcome crosses by its stable check name, carrying no figures"
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

    let ancestors = get(&view, "ancestors").unchecked_into::<Array>();
    assert_eq!(ancestors.length(), 1);
    let crumb = ancestors.get(0);
    assert_eq!(get(&crumb, "name"), JsValue::from_str(""));
    assert_eq!(
        get(&crumb, "id").unchecked_into::<Uint8Array>().to_vec(),
        vec![1u8; 16]
    );
}

/// The refusal builds a `JsError`, so it is only reachable on this target.
#[wasm_bindgen_test]
fn a_zero_retention_cap_is_refused_rather_than_defaulted() {
    assert!(
        VaultSettings::new(PinMode::Hosted, None, Some(0), None).is_err(),
        "0 must not be read as a retention policy"
    );
    assert!(VaultSettings::new(PinMode::Hosted, None, Some(1), None).is_ok());
    assert!(
        VaultSettings::new(PinMode::Hosted, None, None, None).is_ok(),
        "no cap keeps every version"
    );
}

/// The boundary refuses a bin retention the engine would refuse to publish, so
/// the host learns which field it must change rather than a save that cannot
/// land.
#[wasm_bindgen_test]
fn a_bin_retention_past_the_bar_is_refused_at_the_boundary() {
    assert!(
        VaultSettings::new(
            PinMode::Hosted,
            None,
            None,
            Some(MAX_BIN_RETENTION_DAYS + 1)
        )
        .is_err(),
        "a retention past the bar must not build"
    );
    assert!(VaultSettings::new(PinMode::Hosted, None, None, Some(MAX_BIN_RETENTION_DAYS)).is_ok());
    assert!(
        VaultSettings::new(PinMode::Hosted, None, None, Some(0)).is_ok(),
        "0 keeps the hard delete"
    );
}

/// The builder's name is the settings command's whole readable surface.
#[wasm_bindgen_test]
fn a_vault_settings_command_carries_the_stable_builder_name() {
    let settings = VaultSettings::new(
        PinMode::Dual,
        Some(
            ByoIpfsConfig::new(
                "https://kubo.example".to_owned(),
                ByoKind::Kubo,
                Some(b"s3cret".to_vec()),
            )
            .expect("UTF-8 token bytes build"),
        ),
        Some(3),
        Some(30),
    )
    .expect("a positive cap builds");

    assert_eq!(
        Command::save_vault_settings(settings).name(),
        "saveVaultSettings"
    );
}

/// A bearer the engine would refuse never reaches a config object: the refusal
/// would otherwise land after the constructor minted one holding the
/// credential, stranding that allocation with no owner to free it.
#[wasm_bindgen_test]
fn a_bearer_the_engine_would_refuse_never_builds_a_config() {
    // Not text at all, empty, and text carrying bytes a header cannot splice.
    for refused in [
        vec![0xff, 0xfe],
        vec![],
        b"has space".to_vec(),
        "\u{e9}".into(),
    ] {
        assert!(
            ByoIpfsConfig::new(
                "https://kubo.example".to_owned(),
                ByoKind::Kubo,
                Some(refused),
            )
            .is_err()
        );
    }
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
        (facade::DeadLetterReason::TargetLinkedAcrossScopes, 16),
    ] {
        assert_eq!(DeadLetterReason::from(reason) as u32, ordinal, "{reason:?}");
    }
}
