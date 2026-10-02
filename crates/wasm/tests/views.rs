//! The facade view encode at the WASM boundary (wasm32-unknown-unknown, under
//! wasm-bindgen-test-runner → Node.js): each field kind reaches JS as the type
//! the generated view names, and each view carries exactly the keys it names.
#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use core::num::NonZeroU64;

use cipherbox_core::seal::NameSource;
use cipherbox_engine::facade::{
    BinOrigin, BinRow, BinView, Breadcrumb, DeadLetter, DeadLetterReason, InvitePreview,
    LinkPreviewState, NodeId, NodeKind, PendingClass, Permission, PreviewEntry, PreviewNames,
    QueueHold, QueueHoldReason, QuotaView, ReceivedShareRow, SharingContact, SharingGrant,
    SnapshotChild, SnapshotView, Staleness, VaultStorageView, VersionEntry,
};
use cipherbox_engine::seams::OpId;
use cipherbox_engine::{
    AuthMethod, AuthMethodKind, BinIndexHoldCheck, ByoKind, DefaultsReason, LapsedHead,
    PendingApprovalView, PinMode, PlacementRefusal, ProviderError, ReclaimStall,
    ReclaimStallReason, RegisteredDevice, ResolutionClass, RetentionPolicy, SettingsHold,
    SettingsOrigin, Unopened, VaultSettingsSummary,
};
use cipherbox_wasm::OpenedStream;
use cipherbox_wasm::boundary::encode_view;
use js_sys::{Array, BigInt, Object, Reflect, Uint8Array};
use serde::Serialize;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::wasm_bindgen_test;

const IPNS_NAME: &str = "k51qzi5uqu5djmw2yvf8kk5cdjc1ddc00o4d5sjwi6f79xzcay9j3gkddw5uu4";

fn crossed<T: Serialize + ?Sized>(view: &T) -> JsValue {
    encode_view(view).expect("every view encodes")
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

fn big(value: u64) -> JsValue {
    JsValue::from(BigInt::from(value))
}

fn rows(value: JsValue) -> Array {
    assert!(Array::is_array(&value), "rows cross as an array");
    value.unchecked_into::<Array>()
}

fn snapshot(queue_hold: Option<QueueHold>) -> SnapshotView {
    SnapshotView {
        root: NodeId([1; 16]),
        folder: NodeId([2; 16]),
        folder_name: "holiday".into(),
        permission: Permission::Write,
        received_share: true,
        children: vec![
            SnapshotChild {
                id: NodeId([3; 16]),
                name: "photo.jpg".into(),
                kind: NodeKind::File,
                size: Some(u64::MAX),
                mtime: Some(1_700_000_000_000),
                pending: PendingClass::Content,
                dead_letter: false,
                content_version: Some(2),
                content_cid: Some(vec![0xC1, 0xD0]),
                pending_invite_claims: 0,
                ipns_name: Some(IPNS_NAME.into()),
            },
            SnapshotChild {
                id: NodeId([4; 16]),
                name: "docs".into(),
                kind: NodeKind::Folder,
                size: None,
                mtime: None,
                pending: PendingClass::None,
                dead_letter: true,
                content_version: None,
                content_cid: None,
                pending_invite_claims: 2,
                ipns_name: None,
            },
        ],
        ancestors: vec![Breadcrumb {
            id: NodeId([1; 16]),
            name: String::new(),
        }],
        dead_letters: vec![DeadLetter {
            op_id: OpId(u64::MAX),
            reason: DeadLetterReason::SuffixExhausted,
        }],
        queue_hold,
        retained_records: 3,
        staleness: Staleness::Reconciling,
    }
}

/// Node ids and CIDs cross as bytes, every `u64` and count as a `bigint`, an
/// enum as its name, and an absent projection as `null`.
#[wasm_bindgen_test]
fn a_snapshot_crosses_every_field_kind() {
    let view = crossed(&snapshot(None));

    assert_eq!(
        keys(&view),
        [
            "root",
            "folder",
            "folderName",
            "permission",
            "receivedShare",
            "children",
            "ancestors",
            "deadLetters",
            "queueHold",
            "retainedRecords",
            "staleness",
        ]
    );
    assert_eq!(bytes(field(&view, "root")), vec![1; 16]);
    assert_eq!(bytes(field(&view, "folder")), vec![2; 16]);
    assert_eq!(field(&view, "folderName"), JsValue::from_str("holiday"));
    assert_eq!(field(&view, "permission"), JsValue::from_str("write"));
    assert_eq!(field(&view, "receivedShare"), JsValue::TRUE);
    assert!(field(&view, "queueHold").is_null());
    assert_eq!(field(&view, "retainedRecords"), big(3));
    assert_eq!(field(&view, "staleness"), JsValue::from_str("reconciling"));

    let dead = rows(field(&view, "deadLetters")).get(0);
    assert_eq!(field(&dead, "opId"), big(u64::MAX));
    assert_eq!(field(&dead, "reason"), JsValue::from_str("suffixExhausted"));

    let children = rows(field(&view, "children"));
    let file = children.get(0);
    assert_eq!(
        keys(&file),
        [
            "id",
            "name",
            "kind",
            "size",
            "mtime",
            "pending",
            "deadLetter",
            "contentVersion",
            "contentCid",
            "pendingInviteClaims",
            "ipnsName",
        ]
    );
    assert_eq!(bytes(field(&file, "id")), vec![3; 16]);
    assert_eq!(field(&file, "kind"), JsValue::from_str("file"));
    assert_eq!(field(&file, "size"), big(u64::MAX));
    assert_eq!(field(&file, "mtime"), big(1_700_000_000_000));
    assert_eq!(field(&file, "pending"), JsValue::from_str("content"));
    assert_eq!(field(&file, "contentVersion"), big(2));
    assert_eq!(bytes(field(&file, "contentCid")), vec![0xC1, 0xD0]);
    assert_eq!(field(&file, "pendingInviteClaims").as_f64(), Some(0.0));
    assert_eq!(field(&file, "ipnsName"), JsValue::from_str(IPNS_NAME));

    let folder = children.get(1);
    assert_eq!(field(&folder, "kind"), JsValue::from_str("folder"));
    assert_eq!(field(&folder, "pending"), JsValue::from_str("none"));
    assert_eq!(field(&folder, "deadLetter"), JsValue::TRUE);
    for absent in ["size", "mtime", "contentVersion", "contentCid", "ipnsName"] {
        assert!(field(&folder, absent).is_null(), "{absent} crosses as null");
    }

    let crumb = rows(field(&view, "ancestors")).get(0);
    assert_eq!(keys(&crumb), ["id", "name"]);
    assert_eq!(bytes(field(&crumb, "id")), vec![1; 16]);
}

/// A host dispatches on the reason, and each hold carries only the figure its
/// own notice renders: a byte count on a quota hold, a check name otherwise.
#[wasm_bindgen_test]
fn a_queue_hold_names_its_reason_and_carries_only_that_reasons_figure() {
    let hold = |reason| {
        field(
            &crossed(&snapshot(Some(QueueHold {
                op_id: OpId(12),
                node: NodeId([6; 16]),
                reason,
            }))),
            "queueHold",
        )
    };

    let quota = hold(QueueHoldReason::Quota {
        needed_bytes: u64::MAX,
    });
    assert_eq!(keys(&quota), ["reason", "opId", "node", "neededBytes"]);
    assert_eq!(field(&quota, "reason"), JsValue::from_str("quota"));
    assert_eq!(field(&quota, "opId"), big(12));
    assert_eq!(bytes(field(&quota, "node")), vec![6; 16]);
    assert_eq!(field(&quota, "neededBytes"), big(u64::MAX));

    let settings = hold(QueueHoldReason::Settings(
        SettingsHold::byo(ProviderError::BlockedAddress).unwrap(),
    ));
    assert_eq!(keys(&settings), ["reason", "opId", "node", "check"]);
    assert_eq!(field(&settings, "reason"), JsValue::from_str("settings"));
    assert_eq!(
        field(&settings, "check"),
        JsValue::from_str("byo-endpoint-blocked")
    );

    let bin_index = hold(QueueHoldReason::BinIndex(BinIndexHoldCheck::Suppressed));
    assert_eq!(keys(&bin_index), ["reason", "opId", "node", "check"]);
    assert_eq!(field(&bin_index, "reason"), JsValue::from_str("bin-index"));
    assert_eq!(field(&bin_index, "check"), JsValue::from_str("suppressed"));
}

/// Each hold crosses under the check name of the rule that refused: every
/// settings hold the engine can take, and every bin index load outcome.
#[wasm_bindgen_test]
fn a_hold_check_crosses_as_the_check_name_of_its_refusal() {
    let check = |reason| {
        let view = encode_view(&snapshot(Some(QueueHold {
            op_id: OpId(1),
            node: NodeId([6; 16]),
            reason,
        })))
        .unwrap();
        field(&field(&view, "queueHold"), "check")
    };
    let byo = [
        ProviderError::InvalidEndpoint,
        ProviderError::InsecureTransport,
        ProviderError::BlockedAddress,
        ProviderError::InvalidCredential,
        ProviderError::UnresolvedCredential,
        ProviderError::NoStoredCredential,
        ProviderError::RepointedCredential,
    ]
    .map(|error| SettingsHold::byo(error).unwrap());
    let placement = [
        PlacementRefusal::NoProvider,
        PlacementRefusal::NoExternalIngress(ByoKind::Psa),
    ]
    .map(|refusal| refusal.holds().unwrap());
    for hold in byo.into_iter().chain(placement) {
        assert_eq!(
            check(QueueHoldReason::Settings(hold)),
            JsValue::from_str(hold.refusal().check()),
            "{hold:?}"
        );
    }
    // An unavailable settings record crosses under the load's reason, without
    // the figures it carries.
    for reason in [
        DefaultsReason::StrandedMint,
        DefaultsReason::RevisionRolledBack {
            floor: 4,
            revision: 2,
        },
        DefaultsReason::Expired {
            sequence: 3,
            head: LapsedHead::Opened,
        },
        DefaultsReason::Unreadable {
            sequence: 3,
            cause: Unopened::Malformed,
        },
    ] {
        let hold = PlacementRefusal::SettingsUnavailable(reason)
            .holds()
            .unwrap();
        assert_eq!(
            check(QueueHoldReason::Settings(hold)),
            JsValue::from_str(reason.check()),
            "{reason:?}"
        );
    }
    for (held, reason) in [
        (
            BinIndexHoldCheck::UnprovenFirstRun,
            DefaultsReason::UnprovenFirstRun,
        ),
        (BinIndexHoldCheck::Suppressed, DefaultsReason::Suppressed),
        (
            BinIndexHoldCheck::Expired,
            DefaultsReason::Expired {
                sequence: 3,
                head: LapsedHead::Opened,
            },
        ),
        (BinIndexHoldCheck::TimedOut, DefaultsReason::TimedOut),
        (
            BinIndexHoldCheck::FloorUnreadable,
            DefaultsReason::FloorUnreadable,
        ),
    ] {
        assert_eq!(
            check(QueueHoldReason::BinIndex(held)),
            JsValue::from_str(reason.check()),
            "{reason:?}"
        );
    }
}

/// A bin row carries no route and no key: the entry's bin-held key and its
/// `ipnsName` stay in the engine.
#[wasm_bindgen_test]
fn a_bin_row_crosses_its_origin_and_nothing_to_route_or_unseal_with() {
    let row = |origin_folder| BinRow {
        node: NodeId([4; 16]),
        kind: NodeKind::Folder,
        origin_parent: NodeId([1; 16]),
        origin_name: "holiday".into(),
        origin_folder,
        deleted_at: u64::MAX,
        scope: NodeId([2; 16]),
    };
    let view = crossed(&BinView {
        entries: vec![
            row(BinOrigin::Folder {
                name: "trips".into(),
            }),
            row(BinOrigin::Root),
            row(BinOrigin::Gone),
        ],
        origin: SettingsOrigin::Stale,
    });

    assert_eq!(keys(&view), ["entries", "origin"]);
    assert_eq!(field(&view, "origin"), JsValue::from_str("stale"));
    let entries = rows(field(&view, "entries"));
    let folder = entries.get(0);
    assert_eq!(
        keys(&folder),
        [
            "node",
            "kind",
            "originParent",
            "originName",
            "originFolder",
            "deletedAt",
            "scope",
        ]
    );
    assert_eq!(bytes(field(&folder, "node")), vec![4; 16]);
    assert_eq!(bytes(field(&folder, "originParent")), vec![1; 16]);
    assert_eq!(bytes(field(&folder, "scope")), vec![2; 16]);
    assert_eq!(field(&folder, "deletedAt"), big(u64::MAX));
    let origin = field(&folder, "originFolder");
    assert_eq!(keys(&origin), ["kind", "name"]);
    assert_eq!(field(&origin, "kind"), JsValue::from_str("folder"));
    assert_eq!(field(&origin, "name"), JsValue::from_str("trips"));
    for (index, kind) in [(1, "root"), (2, "gone")] {
        let origin = field(&entries.get(index), "originFolder");
        assert_eq!(keys(&origin), ["kind"]);
        assert_eq!(field(&origin, "kind"), JsValue::from_str(kind));
    }
}

/// The names cross together or not at all, and a listing entry carries a name
/// and a kind and nothing that costs a read of the child.
#[wasm_bindgen_test]
fn an_invite_preview_crosses_its_names_together_and_a_bare_listing() {
    let verified = crossed(&InvitePreview {
        scope: NodeId([7; 16]),
        names: Some(PreviewNames {
            owner_name: "Ada".into(),
            folder_name: "trips".into(),
        }),
        permission: Some(Permission::Read),
        state: LinkPreviewState::Live,
        joined: true,
        listing: vec![PreviewEntry {
            name: "notes.txt".into(),
            kind: NodeKind::File,
        }],
    });
    assert_eq!(
        keys(&verified),
        ["scope", "names", "permission", "state", "joined", "listing"]
    );
    assert_eq!(bytes(field(&verified, "scope")), vec![7; 16]);
    let names = field(&verified, "names");
    assert_eq!(keys(&names), ["ownerName", "folderName"]);
    assert_eq!(field(&verified, "permission"), JsValue::from_str("read"));
    assert_eq!(field(&verified, "state"), JsValue::from_str("live"));
    let entry = rows(field(&verified, "listing")).get(0);
    assert_eq!(keys(&entry), ["name", "kind"]);
    assert_eq!(field(&entry, "kind"), JsValue::from_str("file"));

    for (state, name) in [
        (LinkPreviewState::Expired, "expired"),
        (LinkPreviewState::Revoked, "revoked"),
        (LinkPreviewState::Unresolvable, "unresolvable"),
    ] {
        let unverified = crossed(&InvitePreview {
            scope: NodeId([8; 16]),
            names: None,
            permission: None,
            state,
            joined: false,
            listing: Vec::new(),
        });
        assert!(field(&unverified, "names").is_null());
        assert!(field(&unverified, "permission").is_null());
        assert_eq!(field(&unverified, "state"), JsValue::from_str(name));
        assert_eq!(state.name(), name);
    }
}

/// A grantee name crosses with who chose it, and a contact with its pre-fill.
#[wasm_bindgen_test]
fn a_sharing_row_crosses_the_grantee_name_with_its_source() {
    let named = crossed(&SharingGrant {
        recipient_identity_public_key: vec![2; 33],
        permission: Permission::Write,
        grantee_name: Some(("Ada".into(), NameSource::Claimant)),
        via_link: Some(vec![0x44; 32]),
    });
    assert_eq!(
        keys(&named),
        [
            "recipientIdentityPublicKey",
            "permission",
            "granteeName",
            "viaLink",
        ]
    );
    assert_eq!(
        bytes(field(&named, "recipientIdentityPublicKey")),
        vec![2; 33]
    );
    let name = field(&named, "granteeName");
    assert_eq!(keys(&name), ["name", "source"]);
    assert_eq!(field(&name, "name"), JsValue::from_str("Ada"));
    assert_eq!(field(&name, "source"), JsValue::from_str("claimant"));
    assert_eq!(bytes(field(&named, "viaLink")), vec![0x44; 32]);

    let owner_named = crossed(&SharingGrant {
        recipient_identity_public_key: vec![2; 33],
        permission: Permission::Read,
        grantee_name: Some(("Bo".into(), NameSource::Owner)),
        via_link: None,
    });
    assert_eq!(
        field(&field(&owner_named, "granteeName"), "source"),
        JsValue::from_str("owner")
    );
    assert!(field(&owner_named, "viaLink").is_null());

    let contact = crossed(&SharingContact {
        identity_public_key: vec![2; 33],
        cached_name: None,
    });
    assert_eq!(keys(&contact), ["identityPublicKey", "cachedName"]);
    assert!(field(&contact, "cachedName").is_null());
}

/// The verdict crosses under the stable name the engine gives it.
#[wasm_bindgen_test]
fn a_received_share_crosses_its_resolution_under_its_stable_name() {
    let row = |resolution| {
        crossed(&ReceivedShareRow {
            scope: NodeId([5; 16]),
            sharer_identity_public_key: vec![3; 33],
            display_name: "trips".into(),
            permission: Permission::Read,
            resolution,
            via_link: true,
        })
    };
    let unresolved = row(None);
    assert_eq!(
        keys(&unresolved),
        [
            "scope",
            "sharerIdentityPublicKey",
            "displayName",
            "permission",
            "resolution",
            "viaLink",
        ]
    );
    assert!(field(&unresolved, "resolution").is_null());
    for class in [
        ResolutionClass::Granted,
        ResolutionClass::RevocationSignal,
        ResolutionClass::Unresolvable,
        ResolutionClass::EpochLag,
        ResolutionClass::Expired,
    ] {
        assert_eq!(
            field(&row(Some(class)), "resolution"),
            JsValue::from_str(class.name())
        );
    }
}

/// The settings summary carries whether a bearer is stored and never the
/// bearer, and a retention bound wider than a `u32` saturates rather than
/// reading as no bound.
#[wasm_bindgen_test]
fn the_storage_view_crosses_without_the_bearer() {
    let view = |retention, quota| VaultStorageView {
        settings: VaultSettingsSummary {
            pin_mode: PinMode::Dual,
            byo_endpoint: Some("https://pin.example".into()),
            byo_kind: Some(ByoKind::Psa),
            byo_credential_stored: true,
            retention,
            bin_retention_days: 30,
            origin: SettingsOrigin::Resolved,
        },
        quota,
        pending_reclaim_bytes: u64::MAX,
        pending_reclaim_is_partial: true,
        reclaim_stalls: vec![ReclaimStall {
            node: [9; 16],
            target: "bafy".into(),
            reason: ReclaimStallReason::TargetStillLive,
        }],
    };
    let bounded = crossed(&view(
        RetentionPolicy::KeepLatest(NonZeroU64::MAX),
        Some(QuotaView {
            used_bytes: u64::MAX,
            limit_bytes: 4096,
            advisory: true,
        }),
    ));
    assert_eq!(
        keys(&bounded),
        [
            "settings",
            "quota",
            "pendingReclaimBytes",
            "pendingReclaimIsPartial",
            "reclaimStalls",
        ]
    );
    let settings = field(&bounded, "settings");
    assert_eq!(
        keys(&settings),
        [
            "pinMode",
            "byoEndpoint",
            "byoKind",
            "byoCredentialStored",
            "keepLatestVersions",
            "binRetentionDays",
            "origin",
        ]
    );
    assert_eq!(field(&settings, "pinMode"), JsValue::from_str("dual"));
    assert_eq!(field(&settings, "byoKind"), JsValue::from_str("psa"));
    assert_eq!(field(&settings, "byoCredentialStored"), JsValue::TRUE);
    assert_eq!(
        field(&settings, "keepLatestVersions").as_f64(),
        Some(f64::from(u32::MAX))
    );
    assert_eq!(field(&settings, "origin"), JsValue::from_str("resolved"));
    let quota = field(&bounded, "quota");
    assert_eq!(field(&quota, "usedBytes"), big(u64::MAX));
    assert_eq!(field(&quota, "limitBytes"), big(4096));
    assert_eq!(field(&bounded, "pendingReclaimBytes"), big(u64::MAX));
    let stall = rows(field(&bounded, "reclaimStalls")).get(0);
    assert_eq!(bytes(field(&stall, "node")), vec![9; 16]);
    assert_eq!(
        field(&stall, "reason"),
        JsValue::from_str("targetStillLive")
    );

    let unbounded = crossed(&view(RetentionPolicy::KeepAll, None));
    assert!(field(&field(&unbounded, "settings"), "keepLatestVersions").is_null());
    assert!(field(&unbounded, "quota").is_null());
}

/// A list read crosses as an array of rows, an absent field as `null`.
#[wasm_bindgen_test]
fn the_account_lists_cross_as_arrays_of_rows() {
    let methods = rows(crossed(&[AuthMethod {
        id: "m1".into(),
        kind: AuthMethodKind::Unknown,
        identifier_display: None,
        created_at: "2026-01-01T00:00:00Z".into(),
        last_used_at: None,
    }]));
    let method = methods.get(0);
    assert_eq!(
        keys(&method),
        ["id", "kind", "identifierDisplay", "createdAt", "lastUsedAt",]
    );
    assert_eq!(field(&method, "kind"), JsValue::from_str("unknown"));
    assert!(field(&method, "identifierDisplay").is_null());

    let device = rows(crossed(&[RegisteredDevice {
        id: "d1".into(),
        public_key: "ab".into(),
        label: None,
        created_at: "2026-01-01T00:00:00Z".into(),
        last_seen_at: "2026-01-02T00:00:00Z".into(),
    }]))
    .get(0);
    assert_eq!(
        keys(&device),
        ["id", "publicKey", "label", "createdAt", "lastSeenAt"]
    );
    assert!(field(&device, "label").is_null());

    let approval = rows(crossed(&[PendingApprovalView {
        request_id: "r1".into(),
        requester_device_public_key: "ab".into(),
        ephemeral_public_key: "02cd".into(),
        comparison_value: "123456".into(),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2026-01-01T00:05:00Z".into(),
    }]))
    .get(0);
    assert_eq!(
        keys(&approval),
        [
            "requestId",
            "requesterDevicePublicKey",
            "ephemeralPublicKey",
            "comparisonValue",
            "createdAt",
            "expiresAt",
        ]
    );

    let version = rows(crossed(&[VersionEntry {
        content_cid: vec![0xC1],
        size: u64::MAX,
        modified_at: 7,
    }]))
    .get(0);
    assert_eq!(keys(&version), ["contentCid", "size", "modifiedAt"]);
    assert_eq!(bytes(field(&version, "contentCid")), vec![0xC1]);
    assert_eq!(field(&version, "size"), big(u64::MAX));
    assert_eq!(field(&version, "modifiedAt"), big(7));

    assert_eq!(rows(crossed::<[VersionEntry]>(&[])).length(), 0);
}

/// An opened stream crosses as plain data: the handle a `bigint`, the size a
/// number.
#[wasm_bindgen_test]
fn an_opened_stream_crosses_as_its_handle_and_size() {
    let opened = crossed(&OpenedStream::new(u64::MAX, 4096.0));
    assert_eq!(keys(&opened), ["handle", "size"]);
    assert_eq!(field(&opened, "handle"), big(u64::MAX));
    assert_eq!(field(&opened, "size"), JsValue::from(4096.0));
}
