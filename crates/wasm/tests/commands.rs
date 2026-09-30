//! The facade command decode at the WASM boundary (wasm32-unknown-unknown,
//! under wasm-bindgen-test-runner → Node.js): the shape tsify types for TS,
//! the fail-closed refusals, and the zeroizing path of the two commands that
//! carry a secret.
#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use cipherbox_engine::content::{ByoBearer, ByoKind};
use cipherbox_engine::facade::{Command, NodeId, NodeKind, Permission};
use cipherbox_engine::grants::MAX_FRAGMENT_TEXT_LEN;
use cipherbox_engine::seams::{OpId, UnixMillis};
use cipherbox_engine::settings::MAX_BIN_RETENTION_DAYS;
use cipherbox_engine::{PinMode, RetentionPolicy};
use cipherbox_wasm::boundary::decode_command;
use js_sys::{BigInt, Object, Reflect, Uint8Array};
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

const BEARER: &[u8] = b"s3cret-token";
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

fn node(fill: u8) -> JsValue {
    bytes(&[fill; 16])
}

fn buffer(value: &[u8]) -> JsValue {
    Uint8Array::from(value).buffer().into()
}

fn text(value: &str) -> JsValue {
    JsValue::from_str(value)
}

fn settings_command(access_token: JsValue) -> JsValue {
    object(&[
        ("kind", text("saveVaultSettings")),
        (
            "settings",
            object(&[
                ("pinMode", text("dual")),
                (
                    "byo",
                    object(&[
                        ("endpoint", text("https://kubo.example")),
                        ("kind", text("kubo")),
                        ("accessToken", access_token),
                    ]),
                ),
                ("keepLatestVersions", JsValue::from(3)),
                ("binRetentionDays", JsValue::from(30)),
            ]),
        ),
    ])
}

/// A `saveVaultSettings` on the hosted pin mode with no provider, plus `extra`.
fn hosted_settings(extra: &[(&str, JsValue)]) -> JsValue {
    let mut fields = vec![("pinMode", text("hosted")), ("byo", JsValue::NULL)];
    fields.extend(extra.iter().cloned());
    object(&[
        ("kind", text("saveVaultSettings")),
        ("settings", object(&fields)),
    ])
}

fn bearer_of(command: Command) -> ByoBearer {
    match command {
        Command::SaveVaultSettings { settings } => {
            settings
                .byo
                .expect("the command names a provider")
                .access_token
        }
        other => panic!("decoded {other:?}"),
    }
}

#[wasm_bindgen_test]
fn a_command_decodes_from_its_generated_shape() {
    let create = object(&[
        ("kind", text("create")),
        ("parent", node(1)),
        ("name", text("photo.jpg")),
        ("nodeKind", text("file")),
    ]);
    assert!(
        decode_command(&create).unwrap()
            == Command::Create {
                parent: NodeId([1; 16]),
                name: "photo.jpg".into(),
                kind: NodeKind::File,
            }
    );

    let grant = object(&[
        ("kind", text("grant")),
        ("node", node(2)),
        ("recipientIdentityPublicKey", bytes(&[0xab; 33])),
        ("permission", text("write")),
        ("granteeName", JsValue::NULL),
    ]);
    assert!(
        decode_command(&grant).unwrap()
            == Command::Grant {
                node: NodeId([2; 16]),
                recipient_identity_public_key: vec![0xab; 33],
                permission: Permission::Write,
                grantee_name: None,
            }
    );

    let restore = object(&[
        ("kind", text("restore")),
        ("node", node(3)),
        ("into", JsValue::NULL),
    ]);
    assert!(
        decode_command(&restore).unwrap()
            == Command::Restore {
                node: NodeId([3; 16]),
                into: None,
            }
    );

    let manual = object(&[("kind", text("manualRefresh"))]);
    assert!(decode_command(&manual).unwrap() == Command::ManualRefresh);
}

fn mint(expires_at: JsValue, admission_cap: JsValue) -> JsValue {
    object(&[
        ("kind", text("createInviteLink")),
        ("node", node(4)),
        ("permission", text("read")),
        ("expiresAt", expires_at),
        ("ownerName", text("")),
        ("admissionCap", admission_cap),
    ])
}

/// A `u64` field takes a `bigint` in range alone: not a `number`, even a safe
/// integer one, and not a negative or an over-range `bigint`. A `number` field
/// refuses a `bigint`.
#[wasm_bindgen_test]
fn a_u64_takes_a_bigint_in_range_alone() {
    let cancel = |op_id: JsValue| object(&[("kind", text("cancelUpload")), ("opId", op_id)]);
    assert!(decode_command(&cancel(JsValue::from(5))).is_err());
    assert!(decode_command(&cancel(BigInt::from(-1).into())).is_err());
    assert!(decode_command(&cancel(BigInt::from(5u64).into())).is_ok());

    let past_u64: JsValue = BigInt::new(&text("18446744073709551616"))
        .expect("2^64 is a bigint")
        .into();
    for (expires_at, admission_cap) in [
        (past_u64, JsValue::NULL),
        (JsValue::from(1_700_000_000_000_f64), JsValue::NULL),
        (JsValue::NULL, JsValue::from(2.5)),
        (JsValue::NULL, JsValue::from(-1)),
        (JsValue::NULL, JsValue::from(3)),
        (JsValue::NULL, BigInt::from(-1).into()),
    ] {
        assert!(decode_command(&mint(expires_at, admission_cap)).is_err());
    }

    let with_retention = |keep: JsValue| hosted_settings(&[("keepLatestVersions", keep)]);
    assert!(decode_command(&with_retention(BigInt::from(3u64).into())).is_err());
    assert!(decode_command(&with_retention(JsValue::from(3))).is_ok());
}

/// A deadline at the epoch decodes, as a `u64` in range, and the engine refuses
/// it when it mints.
#[wasm_bindgen_test]
fn a_zero_deadline_decodes_for_the_engine_to_refuse() {
    assert!(
        decode_command(&mint(BigInt::from(0u64).into(), JsValue::NULL)).unwrap()
            == Command::CreateInviteLink {
                node: NodeId([4; 16]),
                permission: Permission::Read,
                expires_at: Some(UnixMillis(0)),
                owner_name: String::new(),
                admission_cap: None,
            }
    );
}

/// An op id and a deadline past 2^53 cross as the `bigint` the engine minted.
#[wasm_bindgen_test]
fn a_u64_decodes_from_a_bigint_whole() {
    let cancel = object(&[
        ("kind", text("cancelUpload")),
        ("opId", BigInt::from(u64::MAX).into()),
    ]);
    assert!(
        decode_command(&cancel).unwrap()
            == Command::CancelUpload {
                op_id: OpId(u64::MAX),
            }
    );

    let minted = mint(BigInt::from(u64::MAX).into(), BigInt::from(5u64).into());
    assert!(
        decode_command(&minted).unwrap()
            == Command::CreateInviteLink {
                node: NodeId([4; 16]),
                permission: Permission::Read,
                expires_at: Some(UnixMillis(u64::MAX)),
                owner_name: String::new(),
                admission_cap: Some(5),
            }
    );
}

#[wasm_bindgen_test]
fn an_unknown_kind_is_refused() {
    for kind in ["format", "Create", ""] {
        assert!(
            decode_command(&object(&[("kind", text(kind))])).is_err(),
            "{kind}"
        );
    }
    assert!(decode_command(&object(&[])).is_err());
    assert!(decode_command(&text("manualRefresh")).is_err());
    assert!(decode_command(&JsValue::NULL).is_err());
}

#[wasm_bindgen_test]
fn an_unknown_field_is_refused() {
    let rename = object(&[
        ("kind", text("rename")),
        ("node", node(1)),
        ("newName", text("b.txt")),
        ("force", JsValue::TRUE),
    ]);
    assert!(decode_command(&rename).is_err());

    for kind in ["manualRefresh", "logout", "forgetDevice"] {
        let bare = object(&[("kind", text(kind)), ("force", JsValue::TRUE)]);
        assert!(decode_command(&bare).is_err(), "{kind}");
    }

    let claim = object(&[
        ("kind", text("claimInviteLink")),
        ("fragment", text(FRAGMENT)),
        ("name", text("")),
        ("force", JsValue::TRUE),
    ]);
    assert!(decode_command(&claim).is_err());

    let mut settings = settings_command(buffer(BEARER));
    let byo = Reflect::get(
        &Reflect::get(&settings, &text("settings")).unwrap(),
        &text("byo"),
    )
    .unwrap();
    Reflect::set(&byo, &text("keepAccessToken"), &JsValue::TRUE).unwrap();
    assert!(decode_command(&settings).is_err());

    settings = settings_command(JsValue::NULL);
    Reflect::set(&settings, &text("force"), &JsValue::TRUE).unwrap();
    assert!(decode_command(&settings).is_err());

    settings = settings_command(JsValue::NULL);
    let inner = Reflect::get(&settings, &text("settings")).unwrap();
    Reflect::set(&inner, &text("pinned"), &JsValue::TRUE).unwrap();
    assert!(decode_command(&settings).is_err());
}

/// No field is coerced into a plausible value of another type: not a number
/// into text, not text or a short buffer into a node id, not a truthy number
/// into a flag, and not an unknown literal into an enum.
#[wasm_bindgen_test]
fn a_field_of_the_wrong_type_is_refused() {
    let refused = [
        object(&[
            ("kind", text("rename")),
            ("node", node(1)),
            ("newName", JsValue::from(12345)),
        ]),
        object(&[("kind", text("delete")), ("node", bytes(&[1; 15]))]),
        object(&[("kind", text("delete")), ("node", text("0123456789abcdef"))]),
        object(&[
            ("kind", text("create")),
            ("parent", node(1)),
            ("name", text("a")),
            ("nodeKind", text("directory")),
        ]),
        object(&[
            ("kind", text("revokeInviteLink")),
            ("node", node(1)),
            ("linkTag", JsValue::NULL),
            ("removeGrantees", JsValue::from(1)),
        ]),
        object(&[
            ("kind", text("changePermission")),
            ("node", node(1)),
            ("recipientIdentityPublicKey", bytes(&[1; 33])),
            ("permission", text("admin")),
        ]),
        object(&[("kind", text("rename")), ("node", node(1))]),
    ];
    for (index, command) in refused.iter().enumerate() {
        assert!(decode_command(command).is_err(), "case {index}");
    }
}

#[wasm_bindgen_test]
fn a_claim_takes_its_fragment_verbatim() {
    let claim = object(&[
        ("kind", text("claimInviteLink")),
        ("fragment", text(FRAGMENT)),
        ("name", text("Ada")),
    ]);
    match decode_command(&claim).unwrap() {
        Command::ClaimInviteLink { fragment, name } => {
            assert!(fragment.as_str() == FRAGMENT);
            assert_eq!(name, "Ada");
        }
        other => panic!("decoded {other:?}"),
    }
}

/// The fragment limit: a fragment past the engine's own text bound is refused
/// before it is copied into linear memory.
#[wasm_bindgen_test]
fn a_fragment_past_the_engine_bound_is_refused() {
    let at_bound = object(&[
        ("kind", text("claimInviteLink")),
        ("fragment", text(&"A".repeat(MAX_FRAGMENT_TEXT_LEN))),
        ("name", text("")),
    ]);
    assert!(decode_command(&at_bound).is_ok());

    let past = object(&[
        ("kind", text("claimInviteLink")),
        ("fragment", text(&"A".repeat(MAX_FRAGMENT_TEXT_LEN + 1))),
        ("name", text("")),
    ]);
    assert!(decode_command(&past).is_err());

    let not_text = object(&[
        ("kind", text("claimInviteLink")),
        ("fragment", bytes(FRAGMENT.as_bytes())),
        ("name", text("")),
    ]);
    assert!(decode_command(&not_text).is_err());
}

/// The serde decode of a claim takes only the empty placeholder the boundary
/// puts in the fragment's place, so a claim cannot reach the engine by a path
/// that buffers its fragment and frees it without a wipe.
#[wasm_bindgen_test]
fn the_plain_serde_decode_refuses_a_real_fragment() {
    let claim = object(&[
        ("kind", text("claimInviteLink")),
        ("fragment", text(FRAGMENT)),
        ("name", text("")),
    ]);
    assert!(serde_wasm_bindgen::from_value::<Command>(claim).is_err());
}

/// The bearer is three-state: a transferred buffer sets it, `"keep"` keeps the
/// stored one, and `null` stores none.
#[wasm_bindgen_test]
fn a_settings_bearer_is_three_state() {
    let set = bearer_of(decode_command(&settings_command(buffer(BEARER))).unwrap());
    assert!(set.token().map(|token| token.as_bytes()) == Some(BEARER));

    let keep = bearer_of(decode_command(&settings_command(text("keep"))).unwrap());
    assert!(keep == ByoBearer::Keep);

    let none = bearer_of(decode_command(&settings_command(JsValue::NULL)).unwrap());
    assert!(none == ByoBearer::None);
}

/// The rest of the settings decode as the engine reads them.
#[wasm_bindgen_test]
fn the_settings_around_the_bearer_decode_whole() {
    match decode_command(&settings_command(buffer(BEARER))).unwrap() {
        Command::SaveVaultSettings { settings } => {
            assert_eq!(settings.pin_mode, PinMode::Dual);
            assert_eq!(
                settings.retention,
                RetentionPolicy::KeepLatest(3.try_into().unwrap())
            );
            assert_eq!(settings.bin_retention_days, 30);
            let byo = settings.byo.expect("a provider");
            assert_eq!(byo.endpoint, "https://kubo.example");
            assert_eq!(byo.kind, ByoKind::Kubo);
        }
        other => panic!("decoded {other:?}"),
    }
}

/// The bearer path leaves the caller's object as it was: the host realm, not
/// the decode, is the terminal owner of the buffer it transferred in.
#[wasm_bindgen_test]
fn the_bearer_path_leaves_the_callers_object_whole() {
    let token = buffer(BEARER);
    let command = settings_command(token.clone());
    decode_command(&command).unwrap();
    let byo = Reflect::get(
        &Reflect::get(&command, &text("settings")).unwrap(),
        &text("byo"),
    )
    .unwrap();
    assert!(Reflect::get(&byo, &text("accessToken")).unwrap() == token);
    assert_eq!(
        Uint8Array::new(&token).to_vec(),
        BEARER,
        "the decode copies the bearer and leaves the caller's buffer to the caller"
    );
}

/// A bearer as text, an unsendable one, a view rather than the transferred
/// buffer, and one that is no buffer at all are all refused. The host moves
/// and wipes an `ArrayBuffer` alone, so a view would reach here as a clone.
#[wasm_bindgen_test]
fn a_bearer_the_engine_would_refuse_is_refused() {
    for token in [
        text("s3cret-token"),
        buffer(b""),
        buffer(b"has space"),
        buffer(&[0xff, 0xfe]),
        bytes(BEARER),
        JsValue::from(7),
        object(&[]),
    ] {
        assert!(decode_command(&settings_command(token)).is_err());
    }
}

#[wasm_bindgen_test]
fn a_retention_the_engine_would_refuse_is_refused() {
    let with = |keep: JsValue, bin: JsValue| {
        hosted_settings(&[("keepLatestVersions", keep), ("binRetentionDays", bin)])
    };
    assert!(decode_command(&with(JsValue::from(0), JsValue::NULL)).is_err());
    assert!(
        decode_command(&with(
            JsValue::NULL,
            JsValue::from(MAX_BIN_RETENTION_DAYS + 1)
        ))
        .is_err()
    );
    assert!(decode_command(&with(JsValue::from(2_f64.powi(32) + 1.0), JsValue::NULL)).is_err());
    assert!(decode_command(&with(JsValue::NULL, JsValue::from(0))).is_ok());

    let absent = hosted_settings(&[("keepLatestVersions", JsValue::NULL)]);
    match decode_command(&absent).unwrap() {
        Command::SaveVaultSettings { settings } => {
            assert_eq!(settings.retention, RetentionPolicy::KeepAll);
            assert_eq!(
                settings.bin_retention_days,
                cipherbox_engine::settings::DEFAULT_BIN_RETENTION_DAYS
            );
        }
        other => panic!("decoded {other:?}"),
    }
}
