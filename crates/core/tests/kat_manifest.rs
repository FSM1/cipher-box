//! The KAT manifest job (blueprint/core.md "KAT regime", blueprint/testing.md
//! "crates/core — KATs and property tests"): merge-blocking, machine-checked.
//!
//! Fixtures are embedded with `include_str!` — never loaded from the
//! filesystem at runtime — so the same suite runs natively and under
//! wasm32-wasip1 (the residual parity surface). Vectors regenerate only
//! through the committed generator (`examples/kat_gen.rs`); the exact counts
//! and coverage lists here are the anti-vacuity backstop.

use std::collections::{BTreeMap, BTreeSet};

// On wasm32-unknown-unknown (the browser-shaped KAT leg) there is no libtest
// harness; wasm-bindgen-test provides one. Shadowing `test` with its attribute
// runs every `#[test]` below under wasm-bindgen-test-runner unchanged, while
// native and wasm32-wasip1 keep the built-in `#[test]`.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test as test;

use cipherbox_core::codec::{Map, Value, decode, decode_map_partial, encode, encode_map_partial};
use cipherbox_core::content::{
    CONTENT_CID_CODEC, CONTENT_CID_LEN, CONTENT_CID_MULTIHASH, compute_cid, decode_content_cid_str,
    encode_content_cid_str, open_chunk, seal_chunk, verify_cid,
};
use cipherbox_core::error::{Malformed, TrustViolation};
use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf::{self, EDGES, EdgeProbe};
use cipherbox_core::payload::mailbox::{
    MAILBOX_SIG_DOMAIN, mailbox_sig_preimage, open_mailbox_payload, seal_mailbox_payload,
};
use cipherbox_core::payload::pointer::{
    RepointObject, open_pointer_payload, repoint_preimage, seal_pointer_payload,
};
use cipherbox_core::seal::{
    self, AAD_DOMAIN, AadContext, BIN_INDEX_V, CONTENT_KEY_HPKE_INFO, CONTENT_KEY_V,
    CRITICAL_KEY_PREFIX, GRANT_SECTION_ENVELOPE_HEADROOM_BYTES, GrantLedgerEntry,
    GrantSetCommitment, GrantSetEntry, MAX_BIN_INDEX_BYTES, MAX_BLOCK_BYTES,
    MAX_CRITICAL_CARRIED_BYTES, MAX_GRANT_SECTION_BYTES, MAX_READ_SEALED_BYTES,
    MAX_WRITE_BODY_BYTES, NodeKind, OP_RECORD_HPKE_INFO, OP_RECORD_V, OWNER_LOCAL_HPKE_INFO_PREFIX,
    OWNER_LOCAL_V, OwnerLocalKind, Permission, PreservedFields,
    READ_SEALED_ENVELOPE_HEADROOM_BYTES, SETTINGS_RECORD_HPKE_INFO, SETTINGS_RECORD_V,
    STRUCT_TAG_ASCENT_LINK, STRUCT_TAG_BIN_INDEX, STRUCT_TAG_CONTENT_KEY, STRUCT_TAG_GRANT_BLOB,
    STRUCT_TAG_HISTORY_LINK, STRUCT_TAG_OP_RECORD, STRUCT_TAG_OWNER_BLOB, STRUCT_TAG_OWNER_LOCAL,
    STRUCT_TAG_OWNER_WRITE_BLOB, STRUCT_TAG_READ_BODY, STRUCT_TAG_SETTINGS_RECORD,
    STRUCT_TAG_WRITE_BODY, STRUCT_TAG_WRITE_HISTORY_LINK, STRUCT_TAGS, StructureSigInput,
    UNCUTTABLE_KEYS, WRITE_BODY_RESEAL_HEADROOM_BYTES, ascent_link_sig_body, build_aad,
    decode_ascent_link, decode_bin_index, decode_envelope, decode_grant_blob_payload,
    decode_grant_section, decode_grant_set_commitment, decode_history_link_payload,
    decode_op_record_header, decode_override_seed_payload, decode_owner_write_blob_payload,
    decode_read_body, decode_write_body, encode_ascent_link, encode_bin_index, encode_envelope,
    encode_grant_section, encode_grant_set_commitment, encode_override_seed_payload,
    encode_read_body, encode_recipient_binding, encode_write_body, open_ascent_link,
    open_bin_index, open_content_key, open_grant_blob, open_op_record, open_owner_blob,
    open_owner_history_link, open_owner_local, open_owner_write_blob, open_read_body,
    open_settings_record, seal_bin_index, seal_content_key, seal_op_record,
    seal_owner_history_link, seal_owner_local, seal_settings_record, structure_sig_preimage,
    verify_grant_set, verify_recipient_binding, verify_structure,
};
use cipherbox_core::suite::aead::{KEY_LEN, NONCE_LEN};
use cipherbox_core::suite::contact::{import_contact_code, subkey_binding_preimage};
use cipherbox_core::suite::ecdsa::{EcdsaSignature, EcdsaSigner, EcdsaVerifier};
use cipherbox_core::suite::ed25519::{Ed25519Signature, Ed25519Signer, Ed25519Verifier};
use cipherbox_core::suite::hash::hash;
use cipherbox_core::suite::hpke::{MODE_AUTH, hpke_open, hpke_seal};
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};
use serde::Deserialize;

const MANIFEST: &str = include_str!("../kat/manifest.json");

/// Every vector file the manifest may reference, embedded at compile time.
/// Path keys are manifest-relative (relative to `kat/`).
const FIXTURES: &[(&str, &str)] = &[
    (
        "vectors/codec/accept.json",
        include_str!("../kat/vectors/codec/accept.json"),
    ),
    (
        "vectors/codec/reject.json",
        include_str!("../kat/vectors/codec/reject.json"),
    ),
    (
        "vectors/codec/unknown_fields.json",
        include_str!("../kat/vectors/codec/unknown_fields.json"),
    ),
    (
        "vectors/kdf/edges.json",
        include_str!("../kat/vectors/kdf/edges.json"),
    ),
    (
        "vectors/hpke/seal.json",
        include_str!("../kat/vectors/hpke/seal.json"),
    ),
    (
        "vectors/hpke/open_reject.json",
        include_str!("../kat/vectors/hpke/open_reject.json"),
    ),
    (
        "vectors/contact/accept.json",
        include_str!("../kat/vectors/contact/accept.json"),
    ),
    (
        "vectors/contact/reject.json",
        include_str!("../kat/vectors/contact/reject.json"),
    ),
    (
        "vectors/seal/seal.json",
        include_str!("../kat/vectors/seal/seal.json"),
    ),
    (
        "vectors/seal/open_reject.json",
        include_str!("../kat/vectors/seal/open_reject.json"),
    ),
    (
        "vectors/seal/read_body_accept.json",
        include_str!("../kat/vectors/seal/read_body_accept.json"),
    ),
    (
        "vectors/seal/read_body_reject.json",
        include_str!("../kat/vectors/seal/read_body_reject.json"),
    ),
    (
        "vectors/seal/envelope_accept.json",
        include_str!("../kat/vectors/seal/envelope_accept.json"),
    ),
    (
        "vectors/seal/envelope_reject.json",
        include_str!("../kat/vectors/seal/envelope_reject.json"),
    ),
    (
        "vectors/ipns/name_accept.json",
        include_str!("../kat/vectors/ipns/name_accept.json"),
    ),
    (
        "vectors/ipns/name_reject.json",
        include_str!("../kat/vectors/ipns/name_reject.json"),
    ),
    (
        "vectors/ipns/record_accept.json",
        include_str!("../kat/vectors/ipns/record_accept.json"),
    ),
    (
        "vectors/ipns/record_reject.json",
        include_str!("../kat/vectors/ipns/record_reject.json"),
    ),
    (
        "vectors/ipns/record_reput.json",
        include_str!("../kat/vectors/ipns/record_reput.json"),
    ),
    (
        "vectors/payload/pointer_accept.json",
        include_str!("../kat/vectors/payload/pointer_accept.json"),
    ),
    (
        "vectors/payload/pointer_reject.json",
        include_str!("../kat/vectors/payload/pointer_reject.json"),
    ),
    (
        "vectors/payload/mailbox_accept.json",
        include_str!("../kat/vectors/payload/mailbox_accept.json"),
    ),
    (
        "vectors/payload/mailbox_reject.json",
        include_str!("../kat/vectors/payload/mailbox_reject.json"),
    ),
    (
        "vectors/grant/write_body_accept.json",
        include_str!("../kat/vectors/grant/write_body_accept.json"),
    ),
    (
        "vectors/grant/write_body_reject.json",
        include_str!("../kat/vectors/grant/write_body_reject.json"),
    ),
    (
        "vectors/grant/recipient_binding_accept.json",
        include_str!("../kat/vectors/grant/recipient_binding_accept.json"),
    ),
    (
        "vectors/grant/grant_blob_accept.json",
        include_str!("../kat/vectors/grant/grant_blob_accept.json"),
    ),
    (
        "vectors/grant/grant_blob_reject.json",
        include_str!("../kat/vectors/grant/grant_blob_reject.json"),
    ),
    (
        "vectors/grant/owner_blob_accept.json",
        include_str!("../kat/vectors/grant/owner_blob_accept.json"),
    ),
    (
        "vectors/grant/owner_blob_reject.json",
        include_str!("../kat/vectors/grant/owner_blob_reject.json"),
    ),
    (
        "vectors/grant/owner_write_blob_accept.json",
        include_str!("../kat/vectors/grant/owner_write_blob_accept.json"),
    ),
    (
        "vectors/grant/owner_write_blob_reject.json",
        include_str!("../kat/vectors/grant/owner_write_blob_reject.json"),
    ),
    (
        "vectors/grant/ascent_link_accept.json",
        include_str!("../kat/vectors/grant/ascent_link_accept.json"),
    ),
    (
        "vectors/grant/ascent_link_reject.json",
        include_str!("../kat/vectors/grant/ascent_link_reject.json"),
    ),
    (
        "vectors/grant/history_link_accept.json",
        include_str!("../kat/vectors/grant/history_link_accept.json"),
    ),
    (
        "vectors/grant/history_link_reject.json",
        include_str!("../kat/vectors/grant/history_link_reject.json"),
    ),
    (
        "vectors/grant/write_history_link_accept.json",
        include_str!("../kat/vectors/grant/write_history_link_accept.json"),
    ),
    (
        "vectors/grant/write_history_link_reject.json",
        include_str!("../kat/vectors/grant/write_history_link_reject.json"),
    ),
    (
        "vectors/grant/structure_sig_accept.json",
        include_str!("../kat/vectors/grant/structure_sig_accept.json"),
    ),
    (
        "vectors/grant/structure_sig_reject.json",
        include_str!("../kat/vectors/grant/structure_sig_reject.json"),
    ),
    (
        "vectors/grant/grant_set_accept.json",
        include_str!("../kat/vectors/grant/grant_set_accept.json"),
    ),
    (
        "vectors/grant/grant_set_reject.json",
        include_str!("../kat/vectors/grant/grant_set_reject.json"),
    ),
    (
        "vectors/grant/section_accept.json",
        include_str!("../kat/vectors/grant/section_accept.json"),
    ),
    (
        "vectors/grant/section_reject.json",
        include_str!("../kat/vectors/grant/section_reject.json"),
    ),
    (
        "vectors/content/seal.json",
        include_str!("../kat/vectors/content/seal.json"),
    ),
    (
        "vectors/content/seal_reject.json",
        include_str!("../kat/vectors/content/seal_reject.json"),
    ),
    (
        "vectors/content/cid.json",
        include_str!("../kat/vectors/content/cid.json"),
    ),
    (
        "vectors/content/cid_reject.json",
        include_str!("../kat/vectors/content/cid_reject.json"),
    ),
    (
        "vectors/content/cid_str_accept.json",
        include_str!("../kat/vectors/content/cid_str_accept.json"),
    ),
    (
        "vectors/content/cid_str_reject.json",
        include_str!("../kat/vectors/content/cid_str_reject.json"),
    ),
    (
        "vectors/op_record/op_record_accept.json",
        include_str!("../kat/vectors/op_record/op_record_accept.json"),
    ),
    (
        "vectors/op_record/op_record_reject.json",
        include_str!("../kat/vectors/op_record/op_record_reject.json"),
    ),
    (
        "vectors/settings_record/settings_record_accept.json",
        include_str!("../kat/vectors/settings_record/settings_record_accept.json"),
    ),
    (
        "vectors/settings_record/settings_record_reject.json",
        include_str!("../kat/vectors/settings_record/settings_record_reject.json"),
    ),
    (
        "vectors/content_key/content_key_accept.json",
        include_str!("../kat/vectors/content_key/content_key_accept.json"),
    ),
    (
        "vectors/content_key/content_key_reject.json",
        include_str!("../kat/vectors/content_key/content_key_reject.json"),
    ),
    (
        "vectors/owner_local/owner_local_accept.json",
        include_str!("../kat/vectors/owner_local/owner_local_accept.json"),
    ),
    (
        "vectors/owner_local/owner_local_reject.json",
        include_str!("../kat/vectors/owner_local/owner_local_reject.json"),
    ),
    (
        "vectors/bin_index/bin_index_accept.json",
        include_str!("../kat/vectors/bin_index/bin_index_accept.json"),
    ),
    (
        "vectors/bin_index/bin_index_reject.json",
        include_str!("../kat/vectors/bin_index/bin_index_reject.json"),
    ),
];

// ---------------------------------------------------------------------------
// Manifest + vector file shapes. deny_unknown_fields: a field the schema does
// not know is a manifest drift, not a tolerance.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    manifest_version: u64,
    profile: String,
    codecs: Codecs,
    structure_tags: serde_json::Map<String, serde_json::Value>,
    kdf: KdfSection,
    suite: SuiteSection,
    seal: SealManifest,
    ipns: IpnsManifest,
    payload: PayloadManifest,
    grant: GrantManifest,
    content: ContentManifest,
    op_record: OpRecordManifest,
    settings_record: SettingsRecordManifest,
    content_key: ContentKeyManifest,
    owner_local: OwnerLocalManifest,
    bin_index: BinIndexManifest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BinIndexManifest {
    struct_tag: u8,
    v: u64,
    max_bytes: usize,
    accept: FileCount,
    reject: RejectSection,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BinIndexAcceptVector {
    name: String,
    seal_key: String,
    nonce: String,
    plaintext: String,
    record: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BinIndexRejectVector {
    name: String,
    seal_key: String,
    record: String,
    check: String,
    class: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnerLocalManifest {
    struct_tag: u8,
    v: u64,
    hpke_mode: u8,
    hpke_info_prefix: String,
    kinds: Vec<OwnerLocalKindSpec>,
    accept: FileCount,
    reject: RejectSection,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnerLocalKindSpec {
    name: String,
    discriminator: u8,
    hpke_info: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnerLocalAcceptVector {
    name: String,
    kind: String,
    owner_secret: String,
    owner_public: String,
    ephemeral_scalar: String,
    body: String,
    blob: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnerLocalRejectVector {
    name: String,
    kind: String,
    owner_secret: String,
    blob: String,
    check: String,
    class: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SettingsRecordManifest {
    struct_tag: u8,
    v: u64,
    hpke_mode: u8,
    hpke_info: String,
    accept: FileCount,
    reject: RejectSection,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SettingsRecordAcceptVector {
    name: String,
    owner_secret: String,
    owner_public: String,
    ephemeral_scalar: String,
    body: String,
    record: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SettingsRecordRejectVector {
    name: String,
    owner_secret: String,
    record: String,
    check: String,
    class: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContentKeyManifest {
    struct_tag: u8,
    v: u64,
    hpke_mode: u8,
    hpke_info: String,
    accept: FileCount,
    reject: RejectSection,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContentKeyAcceptVector {
    name: String,
    owner_secret: String,
    owner_public: String,
    ephemeral_scalar: String,
    scope: String,
    epoch: u64,
    content_cid: String,
    key: String,
    blob: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContentKeyRejectVector {
    name: String,
    owner_secret: String,
    scope: String,
    epoch: u64,
    content_cid: String,
    blob: String,
    check: String,
    class: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OpRecordManifest {
    struct_tag: u8,
    v: u64,
    hpke_mode: u8,
    hpke_info: String,
    accept: FileCount,
    reject: RejectSection,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OpRecordAcceptVector {
    name: String,
    owner_secret: String,
    owner_public: String,
    ephemeral_scalar: String,
    content_root_cid: Option<String>,
    body: String,
    record: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OpRecordRejectVector {
    name: String,
    owner_secret: String,
    record: String,
    keyless: bool,
    check: String,
    class: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContentManifest {
    cid_codec: u8,
    cid_multihash: u8,
    cid_len: usize,
    seal: FileCount,
    seal_reject: RejectSection,
    cid: FileCount,
    cid_reject: RejectSection,
    cid_str_accept: FileCount,
    cid_str_reject: RejectSection,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContentCidStrAcceptVector {
    name: String,
    cid: String,
    cid_str: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContentSealVector {
    name: String,
    key: String,
    nonce: String,
    plaintext: String,
    sealed: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContentSealRejectVector {
    name: String,
    key: String,
    sealed: String,
    check: String,
    class: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContentCidVector {
    name: String,
    codec: u8,
    sealed: String,
    cid: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContentCidRejectVector {
    name: String,
    cid: String,
    sealed: String,
    check: String,
    class: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IpnsManifest {
    name_accept: FileCount,
    name_reject: RejectSection,
    record_accept: FileCount,
    record_reject: RejectSection,
    record_reput: FileCount,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PayloadManifest {
    pointer_accept: FileCount,
    pointer_reject: RejectSection,
    mailbox_accept: FileCount,
    mailbox_reject: RejectSection,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NameAcceptVector {
    name: String,
    signer_seed: String,
    ipns_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TextRejectVector {
    name: String,
    text: String,
    check: String,
    class: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordAcceptVector {
    name: String,
    signer_seed: String,
    ipns_name: String,
    value: String,
    sequence: u64,
    ttl: u64,
    validity: String,
    record: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordRejectVector {
    name: String,
    ipns_name: String,
    record: String,
    check: String,
    class: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordReputVector {
    name: String,
    ipns_name: String,
    record: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PointerAcceptVector {
    name: String,
    pointer_read_key: String,
    nonce: String,
    v: u64,
    owner_scalar: String,
    scope_id: String,
    current_root_name: String,
    write_epoch: u64,
    min_read_epoch: u64,
    #[serde(default)]
    prev_root_name: Option<String>,
    sealed: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PointerRejectVector {
    name: String,
    pointer_read_key: String,
    v: u64,
    scope_id: String,
    owner_scalar: String,
    sealed: String,
    check: String,
    class: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MailboxAcceptVector {
    name: String,
    recipient_secret: String,
    recipient_public: String,
    ephemeral_scalar: String,
    v: u64,
    sender_scalar: String,
    payload: String,
    block: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MailboxRejectVector {
    name: String,
    recipient_secret: String,
    v: u64,
    block: String,
    check: String,
    class: String,
}

// --- Grant section schema --------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GrantManifest {
    write_body_struct_tag: u8,
    grant_blob_struct_tag: u8,
    owner_blob_struct_tag: u8,
    owner_write_blob_struct_tag: u8,
    ascent_link_struct_tag: u8,
    history_link_struct_tag: u8,
    write_history_link_struct_tag: u8,
    write_body_max_bytes: usize,
    write_body_reseal_headroom_bytes: usize,
    grant_section_max_bytes: usize,
    grant_section_envelope_headroom_bytes: usize,
    write_body_accept: FileCount,
    write_body_reject: RejectSection,
    recipient_binding_accept: FileCount,
    grant_blob_accept: FileCount,
    grant_blob_reject: RejectSection,
    owner_blob_accept: FileCount,
    owner_blob_reject: RejectSection,
    owner_write_blob_accept: FileCount,
    owner_write_blob_reject: RejectSection,
    ascent_link_accept: FileCount,
    ascent_link_reject: RejectSection,
    history_link_accept: FileCount,
    history_link_reject: RejectSection,
    write_history_link_accept: FileCount,
    write_history_link_reject: RejectSection,
    structure_sig_accept: FileCount,
    structure_sig_reject: RejectSection,
    grant_set_accept: FileCount,
    grant_set_reject: RejectSection,
    section_accept: FileCount,
    section_reject: RejectSection,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WriteBodyAcceptVector {
    name: String,
    hex: String,
    ledger_count: usize,
    child_scope_count: usize,
}

/// A recipient-binding accept vector: the frozen preimage the owner signs over
/// one grant-ledger row and their signature over it. `permission` and
/// `expiresAt` are absent because they are outside the preimage.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecipientBindingAcceptVector {
    name: String,
    owner_identity_pk: String,
    ipns_name: String,
    recipient_identity_pk: String,
    recipient_enc_pk: String,
    tag: String,
    preimage: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SectionAcceptVector {
    name: String,
    hex: String,
    grant_blob_count: usize,
    history_link_count: usize,
    has_ascent_link: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HpkeStructureVector {
    name: String,
    recipient_secret: String,
    recipient_public: String,
    ephemeral_scalar: String,
    v: u64,
    id: String,
    scope: String,
    epoch: u64,
    struct_tag: u8,
    aad: String,
    plaintext: String,
    enc: String,
    ciphertext: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AscentLinkAcceptVector {
    name: String,
    parent_node_seed: String,
    ephemeral_scalar: String,
    v: u64,
    id: String,
    scope: String,
    epoch: u64,
    struct_tag: u8,
    aad: String,
    plaintext: String,
    ascent_public: String,
    container: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AscentLinkRejectVector {
    name: String,
    parent_node_seed: String,
    v: u64,
    id: String,
    scope: String,
    epoch: u64,
    struct_tag: u8,
    container: String,
    check: String,
    class: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HistoryLinkAcceptVector {
    name: String,
    key: String,
    nonce: String,
    v: u64,
    id: String,
    scope: String,
    epoch: u64,
    struct_tag: u8,
    aad: String,
    plaintext: String,
    sealed: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StructureSigAcceptVector {
    name: String,
    signer_seed: String,
    verifier_pk: String,
    scope_id: String,
    epoch: u64,
    struct_tag: u8,
    recipient_tag: String,
    signed_bytes: String,
    ciphertext_hash: String,
    preimage: String,
    signature: String,
    #[serde(default)]
    ascent_binding: Option<AscentBinding>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AscentBinding {
    ascent_public: String,
    enc: String,
    ciphertext: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StructureSigRejectVector {
    name: String,
    verifier_pk: String,
    scope_id: String,
    epoch: u64,
    struct_tag: u8,
    recipient_tag: String,
    ciphertext_hash: String,
    signature: String,
    check: String,
    class: String,
    #[serde(default)]
    ascent_binding: Option<AscentBinding>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GrantSetAcceptVector {
    name: String,
    owner_identity_pk: String,
    commitment: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GrantSetRejectVector {
    name: String,
    owner_identity_pk: String,
    commitment: String,
    signature: String,
    check: String,
    class: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SealManifest {
    aad_domain: String,
    read_body_struct_tag: u8,
    critical_key_prefix: String,
    critical_carried_max_bytes: usize,
    uncuttable_keys: Vec<String>,
    envelope_max_bytes: usize,
    read_sealed_max_bytes: usize,
    read_sealed_envelope_headroom_bytes: usize,
    seal: FileCount,
    open_reject: RejectSection,
    read_body_accept: FileCount,
    read_body_reject: RejectSection,
    envelope_accept: FileCount,
    envelope_reject: RejectSection,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SealVector {
    name: String,
    key: String,
    nonce: String,
    v: u64,
    id: String,
    scope: String,
    epoch: u64,
    struct_tag: u8,
    plaintext: String,
    aad: String,
    sealed: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SealOpenRejectVector {
    name: String,
    key: String,
    sealed: String,
    v: u64,
    id: String,
    scope: String,
    epoch: u64,
    struct_tag: u8,
    check: String,
    class: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReadBodyAcceptVector {
    name: String,
    hex: String,
    kind: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EnvelopeAcceptVector {
    name: String,
    key: String,
    envelope: String,
    read_body: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KdfSection {
    file: String,
    count: usize,
    edges: Vec<EdgeRow>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EdgeRow {
    name: String,
    context: String,
    input_layout: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuiteSection {
    hpke: HpkeMeta,
    contact: ContactMeta,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HpkeMeta {
    kem_id: String,
    kdf_id: String,
    aead_id: String,
    seal_file: String,
    seal_count: usize,
    open_reject_file: String,
    open_reject_count: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContactMeta {
    accept: FileCount,
    reject: RejectSection,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileCount {
    file: String,
    count: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Codecs {
    #[serde(rename = "det-cbor")]
    det_cbor: DetCbor,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DetCbor {
    accept: AcceptSection,
    reject: RejectSection,
    unknown_fields: UnknownFieldsSection,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AcceptSection {
    file: String,
    count: usize,
    required_kinds: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectSection {
    file: String,
    count: usize,
    checks: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnknownFieldsSection {
    file: String,
    count: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptVector {
    name: String,
    hex: String,
    diag: String,
    kinds: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectVector {
    name: String,
    hex: String,
    check: String,
    class: String,
}

/// An HPKE-blob reject vector: a sealed grant/owner blob whose open must fail
/// closed (a tampered ciphertext or a struct-tag transplant). `structTag` is the
/// tag the opener uses — for a transplant it differs from the seal.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HpkeBlobRejectVector {
    name: String,
    recipient_secret: String,
    enc: String,
    v: u64,
    id: String,
    scope: String,
    epoch: u64,
    struct_tag: u8,
    ciphertext: String,
    check: String,
    class: String,
}

/// A grant/owner-blob reject vector: a plaintext-decode failure (`hex`) or an
/// HPKE-open failure (a sealed envelope). Discriminated on which fields are
/// present — a decode vector has `hex`, an HPKE vector has `enc`/`ciphertext`.
#[derive(Deserialize)]
#[serde(untagged)]
enum BlobRejectVector {
    Decode(RejectVector),
    HpkeOpen(HpkeBlobRejectVector),
}

impl BlobRejectVector {
    fn name(&self) -> &str {
        match self {
            Self::Decode(v) => &v.name,
            Self::HpkeOpen(v) => &v.name,
        }
    }

    fn check(&self) -> &str {
        match self {
            Self::Decode(v) => &v.check,
            Self::HpkeOpen(v) => &v.check,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UnknownVector {
    name: String,
    hex: String,
    known_keys: Vec<String>,
    expect_unknown_count: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KdfEdgesFile {
    probe: ProbeJson,
    edges: Vec<EdgeVector>,
    genesis_root_name: GenesisRootNameVector,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenesisRootNameVector {
    scope_id: String,
    ipns_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProbeJson {
    seed: String,
    id: String,
    struct_tag: u8,
    index: u64,
    ipns_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EdgeVector {
    name: String,
    context: String,
    input_layout: String,
    output: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HpkeSealVector {
    name: String,
    recipient_secret: String,
    recipient_public: String,
    ephemeral_scalar: String,
    info: String,
    aad: String,
    plaintext: String,
    enc: String,
    ciphertext: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HpkeOpenRejectVector {
    name: String,
    recipient_secret: String,
    enc: String,
    info: String,
    aad: String,
    ciphertext: String,
    check: String,
    class: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContactAcceptVector {
    name: String,
    hex: String,
    identity_pk: String,
    enc_subkey: String,
    binding_sig: String,
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

fn manifest() -> Manifest {
    serde_json::from_str(MANIFEST).expect("kat/manifest.json must match the manifest schema")
}

fn fixture(path: &str) -> &'static str {
    FIXTURES
        .iter()
        .find(|(p, _)| *p == path)
        .unwrap_or_else(|| panic!("manifest references {path}, which is not include_str!-embedded"))
        .1
}

fn accept_vectors(m: &Manifest) -> Vec<AcceptVector> {
    serde_json::from_str(fixture(&m.codecs.det_cbor.accept.file)).expect("accept.json shape")
}

fn reject_vectors(m: &Manifest) -> Vec<RejectVector> {
    serde_json::from_str(fixture(&m.codecs.det_cbor.reject.file)).expect("reject.json shape")
}

fn unknown_vectors(m: &Manifest) -> Vec<UnknownVector> {
    serde_json::from_str(fixture(&m.codecs.det_cbor.unknown_fields.file))
        .expect("unknown_fields.json shape")
}

fn kdf_edges_file(m: &Manifest) -> KdfEdgesFile {
    serde_json::from_str(fixture(&m.kdf.file)).expect("kdf edges.json shape")
}

fn hpke_seal_vectors(m: &Manifest) -> Vec<HpkeSealVector> {
    serde_json::from_str(fixture(&m.suite.hpke.seal_file)).expect("hpke seal.json shape")
}

fn hpke_open_reject_vectors(m: &Manifest) -> Vec<HpkeOpenRejectVector> {
    serde_json::from_str(fixture(&m.suite.hpke.open_reject_file))
        .expect("hpke open_reject.json shape")
}

fn contact_accept_vectors(m: &Manifest) -> Vec<ContactAcceptVector> {
    serde_json::from_str(fixture(&m.suite.contact.accept.file)).expect("contact accept.json shape")
}

fn contact_reject_vectors(m: &Manifest) -> Vec<RejectVector> {
    serde_json::from_str(fixture(&m.suite.contact.reject.file)).expect("contact reject.json shape")
}

fn seal_vectors(m: &Manifest) -> Vec<SealVector> {
    serde_json::from_str(fixture(&m.seal.seal.file)).expect("seal.json shape")
}

fn seal_open_reject_vectors(m: &Manifest) -> Vec<SealOpenRejectVector> {
    serde_json::from_str(fixture(&m.seal.open_reject.file)).expect("seal open_reject.json shape")
}

fn content_seal_vectors(m: &Manifest) -> Vec<ContentSealVector> {
    serde_json::from_str(fixture(&m.content.seal.file)).expect("content seal.json shape")
}

fn content_seal_reject_vectors(m: &Manifest) -> Vec<ContentSealRejectVector> {
    serde_json::from_str(fixture(&m.content.seal_reject.file))
        .expect("content seal_reject.json shape")
}

fn content_cid_vectors(m: &Manifest) -> Vec<ContentCidVector> {
    serde_json::from_str(fixture(&m.content.cid.file)).expect("content cid.json shape")
}

fn content_cid_reject_vectors(m: &Manifest) -> Vec<ContentCidRejectVector> {
    serde_json::from_str(fixture(&m.content.cid_reject.file))
        .expect("content cid_reject.json shape")
}

fn content_cid_str_accept_vectors(m: &Manifest) -> Vec<ContentCidStrAcceptVector> {
    serde_json::from_str(fixture(&m.content.cid_str_accept.file))
        .expect("content cid_str_accept.json shape")
}

fn content_cid_str_reject_vectors(m: &Manifest) -> Vec<TextRejectVector> {
    serde_json::from_str(fixture(&m.content.cid_str_reject.file))
        .expect("content cid_str_reject.json shape")
}

fn read_body_accept_vectors(m: &Manifest) -> Vec<ReadBodyAcceptVector> {
    serde_json::from_str(fixture(&m.seal.read_body_accept.file))
        .expect("read_body_accept.json shape")
}

fn read_body_reject_vectors(m: &Manifest) -> Vec<RejectVector> {
    serde_json::from_str(fixture(&m.seal.read_body_reject.file))
        .expect("read_body_reject.json shape")
}

fn envelope_accept_vectors(m: &Manifest) -> Vec<EnvelopeAcceptVector> {
    serde_json::from_str(fixture(&m.seal.envelope_accept.file)).expect("envelope_accept.json shape")
}

fn envelope_reject_vectors(m: &Manifest) -> Vec<RejectVector> {
    serde_json::from_str(fixture(&m.seal.envelope_reject.file)).expect("envelope_reject.json shape")
}

fn write_body_accept_vectors(m: &Manifest) -> Vec<WriteBodyAcceptVector> {
    serde_json::from_str(fixture(&m.grant.write_body_accept.file)).expect("write_body_accept shape")
}

fn write_body_reject_vectors(m: &Manifest) -> Vec<RejectVector> {
    serde_json::from_str(fixture(&m.grant.write_body_reject.file)).expect("write_body_reject shape")
}

fn recipient_binding_accept_vectors(m: &Manifest) -> Vec<RecipientBindingAcceptVector> {
    serde_json::from_str(fixture(&m.grant.recipient_binding_accept.file))
        .expect("recipient_binding_accept shape")
}

fn grant_blob_accept_vectors(m: &Manifest) -> Vec<HpkeStructureVector> {
    serde_json::from_str(fixture(&m.grant.grant_blob_accept.file)).expect("grant_blob_accept shape")
}

fn grant_blob_reject_vectors(m: &Manifest) -> Vec<BlobRejectVector> {
    serde_json::from_str(fixture(&m.grant.grant_blob_reject.file)).expect("grant_blob_reject shape")
}

fn owner_blob_accept_vectors(m: &Manifest) -> Vec<HpkeStructureVector> {
    serde_json::from_str(fixture(&m.grant.owner_blob_accept.file)).expect("owner_blob_accept shape")
}

fn owner_blob_reject_vectors(m: &Manifest) -> Vec<BlobRejectVector> {
    serde_json::from_str(fixture(&m.grant.owner_blob_reject.file)).expect("owner_blob_reject shape")
}

fn op_record_accept_vectors(m: &Manifest) -> Vec<OpRecordAcceptVector> {
    serde_json::from_str(fixture(&m.op_record.accept.file)).expect("op_record_accept shape")
}

fn op_record_reject_vectors(m: &Manifest) -> Vec<OpRecordRejectVector> {
    serde_json::from_str(fixture(&m.op_record.reject.file)).expect("op_record_reject shape")
}

fn settings_record_accept_vectors(m: &Manifest) -> Vec<SettingsRecordAcceptVector> {
    serde_json::from_str(fixture(&m.settings_record.accept.file))
        .expect("settings_record_accept shape")
}

fn settings_record_reject_vectors(m: &Manifest) -> Vec<SettingsRecordRejectVector> {
    serde_json::from_str(fixture(&m.settings_record.reject.file))
        .expect("settings_record_reject shape")
}

fn content_key_accept_vectors(m: &Manifest) -> Vec<ContentKeyAcceptVector> {
    serde_json::from_str(fixture(&m.content_key.accept.file)).expect("content_key_accept shape")
}

fn content_key_reject_vectors(m: &Manifest) -> Vec<ContentKeyRejectVector> {
    serde_json::from_str(fixture(&m.content_key.reject.file)).expect("content_key_reject shape")
}

fn owner_local_accept_vectors(m: &Manifest) -> Vec<OwnerLocalAcceptVector> {
    serde_json::from_str(fixture(&m.owner_local.accept.file)).expect("owner_local_accept shape")
}

fn owner_local_reject_vectors(m: &Manifest) -> Vec<OwnerLocalRejectVector> {
    serde_json::from_str(fixture(&m.owner_local.reject.file)).expect("owner_local_reject shape")
}

fn bin_index_accept_vectors(m: &Manifest) -> Vec<BinIndexAcceptVector> {
    serde_json::from_str(fixture(&m.bin_index.accept.file)).expect("bin_index_accept shape")
}

fn bin_index_reject_vectors(m: &Manifest) -> Vec<BinIndexRejectVector> {
    serde_json::from_str(fixture(&m.bin_index.reject.file)).expect("bin_index_reject shape")
}

/// The kind a vector names, or a failure — an unknown kind is manifest drift,
/// never a vector to skip.
fn owner_local_kind(name: &str) -> OwnerLocalKind {
    *OwnerLocalKind::ALL
        .iter()
        .find(|k| k.name() == name)
        .unwrap_or_else(|| panic!("owner-local vector names an unregistered kind {name}"))
}

fn owner_write_blob_accept_vectors(m: &Manifest) -> Vec<HpkeStructureVector> {
    serde_json::from_str(fixture(&m.grant.owner_write_blob_accept.file))
        .expect("owner_write_blob_accept shape")
}

fn owner_write_blob_reject_vectors(m: &Manifest) -> Vec<BlobRejectVector> {
    serde_json::from_str(fixture(&m.grant.owner_write_blob_reject.file))
        .expect("owner_write_blob_reject shape")
}

fn ascent_link_accept_vectors(m: &Manifest) -> Vec<AscentLinkAcceptVector> {
    serde_json::from_str(fixture(&m.grant.ascent_link_accept.file))
        .expect("ascent_link_accept shape")
}

fn ascent_link_reject_vectors(m: &Manifest) -> Vec<AscentLinkRejectVector> {
    serde_json::from_str(fixture(&m.grant.ascent_link_reject.file))
        .expect("ascent_link_reject shape")
}

fn history_link_accept_vectors(m: &Manifest) -> Vec<HistoryLinkAcceptVector> {
    serde_json::from_str(fixture(&m.grant.history_link_accept.file))
        .expect("history_link_accept shape")
}

fn history_link_reject_vectors(m: &Manifest) -> Vec<RejectVector> {
    serde_json::from_str(fixture(&m.grant.history_link_reject.file))
        .expect("history_link_reject shape")
}

fn write_history_link_accept_vectors(m: &Manifest) -> Vec<HpkeStructureVector> {
    serde_json::from_str(fixture(&m.grant.write_history_link_accept.file))
        .expect("write_history_link_accept shape")
}

fn write_history_link_reject_vectors(m: &Manifest) -> Vec<BlobRejectVector> {
    serde_json::from_str(fixture(&m.grant.write_history_link_reject.file))
        .expect("write_history_link_reject shape")
}

fn structure_sig_accept_vectors(m: &Manifest) -> Vec<StructureSigAcceptVector> {
    serde_json::from_str(fixture(&m.grant.structure_sig_accept.file))
        .expect("structure_sig_accept shape")
}

fn structure_sig_reject_vectors(m: &Manifest) -> Vec<StructureSigRejectVector> {
    serde_json::from_str(fixture(&m.grant.structure_sig_reject.file))
        .expect("structure_sig_reject shape")
}

fn grant_set_accept_vectors(m: &Manifest) -> Vec<GrantSetAcceptVector> {
    serde_json::from_str(fixture(&m.grant.grant_set_accept.file)).expect("grant_set_accept shape")
}

fn grant_set_reject_vectors(m: &Manifest) -> Vec<GrantSetRejectVector> {
    serde_json::from_str(fixture(&m.grant.grant_set_reject.file)).expect("grant_set_reject shape")
}

fn section_accept_vectors(m: &Manifest) -> Vec<SectionAcceptVector> {
    serde_json::from_str(fixture(&m.grant.section_accept.file)).expect("section_accept shape")
}

fn section_reject_vectors(m: &Manifest) -> Vec<RejectVector> {
    serde_json::from_str(fixture(&m.grant.section_reject.file)).expect("section_reject shape")
}

fn unhex(name: &str, hex: &str) -> Vec<u8> {
    let bytes = hex::decode(hex).unwrap_or_else(|e| panic!("vector {name}: bad hex: {e}"));
    // Lowercase hex is part of the fixture contract.
    assert_eq!(
        hex::encode(&bytes),
        hex,
        "vector {name}: hex must be lowercase"
    );
    bytes
}

fn unhex_n<const N: usize>(name: &str, hex: &str) -> [u8; N] {
    unhex(name, hex)
        .try_into()
        .unwrap_or_else(|_| panic!("vector {name}: expected {N} bytes"))
}

fn unhex32(name: &str, hex: &str) -> [u8; 32] {
    unhex_n::<32>(name, hex)
}

/// Rebuild an [`AadContext`] from a seal-vector's fields.
fn seal_ctx(name: &str, v: u64, id: &str, scope: &str, epoch: u64, struct_tag: u8) -> AadContext {
    AadContext {
        v,
        id: unhex_n::<16>(name, id),
        scope: unhex_n::<16>(name, scope),
        epoch,
        struct_tag,
    }
}

// ---------------------------------------------------------------------------
// Assertions.
// ---------------------------------------------------------------------------

#[test]
fn manifest_header_is_pinned() {
    let m = manifest();
    assert_eq!(m.manifest_version, 1);
    assert_eq!(m.profile, "cipherbox/v2 det-cbor");
}

#[test]
fn fixture_table_matches_manifest_files() {
    let m = manifest();
    let referenced = [
        m.codecs.det_cbor.accept.file.as_str(),
        m.codecs.det_cbor.reject.file.as_str(),
        m.codecs.det_cbor.unknown_fields.file.as_str(),
        m.kdf.file.as_str(),
        m.suite.hpke.seal_file.as_str(),
        m.suite.hpke.open_reject_file.as_str(),
        m.suite.contact.accept.file.as_str(),
        m.suite.contact.reject.file.as_str(),
        m.seal.seal.file.as_str(),
        m.seal.open_reject.file.as_str(),
        m.seal.read_body_accept.file.as_str(),
        m.seal.read_body_reject.file.as_str(),
        m.seal.envelope_accept.file.as_str(),
        m.seal.envelope_reject.file.as_str(),
        m.ipns.name_accept.file.as_str(),
        m.ipns.name_reject.file.as_str(),
        m.ipns.record_accept.file.as_str(),
        m.ipns.record_reject.file.as_str(),
        m.ipns.record_reput.file.as_str(),
        m.payload.pointer_accept.file.as_str(),
        m.payload.pointer_reject.file.as_str(),
        m.payload.mailbox_accept.file.as_str(),
        m.payload.mailbox_reject.file.as_str(),
        m.grant.write_body_accept.file.as_str(),
        m.grant.write_body_reject.file.as_str(),
        m.grant.recipient_binding_accept.file.as_str(),
        m.grant.grant_blob_accept.file.as_str(),
        m.grant.grant_blob_reject.file.as_str(),
        m.grant.owner_blob_accept.file.as_str(),
        m.grant.owner_blob_reject.file.as_str(),
        m.grant.owner_write_blob_accept.file.as_str(),
        m.grant.owner_write_blob_reject.file.as_str(),
        m.grant.ascent_link_accept.file.as_str(),
        m.grant.ascent_link_reject.file.as_str(),
        m.grant.history_link_accept.file.as_str(),
        m.grant.history_link_reject.file.as_str(),
        m.grant.write_history_link_accept.file.as_str(),
        m.grant.write_history_link_reject.file.as_str(),
        m.grant.structure_sig_accept.file.as_str(),
        m.grant.structure_sig_reject.file.as_str(),
        m.grant.grant_set_accept.file.as_str(),
        m.grant.grant_set_reject.file.as_str(),
        m.grant.section_accept.file.as_str(),
        m.grant.section_reject.file.as_str(),
        m.content.seal.file.as_str(),
        m.content.seal_reject.file.as_str(),
        m.content.cid.file.as_str(),
        m.content.cid_reject.file.as_str(),
        m.content.cid_str_accept.file.as_str(),
        m.content.cid_str_reject.file.as_str(),
        m.op_record.accept.file.as_str(),
        m.op_record.reject.file.as_str(),
        m.settings_record.accept.file.as_str(),
        m.settings_record.reject.file.as_str(),
        m.content_key.accept.file.as_str(),
        m.content_key.reject.file.as_str(),
        m.owner_local.accept.file.as_str(),
        m.owner_local.reject.file.as_str(),
        m.bin_index.accept.file.as_str(),
        m.bin_index.reject.file.as_str(),
    ];
    let referenced_set: BTreeSet<&str> = referenced.iter().copied().collect();
    assert_eq!(
        referenced_set.len(),
        referenced.len(),
        "manifest must not reference the same file twice"
    );
    let embedded: BTreeSet<&str> = FIXTURES.iter().map(|(p, _)| *p).collect();
    assert_eq!(
        referenced_set, embedded,
        "manifest files and include_str!-embedded fixtures must match 1:1"
    );
}

#[test]
fn vector_counts_are_exact() {
    let m = manifest();
    assert_eq!(
        accept_vectors(&m).len(),
        m.codecs.det_cbor.accept.count,
        "accept.json count drift"
    );
    assert_eq!(
        reject_vectors(&m).len(),
        m.codecs.det_cbor.reject.count,
        "reject.json count drift"
    );
    assert_eq!(
        unknown_vectors(&m).len(),
        m.codecs.det_cbor.unknown_fields.count,
        "unknown_fields.json count drift"
    );
}

#[test]
fn vector_names_are_unique_within_each_file() {
    let m = manifest();
    let mut seen = BTreeSet::new();
    for v in accept_vectors(&m) {
        assert!(
            seen.insert(v.name.clone()),
            "duplicate accept vector name {}",
            v.name
        );
    }
    seen.clear();
    for v in reject_vectors(&m) {
        assert!(
            seen.insert(v.name.clone()),
            "duplicate reject vector name {}",
            v.name
        );
    }
    seen.clear();
    for v in unknown_vectors(&m) {
        assert!(
            seen.insert(v.name.clone()),
            "duplicate unknown-field vector name {}",
            v.name
        );
    }
}

/// Which vector files carry HPKE ephemerals, and how many each pins — the
/// anti-vacuity anchor for the freshness check below. A family that stopped
/// emitting `ephemeralScalar` would drop out of a bare total silently; naming
/// the files makes it a failure that says which one went dark.
const HPKE_EPHEMERAL_FAMILIES: &[(&str, usize)] = &[
    ("vectors/content_key/content_key_accept.json", 2),
    ("vectors/grant/ascent_link_accept.json", 1),
    ("vectors/grant/grant_blob_accept.json", 2),
    ("vectors/grant/owner_blob_accept.json", 1),
    ("vectors/grant/owner_write_blob_accept.json", 1),
    ("vectors/hpke/seal.json", 3),
    ("vectors/op_record/op_record_accept.json", 2),
    ("vectors/owner_local/owner_local_accept.json", 6),
    ("vectors/payload/mailbox_accept.json", 2),
    ("vectors/settings_record/settings_record_accept.json", 2),
    ("vectors/grant/write_history_link_accept.json", 1),
];

/// Every `(vector name, ephemeral scalar)` a vector file pins, decoded, so the
/// repeat check compares scalars rather than their spelling. A vector carrying
/// no `ephemeralScalar` is skipped — that absence is how a file with no HPKE
/// ephemerals is recognised — but one that carries the field owes a 32-byte
/// scalar, which [`unhex32`] enforces along with the lowercase-hex contract.
fn ephemeral_scalars(body: &str, path: &str) -> Vec<(String, [u8; 32])> {
    let parsed: serde_json::Value =
        serde_json::from_str(body).unwrap_or_else(|e| panic!("{path}: not JSON ({e})"));
    parsed
        .as_array()
        .into_iter()
        .flatten()
        .filter(|vector| vector.get("ephemeralScalar").is_some())
        .map(|vector| {
            let name = vector.get("name").and_then(|n| n.as_str()).unwrap_or(path);
            let scalar = vector["ephemeralScalar"]
                .as_str()
                .unwrap_or_else(|| panic!("{path}: vector {name} spells no ephemeralScalar"));
            (name.to_owned(), unhex32(name, scalar))
        })
        .collect()
}

/// HPKE ephemeral reuse under one recipient key and one `info` is a
/// confidentiality break (`seal::seal_owner_local`). A vector file is a superset
/// of each `(recipient, info)` group inside it, so per-file uniqueness forbids
/// every real repeat, plus some harmless ones.
///
/// Deliberately not corpus-wide: separate families may reuse a scalar under one
/// recipient and *different* `info` values, which the key schedule separates.
/// Only a regenerated corpus could introduce a real repeat.
#[test]
fn ephemeral_scalars_are_fresh_within_each_vector_file() {
    let mut pinned = BTreeMap::new();
    for (path, body) in FIXTURES {
        let found = ephemeral_scalars(body, path);
        if found.is_empty() {
            continue;
        }
        pinned.insert(*path, found.len());
        let mut seen = BTreeSet::new();
        for (name, scalar) in found {
            assert!(
                seen.insert(scalar),
                "{path}: vector {name} repeats another vector's ephemeral scalar"
            );
        }
    }
    let expected: BTreeMap<&str, usize> = HPKE_EPHEMERAL_FAMILIES.iter().copied().collect();
    assert_eq!(pinned, expected, "hpke ephemeral family coverage drift");
}

/// The codec's decode-reachable checks, fixed HERE as the anti-vacuity anchor
/// (mirrors kat_gen.rs). The suite/kdf checks live on the same error surface
/// but are pinned by the contact and hpke families, not the codec reject file.
const CODEC_DECODE_REACHABLE_CHECKS: &[&str] = &[
    "non-canonical-uint",
    "non-canonical-length",
    "indefinite-length",
    "unsorted-map-keys",
    "duplicate-map-key",
    "truncated",
    "trailing-bytes",
    "invalid-utf8",
    "invalid-map-key-type",
    "tag-forbidden",
    "float-forbidden",
    "simple-value-forbidden",
    "reserved-additional-info",
    "unexpected-break",
    "depth-exceeded",
];

#[test]
fn reject_checks_list_matches_vectors_and_error_surface() {
    let m = manifest();
    let listed: BTreeSet<&str> = m
        .codecs
        .det_cbor
        .reject
        .checks
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        listed.len(),
        m.codecs.det_cbor.reject.checks.len(),
        "manifest checks list must not contain duplicates"
    );

    let vectors = reject_vectors(&m);
    let in_vectors: BTreeSet<&str> = vectors.iter().map(|v| v.check.as_str()).collect();
    assert_eq!(
        listed, in_vectors,
        "manifest checks must be exactly the distinct checks in reject.json"
    );

    // The codec reject family covers exactly the decode-reachable codec checks
    // — fixed above, independent of the generator.
    let canonical: BTreeSet<&str> = CODEC_DECODE_REACHABLE_CHECKS.iter().copied().collect();
    assert_eq!(
        listed, canonical,
        "codec reject vectors must cover exactly the decode-reachable codec checks"
    );

    let surface: BTreeSet<&str> = TrustViolation::CHECKS
        .iter()
        .chain(Malformed::CHECKS)
        .copied()
        .collect();
    assert!(
        listed.is_subset(&surface),
        "every codec reject check must exist on the error surface"
    );
    // Every codec trust check is decode-reachable, hence vector-covered here.
    for check in [
        "non-canonical-uint",
        "non-canonical-length",
        "indefinite-length",
        "unsorted-map-keys",
        "duplicate-map-key",
    ] {
        assert!(listed.contains(check), "missing codec trust check {check}");
    }
}

/// The whole error surface is vector-pinned save the two checks `decode` and
/// the suite decoders can never emit — both encoder caller bugs, unit-test
/// pinned instead: `unknown-field-collision` (src/codec/fields.rs) and
/// `wiped-map` (src/codec/encode.rs). This is the crate-wide extension of the
/// reject-coverage law across the codec, contact, hpke, seal, ipns, and payload
/// families.
#[test]
fn every_crate_check_is_pinned_by_a_vector_family() {
    let m = manifest();
    let mut covered: BTreeSet<String> = BTreeSet::new();
    covered.extend(reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(contact_reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(hpke_open_reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(seal_open_reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(read_body_reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(envelope_reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(name_reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(record_reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(pointer_reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(mailbox_reject_vectors(&m).into_iter().map(|v| v.check));
    // Grant-family reject families.
    covered.extend(write_body_reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(
        grant_blob_reject_vectors(&m)
            .iter()
            .map(|v| v.check().to_string()),
    );
    covered.extend(
        owner_blob_reject_vectors(&m)
            .iter()
            .map(|v| v.check().to_string()),
    );
    covered.extend(
        owner_write_blob_reject_vectors(&m)
            .iter()
            .map(|v| v.check().to_string()),
    );
    covered.extend(history_link_reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(
        write_history_link_reject_vectors(&m)
            .into_iter()
            .map(|v| v.check().to_string()),
    );
    covered.extend(ascent_link_reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(
        structure_sig_reject_vectors(&m)
            .into_iter()
            .map(|v| v.check),
    );
    covered.extend(grant_set_reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(section_reject_vectors(&m).into_iter().map(|v| v.check));
    // Content plane: the content-open and content-CID reject families pin
    // `seal-open-failed`/`truncated` and `content-cid-mismatch`.
    covered.extend(content_seal_reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(content_cid_reject_vectors(&m).into_iter().map(|v| v.check));
    // The content-CID string codec's strict decode pins `content-cid-str-malformed`.
    covered.extend(
        content_cid_str_reject_vectors(&m)
            .into_iter()
            .map(|v| v.check),
    );
    covered.extend(op_record_reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(
        settings_record_reject_vectors(&m)
            .into_iter()
            .map(|v| v.check),
    );
    covered.extend(content_key_reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(owner_local_reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(bin_index_reject_vectors(&m).into_iter().map(|v| v.check));

    let surface: BTreeSet<String> = TrustViolation::CHECKS
        .iter()
        .chain(Malformed::CHECKS)
        .map(|s| s.to_string())
        .collect();
    let uncovered: Vec<&String> = surface.difference(&covered).collect();
    let expected_uncovered = [
        "unknown-field-collision".to_string(),
        "wiped-map".to_string(),
    ];
    assert_eq!(
        uncovered,
        expected_uncovered.iter().collect::<Vec<_>>(),
        "every crate check but the unit-pinned encoder caller-bug checks must have a reject vector"
    );
    assert!(
        covered.is_subset(&surface),
        "every reject-vector check must exist on the error surface"
    );
}

#[test]
fn accept_kinds_cover_required_kinds_exactly() {
    let m = manifest();
    let required: BTreeSet<&str> = m
        .codecs
        .det_cbor
        .accept
        .required_kinds
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        required.len(),
        m.codecs.det_cbor.accept.required_kinds.len(),
        "requiredKinds must not contain duplicates"
    );

    // The canonical kind list is fixed HERE, independent of the generator —
    // the accept-side anchor mirroring how reject checks anchor to the error
    // surface. Dropping an accept vector (and its kind) from kat_gen must
    // fail this test, never silently shrink coverage.
    const ALL_KINDS: &[&str] = &[
        "uint",
        "negint",
        "bytes",
        "text",
        "array",
        "map",
        "bool",
        "null",
        "depth-limit",
    ];
    let canonical: BTreeSet<&str> = ALL_KINDS.iter().copied().collect();
    assert_eq!(
        required, canonical,
        "requiredKinds must be exactly the canonical kind list"
    );

    let vectors = accept_vectors(&m);
    for kind in &required {
        assert!(
            vectors.iter().any(|v| v.kinds.iter().any(|k| k == kind)),
            "required kind {kind} has no accept vector"
        );
    }
    for v in &vectors {
        assert!(!v.kinds.is_empty(), "accept vector {} has no kinds", v.name);
        for k in &v.kinds {
            assert!(
                required.contains(k.as_str()),
                "accept vector {} has kind {k} outside requiredKinds",
                v.name
            );
        }
    }
}

#[test]
fn accept_vectors_decode_reencode_and_render_diag() {
    let m = manifest();
    for v in accept_vectors(&m) {
        let bytes = unhex(&v.name, &v.hex);
        let value = decode(&bytes)
            .unwrap_or_else(|e| panic!("accept vector {}: decoder rejected it: {e}", v.name));
        assert_eq!(
            hex::encode(encode(&value).unwrap()),
            v.hex,
            "accept vector {}: re-encode must be byte-identical",
            v.name
        );
        assert_eq!(
            value.to_diag(),
            v.diag,
            "accept vector {}: diagnostic-notation drift",
            v.name
        );
    }
}

#[test]
fn reject_vectors_fire_the_named_check() {
    let m = manifest();
    for v in reject_vectors(&m) {
        let bytes = unhex(&v.name, &v.hex);
        let err = match decode(&bytes) {
            Err(e) => e,
            Ok(value) => panic!(
                "reject vector {}: decoder accepted it as {}",
                v.name,
                value.to_diag()
            ),
        };
        assert_eq!(
            err.check(),
            v.check,
            "reject vector {}: wrong check ({err})",
            v.name
        );
        assert_eq!(
            err.class(),
            v.class,
            "reject vector {}: wrong class ({err})",
            v.name
        );
    }
}

#[test]
fn reject_vector_class_matches_the_check_lists() {
    let m = manifest();
    for v in reject_vectors(&m) {
        let expected = if TrustViolation::CHECKS.contains(&v.check.as_str()) {
            "trust"
        } else if Malformed::CHECKS.contains(&v.check.as_str()) {
            "malformed"
        } else {
            panic!(
                "reject vector {}: check {} is on neither list",
                v.name, v.check
            )
        };
        assert_eq!(
            v.class, expected,
            "reject vector {}: class must match the list its check lives in",
            v.name
        );
    }
}

#[test]
fn unknown_field_vectors_round_trip_byte_stable() {
    let m = manifest();
    for v in unknown_vectors(&m) {
        let bytes = unhex(&v.name, &v.hex);
        let (known, unknown) =
            decode_map_partial(&bytes, |k| v.known_keys.iter().any(|kk| kk == k)).unwrap_or_else(
                |e| {
                    panic!(
                        "unknown-field vector {}: decode_map_partial failed: {e}",
                        v.name
                    )
                },
            );
        assert_eq!(
            unknown.len(),
            v.expect_unknown_count,
            "unknown-field vector {}: unknown count",
            v.name
        );
        // The known/unknown split must be exhaustive over the map.
        let full = decode(&bytes).expect("vector decodes as a full strict item");
        assert_eq!(
            known.len() + unknown.len(),
            full.as_map().expect("top-level map").len(),
            "unknown-field vector {}: split must cover every entry",
            v.name
        );
        let reencoded = encode_map_partial(&known, &unknown).unwrap_or_else(|e| {
            panic!(
                "unknown-field vector {}: encode_map_partial failed: {e}",
                v.name
            )
        });
        assert_eq!(
            hex::encode(reencoded),
            v.hex,
            "unknown-field vector {}: rewrite must be byte-stable",
            v.name
        );
    }
}

/// The canonical structure-tag name→byte registry, fixed HERE independent of
/// the crate's `STRUCT_TAGS` const and the generator — the anti-vacuity anchor
/// for the domain-separation registry (mirrors ALL_EDGE_NAMES for the KDF
/// catalog). Adding, renaming, or re-numbering a tag must fail a test, never
/// silently shift the byte-space.
const ALL_STRUCT_TAGS: &[(&str, u8)] = &[
    ("read-body", 1),
    ("write-body", 2),
    ("grant-blob", 3),
    ("owner-blob", 4),
    ("ascent-link", 5),
    ("history-link", 6),
    ("pointer-payload", 7),
    ("mailbox-payload", 8),
    ("owner-write-blob", 9),
    ("op-record", 10),
    ("settings-record", 11),
    ("content-key", 12),
    ("owner-local", 13),
    ("write-history-link", 14),
    ("bin-index", 15),
];

#[test]
fn structure_tag_registry_is_complete_and_frozen() {
    let m = manifest();

    // The crate STRUCT_TABLE, the canonical anchor, and the manifest all agree
    // name-for-byte, and the byte-space is exactly the frozen tag set.
    assert_eq!(
        STRUCT_TAGS.len(),
        ALL_STRUCT_TAGS.len(),
        "crate STRUCT_TAGS count drift"
    );
    assert_eq!(
        m.structure_tags.len(),
        ALL_STRUCT_TAGS.len(),
        "manifest structureTags count drift"
    );
    for (i, (name, tag)) in ALL_STRUCT_TAGS.iter().enumerate() {
        let crate_spec = &STRUCT_TAGS[i];
        assert_eq!(crate_spec.name, *name, "crate STRUCT_TAGS {i} name");
        assert_eq!(crate_spec.tag, *tag, "crate STRUCT_TAGS {name} byte");
        let manifest_tag = m
            .structure_tags
            .get(*name)
            .unwrap_or_else(|| panic!("manifest structureTags missing {name}"))
            .as_u64()
            .expect("tag byte is a number");
        assert_eq!(
            manifest_tag,
            u64::from(*tag),
            "manifest tag byte for {name}"
        );
    }

    // read-body is the tag this slice exercises with vectors.
    assert_eq!(
        m.seal.read_body_struct_tag, STRUCT_TAG_READ_BODY,
        "manifest readBodyStructTag must be the crate constant"
    );
    assert_eq!(STRUCT_TAG_READ_BODY, 1, "read-body is byte 1");
}

// ---------------------------------------------------------------------------
// Seal: the AAD domain, the full-envelope symmetric-seal KATs, the accept /
// reject vectors (AAD transplants, downgrade, truncation, duplicate-id /
// -ipnsName), and the read-body + envelope codecs.
// ---------------------------------------------------------------------------

#[test]
fn seal_aad_domain_is_frozen() {
    let m = manifest();
    assert_eq!(m.seal.aad_domain, AAD_DOMAIN, "AAD domain separator drift");
    assert_eq!(
        AAD_DOMAIN, "cipherbox/v2/aad",
        "AAD domain string is frozen"
    );
}

#[test]
fn seal_vectors_are_frozen_and_round_trip() {
    let m = manifest();
    let vectors = seal_vectors(&m);
    assert_eq!(vectors.len(), m.seal.seal.count, "seal count drift");
    assert!(!vectors.is_empty(), "seal family must not be empty");

    let mut names = BTreeSet::new();
    let mut saw_read_body = false;
    for v in &vectors {
        assert!(names.insert(v.name.clone()), "duplicate seal {}", v.name);
        let key = unhex32(&v.name, &v.key);
        let nonce = unhex_n::<NONCE_LEN>(&v.name, &v.nonce);
        let ctx = seal_ctx(&v.name, v.v, &v.id, &v.scope, v.epoch, v.struct_tag);
        let plaintext = unhex(&v.name, &v.plaintext);

        // The AAD layout is frozen, and the fixed key + nonce reproduce the
        // sealed blob byte-for-byte (blueprint/core.md fixed-parameter KAT).
        assert_eq!(
            hex::encode(build_aad(&ctx)),
            v.aad,
            "seal {}: aad drift",
            v.name
        );
        let sealed = seal::seal(&key, &nonce, &ctx, &plaintext);
        assert_eq!(
            hex::encode(&sealed),
            v.sealed,
            "seal {}: sealed drift",
            v.name
        );
        assert_eq!(
            &sealed[..NONCE_LEN],
            &nonce,
            "seal {}: nonce prefix",
            v.name
        );
        let opened = seal::unseal(&key, &ctx, &unhex(&v.name, &v.sealed))
            .unwrap_or_else(|e| panic!("seal {}: unseal must recover: {e}", v.name));
        assert_eq!(opened, plaintext, "seal {}: plaintext", v.name);

        if v.struct_tag == STRUCT_TAG_READ_BODY && !plaintext.is_empty() {
            // The read-body-tag plaintext is a decodable read-body.
            saw_read_body = true;
            let body = decode_read_body(&plaintext)
                .unwrap_or_else(|e| panic!("seal {}: read-body must decode: {e}", v.name));
            assert_eq!(
                encode_read_body(&body).unwrap(),
                plaintext,
                "seal {}: read-body stable",
                v.name
            );
        }
    }
    assert!(
        saw_read_body,
        "at least one seal vector exercises a read-body plaintext"
    );
}

#[test]
fn seal_open_reject_vectors_fail_closed() {
    let m = manifest();
    let vectors = seal_open_reject_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.seal.open_reject.count,
        "seal open-reject count drift"
    );
    assert!(
        !vectors.is_empty(),
        "seal open-reject family must not be empty"
    );

    // The manifest checks list is exactly the distinct checks in the file.
    let listed: BTreeSet<&str> = m
        .seal
        .open_reject
        .checks
        .iter()
        .map(String::as_str)
        .collect();
    let in_vectors: BTreeSet<&str> = vectors.iter().map(|v| v.check.as_str()).collect();
    assert_eq!(
        listed, in_vectors,
        "manifest checks vs seal open_reject.json"
    );
    // Anti-vacuity: the transplant/downgrade defence (seal-open-failed) and the
    // structural floor (truncated) are both covered.
    for required in ["seal-open-failed", "truncated"] {
        assert!(
            listed.contains(required),
            "seal open-reject must cover {required}"
        );
    }

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate seal open-reject {}",
            v.name
        );
        let key = unhex32(&v.name, &v.key);
        let ctx = seal_ctx(&v.name, v.v, &v.id, &v.scope, v.epoch, v.struct_tag);
        let err = seal::unseal(&key, &ctx, &unhex(&v.name, &v.sealed))
            .expect_err("seal open-reject must fail closed");
        assert_eq!(
            err.check(),
            v.check,
            "seal open-reject {}: check ({err})",
            v.name
        );
        assert_eq!(
            err.class(),
            v.class,
            "seal open-reject {}: class ({err})",
            v.name
        );
    }
}

#[test]
fn read_body_accept_vectors_decode_and_round_trip() {
    let m = manifest();
    let vectors = read_body_accept_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.seal.read_body_accept.count,
        "read-body accept count drift"
    );
    assert!(
        !vectors.is_empty(),
        "read-body accept family must not be empty"
    );

    let mut names = BTreeSet::new();
    let mut kinds = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate read-body accept {}",
            v.name
        );
        let bytes = unhex(&v.name, &v.hex);
        let body = decode_read_body(&bytes)
            .unwrap_or_else(|e| panic!("read-body accept {}: rejected: {e}", v.name));
        assert_eq!(
            hex::encode(encode_read_body(&body).unwrap()),
            v.hex,
            "read-body accept {}: re-encode must be byte-identical",
            v.name
        );
        let expected = match v.kind.as_str() {
            "folder" => NodeKind::Folder,
            "file" => NodeKind::File,
            other => panic!("read-body accept {}: bad kind {other}", v.name),
        };
        assert_eq!(body.kind(), expected, "read-body accept {}: kind", v.name);
        kinds.insert(v.kind.clone());
    }
    assert!(
        kinds.contains("folder") && kinds.contains("file"),
        "both kinds covered"
    );
}

#[test]
fn read_body_reject_vectors_fire_the_named_check() {
    let m = manifest();
    let vectors = read_body_reject_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.seal.read_body_reject.count,
        "read-body reject count drift"
    );

    let listed: BTreeSet<&str> = m
        .seal
        .read_body_reject
        .checks
        .iter()
        .map(String::as_str)
        .collect();
    let in_vectors: BTreeSet<&str> = vectors.iter().map(|v| v.check.as_str()).collect();
    assert_eq!(
        listed, in_vectors,
        "manifest checks vs read_body_reject.json"
    );
    // The uniqueness trust checks (#39 D7) and the structural checks are covered.
    for required in ["duplicate-id", "duplicate-ipns-name", "invalid-node-kind"] {
        assert!(
            listed.contains(required),
            "read-body reject must cover {required}"
        );
    }

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate read-body reject {}",
            v.name
        );
        let bytes = unhex(&v.name, &v.hex);
        let err = match decode_read_body(&bytes) {
            Err(e) => e,
            Ok(_) => panic!("read-body reject {}: decoder accepted it", v.name),
        };
        assert_eq!(
            err.check(),
            v.check,
            "read-body reject {}: check ({err})",
            v.name
        );
        assert_eq!(
            err.class(),
            v.class,
            "read-body reject {}: class ({err})",
            v.name
        );
    }
}

#[test]
fn envelope_accept_vectors_decode_open_and_round_trip() {
    let m = manifest();
    let vectors = envelope_accept_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.seal.envelope_accept.count,
        "envelope accept count drift"
    );
    assert!(
        !vectors.is_empty(),
        "envelope accept family must not be empty"
    );

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate envelope accept {}",
            v.name
        );
        let key = unhex32(&v.name, &v.key);
        let bytes = unhex(&v.name, &v.envelope);
        let env = decode_envelope(&bytes)
            .unwrap_or_else(|e| panic!("envelope accept {}: rejected: {e}", v.name));
        assert_eq!(
            hex::encode(encode_envelope(&env).unwrap()),
            v.envelope,
            "envelope accept {}: re-encode must be byte-identical",
            v.name
        );
        // The read-body opens under the frozen key and equals the frozen
        // plaintext (the full symmetric-seal path).
        let body = open_read_body(&env, &key)
            .unwrap_or_else(|e| panic!("envelope accept {}: open: {e}", v.name));
        assert_eq!(
            hex::encode(encode_read_body(&body).unwrap()),
            v.read_body,
            "envelope accept {}: opened read-body drift",
            v.name
        );
    }
}

#[test]
fn envelope_reject_vectors_fire_the_named_check() {
    let m = manifest();
    let vectors = envelope_reject_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.seal.envelope_reject.count,
        "envelope reject count drift"
    );

    let listed: BTreeSet<&str> = m
        .seal
        .envelope_reject
        .checks
        .iter()
        .map(String::as_str)
        .collect();
    let in_vectors: BTreeSet<&str> = vectors.iter().map(|v| v.check.as_str()).collect();
    assert_eq!(
        listed, in_vectors,
        "manifest checks vs envelope_reject.json"
    );

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate envelope reject {}",
            v.name
        );
        let bytes = unhex(&v.name, &v.hex);
        let err = match decode_envelope(&bytes) {
            Err(e) => e,
            Ok(_) => panic!("envelope reject {}: decoder accepted it", v.name),
        };
        assert_eq!(
            err.check(),
            v.check,
            "envelope reject {}: check ({err})",
            v.name
        );
        assert_eq!(
            err.class(),
            v.class,
            "envelope reject {}: class ({err})",
            v.name
        );
    }
}

// ---------------------------------------------------------------------------
// KDF edge catalog: the frozen edges, their contexts + layouts, the
// per-edge output freeze, and the mechanical separation KAT.
// ---------------------------------------------------------------------------

/// The canonical edge-name list, fixed HERE independent of the crate's `EDGES`
/// const and the generator — the anti-vacuity anchor for the catalog (mirrors
/// how ALL_KINDS anchors the accept side). Dropping or renaming an edge must
/// fail a test, never silently shrink the catalog.
const ALL_EDGE_NAMES: &[&str] = &[
    "node-seed",
    "read-key",
    "structure-key",
    "write-seed",
    "write-key",
    "ipns-keypair",
    "ascent-keypair",
    "enc-subkey",
    "blinded-tag",
    "owner-pseudonym-seed",
    "pseudonym-sign",
    "owner-pointer-seed",
    "scope-pointer",
    "pointer-read-key",
    "vault-pointer-index",
    "settings-ipns-keypair",
    "bin-index-ipns-keypair",
    "bin-index-seal-key",
    "bin-held-key",
    "genesis-read-scope-seed",
    "genesis-write-scope-seed",
];

#[test]
fn kdf_catalog_freezes_names_contexts_and_layouts() {
    let m = manifest();
    assert_eq!(m.kdf.count, ALL_EDGE_NAMES.len(), "kdf edge count drift");
    assert_eq!(m.kdf.edges.len(), m.kdf.count, "kdf edges list vs count");
    assert_eq!(EDGES.len(), ALL_EDGE_NAMES.len(), "crate EDGES count drift");

    let file = kdf_edges_file(&m);
    assert_eq!(file.edges.len(), m.kdf.count, "edges.json count drift");

    // Manifest rows, the crate EDGES const, the fixture rows, and the canonical
    // name list must all agree, edge by edge and in order.
    for (i, name) in ALL_EDGE_NAMES.iter().enumerate() {
        let expected_ctx = format!("cipherbox/v2/{name}");
        let man = &m.kdf.edges[i];
        let crate_edge = &EDGES[i];
        let fix = &file.edges[i];

        assert_eq!(man.name, *name, "manifest edge {i} name");
        assert_eq!(man.context, expected_ctx, "manifest edge {name} context");
        assert_eq!(crate_edge.name, *name, "crate EDGES {i} name");
        assert_eq!(
            crate_edge.context, expected_ctx,
            "crate EDGES {name} context"
        );
        assert_eq!(
            crate_edge.input_layout, man.input_layout,
            "layout drift {name}"
        );
        assert_eq!(fix.name, *name, "fixture edge {i} name");
        assert_eq!(fix.context, expected_ctx, "fixture edge {name} context");
        assert_eq!(
            fix.input_layout, man.input_layout,
            "fixture layout drift {name}"
        );
    }
}

#[test]
fn kdf_edge_outputs_are_frozen_and_pairwise_separated() {
    let m = manifest();
    let file = kdf_edges_file(&m);

    // Recompute every edge under the fixture's own probe inputs and check the
    // frozen output byte-for-byte — a BLAKE3 or dependency change moves these.
    let seed = unhex32("probe.seed", &file.probe.seed);
    let id: [u8; 16] = unhex("probe.id", &file.probe.id)
        .try_into()
        .expect("probe id is 16 bytes");
    let ipns_name = unhex("probe.ipnsName", &file.probe.ipns_name);
    let probe = EdgeProbe {
        seed: &seed,
        id: &id,
        struct_tag: file.probe.struct_tag,
        index: file.probe.index,
        ipns_name: &ipns_name,
    };
    let computed = kdf::edge_probe_outputs(&probe);
    assert_eq!(computed.len(), file.edges.len());
    for (c, f) in computed.iter().zip(&file.edges) {
        assert_eq!(c.name, f.name, "probe/fixture order mismatch");
        assert_eq!(
            hex::encode(c.output),
            f.output,
            "kdf edge {} output drift",
            f.name
        );
    }

    // Mechanical separation KAT over the whole table: no two edges share an
    // output for equal inputs.
    let outputs: BTreeSet<&str> = file.edges.iter().map(|e| e.output.as_str()).collect();
    assert_eq!(
        outputs.len(),
        file.edges.len(),
        "two KDF edges froze to the same output"
    );
}

// ---------------------------------------------------------------------------
// Identity-signature preimage separation (blueprint/core.md "KAT regime": the
// mechanical separation law, here over the signing preimages rather than the
// KDF edge table).
// ---------------------------------------------------------------------------

/// Every det-CBOR preimage the vault owner's secp256k1 identity key signs,
/// fixed HERE independent of the codecs — the anti-vacuity anchor (mirrors
/// ALL_EDGE_NAMES and ALL_STRUCT_TAGS). A new identity-signed structure must
/// redden this test until it is listed and proved separate from the rest.
const IDENTITY_SIGNED_PREIMAGES: &[&str] = &[
    "subkey-binding",
    "repoint-object",
    "mailbox-sender-sig",
    "grant-set-commitment",
    "recipient-binding",
];

/// What a preimage's own bytes say it is. A canonical det-CBOR byte string
/// decodes to exactly one value, so two families whose descriptors differ share
/// no preimage at all — which is what non-confusability means here.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum PreimageShape {
    /// A map, identified by its key set.
    Map(BTreeSet<String>),
    /// The one array family, identified by the domain string it leads with.
    DomainLedArray(String),
}

/// Read a family's descriptor back out of the bytes its own codec produced, so
/// a field added to a codec moves the descriptor without anything here changing.
fn preimage_shape(family: &str, bytes: &[u8]) -> PreimageShape {
    match decode(bytes) {
        Ok(Value::Map(m)) => PreimageShape::Map(
            m.entries()
                .iter()
                .map(|(k, _)| k.clone())
                .collect::<BTreeSet<String>>(),
        ),
        Ok(Value::Array(items)) => match items.first() {
            Some(Value::Text(domain)) => PreimageShape::DomainLedArray(domain.clone()),
            _ => panic!("{family}: an array preimage separates only by a leading domain string"),
        },
        Ok(_) => panic!("{family}: a signing preimage is a map or a domain-led array"),
        Err(e) => panic!("{family}: a signing preimage must be strict det-CBOR: {e:?}"),
    }
}

/// One preimage per family, built through the codecs the sign and verify paths
/// use. A family with an optional field contributes every key set it can emit,
/// since separation must hold for each.
fn identity_signed_preimages() -> Vec<(&'static str, Vec<Vec<u8>>)> {
    let owner = EcdsaSigner::from_scalar(&[0x11; 32]).expect("owner scalar");
    let recipient_identity = EcdsaSigner::from_scalar(&[0x12; 32]).expect("recipient scalar");
    let enc_subkey = X25519Secret::from_scalar([0x22; 32]).public();
    let scope_root = b"scope-root-ipns-name".to_vec();

    let repoint = |prev_root: Option<&str>| RepointObject {
        scope_id: [0x33; 16],
        current_root: IpnsName::parse(
            "k51qzi5uqu5dgutdk6i1ynyzgkqngpha5xpgia3a5qqp4jsh0u4csozksxel2r",
        )
        .expect("current root parses"),
        write_epoch: 7,
        min_read_epoch: 3,
        prev_root: prev_root.map(|n| IpnsName::parse(n).expect("prev root parses")),
    };

    let commitment = GrantSetCommitment {
        ipns_name: scope_root.clone(),
        owner_pseudonym_pk: [0x44; 32],
        entries: vec![GrantSetEntry::new([0x55; 32], Permission::Read, [0x66; 32])],
        unknown: PreservedFields::new(),
    };

    let ledger_entry = GrantLedgerEntry::new(
        recipient_identity.verifying_key().to_sec1(),
        enc_subkey.to_bytes(),
        Permission::Write,
        [0x55; 32],
        [0x77; 64],
    );

    vec![
        (
            "subkey-binding",
            vec![subkey_binding_preimage(&owner.verifying_key(), &enc_subkey)],
        ),
        (
            "repoint-object",
            vec![
                repoint_preimage(&repoint(None)),
                repoint_preimage(&repoint(Some(
                    "k51qzi5uqu5dh9ihj4p2v5sl3hxvznpq4mcz1x0d3n4a4y0mrxlj0jczlpqrbx",
                ))),
            ],
        ),
        (
            "mailbox-sender-sig",
            vec![mailbox_sig_preimage(
                1,
                &enc_subkey.to_bytes(),
                &owner.verifying_key().to_sec1(),
                b"mailbox payload",
            )],
        ),
        (
            "grant-set-commitment",
            vec![encode_grant_set_commitment(&commitment).expect("a commitment encodes")],
        ),
        (
            "recipient-binding",
            vec![encode_recipient_binding(&scope_root, &ledger_entry).expect("a binding encodes")],
        ),
    ]
}

/// The authority break this closes: one owner signature accepted as another
/// family's. Structural today — the key sets are disjoint and det-CBOR fixes the
/// head bytes — but nothing failed when a field addition collapsed two sets.
#[test]
fn identity_signed_preimages_are_pairwise_non_confusable() {
    let families = identity_signed_preimages();
    assert_eq!(
        families.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
        IDENTITY_SIGNED_PREIMAGES,
        "the built families must be exactly the anchored list, in order"
    );

    let shapes: Vec<(&str, PreimageShape)> = families
        .iter()
        .flat_map(|(name, variants)| {
            assert!(!variants.is_empty(), "{name}: a family with no preimage");
            variants
                .iter()
                .map(move |bytes| (*name, preimage_shape(name, bytes)))
        })
        .collect();

    // Several variants under one name is a claim that an optional field moves
    // that family's key set. If they collapse to one descriptor the field has
    // stopped being emitted and the extra variants test nothing.
    for (name, variants) in &families {
        if variants.len() > 1 {
            let distinct: BTreeSet<PreimageShape> = variants
                .iter()
                .map(|bytes| preimage_shape(name, bytes))
                .collect();
            assert_eq!(
                distinct.len(),
                variants.len(),
                "{name}: its optional fields no longer change the key set"
            );
        }
    }

    for (i, (a_name, a)) in shapes.iter().enumerate() {
        for (b_name, b) in shapes.iter().skip(i + 1) {
            if a_name == b_name {
                continue;
            }
            assert_ne!(
                a, b,
                "{a_name} and {b_name} share a preimage descriptor: \
                 an owner signature over one would verify as the other"
            );
            // Equality is not the whole hazard: a map family that preserves
            // unknown fields emits its own keys *plus* whatever it carries, so a
            // key set contained in another's is reachable by adding fields.
            if let (PreimageShape::Map(a_keys), PreimageShape::Map(b_keys)) = (a, b) {
                assert!(
                    !a_keys.is_subset(b_keys),
                    "{a_name}'s keys are contained in {b_name}'s: preserved unknown \
                     fields would let a {b_name} preimage present as a {a_name} one"
                );
                assert!(
                    !b_keys.is_subset(a_keys),
                    "{b_name}'s keys are contained in {a_name}'s: preserved unknown \
                     fields would let a {a_name} preimage present as a {b_name} one"
                );
            }
        }
    }

    // The array family separates on its domain string alone, so that string is
    // the whole of its separation and is pinned here.
    assert!(
        shapes
            .iter()
            .any(|(name, shape)| *name == "mailbox-sender-sig"
                && *shape == PreimageShape::DomainLedArray(MAILBOX_SIG_DOMAIN.to_string())),
        "the mailbox preimage must lead with its frozen domain string"
    );
}

/// ADR 0007's whole property, frozen as a name: one login secret mints one
/// genesis root, so the login secret → `genesis-write-scope-seed` → `write-seed`
/// → `ipns-keypair` chain must produce this exact `ipnsName`. A change anywhere
/// along it re-points every account's genesis root and fails here first.
#[test]
fn the_derived_genesis_root_name_is_frozen() {
    let file = kdf_edges_file(&manifest());
    let secret = unhex32("probe.seed", &file.probe.seed);
    let scope_id: [u8; 16] = unhex("genesisRootName.scopeId", &file.genesis_root_name.scope_id)
        .try_into()
        .expect("scope id is 16 bytes");
    // The vector is generated from the probe id. Anchoring it here is what stops
    // a scopeId and an ipnsName being edited together into a self-consistent
    // pair that freezes nothing.
    assert_eq!(
        file.genesis_root_name.scope_id, file.probe.id,
        "the genesis root vector must stand on the probe's own scope id",
    );

    let write_scope_seed = kdf::genesis_write_scope_seed(&secret);
    let name = IpnsName::from_public_key(
        &kdf::ipns_keypair(kdf::write_seed(write_scope_seed.as_bytes(), &scope_id).as_bytes())
            .verifying_key(),
    );
    assert_eq!(
        name.as_str(),
        file.genesis_root_name.ipns_name,
        "the derived genesis root name drifted",
    );
    // Twice from one secret, the same name — stated on the values, since it is
    // the reason a crashed mint's record is re-derivable rather than orphaned.
    assert_eq!(
        kdf::genesis_write_scope_seed(&secret).as_bytes(),
        write_scope_seed.as_bytes(),
    );
}

// ---------------------------------------------------------------------------
// HPKE: the fixed-ephemeral full-envelope KAT and the fail-closed open rejects.
// ---------------------------------------------------------------------------

#[test]
fn hpke_suite_ids_are_frozen() {
    let m = manifest();
    assert_eq!(
        m.suite.hpke.kem_id, "0x0020",
        "KEM = DHKEM(X25519, HKDF-SHA256)"
    );
    assert_eq!(m.suite.hpke.kdf_id, "0x0001", "KDF = HKDF-SHA256");
    assert_eq!(
        m.suite.hpke.aead_id, "0x8000",
        "AEAD = XChaCha20-Poly1305, CipherBox private-use id"
    );
}

#[test]
fn hpke_seal_vectors_are_frozen_and_open() {
    let m = manifest();
    let vectors = hpke_seal_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.suite.hpke.seal_count,
        "hpke seal count drift"
    );
    assert!(!vectors.is_empty(), "hpke seal family must not be empty");

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate hpke seal {}",
            v.name
        );
        let recipient_bytes = unhex32(&v.name, &v.recipient_public);
        let recipient_public = X25519Public::from_bytes(recipient_bytes)
            .expect("accept-vector recipient key is adoptable");
        assert_eq!(
            recipient_public.to_bytes(),
            recipient_bytes,
            "hpke seal {}: an adopted key re-encodes to the bytes it came from",
            v.name
        );
        let eph = unhex32(&v.name, &v.ephemeral_scalar);
        let info = unhex(&v.name, &v.info);
        let aad = unhex(&v.name, &v.aad);
        let plaintext = unhex(&v.name, &v.plaintext);

        // Fixed-ephemeral seal must reproduce the frozen enc + ciphertext.
        let sealed = hpke_seal(&recipient_public, &eph, &info, &aad, &plaintext);
        assert_eq!(
            hex::encode(sealed.enc),
            v.enc,
            "hpke seal {}: enc drift",
            v.name
        );
        assert_eq!(
            hex::encode(&sealed.ciphertext),
            v.ciphertext,
            "hpke seal {}: ciphertext drift",
            v.name
        );

        let recipient = X25519Secret::from_scalar(unhex32(&v.name, &v.recipient_secret));
        let enc = unhex32(&v.name, &v.enc);
        let opened = hpke_open(
            &recipient,
            &enc,
            &info,
            &aad,
            &unhex(&v.name, &v.ciphertext),
        )
        .unwrap_or_else(|_| panic!("hpke seal {}: open must recover plaintext", v.name));
        assert_eq!(
            &opened[..],
            &plaintext[..],
            "hpke seal {}: plaintext",
            v.name
        );
    }
}

#[test]
fn hpke_open_reject_vectors_fail_closed() {
    let m = manifest();
    let vectors = hpke_open_reject_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.suite.hpke.open_reject_count,
        "hpke open-reject count drift"
    );
    assert!(
        !vectors.is_empty(),
        "hpke open-reject family must not be empty"
    );

    for v in &vectors {
        // Both the tag-mismatch check and the low-order/non-contributory check
        // are trust violations the open path fails closed on.
        assert!(
            v.check == "hpke-open-failed" || v.check == "hpke-non-contributory",
            "open-reject {}: unexpected check {}",
            v.name,
            v.check
        );
        assert_eq!(v.class, "trust", "open-reject {}: class", v.name);
        let recipient = X25519Secret::from_scalar(unhex32(&v.name, &v.recipient_secret));
        let enc = unhex32(&v.name, &v.enc);
        let err = hpke_open(
            &recipient,
            &enc,
            &unhex(&v.name, &v.info),
            &unhex(&v.name, &v.aad),
            &unhex(&v.name, &v.ciphertext),
        )
        .expect_err("open-reject vector must fail closed");
        assert_eq!(err.check(), v.check, "open-reject {}", v.name);
    }
}

// ---------------------------------------------------------------------------
// Contact codes: accept vectors import + round-trip; reject vectors pin the
// structural checks and the mandatory fail-closed binding verify.
// ---------------------------------------------------------------------------

#[test]
fn contact_accept_vectors_import_and_round_trip() {
    let m = manifest();
    let vectors = contact_accept_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.suite.contact.accept.count,
        "contact accept count drift"
    );
    assert!(
        !vectors.is_empty(),
        "contact accept family must not be empty"
    );

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate contact accept {}",
            v.name
        );
        let bytes = unhex(&v.name, &v.hex);
        let code = import_contact_code(&bytes)
            .unwrap_or_else(|e| panic!("contact accept {}: must import: {e}", v.name));
        assert_eq!(
            hex::encode(code.encode()),
            v.hex,
            "contact accept {}: rewrite",
            v.name
        );
        assert_eq!(
            hex::encode(code.identity_pk().to_sec1()),
            v.identity_pk,
            "contact accept {}: identityPk",
            v.name
        );
        assert_eq!(
            hex::encode(code.enc_subkey().to_bytes()),
            v.enc_subkey,
            "contact accept {}: encSubkey",
            v.name
        );
        assert_eq!(
            hex::encode(code.binding_sig().to_compact()),
            v.binding_sig,
            "contact accept {}: bindingSig",
            v.name
        );
    }
}

#[test]
fn contact_reject_vectors_fire_the_named_check_and_class() {
    let m = manifest();
    let vectors = contact_reject_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.suite.contact.reject.count,
        "contact reject count drift"
    );

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate contact reject {}",
            v.name
        );
        let bytes = unhex(&v.name, &v.hex);
        let err = match import_contact_code(&bytes) {
            Err(e) => e,
            Ok(_) => panic!("contact reject {}: import accepted it", v.name),
        };
        assert_eq!(err.check(), v.check, "contact reject {}: check", v.name);
        assert_eq!(err.class(), v.class, "contact reject {}: class", v.name);
    }
}

#[test]
fn contact_reject_family_covers_the_binding_checks() {
    let m = manifest();
    // The manifest checks list is exactly the distinct checks in the file...
    let listed: BTreeSet<&str> = m
        .suite
        .contact
        .reject
        .checks
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        listed.len(),
        m.suite.contact.reject.checks.len(),
        "contact reject checks list must not contain duplicates"
    );
    let vectors = contact_reject_vectors(&m);
    let vector_checks: BTreeSet<String> = vectors.iter().map(|v| v.check.clone()).collect();
    let vector_checks_ref: BTreeSet<&str> = vector_checks.iter().map(String::as_str).collect();
    assert_eq!(
        listed, vector_checks_ref,
        "manifest checks vs contact reject.json"
    );

    // ...and it must include the mandatory binding-verify check plus every
    // structural contact check (anti-vacuity: fixed HERE).
    for required in [
        "subkey-binding-invalid",
        "missing-field",
        "invalid-identity-key",
        "invalid-enc-subkey",
        "invalid-binding-sig-encoding",
    ] {
        assert!(
            listed.contains(required),
            "contact rejects must cover {required}"
        );
    }
}

// ---------------------------------------------------------------------------
// IPNS records + name codec, and pointer + mailbox payloads. The name codec,
// the fixed-key injected-timestamp full-record KATs, the keyless byte-stable
// re-PUT, and the pointer/mailbox accept+reject vectors — all consumed from
// the manifest and asserted against the live modules.
// ---------------------------------------------------------------------------

fn name_accept_vectors(m: &Manifest) -> Vec<NameAcceptVector> {
    serde_json::from_str(fixture(&m.ipns.name_accept.file)).expect("name_accept.json shape")
}

fn name_reject_vectors(m: &Manifest) -> Vec<TextRejectVector> {
    serde_json::from_str(fixture(&m.ipns.name_reject.file)).expect("name_reject.json shape")
}

fn record_accept_vectors(m: &Manifest) -> Vec<RecordAcceptVector> {
    serde_json::from_str(fixture(&m.ipns.record_accept.file)).expect("record_accept.json shape")
}

fn record_reject_vectors(m: &Manifest) -> Vec<RecordRejectVector> {
    serde_json::from_str(fixture(&m.ipns.record_reject.file)).expect("record_reject.json shape")
}

fn record_reput_vectors(m: &Manifest) -> Vec<RecordReputVector> {
    serde_json::from_str(fixture(&m.ipns.record_reput.file)).expect("record_reput.json shape")
}

fn pointer_accept_vectors(m: &Manifest) -> Vec<PointerAcceptVector> {
    serde_json::from_str(fixture(&m.payload.pointer_accept.file))
        .expect("pointer_accept.json shape")
}

fn pointer_reject_vectors(m: &Manifest) -> Vec<PointerRejectVector> {
    serde_json::from_str(fixture(&m.payload.pointer_reject.file))
        .expect("pointer_reject.json shape")
}

fn mailbox_accept_vectors(m: &Manifest) -> Vec<MailboxAcceptVector> {
    serde_json::from_str(fixture(&m.payload.mailbox_accept.file))
        .expect("mailbox_accept.json shape")
}

fn mailbox_reject_vectors(m: &Manifest) -> Vec<MailboxRejectVector> {
    serde_json::from_str(fixture(&m.payload.mailbox_reject.file))
        .expect("mailbox_reject.json shape")
}

#[test]
fn ipns_name_accept_vectors_encode_and_parse() {
    let m = manifest();
    let vectors = name_accept_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.ipns.name_accept.count,
        "name-accept count drift"
    );
    assert!(!vectors.is_empty(), "name-accept family must not be empty");

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate name-accept {}",
            v.name
        );
        let key = Ed25519Signer::from_seed(unhex32(&v.name, &v.signer_seed)).verifying_key();
        assert_eq!(
            IpnsName::from_public_key(&key).as_str(),
            v.ipns_name,
            "name-accept {}: encode drift",
            v.name
        );
        // Strict decode: the pubkey comes from the name itself, byte-stable.
        let parsed = IpnsName::parse(&v.ipns_name)
            .unwrap_or_else(|e| panic!("name-accept {}: parse rejected: {e}", v.name));
        assert_eq!(
            parsed.public_key(),
            key,
            "name-accept {}: pubkey from name",
            v.name
        );
        assert_eq!(
            parsed.as_str(),
            v.ipns_name,
            "name-accept {}: byte-stable",
            v.name
        );
    }
}

#[test]
fn ipns_name_reject_vectors_fire_the_named_check() {
    let m = manifest();
    let vectors = name_reject_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.ipns.name_reject.count,
        "name-reject count drift"
    );

    let listed: BTreeSet<&str> = m
        .ipns
        .name_reject
        .checks
        .iter()
        .map(String::as_str)
        .collect();
    let in_vectors: BTreeSet<&str> = vectors.iter().map(|v| v.check.as_str()).collect();
    assert_eq!(listed, in_vectors, "manifest checks vs name_reject.json");
    assert!(
        listed.contains("ipns-name-malformed"),
        "name-reject covers ipns-name-malformed"
    );

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate name-reject {}",
            v.name
        );
        let err = IpnsName::parse(&v.text).expect_err("name-reject must fail closed");
        assert_eq!(
            err.check(),
            v.check,
            "name-reject {}: check ({err})",
            v.name
        );
        assert_eq!(
            err.class(),
            v.class,
            "name-reject {}: class ({err})",
            v.name
        );
    }
}

#[test]
fn ipns_record_accept_vectors_are_frozen_and_verify() {
    let m = manifest();
    let vectors = record_accept_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.ipns.record_accept.count,
        "record-accept count drift"
    );
    assert!(
        !vectors.is_empty(),
        "record-accept family must not be empty"
    );

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate record-accept {}",
            v.name
        );
        let signer = Ed25519Signer::from_seed(unhex32(&v.name, &v.signer_seed));
        let value = unhex(&v.name, &v.value);
        // Fixed key + injected timestamp: the full record bytes are frozen.
        let record =
            IpnsRecord::create_v2(&signer, &value, v.sequence, v.ttl, &v.validity).marshal();
        assert_eq!(
            hex::encode(&record),
            v.record,
            "record-accept {}: record bytes drift",
            v.name
        );
        let reparsed = IpnsRecord::unmarshal(&record)
            .unwrap_or_else(|e| panic!("record-accept {}: unmarshal: {e}", v.name));
        assert_eq!(
            reparsed.marshal(),
            record,
            "record-accept {}: re-PUT byte-stable",
            v.name
        );
        let name = IpnsName::parse(&v.ipns_name).expect("record-accept name parses");
        let verified = reparsed
            .verify(&name)
            .unwrap_or_else(|e| panic!("record-accept {}: verify: {e}", v.name));
        assert_eq!(verified.value, value, "record-accept {}: value", v.name);
        assert_eq!(
            verified.sequence, v.sequence,
            "record-accept {}: sequence",
            v.name
        );
        assert_eq!(verified.ttl, v.ttl, "record-accept {}: ttl", v.name);
        assert_eq!(
            verified.validity,
            v.validity.as_bytes(),
            "record-accept {}: validity",
            v.name
        );
    }
    // Anti-vacuity: a first-publish (sequence 1) record is frozen.
    assert!(
        vectors.iter().any(|v| v.sequence == 1),
        "a first-publish seq-1 record must be pinned"
    );
}

#[test]
fn ipns_record_reject_vectors_fire_the_named_check() {
    let m = manifest();
    let vectors = record_reject_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.ipns.record_reject.count,
        "record-reject count drift"
    );

    let listed: BTreeSet<&str> = m
        .ipns
        .record_reject
        .checks
        .iter()
        .map(String::as_str)
        .collect();
    let in_vectors: BTreeSet<&str> = vectors.iter().map(|v| v.check.as_str()).collect();
    assert_eq!(listed, in_vectors, "manifest checks vs record_reject.json");
    for required in [
        "ipns-signature-invalid",
        "ipns-value-mismatch",
        "ipns-record-malformed",
    ] {
        assert!(
            listed.contains(required),
            "record-reject must cover {required}"
        );
    }

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate record-reject {}",
            v.name
        );
        let name = IpnsName::parse(&v.ipns_name).expect("record-reject name parses");
        let record = unhex(&v.name, &v.record);
        let err = IpnsRecord::unmarshal(&record)
            .and_then(|r| r.verify(&name))
            .expect_err("record-reject must fail closed");
        assert_eq!(
            err.check(),
            v.check,
            "record-reject {}: check ({err})",
            v.name
        );
        assert_eq!(
            err.class(),
            v.class,
            "record-reject {}: class ({err})",
            v.name
        );
    }
}

#[test]
fn ipns_record_reput_vectors_are_byte_stable_and_verify() {
    let m = manifest();
    let vectors = record_reput_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.ipns.record_reput.count,
        "record-reput count drift"
    );
    assert!(!vectors.is_empty(), "record-reput family must not be empty");

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate record-reput {}",
            v.name
        );
        let name = IpnsName::parse(&v.ipns_name).expect("record-reput name parses");
        let bytes = unhex(&v.name, &v.record);
        // Keyless re-PUT: unmarshal→marshal reproduces the foreign record
        // byte-for-byte, unknown protobuf fields (signatureV1, pubKey) included.
        let parsed = IpnsRecord::unmarshal(&bytes)
            .unwrap_or_else(|e| panic!("record-reput {}: unmarshal: {e}", v.name));
        assert_eq!(
            hex::encode(parsed.marshal()),
            v.record,
            "record-reput {}: not byte-stable",
            v.name
        );
        // And the record still verifies (signatureV2 covers only data).
        parsed
            .verify(&name)
            .unwrap_or_else(|e| panic!("record-reput {}: verify: {e}", v.name));
    }
}

#[test]
fn pointer_accept_vectors_are_frozen_and_open() {
    let m = manifest();
    let vectors = pointer_accept_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.payload.pointer_accept.count,
        "pointer-accept count drift"
    );
    assert!(
        !vectors.is_empty(),
        "pointer-accept family must not be empty"
    );

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate pointer-accept {}",
            v.name
        );
        let key = unhex32(&v.name, &v.pointer_read_key);
        let nonce = unhex_n::<NONCE_LEN>(&v.name, &v.nonce);
        let owner =
            EcdsaSigner::from_scalar(&unhex32(&v.name, &v.owner_scalar)).expect("owner scalar");
        let scope_id = unhex_n::<16>(&v.name, &v.scope_id);
        let object = RepointObject {
            scope_id,
            current_root: IpnsName::parse(&v.current_root_name).expect("current root parses"),
            write_epoch: v.write_epoch,
            min_read_epoch: v.min_read_epoch,
            prev_root: v
                .prev_root_name
                .as_ref()
                .map(|n| IpnsName::parse(n).expect("prev root parses")),
        };
        // Fixed key + nonce reproduce the sealed blob byte-for-byte.
        let sealed = seal_pointer_payload(&key, &nonce, v.v, &owner, &object);
        assert_eq!(
            hex::encode(&sealed),
            v.sealed,
            "pointer-accept {}: sealed drift",
            v.name
        );
        let opened = open_pointer_payload(
            &key,
            v.v,
            &scope_id,
            &owner.verifying_key(),
            &unhex(&v.name, &v.sealed),
        )
        .unwrap_or_else(|e| panic!("pointer-accept {}: open: {e}", v.name));
        assert_eq!(opened, object, "pointer-accept {}: round-trip", v.name);
    }
    // Anti-vacuity: both a with-prev and a first-publish (no-prev) object exist.
    assert!(vectors.iter().any(|v| v.prev_root_name.is_some()));
    assert!(vectors.iter().any(|v| v.prev_root_name.is_none()));
}

#[test]
fn pointer_reject_vectors_fail_closed() {
    let m = manifest();
    let vectors = pointer_reject_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.payload.pointer_reject.count,
        "pointer-reject count drift"
    );

    let listed: BTreeSet<&str> = m
        .payload
        .pointer_reject
        .checks
        .iter()
        .map(String::as_str)
        .collect();
    let in_vectors: BTreeSet<&str> = vectors.iter().map(|v| v.check.as_str()).collect();
    assert_eq!(listed, in_vectors, "manifest checks vs pointer_reject.json");
    for required in [
        "seal-open-failed",
        "identity-signature-invalid",
        "truncated",
    ] {
        assert!(
            listed.contains(required),
            "pointer-reject must cover {required}"
        );
    }

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate pointer-reject {}",
            v.name
        );
        let key = unhex32(&v.name, &v.pointer_read_key);
        let scope_id = unhex_n::<16>(&v.name, &v.scope_id);
        let verifier = EcdsaSigner::from_scalar(&unhex32(&v.name, &v.owner_scalar))
            .expect("owner scalar")
            .verifying_key();
        let err = open_pointer_payload(&key, v.v, &scope_id, &verifier, &unhex(&v.name, &v.sealed))
            .expect_err("pointer-reject must fail closed");
        assert_eq!(
            err.check(),
            v.check,
            "pointer-reject {}: check ({err})",
            v.name
        );
        assert_eq!(
            err.class(),
            v.class,
            "pointer-reject {}: class ({err})",
            v.name
        );
    }
}

#[test]
fn mailbox_accept_vectors_are_frozen_and_open() {
    let m = manifest();
    let vectors = mailbox_accept_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.payload.mailbox_accept.count,
        "mailbox-accept count drift"
    );
    assert!(
        !vectors.is_empty(),
        "mailbox-accept family must not be empty"
    );

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate mailbox-accept {}",
            v.name
        );
        let recipient = X25519Secret::from_scalar(unhex32(&v.name, &v.recipient_secret));
        let recipient_public = X25519Public::from_bytes(unhex32(&v.name, &v.recipient_public))
            .expect("accept-vector recipient key is adoptable");
        let eph = unhex32(&v.name, &v.ephemeral_scalar);
        let sender =
            EcdsaSigner::from_scalar(&unhex32(&v.name, &v.sender_scalar)).expect("sender scalar");
        let payload = unhex(&v.name, &v.payload);
        // Fixed ephemeral reproduces the whole block byte-for-byte.
        let block = seal_mailbox_payload(&recipient_public, &eph, v.v, &sender, &payload);
        assert_eq!(
            hex::encode(&block),
            v.block,
            "mailbox-accept {}: block drift",
            v.name
        );
        let item = open_mailbox_payload(&recipient, v.v, &unhex(&v.name, &v.block))
            .unwrap_or_else(|e| panic!("mailbox-accept {}: open: {e}", v.name));
        assert_eq!(item.payload, payload, "mailbox-accept {}: payload", v.name);
        assert_eq!(
            item.sender_identity,
            sender.verifying_key(),
            "mailbox-accept {}: sender identity",
            v.name
        );
    }
}

#[test]
fn mailbox_reject_vectors_fail_closed() {
    let m = manifest();
    let vectors = mailbox_reject_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.payload.mailbox_reject.count,
        "mailbox-reject count drift"
    );

    let listed: BTreeSet<&str> = m
        .payload
        .mailbox_reject
        .checks
        .iter()
        .map(String::as_str)
        .collect();
    let in_vectors: BTreeSet<&str> = vectors.iter().map(|v| v.check.as_str()).collect();
    assert_eq!(listed, in_vectors, "manifest checks vs mailbox_reject.json");
    for required in ["hpke-open-failed", "identity-signature-invalid"] {
        assert!(
            listed.contains(required),
            "mailbox-reject must cover {required}"
        );
    }

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate mailbox-reject {}",
            v.name
        );
        let recipient = X25519Secret::from_scalar(unhex32(&v.name, &v.recipient_secret));
        let err = open_mailbox_payload(&recipient, v.v, &unhex(&v.name, &v.block))
            .expect_err("mailbox-reject must fail closed");
        assert_eq!(
            err.check(),
            v.check,
            "mailbox-reject {}: check ({err})",
            v.name
        );
        assert_eq!(
            err.class(),
            v.class,
            "mailbox-reject {}: class ({err})",
            v.name
        );
    }
}

// ---------------------------------------------------------------------------
// Grant section: the write-body, the grant/owner blobs, the ascent + history
// links, the structure signatures, and the grant-set commitment. Each family's
// accept vectors round-trip / reproduce / verify against the live code, and its
// reject vectors fire the named fail-closed check.
// ---------------------------------------------------------------------------

/// An optional recipient tag: empty hex is `None`, else a 32-byte blinded tag.
fn opt_tag(name: &str, hex: &str) -> Option<[u8; 32]> {
    if hex.is_empty() {
        None
    } else {
        Some(unhex32(name, hex))
    }
}

/// The shared per-codec reject-family shape: exact count, the manifest checks
/// list equals the distinct file checks, and every vector fires its named
/// check + class through `decode_fn`.
fn check_reject_family<T>(
    label: &str,
    vectors: &[RejectVector],
    section: &RejectSection,
    decode_fn: impl Fn(&[u8]) -> Result<T, cipherbox_core::error::CodecError>,
) {
    assert_eq!(vectors.len(), section.count, "{label} reject count drift");
    let listed: BTreeSet<&str> = section.checks.iter().map(String::as_str).collect();
    let in_vectors: BTreeSet<&str> = vectors.iter().map(|v| v.check.as_str()).collect();
    assert_eq!(listed, in_vectors, "manifest checks vs {label} reject.json");
    let mut names = BTreeSet::new();
    for v in vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate {label} reject {}",
            v.name
        );
        let bytes = unhex(&v.name, &v.hex);
        let err = match decode_fn(&bytes) {
            Err(e) => e,
            Ok(_) => panic!("{label} reject {}: decoder accepted it", v.name),
        };
        assert_eq!(
            err.check(),
            v.check,
            "{label} reject {}: check ({err})",
            v.name
        );
        assert_eq!(
            err.class(),
            v.class,
            "{label} reject {}: class ({err})",
            v.name
        );
    }
}

/// The grant/owner-blob reject-family shape: exact count, the manifest checks
/// list equals the distinct file checks, and every vector fails closed — a
/// decode vector through `decode_fn`, an HPKE vector through `open_fn` under the
/// context it carries (a struct-tag transplant carries the opener's differing
/// tag, so the recomputed AAD fails the tag).
fn check_blob_reject_family<TDec, TOpen>(
    label: &str,
    vectors: &[BlobRejectVector],
    section: &RejectSection,
    decode_fn: impl Fn(&[u8]) -> Result<TDec, cipherbox_core::error::CodecError>,
    open_fn: impl Fn(
        &X25519Secret,
        &[u8; 32],
        &AadContext,
        &[u8],
    ) -> Result<TOpen, cipherbox_core::error::CodecError>,
) {
    assert_eq!(vectors.len(), section.count, "{label} reject count drift");
    let listed: BTreeSet<&str> = section.checks.iter().map(String::as_str).collect();
    let in_vectors: BTreeSet<&str> = vectors.iter().map(BlobRejectVector::check).collect();
    assert_eq!(listed, in_vectors, "manifest checks vs {label} reject.json");
    let mut names = BTreeSet::new();
    for v in vectors {
        let name = v.name();
        assert!(
            names.insert(name.to_string()),
            "duplicate {label} reject {name}"
        );
        match v {
            BlobRejectVector::Decode(r) => {
                let bytes = unhex(name, &r.hex);
                let err = match decode_fn(&bytes) {
                    Err(e) => e,
                    Ok(_) => panic!("{label} reject {name}: decoder accepted it"),
                };
                assert_eq!(err.check(), r.check, "{label} reject {name}: check ({err})");
                assert_eq!(err.class(), r.class, "{label} reject {name}: class ({err})");
            }
            BlobRejectVector::HpkeOpen(h) => {
                let ctx = seal_ctx(name, h.v, &h.id, &h.scope, h.epoch, h.struct_tag);
                let recipient = X25519Secret::from_scalar(unhex32(name, &h.recipient_secret));
                let enc = unhex32(name, &h.enc);
                let ciphertext = unhex(name, &h.ciphertext);
                let err = match open_fn(&recipient, &enc, &ctx, &ciphertext) {
                    Err(e) => e,
                    Ok(_) => panic!("{label} reject {name}: open accepted it"),
                };
                assert_eq!(err.check(), h.check, "{label} reject {name}: check ({err})");
                assert_eq!(err.class(), h.class, "{label} reject {name}: class ({err})");
            }
        }
    }
}

#[test]
fn grant_struct_tags_are_frozen() {
    let m = manifest();
    assert_eq!(m.grant.write_body_struct_tag, STRUCT_TAG_WRITE_BODY);
    assert_eq!(m.grant.grant_blob_struct_tag, STRUCT_TAG_GRANT_BLOB);
    assert_eq!(m.grant.owner_blob_struct_tag, STRUCT_TAG_OWNER_BLOB);
    assert_eq!(
        m.grant.owner_write_blob_struct_tag,
        STRUCT_TAG_OWNER_WRITE_BLOB
    );
    assert_eq!(m.grant.ascent_link_struct_tag, STRUCT_TAG_ASCENT_LINK);
    assert_eq!(m.grant.history_link_struct_tag, STRUCT_TAG_HISTORY_LINK);
    assert_eq!(
        m.grant.write_history_link_struct_tag,
        STRUCT_TAG_WRITE_HISTORY_LINK
    );
    // The frozen byte-space (mirrors ALL_STRUCT_TAGS).
    assert_eq!(STRUCT_TAG_WRITE_BODY, 2);
    assert_eq!(STRUCT_TAG_GRANT_BLOB, 3);
    assert_eq!(STRUCT_TAG_OWNER_BLOB, 4);
    assert_eq!(STRUCT_TAG_ASCENT_LINK, 5);
    assert_eq!(STRUCT_TAG_HISTORY_LINK, 6);
    assert_eq!(STRUCT_TAG_OWNER_WRITE_BLOB, 9);
}

/// The write-body's total encoded-size bound is a frozen wire number a
/// cross-language implementation must refuse at, so the manifest carries the
/// value rather than a multi-megabyte reject vector.
#[test]
fn the_write_body_size_bound_is_frozen_in_the_manifest() {
    let m = manifest();
    assert_eq!(m.grant.write_body_max_bytes, MAX_WRITE_BODY_BYTES);
    assert_eq!(
        m.grant.write_body_reseal_headroom_bytes,
        WRITE_BODY_RESEAL_HEADROOM_BYTES
    );
    assert_eq!(
        MAX_WRITE_BODY_BYTES + WRITE_BODY_RESEAL_HEADROOM_BYTES,
        MAX_BLOCK_BYTES,
        "the bound is the block ceiling minus the reserved re-seal headroom"
    );
}

/// The grant section's total encoded-size bound, frozen the same way and for
/// the same reason: a cross-language implementation must refuse at the same
/// byte, and the vector that would prove it is two megabytes long. How the
/// value is pinned against its neighbouring bounds is a `const` assertion in
/// `seal::section`, which no build can skip.
#[test]
fn the_grant_section_size_bound_is_frozen_in_the_manifest() {
    let m = manifest();
    assert_eq!(m.grant.grant_section_max_bytes, MAX_GRANT_SECTION_BYTES);
    assert_eq!(
        m.grant.grant_section_envelope_headroom_bytes,
        GRANT_SECTION_ENVELOPE_HEADROOM_BYTES
    );
}

/// The carried-critical budget: the marker prefix and the byte budget are one
/// wire reservation, and a reader that honours the prefix without the budget
/// hands a publisher an uncuttable field to pad.
#[test]
fn the_critical_carried_budget_is_frozen_in_the_manifest() {
    let m = manifest();
    assert_eq!(m.seal.critical_key_prefix, CRITICAL_KEY_PREFIX);
    assert_eq!(
        m.seal.critical_carried_max_bytes,
        MAX_CRITICAL_CARRIED_BYTES
    );
    // Frozen beside the prefix: honouring the marker alone would cut these and
    // publish a record every reader rejects.
    assert_eq!(m.seal.uncuttable_keys, UNCUTTABLE_KEYS);
}

/// The envelope's two byte bounds, frozen for the reason the section's and the
/// write-body's are: a cross-language implementation must refuse at the same
/// byte, and the vectors that would prove either are two megabytes long.
#[test]
fn the_envelope_size_bounds_are_frozen_in_the_manifest() {
    let m = manifest();
    assert_eq!(m.seal.envelope_max_bytes, MAX_BLOCK_BYTES);
    assert_eq!(m.seal.read_sealed_max_bytes, MAX_READ_SEALED_BYTES);
    assert_eq!(
        m.seal.read_sealed_envelope_headroom_bytes,
        READ_SEALED_ENVELOPE_HEADROOM_BYTES
    );
}

#[test]
fn write_body_accept_vectors_decode_and_round_trip() {
    let m = manifest();
    let vectors = write_body_accept_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.grant.write_body_accept.count,
        "write-body accept count drift"
    );
    assert!(
        !vectors.is_empty(),
        "write-body accept family must not be empty"
    );

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate write-body accept {}",
            v.name
        );
        let bytes = unhex(&v.name, &v.hex);
        let body = decode_write_body(&bytes)
            .unwrap_or_else(|e| panic!("write-body accept {}: rejected: {e}", v.name));
        assert_eq!(
            hex::encode(encode_write_body(&body).expect("accept vector re-encodes")),
            v.hex,
            "write-body accept {}: re-encode must be byte-identical",
            v.name
        );
        assert_eq!(
            body.grant_ledger.len(),
            v.ledger_count,
            "write-body accept {}: ledger count",
            v.name
        );
        assert_eq!(
            body.direct_child_scope_index.len(),
            v.child_scope_count,
            "write-body accept {}: child-scope count",
            v.name
        );
    }
}

#[test]
fn write_body_reject_vectors_fire_the_named_check() {
    let m = manifest();
    let vectors = write_body_reject_vectors(&m);
    check_reject_family(
        "write-body",
        &vectors,
        &m.grant.write_body_reject,
        decode_write_body,
    );
    assert!(
        m.grant
            .write_body_reject
            .checks
            .iter()
            .any(|c| c == "invalid-permission"),
        "write-body reject must cover the grant-permission check"
    );
}

/// The frozen recipient-binding preimage: re-encoding the vector's own fields
/// must reproduce it byte for byte, and the owner's signature must verify over
/// it. This is the authority a re-sealer holding no owner secret checks
/// `recipientEncPk` against before re-wrapping a grant.
#[test]
fn recipient_binding_accept_vectors_reencode_and_verify() {
    let m = manifest();
    let vectors = recipient_binding_accept_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.grant.recipient_binding_accept.count,
        "recipient-binding accept count drift"
    );
    assert!(
        vectors.len() >= 2,
        "recipient-binding accept family must pin more than one row"
    );

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate recipient-binding accept {}",
            v.name
        );
        let ipns_name = unhex(&v.name, &v.ipns_name);
        let entry = GrantLedgerEntry::new(
            unhex_n::<33>(&v.name, &v.recipient_identity_pk),
            unhex32(&v.name, &v.recipient_enc_pk),
            Permission::Read,
            unhex32(&v.name, &v.tag),
            unhex_n::<64>(&v.name, &v.signature),
        );
        assert_eq!(
            hex::encode(
                encode_recipient_binding(&ipns_name, &entry).expect("accept vector re-encodes")
            ),
            v.preimage,
            "recipient-binding accept {}: re-encode must be byte-identical",
            v.name
        );
        let verifier = EcdsaVerifier::from_sec1(&unhex(&v.name, &v.owner_identity_pk))
            .expect("valid owner identity key");
        assert!(
            verify_recipient_binding(&verifier, &ipns_name, &entry).is_ok(),
            "recipient-binding accept {}: must verify",
            v.name
        );

        // `permission` is outside the preimage, which is why the vector carries
        // none: the row above was rebuilt as `Read` regardless of what the
        // generator signed.
        let mut other_permission = entry.clone();
        other_permission.permission = Permission::Write;
        assert!(
            verify_recipient_binding(&verifier, &ipns_name, &other_permission).is_ok(),
            "recipient-binding accept {}: permission must not be bound",
            v.name
        );

        // The scope root is bound: the same row under another name is not
        // owner-attested there.
        assert_eq!(
            verify_recipient_binding(&verifier, b"another-scope-root", &entry)
                .unwrap_err()
                .check(),
            "identity-signature-invalid",
            "recipient-binding accept {}: ipnsName must be bound",
            v.name
        );
    }
}

#[test]
fn grant_section_accept_vectors_decode_and_round_trip() {
    let m = manifest();
    let vectors = section_accept_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.grant.section_accept.count,
        "grant-section accept count drift"
    );
    assert!(
        !vectors.is_empty(),
        "grant-section accept family must not be empty"
    );

    let mut names = BTreeSet::new();
    let mut saw_full = false;
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate grant-section accept {}",
            v.name
        );
        let bytes = unhex(&v.name, &v.hex);
        let section = decode_grant_section(&bytes)
            .unwrap_or_else(|e| panic!("grant-section accept {}: rejected: {e}", v.name));
        assert_eq!(
            hex::encode(encode_grant_section(&section).expect("accept vector re-encodes")),
            v.hex,
            "grant-section accept {}: re-encode must be byte-identical",
            v.name
        );
        assert_eq!(
            section.grant_blobs.len(),
            v.grant_blob_count,
            "grant-section accept {}: grant-blob count",
            v.name
        );
        assert_eq!(
            section.history_links.len(),
            v.history_link_count,
            "grant-section accept {}: history-link count",
            v.name
        );
        assert_eq!(
            section.ascent_link.is_some(),
            v.has_ascent_link,
            "grant-section accept {}: ascent-link presence",
            v.name
        );
        if v.grant_blob_count > 0 && v.has_ascent_link {
            saw_full = true;
        }
    }
    assert!(
        saw_full,
        "a grant-section accept vector must exercise the full bundle (grants + ascent link)"
    );
}

#[test]
fn grant_section_reject_vectors_fire_the_named_check() {
    let m = manifest();
    let vectors = section_reject_vectors(&m);
    check_reject_family(
        "grant-section",
        &vectors,
        &m.grant.section_reject,
        decode_grant_section,
    );
    assert!(
        m.grant
            .section_reject
            .checks
            .iter()
            .any(|c| c == "duplicate-grant-tag"),
        "grant-section reject must cover the duplicate-tag confused-deputy check"
    );
}

/// Reproduce a frozen HPKE-sealed structure (grant/owner blob) under its fixed
/// ephemeral and recipient key, and open it — returning the recovered plaintext.
fn hpke_structure_reproduce_and_open(v: &HpkeStructureVector) -> Vec<u8> {
    let ctx = seal_ctx(&v.name, v.v, &v.id, &v.scope, v.epoch, v.struct_tag);
    assert_eq!(
        hex::encode(build_aad(&ctx)),
        v.aad,
        "hpke structure {}: aad drift",
        v.name
    );
    let recipient_public = X25519Public::from_bytes(unhex32(&v.name, &v.recipient_public))
        .expect("accept-vector recipient key is adoptable");
    let eph = unhex32(&v.name, &v.ephemeral_scalar);
    let plaintext = unhex(&v.name, &v.plaintext);
    // The grant-section HPKE `info` is fixed empty; the structured AAD binds the
    // context. Fixed ephemeral must reproduce the frozen enc + ciphertext.
    let sealed = hpke_seal(&recipient_public, &eph, b"", &build_aad(&ctx), &plaintext);
    assert_eq!(
        hex::encode(sealed.enc),
        v.enc,
        "hpke structure {}: enc drift",
        v.name
    );
    assert_eq!(
        hex::encode(&sealed.ciphertext),
        v.ciphertext,
        "hpke structure {}: ciphertext drift",
        v.name
    );
    let recipient = X25519Secret::from_scalar(unhex32(&v.name, &v.recipient_secret));
    let enc = unhex32(&v.name, &v.enc);
    let opened = hpke_open(
        &recipient,
        &enc,
        b"",
        &build_aad(&ctx),
        &unhex(&v.name, &v.ciphertext),
    )
    .unwrap_or_else(|_| panic!("hpke structure {}: open must recover", v.name));
    assert_eq!(
        &opened[..],
        &plaintext[..],
        "hpke structure {}: plaintext",
        v.name
    );
    plaintext
}

#[test]
fn grant_blob_accept_vectors_seal_reproduce_open_and_decode() {
    let m = manifest();
    let vectors = grant_blob_accept_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.grant.grant_blob_accept.count,
        "grant-blob accept count drift"
    );
    assert!(
        !vectors.is_empty(),
        "grant-blob accept family must not be empty"
    );
    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate grant-blob accept {}",
            v.name
        );
        assert_eq!(
            v.struct_tag, STRUCT_TAG_GRANT_BLOB,
            "grant-blob accept {}: tag",
            v.name
        );
        let plaintext = hpke_structure_reproduce_and_open(v);
        assert!(
            decode_grant_blob_payload(&plaintext).is_ok(),
            "grant-blob accept {}: payload must decode",
            v.name
        );
    }
}

#[test]
fn grant_blob_reject_vectors_fire_the_named_check() {
    let m = manifest();
    let vectors = grant_blob_reject_vectors(&m);
    check_blob_reject_family(
        "grant-blob",
        &vectors,
        &m.grant.grant_blob_reject,
        decode_grant_blob_payload,
        open_grant_blob,
    );
    for required in ["missing-field", "hpke-open-failed"] {
        assert!(
            m.grant
                .grant_blob_reject
                .checks
                .iter()
                .any(|c| c == required),
            "grant-blob reject must cover the {required} check"
        );
    }
}

#[test]
fn owner_blob_accept_vectors_seal_reproduce_open_and_decode() {
    let m = manifest();
    let vectors = owner_blob_accept_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.grant.owner_blob_accept.count,
        "owner-blob accept count drift"
    );
    assert!(
        !vectors.is_empty(),
        "owner-blob accept family must not be empty"
    );
    for v in &vectors {
        assert_eq!(
            v.struct_tag, STRUCT_TAG_OWNER_BLOB,
            "owner-blob accept {}: tag",
            v.name
        );
        let plaintext = hpke_structure_reproduce_and_open(v);
        assert!(
            decode_override_seed_payload(&plaintext).is_ok(),
            "owner-blob accept {}: payload must decode",
            v.name
        );
    }
}

#[test]
fn owner_blob_reject_vectors_fire_the_named_check() {
    let m = manifest();
    let vectors = owner_blob_reject_vectors(&m);
    check_blob_reject_family(
        "owner-blob",
        &vectors,
        &m.grant.owner_blob_reject,
        decode_override_seed_payload,
        open_owner_blob,
    );
    for required in ["missing-field", "hpke-open-failed"] {
        assert!(
            m.grant
                .owner_blob_reject
                .checks
                .iter()
                .any(|c| c == required),
            "owner-blob reject must cover the {required} check"
        );
    }
}

#[test]
fn owner_write_blob_accept_vectors_seal_reproduce_open_and_decode() {
    let m = manifest();
    let vectors = owner_write_blob_accept_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.grant.owner_write_blob_accept.count,
        "owner-write-blob accept count drift"
    );
    assert!(
        !vectors.is_empty(),
        "owner-write-blob accept family must not be empty"
    );
    for v in &vectors {
        assert_eq!(
            v.struct_tag, STRUCT_TAG_OWNER_WRITE_BLOB,
            "owner-write-blob accept {}: tag",
            v.name
        );
        let plaintext = hpke_structure_reproduce_and_open(v);
        assert!(
            decode_owner_write_blob_payload(&plaintext).is_ok(),
            "owner-write-blob accept {}: payload must decode",
            v.name
        );
    }
}

#[test]
fn owner_write_blob_reject_vectors_fire_the_named_check() {
    let m = manifest();
    let vectors = owner_write_blob_reject_vectors(&m);
    check_blob_reject_family(
        "owner-write-blob",
        &vectors,
        &m.grant.owner_write_blob_reject,
        decode_owner_write_blob_payload,
        open_owner_write_blob,
    );
    for required in ["missing-field", "invalid-field-length", "hpke-open-failed"] {
        assert!(
            m.grant
                .owner_write_blob_reject
                .checks
                .iter()
                .any(|c| c == required),
            "owner-write-blob reject must cover the {required} check"
        );
    }
}

/// The write-plane history link's own full envelope: a fixed owner keypair and
/// ephemeral must reproduce `enc(32) || ciphertext||tag` byte for byte through
/// the public API, and the owner must reopen it.
#[test]
fn write_history_link_accept_vectors_seal_reproduce_and_open() {
    let m = manifest();
    assert_eq!(
        m.grant.write_history_link_struct_tag,
        STRUCT_TAG_WRITE_HISTORY_LINK
    );
    let vectors = write_history_link_accept_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.grant.write_history_link_accept.count,
        "write-history-link accept count drift"
    );
    assert!(
        !vectors.is_empty(),
        "write-history-link accept family must not be empty"
    );
    for v in &vectors {
        assert_eq!(
            v.struct_tag, STRUCT_TAG_WRITE_HISTORY_LINK,
            "write-history-link accept {}: tag",
            v.name
        );
        let ctx = seal_ctx(&v.name, v.v, &v.id, &v.scope, v.epoch, v.struct_tag);
        assert_eq!(
            hex::encode(build_aad(&ctx)),
            v.aad,
            "write-history-link accept {}: aad drift",
            v.name
        );
        let owner = X25519Secret::from_scalar(unhex32(&v.name, &v.recipient_secret));
        assert_eq!(
            owner.public().to_bytes(),
            unhex32(&v.name, &v.recipient_public),
            "write-history-link accept {}: owner keypair",
            v.name
        );
        let payload = decode_history_link_payload(&unhex(&v.name, &v.plaintext))
            .unwrap_or_else(|e| panic!("write-history-link accept {}: plaintext: {e}", v.name));
        let sealed = seal_owner_history_link(
            &owner,
            &unhex32(&v.name, &v.ephemeral_scalar),
            &ctx,
            &payload,
        )
        .unwrap_or_else(|e| panic!("write-history-link accept {}: seal: {e}", v.name));
        let mut frozen = unhex(&v.name, &v.enc);
        frozen.extend_from_slice(&unhex(&v.name, &v.ciphertext));
        assert_eq!(
            hex::encode(&sealed),
            hex::encode(&frozen),
            "write-history-link accept {}: envelope drift",
            v.name
        );
        assert_eq!(
            open_owner_history_link(&owner, &ctx, &frozen)
                .unwrap_or_else(|e| panic!("write-history-link accept {}: open: {e}", v.name)),
            payload,
            "write-history-link accept {}: round-trip",
            v.name
        );
    }
}

#[test]
fn write_history_link_reject_vectors_fire_the_named_check() {
    let m = manifest();
    let vectors = write_history_link_reject_vectors(&m);
    check_blob_reject_family(
        "write-history-link",
        &vectors,
        &m.grant.write_history_link_reject,
        decode_history_link_payload,
        |owner, enc, ctx, ciphertext| {
            let mut blob = enc.to_vec();
            blob.extend_from_slice(ciphertext);
            open_owner_history_link(owner, ctx, &blob)
        },
    );
    // A base-mode open under the owner's own secret and the vector's own AAD
    // leaves the static-sender binding as the only thing the reject can be, and
    // `enc` cannot give it away: DHKEM's encapsulated key is the ephemeral
    // public alone.
    let forgery = vectors
        .iter()
        .find_map(|v| match v {
            BlobRejectVector::HpkeOpen(v) if v.name == "base-mode-forgery" => Some(v),
            _ => None,
        })
        .expect("the base-mode-forgery reject vector");
    let ctx = seal_ctx(
        &forgery.name,
        forgery.v,
        &forgery.id,
        &forgery.scope,
        forgery.epoch,
        forgery.struct_tag,
    );
    hpke_open(
        &X25519Secret::from_scalar(unhex32(&forgery.name, &forgery.recipient_secret)),
        &unhex32(&forgery.name, &forgery.enc),
        b"",
        &build_aad(&ctx),
        &unhex(&forgery.name, &forgery.ciphertext),
    )
    .expect("write-history-link base-mode-forgery: not a base-mode seal to the owner");
}

#[test]
fn op_record_accept_vectors_seal_reproduce_open_and_decode() {
    let m = manifest();
    assert_eq!(m.op_record.struct_tag, STRUCT_TAG_OP_RECORD);
    assert_eq!(m.op_record.v, OP_RECORD_V);
    assert_eq!(m.op_record.hpke_mode, MODE_AUTH);
    assert_eq!(m.op_record.hpke_info.as_bytes(), OP_RECORD_HPKE_INFO);

    let vectors = op_record_accept_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.op_record.accept.count,
        "op-record accept count drift"
    );
    assert!(
        vectors.len() >= 2,
        "op-record accept must cover a metadata and a content record"
    );
    assert!(
        vectors.iter().any(|v| v.content_root_cid.is_none())
            && vectors.iter().any(|v| v.content_root_cid.is_some()),
        "op-record accept must cover both an absent and a present content root"
    );

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate op-record accept {}",
            v.name
        );
        let owner = X25519Secret::from_scalar(unhex32(&v.name, &v.owner_secret));
        let owner_public = unhex32(&v.name, &v.owner_public);
        assert_eq!(
            owner.public().to_bytes(),
            owner_public,
            "op-record accept {}: owner keypair",
            v.name
        );
        let eph = unhex32(&v.name, &v.ephemeral_scalar);
        let cid: Option<Vec<u8>> = v.content_root_cid.as_ref().map(|c| unhex(&v.name, c));
        let body = unhex(&v.name, &v.body);

        let sealed = seal_op_record(&owner, &eph, cid.as_deref(), &body)
            .unwrap_or_else(|e| panic!("op-record accept {}: seal ({e})", v.name));
        assert_eq!(
            hex::encode(&sealed),
            v.record,
            "op-record accept {}: record drift",
            v.name
        );

        let record = unhex(&v.name, &v.record);
        let header = decode_op_record_header(&record)
            .unwrap_or_else(|e| panic!("op-record accept {}: header decode ({e})", v.name));
        assert_eq!(
            header.version, OP_RECORD_V,
            "op-record accept {}: clear version",
            v.name
        );
        assert_eq!(
            header.owner_tag, owner_public,
            "op-record accept {}: owner tag",
            v.name
        );
        assert_eq!(
            header.content_root_cid, cid,
            "op-record accept {}: content root cid",
            v.name
        );

        let (opened, plaintext) = open_op_record(&owner, &record)
            .unwrap_or_else(|e| panic!("op-record accept {}: open ({e})", v.name));
        assert_eq!(opened, header, "op-record accept {}: opened header", v.name);
        assert_eq!(
            &plaintext[..],
            &body[..],
            "op-record accept {}: body",
            v.name
        );
    }
}

#[test]
fn op_record_reject_vectors_fire_the_named_check() {
    let m = manifest();
    let vectors = op_record_reject_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.op_record.reject.count,
        "op-record reject count drift"
    );
    let listed: BTreeSet<&str> = m
        .op_record
        .reject
        .checks
        .iter()
        .map(String::as_str)
        .collect();
    let in_vectors: BTreeSet<&str> = vectors.iter().map(|v| v.check.as_str()).collect();
    assert_eq!(
        listed, in_vectors,
        "manifest checks vs op-record reject.json"
    );
    for required in [
        "hpke-open-failed",
        "content-cid-mismatch",
        "missing-field",
        "unsupported-record-version",
        "unknown-record-field",
    ] {
        assert!(
            listed.contains(required),
            "op-record reject must cover the {required} check"
        );
    }

    assert!(
        vectors.iter().any(|v| v.name == "base-mode-forgery"),
        "op-record reject must pin a base-mode forgery under the owner's own tag"
    );

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate op-record reject {}",
            v.name
        );
        let owner = X25519Secret::from_scalar(unhex32(&v.name, &v.owner_secret));
        let record = unhex(&v.name, &v.record);
        let err = match open_op_record(&owner, &record) {
            Err(e) => e,
            Ok(_) => panic!("op-record reject {}: open accepted it", v.name),
        };
        assert_eq!(
            err.check(),
            v.check,
            "op-record reject {}: check ({err})",
            v.name
        );
        assert_eq!(
            err.class(),
            v.class,
            "op-record reject {}: class ({err})",
            v.name
        );

        // The keyless header read is what orphan GC performs: it must fire the
        // same check, or accept, exactly as the vector records.
        match decode_op_record_header(&record) {
            Err(e) => {
                assert!(
                    v.keyless,
                    "op-record reject {}: unexpected keyless reject",
                    v.name
                );
                assert_eq!(
                    e.check(),
                    v.check,
                    "op-record reject {}: keyless check ({e})",
                    v.name
                );
            }
            Ok(_) => assert!(
                !v.keyless,
                "op-record reject {}: keyless read must have refused it",
                v.name
            ),
        }
    }
}

#[test]
fn settings_record_accept_vectors_seal_reproduce_and_open() {
    let m = manifest();
    assert_eq!(m.settings_record.struct_tag, STRUCT_TAG_SETTINGS_RECORD);
    assert_eq!(m.settings_record.v, SETTINGS_RECORD_V);
    assert_eq!(m.settings_record.hpke_mode, MODE_AUTH);
    assert_eq!(
        m.settings_record.hpke_info.as_bytes(),
        SETTINGS_RECORD_HPKE_INFO
    );

    let vectors = settings_record_accept_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.settings_record.accept.count,
        "settings-record accept count drift"
    );
    assert!(
        vectors.iter().any(|v| v.body.is_empty()) && vectors.iter().any(|v| !v.body.is_empty()),
        "settings-record accept must cover both an empty and a populated body"
    );

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate settings-record accept {}",
            v.name
        );
        let owner = X25519Secret::from_scalar(unhex32(&v.name, &v.owner_secret));
        let owner_public = unhex32(&v.name, &v.owner_public);
        assert_eq!(
            owner.public().to_bytes(),
            owner_public,
            "settings-record accept {}: owner keypair",
            v.name
        );
        let eph = unhex32(&v.name, &v.ephemeral_scalar);
        let body = unhex(&v.name, &v.body);

        let sealed = seal_settings_record(&owner, &eph, &body)
            .unwrap_or_else(|e| panic!("settings-record accept {}: seal ({e})", v.name));
        assert_eq!(
            hex::encode(&sealed),
            v.record,
            "settings-record accept {}: record drift",
            v.name
        );

        let record = unhex(&v.name, &v.record);
        // The record is published to the zero-knowledge server, so the owner's
        // enc-subkey public half must stay AAD-bound and unserialized.
        let decoded = decode(&record)
            .unwrap_or_else(|e| panic!("settings-record accept {}: decode ({e})", v.name));
        let keys: Vec<&str> = decoded
            .as_map()
            .unwrap_or_else(|e| panic!("settings-record accept {}: map ({e})", v.name))
            .entries()
            .iter()
            .map(|(k, _)| k.as_str())
            .collect();
        assert_eq!(
            keys,
            ["v", "enc", "ciphertext"],
            "settings-record accept {}: clear header must not carry the owner tag",
            v.name
        );

        let plaintext = open_settings_record(&owner, &record)
            .unwrap_or_else(|e| panic!("settings-record accept {}: open ({e})", v.name));
        assert_eq!(
            &plaintext[..],
            &body[..],
            "settings-record accept {}: body",
            v.name
        );
    }
}

#[test]
fn settings_record_reject_vectors_fire_the_named_check() {
    let m = manifest();
    let vectors = settings_record_reject_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.settings_record.reject.count,
        "settings-record reject count drift"
    );
    let listed: BTreeSet<&str> = m
        .settings_record
        .reject
        .checks
        .iter()
        .map(String::as_str)
        .collect();
    let in_vectors: BTreeSet<&str> = vectors.iter().map(|v| v.check.as_str()).collect();
    assert_eq!(
        listed, in_vectors,
        "manifest checks vs settings-record reject.json"
    );
    for required in [
        "hpke-open-failed",
        "hpke-non-contributory",
        "invalid-field-length",
        "missing-field",
        "unsupported-record-version",
        "unknown-record-field",
    ] {
        assert!(
            listed.contains(required),
            "settings-record reject must cover the {required} check"
        );
    }

    assert!(
        vectors.iter().any(|v| v.name == "base-mode-forgery"),
        "settings-record reject must pin a base-mode forgery under the owner's own tag"
    );
    // Key-schedule separation, not framing: the transplanted op-record KEM
    // output is a structurally valid settings header, so only the struct tag
    // and the distinct info string can refuse it.
    assert!(
        vectors.iter().any(|v| v.name == "cross-family-transplant"),
        "settings-record reject must pin a cross-family transplant from the op record"
    );

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate settings-record reject {}",
            v.name
        );
        let owner = X25519Secret::from_scalar(unhex32(&v.name, &v.owner_secret));
        let record = unhex(&v.name, &v.record);
        let err = match open_settings_record(&owner, &record) {
            Err(e) => e,
            Ok(_) => panic!("settings-record reject {}: open accepted it", v.name),
        };
        assert_eq!(
            err.check(),
            v.check,
            "settings-record reject {}: check ({err})",
            v.name
        );
        assert_eq!(
            err.class(),
            v.class,
            "settings-record reject {}: class ({err})",
            v.name
        );
    }
}

#[test]
fn bin_index_accept_vectors_seal_reproduce_and_open() {
    let m = manifest();
    assert_eq!(m.bin_index.struct_tag, STRUCT_TAG_BIN_INDEX);
    assert_eq!(m.bin_index.v, BIN_INDEX_V);
    assert_eq!(m.bin_index.max_bytes, MAX_BIN_INDEX_BYTES);

    let vectors = bin_index_accept_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.bin_index.accept.count,
        "bin-index accept count drift"
    );

    // One seal key covers this whole family and never rotates, so a repeated
    // nonce would seal two bodies under one keystream. Mirrors the HPKE
    // ephemeral-freshness check.
    let mut nonces = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut saw_empty = false;
    let mut saw_populated = false;
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate bin-index accept {}",
            v.name
        );
        let key: [u8; KEY_LEN] = unhex32(&v.name, &v.seal_key);
        let nonce: [u8; NONCE_LEN] = unhex_n(&v.name, &v.nonce);
        assert!(
            nonces.insert(nonce),
            "bin-index accept {}: nonce reused under one seal key",
            v.name
        );
        let plaintext = unhex(&v.name, &v.plaintext);

        let index = decode_bin_index(&plaintext)
            .unwrap_or_else(|e| panic!("bin-index accept {}: decode ({e})", v.name));
        assert_eq!(
            hex::encode(encode_bin_index(&index).unwrap()),
            v.plaintext,
            "bin-index accept {}: plaintext is not byte-stable",
            v.name
        );

        let sealed = seal_bin_index(&key, &nonce, &index)
            .unwrap_or_else(|e| panic!("bin-index accept {}: seal ({e})", v.name));
        assert_eq!(
            hex::encode(&sealed),
            v.record,
            "bin-index accept {}: record drift",
            v.name
        );

        let record = unhex(&v.name, &v.record);
        let decoded =
            decode(&record).unwrap_or_else(|e| panic!("bin-index accept {}: decode ({e})", v.name));
        let keys: Vec<&str> = decoded
            .as_map()
            .unwrap_or_else(|e| panic!("bin-index accept {}: map ({e})", v.name))
            .entries()
            .iter()
            .map(|(k, _)| k.as_str())
            .collect();
        assert_eq!(
            keys,
            ["v", "sealed"],
            "bin-index accept {}: the clear header is exactly two keys",
            v.name
        );

        let reopened = open_bin_index(&key, &record)
            .unwrap_or_else(|e| panic!("bin-index accept {}: open ({e})", v.name));
        assert_eq!(reopened, index, "bin-index accept {}: index", v.name);
        saw_empty |= index.entries.is_empty();
        saw_populated |= !index.entries.is_empty();

        // The index is owner-sealed, so no entry's held key may appear in the
        // clear bytes a zero-knowledge server stores.
        for entry in &index.entries {
            if let Some(held) = entry.held_key() {
                assert!(
                    !record.windows(held.len()).any(|w| w == held),
                    "bin-index accept {}: a held key rode the wire in the clear",
                    v.name
                );
            }
        }
    }
    assert!(
        saw_empty && saw_populated,
        "bin-index accept must cover both an empty and a populated index"
    );
}

#[test]
fn bin_index_reject_vectors_fire_the_named_check() {
    let m = manifest();
    let vectors = bin_index_reject_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.bin_index.reject.count,
        "bin-index reject count drift"
    );
    let listed: BTreeSet<&str> = m
        .bin_index
        .reject
        .checks
        .iter()
        .map(String::as_str)
        .collect();
    let in_vectors: BTreeSet<&str> = vectors.iter().map(|v| v.check.as_str()).collect();
    assert_eq!(
        listed, in_vectors,
        "manifest checks vs bin-index reject.json"
    );
    for required in [
        "seal-open-failed",
        "duplicate-id",
        "truncated",
        "invalid-field-length",
        "invalid-node-kind",
        "missing-field",
        "too-many-structures",
        "unsupported-record-version",
        "unknown-record-field",
    ] {
        assert!(
            listed.contains(required),
            "bin-index reject must cover the {required} check"
        );
    }
    // The tag is the whole separation claim: the same key and plaintext under
    // the read-body tag must not open here.
    assert!(
        vectors.iter().any(|v| v.name == "struct-tag-transplant"),
        "bin-index reject must pin a structure-tag transplant"
    );

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate bin-index reject {}",
            v.name
        );
        let key: [u8; KEY_LEN] = unhex32(&v.name, &v.seal_key);
        let record = unhex(&v.name, &v.record);
        let err = match open_bin_index(&key, &record) {
            Err(e) => e,
            Ok(_) => panic!("bin-index reject {}: open accepted it", v.name),
        };
        assert_eq!(
            err.check(),
            v.check,
            "bin-index reject {}: check ({err})",
            v.name
        );
        assert_eq!(
            err.class(),
            v.class,
            "bin-index reject {}: class ({err})",
            v.name
        );
    }
}

#[test]
fn content_key_accept_vectors_seal_reproduce_and_open() {
    let m = manifest();
    assert_eq!(m.content_key.struct_tag, STRUCT_TAG_CONTENT_KEY);
    assert_eq!(m.content_key.v, CONTENT_KEY_V);
    assert_eq!(m.content_key.hpke_mode, MODE_AUTH);
    assert_eq!(m.content_key.hpke_info.as_bytes(), CONTENT_KEY_HPKE_INFO);

    let vectors = content_key_accept_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.content_key.accept.count,
        "content-key accept count drift"
    );
    assert!(
        vectors.iter().any(|v| v.epoch == 0)
            && vectors.iter().any(|v| v.epoch > u64::from(u32::MAX)),
        "content-key accept must cover both ends of the epoch range"
    );

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate content-key accept {}",
            v.name
        );
        let owner = X25519Secret::from_scalar(unhex32(&v.name, &v.owner_secret));
        assert_eq!(
            owner.public().to_bytes(),
            unhex32(&v.name, &v.owner_public),
            "content-key accept {}: owner keypair",
            v.name
        );
        let eph = unhex32(&v.name, &v.ephemeral_scalar);
        let scope = unhex_n::<16>(&v.name, &v.scope);
        let cid = unhex(&v.name, &v.content_cid);
        let key = unhex32(&v.name, &v.key);

        let sealed = seal_content_key(&owner, &eph, &scope, v.epoch, &cid, &key)
            .unwrap_or_else(|e| panic!("content-key accept {}: seal ({e})", v.name));
        assert_eq!(
            hex::encode(&sealed),
            v.blob,
            "content-key accept {}: blob drift",
            v.name
        );

        let blob = unhex(&v.name, &v.blob);
        let opened = open_content_key(&owner, &scope, v.epoch, &cid, &blob)
            .unwrap_or_else(|e| panic!("content-key accept {}: open ({e})", v.name));
        assert_eq!(opened.to_vec(), key, "content-key accept {}: key", v.name);
    }
}

#[test]
fn content_key_reject_vectors_fire_the_named_check() {
    let m = manifest();
    let vectors = content_key_reject_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.content_key.reject.count,
        "content-key reject count drift"
    );
    let listed: BTreeSet<&str> = m
        .content_key
        .reject
        .checks
        .iter()
        .map(String::as_str)
        .collect();
    let in_vectors: BTreeSet<&str> = vectors.iter().map(|v| v.check.as_str()).collect();
    assert_eq!(
        listed, in_vectors,
        "manifest checks vs content-key reject.json"
    );
    for required in [
        "hpke-open-failed",
        "content-cid-mismatch",
        "missing-field",
        "invalid-field-length",
        "unsupported-record-version",
        "unknown-record-field",
        "truncated",
    ] {
        assert!(
            listed.contains(required),
            "content-key reject must cover the {required} check"
        );
    }
    for required in [
        "base-mode-forgery",
        "epoch-transplant",
        "scope-transplant",
        "swapped-content-cid",
        // The version gate must outrank the exhaustive-key scan, so a blob a
        // newer build wrote stays retainable rather than being destroyed as
        // malformed grammar.
        "forward-version-unknown-frame-field",
    ] {
        assert!(
            vectors.iter().any(|v| v.name == required),
            "content-key reject must pin the {required} vector"
        );
    }

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate content-key reject {}",
            v.name
        );
        let owner = X25519Secret::from_scalar(unhex32(&v.name, &v.owner_secret));
        let scope = unhex_n::<16>(&v.name, &v.scope);
        let cid = unhex(&v.name, &v.content_cid);
        let blob = unhex(&v.name, &v.blob);
        let err = match open_content_key(&owner, &scope, v.epoch, &cid, &blob) {
            Err(e) => e,
            Ok(_) => panic!("content-key reject {}: open accepted it", v.name),
        };
        assert_eq!(
            err.check(),
            v.check,
            "content-key reject {}: check ({err})",
            v.name
        );
        assert_eq!(
            err.class(),
            v.class,
            "content-key reject {}: class ({err})",
            v.name
        );
    }
}

/// Cross-structure separation: an op record and a content-key blob sealed under
/// one enc subkey with one ephemeral differ only in their HPKE `info` and AAD,
/// so moving either sealed half into the other's frame must fail at the tag.
#[test]
fn an_op_record_and_a_content_key_blob_never_open_as_each_other() {
    let owner = X25519Secret::from_scalar([0x77; 32]);
    let eph = [0x88; 32];
    let scope = [0x99; 16];
    let epoch = 4;
    let cid = compute_cid(CONTENT_CID_CODEC, b"separation probe root block");

    let record = seal_op_record(&owner, &eph, Some(&cid), b"separation probe intent").unwrap();
    let blob = seal_content_key(&owner, &eph, &scope, epoch, &cid, &[0x5a; 32]).unwrap();

    let sealed_half = |bytes: &[u8]| {
        let value = decode(bytes).unwrap();
        let map = value.as_map().unwrap().clone();
        (
            map.get("ciphertext").unwrap().as_bytes().unwrap().to_vec(),
            map.get("enc").unwrap().as_bytes().unwrap().to_vec(),
        )
    };

    let (record_ct, record_enc) = sealed_half(&record);
    let mut as_content_key = Map::new();
    as_content_key.insert("ciphertext", Value::Bytes(record_ct));
    as_content_key.insert("enc", Value::Bytes(record_enc));
    as_content_key.insert("v", Value::Unsigned(CONTENT_KEY_V));
    assert_eq!(
        open_content_key(
            &owner,
            &scope,
            epoch,
            &cid,
            &encode(&Value::Map(as_content_key)).unwrap()
        )
        .unwrap_err()
        .check(),
        "hpke-open-failed",
        "an op record must not open as a content-key blob"
    );

    let (blob_ct, blob_enc) = sealed_half(&blob);
    let mut as_op_record = Map::new();
    as_op_record.insert("ciphertext", Value::Bytes(blob_ct));
    as_op_record.insert("contentRootCid", Value::Bytes(cid.clone()));
    as_op_record.insert("enc", Value::Bytes(blob_enc));
    as_op_record.insert("ownerTag", Value::Bytes(owner.public().to_bytes().to_vec()));
    as_op_record.insert("v", Value::Unsigned(OP_RECORD_V));
    assert_eq!(
        open_op_record(&owner, &encode(&Value::Map(as_op_record)).unwrap())
            .unwrap_err()
            .check(),
        "hpke-open-failed",
        "a content-key blob must not open as an op record"
    );
}

#[test]
fn ascent_link_accept_vectors_derive_verify_and_open() {
    let m = manifest();
    let vectors = ascent_link_accept_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.grant.ascent_link_accept.count,
        "ascent-link accept count drift"
    );
    assert!(
        !vectors.is_empty(),
        "ascent-link accept family must not be empty"
    );
    for v in &vectors {
        assert_eq!(
            v.struct_tag, STRUCT_TAG_ASCENT_LINK,
            "ascent accept {}: tag",
            v.name
        );
        let ctx = seal_ctx(&v.name, v.v, &v.id, &v.scope, v.epoch, v.struct_tag);
        assert_eq!(
            hex::encode(build_aad(&ctx)),
            v.aad,
            "ascent accept {}: aad",
            v.name
        );
        let parent_seed = unhex32(&v.name, &v.parent_node_seed);
        let container = unhex(&v.name, &v.container);
        let link = decode_ascent_link(&container)
            .unwrap_or_else(|e| panic!("ascent accept {}: container decode: {e}", v.name));
        assert_eq!(
            hex::encode(encode_ascent_link(&link).unwrap()),
            v.container,
            "ascent accept {}: container re-encode",
            v.name
        );
        assert_eq!(
            hex::encode(link.ascent_public),
            v.ascent_public,
            "ascent accept {}: public half",
            v.name
        );
        // Re-sealing to the plaintext public half under the fixed ephemeral
        // reproduces the frozen HPKE envelope (any writer with the public half
        // can re-seal).
        let plaintext = unhex(&v.name, &v.plaintext);
        let eph = unhex32(&v.name, &v.ephemeral_scalar);
        let reproduced = hpke_seal(
            &X25519Public::from_bytes(unhex32(&v.name, &v.ascent_public))
                .expect("accept-vector ascent key is adoptable"),
            &eph,
            b"",
            &build_aad(&ctx),
            &plaintext,
        );
        assert_eq!(
            reproduced.enc, link.enc,
            "ascent accept {}: enc drift",
            v.name
        );
        assert_eq!(
            reproduced.ciphertext, link.ciphertext,
            "ascent accept {}: ciphertext drift",
            v.name
        );
        // The ancestor re-derives the keypair, matches the public half, opens.
        let payload = open_ascent_link(&parent_seed, &ctx, &link)
            .unwrap_or_else(|e| panic!("ascent accept {}: open: {e}", v.name));
        assert_eq!(
            hex::encode(encode_override_seed_payload(&payload).unwrap()),
            v.plaintext,
            "ascent accept {}: opened plaintext drift",
            v.name
        );
    }
}

#[test]
fn ascent_link_reject_vectors_fail_closed() {
    let m = manifest();
    let vectors = ascent_link_reject_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.grant.ascent_link_reject.count,
        "ascent-link reject count drift"
    );
    let listed: BTreeSet<&str> = m
        .grant
        .ascent_link_reject
        .checks
        .iter()
        .map(String::as_str)
        .collect();
    let in_vectors: BTreeSet<&str> = vectors.iter().map(|v| v.check.as_str()).collect();
    assert_eq!(
        listed, in_vectors,
        "manifest checks vs ascent_link_reject.json"
    );
    assert!(
        listed.contains("ascent-link-mismatch"),
        "ascent-link reject must cover the derive-and-verify mismatch"
    );
    for v in &vectors {
        assert_eq!(
            v.struct_tag, STRUCT_TAG_ASCENT_LINK,
            "ascent reject {}: tag",
            v.name
        );
        let ctx = seal_ctx(&v.name, v.v, &v.id, &v.scope, v.epoch, v.struct_tag);
        let parent_seed = unhex32(&v.name, &v.parent_node_seed);
        let link = decode_ascent_link(&unhex(&v.name, &v.container))
            .unwrap_or_else(|e| panic!("ascent reject {}: container decode: {e}", v.name));
        let err = open_ascent_link(&parent_seed, &ctx, &link)
            .expect_err("ascent-link reject must fail closed");
        assert_eq!(
            err.check(),
            v.check,
            "ascent reject {}: check ({err})",
            v.name
        );
        assert_eq!(
            err.class(),
            v.class,
            "ascent reject {}: class ({err})",
            v.name
        );
    }
}

#[test]
fn history_link_accept_vectors_seal_reproduce_and_open() {
    let m = manifest();
    let vectors = history_link_accept_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.grant.history_link_accept.count,
        "history-link accept count drift"
    );
    assert!(
        !vectors.is_empty(),
        "history-link accept family must not be empty"
    );
    for v in &vectors {
        assert_eq!(
            v.struct_tag, STRUCT_TAG_HISTORY_LINK,
            "history accept {}: tag",
            v.name
        );
        let key = unhex32(&v.name, &v.key);
        let nonce = unhex_n::<NONCE_LEN>(&v.name, &v.nonce);
        let ctx = seal_ctx(&v.name, v.v, &v.id, &v.scope, v.epoch, v.struct_tag);
        assert_eq!(
            hex::encode(build_aad(&ctx)),
            v.aad,
            "history accept {}: aad",
            v.name
        );
        let plaintext = unhex(&v.name, &v.plaintext);
        // The fixed key + nonce reproduce the frozen sealed blob (the previous
        // epoch's seed under the current one).
        let sealed = seal::seal(&key, &nonce, &ctx, &plaintext);
        assert_eq!(
            hex::encode(&sealed),
            v.sealed,
            "history accept {}: sealed drift",
            v.name
        );
        assert_eq!(
            &sealed[..NONCE_LEN],
            &nonce,
            "history accept {}: nonce prefix",
            v.name
        );
        let opened = seal::unseal(&key, &ctx, &unhex(&v.name, &v.sealed))
            .unwrap_or_else(|e| panic!("history accept {}: unseal: {e}", v.name));
        assert_eq!(opened, plaintext, "history accept {}: plaintext", v.name);
        assert!(
            decode_history_link_payload(&plaintext).is_ok(),
            "history accept {}: payload must decode",
            v.name
        );
    }
}

#[test]
fn history_link_reject_vectors_fire_the_named_check() {
    let m = manifest();
    let vectors = history_link_reject_vectors(&m);
    check_reject_family(
        "history-link",
        &vectors,
        &m.grant.history_link_reject,
        decode_history_link_payload,
    );
    assert!(
        m.grant
            .history_link_reject
            .checks
            .iter()
            .any(|c| c == "missing-field"),
        "history-link reject must cover the missing-field check"
    );
}

#[test]
fn structure_sig_accept_vectors_verify() {
    let m = manifest();
    let vectors = structure_sig_accept_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.grant.structure_sig_accept.count,
        "structure-sig accept count drift"
    );
    assert!(
        !vectors.is_empty(),
        "structure-sig accept family must not be empty"
    );
    let mut saw_recipient_tag = false;
    let mut saw_ascent_binding = false;
    for v in &vectors {
        let scope_id = unhex_n::<16>(&v.name, &v.scope_id);
        let signed_bytes = unhex(&v.name, &v.signed_bytes);
        if let Some(b) = &v.ascent_binding {
            saw_ascent_binding = true;
            assert_eq!(
                hex::encode(ascent_link_sig_body(
                    &unhex32(&v.name, &b.ascent_public),
                    &unhex32(&v.name, &b.enc),
                    &unhex(&v.name, &b.ciphertext),
                )),
                v.signed_bytes,
                "structure-sig accept {}: ascent binding drift",
                v.name
            );
        }
        // H(signed bytes) is the frozen BLAKE3 digest.
        assert_eq!(
            hex::encode(hash(&signed_bytes)),
            v.ciphertext_hash,
            "structure-sig accept {}: ciphertext hash",
            v.name
        );
        let recipient_tag = opt_tag(&v.name, &v.recipient_tag);
        saw_recipient_tag |= recipient_tag.is_some();
        let input = StructureSigInput::over_ciphertext(
            scope_id,
            v.epoch,
            v.struct_tag,
            recipient_tag,
            &signed_bytes,
        );
        // The preimage is frozen.
        assert_eq!(
            hex::encode(structure_sig_preimage(&input)),
            v.preimage,
            "structure-sig accept {}: preimage drift",
            v.name
        );
        // The frozen verifier is exactly the pseudonym pk of the frozen signer
        // seed, so freezing the seed freezes the accepting key.
        let signer = Ed25519Signer::from_seed(unhex32(&v.name, &v.signer_seed));
        assert_eq!(
            hex::encode(signer.verifying_key().to_bytes()),
            v.verifier_pk,
            "structure-sig accept {}: verifier is the signer's pk",
            v.name
        );
        let verifier = Ed25519Verifier::from_bytes(unhex32(&v.name, &v.verifier_pk))
            .expect("valid pseudonym pk");
        let sig = Ed25519Signature::from_bytes(unhex_n::<64>(&v.name, &v.signature));
        assert!(
            verify_structure(&verifier, &input, &sig).is_ok(),
            "structure-sig accept {}: must verify",
            v.name
        );
    }
    assert!(
        saw_recipient_tag,
        "a grant-blob structure signature must carry a recipient tag"
    );
    assert!(
        saw_ascent_binding,
        "an ascent-link structure signature must bind its plaintext public half"
    );
}

#[test]
fn structure_sig_reject_vectors_fail_closed() {
    let m = manifest();
    let vectors = structure_sig_reject_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.grant.structure_sig_reject.count,
        "structure-sig reject count drift"
    );
    let listed: BTreeSet<&str> = m
        .grant
        .structure_sig_reject
        .checks
        .iter()
        .map(String::as_str)
        .collect();
    let in_vectors: BTreeSet<&str> = vectors.iter().map(|v| v.check.as_str()).collect();
    assert_eq!(
        listed, in_vectors,
        "manifest checks vs structure_sig_reject.json"
    );
    // Anti-vacuity: the forgery + two transplant cases are all present.
    let names: BTreeSet<&str> = vectors.iter().map(|v| v.name.as_str()).collect();
    for required in [
        "bad-signature",
        "wrong-tag",
        "recipient-tag-transplant",
        "ascent-public-swapped",
    ] {
        assert!(
            names.contains(required),
            "structure-sig reject must cover {required}"
        );
    }
    let mut saw_ascent_binding = false;
    for v in &vectors {
        if let Some(b) = &v.ascent_binding {
            // The swapped public half is what the verify-side hash covers.
            saw_ascent_binding = true;
            assert_eq!(
                hex::encode(hash(&ascent_link_sig_body(
                    &unhex32(&v.name, &b.ascent_public),
                    &unhex32(&v.name, &b.enc),
                    &unhex(&v.name, &b.ciphertext),
                ))),
                v.ciphertext_hash,
                "structure-sig reject {}: ascent binding drift",
                v.name
            );
        }
        // Rebuild the verify-side input directly (the frozen ciphertext hash and
        // the transplanted tag/recipient-tag).
        let input = StructureSigInput {
            scope_id: unhex_n::<16>(&v.name, &v.scope_id),
            epoch: v.epoch,
            struct_tag: v.struct_tag,
            recipient_tag: opt_tag(&v.name, &v.recipient_tag),
            ciphertext_hash: unhex32(&v.name, &v.ciphertext_hash),
        };
        let verifier = Ed25519Verifier::from_bytes(unhex32(&v.name, &v.verifier_pk))
            .expect("valid pseudonym pk");
        let sig = Ed25519Signature::from_bytes(unhex_n::<64>(&v.name, &v.signature));
        let err = verify_structure(&verifier, &input, &sig)
            .expect_err("structure-sig reject must fail closed");
        assert_eq!(
            err.check(),
            v.check,
            "structure-sig reject {}: check ({err})",
            v.name
        );
        assert_eq!(
            err.class(),
            v.class,
            "structure-sig reject {}: class",
            v.name
        );
    }
    assert!(
        saw_ascent_binding,
        "the ascent-public swap must carry its binding fields"
    );
}

#[test]
fn grant_set_accept_vectors_decode_and_verify() {
    let m = manifest();
    let vectors = grant_set_accept_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.grant.grant_set_accept.count,
        "grant-set accept count drift"
    );
    assert!(
        !vectors.is_empty(),
        "grant-set accept family must not be empty"
    );
    for v in &vectors {
        let bytes = unhex(&v.name, &v.commitment);
        let c = decode_grant_set_commitment(&bytes)
            .unwrap_or_else(|e| panic!("grant-set accept {}: decode: {e}", v.name));
        assert_eq!(
            hex::encode(encode_grant_set_commitment(&c).expect("accept vector re-encodes")),
            v.commitment,
            "grant-set accept {}: re-encode must be byte-identical",
            v.name
        );
        let verifier = EcdsaVerifier::from_sec1(&unhex(&v.name, &v.owner_identity_pk))
            .expect("valid owner identity key");
        let sig = EcdsaSignature::from_compact(&unhex(&v.name, &v.signature))
            .expect("valid owner signature");
        assert!(
            verify_grant_set(&verifier, &c, &sig).is_ok(),
            "grant-set accept {}: must verify",
            v.name
        );
    }
}

#[test]
fn grant_set_reject_vectors_fail_closed() {
    let m = manifest();
    let vectors = grant_set_reject_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.grant.grant_set_reject.count,
        "grant-set reject count drift"
    );
    let listed: BTreeSet<&str> = m
        .grant
        .grant_set_reject
        .checks
        .iter()
        .map(String::as_str)
        .collect();
    let in_vectors: BTreeSet<&str> = vectors.iter().map(|v| v.check.as_str()).collect();
    assert_eq!(
        listed, in_vectors,
        "manifest checks vs grant_set_reject.json"
    );
    assert!(
        listed.contains("commitment-invalid"),
        "grant-set reject must cover the owner-signature failure"
    );
    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate grant-set reject {}",
            v.name
        );
        let bytes = unhex(&v.name, &v.commitment);
        match decode_grant_set_commitment(&bytes) {
            Err(e) => {
                // A commitment-codec defect: no signature is exercised.
                assert!(
                    v.signature.is_empty(),
                    "grant-set reject {}: a codec defect carries no signature",
                    v.name
                );
                assert_eq!(
                    e.check(),
                    v.check,
                    "grant-set reject {}: check ({e})",
                    v.name
                );
                assert_eq!(e.class(), v.class, "grant-set reject {}: class", v.name);
            }
            Ok(c) => {
                // The commitment decodes: the owner signature must fail to verify.
                let verifier = EcdsaVerifier::from_sec1(&unhex(&v.name, &v.owner_identity_pk))
                    .expect("valid owner identity key");
                let sig = EcdsaSignature::from_compact(&unhex(&v.name, &v.signature))
                    .expect("valid signature encoding");
                let err = verify_grant_set(&verifier, &c, &sig)
                    .expect_err("grant-set verify reject must fail closed");
                assert_eq!(
                    err.check(),
                    v.check,
                    "grant-set reject {}: check ({err})",
                    v.name
                );
                assert_eq!(err.class(), v.class, "grant-set reject {}: class", v.name);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Content plane: the content-seal primitive over caller-framed chunks and the
// content-DAG CID compute/verify codec. Frozen CIDv1 codec bytes, the
// fixed-parameter seal KAT, deterministic CID KATs (byte-identical native +
// wasm32), and the fail-closed open / verify reject families.
// ---------------------------------------------------------------------------

#[test]
fn content_cid_codec_bytes_are_frozen() {
    let m = manifest();
    // raw (0x55) multicodec + BLAKE3 (0x1e) multihash + 36-byte CIDv1 length,
    // pinned to the crate constants so a codec/multihash change is caught here.
    assert_eq!(m.content.cid_codec, CONTENT_CID_CODEC, "cid codec drift");
    assert_eq!(m.content.cid_codec, 0x55, "content CID multicodec is raw");
    assert_eq!(
        m.content.cid_multihash, CONTENT_CID_MULTIHASH,
        "cid multihash drift"
    );
    assert_eq!(
        m.content.cid_multihash, 0x1e,
        "content CID multihash is BLAKE3-256"
    );
    assert_eq!(m.content.cid_len, CONTENT_CID_LEN, "cid length drift");
    assert_eq!(m.content.cid_len, 36, "CIDv1 raw||blake3 is 36 bytes");
}

#[test]
fn content_seal_vectors_are_frozen_and_round_trip() {
    let m = manifest();
    let vectors = content_seal_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.content.seal.count,
        "content seal count drift"
    );
    assert!(!vectors.is_empty(), "content seal family must not be empty");

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate content seal {}",
            v.name
        );
        let key = unhex32(&v.name, &v.key);
        let nonce = unhex_n::<NONCE_LEN>(&v.name, &v.nonce);
        let plaintext = unhex(&v.name, &v.plaintext);

        // Fixed key + nonce reproduce the sealed blob byte-for-byte.
        let sealed = seal_chunk(&key, &nonce, &plaintext);
        assert_eq!(
            hex::encode(&sealed),
            v.sealed,
            "content seal {}: sealed drift",
            v.name
        );
        assert_eq!(
            &sealed[..NONCE_LEN],
            &nonce,
            "content seal {}: nonce prefix",
            v.name
        );
        let opened = open_chunk(&key, &unhex(&v.name, &v.sealed))
            .unwrap_or_else(|e| panic!("content seal {}: open must recover: {e}", v.name));
        assert_eq!(opened, plaintext, "content seal {}: plaintext", v.name);
    }
}

#[test]
fn content_seal_open_reject_vectors_fail_closed() {
    let m = manifest();
    let vectors = content_seal_reject_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.content.seal_reject.count,
        "content seal-reject count drift"
    );
    assert!(
        !vectors.is_empty(),
        "content seal-reject family must not be empty"
    );

    let listed: BTreeSet<&str> = m
        .content
        .seal_reject
        .checks
        .iter()
        .map(String::as_str)
        .collect();
    let in_vectors: BTreeSet<&str> = vectors.iter().map(|v| v.check.as_str()).collect();
    assert_eq!(
        listed, in_vectors,
        "manifest checks vs content seal_reject.json"
    );

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate content seal-reject {}",
            v.name
        );
        let key = unhex32(&v.name, &v.key);
        let err = open_chunk(&key, &unhex(&v.name, &v.sealed))
            .expect_err("content open-reject must fail closed");
        assert_eq!(
            err.check(),
            v.check,
            "content open-reject {}: check ({err})",
            v.name
        );
        assert_eq!(
            err.class(),
            v.class,
            "content open-reject {}: class",
            v.name
        );
    }
}

#[test]
fn content_cid_vectors_are_frozen_and_verify() {
    let m = manifest();
    let vectors = content_cid_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.content.cid.count,
        "content cid count drift"
    );
    assert!(!vectors.is_empty(), "content cid family must not be empty");

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate content cid {}",
            v.name
        );
        let sealed = unhex(&v.name, &v.sealed);
        // Deterministic CIDv1 under the vector's codec (raw leaf or a non-raw
        // DAG root), byte-identical here on native and, under the same harness,
        // wasm32 — the parameterized codec must not perturb the digest.
        let cid = compute_cid(v.codec, &sealed);
        assert_eq!(
            hex::encode(&cid),
            v.cid,
            "content cid {}: cid drift",
            v.name
        );
        assert_eq!(cid.len(), CONTENT_CID_LEN, "content cid {}: length", v.name);
        assert_eq!(
            cid[..4],
            [0x01, v.codec, CONTENT_CID_MULTIHASH, 0x20],
            "content cid {}: v1||codec||blake3||len prefix",
            v.name
        );
        verify_cid(&cid, &sealed)
            .unwrap_or_else(|e| panic!("content cid {}: verify must accept: {e}", v.name));
    }
}

#[test]
fn content_cid_reject_vectors_fail_closed() {
    let m = manifest();
    let vectors = content_cid_reject_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.content.cid_reject.count,
        "content cid-reject count drift"
    );
    assert!(
        !vectors.is_empty(),
        "content cid-reject family must not be empty"
    );

    let listed: BTreeSet<&str> = m
        .content
        .cid_reject
        .checks
        .iter()
        .map(String::as_str)
        .collect();
    let in_vectors: BTreeSet<&str> = vectors.iter().map(|v| v.check.as_str()).collect();
    assert_eq!(
        listed, in_vectors,
        "manifest checks vs content cid_reject.json"
    );
    assert!(
        listed.contains("content-cid-mismatch"),
        "content cid-reject must cover content-cid-mismatch"
    );

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate content cid-reject {}",
            v.name
        );
        let claimed = unhex(&v.name, &v.cid);
        let sealed = unhex(&v.name, &v.sealed);
        let err = verify_cid(&claimed, &sealed).expect_err("cid-reject must fail closed");
        assert_eq!(
            err.check(),
            v.check,
            "content cid-reject {}: check ({err})",
            v.name
        );
        assert_eq!(err.class(), v.class, "content cid-reject {}: class", v.name);
    }
}

#[test]
fn content_cid_str_accept_vectors_round_trip() {
    let m = manifest();
    let vectors = content_cid_str_accept_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.content.cid_str_accept.count,
        "content cid-str-accept count drift"
    );
    assert!(
        !vectors.is_empty(),
        "content cid-str-accept family must not be empty"
    );

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate content cid-str {}",
            v.name
        );
        let cid = unhex(&v.name, &v.cid);
        // Encode: the binary CID renders to its one canonical base32-lower string.
        assert_eq!(
            encode_content_cid_str(&cid),
            v.cid_str,
            "content cid-str {}: encode drift",
            v.name
        );
        assert!(
            v.cid_str.starts_with('b'),
            "content cid-str {}: base32 multibase prefix",
            v.name
        );
        // Strict decode recovers the binary anchor byte-for-byte.
        let decoded = decode_content_cid_str(&v.cid_str)
            .unwrap_or_else(|e| panic!("content cid-str {}: decode rejected: {e}", v.name));
        assert_eq!(decoded, cid, "content cid-str {}: decode drift", v.name);
    }
}

#[test]
fn content_cid_str_reject_vectors_fail_closed() {
    let m = manifest();
    let vectors = content_cid_str_reject_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.content.cid_str_reject.count,
        "content cid-str-reject count drift"
    );
    assert!(
        !vectors.is_empty(),
        "content cid-str-reject family must not be empty"
    );

    let listed: BTreeSet<&str> = m
        .content
        .cid_str_reject
        .checks
        .iter()
        .map(String::as_str)
        .collect();
    let in_vectors: BTreeSet<&str> = vectors.iter().map(|v| v.check.as_str()).collect();
    assert_eq!(
        listed, in_vectors,
        "manifest checks vs content cid_str_reject.json"
    );
    assert!(
        listed.contains("content-cid-str-malformed"),
        "content cid-str-reject covers content-cid-str-malformed"
    );

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate content cid-str-reject {}",
            v.name
        );
        let err = decode_content_cid_str(&v.text).expect_err("cid-str-reject must fail closed");
        assert_eq!(
            err.check(),
            v.check,
            "content cid-str-reject {}: check ({err})",
            v.name
        );
        assert_eq!(
            err.class(),
            v.class,
            "content cid-str-reject {}: class",
            v.name
        );
    }
}

#[test]
fn owner_local_kind_registry_is_frozen() {
    let m = manifest();
    assert_eq!(m.owner_local.struct_tag, STRUCT_TAG_OWNER_LOCAL);
    assert_eq!(m.owner_local.v, OWNER_LOCAL_V);
    assert_eq!(m.owner_local.hpke_mode, MODE_AUTH);
    assert_eq!(
        m.owner_local.hpke_info_prefix.as_bytes(),
        OWNER_LOCAL_HPKE_INFO_PREFIX
    );
    assert_eq!(
        m.owner_local.kinds.len(),
        OwnerLocalKind::ALL.len(),
        "owner-local kind count drift"
    );

    for (spec, kind) in m.owner_local.kinds.iter().zip(OwnerLocalKind::ALL) {
        assert_eq!(spec.name, kind.name(), "owner-local kind order/name drift");
        assert_eq!(
            spec.discriminator,
            kind.discriminator(),
            "owner-local {}: discriminator drift",
            spec.name
        );
        assert_eq!(
            spec.hpke_info.as_bytes(),
            kind.hpke_info(),
            "owner-local {}: info string drift",
            spec.name
        );
    }
}

/// The enc-subkey structures are only non-transplantable while their key
/// schedules differ, and `owner-local` is the first family whose `info` string
/// is computed rather than a literal — so a collision first becomes possible
/// here.
#[test]
fn every_enc_subkey_hpke_info_string_is_distinct() {
    let mut infos: Vec<&[u8]> = vec![
        OP_RECORD_HPKE_INFO,
        SETTINGS_RECORD_HPKE_INFO,
        CONTENT_KEY_HPKE_INFO,
    ];
    let owner_local: Vec<Vec<u8>> = OwnerLocalKind::ALL.iter().map(|k| k.hpke_info()).collect();
    infos.extend(owner_local.iter().map(Vec::as_slice));
    assert_eq!(
        infos.iter().collect::<BTreeSet<_>>().len(),
        infos.len(),
        "two structures sealed to one enc subkey share a key schedule"
    );
}

#[test]
fn owner_local_accept_vectors_seal_reproduce_and_open() {
    let m = manifest();
    let vectors = owner_local_accept_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.owner_local.accept.count,
        "owner-local accept count drift"
    );
    assert!(
        vectors.iter().any(|v| v.body.is_empty()) && vectors.iter().any(|v| !v.body.is_empty()),
        "owner-local accept must cover both an empty and a populated body"
    );
    let covered_kinds: BTreeSet<&str> = vectors.iter().map(|v| v.kind.as_str()).collect();
    for kind in OwnerLocalKind::ALL {
        assert!(
            covered_kinds.contains(kind.name()),
            "owner-local accept must pin a blob for the {} kind",
            kind.name()
        );
    }

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate owner-local accept {}",
            v.name
        );
        let kind = owner_local_kind(&v.kind);
        let owner = X25519Secret::from_scalar(unhex32(&v.name, &v.owner_secret));
        let owner_public = unhex32(&v.name, &v.owner_public);
        assert_eq!(
            owner.public().to_bytes(),
            owner_public,
            "owner-local accept {}: owner keypair",
            v.name
        );
        let eph = unhex32(&v.name, &v.ephemeral_scalar);
        let body = unhex(&v.name, &v.body);

        let sealed = seal_owner_local(&owner, kind, &eph, &body)
            .unwrap_or_else(|e| panic!("owner-local accept {}: seal ({e})", v.name));
        assert_eq!(
            hex::encode(&sealed),
            v.blob,
            "owner-local accept {}: blob drift",
            v.name
        );

        let blob = unhex(&v.name, &v.blob);
        // The owner tag and the kind stay AAD-bound and unserialized, so a blob
        // naming a key or a store that cannot open it is unrepresentable.
        let decoded =
            decode(&blob).unwrap_or_else(|e| panic!("owner-local accept {}: decode ({e})", v.name));
        let keys: Vec<&str> = decoded
            .as_map()
            .unwrap_or_else(|e| panic!("owner-local accept {}: map ({e})", v.name))
            .entries()
            .iter()
            .map(|(k, _)| k.as_str())
            .collect();
        assert_eq!(
            keys,
            ["v", "enc", "ciphertext"],
            "owner-local accept {}: clear header must carry neither the owner tag nor the kind",
            v.name
        );

        let plaintext = open_owner_local(&owner, kind, &blob)
            .unwrap_or_else(|e| panic!("owner-local accept {}: open ({e})", v.name));
        assert_eq!(
            &plaintext[..],
            &body[..],
            "owner-local accept {}: body",
            v.name
        );
    }
}

#[test]
fn owner_local_reject_vectors_fire_the_named_check() {
    let m = manifest();
    let vectors = owner_local_reject_vectors(&m);
    assert_eq!(
        vectors.len(),
        m.owner_local.reject.count,
        "owner-local reject count drift"
    );
    let listed: BTreeSet<&str> = m
        .owner_local
        .reject
        .checks
        .iter()
        .map(String::as_str)
        .collect();
    let in_vectors: BTreeSet<&str> = vectors.iter().map(|v| v.check.as_str()).collect();
    assert_eq!(
        listed, in_vectors,
        "manifest checks vs owner-local reject.json"
    );
    for required in [
        "hpke-open-failed",
        "hpke-non-contributory",
        "invalid-field-length",
        "missing-field",
        "unsupported-record-version",
        "unknown-record-field",
    ] {
        assert!(
            listed.contains(required),
            "owner-local reject must cover the {required} check"
        );
    }

    assert!(
        vectors.iter().any(|v| v.name == "base-mode-forgery"),
        "owner-local reject must pin a base-mode forgery under the owner's own tag"
    );
    // Key-schedule separation, not framing: the settings record shares this
    // frame and version byte, so only the struct tag and the distinct info
    // string can refuse it.
    assert!(
        vectors.iter().any(|v| v.name == "cross-family-transplant"),
        "owner-local reject must pin a cross-family transplant from the settings record"
    );

    let mut names = BTreeSet::new();
    for v in &vectors {
        assert!(
            names.insert(v.name.clone()),
            "duplicate owner-local reject {}",
            v.name
        );
        let kind = owner_local_kind(&v.kind);
        let owner = X25519Secret::from_scalar(unhex32(&v.name, &v.owner_secret));
        let blob = unhex(&v.name, &v.blob);
        let err = match open_owner_local(&owner, kind, &blob) {
            Err(e) => e,
            Ok(_) => panic!("owner-local reject {}: open accepted it", v.name),
        };
        assert_eq!(
            err.check(),
            v.check,
            "owner-local reject {}: check ({err})",
            v.name
        );
        assert_eq!(
            err.class(),
            v.class,
            "owner-local reject {}: class ({err})",
            v.name
        );
    }
}

/// The vector the kind discriminator exists to justify: the failure must land at
/// the AEAD rather than at a comparison.
#[test]
fn owner_local_cross_kind_vectors_cover_every_ordered_pair() {
    let m = manifest();
    let vectors = owner_local_reject_vectors(&m);

    for sealed_as in OwnerLocalKind::ALL {
        for opened_as in OwnerLocalKind::ALL {
            if sealed_as == opened_as {
                continue;
            }
            let name = format!("cross-kind-{}-as-{}", sealed_as.name(), opened_as.name());
            let v = vectors
                .iter()
                .find(|v| v.name == name)
                .unwrap_or_else(|| panic!("owner-local reject must pin {name}"));
            assert_eq!(
                v.kind,
                opened_as.name(),
                "{name}: the vector must open under the other kind"
            );
            assert_eq!(
                (v.check.as_str(), v.class.as_str()),
                ("hpke-open-failed", "trust"),
                "{name}: cross-kind separation must be a decryption failure, not a parse failure"
            );

            // The blob is a real blob of its own kind: the pair only proves
            // separation while the sealing kind still opens it.
            let owner = X25519Secret::from_scalar(unhex32(&name, &v.owner_secret));
            let blob = unhex(&name, &v.blob);
            assert!(
                open_owner_local(&owner, sealed_as, &blob).is_ok(),
                "{name}: the blob must open under the kind it was sealed as"
            );
        }
    }
}
