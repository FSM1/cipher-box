//! The KAT manifest job (blueprint/core.md "KAT regime", blueprint/testing.md
//! "crates/core — KATs and property tests"): merge-blocking, machine-checked.
//!
//! Fixtures are embedded with `include_str!` — never loaded from the
//! filesystem at runtime — so the same suite runs natively and under
//! wasm32-wasip1 (the residual parity surface). Vectors regenerate only
//! through the committed generator (`examples/kat_gen.rs`); the exact counts
//! and coverage lists here are the anti-vacuity backstop.

use std::collections::BTreeSet;

// On wasm32-unknown-unknown (the browser-shaped KAT leg) there is no libtest
// harness; wasm-bindgen-test provides one. Shadowing `test` with its attribute
// runs every `#[test]` below under wasm-bindgen-test-runner unchanged, while
// native and wasm32-wasip1 keep the built-in `#[test]`.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test as test;

use cipherbox_core::codec::{decode, decode_map_partial, encode, encode_map_partial};
use cipherbox_core::content::{
    CONTENT_CID_CODEC, CONTENT_CID_LEN, CONTENT_CID_MULTIHASH, compute_cid, open_chunk, seal_chunk,
    verify_cid,
};
use cipherbox_core::error::{Malformed, TrustViolation};
use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf::{self, EDGES, EdgeProbe};
use cipherbox_core::payload::mailbox::{open_mailbox_payload, seal_mailbox_payload};
use cipherbox_core::payload::pointer::{RepointObject, open_pointer_payload, seal_pointer_payload};
use cipherbox_core::seal::{
    self, AAD_DOMAIN, AadContext, NodeKind, STRUCT_TAG_ASCENT_LINK, STRUCT_TAG_GRANT_BLOB,
    STRUCT_TAG_HISTORY_LINK, STRUCT_TAG_OWNER_BLOB, STRUCT_TAG_READ_BODY, STRUCT_TAG_WRITE_BODY,
    STRUCT_TAGS, StructureSigInput, build_aad, decode_ascent_link, decode_envelope,
    decode_grant_blob_payload, decode_grant_set_commitment, decode_history_link_payload,
    decode_override_seed_payload, decode_read_body, decode_write_body, encode_ascent_link,
    encode_envelope, encode_grant_set_commitment, encode_override_seed_payload, encode_read_body,
    encode_write_body, open_ascent_link, open_read_body, structure_sig_preimage, verify_grant_set,
    verify_structure,
};
use cipherbox_core::suite::aead::NONCE_LEN;
use cipherbox_core::suite::contact::import_contact_code;
use cipherbox_core::suite::ecdsa::{EcdsaSignature, EcdsaSigner, EcdsaVerifier};
use cipherbox_core::suite::ed25519::{Ed25519Signature, Ed25519Signer, Ed25519Verifier};
use cipherbox_core::suite::hash::hash;
use cipherbox_core::suite::hpke::{hpke_open, hpke_seal};
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

// --- Grant section (ticket #621) schema ------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GrantManifest {
    write_body_struct_tag: u8,
    grant_blob_struct_tag: u8,
    owner_blob_struct_tag: u8,
    ascent_link_struct_tag: u8,
    history_link_struct_tag: u8,
    write_body_accept: FileCount,
    write_body_reject: RejectSection,
    grant_blob_accept: FileCount,
    grant_blob_reject: RejectSection,
    owner_blob_accept: FileCount,
    owner_blob_reject: RejectSection,
    ascent_link_accept: FileCount,
    ascent_link_reject: RejectSection,
    history_link_accept: FileCount,
    history_link_reject: RejectSection,
    structure_sig_accept: FileCount,
    structure_sig_reject: RejectSection,
    grant_set_accept: FileCount,
    grant_set_reject: RejectSection,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WriteBodyAcceptVector {
    name: String,
    hex: String,
    ledger_count: usize,
    child_scope_count: usize,
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
    ciphertext: String,
    ciphertext_hash: String,
    preimage: String,
    signature: String,
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

fn grant_blob_accept_vectors(m: &Manifest) -> Vec<HpkeStructureVector> {
    serde_json::from_str(fixture(&m.grant.grant_blob_accept.file)).expect("grant_blob_accept shape")
}

fn grant_blob_reject_vectors(m: &Manifest) -> Vec<RejectVector> {
    serde_json::from_str(fixture(&m.grant.grant_blob_reject.file)).expect("grant_blob_reject shape")
}

fn owner_blob_accept_vectors(m: &Manifest) -> Vec<HpkeStructureVector> {
    serde_json::from_str(fixture(&m.grant.owner_blob_accept.file)).expect("owner_blob_accept shape")
}

fn owner_blob_reject_vectors(m: &Manifest) -> Vec<RejectVector> {
    serde_json::from_str(fixture(&m.grant.owner_blob_reject.file)).expect("owner_blob_reject shape")
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
        m.grant.grant_blob_accept.file.as_str(),
        m.grant.grant_blob_reject.file.as_str(),
        m.grant.owner_blob_accept.file.as_str(),
        m.grant.owner_blob_reject.file.as_str(),
        m.grant.ascent_link_accept.file.as_str(),
        m.grant.ascent_link_reject.file.as_str(),
        m.grant.history_link_accept.file.as_str(),
        m.grant.history_link_reject.file.as_str(),
        m.grant.structure_sig_accept.file.as_str(),
        m.grant.structure_sig_reject.file.as_str(),
        m.grant.grant_set_accept.file.as_str(),
        m.grant.grant_set_reject.file.as_str(),
        m.content.seal.file.as_str(),
        m.content.seal_reject.file.as_str(),
        m.content.cid.file.as_str(),
        m.content.cid_reject.file.as_str(),
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

/// The whole error surface is vector-pinned save the one check `decode` and the
/// suite decoders can never emit: `unknown-field-collision` (an
/// `encode_map_partial` caller bug), which stays unit-test-pinned in
/// src/codec/fields.rs. This is the crate-wide extension of the reject-coverage
/// law across the codec, contact, hpke, seal, ipns, and payload families.
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
    // Grant-family reject families (ticket #621).
    covered.extend(write_body_reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(grant_blob_reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(owner_blob_reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(history_link_reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(ascent_link_reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(
        structure_sig_reject_vectors(&m)
            .into_iter()
            .map(|v| v.check),
    );
    covered.extend(grant_set_reject_vectors(&m).into_iter().map(|v| v.check));
    // Content plane (ticket #691): the content-open and content-CID reject
    // families pin `seal-open-failed`/`truncated` and `content-cid-mismatch`.
    covered.extend(content_seal_reject_vectors(&m).into_iter().map(|v| v.check));
    covered.extend(content_cid_reject_vectors(&m).into_iter().map(|v| v.check));

    let surface: BTreeSet<String> = TrustViolation::CHECKS
        .iter()
        .chain(Malformed::CHECKS)
        .map(|s| s.to_string())
        .collect();
    let uncovered: Vec<&String> = surface.difference(&covered).collect();
    let expected_uncovered = "unknown-field-collision".to_string();
    assert_eq!(
        uncovered,
        vec![&expected_uncovered],
        "every crate check but the one unit-pinned collision check must have a reject vector"
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
            hex::encode(encode(&value)),
            v.hex,
            "accept vector {}: re-encode must be byte-identical",
            v.name
        );
        assert_eq!(
            value.to_string(),
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
            Ok(value) => panic!("reject vector {}: decoder accepted it as {value}", v.name),
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
];

#[test]
fn structure_tag_registry_is_complete_and_frozen() {
    let m = manifest();

    // The crate STRUCT_TABLE, the canonical anchor, and the manifest all agree
    // name-for-byte, and the byte-space is exactly the eight frozen tags.
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
        // The nonce is prefixed, and the recipient recovers the plaintext.
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
                encode_read_body(&body),
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
            hex::encode(encode_read_body(&body)),
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
    // Both kinds are exercised.
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
            hex::encode(encode_envelope(&env)),
            v.envelope,
            "envelope accept {}: re-encode must be byte-identical",
            v.name
        );
        // The read-body opens under the frozen key and equals the frozen
        // plaintext (the full symmetric-seal path).
        let body = open_read_body(&env, &key)
            .unwrap_or_else(|e| panic!("envelope accept {}: open: {e}", v.name));
        assert_eq!(
            hex::encode(encode_read_body(&body)),
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
// KDF edge catalog: the fourteen frozen edges, their contexts + layouts, the
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
    "pseudonym-sign",
    "owner-pointer-seed",
    "scope-pointer",
    "pointer-read-key",
    "vault-pointer-index",
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
        let recipient_public = X25519Public::from_bytes(unhex32(&v.name, &v.recipient_public));
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

        // And the recipient must recover the plaintext.
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
        assert_eq!(v.check, "hpke-open-failed", "open-reject {}: check", v.name);
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
        assert_eq!(err.check(), "hpke-open-failed", "open-reject {}", v.name);
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
        // Re-encode is byte-stable, and the components match the vector.
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
// IPNS records + name codec, and pointer + mailbox payloads (ticket #622). The
// name codec, the fixed-key injected-timestamp full-record KATs, the keyless
// byte-stable re-PUT, and the pointer/mailbox accept+reject vectors — all
// consumed from the manifest and asserted against the live modules.
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
        // Encode: the frozen name is the key's one canonical name.
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
        // Keyless re-PUT is byte-stable.
        let reparsed = IpnsRecord::unmarshal(&record)
            .unwrap_or_else(|e| panic!("record-accept {}: unmarshal: {e}", v.name));
        assert_eq!(
            reparsed.marshal(),
            record,
            "record-accept {}: re-PUT byte-stable",
            v.name
        );
        // Verify under the name's key extracts the injected fields.
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
        // And it opens back to the object under the owner's identity key.
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
        let recipient_public = X25519Public::from_bytes(unhex32(&v.name, &v.recipient_public));
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
        // The recipient opens and the sender identity verifies.
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
// Grant section (ticket #621): the write-body, the grant/owner blobs, the
// ascent + history links, the structure signatures, and the grant-set
// commitment. Each family's accept vectors round-trip / reproduce / verify
// against the live code, and its reject vectors fire the named fail-closed
// check.
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

#[test]
fn grant_struct_tags_are_frozen() {
    let m = manifest();
    assert_eq!(m.grant.write_body_struct_tag, STRUCT_TAG_WRITE_BODY);
    assert_eq!(m.grant.grant_blob_struct_tag, STRUCT_TAG_GRANT_BLOB);
    assert_eq!(m.grant.owner_blob_struct_tag, STRUCT_TAG_OWNER_BLOB);
    assert_eq!(m.grant.ascent_link_struct_tag, STRUCT_TAG_ASCENT_LINK);
    assert_eq!(m.grant.history_link_struct_tag, STRUCT_TAG_HISTORY_LINK);
    // The frozen byte-space (mirrors ALL_STRUCT_TAGS).
    assert_eq!(STRUCT_TAG_WRITE_BODY, 2);
    assert_eq!(STRUCT_TAG_GRANT_BLOB, 3);
    assert_eq!(STRUCT_TAG_OWNER_BLOB, 4);
    assert_eq!(STRUCT_TAG_ASCENT_LINK, 5);
    assert_eq!(STRUCT_TAG_HISTORY_LINK, 6);
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
            hex::encode(encode_write_body(&body)),
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
    let recipient_public = X25519Public::from_bytes(unhex32(&v.name, &v.recipient_public));
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
    check_reject_family(
        "grant-blob",
        &vectors,
        &m.grant.grant_blob_reject,
        decode_grant_blob_payload,
    );
    assert!(
        m.grant
            .grant_blob_reject
            .checks
            .iter()
            .any(|c| c == "missing-field"),
        "grant-blob reject must cover the missing-field check"
    );
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
    check_reject_family(
        "owner-blob",
        &vectors,
        &m.grant.owner_blob_reject,
        decode_override_seed_payload,
    );
    assert!(
        m.grant
            .owner_blob_reject
            .checks
            .iter()
            .any(|c| c == "missing-field"),
        "owner-blob reject must cover the missing-field check"
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
            hex::encode(encode_ascent_link(&link)),
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
            &X25519Public::from_bytes(unhex32(&v.name, &v.ascent_public)),
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
            hex::encode(encode_override_seed_payload(&payload)),
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
    for v in &vectors {
        let scope_id = unhex_n::<16>(&v.name, &v.scope_id);
        let ciphertext = unhex(&v.name, &v.ciphertext);
        // H(ciphertext) is the frozen BLAKE3 digest.
        assert_eq!(
            hex::encode(hash(&ciphertext)),
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
            &ciphertext,
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
    for required in ["bad-signature", "wrong-tag", "recipient-tag-transplant"] {
        assert!(
            names.contains(required),
            "structure-sig reject must cover {required}"
        );
    }
    for v in &vectors {
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
            hex::encode(encode_grant_set_commitment(&c)),
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
// Content plane (ticket #691): the content-seal primitive over caller-framed
// chunks and the content-DAG CID compute/verify codec. Frozen CIDv1 codec bytes,
// the fixed-parameter seal KAT, deterministic CID KATs (byte-identical native +
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
        // The nonce is prefixed and the recipient recovers the plaintext.
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
        // Deterministic CIDv1 over fixed sealed bytes, byte-identical here on
        // native and (under the same harness) wasm32.
        let cid = compute_cid(&sealed);
        assert_eq!(
            hex::encode(&cid),
            v.cid,
            "content cid {}: cid drift",
            v.name
        );
        assert_eq!(cid.len(), CONTENT_CID_LEN, "content cid {}: length", v.name);
        assert_eq!(
            cid[..4],
            [0x01, CONTENT_CID_CODEC, CONTENT_CID_MULTIHASH, 0x20],
            "content cid {}: v1||raw||blake3||len prefix",
            v.name
        );
        // Verify accepts the blob against its own CID.
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
