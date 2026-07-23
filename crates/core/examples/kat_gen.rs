//! The committed KAT generator for the det-CBOR codec fixtures
//! (blueprint/core.md "KAT regime": vectors regenerate only through committed
//! generators, never hand-edits).
//!
//! Run from any cwd:
//!
//! ```text
//! cargo run -p cipherbox-core --example kat_gen
//! ```
//!
//! Accept and unknown-field vectors are built from [`Value`] constructors and
//! the live encoder. Reject vectors are explicit hand-crafted byte literals —
//! deriving them from the encoder would be vacuous, since the deterministic
//! encoder cannot emit any of them. Every vector is asserted against the live
//! codec before anything is written, so a generator run is itself a
//! self-check. Output is deterministic: re-running is byte-identical.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use cipherbox_core::codec::{
    MAX_DEPTH, Map, Value, decode, decode_map_partial, encode, encode_map_partial,
};
use cipherbox_core::content::{
    CONTENT_CID_CODEC, CONTENT_CID_LEN, CONTENT_CID_MULTIHASH, compute_cid, decode_content_cid_str,
    encode_content_cid_str, open_chunk, seal_chunk, verify_cid,
};
use cipherbox_core::error::{CodecError, Malformed, TrustViolation};
use cipherbox_core::ipns::{IpnsName, IpnsRecord};
use cipherbox_core::kdf::{self, EDGES, EdgeProbe};
use cipherbox_core::payload::mailbox::{open_mailbox_payload, seal_mailbox_payload};
use cipherbox_core::payload::pointer::{RepointObject, open_pointer_payload, seal_pointer_payload};
use cipherbox_core::seal::{
    self, AAD_DOMAIN, AadContext, AscentLink, ChildRef, ChildScopeRef, GrantBlobPayload,
    GrantLedgerEntry, GrantSetCommitment, GrantSetEntry, HistoryLinkPayload, NodeKind,
    OverrideSeedPayload, Permission, ReadBody, STRUCT_TAG_ASCENT_LINK, STRUCT_TAG_GRANT_BLOB,
    STRUCT_TAG_HISTORY_LINK, STRUCT_TAG_MAILBOX_PAYLOAD, STRUCT_TAG_OWNER_BLOB,
    STRUCT_TAG_READ_BODY, STRUCT_TAG_WRITE_BODY, STRUCT_TAGS, SignedAscentLink, SignedGrantBlob,
    SignedOwnerBlob, SignedSealed, StructureSigInput, Version, WriteBody, build_aad,
    decode_ascent_link, decode_envelope, decode_grant_blob_payload, decode_grant_set_commitment,
    decode_history_link_payload, decode_override_seed_payload, decode_read_body, decode_write_body,
    encode_ascent_link, encode_envelope, encode_grant_blob_payload, encode_grant_set_commitment,
    encode_history_link_payload, encode_override_seed_payload, encode_read_body, encode_write_body,
    open_ascent_link, open_grant_blob, open_history_link, open_owner_blob, open_read_body,
    seal_ascent_link, seal_grant_blob, seal_history_link, seal_owner_blob, seal_read_body,
    sign_grant_set, sign_structure, structure_sig_preimage, verify_grant_set, verify_structure,
};
use cipherbox_core::suite::aead::{KEY_LEN, NONCE_LEN, TAG_LEN};
use cipherbox_core::suite::contact::{ContactCode, import_contact_code};
use cipherbox_core::suite::ecdsa::EcdsaSigner;
use cipherbox_core::suite::ed25519::{Ed25519Signature, Ed25519Signer};
use cipherbox_core::suite::hash::hash;
use cipherbox_core::suite::hpke::{self, hpke_open, hpke_seal};
use cipherbox_core::suite::x25519::X25519Secret;
use serde::Serialize;

const PROFILE: &str = "cipherbox/v2 det-cbor";

fn hexstr(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[derive(Serialize)]
struct AcceptVector {
    name: String,
    hex: String,
    diag: String,
    kinds: Vec<String>,
}

#[derive(Serialize)]
struct RejectVector {
    name: String,
    hex: String,
    check: String,
    class: String,
}

/// An HPKE-blob reject vector: a validly-sealed grant/owner blob whose open must
/// fail closed. `structTag` is the tag the *opener* uses; for a transplant it is
/// deliberately a different tag than the seal, so the recomputed AAD makes the
/// AEAD tag fail — `hpke-open-failed`, the same verdict a tampered ciphertext
/// yields. The scope seed inside these blobs is the highest-value target.
#[derive(Serialize)]
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

/// A grant/owner-blob reject vector: either a plaintext-decode failure (`hex`
/// never decodes) or an HPKE-open failure (a sealed envelope that must not
/// open). One reject file carries both shapes; the harness dispatches on which
/// fields are present.
#[derive(Serialize)]
#[serde(untagged)]
enum BlobRejectVector {
    Decode(RejectVector),
    HpkeOpen(HpkeBlobRejectVector),
}

impl BlobRejectVector {
    fn check(&self) -> &str {
        match self {
            Self::Decode(v) => &v.check,
            Self::HpkeOpen(v) => &v.check,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnknownVector {
    name: String,
    hex: String,
    known_keys: Vec<String>,
    expect_unknown_count: usize,
}

// --- KDF edge vectors -------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KdfEdgesFile {
    probe: ProbeJson,
    edges: Vec<EdgeVector>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProbeJson {
    seed: String,
    id: String,
    struct_tag: u8,
    index: u64,
    ipns_name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EdgeVector {
    name: String,
    context: String,
    input_layout: String,
    output: String,
}

// --- HPKE vectors -----------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
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

// --- Contact code vectors ---------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContactAcceptVector {
    name: String,
    hex: String,
    identity_pk: String,
    enc_subkey: String,
    binding_sig: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    manifest_version: u64,
    profile: String,
    codecs: Codecs,
    structure_tags: serde_json::Value,
    kdf: KdfSection,
    suite: SuiteSection,
    seal: SealSection,
    ipns: IpnsSection,
    payload: PayloadSection,
    grant: GrantSection,
    content: ContentSection,
}

// --- Content section: the content-seal primitive over caller-framed chunks and
// --- the content-DAG CID compute/verify codec (ticket #691).

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContentSection {
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

/// A content-CID string accept vector: a binary CIDv1 and its canonical
/// base32-lowercase multibase (`b…`) rendering, round-tripping byte-for-byte.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContentCidStrAcceptVector {
    name: String,
    cid: String,
    cid_str: String,
}

/// A content-seal accept vector: a fixed content key + nonce seal of
/// caller-framed chunk bytes, reproducible byte-for-byte.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContentSealVector {
    name: String,
    key: String,
    nonce: String,
    plaintext: String,
    sealed: String,
}

/// A content-open reject vector: a sealed blob that must fail closed on open.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContentSealRejectVector {
    name: String,
    key: String,
    sealed: String,
    check: String,
    class: String,
}

/// A content-CID accept vector: fixed bytes plus the multicodec (raw leaf or a
/// non-raw DAG root) and their deterministic CIDv1 (KAT-pinned, byte-identical
/// native + wasm32).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContentCidVector {
    name: String,
    codec: u8,
    sealed: String,
    cid: String,
}

/// A content-CID verify reject vector: a claimed CID that does not match the
/// sealed bytes, rejected fail-closed as `content-cid-mismatch`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContentCidRejectVector {
    name: String,
    cid: String,
    sealed: String,
    check: String,
    class: String,
}

// --- Grant section: write-body, grant/owner blobs, ascent + history links,
// --- structure signatures, and the grant-set commitment (ticket #621).

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GrantSection {
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
    section_accept: FileCount,
    section_reject: RejectSection,
}

/// A write-body accept vector: the canonical plaintext plus the two list counts
/// the codec exposes.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WriteBodyAcceptVector {
    name: String,
    hex: String,
    ledger_count: usize,
    child_scope_count: usize,
}

/// A grant-section accept vector: the canonical bundle plus the counts the
/// framing codec exposes (a decoder cross-check anchor).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SectionAcceptVector {
    name: String,
    hex: String,
    grant_blob_count: usize,
    history_link_count: usize,
    has_ascent_link: bool,
}

/// A per-structure HPKE seal KAT: a fixed-ephemeral seal of a grant/owner-blob
/// payload with the whole envelope (enc + ciphertext) and the structured AAD
/// frozen (the eciesjs lesson, applied per structure).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
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

/// An ascent-link accept vector: the parent node seed, the frozen container
/// (plaintext public half + HPKE seal), and the sealed override-seed plaintext.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
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

/// An ascent-link reject vector: an ancestor opens `container` under
/// `parentNodeSeed`, exercising the derive-and-verify mismatch and the HPKE
/// open-failure paths.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
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

/// A history-link symmetric seal KAT under a fixed structure key + nonce.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
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

/// A structure-signature accept vector: the frozen preimage over the ciphertext
/// hash and context, and the pseudonym signature that verifies against it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
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

/// A structure-signature reject vector: the verify-side context and signature;
/// verifying recomputes a preimage that does not match (bad signature, a
/// struct-tag transplant, or a recipient-tag transplant).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
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

/// A grant-set commitment accept vector: the owner identity key, the frozen
/// commitment preimage, and the owner's ECDSA signature over it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GrantSetAcceptVector {
    name: String,
    owner_identity_pk: String,
    commitment: String,
    signature: String,
}

/// A grant-set reject vector. When `signature` is empty the defect is in the
/// commitment codec (decode fails); otherwise the commitment decodes and the
/// owner signature fails to verify (`commitment-invalid`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GrantSetRejectVector {
    name: String,
    owner_identity_pk: String,
    commitment: String,
    signature: String,
    check: String,
    class: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SealSection {
    aad_domain: String,
    read_body_struct_tag: u8,
    seal: FileCount,
    open_reject: RejectSection,
    read_body_accept: FileCount,
    read_body_reject: RejectSection,
    envelope_accept: FileCount,
    envelope_reject: RejectSection,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadBodyAcceptVector {
    name: String,
    hex: String,
    kind: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnvelopeAcceptVector {
    name: String,
    key: String,
    envelope: String,
    read_body: String,
}

// --- IPNS records + name codec (ticket #622) --------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IpnsSection {
    name_accept: FileCount,
    name_reject: RejectSection,
    record_accept: FileCount,
    record_reject: RejectSection,
    record_reput: FileCount,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NameAcceptVector {
    name: String,
    signer_seed: String,
    ipns_name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TextRejectVector {
    name: String,
    text: String,
    check: String,
    class: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordRejectVector {
    name: String,
    ipns_name: String,
    record: String,
    check: String,
    class: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordReputVector {
    name: String,
    ipns_name: String,
    record: String,
}

// --- Pointer + mailbox payloads (ticket #622) -------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PayloadSection {
    pointer_accept: FileCount,
    pointer_reject: RejectSection,
    mailbox_accept: FileCount,
    mailbox_reject: RejectSection,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    prev_root_name: Option<String>,
    sealed: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MailboxRejectVector {
    name: String,
    recipient_secret: String,
    v: u64,
    block: String,
    check: String,
    class: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KdfSection {
    file: String,
    count: usize,
    edges: Vec<EdgeRow>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EdgeRow {
    name: String,
    context: String,
    input_layout: String,
}

#[derive(Serialize)]
struct SuiteSection {
    hpke: HpkeMeta,
    contact: ContactMeta,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HpkeMeta {
    kem_id: String,
    kdf_id: String,
    aead_id: String,
    seal_file: String,
    seal_count: usize,
    open_reject_file: String,
    open_reject_count: usize,
}

#[derive(Serialize)]
struct ContactMeta {
    accept: FileCount,
    reject: RejectSection,
}

#[derive(Serialize)]
struct FileCount {
    file: String,
    count: usize,
}

#[derive(Serialize)]
struct Codecs {
    #[serde(rename = "det-cbor")]
    det_cbor: DetCbor,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DetCbor {
    accept: AcceptSection,
    reject: RejectSection,
    unknown_fields: UnknownFieldsSection,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AcceptSection {
    file: String,
    count: usize,
    required_kinds: Vec<String>,
}

#[derive(Serialize)]
struct RejectSection {
    file: String,
    count: usize,
    checks: Vec<String>,
}

#[derive(Serialize)]
struct UnknownFieldsSection {
    file: String,
    count: usize,
}

fn main() {
    let kat_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("kat");
    let vectors_dir = kat_dir.join("vectors");
    let codec_dir = vectors_dir.join("codec");
    let kdf_dir = vectors_dir.join("kdf");
    let hpke_dir = vectors_dir.join("hpke");
    let contact_dir = vectors_dir.join("contact");
    let seal_dir = vectors_dir.join("seal");
    let ipns_dir = vectors_dir.join("ipns");
    let payload_dir = vectors_dir.join("payload");
    let grant_dir = vectors_dir.join("grant");
    let content_dir = vectors_dir.join("content");
    for dir in [
        &codec_dir,
        &kdf_dir,
        &hpke_dir,
        &contact_dir,
        &seal_dir,
        &ipns_dir,
        &payload_dir,
        &grant_dir,
        &content_dir,
    ] {
        fs::create_dir_all(dir).unwrap_or_else(|e| panic!("create {}: {e}", dir.display()));
    }

    let accept = build_accept_vectors();
    let reject = build_reject_vectors();
    let unknown = build_unknown_field_vectors();

    write_pretty(&codec_dir.join("accept.json"), &accept);
    write_pretty(&codec_dir.join("reject.json"), &reject);
    write_pretty(&codec_dir.join("unknown_fields.json"), &unknown);

    let kdf_edges = build_kdf_edges();
    let hpke_seal = build_hpke_seal();
    let hpke_open_reject = build_hpke_open_reject();
    let contact_accept = build_contact_accept();
    let contact_reject = build_contact_reject();

    write_pretty(&kdf_dir.join("edges.json"), &kdf_edges);
    write_pretty(&hpke_dir.join("seal.json"), &hpke_seal);
    write_pretty(&hpke_dir.join("open_reject.json"), &hpke_open_reject);
    write_pretty(&contact_dir.join("accept.json"), &contact_accept);
    write_pretty(&contact_dir.join("reject.json"), &contact_reject);

    let seal_vectors = build_seal_vectors();
    let seal_open_reject = build_seal_open_reject();
    let read_body_accept = build_read_body_accept();
    let read_body_reject = build_read_body_reject();
    let envelope_accept = build_envelope_accept();
    let envelope_reject = build_envelope_reject();

    write_pretty(&seal_dir.join("seal.json"), &seal_vectors);
    write_pretty(&seal_dir.join("open_reject.json"), &seal_open_reject);
    write_pretty(&seal_dir.join("read_body_accept.json"), &read_body_accept);
    write_pretty(&seal_dir.join("read_body_reject.json"), &read_body_reject);
    write_pretty(&seal_dir.join("envelope_accept.json"), &envelope_accept);
    write_pretty(&seal_dir.join("envelope_reject.json"), &envelope_reject);

    let name_accept = build_ipns_name_accept();
    let name_reject = build_ipns_name_reject();
    let record_accept = build_ipns_record_accept();
    let record_reject = build_ipns_record_reject();
    let record_reput = build_ipns_record_reput();

    write_pretty(&ipns_dir.join("name_accept.json"), &name_accept);
    write_pretty(&ipns_dir.join("name_reject.json"), &name_reject);
    write_pretty(&ipns_dir.join("record_accept.json"), &record_accept);
    write_pretty(&ipns_dir.join("record_reject.json"), &record_reject);
    write_pretty(&ipns_dir.join("record_reput.json"), &record_reput);

    let pointer_accept = build_pointer_accept();
    let pointer_reject = build_pointer_reject();
    let mailbox_accept = build_mailbox_accept();
    let mailbox_reject = build_mailbox_reject();

    write_pretty(&payload_dir.join("pointer_accept.json"), &pointer_accept);
    write_pretty(&payload_dir.join("pointer_reject.json"), &pointer_reject);
    write_pretty(&payload_dir.join("mailbox_accept.json"), &mailbox_accept);
    write_pretty(&payload_dir.join("mailbox_reject.json"), &mailbox_reject);

    let g = build_grant_vectors();

    write_pretty(
        &grant_dir.join("write_body_accept.json"),
        &g.write_body_accept,
    );
    write_pretty(
        &grant_dir.join("write_body_reject.json"),
        &g.write_body_reject,
    );
    write_pretty(
        &grant_dir.join("grant_blob_accept.json"),
        &g.grant_blob_accept,
    );
    write_pretty(
        &grant_dir.join("grant_blob_reject.json"),
        &g.grant_blob_reject,
    );
    write_pretty(
        &grant_dir.join("owner_blob_accept.json"),
        &g.owner_blob_accept,
    );
    write_pretty(
        &grant_dir.join("owner_blob_reject.json"),
        &g.owner_blob_reject,
    );
    write_pretty(
        &grant_dir.join("ascent_link_accept.json"),
        &g.ascent_link_accept,
    );
    write_pretty(
        &grant_dir.join("ascent_link_reject.json"),
        &g.ascent_link_reject,
    );
    write_pretty(
        &grant_dir.join("history_link_accept.json"),
        &g.history_link_accept,
    );
    write_pretty(
        &grant_dir.join("history_link_reject.json"),
        &g.history_link_reject,
    );
    write_pretty(
        &grant_dir.join("structure_sig_accept.json"),
        &g.structure_sig_accept,
    );
    write_pretty(
        &grant_dir.join("structure_sig_reject.json"),
        &g.structure_sig_reject,
    );
    write_pretty(
        &grant_dir.join("grant_set_accept.json"),
        &g.grant_set_accept,
    );
    write_pretty(
        &grant_dir.join("grant_set_reject.json"),
        &g.grant_set_reject,
    );
    write_pretty(&grant_dir.join("section_accept.json"), &g.section_accept);
    write_pretty(&grant_dir.join("section_reject.json"), &g.section_reject);

    let content_seal = build_content_seal();
    let content_seal_reject = build_content_seal_reject();
    let content_cid = build_content_cid();
    let content_cid_reject = build_content_cid_reject();
    let content_cid_str_accept = build_content_cid_str_accept();
    let content_cid_str_reject = build_content_cid_str_reject();

    write_pretty(&content_dir.join("seal.json"), &content_seal);
    write_pretty(&content_dir.join("seal_reject.json"), &content_seal_reject);
    write_pretty(&content_dir.join("cid.json"), &content_cid);
    write_pretty(&content_dir.join("cid_reject.json"), &content_cid_reject);
    write_pretty(
        &content_dir.join("cid_str_accept.json"),
        &content_cid_str_accept,
    );
    write_pretty(
        &content_dir.join("cid_str_reject.json"),
        &content_cid_str_reject,
    );

    let manifest = build_manifest(ManifestInputs {
        accept: &accept,
        reject: &reject,
        unknown: &unknown,
        kdf_edges: &kdf_edges,
        hpke_seal: &hpke_seal,
        hpke_open_reject: &hpke_open_reject,
        contact_accept: &contact_accept,
        contact_reject: &contact_reject,
        seal: &seal_vectors,
        seal_open_reject: &seal_open_reject,
        read_body_accept: &read_body_accept,
        read_body_reject: &read_body_reject,
        envelope_accept: &envelope_accept,
        envelope_reject: &envelope_reject,
        name_accept: &name_accept,
        name_reject: &name_reject,
        record_accept: &record_accept,
        record_reject: &record_reject,
        record_reput: &record_reput,
        pointer_accept: &pointer_accept,
        pointer_reject: &pointer_reject,
        mailbox_accept: &mailbox_accept,
        mailbox_reject: &mailbox_reject,
        grant: &g,
        content_seal: &content_seal,
        content_seal_reject: &content_seal_reject,
        content_cid: &content_cid,
        content_cid_reject: &content_cid_reject,
        content_cid_str_accept: &content_cid_str_accept,
        content_cid_str_reject: &content_cid_str_reject,
    });
    write_pretty(&kat_dir.join("manifest.json"), &manifest);

    println!(
        "kat_gen: wrote {} accept, {} reject, {} unknown-field, {} kdf-edge, {} hpke-seal, \
         {} hpke-open-reject, {} contact-accept, {} contact-reject, {} seal, {} seal-open-reject, \
         {} read-body-accept, {} read-body-reject, {} envelope-accept, {} envelope-reject, \
         {} name-accept, {} name-reject, {} record-accept, {} record-reject, {} record-reput, \
         {} pointer-accept, {} pointer-reject, {} mailbox-accept, {} mailbox-reject, \
         {} grant-family, {} content-seal, {} content-seal-reject, {} content-cid, \
         {} content-cid-reject, {} content-cid-str-accept, {} content-cid-str-reject \
         vectors + manifest.json",
        accept.len(),
        reject.len(),
        unknown.len(),
        kdf_edges.edges.len(),
        hpke_seal.len(),
        hpke_open_reject.len(),
        contact_accept.len(),
        contact_reject.len(),
        seal_vectors.len(),
        seal_open_reject.len(),
        read_body_accept.len(),
        read_body_reject.len(),
        envelope_accept.len(),
        envelope_reject.len(),
        name_accept.len(),
        name_reject.len(),
        record_accept.len(),
        record_reject.len(),
        record_reput.len(),
        pointer_accept.len(),
        pointer_reject.len(),
        mailbox_accept.len(),
        mailbox_reject.len(),
        g.total(),
        content_seal.len(),
        content_seal_reject.len(),
        content_cid.len(),
        content_cid_reject.len(),
        content_cid_str_accept.len(),
        content_cid_str_reject.len(),
    );
}

fn write_pretty<T: Serialize>(path: &Path, value: &T) {
    let mut text = serde_json::to_string_pretty(value).expect("serialize JSON");
    text.push('\n');
    fs::write(path, text).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

// ---------------------------------------------------------------------------
// Accept vectors: built from Value constructors + the live encoder.
// ---------------------------------------------------------------------------

/// `levels` nested arrays, innermost empty: `nested_arrays(1)` is `[]`.
fn nested_arrays(levels: usize) -> Value {
    let mut v = Value::Array(Vec::new());
    for _ in 1..levels {
        v = Value::Array(vec![v]);
    }
    v
}

fn map_of(entries: Vec<(&str, Value)>) -> Value {
    let mut m = Map::new();
    for (k, v) in entries {
        m.insert(k, v);
    }
    Value::Map(m)
}

fn accept_specs() -> Vec<(&'static str, Value, Vec<&'static str>)> {
    vec![
        // Unsigned boundaries: every argument-width class edge, both sides.
        ("uint-0", Value::Unsigned(0), vec!["uint"]),
        ("uint-23-max-immediate", Value::Unsigned(23), vec!["uint"]),
        ("uint-24-min-8bit", Value::Unsigned(24), vec!["uint"]),
        ("uint-255-max-8bit", Value::Unsigned(255), vec!["uint"]),
        ("uint-256-min-16bit", Value::Unsigned(256), vec!["uint"]),
        ("uint-65535-max-16bit", Value::Unsigned(65535), vec!["uint"]),
        ("uint-65536-min-32bit", Value::Unsigned(65536), vec!["uint"]),
        (
            "uint-4294967295-max-32bit",
            Value::Unsigned(4_294_967_295),
            vec!["uint"],
        ),
        (
            "uint-4294967296-min-64bit",
            Value::Unsigned(4_294_967_296),
            vec!["uint"],
        ),
        ("uint-u64-max", Value::Unsigned(u64::MAX), vec!["uint"]),
        // Negatives: Value::Negative(n) is -1 - n.
        ("negint-minus-1", Value::Negative(0), vec!["negint"]),
        (
            "negint-minus-24-max-immediate",
            Value::Negative(23),
            vec!["negint"],
        ),
        (
            "negint-minus-25-min-8bit",
            Value::Negative(24),
            vec!["negint"],
        ),
        // -2^64: below i64/i128::from(u64) territory on the wire, the full
        // major-1 range. Diag pins the arbitrary-precision rendering.
        (
            "negint-minus-2-pow-64",
            Value::Negative(u64::MAX),
            vec!["negint"],
        ),
        // Bytes: the 24-length one crosses into the 8-bit length header.
        ("bytes-empty", Value::Bytes(Vec::new()), vec!["bytes"]),
        (
            "bytes-short",
            Value::Bytes(vec![0x01, 0x02, 0x03]),
            vec!["bytes"],
        ),
        (
            "bytes-len-24-8bit-length-header",
            Value::Bytes((0u8..24).collect()),
            vec!["bytes"],
        ),
        // Text: empty, ascii, multibyte (UTF-8 length != char count), 24+.
        ("text-empty", Value::Text(String::new()), vec!["text"]),
        ("text-ascii", Value::Text("hello".into()), vec!["text"]),
        (
            "text-multibyte-unicode",
            Value::Text("héllo wörld — ✓🚀".into()),
            vec!["text"],
        ),
        (
            "text-len-26-8bit-length-header",
            Value::Text("abcdefghijklmnopqrstuvwxyz".into()),
            vec!["text"],
        ),
        // Arrays.
        ("array-empty", Value::Array(Vec::new()), vec!["array"]),
        (
            "array-nested",
            Value::Array(vec![
                Value::Unsigned(1),
                Value::Array(vec![
                    Value::Unsigned(2),
                    Value::Array(vec![Value::Unsigned(3)]),
                ]),
            ]),
            vec!["array"],
        ),
        (
            "array-heterogeneous",
            Value::Array(vec![
                Value::Unsigned(1),
                Value::Negative(1),
                Value::Bytes(vec![0xff]),
                Value::Text("mixed".into()),
                Value::Bool(true),
                Value::Null,
                Value::Array(Vec::new()),
                Value::Map(Map::new()),
            ]),
            vec!["array"],
        ),
        // Maps: canonical order is length-first, then bytewise — "a" and "b"
        // sort before "aa".
        ("map-empty", Value::Map(Map::new()), vec!["map"]),
        (
            "map-canonical-key-order-length-first",
            map_of(vec![
                ("aa", Value::Unsigned(3)),
                ("b", Value::Unsigned(2)),
                ("a", Value::Unsigned(1)),
            ]),
            vec!["map"],
        ),
        (
            "map-nested",
            map_of(vec![
                ("k", map_of(vec![("nested", Value::Bool(true))])),
                ("z", Value::Array(vec![Value::Null])),
            ]),
            vec!["map"],
        ),
        // Keys straddling the 23/24 length-header class boundary, in
        // canonical order (length-first: the 23-char key sorts before the
        // 24-char one whose header grows to 78 18). The reversed order is a
        // reject vector.
        (
            "map-keys-length-class-boundary",
            {
                let mut m = Map::new();
                m.insert("a".repeat(23), Value::Unsigned(0));
                m.insert("b".repeat(24), Value::Unsigned(1));
                Value::Map(m)
            },
            vec!["map"],
        ),
        // Simple values.
        ("bool-true", Value::Bool(true), vec!["bool"]),
        ("bool-false", Value::Bool(false), vec!["bool"]),
        ("null", Value::Null, vec!["null"]),
        // Exactly at the depth limit: the innermost (128th) array is read at
        // depth 127 < MAX_DEPTH. One level deeper is the depth-exceeded
        // reject vector.
        (
            "array-nested-at-depth-limit-128",
            nested_arrays(MAX_DEPTH),
            vec!["array", "depth-limit"],
        ),
    ]
}

fn build_accept_vectors() -> Vec<AcceptVector> {
    let specs = accept_specs();
    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(specs.len());
    for (name, value, kinds) in specs {
        assert!(names.insert(name), "duplicate accept vector name {name}");
        let bytes = encode(&value);
        let decoded = decode(&bytes)
            .unwrap_or_else(|e| panic!("accept vector {name}: live decoder rejected it: {e}"));
        assert_eq!(
            decoded, value,
            "accept vector {name}: decode != source value"
        );
        assert_eq!(
            encode(&decoded),
            bytes,
            "accept vector {name}: re-encode not byte-stable"
        );
        out.push(AcceptVector {
            name: name.to_string(),
            hex: hex::encode(&bytes),
            diag: value.to_string(),
            kinds: kinds.into_iter().map(str::to_string).collect(),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Reject vectors: explicit hand-crafted byte literals, one per decode-
// reachable check (several for the load-bearing ones), each asserted against
// the live decoder for the exact check + class.
// ---------------------------------------------------------------------------

fn reject_specs() -> Vec<(&'static str, String, &'static str, &'static str)> {
    let h = |s: &str| s.to_string();
    // MAX_DEPTH (128) array heads then an empty array: the 129th nesting
    // level would be read at depth 128, one past the limit.
    let depth_129 = "81".repeat(MAX_DEPTH) + "80";
    vec![
        // --- trust: non-canonical-uint ---------------------------------
        // 18 17 — uint 23 in 8-bit form; shortest form is the immediate 17.
        (
            "uint-23-in-8bit-form",
            h("1817"),
            "non-canonical-uint",
            "trust",
        ),
        // 19 00ff — uint 255 in 16-bit form; shortest is 18 ff.
        (
            "uint-255-in-16bit-form",
            h("1900ff"),
            "non-canonical-uint",
            "trust",
        ),
        // 1a 0000ffff — uint 65535 in 32-bit form; shortest is 19 ffff.
        (
            "uint-65535-in-32bit-form",
            h("1a0000ffff"),
            "non-canonical-uint",
            "trust",
        ),
        // 1b 00000000ffffffff — uint 4294967295 in 64-bit form.
        (
            "uint-4294967295-in-64bit-form",
            h("1b00000000ffffffff"),
            "non-canonical-uint",
            "trust",
        ),
        // 38 17 — negative -24 (major 1, arg 23) in 8-bit form; shortest is 37.
        (
            "negint-minus-24-in-8bit-form",
            h("3817"),
            "non-canonical-uint",
            "trust",
        ),
        // --- trust: non-canonical-length -------------------------------
        // 58 03 aa bb cc — 3-byte string with an 8-bit length header;
        // shortest is 43.
        (
            "bytes-len-3-in-8bit-form",
            h("5803aabbcc"),
            "non-canonical-length",
            "trust",
        ),
        // 78 01 61 — 1-char text with an 8-bit length header; shortest is 61.
        (
            "text-len-1-in-8bit-form",
            h("780161"),
            "non-canonical-length",
            "trust",
        ),
        // 98 03 01 02 03 — 3-element array with an 8-bit length header.
        (
            "array-len-3-in-8bit-form",
            h("9803010203"),
            "non-canonical-length",
            "trust",
        ),
        // b8 01 61 61 01 — 1-entry map {"a": 1} with an 8-bit length header.
        (
            "map-len-1-in-8bit-form",
            h("b801616101"),
            "non-canonical-length",
            "trust",
        ),
        // --- trust: indefinite-length -----------------------------------
        // 5f 41 aa ff — indefinite bytes, one 1-byte chunk, break.
        (
            "indefinite-bytes",
            h("5f41aaff"),
            "indefinite-length",
            "trust",
        ),
        // 7f 61 61 ff — indefinite text, one chunk "a", break.
        (
            "indefinite-text",
            h("7f6161ff"),
            "indefinite-length",
            "trust",
        ),
        // 9f 01 ff — indefinite array [1], break.
        (
            "indefinite-array",
            h("9f01ff"),
            "indefinite-length",
            "trust",
        ),
        // bf 61 61 01 ff — indefinite map {"a": 1}, break.
        (
            "indefinite-map",
            h("bf616101ff"),
            "indefinite-length",
            "trust",
        ),
        // --- trust: unsorted-map-keys -----------------------------------
        // a2 6162 01 6161 02 — {"b": 1, "a": 2}: bytewise order violation.
        (
            "map-keys-bytewise-out-of-order",
            h("a2616201616102"),
            "unsorted-map-keys",
            "trust",
        ),
        // a2 626161 01 6162 02 — {"aa": 1, "b": 2}: canonical text-key order
        // is length-first, so "b" must sort before "aa".
        (
            "map-keys-length-order-violation",
            h("a262616101616202"),
            "unsorted-map-keys",
            "trust",
        ),
        // --- trust: duplicate-map-key -----------------------------------
        // a2 6161 01 6161 02 — {"a": 1, "a": 2}.
        (
            "map-duplicate-key",
            h("a2616101616102"),
            "duplicate-map-key",
            "trust",
        ),
        // --- malformed: truncated ---------------------------------------
        // Zero bytes: no item at all.
        ("empty-input", h(""), "truncated", "malformed"),
        // 18 — uint head promising an 8-bit argument that never comes.
        (
            "uint-head-missing-argument",
            h("18"),
            "truncated",
            "malformed",
        ),
        // 44 aa bb — bytes head claiming 4 bytes, only 2 present.
        (
            "bytes-shorter-than-length",
            h("44aabb"),
            "truncated",
            "malformed",
        ),
        // 82 01 — array of 2 with only 1 element present.
        ("array-missing-element", h("8201"), "truncated", "malformed"),
        // --- malformed: trailing-bytes ----------------------------------
        // 01 00 — a complete item (1) followed by a stray byte.
        (
            "trailing-byte-after-item",
            h("0100"),
            "trailing-bytes",
            "malformed",
        ),
        // --- malformed: invalid-utf8 ------------------------------------
        // 62 ff fe — 2-byte text whose payload is not UTF-8.
        (
            "text-invalid-utf8",
            h("62fffe"),
            "invalid-utf8",
            "malformed",
        ),
        // --- malformed: invalid-map-key-type ----------------------------
        // a1 01 02 — {1: 2}: integer map key; the profile admits text only.
        (
            "map-key-unsigned",
            h("a10102"),
            "invalid-map-key-type",
            "malformed",
        ),
        // --- malformed: tag-forbidden -----------------------------------
        // d8 2a 45 0001020300… — tag 42 (a DAG-CBOR CID link) around bytes.
        // CID links are outside this profile; every tag rejects.
        (
            "tag-42-dag-cbor-cid-link",
            h("d82a4500010203aa"),
            "tag-forbidden",
            "malformed",
        ),
        // c0 00 — tag 0 (datetime) in immediate form.
        ("tag-0-datetime", h("c000"), "tag-forbidden", "malformed"),
        // --- malformed: float-forbidden ---------------------------------
        // f9 0014 — half-float whose bit pattern (0x0014) aliases simple
        // value 20 (false). A decoder dispatching on the decoded argument
        // instead of the additional info accepts this as `false` — a real
        // bug class in this decoder's history; must reject as a float.
        (
            "half-float-aliasing-simple-false",
            h("f90014"),
            "float-forbidden",
            "malformed",
        ),
        // fa 47c35000 — float32 100000.0.
        ("float32", h("fa47c35000"), "float-forbidden", "malformed"),
        // fb 3ff199999999999a — float64 1.1.
        (
            "float64",
            h("fb3ff199999999999a"),
            "float-forbidden",
            "malformed",
        ),
        // --- malformed: simple-value-forbidden --------------------------
        // f8 14 — simple value 20 in two-byte form. Must NOT alias `false`
        // (f4): only the immediate forms of false/true/null are admitted.
        (
            "two-byte-simple-20-not-false",
            h("f814"),
            "simple-value-forbidden",
            "malformed",
        ),
        // f7 — simple value 23 (undefined).
        (
            "simple-undefined",
            h("f7"),
            "simple-value-forbidden",
            "malformed",
        ),
        // f0 — simple value 16 (unassigned).
        (
            "simple-16-unassigned",
            h("f0"),
            "simple-value-forbidden",
            "malformed",
        ),
        // --- malformed: reserved-additional-info ------------------------
        // 1c — major 0 with additional info 28 (reserved everywhere).
        (
            "uint-ai-28-reserved",
            h("1c"),
            "reserved-additional-info",
            "malformed",
        ),
        // 1f — major 0 with additional info 31: indefinite length is not
        // defined for integers, so this is reserved, not indefinite-length.
        (
            "uint-ai-31-reserved",
            h("1f"),
            "reserved-additional-info",
            "malformed",
        ),
        // --- malformed: unexpected-break --------------------------------
        // ff — a break stop code with no indefinite-length item open.
        ("bare-break", h("ff"), "unexpected-break", "malformed"),
        // --- malformed: depth-exceeded ----------------------------------
        // 129 nested arrays: one past MAX_DEPTH (the 128-deep accept vector
        // is the other side of this edge).
        (
            "array-nesting-129-levels",
            depth_129,
            "depth-exceeded",
            "malformed",
        ),
        // --- crypto-review additions (PR #659 security review) ----------
        // f8 ff — two-byte simple value 255: well-formed CBOR (arg >= 32,
        // unassigned) yet profile-forbidden; f8 14 pins the ill-formed half.
        (
            "two-byte-simple-255",
            h("f8ff"),
            "simple-value-forbidden",
            "malformed",
        ),
        // a2 60 00 60 f4 — {"": 0, "": false}: duplicate empty-string key.
        (
            "map-duplicate-empty-key",
            h("a2600060f4"),
            "duplicate-map-key",
            "trust",
        ),
        // a3 6161 00 6162 01 6161 02 — {"a": 0, "b": 1, "a": 2}: a duplicate
        // separated by a middle key surfaces as an ordering violation, never
        // silently — pins the check-precedence choice.
        (
            "map-gap-duplicate-fires-unsorted",
            h("a3616100616201616102"),
            "unsorted-map-keys",
            "trust",
        ),
        // 5f ff / 7f ff — *empty* indefinite bytes/text (the other
        // indefinite vectors carry chunks).
        (
            "indefinite-bytes-empty",
            h("5fff"),
            "indefinite-length",
            "trust",
        ),
        (
            "indefinite-text-empty",
            h("7fff"),
            "indefinite-length",
            "trust",
        ),
        // dc — a tag head with reserved additional info 28: tag rejection
        // fires on the initial byte, before ai validation.
        (
            "tag-head-reserved-ai-precedence",
            h("dc"),
            "tag-forbidden",
            "malformed",
        ),
        // a1 78 01 61 f6 — {"a"(8-bit len): null}: non-shortest length on
        // the *key* path.
        (
            "map-key-len-1-in-8bit-form",
            h("a1780161f6"),
            "non-canonical-length",
            "trust",
        ),
        // The reversed order of the map-keys-length-class-boundary accept
        // vector: the 24-char key (header 78 18) before the 23-char key
        // (header 77) violates length-first order.
        (
            "map-keys-length-class-boundary-out-of-order",
            format!("a27818{}0177{}00", "62".repeat(24), "61".repeat(23)),
            "unsorted-map-keys",
            "trust",
        ),
    ]
}

fn build_reject_vectors() -> Vec<RejectVector> {
    let specs = reject_specs();
    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(specs.len());
    for (name, hex, check, class) in specs {
        assert!(names.insert(name), "duplicate reject vector name {name}");
        assert_eq!(
            hex,
            hex.to_lowercase(),
            "reject vector {name}: hex must be lowercase"
        );
        let bytes =
            hex::decode(&hex).unwrap_or_else(|e| panic!("reject vector {name}: bad hex: {e}"));
        let err = match decode(&bytes) {
            Err(e) => e,
            Ok(v) => panic!("reject vector {name}: decoder accepted it as {v}"),
        };
        assert_eq!(
            err.check(),
            check,
            "reject vector {name}: wrong check ({err})"
        );
        assert_eq!(
            err.class(),
            class,
            "reject vector {name}: wrong class ({err})"
        );
        out.push(RejectVector {
            name: name.to_string(),
            hex,
            check: check.to_string(),
            class: class.to_string(),
        });
    }

    // Self-check the codec coverage law before writing anything: these vectors
    // cover exactly the codec's decode-reachable checks. The codec's two
    // encode-/schema-side checks (unexpected-type, unknown-field-collision) are
    // unit-test-pinned in src/codec/fields.rs; the suite/kdf checks live in the
    // contact and hpke families, not here.
    let present: BTreeSet<&str> = out.iter().map(|v| v.check.as_str()).collect();
    assert_eq!(
        present,
        codec_decode_reachable_checks(),
        "codec reject vectors must cover exactly the decode-reachable codec checks"
    );
    let surface: BTreeSet<&str> = TrustViolation::CHECKS
        .iter()
        .chain(Malformed::CHECKS)
        .copied()
        .collect();
    assert!(
        present.is_subset(&surface),
        "every codec reject check must exist on the error surface"
    );
    out
}

/// The codec's decode-reachable checks, fixed here as the anti-vacuity anchor
/// for the codec reject family (mirrors kat_manifest.rs). Adding a codec check
/// without a vector, or a vector for a check outside this set, fails the
/// generator self-check.
fn codec_decode_reachable_checks() -> BTreeSet<&'static str> {
    [
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
    ]
    .into_iter()
    .collect()
}

// ---------------------------------------------------------------------------
// Unknown-field vectors: the single decode tolerance, byte-stable on rewrite.
// ---------------------------------------------------------------------------

fn unknown_field_specs() -> Vec<(&'static str, Value, Vec<&'static str>, usize)> {
    vec![
        (
            "all-known",
            map_of(vec![("a", Value::Unsigned(1)), ("b", Value::Unsigned(2))]),
            vec!["a", "b"],
            0,
        ),
        (
            "none-known",
            map_of(vec![("a", Value::Unsigned(1)), ("b", Value::Unsigned(2))]),
            vec![],
            2,
        ),
        // Canonical key order a, b, aa, zz — known and unknown interleave.
        (
            "interleaved-known-unknown",
            map_of(vec![
                ("a", Value::Unsigned(1)),
                ("b", Value::Bytes(vec![0xff])),
                ("aa", Value::Text("x".into())),
                ("zz", Value::Null),
            ]),
            vec!["a", "aa"],
            2,
        ),
        // The preserved unknown value is itself a nested map.
        (
            "unknown-value-nested-map",
            map_of(vec![
                ("id", Value::Unsigned(7)),
                (
                    "meta",
                    map_of(vec![
                        (
                            "x",
                            Value::Array(vec![Value::Unsigned(1), Value::Unsigned(2)]),
                        ),
                        ("y", Value::Text("z".into())),
                    ]),
                ),
            ]),
            vec!["id"],
            1,
        ),
        // The preserved unknown value is itself a nested array.
        (
            "unknown-value-nested-array",
            map_of(vec![
                ("k", Value::Bool(true)),
                (
                    "list",
                    Value::Array(vec![
                        Value::Unsigned(1),
                        Value::Array(vec![Value::Unsigned(2)]),
                        Value::Null,
                    ]),
                ),
            ]),
            vec!["k"],
            1,
        ),
        ("empty-map", Value::Map(Map::new()), vec![], 0),
    ]
}

fn build_unknown_field_vectors() -> Vec<UnknownVector> {
    let specs = unknown_field_specs();
    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(specs.len());
    for (name, value, known_keys, expect_unknown) in specs {
        assert!(
            names.insert(name),
            "duplicate unknown-field vector name {name}"
        );
        let bytes = encode(&value);
        let known_set: BTreeSet<&str> = known_keys.iter().copied().collect();
        let (known, unknown) = decode_map_partial(&bytes, |k| known_set.contains(k))
            .unwrap_or_else(|e| panic!("unknown-field vector {name}: decode failed: {e}"));
        assert_eq!(
            unknown.len(),
            expect_unknown,
            "unknown-field vector {name}: unknown count"
        );
        let total = value.as_map().expect("spec value is a map").len();
        assert_eq!(
            known.len() + unknown.len(),
            total,
            "unknown-field vector {name}: split must be exhaustive"
        );
        let reencoded = encode_map_partial(&known, &unknown)
            .unwrap_or_else(|e| panic!("unknown-field vector {name}: rewrite failed: {e}"));
        assert_eq!(
            reencoded, bytes,
            "unknown-field vector {name}: rewrite not byte-stable"
        );
        out.push(UnknownVector {
            name: name.to_string(),
            hex: hex::encode(&bytes),
            known_keys: known_keys.into_iter().map(str::to_string).collect(),
            expect_unknown_count: expect_unknown,
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Manifest: every byte comes from this generator — header constants and
// counts/checks/requiredKinds from the generated data. The empty
// structureTags/kdfEdges sections are extended by extending this generator
// when those spine slices land, never by hand-editing the JSON.
// ---------------------------------------------------------------------------

/// The full vector inventory `build_manifest` freezes counts and checks from —
/// a struct rather than a long argument list.
struct ManifestInputs<'a> {
    accept: &'a [AcceptVector],
    reject: &'a [RejectVector],
    unknown: &'a [UnknownVector],
    kdf_edges: &'a KdfEdgesFile,
    hpke_seal: &'a [HpkeSealVector],
    hpke_open_reject: &'a [HpkeOpenRejectVector],
    contact_accept: &'a [ContactAcceptVector],
    contact_reject: &'a [RejectVector],
    seal: &'a [SealVector],
    seal_open_reject: &'a [SealOpenRejectVector],
    read_body_accept: &'a [ReadBodyAcceptVector],
    read_body_reject: &'a [RejectVector],
    envelope_accept: &'a [EnvelopeAcceptVector],
    envelope_reject: &'a [RejectVector],
    name_accept: &'a [NameAcceptVector],
    name_reject: &'a [TextRejectVector],
    record_accept: &'a [RecordAcceptVector],
    record_reject: &'a [RecordRejectVector],
    record_reput: &'a [RecordReputVector],
    pointer_accept: &'a [PointerAcceptVector],
    pointer_reject: &'a [PointerRejectVector],
    mailbox_accept: &'a [MailboxAcceptVector],
    mailbox_reject: &'a [MailboxRejectVector],
    grant: &'a GrantVectors,
    content_seal: &'a [ContentSealVector],
    content_seal_reject: &'a [ContentSealRejectVector],
    content_cid: &'a [ContentCidVector],
    content_cid_reject: &'a [ContentCidRejectVector],
    content_cid_str_accept: &'a [ContentCidStrAcceptVector],
    content_cid_str_reject: &'a [TextRejectVector],
}

fn build_manifest(m: ManifestInputs) -> Manifest {
    let accept = m.accept;
    let reject = m.reject;
    let unknown = m.unknown;
    let kdf_edges = m.kdf_edges;
    let hpke_seal = m.hpke_seal;
    let hpke_open_reject = m.hpke_open_reject;
    let contact_accept = m.contact_accept;
    let contact_reject = m.contact_reject;

    // requiredKinds: distinct kinds in first-appearance order (deterministic).
    let mut required_kinds: Vec<String> = Vec::new();
    for v in accept {
        for k in &v.kinds {
            if !required_kinds.contains(k) {
                required_kinds.push(k.clone());
            }
        }
    }

    // The structure-tag registry, frozen from STRUCT_TABLE itself (single
    // source). Serialized as `{name: tagByte}`; serde_json orders the keys
    // deterministically, so regeneration is byte-identical.
    let mut structure_tags = serde_json::Map::new();
    for s in STRUCT_TAGS {
        structure_tags.insert(s.name.to_string(), serde_json::Value::from(s.tag));
    }

    // The KDF catalog table is frozen from EDGES itself (single source).
    let edges: Vec<EdgeRow> = EDGES
        .iter()
        .map(|e| EdgeRow {
            name: e.name.to_string(),
            context: e.context.to_string(),
            input_layout: e.input_layout.to_string(),
        })
        .collect();

    Manifest {
        manifest_version: 1,
        profile: PROFILE.to_string(),
        codecs: Codecs {
            det_cbor: DetCbor {
                accept: AcceptSection {
                    file: "vectors/codec/accept.json".to_string(),
                    count: accept.len(),
                    required_kinds,
                },
                reject: RejectSection {
                    file: "vectors/codec/reject.json".to_string(),
                    count: reject.len(),
                    checks: checks_in_surface_order(reject),
                },
                unknown_fields: UnknownFieldsSection {
                    file: "vectors/codec/unknown_fields.json".to_string(),
                    count: unknown.len(),
                },
            },
        },
        structure_tags: serde_json::Value::Object(structure_tags),
        kdf: KdfSection {
            file: "vectors/kdf/edges.json".to_string(),
            count: kdf_edges.edges.len(),
            edges,
        },
        suite: SuiteSection {
            hpke: HpkeMeta {
                kem_id: "0x0020".to_string(),
                kdf_id: "0x0001".to_string(),
                aead_id: format!("0x{:04x}", hpke::AEAD_ID_XCHACHA),
                seal_file: "vectors/hpke/seal.json".to_string(),
                seal_count: hpke_seal.len(),
                open_reject_file: "vectors/hpke/open_reject.json".to_string(),
                open_reject_count: hpke_open_reject.len(),
            },
            contact: ContactMeta {
                accept: FileCount {
                    file: "vectors/contact/accept.json".to_string(),
                    count: contact_accept.len(),
                },
                reject: RejectSection {
                    file: "vectors/contact/reject.json".to_string(),
                    count: contact_reject.len(),
                    checks: checks_in_surface_order(contact_reject),
                },
            },
        },
        seal: SealSection {
            aad_domain: AAD_DOMAIN.to_string(),
            read_body_struct_tag: STRUCT_TAG_READ_BODY,
            seal: FileCount {
                file: "vectors/seal/seal.json".to_string(),
                count: m.seal.len(),
            },
            open_reject: RejectSection {
                file: "vectors/seal/open_reject.json".to_string(),
                count: m.seal_open_reject.len(),
                checks: checks_surface_ordered(
                    &m.seal_open_reject
                        .iter()
                        .map(|v| v.check.as_str())
                        .collect(),
                ),
            },
            read_body_accept: FileCount {
                file: "vectors/seal/read_body_accept.json".to_string(),
                count: m.read_body_accept.len(),
            },
            read_body_reject: RejectSection {
                file: "vectors/seal/read_body_reject.json".to_string(),
                count: m.read_body_reject.len(),
                checks: checks_in_surface_order(m.read_body_reject),
            },
            envelope_accept: FileCount {
                file: "vectors/seal/envelope_accept.json".to_string(),
                count: m.envelope_accept.len(),
            },
            envelope_reject: RejectSection {
                file: "vectors/seal/envelope_reject.json".to_string(),
                count: m.envelope_reject.len(),
                checks: checks_in_surface_order(m.envelope_reject),
            },
        },
        ipns: IpnsSection {
            name_accept: FileCount {
                file: "vectors/ipns/name_accept.json".to_string(),
                count: m.name_accept.len(),
            },
            name_reject: RejectSection {
                file: "vectors/ipns/name_reject.json".to_string(),
                count: m.name_reject.len(),
                checks: checks_surface_ordered(
                    &m.name_reject.iter().map(|v| v.check.as_str()).collect(),
                ),
            },
            record_accept: FileCount {
                file: "vectors/ipns/record_accept.json".to_string(),
                count: m.record_accept.len(),
            },
            record_reject: RejectSection {
                file: "vectors/ipns/record_reject.json".to_string(),
                count: m.record_reject.len(),
                checks: checks_surface_ordered(
                    &m.record_reject.iter().map(|v| v.check.as_str()).collect(),
                ),
            },
            record_reput: FileCount {
                file: "vectors/ipns/record_reput.json".to_string(),
                count: m.record_reput.len(),
            },
        },
        payload: PayloadSection {
            pointer_accept: FileCount {
                file: "vectors/payload/pointer_accept.json".to_string(),
                count: m.pointer_accept.len(),
            },
            pointer_reject: RejectSection {
                file: "vectors/payload/pointer_reject.json".to_string(),
                count: m.pointer_reject.len(),
                checks: checks_surface_ordered(
                    &m.pointer_reject.iter().map(|v| v.check.as_str()).collect(),
                ),
            },
            mailbox_accept: FileCount {
                file: "vectors/payload/mailbox_accept.json".to_string(),
                count: m.mailbox_accept.len(),
            },
            mailbox_reject: RejectSection {
                file: "vectors/payload/mailbox_reject.json".to_string(),
                count: m.mailbox_reject.len(),
                checks: checks_surface_ordered(
                    &m.mailbox_reject.iter().map(|v| v.check.as_str()).collect(),
                ),
            },
        },
        grant: build_grant_section(m.grant),
        content: build_content_section(&m),
    }
}

/// The content-section manifest metadata (ticket #691): the frozen CIDv1
/// codec/multihash bytes and the generated content-seal + content-CID counts and
/// reject checks.
fn build_content_section(m: &ManifestInputs) -> ContentSection {
    let file = |name: &str, len: usize| FileCount {
        file: format!("vectors/content/{name}.json"),
        count: len,
    };
    ContentSection {
        cid_codec: CONTENT_CID_CODEC,
        cid_multihash: CONTENT_CID_MULTIHASH,
        cid_len: CONTENT_CID_LEN,
        seal: file("seal", m.content_seal.len()),
        seal_reject: RejectSection {
            file: "vectors/content/seal_reject.json".to_string(),
            count: m.content_seal_reject.len(),
            checks: checks_surface_ordered(
                &m.content_seal_reject
                    .iter()
                    .map(|v| v.check.as_str())
                    .collect(),
            ),
        },
        cid: file("cid", m.content_cid.len()),
        cid_reject: RejectSection {
            file: "vectors/content/cid_reject.json".to_string(),
            count: m.content_cid_reject.len(),
            checks: checks_surface_ordered(
                &m.content_cid_reject
                    .iter()
                    .map(|v| v.check.as_str())
                    .collect(),
            ),
        },
        cid_str_accept: file("cid_str_accept", m.content_cid_str_accept.len()),
        cid_str_reject: RejectSection {
            file: "vectors/content/cid_str_reject.json".to_string(),
            count: m.content_cid_str_reject.len(),
            checks: checks_surface_ordered(
                &m.content_cid_str_reject
                    .iter()
                    .map(|v| v.check.as_str())
                    .collect(),
            ),
        },
    }
}

/// The grant-section manifest metadata, frozen from the crate's struct-tag
/// constants and the generated vector counts/checks.
fn build_grant_section(g: &GrantVectors) -> GrantSection {
    let file_count = |name: &str, len: usize| FileCount {
        file: format!("vectors/grant/{name}.json"),
        count: len,
    };
    let reject = |name: &str, checks: &[RejectVector]| RejectSection {
        file: format!("vectors/grant/{name}.json"),
        count: checks.len(),
        checks: checks_in_surface_order(checks),
    };
    let blob_reject = |name: &str, vectors: &[BlobRejectVector]| RejectSection {
        file: format!("vectors/grant/{name}.json"),
        count: vectors.len(),
        checks: checks_surface_ordered(&vectors.iter().map(BlobRejectVector::check).collect()),
    };
    GrantSection {
        write_body_struct_tag: STRUCT_TAG_WRITE_BODY,
        grant_blob_struct_tag: STRUCT_TAG_GRANT_BLOB,
        owner_blob_struct_tag: STRUCT_TAG_OWNER_BLOB,
        ascent_link_struct_tag: STRUCT_TAG_ASCENT_LINK,
        history_link_struct_tag: STRUCT_TAG_HISTORY_LINK,
        write_body_accept: file_count("write_body_accept", g.write_body_accept.len()),
        write_body_reject: reject("write_body_reject", &g.write_body_reject),
        grant_blob_accept: file_count("grant_blob_accept", g.grant_blob_accept.len()),
        grant_blob_reject: blob_reject("grant_blob_reject", &g.grant_blob_reject),
        owner_blob_accept: file_count("owner_blob_accept", g.owner_blob_accept.len()),
        owner_blob_reject: blob_reject("owner_blob_reject", &g.owner_blob_reject),
        ascent_link_accept: file_count("ascent_link_accept", g.ascent_link_accept.len()),
        ascent_link_reject: RejectSection {
            file: "vectors/grant/ascent_link_reject.json".to_string(),
            count: g.ascent_link_reject.len(),
            checks: checks_surface_ordered(
                &g.ascent_link_reject
                    .iter()
                    .map(|v| v.check.as_str())
                    .collect(),
            ),
        },
        history_link_accept: file_count("history_link_accept", g.history_link_accept.len()),
        history_link_reject: reject("history_link_reject", &g.history_link_reject),
        structure_sig_accept: file_count("structure_sig_accept", g.structure_sig_accept.len()),
        structure_sig_reject: RejectSection {
            file: "vectors/grant/structure_sig_reject.json".to_string(),
            count: g.structure_sig_reject.len(),
            checks: checks_surface_ordered(
                &g.structure_sig_reject
                    .iter()
                    .map(|v| v.check.as_str())
                    .collect(),
            ),
        },
        grant_set_accept: file_count("grant_set_accept", g.grant_set_accept.len()),
        grant_set_reject: RejectSection {
            file: "vectors/grant/grant_set_reject.json".to_string(),
            count: g.grant_set_reject.len(),
            checks: checks_surface_ordered(
                &g.grant_set_reject
                    .iter()
                    .map(|v| v.check.as_str())
                    .collect(),
            ),
        },
        section_accept: file_count("section_accept", g.section_accept.len()),
        section_reject: reject("section_reject", &g.section_reject),
    }
}

/// The distinct reject-vector checks, ordered trust-first then malformed to
/// match the error-surface declaration order. Asserts every check comes from
/// the surface.
fn checks_in_surface_order(vectors: &[RejectVector]) -> Vec<String> {
    checks_surface_ordered(&vectors.iter().map(|v| v.check.as_str()).collect())
}

/// The distinct checks in `present`, ordered trust-first then malformed to
/// match the error-surface declaration order. Asserts each check exists on the
/// surface (a reject vector can never name an off-surface check).
fn checks_surface_ordered(present: &BTreeSet<&str>) -> Vec<String> {
    let checks: Vec<String> = TrustViolation::CHECKS
        .iter()
        .chain(Malformed::CHECKS)
        .copied()
        .filter(|c| present.contains(c))
        .map(str::to_string)
        .collect();
    assert_eq!(
        checks.len(),
        present.len(),
        "every reject-vector check must come from the error surface"
    );
    checks
}

// ---------------------------------------------------------------------------
// Seal vectors: the full-envelope symmetric-seal path (blueprint/core.md
// "Fixed-parameter full-envelope KATs"). Every seal is under a fixed key +
// nonce; the AAD, the sealed blob, the read-body plaintext, and the whole
// envelope are frozen, and each vector self-checks against the live seal layer
// before it is written.
// ---------------------------------------------------------------------------

/// The frozen seal probe inputs (fixed key/nonce/ids/epoch), shared across the
/// seal families so their vectors are mutually consistent.
struct SealProbe {
    key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    v: u64,
    id: [u8; 16],
    scope: [u8; 16],
    epoch: u64,
}

fn seal_probe() -> SealProbe {
    SealProbe {
        key: std::array::from_fn(|i| (0x40 + i) as u8),
        nonce: std::array::from_fn(|i| (0x10 + i) as u8),
        v: 2,
        id: std::array::from_fn(|i| (0xa0 + i) as u8),
        scope: std::array::from_fn(|i| (0xb0 + i) as u8),
        epoch: 5,
    }
}

// ---------------------------------------------------------------------------
// Content plane: the content-seal primitive and the content-DAG CID codec
// (ticket #691). The content key is fixed; nonces vary per chunk (nonce reuse
// under one key is a break), so the vectors model correct per-chunk nonces.
// ---------------------------------------------------------------------------

/// The frozen content key for the content KATs (random per version in
/// production; fixed here so the seal reproduces byte-for-byte).
fn content_key() -> [u8; KEY_LEN] {
    std::array::from_fn(|i| (0x80 + i) as u8)
}

/// A per-chunk nonce seeded by a byte, so every content vector uses a distinct
/// nonce under the one fixed key.
fn content_nonce(seed: u8) -> [u8; NONCE_LEN] {
    std::array::from_fn(|i| seed ^ (0x30 + i) as u8)
}

fn build_content_seal() -> Vec<ContentSealVector> {
    let key = content_key();
    let cases: Vec<(&str, u8, Vec<u8>)> = vec![
        (
            "chunk-nonempty",
            0x01,
            b"caller-framed chunk bytes".to_vec(),
        ),
        ("chunk-empty", 0x02, Vec::new()),
        ("chunk-256-bytes", 0x03, (0u8..=255).collect()),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, seed, plaintext) in cases {
        assert!(names.insert(name), "duplicate content seal vector {name}");
        let nonce = content_nonce(seed);
        let sealed = seal_chunk(&key, &nonce, &plaintext);
        assert_eq!(
            seal_chunk(&key, &nonce, &plaintext),
            sealed,
            "content seal {name}: not deterministic"
        );
        assert_eq!(
            &sealed[..NONCE_LEN],
            &nonce,
            "content seal {name}: nonce prefix"
        );
        assert_eq!(
            open_chunk(&key, &sealed).unwrap(),
            plaintext,
            "content seal {name}: open must recover plaintext"
        );
        out.push(ContentSealVector {
            name: name.to_string(),
            key: hexstr(&key),
            nonce: hexstr(&nonce),
            plaintext: hexstr(&plaintext),
            sealed: hexstr(&sealed),
        });
    }
    out
}

fn build_content_seal_reject() -> Vec<ContentSealRejectVector> {
    let key = content_key();
    let nonce = content_nonce(0x10);
    let sealed = seal_chunk(&key, &nonce, b"authentic content");
    assert!(
        open_chunk(&key, &sealed).is_ok(),
        "baseline content seal must open"
    );

    let mut tampered_ct = sealed.clone();
    *tampered_ct.last_mut().unwrap() ^= 0x01;
    let mut tampered_nonce = sealed.clone();
    tampered_nonce[0] ^= 0x01;
    let mut truncated = sealed.clone();
    truncated.truncate(NONCE_LEN + TAG_LEN - 1);

    // (name, sealed-blob, check, class).
    let cases: Vec<(&str, Vec<u8>, &str, &str)> = vec![
        (
            "tampered-ciphertext",
            tampered_ct,
            "seal-open-failed",
            "trust",
        ),
        (
            "tampered-nonce-prefix",
            tampered_nonce,
            "seal-open-failed",
            "trust",
        ),
        (
            "truncated-below-nonce-tag",
            truncated,
            "truncated",
            "malformed",
        ),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, blob, check, class) in cases {
        assert!(
            names.insert(name),
            "duplicate content seal-reject vector {name}"
        );
        let err = open_chunk(&key, &blob).expect_err("content open-reject must fail closed");
        assert_eq!(
            err.check(),
            check,
            "content open-reject {name}: check ({err})"
        );
        assert_eq!(
            err.class(),
            class,
            "content open-reject {name}: class ({err})"
        );
        out.push(ContentSealRejectVector {
            name: name.to_string(),
            key: hexstr(&key),
            sealed: hexstr(&blob),
            check: check.to_string(),
            class: class.to_string(),
        });
    }
    out
}

fn build_content_cid() -> Vec<ContentCidVector> {
    let key = content_key();
    // dag-cbor multicodec (0x71): a non-raw DAG-root codec, engine-owned (#630,
    // engine.md:497), pins the codec parameterization. `verify_cid` keys off the
    // claimed CID's own codec, so the version `contentCid` root verifies too.
    const DAG_CBOR_CODEC: u8 = 0x71;
    // (name, codec, bytes) → deterministic CIDv1. Three raw leaves (a real
    // sealed chunk, the empty input, a full byte range) plus one dag-cbor root.
    let cases: Vec<(&str, u8, Vec<u8>)> = vec![
        (
            "cid-sealed-chunk",
            CONTENT_CID_CODEC,
            seal_chunk(&key, &content_nonce(0x01), b"caller-framed chunk bytes"),
        ),
        ("cid-empty-input", CONTENT_CID_CODEC, Vec::new()),
        ("cid-256-bytes", CONTENT_CID_CODEC, (0u8..=255).collect()),
        (
            "cid-dag-root-nonraw-codec",
            DAG_CBOR_CODEC,
            b"assembled dag-root node bytes".to_vec(),
        ),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, codec, sealed) in cases {
        assert!(names.insert(name), "duplicate content cid vector {name}");
        let cid = compute_cid(codec, &sealed);
        assert_eq!(cid.len(), CONTENT_CID_LEN, "content cid {name}: length");
        assert_eq!(
            cid[..4],
            [0x01, codec, CONTENT_CID_MULTIHASH, 0x20],
            "content cid {name}: v1||codec||blake3||len prefix"
        );
        assert!(
            verify_cid(&cid, &sealed).is_ok(),
            "content cid {name}: verify must accept its own CID"
        );
        out.push(ContentCidVector {
            name: name.to_string(),
            codec,
            sealed: hexstr(&sealed),
            cid: hexstr(&cid),
        });
    }
    out
}

fn build_content_cid_reject() -> Vec<ContentCidRejectVector> {
    let key = content_key();
    let sealed = seal_chunk(&key, &content_nonce(0x20), b"the sealed content blob");
    let good = compute_cid(CONTENT_CID_CODEC, &sealed);

    let mut flipped_digest = good.clone();
    *flipped_digest.last_mut().unwrap() ^= 0x01;

    // A well-framed digest over the right bytes but the wrong multihash code:
    // must fail closed even though the codec byte is caller/engine-chosen.
    let mut wrong_multihash = good.clone();
    wrong_multihash[2] ^= 0xff;

    // (name, claimed-cid, sealed-bytes). Every claim mismatches the sealed bytes.
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "mismatched-content",
            compute_cid(CONTENT_CID_CODEC, b"different bytes"),
        ),
        ("flipped-digest-byte", flipped_digest),
        ("wrong-multihash-code", wrong_multihash),
        ("truncated-claimed-cid", good[..good.len() - 1].to_vec()),
        ("foreign-claimed-cid", b"not a cid at all".to_vec()),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, claimed) in cases {
        assert!(
            names.insert(name),
            "duplicate content cid-reject vector {name}"
        );
        let err = verify_cid(&claimed, &sealed).expect_err("cid-reject must fail closed");
        assert_eq!(
            err.check(),
            "content-cid-mismatch",
            "content cid-reject {name}: check ({err})"
        );
        assert_eq!(
            err.class(),
            "trust",
            "content cid-reject {name}: class ({err})"
        );
        out.push(ContentCidRejectVector {
            name: name.to_string(),
            cid: hexstr(&claimed),
            sealed: hexstr(&sealed),
            check: "content-cid-mismatch".to_string(),
            class: "trust".to_string(),
        });
    }
    out
}

fn build_content_cid_str_accept() -> Vec<ContentCidStrAcceptVector> {
    let key = content_key();
    const DAG_CBOR_CODEC: u8 = 0x71;
    // (name, codec, bytes) → binary CIDv1 → canonical base32-lower `b…` string.
    // A raw leaf, the empty-input leaf, and the dag-cbor DAG root (the head-block
    // codec a scope's `/ipfs/<head_cid>` record actually carries).
    let cases: Vec<(&str, u8, Vec<u8>)> = vec![
        (
            "cid-str-sealed-chunk",
            CONTENT_CID_CODEC,
            seal_chunk(&key, &content_nonce(0x11), b"caller-framed chunk bytes"),
        ),
        ("cid-str-empty-input", CONTENT_CID_CODEC, Vec::new()),
        (
            "cid-str-dag-root-nonraw-codec",
            DAG_CBOR_CODEC,
            b"assembled dag-root node bytes".to_vec(),
        ),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, codec, sealed) in cases {
        assert!(
            names.insert(name),
            "duplicate content cid-str vector {name}"
        );
        let cid = compute_cid(codec, &sealed);
        let cid_str = encode_content_cid_str(&cid);
        // Self-checks: canonical `b` prefix and a byte-stable strict round-trip.
        assert!(
            cid_str.starts_with('b'),
            "content cid-str {name}: base32 multibase prefix"
        );
        assert_eq!(
            decode_content_cid_str(&cid_str).expect("own string decodes"),
            cid,
            "content cid-str {name}: decode recovers the binary CID"
        );
        out.push(ContentCidStrAcceptVector {
            name: name.to_string(),
            cid: hexstr(&cid),
            cid_str,
        });
    }
    out
}

fn build_content_cid_str_reject() -> Vec<TextRejectVector> {
    let good = encode_content_cid_str(&compute_cid(CONTENT_CID_CODEC, b"anchor bytes"));
    let body = &good[1..];

    // A canonical base32 body over a 36-byte string whose multihash code is
    // corrupted: valid base32, wrong CIDv1 framing → must fail closed.
    let mut wrong_framing = compute_cid(CONTENT_CID_CODEC, b"anchor bytes");
    wrong_framing[2] ^= 0xff;
    let mut wrong_framing_str = String::from("b");
    base32_encode_into_ref(&wrong_framing, &mut wrong_framing_str);

    // (name, string). Every string is not the one canonical `b…` CIDv1.
    let cases: Vec<(&str, String)> = vec![
        ("empty", String::new()),
        ("prefix-only", "b".to_string()),
        ("wrong-multibase-base36-k", format!("k{body}")),
        ("wrong-multibase-base58-z", format!("z{body}")),
        ("uppercase-base32-upper", good.to_uppercase()),
        ("non-base32-char-1", format!("b1{body}")),
        ("truncated", good[..good.len() - 1].to_string()),
        ("trailing-extra-char", format!("{good}a")),
        ("wrong-cid-framing", wrong_framing_str),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, text) in cases {
        assert!(
            names.insert(name),
            "duplicate content cid-str-reject {name}"
        );
        let err = decode_content_cid_str(&text).expect_err("cid-str-reject must fail closed");
        assert_eq!(
            err.check(),
            "content-cid-str-malformed",
            "content cid-str-reject {name}: check ({err})"
        );
        assert_eq!(
            err.class(),
            "malformed",
            "content cid-str-reject {name}: class ({err})"
        );
        out.push(TextRejectVector {
            name: name.to_string(),
            text,
            check: err.check().to_string(),
            class: err.class().to_string(),
        });
    }
    out
}

/// Canonical base32-lowercase (no-padding) of `input` appended to `out` — the
/// same transform the codec applies, used only to hand-craft the wrong-framing
/// reject vector's body from arbitrary (non-CID) bytes.
fn base32_encode_into_ref(input: &[u8], out: &mut String) {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in input {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 0x1f) as usize] as char);
    }
}

/// A frozen sample folder read-body, used as the read-body-tag plaintext.
fn sample_folder() -> ReadBody {
    ReadBody::Folder {
        created_at: 1000,
        modified_at: 2000,
        children: vec![
            ChildRef {
                id: [0x11; 16],
                name: "a.txt".to_string(),
                ipns_name: b"ipns-name-a".to_vec(),
                kind: NodeKind::File,
                link_counter: 1,
                unknown: Vec::new(),
            },
            ChildRef {
                id: [0x22; 16],
                name: "sub".to_string(),
                ipns_name: b"ipns-name-b".to_vec(),
                kind: NodeKind::Folder,
                link_counter: 2,
                unknown: Vec::new(),
            },
        ],
        unknown: Vec::new(),
    }
}

/// A frozen sample multi-version file read-body (newest-first).
fn sample_file() -> ReadBody {
    ReadBody::File {
        created_at: 1500,
        modified_at: 2500,
        versions: vec![
            Version::new(b"content-cid-new".to_vec(), [0x77; 32], 8192, 2500),
            Version::new(b"content-cid-old".to_vec(), [0x66; 32], 4096, 1500),
        ],
        unknown: Vec::new(),
    }
}

fn build_seal_vectors() -> Vec<SealVector> {
    let p = seal_probe();
    let read_body_pt = encode_read_body(&sample_folder());

    // (name, structTag, plaintext). read-body carries a real read-body; the
    // write-body tag reuses the primitive to prove per-tag AAD separation (its
    // body codec is a later slice); empty plaintext is the length edge.
    let cases: Vec<(&str, u8, Vec<u8>)> = vec![
        ("read-body-folder", STRUCT_TAG_READ_BODY, read_body_pt),
        (
            "write-body-tag-separation",
            STRUCT_TAG_WRITE_BODY,
            b"write-body-placeholder".to_vec(),
        ),
        (
            "read-body-empty-plaintext",
            STRUCT_TAG_READ_BODY,
            Vec::new(),
        ),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, struct_tag, plaintext) in cases {
        assert!(names.insert(name), "duplicate seal vector {name}");
        let ctx = AadContext {
            v: p.v,
            id: p.id,
            scope: p.scope,
            epoch: p.epoch,
            struct_tag,
        };
        let aad = build_aad(&ctx);
        let sealed = seal::seal(&p.key, &p.nonce, &ctx, &plaintext);
        // Determinism under a fixed key + nonce, and a clean round-trip.
        assert_eq!(
            seal::seal(&p.key, &p.nonce, &ctx, &plaintext),
            sealed,
            "seal {name}: not deterministic"
        );
        assert_eq!(
            seal::unseal(&p.key, &ctx, &sealed).unwrap(),
            plaintext,
            "seal {name}: unseal must recover plaintext"
        );
        out.push(SealVector {
            name: name.to_string(),
            key: hexstr(&p.key),
            nonce: hexstr(&p.nonce),
            v: p.v,
            id: hexstr(&p.id),
            scope: hexstr(&p.scope),
            epoch: p.epoch,
            struct_tag,
            plaintext: hexstr(&plaintext),
            aad: hexstr(&aad),
            sealed: hexstr(&sealed),
        });
    }
    out
}

fn build_seal_open_reject() -> Vec<SealOpenRejectVector> {
    let p = seal_probe();
    let base = AadContext {
        v: p.v,
        id: p.id,
        scope: p.scope,
        epoch: p.epoch,
        struct_tag: STRUCT_TAG_READ_BODY,
    };
    let sealed = seal::seal(&p.key, &p.nonce, &base, b"authentic body");
    assert!(
        seal::unseal(&p.key, &base, &sealed).is_ok(),
        "baseline seal must open"
    );

    let transplant = |f: &dyn Fn(&mut AadContext)| {
        let mut c = base;
        f(&mut c);
        c
    };
    let mut truncated = sealed.clone();
    truncated.truncate(NONCE_LEN + TAG_LEN - 1);
    let mut tampered = sealed.clone();
    *tampered.last_mut().unwrap() ^= 0x01;

    // (name, ctx-used-for-unseal, sealed-blob, check, class).
    let cases: Vec<(&str, AadContext, Vec<u8>, &str, &str)> = vec![
        (
            "downgrade-v",
            transplant(&|c| c.v -= 1),
            sealed.clone(),
            "seal-open-failed",
            "trust",
        ),
        (
            "id-transplant",
            transplant(&|c| c.id[0] ^= 0x01),
            sealed.clone(),
            "seal-open-failed",
            "trust",
        ),
        (
            "scope-transplant",
            transplant(&|c| c.scope[0] ^= 0x01),
            sealed.clone(),
            "seal-open-failed",
            "trust",
        ),
        (
            "epoch-transplant",
            transplant(&|c| c.epoch += 1),
            sealed.clone(),
            "seal-open-failed",
            "trust",
        ),
        (
            "struct-tag-transplant",
            transplant(&|c| c.struct_tag = STRUCT_TAG_WRITE_BODY),
            sealed.clone(),
            "seal-open-failed",
            "trust",
        ),
        (
            "tampered-ciphertext",
            base,
            tampered,
            "seal-open-failed",
            "trust",
        ),
        (
            "truncated-below-nonce-tag",
            base,
            truncated,
            "truncated",
            "malformed",
        ),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, ctx, blob, check, class) in cases {
        assert!(
            names.insert(name),
            "duplicate seal open-reject vector {name}"
        );
        let err = seal::unseal(&p.key, &ctx, &blob).expect_err("open-reject must fail closed");
        assert_eq!(err.check(), check, "seal open-reject {name}: check ({err})");
        assert_eq!(err.class(), class, "seal open-reject {name}: class ({err})");
        out.push(SealOpenRejectVector {
            name: name.to_string(),
            key: hexstr(&p.key),
            sealed: hexstr(&blob),
            v: ctx.v,
            id: hexstr(&ctx.id),
            scope: hexstr(&ctx.scope),
            epoch: ctx.epoch,
            struct_tag: ctx.struct_tag,
            check: check.to_string(),
            class: class.to_string(),
        });
    }
    out
}

fn build_read_body_accept() -> Vec<ReadBodyAcceptVector> {
    let empty_folder = ReadBody::Folder {
        created_at: 1,
        modified_at: 2,
        children: Vec::new(),
        unknown: Vec::new(),
    };
    let single_version = ReadBody::File {
        created_at: 3,
        modified_at: 4,
        versions: vec![Version::new(b"cid".to_vec(), [0x55; 32], 512, 4)],
        unknown: Vec::new(),
    };
    let cases: Vec<(&str, ReadBody)> = vec![
        ("empty-folder", empty_folder),
        ("folder-two-children", sample_folder()),
        ("file-single-version", single_version),
        ("file-multi-version", sample_file()),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, body) in cases {
        assert!(
            names.insert(name),
            "duplicate read-body accept vector {name}"
        );
        let bytes = encode_read_body(&body);
        let decoded = decode_read_body(&bytes)
            .unwrap_or_else(|e| panic!("read-body accept {name}: live decoder rejected it: {e}"));
        assert_eq!(decoded, body, "read-body accept {name}: decode != source");
        assert_eq!(
            encode_read_body(&decoded),
            bytes,
            "read-body accept {name}: re-encode not byte-stable"
        );
        out.push(ReadBodyAcceptVector {
            name: name.to_string(),
            hex: hexstr(&bytes),
            kind: body.kind().as_wire().to_string(),
        });
    }
    out
}

/// A child-ref map value with the given fields; used to hand-craft read-body
/// reject vectors the encoder itself could never emit.
fn child_map(id: Vec<u8>, name: &str, ipns: &[u8], kind: &str, link_counter: u64) -> Value {
    map_of(vec![
        ("id", Value::Bytes(id)),
        ("name", Value::Text(name.to_string())),
        ("ipnsName", Value::Bytes(ipns.to_vec())),
        ("kind", Value::Text(kind.to_string())),
        ("linkCounter", Value::Unsigned(link_counter)),
    ])
}

fn build_read_body_reject() -> Vec<RejectVector> {
    let good_child = |id: u8, ipns: &[u8]| child_map(vec![id; 16], "n", ipns, "file", 0);

    // (name, read-body Value, check, class). Each is hand-built so the defect is
    // explicit; the live decoder is asserted below to fire the named check.
    let cases: Vec<(&str, Value, &str, &str)> = vec![
        (
            "duplicate-child-id",
            map_of(vec![
                ("kind", Value::Text("folder".to_string())),
                (
                    "children",
                    Value::Array(vec![good_child(1, b"ipns-a"), good_child(1, b"ipns-b")]),
                ),
                ("createdAt", Value::Unsigned(1)),
                ("modifiedAt", Value::Unsigned(2)),
            ]),
            "duplicate-id",
            "trust",
        ),
        (
            "duplicate-child-ipns-name",
            map_of(vec![
                ("kind", Value::Text("folder".to_string())),
                (
                    "children",
                    Value::Array(vec![
                        good_child(1, b"same-ipns"),
                        good_child(2, b"same-ipns"),
                    ]),
                ),
                ("createdAt", Value::Unsigned(1)),
                ("modifiedAt", Value::Unsigned(2)),
            ]),
            "duplicate-ipns-name",
            "trust",
        ),
        (
            "unknown-node-kind",
            map_of(vec![
                ("kind", Value::Text("directory".to_string())),
                ("children", Value::Array(vec![])),
                ("createdAt", Value::Unsigned(1)),
                ("modifiedAt", Value::Unsigned(2)),
            ]),
            "invalid-node-kind",
            "malformed",
        ),
        (
            "child-id-wrong-length",
            map_of(vec![
                ("kind", Value::Text("folder".to_string())),
                (
                    "children",
                    Value::Array(vec![child_map(vec![0u8; 15], "n", b"ipns", "file", 0)]),
                ),
                ("createdAt", Value::Unsigned(1)),
                ("modifiedAt", Value::Unsigned(2)),
            ]),
            "invalid-field-length",
            "malformed",
        ),
        (
            "missing-kind",
            map_of(vec![
                ("children", Value::Array(vec![])),
                ("createdAt", Value::Unsigned(1)),
                ("modifiedAt", Value::Unsigned(2)),
            ]),
            "missing-field",
            "malformed",
        ),
        (
            "created-at-wrong-type",
            map_of(vec![
                ("kind", Value::Text("folder".to_string())),
                ("children", Value::Array(vec![])),
                ("createdAt", Value::Text("not-a-number".to_string())),
                ("modifiedAt", Value::Unsigned(2)),
            ]),
            "unexpected-type",
            "malformed",
        ),
    ];

    finish_hex_reject_vectors("read-body", cases, decode_read_body)
}

fn build_envelope_accept() -> Vec<EnvelopeAcceptVector> {
    // Every seal below reuses the one fixed (key, nonce) from `seal_probe()`.
    // That is deliberate and required here: KAT vectors must be byte-reproducible,
    // so the generator injects a pinned nonce rather than sampling one. It is NOT
    // a sanctioned production pattern — production sources a unique nonce per seal
    // from the entropy seam (see `seal()`'s doc: XChaCha20-Poly1305 nonce reuse
    // under one key breaks confidentiality and integrity). These fixtures protect
    // no real data; they only pin the wire format and the accept verdict.
    let p = seal_probe();
    let bodies: Vec<(&str, ReadBody)> = vec![("folder", sample_folder()), ("file", sample_file())];

    let mut names = BTreeSet::new();
    let mut out = Vec::new();

    for (name, body) in bodies {
        assert!(
            names.insert(name.to_string()),
            "duplicate envelope accept {name}"
        );
        let env = seal_read_body(&p.key, &p.nonce, p.v, p.id, p.scope, p.epoch, &body)
            .expect("sample bodies are valid");
        let envelope_hex = envelope_accept_self_check(name, &env, &body, &p.key);
        out.push(EnvelopeAcceptVector {
            name: name.to_string(),
            key: hexstr(&p.key),
            envelope: envelope_hex,
            read_body: hexstr(&encode_read_body(&body)),
        });
    }

    // An envelope carrying a future top-level field (writeSealed stand-in): it
    // must round-trip byte-stable and still open.
    let body = sample_folder();
    let env = seal_read_body(&p.key, &p.nonce, p.v, p.id, p.scope, p.epoch, &body)
        .expect("sample folder is valid");
    let mut m = decode(&encode_envelope(&env))
        .unwrap()
        .as_map()
        .unwrap()
        .clone();
    m.insert("writeSealed", Value::Bytes(b"future-write-body".to_vec()));
    let bytes = encode(&Value::Map(m));
    let decoded = decode_envelope(&bytes).expect("tolerant envelope decode");
    assert_eq!(
        encode_envelope(&decoded),
        bytes,
        "envelope accept with-unknown-field: not byte-stable"
    );
    assert_eq!(
        decoded.unknown.len(),
        1,
        "the unknown field must be preserved"
    );
    assert_eq!(
        open_read_body(&decoded, &p.key).expect("opens despite unknown field"),
        body,
        "envelope accept with-unknown-field: open mismatch"
    );
    assert!(
        names.insert("with-unknown-field".to_string()),
        "duplicate envelope accept with-unknown-field"
    );
    out.push(EnvelopeAcceptVector {
        name: "with-unknown-field".to_string(),
        key: hexstr(&p.key),
        envelope: hexstr(&bytes),
        read_body: hexstr(&encode_read_body(&body)),
    });

    out
}

/// Assert an envelope decodes byte-stable and its read-body opens to `body`;
/// returns the frozen envelope hex.
fn envelope_accept_self_check(
    name: &str,
    env: &cipherbox_core::seal::Envelope,
    body: &ReadBody,
    key: &[u8; KEY_LEN],
) -> String {
    let bytes = encode_envelope(env);
    let decoded = decode_envelope(&bytes)
        .unwrap_or_else(|e| panic!("envelope accept {name}: decode rejected it: {e}"));
    assert_eq!(&decoded, env, "envelope accept {name}: decode != source");
    assert_eq!(
        encode_envelope(&decoded),
        bytes,
        "envelope accept {name}: re-encode not byte-stable"
    );
    let opened = open_read_body(&decoded, key)
        .unwrap_or_else(|e| panic!("envelope accept {name}: open: {e}"));
    assert_eq!(
        &opened, body,
        "envelope accept {name}: opened body mismatch"
    );
    hexstr(&bytes)
}

fn build_envelope_reject() -> Vec<RejectVector> {
    let p = seal_probe();
    let env = seal_read_body(
        &p.key,
        &p.nonce,
        p.v,
        p.id,
        p.scope,
        p.epoch,
        &sample_folder(),
    )
    .expect("sample folder is valid");
    let base = decode(&encode_envelope(&env))
        .unwrap()
        .as_map()
        .unwrap()
        .clone();

    let mutated = |f: &dyn Fn(&mut Map)| {
        let mut m = base.clone();
        f(&mut m);
        Value::Map(m)
    };

    let cases: Vec<(&str, Value, &str, &str)> = vec![
        (
            "missing-v",
            mutated(&|m| {
                m.remove("v");
            }),
            "missing-field",
            "malformed",
        ),
        (
            "v-wrong-type",
            mutated(&|m| {
                m.insert("v", Value::Text("two".to_string()));
            }),
            "unexpected-type",
            "malformed",
        ),
        (
            "id-wrong-length",
            mutated(&|m| {
                m.insert("id", Value::Bytes(vec![0u8; 15]));
            }),
            "invalid-field-length",
            "malformed",
        ),
        (
            "epoch-tag-wrong-type",
            mutated(&|m| {
                m.insert("epochTag", Value::Unsigned(0));
            }),
            "unexpected-type",
            "malformed",
        ),
    ];

    finish_hex_reject_vectors("envelope", cases, decode_envelope)
}

/// Encode each hand-built defect Value, assert the live decoder fires the named
/// check + class, and freeze it as a `{name, hex, check, class}` reject vector.
fn finish_hex_reject_vectors<T, F>(
    family: &str,
    cases: Vec<(&str, Value, &str, &str)>,
    decode_fn: F,
) -> Vec<RejectVector>
where
    F: Fn(&[u8]) -> Result<T, cipherbox_core::error::CodecError>,
{
    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, value, check, class) in cases {
        assert!(
            names.insert(name),
            "duplicate {family} reject vector {name}"
        );
        let bytes = encode(&value);
        let err = match decode_fn(&bytes) {
            Err(e) => e,
            Ok(_) => panic!("{family} reject {name}: decoder accepted it"),
        };
        assert_eq!(err.check(), check, "{family} reject {name}: check ({err})");
        assert_eq!(err.class(), class, "{family} reject {name}: class ({err})");
        out.push(RejectVector {
            name: name.to_string(),
            hex: hexstr(&bytes),
            check: check.to_string(),
            class: class.to_string(),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// KDF edge vectors: the whole catalog under one fixed probe. Frozen outputs
// pin every edge byte-for-byte (a BLAKE3 or dependency change would move them),
// and the separation self-check asserts no two edges collide.
// ---------------------------------------------------------------------------

fn build_kdf_edges() -> KdfEdgesFile {
    // Fixed probe inputs, frozen alongside the outputs.
    let seed: [u8; 32] = std::array::from_fn(|i| i as u8);
    let id: [u8; 16] = std::array::from_fn(|i| (0x40 + i) as u8);
    let struct_tag = 0x01u8;
    let index = 0u64;
    let ipns_name = b"cipherbox/v2/scope-root".to_vec();

    let probe = EdgeProbe {
        seed: &seed,
        id: &id,
        struct_tag,
        index,
        ipns_name: &ipns_name,
    };
    let outputs = kdf::edge_probe_outputs(&probe);
    assert_eq!(outputs.len(), EDGES.len(), "probe must cover every edge");

    // Mechanical separation KAT: no two edges share an output for equal inputs.
    let distinct: BTreeSet<[u8; 32]> = outputs.iter().map(|o| o.output).collect();
    assert_eq!(
        distinct.len(),
        EDGES.len(),
        "two KDF edges produced equal output under uniform inputs"
    );

    let edges: Vec<EdgeVector> = outputs
        .iter()
        .zip(EDGES)
        .map(|(o, e)| {
            assert_eq!(o.name, e.name, "probe order must track EDGES order");
            EdgeVector {
                name: e.name.to_string(),
                context: e.context.to_string(),
                input_layout: e.input_layout.to_string(),
                output: hexstr(&o.output),
            }
        })
        .collect();

    KdfEdgesFile {
        probe: ProbeJson {
            seed: hexstr(&seed),
            id: hexstr(&id),
            struct_tag,
            index,
            ipns_name: hexstr(&ipns_name),
        },
        edges,
    }
}

// ---------------------------------------------------------------------------
// HPKE vectors: fixed-ephemeral seals (the eciesjs lesson — freeze enc + the
// whole ciphertext) plus open-reject cases pinning the fail-closed check.
// ---------------------------------------------------------------------------

/// A fixed HPKE seal case: name, ephemeral scalar, info, aad, plaintext.
type SealCase = (
    &'static str,
    [u8; 32],
    &'static [u8],
    &'static [u8],
    &'static [u8],
);

fn build_hpke_seal() -> Vec<HpkeSealVector> {
    let recipient_scalar: [u8; 32] = std::array::from_fn(|i| (0x10 + i) as u8);
    let recipient = X25519Secret::from_scalar(recipient_scalar);
    let recipient_public = recipient.public();

    let cases: Vec<SealCase> = vec![
        (
            "empty-info-empty-aad",
            std::array::from_fn(|i| (0x20 + i) as u8),
            b"",
            b"",
            b"grant blob payload",
        ),
        (
            "with-info-and-aad",
            std::array::from_fn(|i| (0x30 + i) as u8),
            b"cipherbox/v2 grant",
            b"scope-aad",
            b"read scope seed",
        ),
        (
            "empty-plaintext",
            std::array::from_fn(|i| (0x50 + i) as u8),
            b"info",
            b"aad",
            b"",
        ),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, eph, info, aad, pt) in cases {
        assert!(names.insert(name), "duplicate hpke seal vector {name}");
        let sealed = hpke_seal(&recipient_public, &eph, info, aad, pt);
        // Determinism under a fixed ephemeral scalar.
        assert_eq!(
            hpke_seal(&recipient_public, &eph, info, aad, pt),
            sealed,
            "hpke seal {name}: not deterministic"
        );
        // Round-trips.
        let opened = hpke_open(&recipient, &sealed.enc, info, aad, &sealed.ciphertext)
            .unwrap_or_else(|_| panic!("hpke seal {name}: open must recover plaintext"));
        assert_eq!(&opened[..], pt, "hpke seal {name}: plaintext mismatch");
        out.push(HpkeSealVector {
            name: name.to_string(),
            recipient_secret: hexstr(&recipient_scalar),
            recipient_public: hexstr(&recipient_public.to_bytes()),
            ephemeral_scalar: hexstr(&eph),
            info: hexstr(info),
            aad: hexstr(aad),
            plaintext: hexstr(pt),
            enc: hexstr(&sealed.enc),
            ciphertext: hexstr(&sealed.ciphertext),
        });
    }
    out
}

/// An hpke open-reject case: (name, enc, ciphertext, aad, expected check).
type HpkeOpenRejectCase = (&'static str, [u8; 32], Vec<u8>, &'static [u8], &'static str);

/// An RFC 7748 order-8 X25519 u-coordinate: a low-order point that forces an
/// all-zero ECDH, so a grant blob sealed to it would be world-readable (#708).
const LOW_ORDER_X25519: [u8; 32] = [
    0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
    0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
];

fn build_hpke_open_reject() -> Vec<HpkeOpenRejectVector> {
    let recipient_scalar: [u8; 32] = std::array::from_fn(|i| (0x10 + i) as u8);
    let recipient = X25519Secret::from_scalar(recipient_scalar);
    let eph: [u8; 32] = std::array::from_fn(|i| (0x60 + i) as u8);
    let info: &[u8] = b"info";
    let aad: &[u8] = b"aad";
    let sealed = hpke_seal(&recipient.public(), &eph, info, aad, b"open-me");
    assert!(
        hpke_open(&recipient, &sealed.enc, info, aad, &sealed.ciphertext).is_ok(),
        "baseline seal must open"
    );

    let mut tampered = sealed.ciphertext.clone();
    tampered[0] ^= 0x01;
    // A low-order `enc` (RFC 7748 order-8 point): decap rejects it as
    // non-contributory before the AEAD open, so the ciphertext is never reached
    // (RFC 9180 §7.1.4).
    let low_order_enc = LOW_ORDER_X25519;
    // (name, enc, ciphertext, aad, check).
    let cases: Vec<HpkeOpenRejectCase> = vec![
        (
            "tampered-ciphertext",
            sealed.enc,
            tampered,
            aad,
            "hpke-open-failed",
        ),
        (
            "wrong-aad",
            sealed.enc,
            sealed.ciphertext.clone(),
            b"other-aad",
            "hpke-open-failed",
        ),
        (
            "low-order-enc",
            low_order_enc,
            sealed.ciphertext.clone(),
            aad,
            "hpke-non-contributory",
        ),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, enc, ct, open_aad, check) in cases {
        assert!(
            names.insert(name),
            "duplicate hpke open-reject vector {name}"
        );
        let err =
            hpke_open(&recipient, &enc, info, open_aad, &ct).expect_err("open must fail closed");
        assert_eq!(err.check(), check, "hpke open-reject {name}");
        out.push(HpkeOpenRejectVector {
            name: name.to_string(),
            recipient_secret: hexstr(&recipient_scalar),
            enc: hexstr(&enc),
            info: hexstr(info),
            aad: hexstr(open_aad),
            ciphertext: hexstr(&ct),
            check: check.to_string(),
            class: "trust".to_string(),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Contact code vectors: valid codes that import, and every fail-closed reject —
// structural (malformed) and the mandatory binding verify (trust).
// ---------------------------------------------------------------------------

fn build_contact_accept() -> Vec<ContactAcceptVector> {
    let cases: Vec<(&str, [u8; 32], [u8; 32])> = vec![
        ("primary", [0x22; 32], [0x33; 32]),
        (
            "alt-keys",
            std::array::from_fn(|i| (i + 1) as u8),
            std::array::from_fn(|i| (0x80 + i) as u8),
        ),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, id_scalar, enc_scalar) in cases {
        assert!(names.insert(name), "duplicate contact accept vector {name}");
        let signer = EcdsaSigner::from_scalar(&id_scalar).expect("valid identity scalar");
        let enc_public = X25519Secret::from_scalar(enc_scalar).public();
        let code = ContactCode::create(&signer, enc_public);
        let bytes = code.encode();
        // Self-check: imports, and re-encode is byte-stable.
        let imported = import_contact_code(&bytes).expect("accept vector must import");
        assert_eq!(
            imported.encode(),
            bytes,
            "contact accept {name}: not byte-stable"
        );
        out.push(ContactAcceptVector {
            name: name.to_string(),
            hex: hexstr(&bytes),
            identity_pk: hexstr(&code.identity_pk().to_sec1()),
            enc_subkey: hexstr(&code.enc_subkey().to_bytes()),
            binding_sig: hexstr(&code.binding_sig().to_compact()),
        });
    }
    out
}

/// The 65-byte uncompressed SEC1 encoding of a compressed secp256k1 key: a
/// byte-distinct re-encoding of the same point that the frozen 33-byte identity
/// width must reject (issue #709).
fn uncompressed_sec1(compressed: &[u8]) -> Vec<u8> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let pk = k256::PublicKey::from_sec1_bytes(compressed).expect("valid compressed key");
    pk.to_encoded_point(false).as_bytes().to_vec()
}

fn build_contact_reject() -> Vec<RejectVector> {
    let signer = EcdsaSigner::from_scalar(&[0x22; 32]).expect("valid scalar");
    let good_id = signer.verifying_key().to_sec1().to_vec();
    let uncompressed_id = uncompressed_sec1(&good_id);
    let enc_public = X25519Secret::from_scalar([0x33; 32]).public();
    let good_enc = enc_public.to_bytes().to_vec();
    let good_sig = ContactCode::create(&signer, enc_public)
        .binding_sig()
        .to_compact()
        .to_vec();

    // A structurally valid code whose enc subkey has been flipped: every field
    // parses, but the binding no longer matches.
    let mut tampered_enc = good_enc.clone();
    tampered_enc[0] ^= 0x01;

    let bytes_of = |identity: Option<Value>, enc: Option<Value>, sig: Option<Value>| -> Vec<u8> {
        let mut m = Map::new();
        if let Some(v) = sig {
            m.insert("bindingSig", v);
        }
        if let Some(v) = enc {
            m.insert("encSubkey", v);
        }
        if let Some(v) = identity {
            m.insert("identityPk", v);
        }
        encode(&Value::Map(m))
    };
    let b = |v: &[u8]| Value::Bytes(v.to_vec());

    let cases: Vec<(&str, Vec<u8>, &str, &str)> = vec![
        (
            "missing-binding-sig",
            bytes_of(Some(b(&good_id)), Some(b(&good_enc)), None),
            "missing-field",
            "malformed",
        ),
        (
            "identity-pk-wrong-type",
            bytes_of(
                Some(Value::Unsigned(1)),
                Some(b(&good_enc)),
                Some(b(&good_sig)),
            ),
            "unexpected-type",
            "malformed",
        ),
        (
            "identity-pk-not-on-curve",
            bytes_of(Some(b(&[0xff; 33])), Some(b(&good_enc)), Some(b(&good_sig))),
            "invalid-identity-key",
            "malformed",
        ),
        (
            // A valid identity point re-encoded uncompressed (65 bytes): the
            // frozen 33-byte width rejects it before the binding verify runs.
            "identity-pk-uncompressed",
            bytes_of(
                Some(b(&uncompressed_id)),
                Some(b(&good_enc)),
                Some(b(&good_sig)),
            ),
            "invalid-identity-key",
            "malformed",
        ),
        (
            "enc-subkey-wrong-length",
            bytes_of(Some(b(&good_id)), Some(b(&[0u8; 31])), Some(b(&good_sig))),
            "invalid-enc-subkey",
            "malformed",
        ),
        (
            // A 32-byte but low-order enc subkey (RFC 7748 order-8 point): the
            // bytes are structurally fine, so it fails closed as a chosen-key
            // trust violation, rejected before the binding verify.
            "enc-subkey-low-order",
            bytes_of(
                Some(b(&good_id)),
                Some(b(&LOW_ORDER_X25519)),
                Some(b(&good_sig)),
            ),
            "hpke-non-contributory",
            "trust",
        ),
        (
            "binding-sig-wrong-length",
            bytes_of(Some(b(&good_id)), Some(b(&good_enc)), Some(b(&[0u8; 63]))),
            "invalid-binding-sig-encoding",
            "malformed",
        ),
        (
            "binding-sig-all-zero",
            bytes_of(Some(b(&good_id)), Some(b(&good_enc)), Some(b(&[0u8; 64]))),
            "invalid-binding-sig-encoding",
            "malformed",
        ),
        (
            "binding-does-not-verify",
            bytes_of(
                Some(b(&good_id)),
                Some(b(&tampered_enc)),
                Some(b(&good_sig)),
            ),
            "subkey-binding-invalid",
            "trust",
        ),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, bytes, check, class) in cases {
        assert!(names.insert(name), "duplicate contact reject vector {name}");
        let err = match import_contact_code(&bytes) {
            Err(e) => e,
            Ok(_) => panic!("contact reject {name}: import accepted it"),
        };
        assert_eq!(
            err.check(),
            check,
            "contact reject {name}: wrong check ({err})"
        );
        assert_eq!(
            err.class(),
            class,
            "contact reject {name}: wrong class ({err})"
        );
        out.push(RejectVector {
            name: name.to_string(),
            hex: hexstr(&bytes),
            check: check.to_string(),
            class: class.to_string(),
        });
    }
    out
}

// ===========================================================================
// IPNS records + name codec (ticket #622). Accept vectors come from the live
// codec/signer; reject and re-PUT vectors are hand-built protobuf so the frozen
// wire structure is pinned independently. Every vector self-checks against the
// live IPNS module before it is written.
// ===========================================================================

/// The `signatureV2` domain prefix, mirrored here so the generator builds the
/// signed preimage independently of `crate::ipns`.
const IPNS_SIG_DOMAIN: &[u8] = b"ipns-signature:";

/// A record-accept case: (name, signer seed, value, sequence, ttl, EOL).
type RecordAcceptCase = (&'static str, u8, &'static [u8], u64, u64, &'static str);
/// A pointer-reject case: (name, v, scope id, owner scalar, sealed, check).
type PointerRejectCase = (&'static str, u64, [u8; 16], [u8; 32], Vec<u8>, &'static str);
/// A mailbox-reject case: (name, recipient secret, v, block, check).
type MailboxRejectCase = (&'static str, [u8; 32], u64, Vec<u8>, &'static str);

fn ed_signer(seed: u8) -> Ed25519Signer {
    Ed25519Signer::from_seed([seed; 32])
}

fn ipns_name_of(seed: u8) -> IpnsName {
    IpnsName::from_public_key(&ed_signer(seed).verifying_key())
}

fn build_ipns_name_accept() -> Vec<NameAcceptVector> {
    let mut names = BTreeSet::new();
    let mut out = Vec::new();
    for seed in [1u8, 2, 7, 42] {
        let name = format!("seed-{seed}");
        assert!(names.insert(name.clone()), "duplicate name-accept {name}");
        let ipns = ipns_name_of(seed);
        // Self-check: the name parses back to the same key, byte-stable.
        let parsed = IpnsName::parse(ipns.as_str()).expect("own name parses");
        assert_eq!(parsed.public_key(), ed_signer(seed).verifying_key());
        assert_eq!(parsed.as_str(), ipns.as_str());
        out.push(NameAcceptVector {
            name,
            signer_seed: hexstr(&[seed; 32]),
            ipns_name: ipns.as_str().to_string(),
        });
    }
    out
}

fn build_ipns_name_reject() -> Vec<TextRejectVector> {
    // Off-curve and wrong-multicodec names are precomputed (their base36 bodies
    // encode non-key CID bytes); the rest are literal structural defects.
    let cases: Vec<(&str, &str)> = vec![
        ("wrong-multibase-prefix", "bxyz"),
        ("empty", ""),
        ("prefix-only", "k"),
        ("uppercase-not-base36", "kABC"),
        ("wrong-cid-length", "k0"),
        (
            "wrong-multicodec-dag-cbor",
            "k519aw276bkyh20qga910ek5zwiz9nlb329bkgak2epd50bejiw383bj8o7exo",
        ),
        (
            "off-curve-pubkey",
            "k51qzi5uqu5dg8dthom0e9mburtjey6kg9yav7ccp56wlnw1r89f0ny9l0ixvk",
        ),
    ];
    let mut names = BTreeSet::new();
    let mut out = Vec::new();
    for (name, text) in cases {
        assert!(names.insert(name), "duplicate name-reject {name}");
        let err = IpnsName::parse(text).expect_err("name-reject must fail");
        assert_eq!(err.check(), "ipns-name-malformed", "name-reject {name}");
        assert_eq!(err.class(), "malformed", "name-reject {name}");
        out.push(TextRejectVector {
            name: name.to_string(),
            text: text.to_string(),
            check: err.check().to_string(),
            class: err.class().to_string(),
        });
    }
    out
}

fn build_ipns_record_accept() -> Vec<RecordAcceptVector> {
    // (name, seed, value, sequence, ttl-nanos, RFC3339 EOL).
    let cases: Vec<RecordAcceptCase> = vec![
        (
            "first-publish-seq-1",
            3,
            b"/ipfs/bafyfirstpublish",
            1,
            3_600_000_000_000,
            "2026-10-18T00:00:00.000000000Z",
        ),
        (
            "cas-publish-seq-42",
            4,
            b"/ipfs/bafycasrepublish",
            42,
            86_400_000_000_000,
            "2026-12-31T23:59:59.000000000Z",
        ),
    ];
    let mut names = BTreeSet::new();
    let mut out = Vec::new();
    for (name, seed, value, sequence, ttl, validity) in cases {
        assert!(names.insert(name), "duplicate record-accept {name}");
        let signer = ed_signer(seed);
        let ipns = ipns_name_of(seed);
        let record = IpnsRecord::create_v2(&signer, value, sequence, ttl, validity).marshal();

        // Self-checks: byte-stable keyless re-PUT, and the verify chain extracts
        // the injected fields under the name's key.
        let reparsed = IpnsRecord::unmarshal(&record).expect("own record unmarshals");
        assert_eq!(reparsed.marshal(), record, "record-accept {name}: re-PUT");
        let verified = reparsed.verify(&ipns).expect("own record verifies");
        assert_eq!(verified.value, value, "record-accept {name}: value");
        assert_eq!(
            verified.sequence, sequence,
            "record-accept {name}: sequence"
        );
        assert_eq!(verified.ttl, ttl, "record-accept {name}: ttl");
        assert_eq!(
            verified.validity,
            validity.as_bytes(),
            "record-accept {name}: validity"
        );

        out.push(RecordAcceptVector {
            name: name.to_string(),
            signer_seed: hexstr(&[seed; 32]),
            ipns_name: ipns.as_str().to_string(),
            value: hexstr(value),
            sequence,
            ttl,
            validity: validity.to_string(),
            record: hexstr(&record),
        });
    }
    out
}

// --- hand-built IPNS protobuf, for the reject / re-PUT families -------------

fn pb_write_varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            out.push(byte | 0x80);
        } else {
            out.push(byte);
            return;
        }
    }
}

fn pb_len_field(number: u64, payload: &[u8], out: &mut Vec<u8>) {
    pb_write_varint((number << 3) | 2, out);
    pb_write_varint(payload.len() as u64, out);
    out.extend_from_slice(payload);
}

fn pb_varint_field(number: u64, value: u64, out: &mut Vec<u8>) {
    // Tag: field number, wire type 0 (varint).
    pb_write_varint(number << 3, out);
    pb_write_varint(value, out);
}

/// The signed `data` field, built independently of `crate::ipns`.
fn ipns_data_cbor(
    value: &[u8],
    validity: &[u8],
    validity_type: u64,
    sequence: u64,
    ttl: u64,
) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("TTL", Value::Unsigned(ttl));
    m.insert("Value", Value::Bytes(value.to_vec()));
    m.insert("Sequence", Value::Unsigned(sequence));
    m.insert("Validity", Value::Bytes(validity.to_vec()));
    m.insert("ValidityType", Value::Unsigned(validity_type));
    encode(&Value::Map(m))
}

fn ipns_sign(signer: &Ed25519Signer, data: &[u8]) -> [u8; 64] {
    let mut preimage = IPNS_SIG_DOMAIN.to_vec();
    preimage.extend_from_slice(data);
    signer.sign(&preimage).to_bytes()
}

fn build_ipns_record_reject() -> Vec<RecordRejectVector> {
    let seed = 5u8;
    let signer = ed_signer(seed);
    let ipns = ipns_name_of(seed);
    let value: &[u8] = b"/ipfs/bafybaserecord";
    let validity = "2026-01-01T00:00:00.000000000Z";
    let seq = 1u64;
    let ttl = 60_000_000_000u64;

    // A base valid record, then a single-defect data tamper.
    let base = IpnsRecord::create_v2(&signer, value, seq, ttl, validity).marshal();
    let mut tampered = base.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;

    // A record whose signed data.Value disagrees with the top-level value field.
    let data = ipns_data_cbor(value, validity.as_bytes(), 0, seq, ttl);
    let sig = ipns_sign(&signer, &data);
    let mut value_mismatch = Vec::new();
    pb_len_field(1, b"/ipfs/bafyDIFFERENTvalue", &mut value_mismatch);
    pb_varint_field(3, 0, &mut value_mismatch);
    pb_len_field(4, validity.as_bytes(), &mut value_mismatch);
    pb_varint_field(5, seq, &mut value_mismatch);
    pb_varint_field(6, ttl, &mut value_mismatch);
    pb_len_field(8, &sig, &mut value_mismatch);
    pb_len_field(9, &data, &mut value_mismatch);

    // A record missing signatureV2 (field 8) entirely.
    let mut missing_sig = Vec::new();
    pb_len_field(1, value, &mut missing_sig);
    pb_varint_field(3, 0, &mut missing_sig);
    pb_len_field(4, validity.as_bytes(), &mut missing_sig);
    pb_varint_field(5, seq, &mut missing_sig);
    pb_varint_field(6, ttl, &mut missing_sig);
    pb_len_field(9, &data, &mut missing_sig);

    // A record with a validly-signed but unsupported validity type (not EOL).
    let data_bad_vt = ipns_data_cbor(value, validity.as_bytes(), 1, seq, ttl);
    let sig_bad_vt = ipns_sign(&signer, &data_bad_vt);
    let mut bad_validity_type = Vec::new();
    pb_len_field(1, value, &mut bad_validity_type);
    pb_varint_field(3, 1, &mut bad_validity_type);
    pb_len_field(4, validity.as_bytes(), &mut bad_validity_type);
    pb_varint_field(5, seq, &mut bad_validity_type);
    pb_varint_field(6, ttl, &mut bad_validity_type);
    pb_len_field(8, &sig_bad_vt, &mut bad_validity_type);
    pb_len_field(9, &data_bad_vt, &mut bad_validity_type);

    // The signed data field (9) appearing twice: the unique_len_field guard must
    // reject a duplicated required field, never fold it silently.
    let mut duplicate_data = Vec::new();
    pb_len_field(1, value, &mut duplicate_data);
    pb_varint_field(3, 0, &mut duplicate_data);
    pb_len_field(4, validity.as_bytes(), &mut duplicate_data);
    pb_varint_field(5, seq, &mut duplicate_data);
    pb_varint_field(6, ttl, &mut duplicate_data);
    pb_len_field(8, &sig, &mut duplicate_data);
    pb_len_field(9, &data, &mut duplicate_data);
    pb_len_field(9, &data, &mut duplicate_data);

    // The value field (1) as a varint, not length-delimited: unique_len_field
    // requires WIRE_LEN for every required field (value/signatureV2/data).
    let mut value_wrong_wire = Vec::new();
    pb_varint_field(1, 7, &mut value_wrong_wire);
    pb_varint_field(3, 0, &mut value_wrong_wire);
    pb_len_field(4, validity.as_bytes(), &mut value_wrong_wire);
    pb_varint_field(5, seq, &mut value_wrong_wire);
    pb_varint_field(6, ttl, &mut value_wrong_wire);
    pb_len_field(8, &sig, &mut value_wrong_wire);
    pb_len_field(9, &data, &mut value_wrong_wire);

    let cases: Vec<(&str, Vec<u8>, &str, &str)> = vec![
        (
            "tampered-data-signature",
            tampered,
            "ipns-signature-invalid",
            "trust",
        ),
        (
            "value-mismatch",
            value_mismatch,
            "ipns-value-mismatch",
            "trust",
        ),
        (
            "missing-signature-v2",
            missing_sig,
            "ipns-record-malformed",
            "malformed",
        ),
        (
            "unsupported-validity-type",
            bad_validity_type,
            "ipns-record-malformed",
            "malformed",
        ),
        (
            "garbage-protobuf",
            vec![0xff],
            "ipns-record-malformed",
            "malformed",
        ),
        (
            "duplicate-data-field",
            duplicate_data,
            "ipns-record-malformed",
            "malformed",
        ),
        (
            "value-field-non-len-wire-type",
            value_wrong_wire,
            "ipns-record-malformed",
            "malformed",
        ),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::new();
    for (name, record, check, class) in cases {
        assert!(names.insert(name), "duplicate record-reject {name}");
        let err = IpnsRecord::unmarshal(&record)
            .and_then(|r| r.verify(&ipns))
            .expect_err("record-reject must fail");
        assert_eq!(err.check(), check, "record-reject {name}: check ({err})");
        assert_eq!(err.class(), class, "record-reject {name}: class ({err})");
        out.push(RecordRejectVector {
            name: name.to_string(),
            ipns_name: ipns.as_str().to_string(),
            record: hexstr(&record),
            check: check.to_string(),
            class: class.to_string(),
        });
    }
    out
}

fn build_ipns_record_reput() -> Vec<RecordReputVector> {
    // A foreign record carrying fields this codec does not model — a legacy
    // signatureV1 (field 2) and an inline pubKey (field 7) — in ascending field
    // order. Keyless re-PUT must reproduce it byte-for-byte, and verify (which
    // reads only signatureV2 over data) must still accept it.
    let seed = 6u8;
    let signer = ed_signer(seed);
    let ipns = ipns_name_of(seed);
    let value: &[u8] = b"/ipfs/bafyforeignrecord";
    let validity = "2026-06-30T12:00:00.000000000Z";
    let seq = 9u64;
    let ttl = 120_000_000_000u64;

    let data = ipns_data_cbor(value, validity.as_bytes(), 0, seq, ttl);
    let sig = ipns_sign(&signer, &data);

    let mut record = Vec::new();
    pb_len_field(1, value, &mut record);
    pb_len_field(2, b"legacy-v1-signature", &mut record);
    pb_varint_field(3, 0, &mut record);
    pb_len_field(4, validity.as_bytes(), &mut record);
    pb_varint_field(5, seq, &mut record);
    pb_varint_field(6, ttl, &mut record);
    pb_len_field(7, b"legacy-inline-pubkey", &mut record);
    pb_len_field(8, &sig, &mut record);
    pb_len_field(9, &data, &mut record);

    // Self-checks: byte-stable re-PUT preserves the unknown fields, and verify
    // still accepts (signatureV2 covers only data).
    let parsed = IpnsRecord::unmarshal(&record).expect("foreign record unmarshals");
    assert_eq!(
        parsed.marshal(),
        record,
        "re-PUT must preserve unknown fields"
    );
    let verified = parsed.verify(&ipns).expect("foreign record verifies");
    assert_eq!(verified.sequence, seq);

    vec![RecordReputVector {
        name: "with-legacy-v1-and-pubkey".to_string(),
        ipns_name: ipns.as_str().to_string(),
        record: hexstr(&record),
    }]
}

// ===========================================================================
// Pointer + mailbox payloads (ticket #622). Accept vectors freeze the sealed
// bytes under fixed keys/nonces/ephemerals; reject vectors pin the fail-closed
// checks. Each self-checks against the live payload module.
// ===========================================================================

fn build_pointer_accept() -> Vec<PointerAcceptVector> {
    let key = [0x33u8; KEY_LEN];
    let nonce = [0x44u8; NONCE_LEN];
    let v = 2u64;
    let owner_scalar = [0x21u8; 32];
    let owner = EcdsaSigner::from_scalar(&owner_scalar).expect("valid owner scalar");
    let scope_id = [0x07u8; 16];

    let cases: Vec<(&str, RepointObject)> = vec![
        (
            "with-prev-root",
            RepointObject {
                scope_id,
                current_root: ipns_name_of(1),
                write_epoch: 4,
                min_read_epoch: 2,
                prev_root: Some(ipns_name_of(2)),
            },
        ),
        (
            "first-publish-no-prev-root",
            RepointObject {
                scope_id,
                current_root: ipns_name_of(3),
                write_epoch: 1,
                min_read_epoch: 0,
                prev_root: None,
            },
        ),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::new();
    for (name, object) in cases {
        assert!(names.insert(name), "duplicate pointer-accept {name}");
        let sealed = seal_pointer_payload(&key, &nonce, v, &owner, &object);
        // Determinism + round-trip under the live module.
        assert_eq!(
            seal_pointer_payload(&key, &nonce, v, &owner, &object),
            sealed,
            "pointer-accept {name}: not deterministic"
        );
        let opened =
            open_pointer_payload(&key, v, &scope_id, &owner.verifying_key(), &sealed).unwrap();
        assert_eq!(opened, object, "pointer-accept {name}: round-trip");
        out.push(PointerAcceptVector {
            name: name.to_string(),
            pointer_read_key: hexstr(&key),
            nonce: hexstr(&nonce),
            v,
            owner_scalar: hexstr(&owner_scalar),
            scope_id: hexstr(&scope_id),
            current_root_name: object.current_root.as_str().to_string(),
            write_epoch: object.write_epoch,
            min_read_epoch: object.min_read_epoch,
            prev_root_name: object.prev_root.as_ref().map(|n| n.as_str().to_string()),
            sealed: hexstr(&sealed),
        });
    }
    out
}

fn build_pointer_reject() -> Vec<PointerRejectVector> {
    let key = [0x33u8; KEY_LEN];
    let nonce = [0x44u8; NONCE_LEN];
    let v = 2u64;
    let owner_scalar = [0x21u8; 32];
    let owner = EcdsaSigner::from_scalar(&owner_scalar).expect("valid owner scalar");
    let wrong_owner_scalar = [0x31u8; 32];
    let scope_id = [0x07u8; 16];
    let object = RepointObject {
        scope_id,
        current_root: ipns_name_of(1),
        write_epoch: 4,
        min_read_epoch: 2,
        prev_root: Some(ipns_name_of(2)),
    };
    let sealed = seal_pointer_payload(&key, &nonce, v, &owner, &object);

    let mut tampered = sealed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;

    // (name, v, scope_id, owner_scalar, sealed, check).
    let cases: Vec<PointerRejectCase> = vec![
        (
            "tampered-sealed",
            v,
            scope_id,
            owner_scalar,
            tampered,
            "seal-open-failed",
        ),
        (
            "scope-transplant",
            v,
            [0x08u8; 16],
            owner_scalar,
            sealed.clone(),
            "seal-open-failed",
        ),
        (
            "version-downgrade",
            1,
            scope_id,
            owner_scalar,
            sealed.clone(),
            "seal-open-failed",
        ),
        (
            "wrong-owner-key",
            v,
            scope_id,
            wrong_owner_scalar,
            sealed.clone(),
            "identity-signature-invalid",
        ),
        (
            "truncated-sealed",
            v,
            scope_id,
            owner_scalar,
            sealed[..NONCE_LEN + TAG_LEN - 1].to_vec(),
            "truncated",
        ),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::new();
    for (name, ver, scope, owner_scalar, blob, check) in cases {
        assert!(names.insert(name), "duplicate pointer-reject {name}");
        let verifier = EcdsaSigner::from_scalar(&owner_scalar)
            .expect("valid scalar")
            .verifying_key();
        let err = open_pointer_payload(&key, ver, &scope, &verifier, &blob)
            .expect_err("pointer-reject must fail");
        assert_eq!(err.check(), check, "pointer-reject {name}: check ({err})");
        out.push(PointerRejectVector {
            name: name.to_string(),
            pointer_read_key: hexstr(&key),
            v: ver,
            scope_id: hexstr(&scope),
            owner_scalar: hexstr(&owner_scalar),
            sealed: hexstr(&blob),
            check: err.check().to_string(),
            class: err.class().to_string(),
        });
    }
    out
}

fn build_mailbox_accept() -> Vec<MailboxAcceptVector> {
    let recipient_scalar = [0x40u8; 32];
    let recipient = X25519Secret::from_scalar(recipient_scalar);
    let recipient_public = recipient.public();
    let v = 2u64;
    let sender_scalar = [0x22u8; 32];
    let sender = EcdsaSigner::from_scalar(&sender_scalar).expect("valid sender scalar");

    // Each seal to `recipient` draws its own ephemeral. An HPKE seal is
    // plaintext-independent, so a shared ephemeral under one recipient/AAD reuses
    // the XChaCha20-Poly1305 key + base nonce across distinct plaintexts.
    let cases: Vec<(&str, [u8; 32], &[u8])> = vec![
        ("discovery-ping", [0x51u8; 32], b"discovery ping payload"),
        ("empty-payload", [0x52u8; 32], b""),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::new();
    for (name, eph, payload) in cases {
        assert!(names.insert(name), "duplicate mailbox-accept {name}");
        let block = seal_mailbox_payload(&recipient_public, &eph, v, &sender, payload);
        assert_eq!(
            seal_mailbox_payload(&recipient_public, &eph, v, &sender, payload),
            block,
            "mailbox-accept {name}: not deterministic"
        );
        let item = open_mailbox_payload(&recipient, v, &block).unwrap();
        assert_eq!(item.payload, payload, "mailbox-accept {name}: payload");
        assert_eq!(
            item.sender_identity,
            sender.verifying_key(),
            "mailbox-accept {name}: sender"
        );
        out.push(MailboxAcceptVector {
            name: name.to_string(),
            recipient_secret: hexstr(&recipient_scalar),
            recipient_public: hexstr(&recipient_public.to_bytes()),
            ephemeral_scalar: hexstr(&eph),
            v,
            sender_scalar: hexstr(&sender_scalar),
            payload: hexstr(payload),
            block: hexstr(&block),
        });
    }

    out
}

fn build_mailbox_reject() -> Vec<MailboxRejectVector> {
    let recipient_scalar = [0x40u8; 32];
    let recipient = X25519Secret::from_scalar(recipient_scalar);
    let v = 2u64;
    let sender = EcdsaSigner::from_scalar(&[0x22u8; 32]).expect("valid sender scalar");
    // The authentic block and the forged block seal distinct plaintexts to one
    // recipient: distinct ephemerals keep each seal's key + base nonce unique.
    let authentic_eph = [0x55u8; 32];
    let forged_eph = [0x56u8; 32];
    let block = seal_mailbox_payload(
        &recipient.public(),
        &authentic_eph,
        v,
        &sender,
        b"authentic",
    );

    // Tamper the ciphertext inside the block and re-encode.
    let mut m = decode(&block).unwrap().as_map().unwrap().clone();
    let mut ct = m.get("ct").unwrap().as_bytes().unwrap().to_vec();
    ct[0] ^= 0x01;
    m.insert("ct", Value::Bytes(ct));
    let tampered_block = encode(&Value::Map(m));

    // A block that opens (anyone can HPKE-seal) but whose sender signature does
    // not verify: build the inner with a wrong signature and seal it.
    let sender_pk = sender.verifying_key().to_sec1();
    let mut inner = Map::new();
    inner.insert("payload", Value::Bytes(b"forged".to_vec()));
    inner.insert("senderIdentityPk", Value::Bytes(sender_pk.to_vec()));
    inner.insert(
        "senderSig",
        Value::Bytes(
            sender
                .sign_detcbor(b"not the preimage")
                .to_compact()
                .to_vec(),
        ),
    );
    let inner_bytes = encode(&Value::Map(inner));
    let info = build_aad(&AadContext {
        v,
        id: [0; 16],
        scope: [0; 16],
        epoch: 0,
        struct_tag: STRUCT_TAG_MAILBOX_PAYLOAD,
    });
    let sealed = hpke_seal(&recipient.public(), &forged_eph, &info, &[], &inner_bytes);
    let mut forged = Map::new();
    forged.insert("ct", Value::Bytes(sealed.ciphertext));
    forged.insert("enc", Value::Bytes(sealed.enc.to_vec()));
    let forged_block = encode(&Value::Map(forged));

    // A block that opens but whose senderIdentityPk is the 65-byte uncompressed
    // re-encoding of the sender key: the frozen 33-byte identity width rejects it
    // as identity-signature-invalid, and — because sig_preimage hashes the raw
    // sender key — an uncompressed re-encode is byte-distinct from the authentic
    // block, so admitting it would forge a distinct signed preimage (issue #709).
    let uncompressed_eph = [0x57u8; 32];
    let mut uncompressed_inner = Map::new();
    uncompressed_inner.insert("payload", Value::Bytes(b"uncompressed".to_vec()));
    uncompressed_inner.insert(
        "senderIdentityPk",
        Value::Bytes(uncompressed_sec1(&sender_pk)),
    );
    uncompressed_inner.insert(
        "senderSig",
        Value::Bytes(sender.sign_detcbor(b"any").to_compact().to_vec()),
    );
    let uncompressed_inner_bytes = encode(&Value::Map(uncompressed_inner));
    let sealed_uncompressed = hpke_seal(
        &recipient.public(),
        &uncompressed_eph,
        &info,
        &[],
        &uncompressed_inner_bytes,
    );
    let mut uncompressed_block_map = Map::new();
    uncompressed_block_map.insert("ct", Value::Bytes(sealed_uncompressed.ciphertext));
    uncompressed_block_map.insert("enc", Value::Bytes(sealed_uncompressed.enc.to_vec()));
    let uncompressed_block = encode(&Value::Map(uncompressed_block_map));

    // Cross-recipient relay lift (#712): R1 opens an item sealed to it and
    // re-seals the untouched inner — sender signature included — to R2. Recipient
    // binding in the signature preimage makes R2's identity check fail.
    let r2_scalar = [0x42u8; 32];
    let r2 = X25519Secret::from_scalar(r2_scalar);
    let r1_relay_eph = [0x54u8; 32];
    let relay_eph = [0x53u8; 32];
    let block_to_r1 =
        seal_mailbox_payload(&recipient.public(), &r1_relay_eph, v, &sender, b"relayed");
    let r1_map = decode(&block_to_r1).unwrap().as_map().unwrap().clone();
    let ct1 = r1_map.get("ct").unwrap().as_bytes().unwrap().to_vec();
    let enc1: [u8; 32] = r1_map
        .get("enc")
        .unwrap()
        .as_bytes()
        .unwrap()
        .try_into()
        .unwrap();
    let relayed_inner = hpke_open(&recipient, &enc1, &info, &[], &ct1).expect("R1 opens the item");
    let sealed_to_r2 = hpke_seal(&r2.public(), &relay_eph, &info, &[], &relayed_inner);
    let mut relay_block_map = Map::new();
    relay_block_map.insert("ct", Value::Bytes(sealed_to_r2.ciphertext));
    relay_block_map.insert("enc", Value::Bytes(sealed_to_r2.enc.to_vec()));
    let relay_block = encode(&Value::Map(relay_block_map));

    // (name, recipient_secret, v, block, check).
    let wrong_recipient = [0x41u8; 32];
    let cases: Vec<MailboxRejectCase> = vec![
        (
            "tampered-ciphertext",
            recipient_scalar,
            v,
            tampered_block,
            "hpke-open-failed",
        ),
        (
            "version-downgrade",
            recipient_scalar,
            1,
            block.clone(),
            "hpke-open-failed",
        ),
        (
            "wrong-recipient",
            wrong_recipient,
            v,
            block.clone(),
            "hpke-open-failed",
        ),
        (
            "forged-sender-signature",
            recipient_scalar,
            v,
            forged_block,
            "identity-signature-invalid",
        ),
        (
            "sender-pk-uncompressed",
            recipient_scalar,
            v,
            uncompressed_block,
            "identity-signature-invalid",
        ),
        (
            "relay-to-other-recipient",
            r2_scalar,
            v,
            relay_block,
            "identity-signature-invalid",
        ),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::new();
    for (name, secret, ver, blob, check) in cases {
        assert!(names.insert(name), "duplicate mailbox-reject {name}");
        let err = open_mailbox_payload(&X25519Secret::from_scalar(secret), ver, &blob)
            .expect_err("mailbox-reject must fail");
        assert_eq!(err.check(), check, "mailbox-reject {name}: check ({err})");
        out.push(MailboxRejectVector {
            name: name.to_string(),
            recipient_secret: hexstr(&secret),
            v: ver,
            block: hexstr(&blob),
            check: err.check().to_string(),
            class: err.class().to_string(),
        });
    }
    out
}

// ===========================================================================
// Grant section (ticket #621): the write-body, the grant/owner blobs, the
// ascent + history links, the structure signatures, and the grant-set
// commitment. Every vector self-checks against the live code before it is
// written, and the fixed keys/scalars/nonces make each seal byte-reproducible
// (the eciesjs lesson, applied per structure; production sources a fresh
// per-seal ephemeral/nonce from the entropy seam — see the seal-layer docs).
// ===========================================================================

/// The whole grant-family vector inventory, returned by [`build_grant_vectors`].
struct GrantVectors {
    write_body_accept: Vec<WriteBodyAcceptVector>,
    write_body_reject: Vec<RejectVector>,
    grant_blob_accept: Vec<HpkeStructureVector>,
    grant_blob_reject: Vec<BlobRejectVector>,
    owner_blob_accept: Vec<HpkeStructureVector>,
    owner_blob_reject: Vec<BlobRejectVector>,
    ascent_link_accept: Vec<AscentLinkAcceptVector>,
    ascent_link_reject: Vec<AscentLinkRejectVector>,
    history_link_accept: Vec<HistoryLinkAcceptVector>,
    history_link_reject: Vec<RejectVector>,
    structure_sig_accept: Vec<StructureSigAcceptVector>,
    structure_sig_reject: Vec<StructureSigRejectVector>,
    grant_set_accept: Vec<GrantSetAcceptVector>,
    grant_set_reject: Vec<GrantSetRejectVector>,
    section_accept: Vec<SectionAcceptVector>,
    section_reject: Vec<RejectVector>,
}

impl GrantVectors {
    fn total(&self) -> usize {
        self.section_accept.len()
            + self.section_reject.len()
            + self.write_body_accept.len()
            + self.write_body_reject.len()
            + self.grant_blob_accept.len()
            + self.grant_blob_reject.len()
            + self.owner_blob_accept.len()
            + self.owner_blob_reject.len()
            + self.ascent_link_accept.len()
            + self.ascent_link_reject.len()
            + self.history_link_accept.len()
            + self.history_link_reject.len()
            + self.structure_sig_accept.len()
            + self.structure_sig_reject.len()
            + self.grant_set_accept.len()
            + self.grant_set_reject.len()
    }
}

/// Frozen probe material shared across the grant families so their vectors are
/// mutually consistent (a scope root's id equals its scope, per the AAD).
const GRANT_V: u64 = 2;
const GRANT_EPOCH: u64 = 4;
fn grant_scope_id() -> [u8; 16] {
    std::array::from_fn(|i| (0xc0 + i) as u8)
}

/// The AAD context of a scope-root grant structure: `id == scope` (the scope
/// root's own node id is the scope id).
fn grant_ctx(struct_tag: u8) -> AadContext {
    let id = grant_scope_id();
    AadContext {
        v: GRANT_V,
        id,
        scope: id,
        epoch: GRANT_EPOCH,
        struct_tag,
    }
}

fn build_grant_vectors() -> GrantVectors {
    GrantVectors {
        write_body_accept: build_write_body_accept(),
        write_body_reject: build_write_body_reject(),
        section_accept: build_grant_section_accept(),
        section_reject: build_grant_section_reject(),
        grant_blob_accept: build_grant_blob_accept(),
        grant_blob_reject: build_grant_blob_reject(),
        owner_blob_accept: build_owner_blob_accept(),
        owner_blob_reject: build_owner_blob_reject(),
        ascent_link_accept: build_ascent_link_accept(),
        ascent_link_reject: build_ascent_link_reject(),
        history_link_accept: build_history_link_accept(),
        history_link_reject: build_history_link_reject(),
        structure_sig_accept: build_structure_sig_accept(),
        structure_sig_reject: build_structure_sig_reject(),
        grant_set_accept: build_grant_set_accept(),
        grant_set_reject: build_grant_set_reject(),
    }
}

// --- Write-body -------------------------------------------------------------

fn build_write_body_accept() -> Vec<WriteBodyAcceptVector> {
    let full = WriteBody {
        grant_ledger: vec![
            GrantLedgerEntry::new([0x02; 33], [0x11; 32], Permission::Read, [0x21; 32]),
            GrantLedgerEntry::new([0x03; 33], [0x12; 32], Permission::Write, [0x22; 32]),
        ],
        write_history_link: b"sealed-write-history-link".to_vec(),
        direct_child_scope_index: vec![
            ChildScopeRef::new([0x55; 16], b"child-scope-ipns-a".to_vec()),
            ChildScopeRef::new([0x66; 16], b"child-scope-ipns-b".to_vec()),
        ],
        unknown: Vec::new(),
    };
    // Write epoch 1: no prior write epoch, so no history link, and a scope root
    // with no descendant scopes and no grants yet.
    let epoch_one = WriteBody {
        grant_ledger: Vec::new(),
        write_history_link: Vec::new(),
        direct_child_scope_index: Vec::new(),
        unknown: Vec::new(),
    };
    let read_only = WriteBody {
        grant_ledger: vec![GrantLedgerEntry::new(
            [0x02; 33],
            [0x11; 32],
            Permission::Read,
            [0x21; 32],
        )],
        write_history_link: b"h".to_vec(),
        direct_child_scope_index: vec![ChildScopeRef::new([0x77; 16], b"one-child".to_vec())],
        unknown: Vec::new(),
    };
    let cases: Vec<(&str, WriteBody)> = vec![
        ("full", full),
        ("write-epoch-1-empty", epoch_one),
        ("read-only-single-child", read_only),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, body) in cases {
        assert!(names.insert(name), "duplicate write-body accept {name}");
        let bytes = encode_write_body(&body).expect("write-body accept encodes");
        let decoded = decode_write_body(&bytes)
            .unwrap_or_else(|e| panic!("write-body accept {name}: rejected: {e}"));
        assert_eq!(decoded, body, "write-body accept {name}: decode != source");
        assert_eq!(
            encode_write_body(&decoded).unwrap(),
            bytes,
            "write-body accept {name}: not byte-stable"
        );
        out.push(WriteBodyAcceptVector {
            name: name.to_string(),
            hex: hexstr(&bytes),
            ledger_count: body.grant_ledger.len(),
            child_scope_count: body.direct_child_scope_index.len(),
        });
    }
    out
}

/// A grant-ledger entry map value, for hand-crafting write-body reject vectors.
fn ledger_entry_map(identity: Vec<u8>, enc: Vec<u8>, permission: &str, tag: Vec<u8>) -> Value {
    map_of(vec![
        ("permission", Value::Text(permission.to_string())),
        ("recipientEncPk", Value::Bytes(enc)),
        ("recipientIdentityPk", Value::Bytes(identity)),
        ("tag", Value::Bytes(tag)),
    ])
}

fn build_write_body_reject() -> Vec<RejectVector> {
    // A write-body with the given grant ledger and write-history-link value; the
    // child-scope index is always empty. Each case builds its whole map, so no
    // key is ever inserted twice.
    let body = |ledger: Vec<Value>, write_history_link: Value| {
        map_of(vec![
            ("directChildScopeIndex", Value::Array(vec![])),
            ("grantLedger", Value::Array(ledger)),
            ("writeHistoryLink", write_history_link),
        ])
    };
    let good_entry = || ledger_entry_map(vec![0x02; 33], vec![0x11; 32], "read", vec![0x21; 32]);

    let cases: Vec<(&str, Value, &str, &str)> = vec![
        (
            "ledger-invalid-permission",
            body(
                vec![ledger_entry_map(
                    vec![0x02; 33],
                    vec![0x11; 32],
                    "owner",
                    vec![0x21; 32],
                )],
                Value::Bytes(vec![]),
            ),
            "invalid-permission",
            "malformed",
        ),
        (
            "identity-pk-wrong-length",
            body(
                vec![ledger_entry_map(
                    vec![0x02; 32],
                    vec![0x11; 32],
                    "read",
                    vec![0x21; 32],
                )],
                Value::Bytes(vec![]),
            ),
            "invalid-field-length",
            "malformed",
        ),
        (
            "missing-grant-ledger",
            map_of(vec![
                ("directChildScopeIndex", Value::Array(vec![])),
                ("writeHistoryLink", Value::Bytes(vec![])),
            ]),
            "missing-field",
            "malformed",
        ),
        (
            "write-history-link-wrong-type",
            body(vec![good_entry()], Value::Unsigned(0)),
            "unexpected-type",
            "malformed",
        ),
        (
            // Confused-deputy: one blinded tag committed twice, `read` then
            // `write`, with a different recipientEncPk — the shared-write holder
            // injecting a second ledger row for a victim's tag.
            "ledger-duplicate-tag",
            body(
                vec![
                    ledger_entry_map(vec![0x02; 33], vec![0x11; 32], "read", vec![0x21; 32]),
                    ledger_entry_map(vec![0x03; 33], vec![0x99; 32], "write", vec![0x21; 32]),
                ],
                Value::Bytes(vec![]),
            ),
            "duplicate-grant-tag",
            "trust",
        ),
    ];

    finish_hex_reject_vectors("write-body", cases, decode_write_body)
}

// --- Grant section (the seed-bearing-structure bundle) ----------------------

/// A frozen grant-section bundle: the framing codec is crypto-free, so the
/// sealed bytes and signatures are fixed opaque fillers (the sig-verifying KATs
/// live in the per-structure families). A commitment is a real encoded
/// `GrantSetCommitment` so `decode_grant_section` exercises the nested codec.
fn section_commitment(entries: Vec<GrantSetEntry>) -> GrantSetCommitment {
    GrantSetCommitment {
        ipns_name: b"grant-section-scope-root".to_vec(),
        owner_pseudonym_pk: [0x88; 32],
        entries,
        unknown: Vec::new(),
    }
}

fn section_grant_blob(tag: u8) -> SignedGrantBlob {
    SignedGrantBlob {
        tag: [tag; 32],
        enc: [0x0a; 32],
        ciphertext: vec![0x0b, 0x0c, 0x0d],
        signature: [0x0e; 64],
        unknown: Vec::new(),
    }
}

fn build_grant_section_accept() -> Vec<SectionAcceptVector> {
    let full = seal::GrantSection {
        commitment: section_commitment(vec![
            GrantSetEntry::new([0x01; 32], Permission::Read, [0x02; 32]),
            GrantSetEntry::new([0x03; 32], Permission::Write, [0x04; 32]),
        ]),
        commitment_sig: [0x11; 64],
        grant_blobs: vec![section_grant_blob(0x01), section_grant_blob(0x03)],
        owner_blob: SignedOwnerBlob {
            enc: [0x20; 32],
            ciphertext: vec![0x21, 0x22],
            signature: [0x23; 64],
            unknown: Vec::new(),
        },
        ascent_link: Some(SignedAscentLink {
            ascent_public: [0x30; 32],
            enc: [0x31; 32],
            ciphertext: vec![0x32, 0x33],
            signature: [0x34; 64],
            unknown: Vec::new(),
        }),
        history_links: vec![SignedSealed {
            sealed: vec![0x40, 0x41, 0x42],
            signature: [0x43; 64],
            unknown: Vec::new(),
        }],
        write_body: SignedSealed {
            sealed: vec![0x50, 0x51, 0x52],
            signature: [0x53; 64],
            unknown: Vec::new(),
        },
        unknown: Vec::new(),
    };
    // Epoch 1 at the vault root: no grants, no history link, no ascent link.
    let minimal = seal::GrantSection {
        commitment: section_commitment(Vec::new()),
        commitment_sig: [0x11; 64],
        grant_blobs: Vec::new(),
        owner_blob: SignedOwnerBlob {
            enc: [0x20; 32],
            ciphertext: vec![0x21],
            signature: [0x23; 64],
            unknown: Vec::new(),
        },
        ascent_link: None,
        history_links: Vec::new(),
        write_body: SignedSealed {
            sealed: vec![0x50],
            signature: [0x53; 64],
            unknown: Vec::new(),
        },
        unknown: Vec::new(),
    };
    let cases: Vec<(&str, seal::GrantSection)> =
        vec![("full", full), ("vault-root-epoch-1", minimal)];

    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, section) in cases {
        assert!(names.insert(name), "duplicate grant-section accept {name}");
        let bytes = seal::encode_grant_section(&section).expect("grant-section accept encodes");
        let decoded = seal::decode_grant_section(&bytes)
            .unwrap_or_else(|e| panic!("grant-section accept {name}: rejected: {e}"));
        assert_eq!(
            decoded, section,
            "grant-section accept {name}: decode != source"
        );
        assert_eq!(
            seal::encode_grant_section(&decoded).unwrap(),
            bytes,
            "grant-section accept {name}: not byte-stable"
        );
        out.push(SectionAcceptVector {
            name: name.to_string(),
            hex: hexstr(&bytes),
            grant_blob_count: section.grant_blobs.len(),
            history_link_count: section.history_links.len(),
            has_ascent_link: section.ascent_link.is_some(),
        });
    }
    out
}

fn build_grant_section_reject() -> Vec<RejectVector> {
    // A structural filler owner blob / write body map for hand-built sections.
    let owner_blob = || {
        map_of(vec![
            ("ciphertext", Value::Bytes(vec![0x21, 0x22])),
            ("enc", Value::Bytes(vec![0x20; 32])),
            ("sig", Value::Bytes(vec![0x23; 64])),
        ])
    };
    let write_body = || {
        map_of(vec![
            ("sealed", Value::Bytes(vec![0x50, 0x51])),
            ("sig", Value::Bytes(vec![0x53; 64])),
        ])
    };
    let commitment_bytes =
        encode_grant_set_commitment(&section_commitment(Vec::new())).expect("commitment encodes");
    let grant_blob_map = |tag: u8| {
        map_of(vec![
            ("ciphertext", Value::Bytes(vec![0x0b, 0x0c])),
            ("enc", Value::Bytes(vec![0x0a; 32])),
            ("sig", Value::Bytes(vec![0x0e; 64])),
            ("tag", Value::Bytes(vec![tag; 32])),
        ])
    };
    // A whole section map with caller-chosen grant blobs / owner blob presence.
    let section = |grant_blobs: Vec<Value>, owner: Option<Value>| {
        let mut entries = vec![
            ("commitment", Value::Bytes(commitment_bytes.clone())),
            ("commitmentSig", Value::Bytes(vec![0x11; 64])),
            ("grantBlobs", Value::Array(grant_blobs)),
            ("historyLinks", Value::Array(vec![])),
            ("writeBody", write_body()),
        ];
        if let Some(o) = owner {
            entries.push(("ownerBlob", o));
        }
        map_of(entries)
    };

    let cases: Vec<(&str, Value, &str, &str)> = vec![
        (
            // Confused-deputy: one blinded tag under two grant blobs.
            "duplicate-grant-blob-tag",
            section(
                vec![grant_blob_map(0x01), grant_blob_map(0x01)],
                Some(owner_blob()),
            ),
            "duplicate-grant-tag",
            "trust",
        ),
        (
            "missing-owner-blob",
            section(vec![], None),
            "missing-field",
            "malformed",
        ),
        (
            // A structure signature truncated below the fixed 64-byte width.
            "owner-blob-short-signature",
            section(
                vec![],
                Some(map_of(vec![
                    ("ciphertext", Value::Bytes(vec![0x21])),
                    ("enc", Value::Bytes(vec![0x20; 32])),
                    ("sig", Value::Bytes(vec![0x23; 63])),
                ])),
            ),
            "invalid-field-length",
            "malformed",
        ),
        (
            "commitment-sig-wrong-type",
            map_of(vec![
                ("commitment", Value::Bytes(commitment_bytes.clone())),
                ("commitmentSig", Value::Unsigned(0)),
                ("grantBlobs", Value::Array(vec![])),
                ("historyLinks", Value::Array(vec![])),
                ("ownerBlob", owner_blob()),
                ("writeBody", write_body()),
            ]),
            "unexpected-type",
            "malformed",
        ),
    ];

    finish_hex_reject_vectors("grant-section", cases, seal::decode_grant_section)
}

// --- Grant blob (HPKE) ------------------------------------------------------

fn build_grant_blob_accept() -> Vec<HpkeStructureVector> {
    let recipient_scalar: [u8; 32] = std::array::from_fn(|i| (0x30 + i) as u8);
    let recipient = X25519Secret::from_scalar(recipient_scalar);
    let ctx = grant_ctx(STRUCT_TAG_GRANT_BLOB);

    let cases: Vec<(&str, [u8; 32], GrantBlobPayload)> = vec![
        (
            "read-grant",
            std::array::from_fn(|i| (0x50 + i) as u8),
            GrantBlobPayload::new([0x11; 32], None, GRANT_EPOCH, [0x22; 32]),
        ),
        (
            "write-grant",
            std::array::from_fn(|i| (0x58 + i) as u8),
            GrantBlobPayload::new([0x11; 32], Some([0x44; 32]), GRANT_EPOCH, [0x22; 32]),
        ),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, eph, payload) in cases {
        assert!(names.insert(name), "duplicate grant-blob accept {name}");
        let plaintext = encode_grant_blob_payload(&payload);
        let sealed = seal_grant_blob(&recipient.public(), &eph, &ctx, &payload);
        assert_eq!(
            seal_grant_blob(&recipient.public(), &eph, &ctx, &payload).ciphertext,
            sealed.ciphertext,
            "grant-blob {name}: not deterministic"
        );
        let opened = open_grant_blob(&recipient, &sealed.enc, &ctx, &sealed.ciphertext)
            .unwrap_or_else(|e| panic!("grant-blob {name}: open: {e}"));
        assert_eq!(opened, payload, "grant-blob {name}: round-trip");
        out.push(hpke_structure_vector(
            name,
            &ctx,
            recipient_scalar,
            &recipient,
            eph,
            &plaintext,
            &sealed,
        ));
    }
    out
}

fn build_grant_blob_reject() -> Vec<BlobRejectVector> {
    let cases: Vec<(&str, Value, &str, &str)> = vec![
        (
            "read-scope-seed-wrong-length",
            map_of(vec![
                ("epoch", Value::Unsigned(GRANT_EPOCH)),
                ("pointerReadKey", Value::Bytes(vec![0x22; 32])),
                ("readScopeSeed", Value::Bytes(vec![0x11; 31])),
            ]),
            "invalid-field-length",
            "malformed",
        ),
        (
            "missing-pointer-read-key",
            map_of(vec![
                ("epoch", Value::Unsigned(GRANT_EPOCH)),
                ("readScopeSeed", Value::Bytes(vec![0x11; 32])),
            ]),
            "missing-field",
            "malformed",
        ),
        (
            "epoch-wrong-type",
            map_of(vec![
                ("epoch", Value::Text("four".to_string())),
                ("pointerReadKey", Value::Bytes(vec![0x22; 32])),
                ("readScopeSeed", Value::Bytes(vec![0x11; 32])),
            ]),
            "unexpected-type",
            "malformed",
        ),
    ];
    let mut out: Vec<BlobRejectVector> =
        finish_hex_reject_vectors("grant-blob", cases, decode_grant_blob_payload)
            .into_iter()
            .map(BlobRejectVector::Decode)
            .collect();

    // HPKE-open rejects: seal a real read+write grant blob, then a byte flip and
    // a struct-tag transplant must both fail closed at the AEAD tag.
    let recipient_scalar: [u8; 32] = std::array::from_fn(|i| (0x30 + i) as u8);
    let recipient = X25519Secret::from_scalar(recipient_scalar);
    let ctx = grant_ctx(STRUCT_TAG_GRANT_BLOB);
    let payload = GrantBlobPayload::new([0x11; 32], Some([0x44; 32]), GRANT_EPOCH, [0x22; 32]);
    let sealed = seal_grant_blob(&recipient.public(), &[0x68; 32], &ctx, &payload);
    out.extend(hpke_blob_reject_pair(
        recipient_scalar,
        &recipient,
        &sealed,
        &ctx,
        STRUCT_TAG_OWNER_BLOB,
        |r, e, c, ct| open_grant_blob(r, e, c, ct).map(drop),
    ));
    out
}

/// The two HPKE-open reject vectors for a sealed grant/owner blob: a tampered
/// ciphertext (same ctx) and a struct-tag transplant (intact ciphertext opened
/// under `transplant_tag`). Both must fail closed at the AEAD tag.
fn hpke_blob_reject_pair(
    recipient_scalar: [u8; 32],
    recipient: &X25519Secret,
    sealed: &cipherbox_core::suite::hpke::HpkeCiphertext,
    ctx: &AadContext,
    transplant_tag: u8,
    open_fn: impl Fn(&X25519Secret, &[u8; 32], &AadContext, &[u8]) -> Result<(), CodecError>,
) -> Vec<BlobRejectVector> {
    let mut tampered = sealed.ciphertext.clone();
    *tampered.last_mut().expect("non-empty ciphertext") ^= 0x01;
    let transplant_ctx = AadContext {
        struct_tag: transplant_tag,
        ..*ctx
    };
    vec![
        hpke_blob_reject_vector(
            "tampered-ciphertext",
            recipient_scalar,
            recipient,
            &sealed.enc,
            ctx,
            &tampered,
            &open_fn,
        ),
        hpke_blob_reject_vector(
            "struct-tag-transplant",
            recipient_scalar,
            recipient,
            &sealed.enc,
            &transplant_ctx,
            &sealed.ciphertext,
            &open_fn,
        ),
    ]
}

/// Build + self-check one HPKE-blob reject vector: `open_fn` must fail closed
/// with `hpke-open-failed`/`trust` under `ctx`.
fn hpke_blob_reject_vector(
    name: &str,
    recipient_scalar: [u8; 32],
    recipient: &X25519Secret,
    enc: &[u8; 32],
    ctx: &AadContext,
    ciphertext: &[u8],
    open_fn: impl Fn(&X25519Secret, &[u8; 32], &AadContext, &[u8]) -> Result<(), CodecError>,
) -> BlobRejectVector {
    let err = match open_fn(recipient, enc, ctx, ciphertext) {
        Err(e) => e,
        Ok(()) => panic!("hpke-blob reject {name}: open accepted it"),
    };
    assert_eq!(
        err.check(),
        "hpke-open-failed",
        "hpke-blob reject {name}: check ({err})"
    );
    assert_eq!(
        err.class(),
        "trust",
        "hpke-blob reject {name}: class ({err})"
    );
    BlobRejectVector::HpkeOpen(HpkeBlobRejectVector {
        name: name.to_string(),
        recipient_secret: hexstr(&recipient_scalar),
        enc: hexstr(enc),
        v: ctx.v,
        id: hexstr(&ctx.id),
        scope: hexstr(&ctx.scope),
        epoch: ctx.epoch,
        struct_tag: ctx.struct_tag,
        ciphertext: hexstr(ciphertext),
        check: "hpke-open-failed".to_string(),
        class: "trust".to_string(),
    })
}

// --- Owner blob (HPKE) ------------------------------------------------------

fn build_owner_blob_accept() -> Vec<HpkeStructureVector> {
    let owner_scalar: [u8; 32] = std::array::from_fn(|i| (0x31 + i) as u8);
    let owner = X25519Secret::from_scalar(owner_scalar);
    let ctx = grant_ctx(STRUCT_TAG_OWNER_BLOB);
    let eph: [u8; 32] = std::array::from_fn(|i| (0x60 + i) as u8);
    let payload = OverrideSeedPayload::new([0x77; 32], GRANT_EPOCH);

    let plaintext = encode_override_seed_payload(&payload);
    let sealed = seal_owner_blob(&owner.public(), &eph, &ctx, &payload);
    assert_eq!(
        seal_owner_blob(&owner.public(), &eph, &ctx, &payload).ciphertext,
        sealed.ciphertext,
        "owner-blob: not deterministic"
    );
    let opened =
        open_owner_blob(&owner, &sealed.enc, &ctx, &sealed.ciphertext).expect("owner-blob open");
    assert_eq!(opened, payload, "owner-blob: round-trip");
    vec![hpke_structure_vector(
        "owner",
        &ctx,
        owner_scalar,
        &owner,
        eph,
        &plaintext,
        &sealed,
    )]
}

fn build_owner_blob_reject() -> Vec<BlobRejectVector> {
    let cases: Vec<(&str, Value, &str, &str)> = vec![
        (
            "override-seed-wrong-length",
            map_of(vec![
                ("epoch", Value::Unsigned(GRANT_EPOCH)),
                ("overrideSeed", Value::Bytes(vec![0x77; 31])),
            ]),
            "invalid-field-length",
            "malformed",
        ),
        (
            "missing-epoch",
            map_of(vec![("overrideSeed", Value::Bytes(vec![0x77; 32]))]),
            "missing-field",
            "malformed",
        ),
    ];
    let mut out: Vec<BlobRejectVector> =
        finish_hex_reject_vectors("owner-blob", cases, decode_override_seed_payload)
            .into_iter()
            .map(BlobRejectVector::Decode)
            .collect();

    // HPKE-open rejects: seal a real owner blob, then a byte flip and a
    // struct-tag transplant must both fail closed at the AEAD tag.
    let owner_scalar: [u8; 32] = std::array::from_fn(|i| (0x31 + i) as u8);
    let owner = X25519Secret::from_scalar(owner_scalar);
    let ctx = grant_ctx(STRUCT_TAG_OWNER_BLOB);
    let payload = OverrideSeedPayload::new([0x77; 32], GRANT_EPOCH);
    let sealed = seal_owner_blob(&owner.public(), &[0x69; 32], &ctx, &payload);
    out.extend(hpke_blob_reject_pair(
        owner_scalar,
        &owner,
        &sealed,
        &ctx,
        STRUCT_TAG_GRANT_BLOB,
        |r, e, c, ct| open_owner_blob(r, e, c, ct).map(drop),
    ));
    out
}

/// Freeze one HPKE-sealed structure (grant blob / owner blob) as a vector,
/// pinning the recipient keys, the injected ephemeral, the structured AAD, the
/// plaintext, and the whole HPKE envelope (enc + ciphertext).
fn hpke_structure_vector(
    name: &str,
    ctx: &AadContext,
    recipient_scalar: [u8; 32],
    recipient: &X25519Secret,
    eph: [u8; 32],
    plaintext: &[u8],
    sealed: &cipherbox_core::suite::hpke::HpkeCiphertext,
) -> HpkeStructureVector {
    HpkeStructureVector {
        name: name.to_string(),
        recipient_secret: hexstr(&recipient_scalar),
        recipient_public: hexstr(&recipient.public().to_bytes()),
        ephemeral_scalar: hexstr(&eph),
        v: ctx.v,
        id: hexstr(&ctx.id),
        scope: hexstr(&ctx.scope),
        epoch: ctx.epoch,
        struct_tag: ctx.struct_tag,
        aad: hexstr(&build_aad(ctx)),
        plaintext: hexstr(plaintext),
        enc: hexstr(&sealed.enc),
        ciphertext: hexstr(&sealed.ciphertext),
    }
}

// --- Ascent link ------------------------------------------------------------

fn build_ascent_link_accept() -> Vec<AscentLinkAcceptVector> {
    let parent_node_seed: [u8; 32] = std::array::from_fn(|i| (0x12 + i) as u8);
    let eph: [u8; 32] = std::array::from_fn(|i| (0x70 + i) as u8);
    let ctx = grant_ctx(STRUCT_TAG_ASCENT_LINK);
    let payload = OverrideSeedPayload::new([0x88; 32], GRANT_EPOCH);
    let plaintext = encode_override_seed_payload(&payload);

    let link = seal_ascent_link(&parent_node_seed, &eph, &ctx, &payload);
    // The ancestor re-derives the keypair, matches the public half, and opens.
    let opened = open_ascent_link(&parent_node_seed, &ctx, &link).expect("ascent open");
    assert_eq!(opened, payload, "ascent-link: round-trip");
    let container = encode_ascent_link(&link);
    let decoded = decode_ascent_link(&container).expect("ascent container decodes");
    assert_eq!(decoded, link, "ascent-link: container decode != source");
    assert_eq!(
        encode_ascent_link(&decoded),
        container,
        "ascent-link: container not byte-stable"
    );

    vec![AscentLinkAcceptVector {
        name: "ascent".to_string(),
        parent_node_seed: hexstr(&parent_node_seed),
        ephemeral_scalar: hexstr(&eph),
        v: ctx.v,
        id: hexstr(&ctx.id),
        scope: hexstr(&ctx.scope),
        epoch: ctx.epoch,
        struct_tag: ctx.struct_tag,
        aad: hexstr(&build_aad(&ctx)),
        plaintext: hexstr(&plaintext),
        ascent_public: hexstr(&link.ascent_public),
        container: hexstr(&container),
    }]
}

fn build_ascent_link_reject() -> Vec<AscentLinkRejectVector> {
    let parent_node_seed: [u8; 32] = std::array::from_fn(|i| (0x12 + i) as u8);
    let eph: [u8; 32] = std::array::from_fn(|i| (0x78 + i) as u8);
    let ctx = grant_ctx(STRUCT_TAG_ASCENT_LINK);
    let payload = OverrideSeedPayload::new([0x88; 32], GRANT_EPOCH);
    let good = seal_ascent_link(&parent_node_seed, &eph, &ctx, &payload);

    // Mismatched public half: derive-and-verify rejects before the HPKE open.
    let mut mismatched = good.clone();
    mismatched.ascent_public[0] ^= 0x01;
    // Tampered ciphertext: the public half still matches, so the HPKE open runs
    // and fails the tag.
    let mut tampered = good.clone();
    *tampered.ciphertext.last_mut().unwrap() ^= 0x01;

    let cases: Vec<(&str, AscentLink, &str, &str)> = vec![
        (
            "mismatched-public-half",
            mismatched,
            "ascent-link-mismatch",
            "trust",
        ),
        ("tampered-ciphertext", tampered, "hpke-open-failed", "trust"),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, link, check, class) in cases {
        assert!(names.insert(name), "duplicate ascent-link reject {name}");
        let container = encode_ascent_link(&link);
        let err = open_ascent_link(&parent_node_seed, &ctx, &link)
            .expect_err("ascent-link reject must fail closed");
        assert_eq!(
            err.check(),
            check,
            "ascent-link reject {name}: check ({err})"
        );
        assert_eq!(
            err.class(),
            class,
            "ascent-link reject {name}: class ({err})"
        );
        out.push(AscentLinkRejectVector {
            name: name.to_string(),
            parent_node_seed: hexstr(&parent_node_seed),
            v: ctx.v,
            id: hexstr(&ctx.id),
            scope: hexstr(&ctx.scope),
            epoch: ctx.epoch,
            struct_tag: ctx.struct_tag,
            container: hexstr(&container),
            check: check.to_string(),
            class: class.to_string(),
        });
    }
    out
}

// --- History link (symmetric) -----------------------------------------------

fn build_history_link_accept() -> Vec<HistoryLinkAcceptVector> {
    let key: [u8; KEY_LEN] = std::array::from_fn(|i| (0x40 + i) as u8);
    let nonce: [u8; NONCE_LEN] = std::array::from_fn(|i| (0x10 + i) as u8);
    let ctx = grant_ctx(STRUCT_TAG_HISTORY_LINK);
    let payload = HistoryLinkPayload::new([0x99; 32], GRANT_EPOCH - 1);
    let plaintext = encode_history_link_payload(&payload);

    let sealed = seal_history_link(&key, &nonce, &ctx, &payload);
    assert_eq!(
        seal_history_link(&key, &nonce, &ctx, &payload),
        sealed,
        "history-link: not deterministic"
    );
    assert_eq!(&sealed[..NONCE_LEN], &nonce, "history-link: nonce prefix");
    let opened = open_history_link(&key, &ctx, &sealed).expect("history-link open");
    assert_eq!(opened, payload, "history-link: round-trip");

    vec![HistoryLinkAcceptVector {
        name: "prev-epoch".to_string(),
        key: hexstr(&key),
        nonce: hexstr(&nonce),
        v: ctx.v,
        id: hexstr(&ctx.id),
        scope: hexstr(&ctx.scope),
        epoch: ctx.epoch,
        struct_tag: ctx.struct_tag,
        aad: hexstr(&build_aad(&ctx)),
        plaintext: hexstr(&plaintext),
        sealed: hexstr(&sealed),
    }]
}

fn build_history_link_reject() -> Vec<RejectVector> {
    let cases: Vec<(&str, Value, &str, &str)> = vec![
        (
            "prev-seed-wrong-length",
            map_of(vec![
                ("prevEpoch", Value::Unsigned(3)),
                ("prevSeed", Value::Bytes(vec![0x99; 31])),
            ]),
            "invalid-field-length",
            "malformed",
        ),
        (
            "missing-prev-epoch",
            map_of(vec![("prevSeed", Value::Bytes(vec![0x99; 32]))]),
            "missing-field",
            "malformed",
        ),
    ];
    finish_hex_reject_vectors("history-link", cases, decode_history_link_payload)
}

// --- Structure signatures ---------------------------------------------------

/// One structure-signature accept case: name, struct tag, optional recipient
/// tag, and the ciphertext to hash.
type StructSigCase = (&'static str, u8, Option<[u8; 32]>, &'static [u8]);

fn build_structure_sig_accept() -> Vec<StructureSigAcceptVector> {
    let signer_seed: [u8; 32] = std::array::from_fn(|i| (0x07 + i) as u8);
    let signer = Ed25519Signer::from_seed(signer_seed);
    let verifier = signer.verifying_key();
    let scope_id = grant_scope_id();

    let cases: Vec<StructSigCase> = vec![
        (
            "grant-blob-with-recipient-tag",
            STRUCT_TAG_GRANT_BLOB,
            Some([0x01; 32]),
            b"grant-blob-ciphertext",
        ),
        (
            "owner-blob-no-recipient-tag",
            STRUCT_TAG_OWNER_BLOB,
            None,
            b"owner-blob-ciphertext",
        ),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, struct_tag, recipient_tag, ciphertext) in cases {
        assert!(names.insert(name), "duplicate structure-sig accept {name}");
        let input =
            StructureSigInput::over_ciphertext(scope_id, 5, struct_tag, recipient_tag, ciphertext);
        let preimage = structure_sig_preimage(&input);
        let sig = sign_structure(&signer, &input);
        assert!(
            verify_structure(&verifier, &input, &sig).is_ok(),
            "structure-sig {name}: must verify"
        );
        out.push(StructureSigAcceptVector {
            name: name.to_string(),
            signer_seed: hexstr(&signer_seed),
            verifier_pk: hexstr(&verifier.to_bytes()),
            scope_id: hexstr(&scope_id),
            epoch: 5,
            struct_tag,
            recipient_tag: recipient_tag.map(|t| hexstr(&t)).unwrap_or_default(),
            ciphertext: hexstr(ciphertext),
            ciphertext_hash: hexstr(&hash(ciphertext)),
            preimage: hexstr(&preimage),
            signature: hexstr(&sig.to_bytes()),
        });
    }
    out
}

fn build_structure_sig_reject() -> Vec<StructureSigRejectVector> {
    let signer = Ed25519Signer::from_seed(std::array::from_fn(|i| (0x07 + i) as u8));
    let verifier = signer.verifying_key();
    let scope_id = grant_scope_id();
    // The authentic signature is over a grant blob with recipient tag A.
    let base = StructureSigInput::over_ciphertext(
        scope_id,
        5,
        STRUCT_TAG_GRANT_BLOB,
        Some([0x01; 32]),
        b"structure-sig-ciphertext",
    );
    let base_sig = sign_structure(&signer, &base);

    // (name, verify-side input, verify-side signature). Each recomputes a
    // preimage that the signature does not cover.
    let mut bad_sig_bytes = base_sig.to_bytes();
    bad_sig_bytes[0] ^= 0x01;
    let cases: Vec<(&str, StructureSigInput, Ed25519Signature)> = vec![
        (
            "bad-signature",
            base,
            Ed25519Signature::from_bytes(bad_sig_bytes),
        ),
        (
            "wrong-tag",
            StructureSigInput {
                struct_tag: STRUCT_TAG_OWNER_BLOB,
                ..base
            },
            base_sig,
        ),
        (
            "recipient-tag-transplant",
            StructureSigInput {
                recipient_tag: Some([0x02; 32]),
                ..base
            },
            base_sig,
        ),
    ];

    let mut names = BTreeSet::new();
    let mut out = Vec::with_capacity(cases.len());
    for (name, input, sig) in cases {
        assert!(names.insert(name), "duplicate structure-sig reject {name}");
        let err = verify_structure(&verifier, &input, &sig)
            .expect_err("structure-sig reject must fail closed");
        assert_eq!(
            err.check(),
            "structure-signature-invalid",
            "structure-sig reject {name}: check ({err})"
        );
        out.push(StructureSigRejectVector {
            name: name.to_string(),
            verifier_pk: hexstr(&verifier.to_bytes()),
            scope_id: hexstr(&input.scope_id),
            epoch: input.epoch,
            struct_tag: input.struct_tag,
            recipient_tag: input.recipient_tag.map(|t| hexstr(&t)).unwrap_or_default(),
            ciphertext_hash: hexstr(&input.ciphertext_hash),
            signature: hexstr(&sig.to_bytes()),
            check: "structure-signature-invalid".to_string(),
            class: "trust".to_string(),
        });
    }
    out
}

// --- Grant-set commitment ---------------------------------------------------

fn grant_set_sample() -> GrantSetCommitment {
    GrantSetCommitment {
        ipns_name: b"scope-root-ipns".to_vec(),
        owner_pseudonym_pk: [0x88; 32],
        entries: vec![
            GrantSetEntry::new([0x01; 32], Permission::Read, [0x02; 32]),
            GrantSetEntry::new([0x03; 32], Permission::Write, [0x04; 32]),
        ],
        unknown: Vec::new(),
    }
}

fn build_grant_set_accept() -> Vec<GrantSetAcceptVector> {
    let owner = EcdsaSigner::from_scalar(&[0x11; 32]).expect("valid identity scalar");
    let c = grant_set_sample();
    let bytes = encode_grant_set_commitment(&c).expect("commitment encodes");
    let decoded = decode_grant_set_commitment(&bytes).expect("commitment decodes");
    assert_eq!(decoded, c, "grant-set accept: decode != source");
    assert_eq!(
        encode_grant_set_commitment(&decoded).unwrap(),
        bytes,
        "grant-set accept: not byte-stable"
    );
    let sig = sign_grant_set(&owner, &c).expect("commitment signs");
    assert!(
        verify_grant_set(&owner.verifying_key(), &c, &sig).is_ok(),
        "grant-set accept: must verify"
    );
    vec![GrantSetAcceptVector {
        name: "read-and-write".to_string(),
        owner_identity_pk: hexstr(&owner.verifying_key().to_sec1()),
        commitment: hexstr(&bytes),
        signature: hexstr(&sig.to_compact()),
    }]
}

/// A grant-set entry map value, for hand-crafting commitment reject vectors.
fn grant_set_entry_map(tag: Vec<u8>, permission: &str, pseudonym: Vec<u8>) -> Value {
    map_of(vec![
        ("permission", Value::Text(permission.to_string())),
        ("pseudonymPk", Value::Bytes(pseudonym)),
        ("tag", Value::Bytes(tag)),
    ])
}

fn build_grant_set_reject() -> Vec<GrantSetRejectVector> {
    let owner = EcdsaSigner::from_scalar(&[0x11; 32]).expect("valid identity scalar");
    let owner_pk_hex = hexstr(&owner.verifying_key().to_sec1());

    // Codec rejects (signature empty): the commitment never decodes.
    let commitment_of = |entries: Vec<Value>, omit_entries: bool| -> Vec<u8> {
        let mut kv = vec![
            ("ipnsName", Value::Bytes(b"scope-root-ipns".to_vec())),
            ("ownerPseudonymPk", Value::Bytes(vec![0x88; 32])),
        ];
        if !omit_entries {
            kv.push(("entries", Value::Array(entries)));
        }
        encode(&map_of(kv))
    };
    let codec_cases: Vec<(&str, Vec<u8>, &str)> = vec![
        (
            "entry-invalid-permission",
            commitment_of(
                vec![grant_set_entry_map(vec![0x01; 32], "owner", vec![0x02; 32])],
                false,
            ),
            "invalid-permission",
        ),
        (
            "pseudonym-pk-wrong-length",
            commitment_of(
                vec![grant_set_entry_map(vec![0x01; 32], "read", vec![0x02; 31])],
                false,
            ),
            "invalid-field-length",
        ),
        (
            "missing-entries",
            commitment_of(vec![], true),
            "missing-field",
        ),
    ];

    let mut names = BTreeSet::new();
    let mut out: Vec<GrantSetRejectVector> = Vec::new();
    for (name, bytes, check) in codec_cases {
        assert!(names.insert(name), "duplicate grant-set reject {name}");
        let err = match decode_grant_set_commitment(&bytes) {
            Err(e) => e,
            Ok(_) => panic!("grant-set reject {name}: decoder accepted it"),
        };
        assert_eq!(err.check(), check, "grant-set reject {name}: check ({err})");
        assert_eq!(err.class(), "malformed", "grant-set reject {name}: class");
        out.push(GrantSetRejectVector {
            name: name.to_string(),
            owner_identity_pk: String::new(),
            commitment: hexstr(&bytes),
            signature: String::new(),
            check: check.to_string(),
            class: "malformed".to_string(),
        });
    }

    // A trust decode-reject: one blinded tag committed twice, `read` then
    // `write`, with a different pseudonym — the confused-deputy shape. It rejects
    // at decode (no signature exercised), so its signature stays empty.
    let dup_tag_bytes = commitment_of(
        vec![
            grant_set_entry_map(vec![0x01; 32], "read", vec![0x02; 32]),
            grant_set_entry_map(vec![0x01; 32], "write", vec![0x09; 32]),
        ],
        false,
    );
    let err = decode_grant_set_commitment(&dup_tag_bytes)
        .expect_err("duplicate grant-set tag must reject");
    assert_eq!(
        err.check(),
        "duplicate-grant-tag",
        "grant-set dup-tag reject"
    );
    assert_eq!(err.class(), "trust", "grant-set dup-tag class");
    assert!(names.insert("entries-duplicate-tag"));
    out.push(GrantSetRejectVector {
        name: "entries-duplicate-tag".to_string(),
        owner_identity_pk: String::new(),
        commitment: hexstr(&dup_tag_bytes),
        signature: String::new(),
        check: "duplicate-grant-tag".to_string(),
        class: "trust".to_string(),
    });

    // A verify reject: a well-formed low-S signature over a *different*
    // commitment never verifies against this one (commitment-invalid).
    let this = grant_set_sample();
    let mut other = grant_set_sample();
    other.entries[0].permission = Permission::Write;
    let sig_over_other = sign_grant_set(&owner, &other).expect("other commitment signs");
    let this_bytes = encode_grant_set_commitment(&this).expect("this commitment encodes");
    let decoded = decode_grant_set_commitment(&this_bytes).expect("this commitment decodes");
    let err = verify_grant_set(&owner.verifying_key(), &decoded, &sig_over_other)
        .expect_err("mismatched-signature must fail closed");
    assert_eq!(err.check(), "commitment-invalid", "grant-set verify reject");
    assert!(names.insert("signature-over-other-commitment"));
    out.push(GrantSetRejectVector {
        name: "signature-over-other-commitment".to_string(),
        owner_identity_pk: owner_pk_hex,
        commitment: hexstr(&this_bytes),
        signature: hexstr(&sig_over_other.to_compact()),
        check: "commitment-invalid".to_string(),
        class: "trust".to_string(),
    });
    out
}
