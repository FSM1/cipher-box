//! Unified Node type model (`node/v3`) — the Rust twin of
//! `packages/core/src/node/{types,encode,decode}.ts`.
//!
//! Defines the discriminated `Node` enum (folder/file/root), the read-chain
//! link `SealedChildRef`, file content descriptors, and the write-plane
//! types (`NodeWriteBody`/`WriteChildRef`) reserved for the wave-6 D-07
//! dual-keying work (RESEARCH Open Question 3).
//!
//! This module is ADDITIVE alongside the legacy `crate::folder` types — see
//! the 69-10 cutover plan for their retirement (D-04).
//!
//! Design references: `docs/METADATA_SCHEMAS.md` §3-8, NODE-01..NODE-04.

use cipherbox_crypto::CryptoError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors surfaced by the Node codec.
///
/// Mirrors `FolderError`'s idiom (do NOT reuse `FolderError` — this is a
/// distinct additive type per the 69-01 plan).
#[derive(Debug, Error)]
pub enum NodeError {
    #[error("Node serialization failed")]
    SerializationFailed,
    #[error("Node deserialization failed: {0}")]
    DeserializationFailed(String),
    #[error("Invalid node format: {0}")]
    InvalidFormat(String),
    /// AAD-bound seal/unseal failure (69-04): AEAD auth-tag mismatch,
    /// malformed node_id, or any other `cipherbox_crypto` failure.
    #[error("Node seal/unseal failed: {0}")]
    SealFailed(#[from] CryptoError),
}

/// Discriminator for the three node kinds (mirrors TS `NodeKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Folder,
    File,
    Root,
}

impl NodeKind {
    /// The lowercase wire string for this kind (matches TS `NodeKind` literal values).
    pub fn as_str(&self) -> &'static str {
        match self {
            NodeKind::Folder => "folder",
            NodeKind::File => "file",
            NodeKind::Root => "root",
        }
    }
}

/// One historical version of a file node's content (mirrors TS `VersionEntry`).
///
/// `file_key` is a raw 32-byte AES key stored **inside** the sealed read-body
/// — it is NOT an ECIES hex string (semantic type change, D-07/NODE-02).
/// `encryption_mode` is mandatory; do not normalise to GCM-only (CTR drives
/// large-file range reads).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionEntry {
    pub version_id: String,
    pub cid: String,
    pub file_iv: String,
    pub size: u64,
    pub created_at: u64,
    /// Mandatory: `"GCM"` (default) or `"CTR"` (large-file range reads).
    pub encryption_mode: String,
    /// Raw 32-byte AES key; base64-encoded on the JSON wire.
    #[serde(with = "base64_key")]
    pub file_key: Vec<u8>,
}

/// Content descriptor for a file node (read-body, sealed under the file
/// node's own `readKey`). Mirrors TS `NodeContent`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeContent {
    pub cid: String,
    pub file_iv: String,
    pub size: u64,
    pub mime_type: String,
    /// Mandatory: `"GCM"` or `"CTR"`.
    pub encryption_mode: String,
    /// Raw 32-byte AES key; base64-encoded on the JSON wire.
    #[serde(with = "base64_key")]
    pub file_key: Vec<u8>,
    pub versions: Vec<VersionEntry>,
}

/// A sealed reference to a child node stored inside the parent's read-body.
///
/// Frozen NODE-03 five-field set — {name, ipnsName, generation, versionFloor,
/// readKeySealed} — and carries NO write field (design §2.2/§2.6). This
/// struct is intentionally exactly five fields; do not add optional display
/// mirrors here without updating the NODE-03 verification in this plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedChildRef {
    /// Display name of the child (plaintext within the sealed parent read-body).
    pub name: String,
    /// IPNS k51 name of the child node.
    pub ipns_name: String,
    /// Staleness witness for the child's read-key epoch (D-07 invariant 1).
    pub generation: u32,
    /// Owner-vouched IPNS sequence-number floor, bound at (re)share.
    /// Serialized as a decimal string on the wire (mirrors the TS bigint convention).
    #[serde(with = "u64_as_string")]
    pub version_floor: u64,
    /// AES-256-GCM seal of the child's readKey under the parent readKey.
    /// Base64; AAD role = 0x02 child-readkey.
    pub read_key_sealed: String,
}

/// Write-chain link stored inside the parent's write-body (mirrors TS `WriteChildRef`).
///
/// The `write_key_sealed` conveys the child's writeKey sealed under the
/// parent writeKey. This field is NEVER in `SealedChildRef` (NODE-03).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteChildRef {
    /// Hyphenated UUID of the child node.
    pub child_id: String,
    /// AES-256-GCM seal of the child's writeKey under the parent writeKey.
    /// Base64; AAD role = 0x04 child-writekey.
    pub write_key_sealed: String,
}

/// Write-body for a node — sealed under the node's writeKey (separate from
/// readKey). Absent on read-only nodes (the read grant never conveys writeKey).
///
/// Reserved for the wave-6 D-07 dual-keying work (RESEARCH Open Question 3);
/// not yet wired to AEAD sealing in this plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeWriteBody {
    /// Raw Ed25519 signing seed (inside the sealed write-body — never exposed
    /// in read grants). Base64-encoded on the wire.
    #[serde(with = "base64_key")]
    pub ipns_private_key: Vec<u8>,
    /// Write chain to child nodes; mirrors the read chain in `SealedChildRef`.
    pub write_children: Vec<WriteChildRef>,
    /// Recipient-pubkey pins bound at share/re-mint (D-03b) — each entry a raw
    /// compressed secp256k1 public key, base64-encoded on the wire.
    ///
    /// Additive optional field (METADATA_EVOLUTION_PROTOCOL §3.1): omitted from
    /// the wire when empty (`skip_serializing_if`) so the frozen empty-pin KAT
    /// (`seal_vectors[0]`) is preserved byte-for-byte, and defaulted to empty
    /// on decode so older/newer readers never fail-closed on it. Note the
    /// enclosing struct intentionally carries NO `deny_unknown_fields` (forward
    /// tolerance, unlike `SealedChildRef`).
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "base64_key_list")]
    pub recipient_pins: Vec<Vec<u8>>,
}

/// The unified in-memory Node shape (decrypted, plaintext). Mirrors TS `Node`.
///
/// `generation` is a per-node read-key rotation clock in `[0, 2^32-1]`
/// (u32-safe, D-08, NODE-04). Discriminated by variant so folder/root
/// (`children`) and file (`content`) states are structurally impossible to
/// conflate.
#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    Folder {
        /// Hyphenated UUID (RFC-4122).
        id: String,
        generation: u32,
        created_at: u64,
        modified_at: u64,
        children: Vec<SealedChildRef>,
    },
    File {
        id: String,
        generation: u32,
        created_at: u64,
        modified_at: u64,
        content: NodeContent,
    },
    Root {
        id: String,
        generation: u32,
        created_at: u64,
        modified_at: u64,
        children: Vec<SealedChildRef>,
    },
}

impl Node {
    /// The `NodeKind` discriminator for this variant.
    pub fn kind(&self) -> NodeKind {
        match self {
            Node::Folder { .. } => NodeKind::Folder,
            Node::File { .. } => NodeKind::File,
            Node::Root { .. } => NodeKind::Root,
        }
    }

    /// The node's hyphenated UUID.
    pub fn id(&self) -> &str {
        match self {
            Node::Folder { id, .. } | Node::File { id, .. } | Node::Root { id, .. } => id,
        }
    }

    /// The node's read-key rotation clock (AAD-bound epoch).
    pub fn generation(&self) -> u32 {
        match self {
            Node::Folder { generation, .. }
            | Node::File { generation, .. }
            | Node::Root { generation, .. } => *generation,
        }
    }
}

/// The on-wire published node as stored in IPFS/IPNS. Mirrors TS `PublishedNode`.
///
/// `schema`, `kind`, `id`, `generation`, and `aeadVersion` are plaintext and
/// AAD inputs (tamper-evident via the IPNS signature chain). `readSealed`
/// and `writeSealed` are the two AES-256-GCM sealed bodies (design §2.4,
/// NODE-04) — this plan treats them as opaque base64 strings; the AEAD
/// sealing itself is wired in a later Phase-69 plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishedNode {
    pub schema: String,
    pub kind: String,
    /// Hyphenated UUID.
    pub id: String,
    /// Plaintext + AAD-bound generation; lets honest readers detect staleness.
    pub generation: u32,
    /// AEAD primitive version tag (always 1 for this implementation).
    pub aead_version: u8,
    /// Base64 of `IV || AES-256-GCM ciphertext || tag` for the read-body.
    pub read_sealed: String,
    /// Base64 of `IV || AES-256-GCM ciphertext || tag` for the write-body.
    /// Absent on read-only nodes (no writeKey).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_sealed: Option<String>,
}

// ---------------------------------------------------------------------------
// Wire-format encoding helpers
// ---------------------------------------------------------------------------

/// Base64 (standard alphabet) serde helper for raw key bytes on the JSON wire.
mod base64_key {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let raw = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(&raw)
            .map_err(serde::de::Error::custom)
    }
}

/// Base64 (standard alphabet) serde helper for a LIST of raw key/pubkey byte
/// vectors on the JSON wire (each element base64, the outer value a JSON array).
///
/// Used by `NodeWriteBody.recipient_pins`; mirrors the TS `string[]` (base64)
/// wire convention so the two codecs are byte-identical (D-03b).
mod base64_key_list {
    use base64::Engine as _;
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(items: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(items.len()))?;
        for item in items {
            seq.serialize_element(&base64::engine::general_purpose::STANDARD.encode(item))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        let raw = Vec::<String>::deserialize(d)?;
        raw.into_iter()
            .map(|s| {
                base64::engine::general_purpose::STANDARD
                    .decode(&s)
                    .map_err(serde::de::Error::custom)
            })
            .collect()
    }
}

/// Decimal-string serde helper for `versionFloor` (bigint on the TS wire;
/// bigint is not JSON-serializable, so it is a decimal string, D-04).
mod u64_as_string {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        let raw = String::deserialize(d)?;
        raw.parse::<u64>().map_err(serde::de::Error::custom)
    }
}
