//! The bin index: one owner-sealed, vault-level record of every soft-deleted
//! node (FSM1/cipher-box-next ADR 0010).
//!
//! Published at an IPNS name the `bin-index-ipns-keypair` edge derives, and
//! sealed symmetrically under the `bin-index-seal-key` edge, so the record
//! resolves and opens at cold start from the login secret alone. No grant
//! carries either key — the index is the owner's, never a scope's.
//!
//! An entry keeps a node reachable after its parent drops the `ChildRef`: the
//! `ipnsName` is the only remaining route to a record no folder names, and
//! `originParent`/`originName` are what a restore puts back. `heldKey` is
//! present only when the delete re-keyed the doomed subtree out of a shared
//! scope's derivation (ADR 0010 item 3), which is the access cut key regression
//! cannot give.
//!
//! One strictness policy, everywhere (#27 D10): every map level decodes strict
//! det-CBOR and preserves unknown fields byte-stable, and `nodeId` uniqueness is
//! fail-closed at decode — two entries for one node would make restore and purge
//! pick a winner by position.

use core::fmt;
use std::collections::BTreeSet;

use zeroize::{Zeroize, Zeroizing};

use crate::codec::scrub::{ScrubOnDrop, ScrubOwned};
use crate::codec::{Map, RedactedBytes, RedactedText, Value, decode, encode, encode_fixed_depth};
use crate::error::{CodecError, Malformed, TrustViolation};
use crate::ipns::MAX_IPNS_NAME_BYTES;
use crate::seal::aad::{AAD_DOMAIN, STRUCT_TAG_BIN_INDEX};
use crate::seal::body::{
    NodeKind, PreservedFields, assert_unknown_disjoint, assert_within_bound, bytes_fixed,
    collect_unknown, merge_unknown, req,
};
use crate::seal::envelope::MAX_BLOCK_BYTES;
use crate::suite::aead::{self, KEY_LEN, NONCE_LEN, TAG_LEN};
use crate::suite::secret::{SECRET_LEN, SecretBytes};

/// The bin-index format version this build writes and can open. Carried in the
/// clear header *and* bound into the AAD, so rewriting the clear copy fails the
/// tag.
pub const BIN_INDEX_V: u64 = 1;

/// The bytes a seal adds around a bin index plaintext: the nonce, the AEAD tag,
/// and the clear-header framing.
const BIN_INDEX_SEAL_HEADROOM_BYTES: usize = 1024;

/// The frozen bound on a bin index plaintext's total encoded size. The record
/// is one published block, so the bound is the block ceiling less what the seal
/// adds; entry counts follow from it rather than from a second number.
pub const MAX_BIN_INDEX_BYTES: usize = MAX_BLOCK_BYTES - BIN_INDEX_SEAL_HEADROOM_BYTES;

// ---------------------------------------------------------------------------
// One bin entry.
// ---------------------------------------------------------------------------

/// One soft-deleted node.
///
/// `ipns_name` and `origin_name` are sealed-record plaintext — user-private
/// metadata in a zero-knowledge system — so they render redacted and the entry
/// is their terminal owner: it wipes both on drop. A clone owns its own buffers,
/// so one instance's wipe never reaches another's.
#[derive(Clone, PartialEq, Eq)]
pub struct BinEntry {
    /// The deleted node's location-independent node id (16-byte UUID).
    pub node_id: [u8; 16],
    ipns_name: Vec<u8>,
    /// The node's immutable kind.
    pub kind: NodeKind,
    /// The node id of the folder the node was unlinked from.
    pub origin_parent: [u8; 16],
    origin_name: String,
    /// The injected deletion time.
    pub deleted_at: u64,
    /// The scope root the node belonged to at deletion.
    pub scope_id: [u8; 16],
    held_key: Option<SecretBytes>,
    /// Preserved unknown fields (never any of the known keys); re-emitted
    /// canonically on rewrite.
    pub unknown: PreservedFields,
}

const ENTRY_KNOWN: &[&str] = &[
    "deletedAt",
    "heldKey",
    "ipnsName",
    "kind",
    "nodeId",
    "originName",
    "originParent",
    "scopeId",
];

impl fmt::Debug for BinEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BinEntry")
            .field("node_id", &self.node_id)
            .field("ipns_name", &RedactedBytes::of(&self.ipns_name))
            .field("kind", &self.kind)
            .field("origin_parent", &self.origin_parent)
            .field("origin_name", &RedactedText::of(&self.origin_name))
            .field("deleted_at", &self.deleted_at)
            .field("scope_id", &self.scope_id)
            .field("held_key", &self.held_key)
            .field("unknown", &self.unknown)
            .finish()
    }
}

impl Drop for BinEntry {
    fn drop(&mut self) {
        self.ipns_name.zeroize();
        self.origin_name.zeroize();
    }
}

impl BinEntry {
    /// An entry with no preserved unknown fields (the construction path).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_id: [u8; 16],
        ipns_name: Vec<u8>,
        kind: NodeKind,
        origin_parent: [u8; 16],
        origin_name: String,
        deleted_at: u64,
        scope_id: [u8; 16],
        held_key: Option<[u8; SECRET_LEN]>,
    ) -> Self {
        Self {
            node_id,
            ipns_name,
            kind,
            origin_parent,
            origin_name,
            deleted_at,
            scope_id,
            held_key: held_key.map(SecretBytes::new),
            unknown: PreservedFields::new(),
        }
    }

    /// The deleted node's opaque `ipnsName` bytes — the only route left to a
    /// record no folder names.
    pub fn ipns_name(&self) -> &[u8] {
        &self.ipns_name
    }

    /// The display name the node carried in `origin_parent`.
    pub fn origin_name(&self) -> &str {
        &self.origin_name
    }

    /// The key the doomed subtree was re-keyed under, when the delete re-keyed
    /// it. `None` for a delete from a scope with no grants, which keeps the
    /// cheap unlink.
    pub fn held_key(&self) -> Option<&[u8; SECRET_LEN]> {
        self.held_key.as_ref().map(SecretBytes::as_bytes)
    }

    /// The release-active invariants on the entry, so decode and every encode
    /// path enforce them identically (AGENTS.md rule 8).
    fn validate(&self) -> Result<(), CodecError> {
        assert_unknown_disjoint(&self.unknown, ENTRY_KNOWN)?;
        assert_within_bound("ipnsName", self.ipns_name.len(), MAX_IPNS_NAME_BYTES)
    }

    fn from_value(v: &Value) -> Result<Self, CodecError> {
        let map = v.as_map()?;
        let ipns_name = req(map, "ipnsName")?.as_bytes()?;
        assert_within_bound("ipnsName", ipns_name.len(), MAX_IPNS_NAME_BYTES)?;
        let held_key = match map.get("heldKey") {
            Some(v) => Some(SecretBytes::new(bytes_fixed::<SECRET_LEN>(v, "heldKey")?)),
            None => None,
        };
        Ok(Self {
            node_id: bytes_fixed::<16>(req(map, "nodeId")?, "nodeId")?,
            ipns_name: ipns_name.to_vec(),
            kind: NodeKind::from_wire(req(map, "kind")?.as_text()?)
                .ok_or(Malformed::InvalidNodeKind)?,
            origin_parent: bytes_fixed::<16>(req(map, "originParent")?, "originParent")?,
            origin_name: req(map, "originName")?.as_text()?.to_string(),
            deleted_at: req(map, "deletedAt")?.as_unsigned()?,
            scope_id: bytes_fixed::<16>(req(map, "scopeId")?, "scopeId")?,
            held_key,
            unknown: collect_unknown(map, ENTRY_KNOWN),
        })
    }

    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("nodeId", Value::Bytes(self.node_id.to_vec()));
        m.insert("ipnsName", Value::Bytes(self.ipns_name.clone()));
        m.insert("kind", Value::Text(self.kind.as_wire().to_string()));
        m.insert("originParent", Value::Bytes(self.origin_parent.to_vec()));
        m.insert("originName", Value::Text(self.origin_name.clone()));
        m.insert("deletedAt", Value::Unsigned(self.deleted_at));
        m.insert("scopeId", Value::Bytes(self.scope_id.to_vec()));
        if let Some(key) = &self.held_key {
            m.insert("heldKey", Value::Bytes(key.as_bytes().to_vec()));
        }
        merge_unknown(&mut m, &self.unknown);
        Value::Map(m)
    }
}

// ---------------------------------------------------------------------------
// The index body.
// ---------------------------------------------------------------------------

/// The bin index body: the entries plus the durable revision the floor law
/// orders two records by when the outer IPNS sequence cannot tell them apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinIndex {
    /// The body revision this record was published at.
    pub revision: u64,
    /// The entries, one per soft-deleted node.
    pub entries: Vec<BinEntry>,
    /// Preserved unknown fields (never any of the known keys).
    pub unknown: PreservedFields,
}

const INDEX_KNOWN: &[&str] = &["entries", "revision"];

impl BinIndex {
    /// An empty index at `revision` — what a cold start with no published
    /// record loads.
    pub fn new(revision: u64) -> Self {
        Self {
            revision,
            entries: Vec::new(),
            unknown: PreservedFields::new(),
        }
    }

    /// The decode-time invariants re-checked on a *constructed* index: the
    /// encode path runs this so it never publishes a body decode would refuse
    /// to reopen (AGENTS.md rule 8).
    pub fn validate(&self) -> Result<(), CodecError> {
        assert_unknown_disjoint(&self.unknown, INDEX_KNOWN)?;
        for entry in &self.entries {
            entry.validate()?;
        }
        assert_entries_unique(&self.entries)
    }
}

/// Fail-closed uniqueness over the index: a node id names at most one entry, so
/// a duplicate would let restore and purge pick a winner by position.
fn assert_entries_unique(entries: &[BinEntry]) -> Result<(), CodecError> {
    let mut ids = BTreeSet::new();
    for e in entries {
        if !ids.insert(e.node_id) {
            return Err(TrustViolation::DuplicateId.into());
        }
    }
    Ok(())
}

/// Decode a bin index plaintext (strict det-CBOR, uniqueness enforced).
///
/// The transient decoded tree carries a verbatim copy of every `heldKey`, so it
/// is scrubbed through the owning [`ScrubOwned`] guard (terminal-owner rule;
/// symmetric with [`encode_bin_index`]).
pub fn decode_bin_index(bytes: &[u8]) -> Result<BinIndex, CodecError> {
    assert_within_bound(BIN_INDEX_SIZE_CHECK, bytes.len(), MAX_BIN_INDEX_BYTES)?;
    let value = ScrubOwned(decode(bytes)?);
    let map = value.value().as_map()?;

    let revision = req(map, "revision")?.as_unsigned()?;
    let mut entries = Vec::new();
    for item in req(map, "entries")?.as_array()? {
        entries.push(BinEntry::from_value(item)?);
    }
    assert_entries_unique(&entries)?;
    Ok(BinIndex {
        revision,
        entries,
        unknown: collect_unknown(map, INDEX_KNOWN),
    })
}

/// Encode a bin index to its canonical det-CBOR plaintext.
///
/// The returned buffer carries `heldKey` material verbatim, so its caller is the
/// terminal owner and must zeroize it ([`seal_bin_index`] does).
pub fn encode_bin_index(index: &BinIndex) -> Result<Vec<u8>, CodecError> {
    index.validate()?;
    let mut m = Map::new();
    m.insert(
        "entries",
        Value::Array(index.entries.iter().map(BinEntry::to_value).collect()),
    );
    m.insert("revision", Value::Unsigned(index.revision));
    merge_unknown(&mut m, &index.unknown);

    let mut value = Value::Map(m);
    let guard = ScrubOnDrop(&mut value);
    let bytes = encode(guard.0)?;
    assert_within_bound(BIN_INDEX_SIZE_CHECK, bytes.len(), MAX_BIN_INDEX_BYTES)?;
    Ok(bytes)
}

/// The collection label the total-size refusal reports.
const BIN_INDEX_SIZE_CHECK: &str = "binIndex";

// ---------------------------------------------------------------------------
// The sealed record.
// ---------------------------------------------------------------------------

/// The AAD of a bin index record: the `cipherbox/v2` domain separator, the
/// version, and the `bin-index` structure tag. The tag is what keeps a bin
/// ciphertext from being reinterpreted as any other symmetric structure, and the
/// version is the downgrade defence. Public — the frozen layout, so the KAT
/// generator pins it directly.
pub fn bin_index_aad() -> Vec<u8> {
    encode_fixed_depth(&Value::Array(vec![
        Value::Text(AAD_DOMAIN.to_string()),
        Value::Unsigned(BIN_INDEX_V),
        Value::Unsigned(u64::from(STRUCT_TAG_BIN_INDEX)),
    ]))
}

/// Seal a bin index under the owner's `bin-index-seal-key`.
///
/// `nonce` must be unique for every seal under a given key: XChaCha20-Poly1305
/// nonce reuse is a confidentiality and integrity break. It is caller-injected
/// entropy (the KATs pin it), prefixed inside the sealed blob so
/// [`open_bin_index`] recovers it, and authenticated by the AEAD.
pub fn seal_bin_index(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    index: &BinIndex,
) -> Result<Vec<u8>, CodecError> {
    let plaintext = Zeroizing::new(encode_bin_index(index)?);
    let mut sealed = Vec::with_capacity(NONCE_LEN + plaintext.len() + TAG_LEN);
    sealed.extend_from_slice(nonce);
    sealed.extend(aead::encrypt(key, nonce, &bin_index_aad(), &plaintext));

    let mut m = Map::new();
    m.insert("sealed", Value::Bytes(sealed));
    m.insert("v", Value::Unsigned(BIN_INDEX_V));
    encode(&Value::Map(m))
}

/// Open a bin index record under the owner's `bin-index-seal-key`.
///
/// The version gate runs before the AEAD: opening a future record under this
/// build's body grammar would misread its intent. A tag that does not verify —
/// tampering, a transplant, or a rewritten `v`, which is the AAD — is
/// [`TrustViolation::SealOpenFailed`], never a stale read.
pub fn open_bin_index(key: &[u8; KEY_LEN], record: &[u8]) -> Result<BinIndex, CodecError> {
    let value = decode(record)?;
    let map = value.as_map()?;
    let version = req(map, "v")?.as_unsigned()?;
    if version != BIN_INDEX_V {
        return Err(Malformed::UnsupportedRecordVersion { version }.into());
    }
    if let Some((field, _)) = map
        .entries()
        .iter()
        .find(|(field, _)| !HEADER_KEYS.contains(&field.as_str()))
    {
        return Err(Malformed::UnknownRecordField { key: field.clone() }.into());
    }
    let sealed = req(map, "sealed")?.as_bytes()?;
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(Malformed::Truncated {
            offset: sealed.len(),
        }
        .into());
    }
    // The plaintext bound before the AEAD, so an oversized record costs a length
    // check rather than a decrypt of attacker-chosen bytes.
    assert_within_bound(
        BIN_INDEX_SIZE_CHECK,
        sealed.len() - NONCE_LEN - TAG_LEN,
        MAX_BIN_INDEX_BYTES,
    )?;
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let nonce: &[u8; NONCE_LEN] = nonce.try_into().expect("split_at NONCE_LEN");
    let plaintext = Zeroizing::new(
        aead::decrypt(key, nonce, &bin_index_aad(), ciphertext)
            .ok_or(TrustViolation::SealOpenFailed)?,
    );
    decode_bin_index(&plaintext)
}

/// The two clear-header keys, exhaustive at [`BIN_INDEX_V`].
const HEADER_KEYS: [&str; 2] = ["sealed", "v"];

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(seed: u8) -> BinEntry {
        BinEntry::new(
            [seed; 16],
            vec![seed, seed + 1, seed + 2],
            NodeKind::File,
            [seed + 0x10; 16],
            format!("note-{seed}.txt"),
            u64::from(seed) * 1000,
            [seed + 0x20; 16],
            Some([seed + 0x30; SECRET_LEN]),
        )
    }

    fn populated() -> BinIndex {
        let mut index = BinIndex::new(7);
        index.entries.push(entry(1));
        index.entries.push({
            let mut e = entry(2);
            e.held_key = None;
            e.kind = NodeKind::Folder;
            e
        });
        index
    }

    fn reframe(record: &[u8], key: &str, value: Value) -> Vec<u8> {
        let decoded = decode(record).unwrap();
        let mut map = decoded.as_map().unwrap().clone();
        map.insert(key, value);
        encode(&Value::Map(map)).unwrap()
    }

    #[test]
    fn an_index_round_trips_with_every_field_preserved() {
        let index = populated();
        let decoded = decode_bin_index(&encode_bin_index(&index).unwrap()).unwrap();
        assert_eq!(decoded, index);
        assert_eq!(decoded.entries[0].origin_name(), "note-1.txt");
        assert_eq!(decoded.entries[0].ipns_name(), &[1, 2, 3]);
        assert_eq!(decoded.entries[0].held_key(), Some(&[0x31; SECRET_LEN]));
        assert_eq!(decoded.entries[1].held_key(), None);
    }

    #[test]
    fn an_empty_index_round_trips() {
        let index = BinIndex::new(0);
        assert_eq!(
            decode_bin_index(&encode_bin_index(&index).unwrap()).unwrap(),
            index
        );
    }

    #[test]
    fn a_record_round_trips_under_the_owners_seal_key() {
        let index = populated();
        let record = seal_bin_index(&[9; KEY_LEN], &[3; NONCE_LEN], &index).unwrap();
        assert_eq!(open_bin_index(&[9; KEY_LEN], &record).unwrap(), index);
    }

    #[test]
    fn a_foreign_seal_key_never_opens() {
        let record = seal_bin_index(&[1; KEY_LEN], &[2; NONCE_LEN], &populated()).unwrap();
        assert_eq!(
            open_bin_index(&[4; KEY_LEN], &record).unwrap_err().check(),
            "seal-open-failed"
        );
    }

    /// The struct tag is the whole separation claim: the same key and nonce over
    /// the same plaintext under a different tag must not open here.
    #[test]
    fn a_foreign_struct_tag_fails_the_tag() {
        let key = [5u8; KEY_LEN];
        let nonce = [6u8; NONCE_LEN];
        let plaintext = encode_bin_index(&populated()).unwrap();
        let foreign_aad = encode_fixed_depth(&Value::Array(vec![
            Value::Text(AAD_DOMAIN.to_string()),
            Value::Unsigned(BIN_INDEX_V),
            Value::Unsigned(u64::from(STRUCT_TAG_BIN_INDEX) + 1),
        ]));
        let mut sealed = nonce.to_vec();
        sealed.extend(aead::encrypt(&key, &nonce, &foreign_aad, &plaintext));
        let mut m = Map::new();
        m.insert("sealed", Value::Bytes(sealed));
        m.insert("v", Value::Unsigned(BIN_INDEX_V));
        let record = encode(&Value::Map(m)).unwrap();

        assert_eq!(
            open_bin_index(&key, &record).unwrap_err().check(),
            "seal-open-failed"
        );
    }

    #[test]
    fn a_duplicate_node_id_is_refused_on_both_sides() {
        let mut index = BinIndex::new(1);
        index.entries.push(entry(1));
        index.entries.push(entry(1));
        assert_eq!(
            encode_bin_index(&index).unwrap_err().check(),
            "duplicate-id",
            "the encode path must refuse what decode hard-rejects",
        );

        // The same bytes framed past the encoder: decode must refuse them too.
        let one = entry(1).to_value();
        let mut m = Map::new();
        m.insert("entries", Value::Array(vec![one.clone(), one]));
        m.insert("revision", Value::Unsigned(1));
        let bytes = encode(&Value::Map(m)).unwrap();
        assert_eq!(
            decode_bin_index(&bytes).unwrap_err().check(),
            "duplicate-id"
        );
    }

    #[test]
    fn an_over_bound_ipns_name_is_refused_on_both_sides() {
        let mut index = BinIndex::new(1);
        let mut over = entry(1);
        over.ipns_name = vec![0x6b; MAX_IPNS_NAME_BYTES + 1];
        let framed = over.to_value();
        index.entries.push(over);
        assert_eq!(
            encode_bin_index(&index).unwrap_err().check(),
            "too-many-structures"
        );

        let mut m = Map::new();
        m.insert("entries", Value::Array(vec![framed]));
        m.insert("revision", Value::Unsigned(1));
        let bytes = encode(&Value::Map(m)).unwrap();
        assert_eq!(
            decode_bin_index(&bytes).unwrap_err().check(),
            "too-many-structures"
        );
    }

    /// `heldKey` is optional, so a caller-built `unknown` list could fill the
    /// key when the typed field is `None` and seal a value the struct denies.
    #[test]
    fn a_preserved_field_may_not_shadow_the_optional_held_key() {
        let mut index = BinIndex::new(1);
        let mut e = entry(1);
        e.held_key = None;
        e.unknown =
            core::iter::once(("heldKey".to_string(), Value::Bytes(vec![0; SECRET_LEN]))).collect();
        index.entries.push(e);
        assert_eq!(
            encode_bin_index(&index).unwrap_err().check(),
            "unknown-field-collision"
        );
    }

    #[test]
    fn an_unknown_field_survives_a_decode_and_re_encode() {
        let mut entry_map = entry(1).to_value().as_map().unwrap().clone();
        entry_map.insert("futureField", Value::Unsigned(42));
        let mut m = Map::new();
        m.insert("entries", Value::Array(vec![Value::Map(entry_map)]));
        m.insert("futureTop", Value::Text("x".to_string()));
        m.insert("revision", Value::Unsigned(3));
        let bytes = encode(&Value::Map(m)).unwrap();

        let index = decode_bin_index(&bytes).unwrap();
        assert_eq!(
            index.unknown.get("futureTop"),
            Some(&Value::Text("x".to_string()))
        );
        assert_eq!(
            index.entries[0].unknown.get("futureField"),
            Some(&Value::Unsigned(42))
        );
        assert_eq!(
            encode_bin_index(&index).unwrap(),
            bytes,
            "a re-encode must be byte-stable"
        );
    }

    #[test]
    fn a_forward_version_never_reaches_the_aead() {
        let record = seal_bin_index(&[1; KEY_LEN], &[2; NONCE_LEN], &populated()).unwrap();
        let future = reframe(&record, "v", Value::Unsigned(BIN_INDEX_V + 1));
        assert_eq!(
            open_bin_index(&[1; KEY_LEN], &future).unwrap_err().check(),
            "unsupported-record-version"
        );
    }

    #[test]
    fn an_unknown_clear_header_field_is_malformed() {
        let record = seal_bin_index(&[1; KEY_LEN], &[2; NONCE_LEN], &populated()).unwrap();
        let extended = reframe(&record, "extra", Value::Unsigned(1));
        assert_eq!(
            open_bin_index(&[1; KEY_LEN], &extended)
                .unwrap_err()
                .check(),
            "unknown-record-field"
        );
    }

    #[test]
    fn a_missing_clear_field_is_malformed() {
        for missing in HEADER_KEYS {
            let record = seal_bin_index(&[1; KEY_LEN], &[2; NONCE_LEN], &populated()).unwrap();
            let decoded = decode(&record).unwrap();
            let mut map = decoded.as_map().unwrap().clone();
            map.remove(missing);
            let framed = encode(&Value::Map(map)).unwrap();
            assert_eq!(
                open_bin_index(&[1; KEY_LEN], &framed).unwrap_err().check(),
                "missing-field",
                "{missing}",
            );
        }
    }

    /// The plaintext bound is charged before the AEAD, so an oversized record
    /// costs a length check rather than a decrypt of attacker-chosen bytes.
    #[test]
    fn an_over_bound_sealed_blob_never_reaches_the_aead() {
        let record = seal_bin_index(&[1; KEY_LEN], &[2; NONCE_LEN], &populated()).unwrap();
        let over = reframe(
            &record,
            "sealed",
            Value::Bytes(vec![0; NONCE_LEN + TAG_LEN + MAX_BIN_INDEX_BYTES + 1]),
        );
        assert_eq!(
            open_bin_index(&[1; KEY_LEN], &over).unwrap_err().check(),
            "too-many-structures"
        );
    }

    #[test]
    fn a_short_sealed_blob_never_reaches_the_aead() {
        let record = seal_bin_index(&[1; KEY_LEN], &[2; NONCE_LEN], &populated()).unwrap();
        let short = reframe(
            &record,
            "sealed",
            Value::Bytes(vec![0; NONCE_LEN + TAG_LEN - 1]),
        );
        assert_eq!(
            open_bin_index(&[1; KEY_LEN], &short).unwrap_err().check(),
            "truncated"
        );
    }

    #[test]
    fn a_wrong_length_held_key_is_malformed() {
        let mut entry_map = entry(1).to_value().as_map().unwrap().clone();
        entry_map.insert("heldKey", Value::Bytes(vec![0; SECRET_LEN - 1]));
        let mut m = Map::new();
        m.insert("entries", Value::Array(vec![Value::Map(entry_map)]));
        m.insert("revision", Value::Unsigned(1));
        let bytes = encode(&Value::Map(m)).unwrap();
        assert_eq!(
            decode_bin_index(&bytes).unwrap_err().check(),
            "invalid-field-length"
        );
    }

    #[test]
    fn an_unrecognised_kind_is_malformed() {
        let mut entry_map = entry(1).to_value().as_map().unwrap().clone();
        entry_map.insert("kind", Value::Text("shortcut".to_string()));
        let mut m = Map::new();
        m.insert("entries", Value::Array(vec![Value::Map(entry_map)]));
        m.insert("revision", Value::Unsigned(1));
        let bytes = encode(&Value::Map(m)).unwrap();
        assert_eq!(
            decode_bin_index(&bytes).unwrap_err().check(),
            "invalid-node-kind"
        );
    }

    /// Never-log-keys: an entry's `Debug` must not render the held key or the
    /// user-private origin name.
    #[test]
    fn debug_redacts_the_held_key_and_the_origin_name() {
        let rendered = format!("{:?}", entry(1));
        assert!(!rendered.contains("note-1.txt"), "{rendered}");
        assert!(rendered.contains("SecretBytes(redacted)"), "{rendered}");
    }
}
