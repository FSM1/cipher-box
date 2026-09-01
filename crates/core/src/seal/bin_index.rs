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
//! `originParent`/`originName` are what a restore puts back.
//!
//! One strictness policy, everywhere (#27 D10): every map level decodes strict
//! det-CBOR and preserves unknown fields byte-stable.

use core::fmt;
use std::collections::BTreeSet;

use zeroize::{Zeroize, Zeroizing};

use crate::codec::scrub::{ScrubOnDrop, ScrubOwned};
use crate::codec::{
    Map, RedactedBytes, RedactedText, Value, decode, encode, encode_fixed_depth, encoded_len,
    head_len,
};
use crate::error::{CodecError, Malformed, TrustViolation};
use crate::ipns::MAX_IPNS_NAME_BYTES;
use crate::seal::aad::{AAD_DOMAIN, STRUCT_TAG_BIN_INDEX};
use crate::seal::body::{
    NodeKind, PreservedFields, assert_unknown_disjoint, assert_within_bound, bytes_fixed,
    collect_unknown, merge_unknown, req,
};
use crate::seal::envelope::MAX_BLOCK_BYTES;
use crate::seal::{open_framed, seal_framed};
use crate::suite::aead::{KEY_LEN, NONCE_LEN};
use crate::suite::secret::{SECRET_LEN, SecretBytes};

/// The bin-index format version this build writes and can open. Carried in the
/// clear header *and* bound into the AAD, so rewriting the clear copy fails the
/// tag.
pub const BIN_INDEX_V: u64 = 1;

/// The bytes reserved above [`MAX_BIN_INDEX_BYTES`]: the nonce, the AEAD tag,
/// and the clear-header framing, plus room for a later `v` to add a clear-header
/// field without shrinking the body a conforming writer may already emit.
const BIN_INDEX_SEAL_HEADROOM_BYTES: usize = 1024;

/// The frozen bound on a bin index plaintext's total encoded size. The record
/// is one published block, so the bound is the block ceiling less what the seal
/// adds; entry counts follow from it rather than from a second number.
pub const MAX_BIN_INDEX_BYTES: usize = MAX_BLOCK_BYTES - BIN_INDEX_SEAL_HEADROOM_BYTES;

/// The frozen sizes every bin index plaintext pads up to, so the published
/// ciphertext length discloses the rung and nothing finer (blueprint/core.md
/// "Bin index"). Ascending, and topped by [`MAX_BIN_INDEX_BYTES`]. Scoped to
/// [`BIN_INDEX_V`]: a reader refuses an off-rung length fail-closed, so a change
/// to the ladder is a version bump.
pub const BIN_INDEX_RUNGS: &[usize] = &[
    4 * 1024,
    16 * 1024,
    64 * 1024,
    256 * 1024,
    1024 * 1024,
    MAX_BIN_INDEX_BYTES,
];

/// The totals `head_len(n) + n` never takes, because the byte-string head steps
/// width between them under the shortest-form rule. [`pad_len`] cannot land a
/// body on a rung that sits exactly this far above it.
const PAD_GAPS: [usize; 4] = [25, 258, 65539, 65540];

/// The largest *unpadded* body a rung admits.
///
/// A rung cannot absorb a body that sits a [`PAD_GAPS`] distance below it, so
/// the cap sits below the lowest such body. That is what makes the rung a body
/// takes rise monotonically with the body: without it, one byte of growth can
/// push a body over a gap and up a whole rung, and the 4x spike in the published
/// length would disclose the body size to the byte — the very thing the padding
/// exists to hide.
const fn rung_cap(rung: usize) -> usize {
    let mut largest = 0;
    let mut i = 0;
    while i < PAD_GAPS.len() {
        if PAD_GAPS[i] <= rung && PAD_GAPS[i] > largest {
            largest = PAD_GAPS[i];
        }
        i += 1;
    }
    rung - largest
}

/// The frozen bound on a bin index body *before* its pad. A body above it is
/// refused; every body at or below it reaches a rung.
pub const MAX_BIN_INDEX_BODY_BYTES: usize = rung_cap(MAX_BIN_INDEX_BYTES);

const _: () = {
    let mut i = 1;
    while i < BIN_INDEX_RUNGS.len() {
        // fit_rung takes the first rung at or above a body, so order is load-bearing.
        assert!(BIN_INDEX_RUNGS[i - 1] < BIN_INDEX_RUNGS[i]);
        i += 1;
    }
    assert!(BIN_INDEX_RUNGS[BIN_INDEX_RUNGS.len() - 1] == MAX_BIN_INDEX_BYTES);
};

/// The wire key holding the pad bytes. Known rather than preserved: a decode
/// drops it and the next encode recomputes it, so a rewrite re-pads to the rung
/// its own body needs.
const PAD_KEY: &str = "pad";

// ---------------------------------------------------------------------------
// One bin entry.
// ---------------------------------------------------------------------------

/// One soft-deleted node.
///
/// `ipns_name` and `origin_name` are sealed-record plaintext — user-private
/// metadata in a zero-knowledge system — so they render redacted and the entry
/// is their terminal owner: it wipes both on drop. A clone owns its own buffers,
/// so one instance's wipe never reaches another's. They stay private, unlike
/// [`ChildRef`](super::body::ChildRef)'s pair, because an entry is written once:
/// with no rewrite path there is no assignment that could drop a live buffer
/// unwiped.
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

    /// The deleted node's opaque `ipnsName` bytes.
    pub fn ipns_name(&self) -> &[u8] {
        &self.ipns_name
    }

    /// The display name the node carried in `origin_parent`.
    pub fn origin_name(&self) -> &str {
        &self.origin_name
    }

    /// The key the doomed subtree was re-keyed under; `None` when the delete
    /// skipped the re-key.
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
        let held_key = match map.get("heldKey") {
            Some(v) => Some(SecretBytes::new(bytes_fixed::<SECRET_LEN>(v, "heldKey")?)),
            None => None,
        };
        Ok(Self {
            node_id: bytes_fixed::<16>(req(map, "nodeId")?, "nodeId")?,
            ipns_name: req(map, "ipnsName")?.as_bytes()?.to_vec(),
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

const INDEX_KNOWN: &[&str] = &["entries", PAD_KEY, "revision"];

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

    /// Every invariant a decode hard-rejects, re-checked on a *constructed*
    /// index: both directions run this, so the encode path never publishes a
    /// body decode would refuse to reopen (AGENTS.md rule 8).
    ///
    /// `node_id` uniqueness is the fail-closed one: two entries for one node
    /// would let restore and purge pick a winner by position.
    fn validate(&self) -> Result<(), CodecError> {
        assert_unknown_disjoint(&self.unknown, INDEX_KNOWN)?;
        let mut ids = BTreeSet::new();
        for entry in &self.entries {
            entry.validate()?;
            if !ids.insert(entry.node_id) {
                return Err(TrustViolation::DuplicateId.into());
            }
        }
        Ok(())
    }
}

/// Decode a bin index plaintext (strict det-CBOR, uniqueness enforced).
///
/// The transient decoded tree carries a verbatim copy of every `heldKey`, so it
/// is scrubbed through the owning [`ScrubOwned`] guard (terminal-owner rule;
/// symmetric with [`encode_bin_index`]).
pub fn decode_bin_index(bytes: &[u8]) -> Result<BinIndex, CodecError> {
    assert_within_bound(BIN_INDEX_SIZE_CHECK, bytes.len(), MAX_BIN_INDEX_BYTES)?;
    if !BIN_INDEX_RUNGS.contains(&bytes.len()) {
        return Err(TrustViolation::NonCanonicalPadding.into());
    }
    let value = ScrubOwned(decode(bytes)?);
    let map = value.value().as_map()?;

    if req(map, PAD_KEY)?.as_bytes()?.iter().any(|b| *b != 0) {
        return Err(TrustViolation::NonCanonicalPadding.into());
    }
    let items = req(map, "entries")?.as_array()?;
    let mut entries = Vec::with_capacity(items.len());
    for item in items {
        entries.push(BinEntry::from_value(item)?);
    }
    let index = BinIndex {
        revision: req(map, "revision")?.as_unsigned()?,
        entries,
        unknown: collect_unknown(map, INDEX_KNOWN),
    };
    index.validate()?;
    Ok(index)
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
    m.insert(PAD_KEY, Value::Bytes(Vec::new()));
    m.insert("revision", Value::Unsigned(index.revision));
    merge_unknown(&mut m, &index.unknown);

    let mut value = Value::Map(m);
    let guard = ScrubOnDrop(&mut value);
    // Measured rather than encoded first: a body no rung admits never
    // materializes the plaintext buffer it would only be refused and wiped for.
    let bare = encoded_len(guard.0)?;
    let (rung, pad) = match fit_rung(bare) {
        Some(fit) => fit,
        None => {
            return Err(Malformed::TooManyStructures {
                collection: BIN_INDEX_SIZE_CHECK,
                count: bare,
                limit: MAX_BIN_INDEX_BODY_BYTES,
            }
            .into());
        }
    };
    if let Value::Map(map) = &mut *guard.0 {
        map.insert(PAD_KEY, Value::Bytes(vec![0; pad]));
    }

    let mut bytes = encode(guard.0)?;
    // The encode-side mirror of the decode's rung check (AGENTS.md rule 8). A
    // self-check on this build's own arithmetic, never a verdict on remote
    // bytes. The buffer carries every `heldKey`, and only the success path hands
    // the wipe to a caller, so this arm is its terminal owner.
    if bytes.len() != rung {
        bytes.zeroize();
        return Err(TrustViolation::NonCanonicalPadding.into());
    }
    Ok(bytes)
}

/// The rung a body measured at `bare` pads onto, and the pad byte count that
/// lands it there exactly. `None` when no rung admits the body.
///
/// The smallest rung whose [`rung_cap`] admits the body, so the result rises
/// monotonically with `bare`.
///
/// `#[doc(hidden)]`: `pub` only for the `kat_gen` example, which pads the
/// deliberately malformed bodies its reject vectors need and cannot go through
/// [`encode_bin_index`] to do it. Not supported API.
#[doc(hidden)]
pub fn fit_rung(bare: usize) -> Option<(usize, usize)> {
    let rung = BIN_INDEX_RUNGS
        .iter()
        .copied()
        .find(|rung| bare <= rung_cap(*rung))?;
    pad_len(bare, rung).map(|pad| (rung, pad))
}

/// The pad byte count that takes a body measured at `bare` — with `pad` present
/// and empty — to exactly `rung`.
///
/// Growing the pad by `n` bytes grows the body by `n` plus the byte-string
/// head's own growth, and that head is a step function under the shortest-form
/// rule, so this solves for the one head width that lands the total on the rung.
fn pad_len(bare: usize, rung: usize) -> Option<usize> {
    let room = rung.checked_sub(bare)? + head_len(0);
    [1usize, 2, 3, 5, 9]
        .into_iter()
        .filter_map(|width| room.checked_sub(width).map(|n| (width, n)))
        .find(|(width, n)| head_len(*n as u64) == *width)
        .map(|(_, n)| n)
}

/// The collection label the total-size refusal reports, so a caller can tell a
/// bin that no rung admits from any other refusal [`encode_bin_index`] makes.
pub const BIN_INDEX_SIZE_CHECK: &str = "binIndex";

// ---------------------------------------------------------------------------
// The sealed record.
// ---------------------------------------------------------------------------

/// The AAD of a bin index record: the `cipherbox/v2` domain separator, the
/// declared version, and the `bin-index` structure tag. The tag is what keeps a
/// bin ciphertext from being reinterpreted as any other symmetric structure, and
/// the version is the downgrade defence. Public — the frozen layout, so the KAT
/// generator pins it directly.
///
/// `version` is the record's own declared value rather than [`BIN_INDEX_V`], so
/// the binding stays honest once a build accepts more than one version.
pub fn bin_index_aad(version: u64) -> Vec<u8> {
    encode_fixed_depth(&Value::Array(vec![
        Value::Text(AAD_DOMAIN.to_string()),
        Value::Unsigned(version),
        Value::Unsigned(u64::from(STRUCT_TAG_BIN_INDEX)),
    ]))
}

/// Seal a bin index under the owner's `bin-index-seal-key`.
///
/// `nonce` must be **drawn fresh from a CSPRNG for every seal**, not counted and
/// not derived from the body revision. The seal key takes no epoch input, so it
/// never rotates, and two devices publish this record concurrently under one CAS
/// guard: a counter is unique on one device and collides across two.
/// XChaCha20-Poly1305 nonce reuse under one key discloses every `heldKey` the
/// two bodies carry and admits forgery. The nonce is caller-injected entropy
/// (the KATs pin it), prefixed inside the sealed blob so [`open_bin_index`]
/// recovers it, and authenticated by the AEAD.
pub fn seal_bin_index(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    index: &BinIndex,
) -> Result<Vec<u8>, CodecError> {
    let plaintext = Zeroizing::new(encode_bin_index(index)?);
    let mut m = Map::new();
    m.insert(
        "sealed",
        Value::Bytes(seal_framed(
            key,
            nonce,
            &bin_index_aad(BIN_INDEX_V),
            &plaintext,
        )),
    );
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
    // Charged before the decode, so an oversized record costs a comparison
    // rather than a full tree walk of attacker bytes.
    assert_within_bound(BIN_INDEX_SIZE_CHECK, record.len(), MAX_BLOCK_BYTES)?;
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
    let plaintext = Zeroizing::new(open_framed(key, &bin_index_aad(version), sealed)?);
    decode_bin_index(&plaintext)
}

/// The two clear-header keys, exhaustive at [`BIN_INDEX_V`].
const HEADER_KEYS: [&str; 2] = ["sealed", "v"];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::aead::TAG_LEN;

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

    /// A hand-built body padded to its rung, so a decode reaches the grammar
    /// check under test rather than the padding check in front of it.
    fn padded_body(mut m: Map) -> Vec<u8> {
        m.insert(PAD_KEY, Value::Bytes(Vec::new()));
        let mut value = Value::Map(m);
        let bare = encoded_len(&value).unwrap();
        let (_, pad) = fit_rung(bare).unwrap();
        match &mut value {
            Value::Map(map) => map.insert(PAD_KEY, Value::Bytes(vec![0; pad])),
            _ => unreachable!(),
        }
        encode(&value).unwrap()
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

    /// The nonce is a real input and the AEAD authenticates it: two nonces over
    /// one index give two records, and a flip inside the nonce prefix fails the
    /// tag rather than opening a shifted keystream.
    #[test]
    fn the_nonce_is_an_input_and_is_authenticated() {
        let key = [8u8; KEY_LEN];
        let index = populated();
        let a = seal_bin_index(&key, &[1; NONCE_LEN], &index).unwrap();
        let b = seal_bin_index(&key, &[2; NONCE_LEN], &index).unwrap();
        assert_ne!(a, b, "a fresh nonce must change the record");

        let mut sealed = decode(&a)
            .unwrap()
            .as_map()
            .unwrap()
            .get("sealed")
            .unwrap()
            .as_bytes()
            .unwrap()
            .to_vec();
        sealed[0] ^= 1;
        assert_eq!(
            open_bin_index(&key, &reframe(&a, "sealed", Value::Bytes(sealed)))
                .unwrap_err()
                .check(),
            "seal-open-failed"
        );
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
            Value::Unsigned(u64::from(crate::seal::aad::STRUCT_TAG_READ_BODY)),
        ]));
        let mut m = Map::new();
        m.insert(
            "sealed",
            Value::Bytes(seal_framed(&key, &nonce, &foreign_aad, &plaintext)),
        );
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
        assert_eq!(
            decode_bin_index(&padded_body(m)).unwrap_err().check(),
            "duplicate-id"
        );
    }

    #[test]
    fn an_over_bound_body_is_refused_on_both_sides() {
        let mut index = BinIndex::new(1);
        index.entries.push(entry(1));
        index.unknown = core::iter::once((
            "filler".to_string(),
            Value::Bytes(vec![0; MAX_BIN_INDEX_BYTES]),
        ))
        .collect();
        assert_eq!(
            encode_bin_index(&index).unwrap_err().check(),
            "too-many-structures"
        );

        // The same body framed past the encoder: decode must refuse it too.
        let mut m = Map::new();
        m.insert("entries", Value::Array(vec![entry(1).to_value()]));
        m.insert("filler", Value::Bytes(vec![0; MAX_BIN_INDEX_BYTES]));
        m.insert("revision", Value::Unsigned(1));
        let bytes = encode(&Value::Map(m)).unwrap();
        assert_eq!(
            decode_bin_index(&bytes).unwrap_err().check(),
            "too-many-structures"
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
        assert_eq!(
            decode_bin_index(&padded_body(m)).unwrap_err().check(),
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
        let bytes = padded_body(m);

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

    /// The privacy claim: two indexes whose entry counts differ inside one rung
    /// seal to records of equal length, so the ciphertext discloses the rung and
    /// nothing finer.
    #[test]
    fn bodies_on_one_rung_seal_to_equal_lengths() {
        let with = |count: usize| {
            let mut index = BinIndex::new(4);
            for seed in 1..=count {
                index.entries.push(entry(seed as u8));
            }
            index
        };
        for count in 0..=2 {
            assert_eq!(
                encode_bin_index(&with(count)).unwrap().len(),
                BIN_INDEX_RUNGS[0],
                "{count} entries must pad to the first rung",
            );
        }

        let key = [4u8; KEY_LEN];
        assert_eq!(
            seal_bin_index(&key, &[1; NONCE_LEN], &with(0))
                .unwrap()
                .len(),
            seal_bin_index(&key, &[2; NONCE_LEN], &with(2))
                .unwrap()
                .len(),
            "the record length must not track the entry count",
        );
    }

    /// The property the rung caps exist for. Without them a body that grows one
    /// byte over a head-step gap climbs a whole rung, and the 4x jump in the
    /// published length names the body size to the byte.
    #[test]
    fn the_rung_a_body_takes_never_falls_as_it_grows() {
        let build = |fill: usize| {
            let mut index = BinIndex::new(9);
            let mut e = entry(1);
            e.origin_name = "x".repeat(fill);
            index.entries.push(e);
            index
        };
        let mut last = 0usize;
        for fill in 0..(BIN_INDEX_RUNGS[0] + 600) {
            let len = encode_bin_index(&build(fill)).unwrap().len();
            assert!(
                len >= last,
                "one more byte of body shrank the record at fill={fill}",
            );
            last = len;
        }
        assert_eq!(last, BIN_INDEX_RUNGS[1], "the walk must cross one rung");
    }

    /// [`PAD_GAPS`] is a hand-written constant that the caps derive from, so it
    /// is pinned against the head widths rather than trusted.
    #[test]
    fn the_pad_gaps_are_exactly_the_unreachable_totals() {
        let ceiling = PAD_GAPS[PAD_GAPS.len() - 1] + 8;
        let reachable: BTreeSet<usize> = (0..ceiling)
            .map(|n| head_len(n as u64) + n)
            .filter(|room| *room < ceiling)
            .collect();
        let gaps: Vec<usize> = (1..ceiling).filter(|r| !reachable.contains(r)).collect();
        assert_eq!(gaps, PAD_GAPS, "the head-step gaps moved");
    }

    /// Every rung cap is reachable, and a body one byte past it climbs exactly
    /// one rung. The caps are what the ladder promises, not the raw rung sizes.
    #[test]
    fn a_body_at_a_rung_cap_pads_and_one_past_it_climbs() {
        for pair in BIN_INDEX_RUNGS.windows(2) {
            let (rung, next) = (pair[0], pair[1]);
            let cap = rung_cap(rung);
            assert_eq!(fit_rung(cap).map(|(r, _)| r), Some(rung));
            assert_eq!(fit_rung(cap + 1).map(|(r, _)| r), Some(next));
        }
        assert_eq!(fit_rung(MAX_BIN_INDEX_BODY_BYTES + 1), None);
    }

    /// The decoder tests rung membership, not minimality: an over-padded body
    /// opens, and the rewrite pads it back down. Checking minimality would make
    /// every later encoder change a hard break.
    #[test]
    fn a_body_padded_to_a_larger_rung_opens_and_re_pads_down() {
        let index = populated();
        let bytes = encode_bin_index(&index).unwrap();
        assert_eq!(bytes.len(), BIN_INDEX_RUNGS[0]);

        let decoded = decode(&bytes).unwrap();
        let mut m = decoded.as_map().unwrap().clone();
        let pad = m.get(PAD_KEY).unwrap().as_bytes().unwrap().len();
        m.insert(
            PAD_KEY,
            Value::Bytes(vec![0; pad + BIN_INDEX_RUNGS[1] - BIN_INDEX_RUNGS[0]]),
        );
        let over = encode(&Value::Map(m)).unwrap();
        assert_eq!(over.len(), BIN_INDEX_RUNGS[1]);

        let reopened = decode_bin_index(&over).unwrap();
        assert_eq!(reopened, index);
        assert_eq!(
            encode_bin_index(&reopened).unwrap().len(),
            BIN_INDEX_RUNGS[0],
            "a rewrite must fall back to the rung the body needs",
        );
    }

    #[test]
    fn an_off_rung_length_is_refused() {
        let bytes = encode_bin_index(&populated()).unwrap();
        let decoded = decode(&bytes).unwrap();
        let mut m = decoded.as_map().unwrap().clone();
        let pad = m.get(PAD_KEY).unwrap().as_bytes().unwrap().len();
        m.insert(PAD_KEY, Value::Bytes(vec![0; pad - 1]));
        assert_eq!(
            decode_bin_index(&encode(&Value::Map(m)).unwrap())
                .unwrap_err()
                .check(),
            "non-canonical-padding"
        );
    }

    #[test]
    fn a_non_zero_pad_byte_is_refused() {
        let bytes = encode_bin_index(&populated()).unwrap();
        let decoded = decode(&bytes).unwrap();
        let mut m = decoded.as_map().unwrap().clone();
        let mut pad = m.get(PAD_KEY).unwrap().as_bytes().unwrap().to_vec();
        pad[0] = 1;
        m.insert(PAD_KEY, Value::Bytes(pad));
        assert_eq!(
            decode_bin_index(&encode(&Value::Map(m)).unwrap())
                .unwrap_err()
                .check(),
            "non-canonical-padding"
        );
    }

    #[test]
    fn a_missing_pad_field_is_malformed() {
        let bytes = encode_bin_index(&populated()).unwrap();
        let decoded = decode(&bytes).unwrap();
        let mut m = decoded.as_map().unwrap().clone();
        let pad = m.get(PAD_KEY).unwrap().as_bytes().unwrap().len();
        m.remove(PAD_KEY);
        // Keep the body on its rung through an unknown field of the same key
        // width and size, so the length check cannot fire before this one.
        m.insert("zzz", Value::Bytes(vec![0; pad]));
        assert_eq!(
            decode_bin_index(&encode(&Value::Map(m)).unwrap())
                .unwrap_err()
                .check(),
            "missing-field"
        );
    }

    #[test]
    fn the_pad_never_survives_into_the_preserved_set() {
        let index = decode_bin_index(&encode_bin_index(&populated()).unwrap()).unwrap();
        assert!(index.unknown.is_empty());
    }

    #[test]
    fn an_over_bound_record_never_reaches_the_decoder() {
        let over = vec![0u8; MAX_BLOCK_BYTES + 1];
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
        assert_eq!(
            decode_bin_index(&padded_body(m)).unwrap_err().check(),
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
        assert_eq!(
            decode_bin_index(&padded_body(m)).unwrap_err().check(),
            "invalid-node-kind"
        );
    }

    /// Never-log-keys: an entry's `Debug` must render neither the held key nor
    /// the two user-private plaintext fields.
    #[test]
    fn debug_redacts_the_held_key_the_origin_name_and_the_ipns_name() {
        let rendered = format!("{:?}", entry(1));
        assert!(!rendered.contains("note-1.txt"), "{rendered}");
        assert!(rendered.contains("SecretBytes(redacted)"), "{rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
        assert!(
            !rendered.contains("[1, 2, 3]"),
            "the ipnsName bytes must not render: {rendered}"
        );
    }
}
