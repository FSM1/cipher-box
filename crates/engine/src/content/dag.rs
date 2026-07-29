//! DAG assembly: the version root addressed by its `contentCid`
//! (blueprint/engine.md "Content plane": "assembles a DAG addressed by the
//! version's `contentCid`, shaped so ranged block/CAR fetches map
//! chunk-aligned").
//!
//! The DAG *shape* is engine-owned; the *encoding* and the content-address are
//! core's — the root node is serialized with core's deterministic CBOR
//! ([`cipherbox_core::codec`], a strict DAG-CBOR subset) and addressed by
//! [`cipherbox_core::content::compute_cid`] under the engine-chosen `dag-cbor`
//! codec, so there is one codec and one KAT set (AGENTS.md rules 4-5).
//!
//! The shape is frozen (#820, blueprint/engine.md "Content plane"): a single
//! flat root over the ordered leaf CIDs plus the fixed chunk size, the
//! plaintext length, and [`ROOT_FORMAT_VERSION`]. Flat keeps the byte→leaf map
//! a single division, which is the chunk-alignment a ranged fetch needs, and
//! costs the ceiling documented on [`DagError::RootTooLarge`].

use cipherbox_core::codec::{Map, Value, decode, encode_fixed_depth};
use cipherbox_core::content::{
    CONTENT_CID_CODEC, CONTENT_CID_LEN, CONTENT_CID_MULTIHASH, compute_cid, encode_content_cid_str,
};
use cipherbox_core::error::{CodecError, Malformed};

use super::limits::MAX_RESOLVED_RECORD_BYTES;
use super::profile::ContentProfile;

/// The multicodec of the DAG-root `contentCid`: `dag-cbor` (0x71). Engine-owned
/// (#630, engine.md:497) — core keeps the leaf `raw` codec but takes the root
/// codec as a parameter. Single-byte, inside core's frozen content-plane set.
pub const DAG_ROOT_CODEC: u8 = 0x71;

/// A root-plane block's own content address, as a record `Value` and a link
/// spell it. The one place the root codec meets the multibase spelling.
#[must_use]
pub fn root_block_cid(block: &[u8]) -> String {
    encode_content_cid_str(&compute_cid(DAG_ROOT_CODEC, block))
}

/// The root-manifest format version this crate writes and the only one it
/// reads. A discriminator, not a compatibility arm: a root carrying any other
/// version is refused as [`DagError::UnsupportedFormat`], so a client meeting a
/// future shape reports "upgrade" instead of a rule-6 trust violation (#820).
pub const ROOT_FORMAT_VERSION: u64 = 1;

/// CIDv1 version byte, and the digest-length byte (BLAKE3-256 = 32) — the two
/// fixed CIDv1 framing bytes core does not expose as public constants; used to
/// validate that a decoded leaf link is a well-formed content CID.
const CID_VERSION: u8 = 0x01;
const CID_DIGEST_LEN: u8 = 32;

/// Why assembling or decoding a root block failed, fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DagError {
    /// The root block was not valid deterministic CBOR, or not the root map
    /// shape (a non-canonical encoding, a missing field, a wrong-typed field) —
    /// a core [`CodecError`] surfaced verbatim.
    Cbor(CodecError),
    /// The root declared a format version other than [`ROOT_FORMAT_VERSION`].
    /// Deliberately distinct from the invariant rejects below: the content is
    /// not suspect, this build simply cannot read the shape.
    UnsupportedFormat {
        /// The version the root declared.
        version: u64,
    },
    /// The root declared a zero chunk size, which no framing can produce and
    /// which would make the byte→leaf map a division by zero.
    ZeroChunkSize,
    /// A leaf link was not a well-formed `raw` content CID.
    MalformedLeafCid,
    /// The link count disagreed with `ceil(size / chunkSize)`. An internally
    /// inconsistent manifest is never trusted, even when its own `contentCid`
    /// verifies.
    LinkCountMismatch,
    /// The assembled root manifest exceeded [`MAX_RESOLVED_RECORD_BYTES`]: the
    /// flat root inlines every leaf CID, so a file past the flat-DAG ceiling
    /// (~108 GiB) produces a root [`read_block`](super::read::read_block) would
    /// reject on fetch. Fails closed here so the encoder never emits an
    /// unreadable root (AGENTS.md rule 8; #788).
    RootTooLarge {
        /// The encoded root size.
        size: usize,
        /// The enforced ceiling ([`MAX_RESOLVED_RECORD_BYTES`]).
        limit: usize,
    },
}

impl DagError {
    /// Every engine-owned DAG check, in declaration order — the surface
    /// `crates/engine/tests/kat_content.rs` pins. The `dag-` prefix keeps an
    /// engine check from ever colliding with a core one.
    pub const CHECKS: &'static [&'static str] = &[
        "dag-unsupported-format",
        "dag-zero-chunk-size",
        "dag-malformed-leaf-cid",
        "dag-link-count-mismatch",
        "dag-root-too-large",
    ];

    /// The stable name of the check that fired.
    pub fn check(&self) -> &'static str {
        match self {
            Self::Cbor(error) => error.check(),
            Self::UnsupportedFormat { .. } => "dag-unsupported-format",
            Self::ZeroChunkSize => "dag-zero-chunk-size",
            Self::MalformedLeafCid => "dag-malformed-leaf-cid",
            Self::LinkCountMismatch => "dag-link-count-mismatch",
            Self::RootTooLarge { .. } => "dag-root-too-large",
        }
    }

    /// The class label used in reject vectors. Exhaustive so a new variant must
    /// state its class rather than inherit `"trust"`.
    pub fn class(&self) -> &'static str {
        match self {
            Self::Cbor(error) => error.class(),
            Self::UnsupportedFormat { .. } => "unsupported",
            Self::RootTooLarge { .. } => "over-cap",
            Self::ZeroChunkSize | Self::MalformedLeafCid | Self::LinkCountMismatch => "trust",
        }
    }
}

impl From<CodecError> for DagError {
    fn from(error: CodecError) -> Self {
        Self::Cbor(error)
    }
}

impl From<Malformed> for DagError {
    fn from(error: Malformed) -> Self {
        Self::Cbor(error.into())
    }
}

const VERSION_KEY: &str = "v";
const CHUNK_SIZE_KEY: &str = "chunkSize";
const SIZE_KEY: &str = "size";
const LINKS_KEY: &str = "links";

/// An assembled content DAG: the version root block and the `contentCid` that
/// addresses it. The leaf blocks it links are staged separately; this is only
/// the root the version metadata pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentDag {
    /// The version's `contentCid` (binary CIDv1, `dag-cbor` codec) — a BLAKE3
    /// digest over [`Self::root_block`]. A verified read of the root recomputes
    /// and fails closed on mismatch.
    pub content_cid: Vec<u8>,
    /// The deterministic det-CBOR root node bytes this CID addresses.
    pub root_block: Vec<u8>,
}

/// Assemble the ordered `leaf_cids` into a version root addressed by its
/// `contentCid`. `plaintext_len` is the pre-seal byte length (the ranged-read
/// size bound). Deterministic: identical links + length + profile give a
/// byte-identical root block and CID.
///
/// Takes the leaf **addresses**, not the leaf blocks: a streaming write stages
/// each sealed leaf as it is framed and never holds the set
/// ([`ContentWriter`](super::write::ContentWriter)).
///
/// Every caller-supplied invariant [`decode_root`] rejects on is enforced here
/// too, in every build (not a release-compiled-out `debug_assert`): a mis-wired
/// caller must never emit a root this crate's own decoder rejects, which would
/// leave the published version permanently unreadable (AGENTS.md rule 8).
pub fn assemble(
    leaf_cids: &[Vec<u8>],
    plaintext_len: u64,
    profile: &ContentProfile,
) -> Result<ContentDag, DagError> {
    if !leaf_cids.iter().all(|cid| is_raw_leaf_cid(cid)) {
        return Err(DagError::MalformedLeafCid);
    }
    if leaf_cids.len() as u64 != expected_leaf_count(plaintext_len, profile.chunk_size() as u64) {
        return Err(DagError::LinkCountMismatch);
    }
    let links = leaf_cids.iter().cloned().map(Value::Bytes).collect();
    let mut root = Map::new();
    root.insert(VERSION_KEY, Value::Unsigned(ROOT_FORMAT_VERSION));
    root.insert(CHUNK_SIZE_KEY, Value::Unsigned(profile.chunk_size() as u64));
    root.insert(SIZE_KEY, Value::Unsigned(plaintext_len));
    root.insert(LINKS_KEY, Value::Array(links));
    let root_block = encode_fixed_depth(&Value::Map(root));
    // fail closed: an over-cap root would be unreadable — see DagError::RootTooLarge.
    if root_block.len() > MAX_RESOLVED_RECORD_BYTES {
        return Err(DagError::RootTooLarge {
            size: root_block.len(),
            limit: MAX_RESOLVED_RECORD_BYTES,
        });
    }
    let content_cid = compute_cid(DAG_ROOT_CODEC, &root_block);
    Ok(ContentDag {
        content_cid,
        root_block,
    })
}

/// The manifest read back from a verified root block: the fixed chunk size, the
/// plaintext length, and the ordered leaf CIDs. What a ranged read consults to
/// map a byte range to leaf blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootManifest {
    /// The fixed chunk size the leaves were framed at.
    pub chunk_size: u64,
    /// The total plaintext byte length across all leaves.
    pub size: u64,
    /// The leaf content CIDs, in file order.
    pub leaf_cids: Vec<Vec<u8>>,
}

/// Decode a root block (already verified against its `contentCid` by the
/// caller) into its manifest, fail-closed — a `contentCid`-valid-but-internally
/// inconsistent root is rejected, not silently trusted. The format version is
/// read first, so a future shape is refused as
/// [`DagError::UnsupportedFormat`] rather than by whichever invariant it
/// happens to trip.
pub fn decode_root(root_block: &[u8]) -> Result<RootManifest, DagError> {
    let root = decode(root_block)?;
    let map = root.as_map()?;
    let version = map
        .get(VERSION_KEY)
        .ok_or(Malformed::MissingField { field: "v" })?
        .as_unsigned()?;
    if version != ROOT_FORMAT_VERSION {
        return Err(DagError::UnsupportedFormat { version });
    }
    let chunk_size = map
        .get(CHUNK_SIZE_KEY)
        .ok_or(Malformed::MissingField { field: "chunkSize" })?
        .as_unsigned()?;
    let size = map
        .get(SIZE_KEY)
        .ok_or(Malformed::MissingField { field: "size" })?
        .as_unsigned()?;
    let leaf_cids = map
        .get(LINKS_KEY)
        .ok_or(Malformed::MissingField { field: "links" })?
        .as_array()?
        .iter()
        .map(|link| link.as_bytes().map(<[u8]>::to_vec))
        .collect::<Result<Vec<_>, Malformed>>()?;

    if chunk_size == 0 {
        return Err(DagError::ZeroChunkSize);
    }
    if !leaf_cids.iter().all(|cid| is_raw_leaf_cid(cid)) {
        return Err(DagError::MalformedLeafCid);
    }
    if leaf_cids.len() as u64 != expected_leaf_count(size, chunk_size) {
        return Err(DagError::LinkCountMismatch);
    }

    Ok(RootManifest {
        chunk_size,
        size,
        leaf_cids,
    })
}

/// The leaf count a version of `plaintext_len` bytes frames to at `chunk_size`:
/// `ceil(len / chunk_size)`, except an empty version is exactly one empty leaf.
/// The single formula both [`assemble`] (produce) and [`decode_root`] (consume)
/// share, so the two sides cannot diverge. `chunk_size` is nonzero at both call
/// sites (a profile invariant on produce; the zero-chunk check runs first on
/// decode).
pub(crate) fn expected_leaf_count(plaintext_len: u64, chunk_size: u64) -> u64 {
    if plaintext_len == 0 {
        1
    } else {
        plaintext_len.div_ceil(chunk_size)
    }
}

/// Whether `cid` is a well-formed `raw` leaf content CID: the fixed CIDv1 framing
/// `version || raw || blake3 || len` over a 32-byte digest. This checks framing,
/// not the digest — the digest is verified when the leaf block is fetched and
/// run through [`cipherbox_core::content::verify_cid`].
fn is_raw_leaf_cid(cid: &[u8]) -> bool {
    cid.len() == CONTENT_CID_LEN
        && cid[0] == CID_VERSION
        && cid[1] == CONTENT_CID_CODEC
        && cid[2] == CONTENT_CID_MULTIHASH
        && cid[3] == CID_DIGEST_LEN
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::chunk::{ContentKey, frame_and_seal};
    use crate::testkit::SeededEntropy;
    use cipherbox_core::codec::encode;
    use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid, verify_cid};
    use cipherbox_core::suite::aead::KEY_LEN;

    fn framed(plaintext: &[u8], seed: u64) -> (Vec<Vec<u8>>, ContentProfile) {
        let profile = ContentProfile::CI;
        let key = ContentKey::from_bytes([7u8; KEY_LEN]);
        let leaves =
            frame_and_seal(plaintext, &key, &mut SeededEntropy::new(seed), &profile).unwrap();
        (leaves.into_iter().map(|leaf| leaf.cid).collect(), profile)
    }

    /// Hand-build a root block with arbitrary fields, bypassing `assemble`, to
    /// drive the fail-closed manifest checks.
    fn root_bytes(version: u64, chunk_size: u64, size: u64, links: &[Vec<u8>]) -> Vec<u8> {
        let mut root = Map::new();
        root.insert(VERSION_KEY, Value::Unsigned(version));
        root.insert(CHUNK_SIZE_KEY, Value::Unsigned(chunk_size));
        root.insert(SIZE_KEY, Value::Unsigned(size));
        root.insert(
            LINKS_KEY,
            Value::Array(links.iter().cloned().map(Value::Bytes).collect()),
        );
        encode(&Value::Map(root)).unwrap()
    }

    fn reject_check(block: &[u8]) -> &'static str {
        match decode_root(block) {
            Err(error) => error.check(),
            Ok(manifest) => panic!("expected a fail-closed reject, got {manifest:?}"),
        }
    }

    #[test]
    fn root_content_addresses_to_its_content_cid() {
        let (leaves, profile) = framed(&(0..40u8).collect::<Vec<_>>(), 1);
        let dag = assemble(&leaves, 40, &profile).unwrap();
        assert!(verify_cid(&dag.content_cid, &dag.root_block).is_ok());
        assert_eq!(
            dag.content_cid[1], DAG_ROOT_CODEC,
            "root CID carries dag-cbor"
        );
    }

    #[test]
    fn assembly_is_deterministic() {
        let (leaves, profile) = framed(&(0..40u8).collect::<Vec<_>>(), 7);
        let a = assemble(&leaves, 40, &profile).unwrap();
        let b = assemble(&leaves, 40, &profile).unwrap();
        assert_eq!(a, b, "same leaves + length => byte-identical root");
    }

    #[test]
    fn root_manifest_round_trips_the_ordered_leaf_cids() {
        let plaintext: Vec<u8> = (0..40u8).collect();
        let (leaves, profile) = framed(&plaintext, 3);
        let dag = assemble(&leaves, plaintext.len() as u64, &profile).unwrap();

        let manifest = decode_root(&dag.root_block).unwrap();
        assert_eq!(manifest.chunk_size, profile.chunk_size() as u64);
        assert_eq!(manifest.size, plaintext.len() as u64);
        assert_eq!(manifest.leaf_cids, leaves, "links preserve file order");
    }

    #[test]
    fn leaf_cids_use_the_raw_codec_root_uses_dag_cbor() {
        let (leaves, profile) = framed(b"abc", 5);
        let dag = assemble(&leaves, 3, &profile).unwrap();
        assert_eq!(leaves[0][1], CONTENT_CID_CODEC, "leaf is raw");
        assert_eq!(dag.content_cid[1], DAG_ROOT_CODEC, "root is dag-cbor");
    }

    #[test]
    fn decode_rejects_a_non_root_block_fail_closed() {
        // A valid det-CBOR value that is not the root map shape.
        let not_a_root = encode(&Value::Unsigned(7)).unwrap();
        assert!(decode_root(&not_a_root).is_err());
    }

    #[test]
    fn decode_root_rejects_a_zero_chunk_size() {
        assert_eq!(
            reject_check(&root_bytes(ROOT_FORMAT_VERSION, 0, 0, &[])),
            "dag-zero-chunk-size"
        );
    }

    #[test]
    fn decode_root_rejects_a_malformed_leaf_cid() {
        // chunkSize 16, size 16 => one leaf expected; the one link is not a CID.
        let block = root_bytes(
            ROOT_FORMAT_VERSION,
            16,
            16,
            &[b"not-a-content-cid".to_vec()],
        );
        assert_eq!(reject_check(&block), "dag-malformed-leaf-cid");
    }

    #[test]
    fn decode_root_rejects_a_link_count_size_mismatch() {
        // size 40 at chunkSize 16 expects 3 leaves; only one (valid) link given.
        let block = root_bytes(
            ROOT_FORMAT_VERSION,
            16,
            40,
            &[compute_cid(CONTENT_CID_CODEC, b"x")],
        );
        assert_eq!(reject_check(&block), "dag-link-count-mismatch");
    }

    #[test]
    fn assemble_stamps_the_frozen_format_version() {
        let (leaves, profile) = framed(b"abc", 13);
        let dag = assemble(&leaves, 3, &profile).unwrap();
        let root = decode(&dag.root_block).unwrap();
        assert_eq!(
            root.as_map().unwrap().get(VERSION_KEY).unwrap(),
            &Value::Unsigned(ROOT_FORMAT_VERSION),
            "every published root carries the format discriminator"
        );
    }

    #[test]
    fn decode_root_refuses_an_unrecognized_format_version() {
        // A future fan-out root: the version check fires first, so the client
        // learns it is out of date instead of reporting a trust violation.
        let block = root_bytes(
            ROOT_FORMAT_VERSION + 1,
            16,
            16,
            &[b"not-a-content-cid".to_vec()],
        );
        assert_eq!(
            decode_root(&block),
            Err(DagError::UnsupportedFormat {
                version: ROOT_FORMAT_VERSION + 1
            })
        );
    }

    #[test]
    fn decode_root_rejects_a_root_with_no_format_version() {
        let mut root = Map::new();
        root.insert(CHUNK_SIZE_KEY, Value::Unsigned(16));
        root.insert(SIZE_KEY, Value::Unsigned(0));
        root.insert(LINKS_KEY, Value::Array(Vec::new()));
        assert_eq!(
            reject_check(&encode(&Value::Map(root)).unwrap()),
            "missing-field"
        );
    }

    #[test]
    fn decode_root_accepts_the_empty_version_single_leaf() {
        // size 0 frames to exactly one empty leaf; the count check must allow it.
        let (leaves, profile) = framed(b"", 9);
        let dag = assemble(&leaves, 0, &profile).unwrap();
        let manifest = decode_root(&dag.root_block).unwrap();
        assert_eq!(manifest.size, 0);
        assert_eq!(manifest.leaf_cids.len(), 1);
    }

    /// `count` distinct well-formed leaf CIDs — the root can be sized without
    /// materializing any file bytes.
    fn dummy_leaves(count: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|i| compute_cid(CONTENT_CID_CODEC, &(i as u64).to_be_bytes()))
            .collect()
    }

    #[test]
    fn assemble_fails_closed_when_the_root_exceeds_the_block_cap() {
        // Each inlined 36-byte CID costs ~38 CBOR bytes, so ~120k links push the
        // flat root over the 4 MiB cap; `assemble` must fail closed in every
        // build (not a release-stripped assert) rather than emit an unreadable
        // root (AGENTS.md rule 8). `plaintext_len = count * chunkSize` keeps the
        // leaf-count invariant satisfied so the size guard is what fires.
        let profile = ContentProfile::CI;
        let chunk_size = profile.chunk_size() as u64;
        let count = 120_000;
        let leaves = dummy_leaves(count);
        match assemble(&leaves, count as u64 * chunk_size, &profile) {
            Err(DagError::RootTooLarge { size, limit }) => {
                assert!(size > limit, "reported size exceeds the cap");
                assert_eq!(limit, 4 * 1024 * 1024);
            }
            other => panic!("expected RootTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn assemble_accepts_a_root_just_under_the_block_cap() {
        // ~100k links keep the root comfortably under 4 MiB; it assembles Ok and
        // content-addresses, proving the guard rejects only over-cap roots.
        let profile = ContentProfile::CI;
        let chunk_size = profile.chunk_size() as u64;
        let count = 100_000;
        let leaves = dummy_leaves(count);
        let dag = assemble(&leaves, count as u64 * chunk_size, &profile).unwrap();
        assert!(dag.root_block.len() <= 4 * 1024 * 1024);
        assert!(verify_cid(&dag.content_cid, &dag.root_block).is_ok());
    }

    #[test]
    fn assemble_rejects_a_leaf_count_size_mismatch_in_every_build() {
        // `b"abc"` frames to one leaf at CI's 16-byte chunk, but a plaintext_len
        // of 40 expects three — the invariant fails closed in a normal (non
        // debug_assert) test build rather than emitting an unreadable root.
        let (leaves, profile) = framed(b"abc", 11);
        assert_eq!(leaves.len(), 1);
        assert_eq!(
            assemble(&leaves, 40, &profile),
            Err(DagError::LinkCountMismatch)
        );
    }

    #[test]
    fn assemble_rejects_a_malformed_leaf_cid_in_every_build() {
        // The encode-side half of `decode_root`'s leaf-CID reject (rule 8).
        let profile = ContentProfile::CI;
        let leaves = vec![b"not-a-content-cid".to_vec()];
        assert_eq!(
            assemble(&leaves, profile.chunk_size() as u64, &profile),
            Err(DagError::MalformedLeafCid)
        );
    }

    #[test]
    fn the_check_surface_matches_the_engine_owned_variants_in_order() {
        let named: Vec<&str> = [
            DagError::UnsupportedFormat { version: 2 },
            DagError::ZeroChunkSize,
            DagError::MalformedLeafCid,
            DagError::LinkCountMismatch,
            DagError::RootTooLarge { size: 1, limit: 0 },
        ]
        .iter()
        .map(DagError::check)
        .collect();
        assert_eq!(named, DagError::CHECKS);
    }
}
