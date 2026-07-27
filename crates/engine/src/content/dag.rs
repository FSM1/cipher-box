//! DAG assembly: the version root addressed by its `contentCid`
//! (blueprint/engine.md "Content plane": "assembles a DAG addressed by the
//! version's `contentCid`, shaped so ranged block/CAR fetches map
//! chunk-aligned").
//!
//! The DAG *shape* is engine-owned (an open edge); the *encoding* and the
//! content-address are core's — the root node is serialized with core's
//! deterministic CBOR ([`cipherbox_core::codec`], a strict DAG-CBOR subset) and
//! addressed by [`cipherbox_core::content::compute_cid`] under the engine-chosen
//! `dag-cbor` codec, so there is one codec and one KAT set (AGENTS.md rules 4-5).
//!
//! Shape today is a single flat root over the ordered leaf CIDs plus the fixed
//! chunk size and the plaintext length. Flat keeps the byte→leaf map trivial
//! (offset / chunkSize), which is exactly the chunk-alignment a ranged fetch
//! needs; a fan-out/balancing profile is the open edge deferred with the chunk
//! size (blueprint/engine.md "Open edges").

use cipherbox_core::codec::{Map, Value, decode, encode_fixed_depth};
use cipherbox_core::content::{
    CONTENT_CID_CODEC, CONTENT_CID_LEN, CONTENT_CID_MULTIHASH, compute_cid,
};
use cipherbox_core::error::{CodecError, Malformed};

use super::chunk::SealedChunk;
use super::limits::MAX_RESOLVED_RECORD_BYTES;
use super::profile::ContentProfile;

/// The multicodec of the DAG-root `contentCid`: `dag-cbor` (0x71). Engine-owned
/// (#630, engine.md:497) — core keeps the leaf `raw` codec but takes the root
/// codec as a parameter. Single-byte, inside core's frozen content-plane set.
pub const DAG_ROOT_CODEC: u8 = 0x71;

/// CIDv1 version byte, and the digest-length byte (BLAKE3-256 = 32) — the two
/// fixed CIDv1 framing bytes core does not expose as public constants; used to
/// validate that a decoded leaf link is a well-formed content CID.
const CID_VERSION: u8 = 0x01;
const CID_DIGEST_LEN: u8 = 32;

/// Why decoding a root block failed, fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DagError {
    /// The root block was not valid deterministic CBOR, or not the root map
    /// shape (a non-canonical encoding, a missing field, a wrong-typed field) —
    /// a core [`CodecError`] surfaced verbatim.
    Cbor(CodecError),
    /// The root decoded but violated a manifest invariant: a zero chunk size, a
    /// leaf link that is not a well-formed content CID, or a link count
    /// inconsistent with the byte size. An internally inconsistent manifest is
    /// never trusted, even when its own `contentCid` verifies.
    InvalidManifest {
        /// Which invariant failed.
        reason: &'static str,
    },
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

const CHUNK_SIZE_KEY: &str = "chunkSize";
const SIZE_KEY: &str = "size";
const LINKS_KEY: &str = "links";

/// An assembled content DAG: the version root block and the `contentCid` that
/// addresses it. The leaf blocks live in the [`SealedChunk`]s passed to
/// [`assemble`]; this is only the root the version metadata pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentDag {
    /// The version's `contentCid` (binary CIDv1, `dag-cbor` codec) — a BLAKE3
    /// digest over [`Self::root_block`]. A verified read of the root recomputes
    /// and fails closed on mismatch.
    pub content_cid: Vec<u8>,
    /// The deterministic det-CBOR root node bytes this CID addresses.
    pub root_block: Vec<u8>,
}

/// Assemble the ordered `leaves` into a version root addressed by its
/// `contentCid`. `plaintext_len` is the pre-seal byte length (the ranged-read
/// size bound). Deterministic: identical leaves + length + profile give a
/// byte-identical root block and CID.
///
/// Fails closed when the leaf count does not match [`decode_root`]'s
/// `ceil(size / chunkSize)`. Enforced in every build (not a release-compiled-out
/// `debug_assert`): a mis-wired caller must never emit a root this crate's own
/// [`decode_root`] would reject as `link count inconsistent with size`, which
/// would leave the published version permanently unreadable.
pub fn assemble(
    leaves: &[SealedChunk],
    plaintext_len: u64,
    profile: &ContentProfile,
) -> Result<ContentDag, DagError> {
    if leaves.len() as u64 != expected_leaf_count(plaintext_len, profile.chunk_size() as u64) {
        return Err(DagError::InvalidManifest {
            reason: "link count inconsistent with size",
        });
    }
    let links = leaves
        .iter()
        .map(|leaf| Value::Bytes(leaf.cid.clone()))
        .collect();
    let mut root = Map::new();
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
/// caller) into its manifest, fail-closed. Beyond the core-CBOR checks (a
/// non-canonical encoding, a missing or wrong-typed field), the manifest
/// invariants are enforced here so a `contentCid`-valid-but-inconsistent root is
/// rejected, not silently trusted: the chunk size must be nonzero, every leaf
/// link must be a well-formed `raw` content CID, and the link count must match
/// `ceil(size / chunkSize)` (an empty version is exactly one empty leaf).
pub fn decode_root(root_block: &[u8]) -> Result<RootManifest, DagError> {
    let root = decode(root_block)?;
    let map = root.as_map()?;
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
        return Err(DagError::InvalidManifest {
            reason: "zero chunk size",
        });
    }
    if !leaf_cids.iter().all(|cid| is_raw_leaf_cid(cid)) {
        return Err(DagError::InvalidManifest {
            reason: "malformed leaf cid",
        });
    }
    if leaf_cids.len() as u64 != expected_leaf_count(size, chunk_size) {
        return Err(DagError::InvalidManifest {
            reason: "link count inconsistent with size",
        });
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
fn expected_leaf_count(plaintext_len: u64, chunk_size: u64) -> u64 {
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

    fn framed(plaintext: &[u8], seed: u64) -> (Vec<SealedChunk>, ContentProfile) {
        let profile = ContentProfile::CI;
        let key = ContentKey::from_bytes([7u8; KEY_LEN]);
        let leaves =
            frame_and_seal(plaintext, &key, &mut SeededEntropy::new(seed), &profile).unwrap();
        (leaves, profile)
    }

    /// Hand-build a root block with arbitrary fields, bypassing `assemble`, to
    /// drive the fail-closed manifest checks.
    fn root_bytes(chunk_size: u64, size: u64, links: &[Vec<u8>]) -> Vec<u8> {
        let mut root = Map::new();
        root.insert(CHUNK_SIZE_KEY, Value::Unsigned(chunk_size));
        root.insert(SIZE_KEY, Value::Unsigned(size));
        root.insert(
            LINKS_KEY,
            Value::Array(links.iter().cloned().map(Value::Bytes).collect()),
        );
        encode(&Value::Map(root)).unwrap()
    }

    fn invalid_manifest_reason(block: &[u8]) -> &'static str {
        match decode_root(block) {
            Err(DagError::InvalidManifest { reason }) => reason,
            other => panic!("expected an InvalidManifest error, got {other:?}"),
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
        assert_eq!(
            manifest.leaf_cids,
            leaves.iter().map(|l| l.cid.clone()).collect::<Vec<_>>(),
            "links preserve file order"
        );
    }

    #[test]
    fn leaf_cids_use_the_raw_codec_root_uses_dag_cbor() {
        let (leaves, profile) = framed(b"abc", 5);
        let dag = assemble(&leaves, 3, &profile).unwrap();
        assert_eq!(leaves[0].cid[1], CONTENT_CID_CODEC, "leaf is raw");
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
            invalid_manifest_reason(&root_bytes(0, 0, &[])),
            "zero chunk size"
        );
    }

    #[test]
    fn decode_root_rejects_a_malformed_leaf_cid() {
        // chunkSize 16, size 16 => one leaf expected; the one link is not a CID.
        let block = root_bytes(16, 16, &[b"not-a-content-cid".to_vec()]);
        assert_eq!(invalid_manifest_reason(&block), "malformed leaf cid");
    }

    #[test]
    fn decode_root_rejects_a_link_count_size_mismatch() {
        // size 40 at chunkSize 16 expects 3 leaves; only one (valid) link given.
        let block = root_bytes(16, 40, &[compute_cid(CONTENT_CID_CODEC, b"x")]);
        assert_eq!(
            invalid_manifest_reason(&block),
            "link count inconsistent with size"
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

    /// `count` dummy leaves with 36-byte (`CONTENT_CID_LEN`) CIDs and empty
    /// sealed bytes, framed to match a `chunk_size`-16 profile — enough to size
    /// the root manifest without materializing any file bytes. `assemble` only
    /// reads `leaf.cid`, so the sealed payload can stay empty.
    fn dummy_leaves(count: usize) -> Vec<SealedChunk> {
        (0..count)
            .map(|_| SealedChunk {
                cid: vec![0u8; CONTENT_CID_LEN],
                sealed: Vec::new(),
            })
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
            Err(DagError::InvalidManifest {
                reason: "link count inconsistent with size",
            })
        );
    }
}
