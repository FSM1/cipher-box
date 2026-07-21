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

use cipherbox_core::codec::{Map, Value, decode, encode};
use cipherbox_core::content::compute_cid;
use cipherbox_core::error::{CodecError, Malformed};

use super::chunk::SealedChunk;
use super::profile::ContentProfile;

/// The multicodec of the DAG-root `contentCid`: `dag-cbor` (0x71). Engine-owned
/// (#630, engine.md:497) — core keeps the leaf `raw` codec but takes the root
/// codec as a parameter. Single-byte, inside core's frozen content-plane set.
pub const DAG_ROOT_CODEC: u8 = 0x71;

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
pub fn assemble(
    leaves: &[SealedChunk],
    plaintext_len: u64,
    profile: &ContentProfile,
) -> ContentDag {
    let links = leaves
        .iter()
        .map(|leaf| Value::Bytes(leaf.cid.clone()))
        .collect();
    let mut root = Map::new();
    root.insert(CHUNK_SIZE_KEY, Value::Unsigned(profile.chunk_size as u64));
    root.insert(SIZE_KEY, Value::Unsigned(plaintext_len));
    root.insert(LINKS_KEY, Value::Array(links));
    let root_block = encode(&Value::Map(root));
    let content_cid = compute_cid(DAG_ROOT_CODEC, &root_block);
    ContentDag {
        content_cid,
        root_block,
    }
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
/// caller) into its manifest. Fail-closed on a structurally invalid root: a
/// non-canonical encoding is a core [`CodecError`] surfaced verbatim; a missing
/// or wrong-typed field is [`Malformed`].
pub fn decode_root(root_block: &[u8]) -> Result<RootManifest, CodecError> {
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
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RootManifest {
        chunk_size,
        size,
        leaf_cids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::chunk::{ContentKey, frame_and_seal};
    use crate::testkit::SeededEntropy;
    use cipherbox_core::content::{CONTENT_CID_CODEC, verify_cid};
    use cipherbox_core::suite::aead::KEY_LEN;

    fn framed(plaintext: &[u8], seed: u64) -> (Vec<SealedChunk>, ContentProfile) {
        let profile = ContentProfile::CI;
        let key = ContentKey::from_bytes([7u8; KEY_LEN]);
        let leaves =
            frame_and_seal(plaintext, &key, &mut SeededEntropy::new(seed), &profile).unwrap();
        (leaves, profile)
    }

    #[test]
    fn root_content_addresses_to_its_content_cid() {
        let (leaves, profile) = framed(&(0..40u8).collect::<Vec<_>>(), 1);
        let dag = assemble(&leaves, 40, &profile);
        assert!(verify_cid(&dag.content_cid, &dag.root_block).is_ok());
        assert_eq!(
            dag.content_cid[1], DAG_ROOT_CODEC,
            "root CID carries dag-cbor"
        );
    }

    #[test]
    fn assembly_is_deterministic() {
        let (leaves, profile) = framed(&(0..40u8).collect::<Vec<_>>(), 7);
        let a = assemble(&leaves, 40, &profile);
        let b = assemble(&leaves, 40, &profile);
        assert_eq!(a, b, "same leaves + length => byte-identical root");
    }

    #[test]
    fn root_manifest_round_trips_the_ordered_leaf_cids() {
        let plaintext: Vec<u8> = (0..40u8).collect();
        let (leaves, profile) = framed(&plaintext, 3);
        let dag = assemble(&leaves, plaintext.len() as u64, &profile);

        let manifest = decode_root(&dag.root_block).unwrap();
        assert_eq!(manifest.chunk_size, profile.chunk_size as u64);
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
        let dag = assemble(&leaves, 3, &profile);
        assert_eq!(leaves[0].cid[1], CONTENT_CID_CODEC, "leaf is raw");
        assert_eq!(dag.content_cid[1], DAG_ROOT_CODEC, "root is dag-cbor");
    }

    #[test]
    fn decode_rejects_a_non_root_block_fail_closed() {
        // A valid det-CBOR value that is not the root map shape.
        let not_a_root = encode(&Value::Unsigned(7));
        assert!(decode_root(&not_a_root).is_err());
    }
}
