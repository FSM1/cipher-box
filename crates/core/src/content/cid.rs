//! The content-DAG CID codec (blueprint/core.md "Open edges"; AGENTS.md rules
//! 4-5: content-address codecs live in core, one KAT set).
//!
//! The deterministic CIDv1 content address of a content blob, computed beside
//! the in-core name codec ([`crate::ipns::name`], which likewise hand-assembles
//! a fixed CIDv1 byte prefix). The digest is the frozen suite hash BLAKE3-256
//! ([`crate::suite::hash::hash`]) — no content hash lives outside the suite
//! (AGENTS.md rule 4) — so the CID is byte-identical on native and wasm32.
//!
//! CIDv1 layout — all four framing bytes are single-byte multicodec varints, so
//! the CID is a fixed 4-byte prefix followed by the digest:
//!
//! | byte   | meaning                                                     |
//! | ------ | ----------------------------------------------------------- |
//! | `0x01` | CID version 1                                               |
//! | codec  | multicodec — `raw` (0x55) for a leaf, engine-chosen at root |
//! | `0x1e` | multihash `blake3` (the frozen suite hash)                  |
//! | `0x20` | multihash digest length = 32                                |
//! | …      | 32-byte BLAKE3 digest of `bytes`                            |
//!
//! Core addresses *leaf* sealed chunks as `raw` ([`CONTENT_CID_CODEC`]). The
//! version's `contentCid` is a DAG **root** (engine.md:473-474) whose codec —
//! `dag-pb`/`dag-cbor` — is engine-owned (#630, engine.md:497 open edge), so the
//! codec is a parameter here, not a constant. Core must verify that root CID on
//! every block/CAR response (engine.md:468); [`verify_cid`] therefore keys off
//! the claimed CID's *own* codec byte, validating both a raw leaf and a DAG root
//! while the version, multihash, and length framing stay fixed and fail-closed.

use crate::error::{CodecError, TrustViolation};
use crate::suite::hash::hash;
use crate::suite::secret::SECRET_LEN;

/// CIDv1 version byte (version 1).
const CID_VERSION: u8 = 0x01;

/// Byte offset of the multicodec within the CIDv1 framing.
const CID_CODEC_INDEX: usize = 1;

/// The leaf (raw, 0x55) multicodec: core content-addresses each opaque sealed
/// chunk as raw bytes. The DAG-root `contentCid` codec is engine-owned (#630,
/// engine.md:497), passed to [`compute_cid`] by the engine — not fixed here.
pub const CONTENT_CID_CODEC: u8 = 0x55;

/// Multihash code for BLAKE3-256 (0x1e) — the frozen suite hash
/// ([`crate::suite::hash::hash`]).
pub const CONTENT_CID_MULTIHASH: u8 = 0x1e;

/// The multihash digest width: the suite BLAKE3 hash output, `SECRET_LEN`
/// (32 bytes). Tied to the suite so a hash-width change is a compile-time break.
const DIGEST_LEN: usize = SECRET_LEN;

/// Number of fixed framing bytes preceding the digest (version||codec||mh||len).
const CID_PREFIX_LEN: usize = 4;

/// Total CIDv1 byte length: the 4-byte prefix plus the 32-byte digest.
pub const CONTENT_CID_LEN: usize = CID_PREFIX_LEN + DIGEST_LEN;

/// Compute the content CID (binary CIDv1) of `bytes` under multicodec `codec`.
/// Leaf sealed chunks pass [`CONTENT_CID_CODEC`] (`raw`); the engine passes the
/// DAG-root codec for a version's `contentCid` (#630). Deterministic and
/// byte-identical across native and wasm32; a public content address, so no key
/// material flows through here.
pub fn compute_cid(codec: u8, bytes: &[u8]) -> Vec<u8> {
    let digest = hash(bytes);
    let mut cid = Vec::with_capacity(CONTENT_CID_LEN);
    cid.extend_from_slice(&[CID_VERSION, codec, CONTENT_CID_MULTIHASH, DIGEST_LEN as u8]);
    cid.extend_from_slice(&digest);
    cid
}

/// Verify that `bytes` content-addresses to `claimed_cid`, fail-closed. The
/// codec is read from `claimed_cid` itself (#630 owns the DAG-root codec,
/// engine.md:497), so a raw leaf and a DAG-root `contentCid` both verify while
/// the version, multihash code, digest length, and digest are recomputed and
/// compared byte-for-byte. A malformed/truncated/foreign claimed CID, a wrong
/// multihash code, or a digest mismatch is [`TrustViolation::ContentCidMismatch`],
/// never mere staleness. The comparison is over a public content address (no
/// secret), so ordinary equality is used.
pub fn verify_cid(claimed_cid: &[u8], bytes: &[u8]) -> Result<(), CodecError> {
    if claimed_cid.len() == CONTENT_CID_LEN
        && compute_cid(claimed_cid[CID_CODEC_INDEX], bytes) == claimed_cid
    {
        Ok(())
    } else {
        Err(TrustViolation::ContentCidMismatch.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cid_shape_is_the_frozen_prefix_plus_digest() {
        let cid = compute_cid(CONTENT_CID_CODEC, b"sealed bytes");
        assert_eq!(cid.len(), CONTENT_CID_LEN);
        assert_eq!(
            &cid[..4],
            &[CID_VERSION, CONTENT_CID_CODEC, CONTENT_CID_MULTIHASH, 0x20],
            "version||raw||blake3||len prefix"
        );
        assert_eq!(&cid[4..], &hash(b"sealed bytes"), "suite BLAKE3 digest");
    }

    #[test]
    fn compute_cid_carries_the_caller_codec() {
        // The DAG-root codec (dag-cbor 0x71) is engine-chosen (#630): only the
        // codec byte moves; version/multihash/len/digest stay frozen.
        let cid = compute_cid(0x71, b"dag root bytes");
        assert_eq!(cid[CID_CODEC_INDEX], 0x71, "codec byte is the parameter");
        assert_eq!(
            &cid[..4],
            &[CID_VERSION, 0x71, CONTENT_CID_MULTIHASH, 0x20],
            "v1||dag-cbor||blake3||len prefix"
        );
        assert_eq!(&cid[4..], &hash(b"dag root bytes"), "suite BLAKE3 digest");
        // Same bytes, different codec → distinct CID, identical digest tail.
        let raw = compute_cid(CONTENT_CID_CODEC, b"dag root bytes");
        assert_ne!(cid, raw, "codec separates the CID");
        assert_eq!(&cid[4..], &raw[4..], "digest is codec-independent");
    }

    #[test]
    fn cid_is_deterministic_and_content_separated() {
        assert_eq!(
            compute_cid(CONTENT_CID_CODEC, b"a"),
            compute_cid(CONTENT_CID_CODEC, b"a"),
            "deterministic"
        );
        assert_ne!(
            compute_cid(CONTENT_CID_CODEC, b"a"),
            compute_cid(CONTENT_CID_CODEC, b"b"),
            "distinct bytes"
        );
    }

    #[test]
    fn verify_accepts_the_matching_raw_leaf_cid() {
        let bytes = b"the sealed content blob";
        let cid = compute_cid(CONTENT_CID_CODEC, bytes);
        assert!(verify_cid(&cid, bytes).is_ok());
    }

    #[test]
    fn verify_accepts_a_dag_root_cid_off_its_own_codec() {
        // A non-raw (dag-cbor) DAG-root CID must verify — core keys off the
        // claimed CID's codec byte, not a hardcoded raw prefix (engine.md:468).
        let bytes = b"the assembled dag root node";
        let cid = compute_cid(0x71, bytes);
        assert_ne!(cid[CID_CODEC_INDEX], CONTENT_CID_CODEC, "non-raw codec");
        assert!(verify_cid(&cid, bytes).is_ok());
    }

    #[test]
    fn verify_rejects_mismatched_bytes_fail_closed() {
        let cid = compute_cid(CONTENT_CID_CODEC, b"original");
        assert_eq!(
            verify_cid(&cid, b"tampered").unwrap_err().check(),
            "content-cid-mismatch"
        );
    }

    #[test]
    fn verify_rejects_a_wrong_multihash_code_fail_closed() {
        let bytes = b"content";
        let mut cid = compute_cid(CONTENT_CID_CODEC, bytes);
        cid[2] ^= 0xff; // corrupt the multihash-code byte, digest still matches
        assert_eq!(
            verify_cid(&cid, bytes).unwrap_err().check(),
            "content-cid-mismatch"
        );
    }

    #[test]
    fn verify_rejects_a_truncated_or_foreign_claimed_cid() {
        let bytes = b"content";
        let cid = compute_cid(CONTENT_CID_CODEC, bytes);
        assert_eq!(
            verify_cid(&cid[..cid.len() - 1], bytes)
                .unwrap_err()
                .check(),
            "content-cid-mismatch"
        );
        assert_eq!(
            verify_cid(b"not a cid", bytes).unwrap_err().check(),
            "content-cid-mismatch"
        );
    }
}
