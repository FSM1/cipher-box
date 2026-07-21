//! The content-DAG CID codec (blueprint/core.md "Open edges"; AGENTS.md rules
//! 4-5: content-address codecs live in core, one KAT set).
//!
//! The deterministic CIDv1 content address of a sealed content blob, computed
//! beside the in-core name codec ([`crate::ipns::name`], which likewise
//! hand-assembles a fixed CIDv1 byte prefix). The digest is the frozen suite
//! hash BLAKE3-256 ([`crate::suite::hash::hash`]) — no content hash lives
//! outside the suite (AGENTS.md rule 4) — so the CID is byte-identical on native
//! and wasm32.
//!
//! CIDv1 layout — all four framing bytes are single-byte multicodec varints, so
//! the CID is a fixed 4-byte prefix followed by the digest:
//!
//! | byte   | meaning                                                    |
//! | ------ | ---------------------------------------------------------- |
//! | `0x01` | CID version 1                                              |
//! | `0x55` | multicodec `raw` — core addresses the opaque sealed bytes  |
//! | `0x1e` | multihash `blake3` (the frozen suite hash)                 |
//! | `0x20` | multihash digest length = 32                               |
//! | …      | 32-byte BLAKE3 digest of the sealed bytes                  |
//!
//! `raw` (0x55) is the spec-faithful codec: the DAG assembly shape is
//! engine-owned (#630), so core sees an opaque sealed byte string — not a DAG it
//! can interpret — and addresses those bytes as raw leaf content. If #630 needs
//! intermediate DAG nodes under a structured codec, that is the engine's concern
//! above this primitive.

use crate::error::{CodecError, TrustViolation};
use crate::suite::hash::hash;
use crate::suite::secret::SECRET_LEN;

/// CIDv1 multicodec for the content plane: `raw` (0x55). See the module docs for
/// why raw is the spec-faithful choice over a DAG codec here.
pub const CONTENT_CID_CODEC: u8 = 0x55;

/// Multihash code for BLAKE3-256 (0x1e) — the frozen suite hash
/// ([`crate::suite::hash::hash`]).
pub const CONTENT_CID_MULTIHASH: u8 = 0x1e;

/// The multihash digest width: the suite BLAKE3 hash output, `SECRET_LEN`
/// (32 bytes). Tied to the suite so a hash-width change is a compile-time break.
const DIGEST_LEN: usize = SECRET_LEN;

/// The fixed CIDv1 byte prefix that precedes the digest.
const CID_PREFIX: [u8; 4] = [
    0x01,
    CONTENT_CID_CODEC,
    CONTENT_CID_MULTIHASH,
    DIGEST_LEN as u8,
];

/// Total CIDv1 byte length: the 4-byte prefix plus the 32-byte digest.
pub const CONTENT_CID_LEN: usize = CID_PREFIX.len() + DIGEST_LEN;

/// Compute the content CID (binary CIDv1) of `sealed` — the exact opaque bytes
/// stored on IPFS (`nonce || ciphertext||tag`). Deterministic and byte-identical
/// across native and wasm32; a public content address, so no key material flows
/// through here.
pub fn compute_cid(sealed: &[u8]) -> Vec<u8> {
    let digest = hash(sealed);
    let mut cid = Vec::with_capacity(CONTENT_CID_LEN);
    cid.extend_from_slice(&CID_PREFIX);
    cid.extend_from_slice(&digest);
    cid
}

/// Verify that `sealed` content-addresses to `claimed_cid`, fail-closed. Any
/// mismatch — tampered bytes or a wrong claimed CID — is
/// [`TrustViolation::ContentCidMismatch`], never mere staleness. The comparison
/// is over a public content address (no secret), so ordinary equality is used.
pub fn verify_cid(claimed_cid: &[u8], sealed: &[u8]) -> Result<(), CodecError> {
    if compute_cid(sealed) == claimed_cid {
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
        let cid = compute_cid(b"sealed bytes");
        assert_eq!(cid.len(), CONTENT_CID_LEN);
        assert_eq!(&cid[..4], &CID_PREFIX, "version||raw||blake3||len prefix");
        assert_eq!(&cid[4..], &hash(b"sealed bytes"), "suite BLAKE3 digest");
    }

    #[test]
    fn cid_is_deterministic_and_content_separated() {
        assert_eq!(compute_cid(b"a"), compute_cid(b"a"), "deterministic");
        assert_ne!(compute_cid(b"a"), compute_cid(b"b"), "distinct bytes");
    }

    #[test]
    fn verify_accepts_the_matching_cid() {
        let sealed = b"the sealed content blob";
        let cid = compute_cid(sealed);
        assert!(verify_cid(&cid, sealed).is_ok());
    }

    #[test]
    fn verify_rejects_mismatched_bytes_fail_closed() {
        let cid = compute_cid(b"original");
        assert_eq!(
            verify_cid(&cid, b"tampered").unwrap_err().check(),
            "content-cid-mismatch"
        );
    }

    #[test]
    fn verify_rejects_a_truncated_or_foreign_claimed_cid() {
        let sealed = b"content";
        let cid = compute_cid(sealed);
        assert_eq!(
            verify_cid(&cid[..cid.len() - 1], sealed)
                .unwrap_err()
                .check(),
            "content-cid-mismatch"
        );
        assert_eq!(
            verify_cid(b"not a cid", sealed).unwrap_err().check(),
            "content-cid-mismatch"
        );
    }
}
