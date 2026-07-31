//! Fixed-size chunk framing over core's content-seal, under a fresh random
//! per-version content key (blueprint/engine.md "Content plane").
//!
//! Framing is the engine's job; the seal and the leaf content-address are
//! core's ([`cipherbox_core::content`], #691). This module owns only the
//! split-into-fixed-chunks decision and the per-chunk nonce draw from injected
//! entropy — no crypto of its own (AGENTS.md rule 4).

use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid, seal_chunk};
use cipherbox_core::suite::aead::{KEY_LEN, NONCE_LEN, TAG_LEN};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::profile::ContentProfile;
use crate::entropy::{Entropy, EntropyError};

/// The sealed byte overhead one leaf adds to its plaintext chunk:
/// `nonce(24) || ciphertext || tag(16)`, with ciphertext length equal to
/// plaintext length. The staging admission ledger sizes a version from this, so
/// the reservation is the exact sealed total rather than an estimate (#828).
pub const SEALED_LEAF_OVERHEAD: u64 = (NONCE_LEN + TAG_LEN) as u64;

/// A fresh random per-version content key (blueprint/engine.md, #26 D6). The
/// terminal owner of the key bytes: zeroized on drop, borrowed (never copied)
/// by the seal, which must not zero it (the "zeroize at the terminal owner
/// only" rule). One key seals every chunk of a version; a new version mints a
/// new key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ContentKey([u8; KEY_LEN]);

impl ContentKey {
    /// Mint a fresh content key from injected entropy. Fails closed if entropy
    /// acquisition fails — never substitutes predictable bytes. The staging
    /// buffer self-zeroizes on every return path (incl. the error path, where
    /// it may hold partially-written key bytes).
    pub fn generate(entropy: &mut impl Entropy) -> Result<Self, EntropyError> {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        entropy.fill(bytes.as_mut())?;
        Ok(Self(*bytes))
    }

    /// Adopt caller-supplied key bytes (a restored per-version key). The array
    /// is caller-owned; callers holding secret material zeroize it themselves.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw key bytes for the seal. Borrowed, never taken — the seal
    /// leaves this buffer intact.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

// A key must never render its bytes to a log site (security rule 2).
impl core::fmt::Debug for ContentKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ContentKey(<redacted>)")
    }
}

/// One sealed leaf: its content-address and the sealed wire bytes that address
/// resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedChunk {
    /// The leaf content CID (binary CIDv1, `raw` codec) — a BLAKE3 digest over
    /// [`Self::sealed`]. The block's authenticity anchor: a verified read
    /// recomputes it and fails closed on mismatch.
    pub cid: Vec<u8>,
    /// The sealed wire blob `nonce(24) || ciphertext||tag` this CID addresses.
    pub sealed: Vec<u8>,
}

/// Frame `plaintext` into fixed-size chunks and seal each under `key`
/// (blueprint/engine.md "Content plane"). Every chunk but the last carries
/// exactly `profile.chunk_size` plaintext bytes; empty input frames to a single
/// empty leaf so every version has at least one addressable block.
///
/// Each chunk draws a fresh nonce from injected `entropy` — XChaCha20-Poly1305
/// nonce reuse under one key is a break, and the nonce is public (core prefixes
/// it into the sealed blob). Deterministic under a fixed key and a seeded
/// entropy stream: the leaf CIDs and sealed bytes are byte-identical run to run.
pub fn frame_and_seal(
    plaintext: &[u8],
    key: &ContentKey,
    entropy: &mut impl Entropy,
    profile: &ContentProfile,
) -> Result<Vec<SealedChunk>, EntropyError> {
    let framed: Vec<&[u8]> = if plaintext.is_empty() {
        vec![&[][..]]
    } else {
        plaintext.chunks(profile.chunk_size()).collect()
    };
    framed
        .into_iter()
        .map(|chunk| seal_one_chunk(key, chunk, entropy))
        .collect()
}

/// Seal one already-framed chunk under `key`, drawing its nonce from injected
/// `entropy`. The single seal step both the batch framer and the streaming
/// writer ([`super::write::ContentWriter`]) go through, so the two cannot
/// produce different bytes for the same chunk.
pub fn seal_one_chunk(
    key: &ContentKey,
    chunk: &[u8],
    entropy: &mut impl Entropy,
) -> Result<SealedChunk, EntropyError> {
    let mut nonce = [0u8; NONCE_LEN];
    entropy.fill(&mut nonce)?;
    let sealed = seal_chunk(key.as_bytes(), &nonce, chunk);
    let cid = compute_cid(CONTENT_CID_CODEC, &sealed);
    Ok(SealedChunk { cid, sealed })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::SeededEntropy;
    use cipherbox_core::content::{open_chunk, verify_cid};

    fn ci() -> ContentProfile {
        ContentProfile::CI
    }

    #[test]
    fn frames_into_chunk_sized_leaves_with_a_short_tail() {
        // 40 bytes at 16-byte chunks => 16 + 16 + 8.
        let plaintext: Vec<u8> = (0..40u8).collect();
        let key = ContentKey::from_bytes([7u8; KEY_LEN]);
        let mut entropy = SeededEntropy::new(1);
        let leaves = frame_and_seal(&plaintext, &key, &mut entropy, &ci()).unwrap();
        assert_eq!(leaves.len(), 3);

        // Every leaf verifies against its own CID and opens to the right slice.
        let mut recovered = Vec::new();
        for leaf in &leaves {
            assert!(verify_cid(&leaf.cid, &leaf.sealed).is_ok());
            recovered.extend(open_chunk(key.as_bytes(), &leaf.sealed).unwrap());
        }
        assert_eq!(recovered, plaintext, "chunks reassemble to the original");
    }

    /// The staging reservation is exact only while this constant is the real
    /// per-leaf overhead, so pin it against a sealed leaf rather than against a
    /// second copy of the wire layout's arithmetic.
    #[test]
    fn the_leaf_overhead_constant_matches_a_real_sealed_leaf() {
        let key = ContentKey::from_bytes([2u8; KEY_LEN]);
        for len in [0usize, 1, 13, 16] {
            let leaf =
                seal_one_chunk(&key, &vec![0xABu8; len], &mut SeededEntropy::new(4)).unwrap();
            assert_eq!(
                leaf.sealed.len() as u64,
                len as u64 + SEALED_LEAF_OVERHEAD,
                "{len}-byte chunk: the reservation must match the sealed layout"
            );
        }
    }

    #[test]
    fn empty_input_frames_to_one_empty_leaf() {
        let key = ContentKey::from_bytes([3u8; KEY_LEN]);
        let mut entropy = SeededEntropy::new(2);
        let leaves = frame_and_seal(b"", &key, &mut entropy, &ci()).unwrap();
        assert_eq!(
            leaves.len(),
            1,
            "empty version still has one addressable leaf"
        );
        assert_eq!(open_chunk(key.as_bytes(), &leaves[0].sealed).unwrap(), b"");
    }

    #[test]
    fn exact_multiple_has_no_trailing_empty_leaf() {
        let plaintext = vec![9u8; 32]; // exactly two 16-byte chunks
        let key = ContentKey::from_bytes([1u8; KEY_LEN]);
        let mut entropy = SeededEntropy::new(3);
        let leaves = frame_and_seal(&plaintext, &key, &mut entropy, &ci()).unwrap();
        assert_eq!(
            leaves.len(),
            2,
            "no phantom empty leaf on an exact multiple"
        );
    }

    #[test]
    fn deterministic_under_fixed_key_and_seeded_entropy() {
        let plaintext: Vec<u8> = (0..50u8).collect();
        let key = ContentKey::from_bytes([5u8; KEY_LEN]);
        let a = frame_and_seal(&plaintext, &key, &mut SeededEntropy::new(42), &ci()).unwrap();
        let b = frame_and_seal(&plaintext, &key, &mut SeededEntropy::new(42), &ci()).unwrap();
        assert_eq!(a, b, "same key + seed => byte-identical framing");
    }

    #[test]
    fn distinct_seeds_give_distinct_nonces_and_cids() {
        let plaintext = vec![0u8; 16];
        let key = ContentKey::from_bytes([5u8; KEY_LEN]);
        let a = frame_and_seal(&plaintext, &key, &mut SeededEntropy::new(1), &ci()).unwrap();
        let b = frame_and_seal(&plaintext, &key, &mut SeededEntropy::new(2), &ci()).unwrap();
        assert_ne!(
            a[0].cid, b[0].cid,
            "a fresh nonce changes the sealed bytes and CID"
        );
    }

    #[test]
    fn generate_produces_a_usable_key_and_redacts_debug() {
        let mut entropy = SeededEntropy::new(99);
        let key = ContentKey::generate(&mut entropy).unwrap();
        let sealed = frame_and_seal(b"payload", &key, &mut SeededEntropy::new(1), &ci()).unwrap();
        assert_eq!(
            open_chunk(key.as_bytes(), &sealed[0].sealed).unwrap(),
            b"payload"
        );
        assert_eq!(format!("{key:?}"), "ContentKey(<redacted>)");
    }

    #[test]
    fn generate_fails_closed_when_entropy_fails() {
        struct FailingEntropy;
        impl Entropy for FailingEntropy {
            fn fill(&mut self, _: &mut [u8]) -> Result<(), EntropyError> {
                Err(EntropyError::new("no entropy"))
            }
        }
        // The error path (where the staging buffer may hold partial key bytes and
        // the Zeroizing wrapper scrubs it on drop) returns Err, never a key.
        assert!(ContentKey::generate(&mut FailingEntropy).is_err());
    }
}
