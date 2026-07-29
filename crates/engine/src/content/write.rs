//! The streaming framer behind a facade write handle: the client slices the
//! file and feeds chunks, the engine seals and stages each one, and the op is
//! journaled once at commit (blueprint/engine.md "Content plane"; #815).
//!
//! Peak plaintext held is one chunk however much a caller pushes at once —
//! [`ContentWriter::push`] copies only up to the chunk boundary and hands the
//! rest back — so a multi-gigabyte file never has to fit in the wasm heap. The
//! sealed leaf a push yields is the caller's to stage and drop; the writer keeps
//! only its content address.

use zeroize::Zeroizing;

use super::chunk::{ContentKey, SealedChunk, seal_one_chunk};
use super::dag::{ContentDag, assemble};
use super::profile::ContentProfile;
use super::{SealError, SealedContent};
use crate::entropy::{Entropy, EntropyError};

/// One version's framing state: the fresh per-version content key, the
/// partial chunk still being filled, and the leaf addresses framed so far.
pub struct ContentWriter {
    key: ContentKey,
    profile: ContentProfile,
    /// Plaintext awaiting a full chunk — never longer than one chunk, and
    /// zeroized on drop (it is user content at rest in memory).
    pending: Zeroizing<Vec<u8>>,
    leaf_cids: Vec<Vec<u8>>,
    observed: u64,
}

/// What [`ContentWriter::finish`] produced: the version's published identity,
/// the root block to stage, the last leaf when the framing had a tail, and the
/// content key the caller must now seal into the op.
pub struct FinishedContent {
    /// The version's `contentCid` and plaintext length — one value, so the
    /// published `Version` cannot disagree with its own manifest.
    pub content: SealedContent,
    /// The DAG root block, staged under [`SealedContent::content_cid`].
    pub root_block: Vec<u8>,
    /// The final leaf, `None` when the plaintext was an exact multiple of the
    /// chunk size and every leaf already left through [`ContentWriter::push`].
    pub tail: Option<SealedChunk>,
    /// The per-version content key. Returned rather than dropped: it is a KDF
    /// non-edge and unrecoverable, so the commit path seals it into the op
    /// before the staged bytes become unopenable.
    pub key: ContentKey,
}

impl ContentWriter {
    /// Start framing a version under a freshly minted content key.
    pub fn new(key: ContentKey, profile: ContentProfile) -> Self {
        Self {
            key,
            profile,
            pending: Zeroizing::new(Vec::with_capacity(profile.chunk_size())),
            leaf_cids: Vec::new(),
            observed: 0,
        }
    }

    /// Absorb the head of `bytes` up to the chunk boundary, sealing a leaf if
    /// that completed one. Returns the bytes not yet absorbed, so a caller
    /// loops until the slice is empty; every iteration either seals a leaf or
    /// empties the slice, so the loop always makes progress.
    pub fn push<'a>(
        &mut self,
        bytes: &'a [u8],
        entropy: &mut impl Entropy,
    ) -> Result<(&'a [u8], Option<SealedChunk>), EntropyError> {
        let room = self.profile.chunk_size() - self.pending.len();
        let take = room.min(bytes.len());
        self.pending.extend_from_slice(&bytes[..take]);
        self.observed += take as u64;
        let leaf = if self.pending.len() == self.profile.chunk_size() {
            Some(self.seal_pending(entropy)?)
        } else {
            None
        };
        Ok((&bytes[take..], leaf))
    }

    /// Total plaintext absorbed so far — the observed size the commit
    /// cross-checks against the declaration (#830).
    pub fn observed_size(&self) -> u64 {
        self.observed
    }

    /// The leaves framed so far, in file order — the staging keys an abandoned
    /// write must release.
    pub fn staged_leaf_cids(&self) -> &[Vec<u8>] {
        &self.leaf_cids
    }

    /// Seal the tail and assemble the root. An empty version frames to exactly
    /// one empty leaf, so every version has at least one addressable block.
    pub fn finish(mut self, entropy: &mut impl Entropy) -> Result<FinishedContent, SealError> {
        let tail = if self.pending.is_empty() && !self.leaf_cids.is_empty() {
            None
        } else {
            Some(self.seal_pending(entropy)?)
        };
        let ContentDag {
            content_cid,
            root_block,
        } = assemble(&self.leaf_cids, self.observed, &self.profile)?;
        Ok(FinishedContent {
            content: SealedContent::new(content_cid, self.observed, self.leaf_cids),
            root_block,
            tail,
            key: self.key,
        })
    }

    /// Seal whatever `pending` holds as the next leaf and record its address.
    fn seal_pending(&mut self, entropy: &mut impl Entropy) -> Result<SealedChunk, EntropyError> {
        let leaf = seal_one_chunk(&self.key, &self.pending, entropy)?;
        self.pending.clear();
        self.leaf_cids.push(leaf.cid.clone());
        Ok(leaf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::{decode_root, frame_and_seal};
    use crate::testkit::SeededEntropy;
    use cipherbox_core::content::{open_chunk, verify_cid};
    use cipherbox_core::suite::aead::KEY_LEN;

    /// Feed `plaintext` in `stride`-byte pushes, returning every sealed block in
    /// file order (leaves then root) plus the finish result.
    fn stream(plaintext: &[u8], stride: usize, seed: u64) -> (Vec<SealedChunk>, FinishedContent) {
        let mut entropy = SeededEntropy::new(seed);
        let key = ContentKey::from_bytes([7u8; KEY_LEN]);
        let mut writer = ContentWriter::new(key, ContentProfile::CI);
        let mut leaves = Vec::new();
        for piece in plaintext.chunks(stride.max(1)) {
            let mut rest = piece;
            loop {
                let (remaining, leaf) = writer.push(rest, &mut entropy).unwrap();
                if let Some(leaf) = leaf {
                    leaves.push(leaf);
                }
                if remaining.is_empty() {
                    break;
                }
                rest = remaining;
            }
        }
        let finished = writer.finish(&mut entropy).unwrap();
        if let Some(tail) = finished.tail.clone() {
            leaves.push(tail);
        }
        (leaves, finished)
    }

    #[test]
    fn a_streamed_version_matches_the_one_shot_framing_byte_for_byte() {
        // The stream and the batch framer draw nonces from the same seeded
        // entropy in the same order, so the sealed blocks must be identical —
        // the streaming path changes memory shape, never the wire format.
        let plaintext: Vec<u8> = (0..40u8).collect();
        let key = ContentKey::from_bytes([7u8; KEY_LEN]);
        let batch = frame_and_seal(
            &plaintext,
            &key,
            &mut SeededEntropy::new(1),
            &ContentProfile::CI,
        )
        .unwrap();
        let (streamed, _) = stream(&plaintext, 7, 1);
        assert_eq!(streamed, batch);
    }

    #[test]
    fn the_push_stride_does_not_change_the_framing() {
        let plaintext: Vec<u8> = (0..100u8).collect();
        let reference = stream(&plaintext, 1, 3).1.content;
        for stride in [2usize, 5, 16, 17, 64, 1000] {
            assert_eq!(
                stream(&plaintext, stride, 3).1.content.content_cid(),
                reference.content_cid(),
                "stride {stride} framed differently"
            );
        }
    }

    #[test]
    fn every_leaf_verifies_and_reassembles_to_the_plaintext() {
        let plaintext: Vec<u8> = (0..100u8).collect();
        let (leaves, finished) = stream(&plaintext, 9, 5);
        let manifest = decode_root(&finished.root_block).unwrap();
        assert_eq!(manifest.size, plaintext.len() as u64);
        assert_eq!(manifest.leaf_cids, finished.content.leaf_cids());

        let mut recovered = Vec::new();
        for (leaf, cid) in leaves.iter().zip(&manifest.leaf_cids) {
            assert!(verify_cid(cid, &leaf.sealed).is_ok());
            recovered.extend(open_chunk(finished.key.as_bytes(), &leaf.sealed).unwrap());
        }
        assert_eq!(recovered, plaintext);
        assert!(verify_cid(finished.content.content_cid(), &finished.root_block).is_ok());
    }

    #[test]
    fn an_exact_multiple_has_no_trailing_empty_leaf() {
        let plaintext = vec![9u8; 32]; // exactly two CI chunks
        let (leaves, finished) = stream(&plaintext, 32, 7);
        assert!(
            finished.tail.is_none(),
            "the last push already sealed the final leaf"
        );
        assert_eq!(leaves.len(), 2);
        assert_eq!(finished.content.leaf_cids().len(), 2);
    }

    #[test]
    fn an_empty_version_frames_to_one_empty_leaf() {
        let (leaves, finished) = stream(b"", 1, 11);
        assert_eq!(leaves.len(), 1);
        assert_eq!(finished.content.size(), 0);
        assert_eq!(
            open_chunk(finished.key.as_bytes(), &leaves[0].sealed).unwrap(),
            b""
        );
    }

    #[test]
    fn the_observed_size_is_the_sum_of_the_pushes() {
        let mut entropy = SeededEntropy::new(13);
        let mut writer =
            ContentWriter::new(ContentKey::from_bytes([1u8; KEY_LEN]), ContentProfile::CI);
        assert_eq!(writer.observed_size(), 0);
        let mut rest: &[u8] = &[0u8; 37];
        while !rest.is_empty() {
            let (remaining, _) = writer.push(rest, &mut entropy).unwrap();
            rest = remaining;
        }
        assert_eq!(writer.observed_size(), 37);
    }
}
