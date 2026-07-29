//! The content profile — the frozen chunk-framing constant
//! (blueprint/engine.md "Content plane"; frozen by #820 and pinned by the
//! engine KAT).
//!
//! Chunk size is engine-owned per core.md's hand-off and, like the sync timing
//! profile, is injected rather than hardcoded at a call site: framing reads the
//! size from the profile handed in.

/// The content-plane framing profile (#630). Fixed-size chunking over a flat
/// DAG is the whole of the shape, frozen by #820.
///
/// There is deliberately **no `Default`** (mirrors [`crate::profile`]): every
/// construction site names its profile, and the chunk size is always a real,
/// nonzero value — the field is private and every constructor rejects zero, so
/// a zero chunk size (which would panic framing at `chunks(0)`) is
/// unrepresentable rather than a fail-late panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentProfile {
    /// Fixed content chunk size in bytes. Every leaf but the last carries
    /// exactly this many plaintext bytes, so a byte offset maps to a leaf index
    /// by integer division — the chunk-aligned property ranged block/CAR
    /// fetches rely on (blueprint/engine.md "shaped so ranged ... fetches map
    /// chunk-aligned"). Private with a nonzero invariant; read via
    /// [`ContentProfile::chunk_size`].
    chunk_size: usize,
}

impl ContentProfile {
    /// Shipped framing, frozen by #820: the **sealed leaf** is exactly 1 MiB.
    ///
    /// The 1 MiB budget belongs to the block, not the plaintext, because the
    /// ecosystem imposes its limits on blocks — so the plaintext chunk is
    /// 1 MiB less core's seal overhead (`nonce || ciphertext||tag`). Frozen in
    /// every published root and pinned by the engine KAT: changing it changes
    /// the wire format.
    pub const PRODUCTION: Self = Self {
        chunk_size: 1_048_536,
    };

    /// CI framing: 16-byte chunks so multi-chunk framing and DAG assembly are
    /// reachable from tiny fixtures (blueprint/testing.md "The DX hook").
    pub const CI: Self = Self { chunk_size: 16 };

    /// A custom profile with the given chunk size, or `None` for a zero size —
    /// the construction site that enforces the nonzero invariant.
    pub const fn new(chunk_size: usize) -> Option<Self> {
        if chunk_size == 0 {
            None
        } else {
            Some(Self { chunk_size })
        }
    }

    /// The fixed chunk size in bytes (always nonzero).
    pub const fn chunk_size(&self) -> usize {
        self.chunk_size
    }
}

#[cfg(test)]
// These tests assert on constants deliberately: the guard-rail that an edit to
// a profile value cannot drift silently past the blueprint's intent.
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::*;
    use cipherbox_core::content::seal_chunk;
    use cipherbox_core::suite::aead::{KEY_LEN, NONCE_LEN};

    #[test]
    fn a_production_chunk_seals_to_exactly_a_one_mib_block() {
        let plaintext = vec![0u8; ContentProfile::PRODUCTION.chunk_size()];
        let sealed = seal_chunk(&[0u8; KEY_LEN], &[0u8; NONCE_LEN], &plaintext);
        assert_eq!(
            sealed.len(),
            1 << 20,
            "the 1 MiB budget belongs to the block, not the plaintext"
        );
    }

    #[test]
    fn ci_chunk_size_keeps_multi_chunk_reachable() {
        assert!(
            ContentProfile::CI.chunk_size() <= 64,
            "CI chunk size must be small enough to exceed from a tiny fixture"
        );
    }

    #[test]
    fn every_profile_chunk_size_is_nonzero() {
        for profile in [ContentProfile::PRODUCTION, ContentProfile::CI] {
            assert!(
                profile.chunk_size() > 0,
                "chunk size is always real, never zero"
            );
        }
    }

    #[test]
    fn new_rejects_a_zero_chunk_size() {
        assert_eq!(ContentProfile::new(0), None, "zero is unrepresentable");
        assert_eq!(ContentProfile::new(4096).unwrap().chunk_size(), 4096);
    }
}
