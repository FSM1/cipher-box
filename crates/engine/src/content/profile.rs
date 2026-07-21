//! The content profile — the open-edge chunk-framing constant
//! (blueprint/engine.md "Content plane"; "Open edges": "Chunk size, DAG shape,
//! retention defaults ... freeze alongside the KAT manifest").
//!
//! Chunk size is engine-owned per core.md's hand-off and, like the sync timing
//! profile, is injected rather than hardcoded at a call site: framing reads the
//! size from the profile handed in, so a future measured value lands as one
//! profile-constant change.

/// The content-plane framing profile (#630). Fixed-size chunking is the whole
/// of the shape today; DAG fan-out/balancing stays flat (an open edge below).
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
    /// Shipped framing: 1 MiB chunks.
    ///
    /// A placeholder pending the measurement process in blueprint/testing.md
    /// ("The profile is where measured constants land"); it lands as a
    /// profile-constant change with its measurement linked, and the DAG fan-out
    /// open edge is settled alongside it.
    pub const PRODUCTION: Self = Self {
        chunk_size: 1 << 20,
    };

    /// CI framing: 16-byte chunks so multi-chunk framing and DAG assembly are
    /// reachable from tiny fixtures (blueprint/testing.md "The DX hook").
    pub const CI: Self = Self { chunk_size: 16 };

    /// A custom profile with the given chunk size, or `None` for a zero size.
    /// The nonzero invariant is enforced here so framing never divides or
    /// `chunks()` by zero — a zero chunk size is rejected at construction, not
    /// discovered as a panic during a seal.
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

    #[test]
    fn production_chunk_size_is_one_mib() {
        assert_eq!(ContentProfile::PRODUCTION.chunk_size(), 1 << 20);
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
