//! Injected entropy — the engine's only randomness source.
//!
//! Entropy is an engine input to core's pure functions (blueprint/engine.md
//! "Host seams" notes; blueprint/core.md doctrine). It is deliberately *not*
//! one of the nine host seams: production wiring is per-target `getrandom`,
//! owned by the engine's construction site, not host logic. It is still
//! injected — engine logic never calls an RNG directly — so tests substitute
//! the test kit's seeded source and every seed, jitter, and nonce becomes
//! reproducible.

/// A source of entropy for key seeds, nonces, and timer jitter.
///
/// Production implementations must be cryptographically secure
/// (per-target `getrandom`). The test kit's `SeededEntropy` is
/// deterministic and test-only.
pub trait Entropy {
    /// Fills `dest` entirely with entropy bytes.
    fn fill(&mut self, dest: &mut [u8]);
}
