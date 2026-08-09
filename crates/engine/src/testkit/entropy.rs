//! Seeded, deterministic entropy for tests.

use crate::entropy::{Entropy, EntropyError};

/// Deterministic entropy from a 64-bit seed (SplitMix64 stream).
///
/// **Test-only, not cryptographic.** Same seed, same byte stream — every
/// engine-minted seed and nonce becomes reproducible, which
/// is the point (determinism is injected, blueprint/testing.md law 3).
pub struct SeededEntropy {
    state: u64,
}

impl SeededEntropy {
    /// A deterministic entropy stream for `seed`.
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// The first 32-byte draw off `seed` — what a primitive that mints one seed
    /// before anything else gets, so a test can name every derived value.
    pub fn first_draw(seed: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        Self::new(seed).fill(&mut out).expect("infallible");
        out
    }

    fn next_u64(&mut self) -> u64 {
        // SplitMix64: tiny, well-distributed, dependency-free.
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

impl Entropy for SeededEntropy {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_stream() {
        let mut a = SeededEntropy::new(7);
        let mut b = SeededEntropy::new(7);
        let (mut buf_a, mut buf_b) = ([0u8; 33], [0u8; 33]);
        a.fill(&mut buf_a).expect("seeded entropy never fails");
        b.fill(&mut buf_b).expect("seeded entropy never fails");
        assert_eq!(buf_a, buf_b);
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = SeededEntropy::new(1);
        let mut b = SeededEntropy::new(2);
        let (mut buf_a, mut buf_b) = ([0u8; 32], [0u8; 32]);
        a.fill(&mut buf_a).expect("seeded entropy never fails");
        b.fill(&mut buf_b).expect("seeded entropy never fails");
        assert_ne!(buf_a, buf_b);
    }

    #[test]
    fn fills_non_multiple_of_eight_lengths() {
        let mut e = SeededEntropy::new(9);
        let mut buf = [0u8; 5];
        e.fill(&mut buf).expect("seeded entropy never fails");
        assert_ne!(buf, [0u8; 5], "five bytes should be written");
    }
}
