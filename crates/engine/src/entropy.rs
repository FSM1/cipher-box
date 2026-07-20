//! Injected entropy — the engine's only randomness source.
//!
//! Entropy is an engine input to core's pure functions (blueprint/engine.md
//! "Host seams" notes; blueprint/core.md doctrine). It is deliberately *not*
//! one of the nine host seams: production wiring is per-target `getrandom`,
//! owned by the engine's construction site, not host logic. It is still
//! injected — engine logic never calls an RNG directly — so tests substitute
//! the test kit's seeded source and every seed, jitter, and nonce becomes
//! reproducible.

use core::fmt;

/// Entropy acquisition failed.
///
/// Fail closed: the engine surfaces this as a typed error — it never
/// panics and never substitutes predictable bytes. The message is
/// diagnostic only and must never carry key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntropyError {
    message: String,
}

impl EntropyError {
    /// Builds an entropy error from a diagnostic message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The diagnostic message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for EntropyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "entropy error: {}", self.message)
    }
}

impl std::error::Error for EntropyError {}

/// A source of entropy for key seeds, nonces, and timer jitter.
///
/// Production implementations must be cryptographically secure
/// (per-target `getrandom`, whose acquisition is fallible — hence the
/// `Result`). The test kit's `SeededEntropy` is deterministic and
/// test-only.
pub trait Entropy {
    /// Fills `dest` entirely with entropy bytes, or fails closed.
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError>;
}
