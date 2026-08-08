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

use zeroize::Zeroizing;

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

/// The engine holds its source boxed so one instance is shared with every
/// spawned loop; this lets that box satisfy the generic bound the content
/// plane's pure framing takes.
impl<E: Entropy + ?Sized> Entropy for Box<E> {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        (**self).fill(dest)
    }
}

/// A fresh 32-byte HPKE ephemeral scalar, or a closed failure.
///
/// Reuse across two seals under one recipient key is a confidentiality break, so
/// a seam that reports success having written nothing is refused here rather
/// than at each seal site.
pub fn fresh_ephemeral<E: Entropy + ?Sized>(
    entropy: &mut E,
) -> Result<Zeroizing<[u8; 32]>, EntropyError> {
    let mut ephemeral = Zeroizing::new([0u8; 32]);
    entropy.fill(ephemeral.as_mut_slice())?;
    if ephemeral.iter().all(|byte| *byte == 0) {
        return Err(EntropyError::new(
            "entropy seam produced an all-zero HPKE ephemeral",
        ));
    }
    Ok(ephemeral)
}

#[cfg(test)]
mod fresh_ephemeral_tests {
    use super::*;

    struct Silent;

    impl Entropy for Silent {
        fn fill(&mut self, _dest: &mut [u8]) -> Result<(), EntropyError> {
            Ok(())
        }
    }

    struct Broken;

    impl Entropy for Broken {
        fn fill(&mut self, _dest: &mut [u8]) -> Result<(), EntropyError> {
            Err(EntropyError::new("no entropy"))
        }
    }

    #[test]
    fn a_seam_that_writes_nothing_is_refused() {
        assert!(fresh_ephemeral(&mut Silent).is_err());
    }

    #[test]
    fn a_failing_seam_propagates() {
        assert!(fresh_ephemeral(&mut Broken).is_err());
    }

    #[test]
    fn a_real_seam_yields_nonzero_bytes() {
        let mut seeded = crate::testkit::SeededEntropy::new(4);
        let ephemeral = fresh_ephemeral(&mut seeded).expect("fresh");
        assert!(ephemeral.iter().any(|byte| *byte != 0));
    }
}
