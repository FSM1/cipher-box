//! Injected entropy — the engine's only randomness source.
//!
//! Entropy is an engine input to core's pure functions (blueprint/engine.md
//! "Host seams" notes; blueprint/core.md doctrine). It is deliberately *not*
//! one of the eight host seams: production wiring is per-target `getrandom`,
//! owned by the engine's construction site, not host logic. It is still
//! injected — engine logic never calls an RNG directly — so tests substitute
//! the test kit's seeded source and every seed and nonce becomes reproducible.

// The fresh-draw helpers below are where the raw seam draw is made and checked;
// `clippy.toml`'s `disallowed_methods` policy gates every other site.
#![allow(clippy::disallowed_methods)]

use core::cell::RefCell;
use core::fmt;

use cipherbox_core::suite::aead::NONCE_LEN;
use cipherbox_core::suite::secret::SECRET_LEN;

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

/// A source of entropy for key seeds and nonces.
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

/// A shared [`Entropy`] cell as an [`Entropy`] source that re-borrows per draw.
///
/// The engine holds one source behind a [`RefCell`] shared with every spawned
/// loop, and an async port that takes `&mut E` would otherwise hold the `RefMut`
/// across each `.await` — a panic the moment a loop, or a seam the port itself
/// drives, drew from the same cell.
pub(crate) struct SharedEntropy<'a, E: ?Sized>(pub &'a RefCell<E>);

impl<E: Entropy + ?Sized> Entropy for SharedEntropy<'_, E> {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        self.0.borrow_mut().fill(dest)
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

/// A fresh key seed, or a closed failure.
///
/// Same refusal as [`fresh_ephemeral`]: a seed anyone can guess is a key anyone
/// can re-derive, for every edge the KDF tree grows from it.
pub fn fresh_seed<E: Entropy + ?Sized>(
    entropy: &mut E,
) -> Result<Zeroizing<[u8; SECRET_LEN]>, EntropyError> {
    let mut seed = Zeroizing::new([0u8; SECRET_LEN]);
    entropy.fill(seed.as_mut_slice())?;
    if seed.iter().all(|byte| *byte == 0) {
        return Err(EntropyError::new("entropy seam produced an all-zero seed"));
    }
    Ok(seed)
}

/// A fresh AEAD nonce, or a closed failure.
///
/// Same refusal as [`fresh_ephemeral`], for the sharper reason: a seam that
/// reports success having written nothing seals every body under one fixed
/// nonce, and two seals under one key at one nonce is a confidentiality break.
pub fn fresh_nonce<E: Entropy + ?Sized>(entropy: &mut E) -> Result<[u8; NONCE_LEN], EntropyError> {
    fresh_bytes(entropy, "nonce")
}

/// A fresh non-key draw of `N` bytes, or a closed failure.
///
/// The same refusal as [`fresh_ephemeral`], for values that are neither keys nor
/// seeds and so want no [`Zeroizing`]. `what` names the draw in the error.
///
/// The refusal covers an untouched zero buffer only, not a seam stuck on one
/// non-zero value — no single draw can tell those apart.
pub fn fresh_bytes<const N: usize, E: Entropy + ?Sized>(
    entropy: &mut E,
    what: &str,
) -> Result<[u8; N], EntropyError> {
    let mut drawn = [0u8; N];
    entropy.fill(&mut drawn)?;
    if drawn.iter().all(|byte| *byte == 0) {
        return Err(EntropyError::new(format!(
            "entropy seam produced an all-zero {what}"
        )));
    }
    Ok(drawn)
}

#[cfg(test)]
mod fresh_draw_tests {
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
        assert!(fresh_nonce(&mut Silent).is_err());
        assert!(fresh_seed(&mut Silent).is_err());
    }

    #[test]
    fn a_failing_seam_propagates() {
        // The seam's own message, not merely an error: a local rejection would
        // pass an `is_err()` while swallowing what the seam actually said.
        assert_eq!(
            fresh_ephemeral(&mut Broken)
                .expect_err("the seam failure propagates")
                .message(),
            "no entropy",
        );
        assert_eq!(
            fresh_nonce(&mut Broken)
                .expect_err("the seam failure propagates")
                .message(),
            "no entropy",
        );
        assert_eq!(
            fresh_seed(&mut Broken)
                .expect_err("the seam failure propagates")
                .message(),
            "no entropy",
        );
    }

    #[test]
    fn a_real_seam_yields_nonzero_bytes() {
        let mut seeded = crate::testkit::SeededEntropy::new(4);
        let ephemeral = fresh_ephemeral(&mut seeded).expect("fresh");
        assert!(ephemeral.iter().any(|byte| *byte != 0));
        assert!(
            fresh_nonce(&mut seeded)
                .expect("fresh")
                .iter()
                .any(|b| *b != 0)
        );
        assert!(
            fresh_seed(&mut seeded)
                .expect("fresh")
                .iter()
                .any(|b| *b != 0)
        );
    }
}
