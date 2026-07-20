//! The one owning type for 32-byte secret key material.
//!
//! Blueprint/core.md "Crypto suite": key material lives in `Zeroizing` owning
//! types — type-enforced, never comment-enforced. [`SecretBytes`] is that type
//! for the KDF catalog's seeds and symmetric keys: it zeroizes on drop and its
//! `Debug` is redacted, so key bytes never linger past drop nor leak through a
//! derived `Debug` (critical security rule: never Debug-print key material).

use core::fmt;

use zeroize::Zeroize;

/// The length of every seed and symmetric key in the catalog.
pub const SECRET_LEN: usize = 32;

/// Owned 32-byte secret key material. Cloneable (derivation reuses seeds), but
/// deliberately not `PartialEq` (no timing-variable equality on secrets) and
/// not `Copy` (an owning type with a `Drop` that zeroizes).
#[derive(Clone)]
pub struct SecretBytes([u8; SECRET_LEN]);

impl SecretBytes {
    /// Take ownership of raw key bytes.
    pub fn new(bytes: [u8; SECRET_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes. Callers that hand these to a signer/AEAD are the
    /// terminal owners of the copy they make; this borrow never transfers the
    /// zeroization responsibility.
    pub fn as_bytes(&self) -> &[u8; SECRET_LEN] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(redacted)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = SecretBytes::new([0xab; SECRET_LEN]);
        assert_eq!(format!("{s:?}"), "SecretBytes(redacted)");
        assert!(!format!("{s:?}").contains("ab"));
    }

    #[test]
    fn as_bytes_round_trips() {
        let raw = [7u8; SECRET_LEN];
        assert_eq!(SecretBytes::new(raw).as_bytes(), &raw);
    }
}
