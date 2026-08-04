//! The one owning type for 32-byte secret key material.
//!
//! Blueprint/core.md "Crypto suite": key material lives in `Zeroizing` owning
//! types — type-enforced, never comment-enforced. [`SecretBytes`] is that type
//! for the KDF catalog's seeds and symmetric keys: it zeroizes on drop, its
//! `Debug` is redacted (critical security rule: never Debug-print key
//! material), and its equality is constant-time. A struct that holds its
//! secrets here inherits all three by deriving `Debug`/`PartialEq` — but a
//! derived struct `PartialEq` short-circuits **across** fields, so it stays a
//! round-trip comparator, not a security comparison.

use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// The length of every seed and symmetric key in the catalog.
pub const SECRET_LEN: usize = 32;

/// The escape hatch for secret material not yet held in [`SecretBytes`] —
/// prefer `==` on the owning type. Same guarantee: no data-dependent early
/// exit.
pub fn ct_eq(a: &[u8; SECRET_LEN], b: &[u8; SECRET_LEN]) -> bool {
    a.ct_eq(b).into()
}

/// Owned 32-byte secret key material. Cloneable (derivation reuses seeds), but
/// deliberately not `Copy` (an owning type with a `Drop` that zeroizes), and
/// deliberately neither `Hash` nor `Ord`: hashing key bytes into a std map
/// reintroduces the timing channel [`ct_eq`] removes.
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

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(&self.0, &other.0)
    }
}

impl Eq for SecretBytes {}

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

    #[test]
    fn equality_matches_the_raw_bytes() {
        let a = SecretBytes::new([7u8; SECRET_LEN]);
        assert_eq!(a, SecretBytes::new([7u8; SECRET_LEN]));
        // Reflexive over a clone: `Eq` must hold on a type whose `Drop` wipes.
        assert_eq!(a, a.clone());

        // Every single-byte difference, at every position, compares unequal.
        for index in 0..SECRET_LEN {
            let mut raw = [7u8; SECRET_LEN];
            raw[index] ^= 0x01;
            assert_ne!(a, SecretBytes::new(raw), "byte {index}");
            assert!(!ct_eq(a.as_bytes(), &raw), "byte {index}");
        }
    }
}
