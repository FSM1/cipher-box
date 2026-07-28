//! Ed25519 signing (blueprint/core.md "Crypto suite": pseudonym + record
//! signing). Deterministic by construction — no RNG — so seeds injected by the
//! [`crate::kdf`] catalog's Ed25519 edges yield reproducible keypairs.
//!
//! The structure-signature verify *policy* (fail-closed, whole-record) is the
//! engine's gate; this module ships only the pure primitive.

use core::fmt;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use super::secret::SECRET_LEN;

/// Length of an Ed25519 public key and of a signature's halves-combined form.
pub const PUBLIC_LEN: usize = 32;
/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// An Ed25519 signing key. Zeroizes on drop (dalek `zeroize` feature); `Debug`
/// is redacted so the seed never prints.
#[derive(Clone)]
pub struct Ed25519Signer(SigningKey);

/// An Ed25519 verifying (public) key. Public material.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ed25519Verifier(VerifyingKey);

/// A detached Ed25519 signature, stored in its canonical 64-byte form.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ed25519Signature([u8; SIGNATURE_LEN]);

impl Ed25519Signer {
    /// Derive the keypair from a 32-byte seed (dalek hashes it into the scalar
    /// and prefix internally — Ed25519's standard construction).
    pub fn from_seed(seed: [u8; SECRET_LEN]) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }

    /// The matching verifying key.
    pub fn verifying_key(&self) -> Ed25519Verifier {
        Ed25519Verifier(self.0.verifying_key())
    }

    /// Sign a message. Ed25519 is deterministic: the same key and message
    /// always produce the same signature.
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        Ed25519Signature(self.0.sign(message).to_bytes())
    }
}

impl fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ed25519Signer(redacted)")
    }
}

impl Ed25519Verifier {
    /// Parse a 32-byte public key. `None` when the bytes are not a valid
    /// compressed Edwards point.
    pub fn from_bytes(bytes: [u8; PUBLIC_LEN]) -> Option<Self> {
        VerifyingKey::from_bytes(&bytes).ok().map(Self)
    }

    /// The 32-byte public-key encoding.
    pub fn to_bytes(&self) -> [u8; PUBLIC_LEN] {
        self.0.to_bytes()
    }

    /// Verify a detached signature over `message`. Returns `true` on a valid
    /// signature; the fail-closed trust policy over this boolean lives in the
    /// engine.
    ///
    /// Uses dalek's **strict** verification: it rejects the S-malleability
    /// (`S` and `S + L` both satisfy cofactored verification) and small-order
    /// `A`/`R`, so each (key, message) has a single accepting signature. That
    /// non-malleability is required where signed structures/records may be
    /// compared or committed in a zero-knowledge store.
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> bool {
        let sig = ed25519_dalek::Signature::from_bytes(&signature.0);
        self.0.verify_strict(message, &sig).is_ok()
    }
}

impl fmt::Debug for Ed25519Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519Verifier({})", hex_lower(&self.to_bytes()))
    }
}

impl Ed25519Signature {
    /// Adopt a raw 64-byte signature.
    pub fn from_bytes(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw 64-byte encoding.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.0
    }
}

impl fmt::Debug for Ed25519Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519Signature({})", hex_lower(&self.0))
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).expect("nibble"));
        s.push(char::from_digit((b & 0xf) as u32, 16).expect("nibble"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_round_trip_and_determinism() {
        let signer = Ed25519Signer::from_seed([5u8; 32]);
        let vk = signer.verifying_key();
        let msg = b"cipherbox structure";
        let sig = signer.sign(msg);
        assert!(vk.verify(msg, &sig));
        // Deterministic.
        assert_eq!(signer.sign(msg), sig);
        // Wrong message fails.
        assert!(!vk.verify(b"tampered", &sig));
    }

    #[test]
    fn verifier_round_trips_bytes() {
        let vk = Ed25519Signer::from_seed([6u8; 32]).verifying_key();
        assert_eq!(Ed25519Verifier::from_bytes(vk.to_bytes()), Some(vk));
    }

    #[test]
    fn signer_debug_is_redacted() {
        let s = Ed25519Signer::from_seed([1u8; 32]);
        assert_eq!(format!("{s:?}"), "Ed25519Signer(redacted)");
    }
}
