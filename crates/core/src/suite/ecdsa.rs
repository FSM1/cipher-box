//! secp256k1 ECDSA over det-CBOR (blueprint/core.md "Crypto suite": identity
//! signing — subkey binding, grant-set commitment, re-point object, mailbox
//! sender signature). Nonces are RFC 6979 deterministic (the `rfc6979` crate,
//! no RNG), and messages are hashed with SHA-256 before signing, so a fixed key
//! and message always produce the same signature.
//!
//! Signatures are the canonical 64-byte compact `r || s` form (low-S is what
//! the deterministic signer emits); the `sec1` compressed public key is 33
//! bytes. Both are frozen widths so the contact code stays ~130 bytes.

use core::fmt;

use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use super::secret::SECRET_LEN;

/// Length of a compressed secp256k1 public key (SEC1).
pub const IDENTITY_PUBLIC_LEN: usize = 33;
/// Length of a compact ECDSA signature (`r || s`).
pub const SIGNATURE_LEN: usize = 64;

/// A secp256k1 signing key. Zeroizes on drop (k256 zeroizes its scalar);
/// `Debug` is redacted.
#[derive(Clone)]
pub struct EcdsaSigner(SigningKey);

/// A secp256k1 verifying (public) key. Public material.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EcdsaVerifier(VerifyingKey);

/// A canonical compact ECDSA signature. Constructing one validates that
/// `r`/`s` are in range, so a stored value is always a well-formed signature.
#[derive(Clone, PartialEq, Eq)]
pub struct EcdsaSignature(Signature);

impl EcdsaSigner {
    /// Adopt a 32-byte scalar as the signing key. `None` when the scalar is
    /// zero or not below the group order.
    pub fn from_scalar(scalar: &[u8; SECRET_LEN]) -> Option<Self> {
        SigningKey::from_slice(scalar).ok().map(Self)
    }

    /// The matching verifying key.
    pub fn verifying_key(&self) -> EcdsaVerifier {
        EcdsaVerifier(*self.0.verifying_key())
    }

    /// Sign a det-CBOR message: RFC 6979 ECDSA over `SHA-256(message)`.
    pub fn sign_detcbor(&self, message: &[u8]) -> EcdsaSignature {
        let digest = Sha256::digest(message);
        let sig: Signature = self
            .0
            .sign_prehash(&digest)
            .expect("RFC 6979 signing over a 32-byte digest is infallible");
        EcdsaSignature(sig)
    }
}

impl fmt::Debug for EcdsaSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EcdsaSigner(redacted)")
    }
}

impl EcdsaVerifier {
    /// Parse a compressed SEC1 public key. `None` when the bytes are not a
    /// valid point on secp256k1.
    pub fn from_sec1(bytes: &[u8]) -> Option<Self> {
        VerifyingKey::from_sec1_bytes(bytes).ok().map(Self)
    }

    /// The 33-byte compressed SEC1 encoding.
    pub fn to_sec1(&self) -> [u8; IDENTITY_PUBLIC_LEN] {
        let point = self.0.to_encoded_point(true);
        let mut out = [0u8; IDENTITY_PUBLIC_LEN];
        out.copy_from_slice(point.as_bytes());
        out
    }

    /// Verify a det-CBOR signature: ECDSA verify over `SHA-256(message)`.
    pub fn verify_detcbor(&self, message: &[u8], signature: &EcdsaSignature) -> bool {
        let digest = Sha256::digest(message);
        self.0.verify_prehash(&digest, &signature.0).is_ok()
    }
}

impl fmt::Debug for EcdsaVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EcdsaVerifier({})", hex_lower(&self.to_sec1()))
    }
}

impl EcdsaSignature {
    /// Parse a compact signature. `None` when it is not exactly 64 bytes or
    /// `r`/`s` are out of range — the `invalid-binding-sig-encoding` gate.
    pub fn from_compact(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SIGNATURE_LEN {
            return None;
        }
        Signature::from_slice(bytes).ok().map(Self)
    }

    /// The 64-byte compact `r || s` encoding.
    pub fn to_compact(&self) -> [u8; SIGNATURE_LEN] {
        self.0.to_bytes().into()
    }
}

impl fmt::Debug for EcdsaSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EcdsaSignature({})", hex_lower(&self.to_compact()))
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

    fn signer() -> EcdsaSigner {
        // A fixed non-zero scalar below the group order.
        EcdsaSigner::from_scalar(&[0x11; 32]).expect("valid scalar")
    }

    #[test]
    fn sign_verify_round_trip_and_determinism() {
        let s = signer();
        let vk = s.verifying_key();
        let msg = b"det-cbor bytes";
        let sig = s.sign_detcbor(msg);
        assert!(vk.verify_detcbor(msg, &sig));
        // RFC 6979 determinism.
        assert_eq!(s.sign_detcbor(msg), sig);
        // Tampered message fails.
        assert!(!vk.verify_detcbor(b"other", &sig));
    }

    #[test]
    fn compact_signature_round_trips() {
        let sig = signer().sign_detcbor(b"x");
        let bytes = sig.to_compact();
        assert_eq!(EcdsaSignature::from_compact(&bytes), Some(sig));
    }

    #[test]
    fn public_key_round_trips_compressed() {
        let vk = signer().verifying_key();
        let sec1 = vk.to_sec1();
        assert_eq!(sec1.len(), IDENTITY_PUBLIC_LEN);
        assert_eq!(EcdsaVerifier::from_sec1(&sec1), Some(vk));
    }

    #[test]
    fn wrong_length_and_zero_signature_reject() {
        assert_eq!(EcdsaSignature::from_compact(&[0u8; 63]), None);
        // All-zero r||s is not a valid signature.
        assert_eq!(EcdsaSignature::from_compact(&[0u8; 64]), None);
    }

    #[test]
    fn signer_debug_is_redacted() {
        assert_eq!(format!("{:?}", signer()), "EcdsaSigner(redacted)");
    }
}
