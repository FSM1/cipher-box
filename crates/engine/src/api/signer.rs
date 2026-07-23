//! Challenge-signature signing for identity login.
//!
//! Login is engine-native (blueprint/engine.md "API client"): the engine holds
//! the secp256k1 identity key and signs the server-issued challenge. All crypto
//! lives in `crates/core` (security rule 4) — [`IdentityChallengeSigner`] is a
//! thin adapter over [`cipherbox_core::suite::ecdsa`]; the engine only
//! hex-encodes the public key and signature for the wire.

use cipherbox_core::suite::ecdsa::EcdsaSigner;

use crate::hex::hex_lower;

/// Produces the two hex fields the `/auth/challenge` + `/auth/login` flow
/// needs: the identity public key and a signature over a challenge string.
///
/// An abstraction rather than a concrete type so the [`super::ApiClient`] stays
/// crypto-free and testable with a stub, while the production implementation
/// ([`IdentityChallengeSigner`]) routes through core.
pub trait ChallengeSigner {
    /// The identity public key as the API's `publicKey` field: compressed
    /// SEC1, lowercase hex (66 chars, `02`/`03` prefix).
    fn public_key_hex(&self) -> String;

    /// A signature over `sha256(utf8(challenge))` as the API's `signature`
    /// field: the compact `r || s` form, lowercase hex (128 chars).
    fn sign_challenge(&self, challenge: &str) -> String;
}

/// The production [`ChallengeSigner`]: a secp256k1 identity key held in the
/// engine, signing through core's RFC 6979 deterministic ECDSA.
///
/// `sign_detcbor` hashes its input with SHA-256 before signing, which is
/// exactly the API's `sha256(utf8(challenge))` verification input, so signing
/// the raw challenge bytes here matches the server verbatim.
pub struct IdentityChallengeSigner {
    signer: EcdsaSigner,
}

impl IdentityChallengeSigner {
    /// Adopts a 32-byte scalar as the identity signing key. `None` when the
    /// scalar is zero or not below the group order (core's validation).
    pub fn from_scalar(scalar: &[u8; 32]) -> Option<Self> {
        EcdsaSigner::from_scalar(scalar).map(|signer| Self { signer })
    }

    /// Adopts the session's already-derived identity signer, so cold-start
    /// login reuses the derived key instead of re-reading the raw login secret.
    pub fn from_signer(signer: EcdsaSigner) -> Self {
        Self { signer }
    }
}

impl ChallengeSigner for IdentityChallengeSigner {
    fn public_key_hex(&self) -> String {
        hex_lower(&self.signer.verifying_key().to_sec1())
    }

    fn sign_challenge(&self, challenge: &str) -> String {
        hex_lower(&self.signer.sign_detcbor(challenge.as_bytes()).to_compact())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> IdentityChallengeSigner {
        IdentityChallengeSigner::from_scalar(&[0x11; 32]).expect("valid scalar")
    }

    #[test]
    fn public_key_is_compressed_lowercase_hex() {
        let pk = signer().public_key_hex();
        assert_eq!(pk.len(), 66, "compressed SEC1 is 33 bytes");
        assert!(
            pk.starts_with("02") || pk.starts_with("03"),
            "compressed prefix"
        );
        assert_eq!(pk, pk.to_lowercase(), "lowercase hex");
    }

    #[test]
    fn signature_is_compact_lowercase_hex_and_deterministic() {
        let s = signer();
        let sig = s.sign_challenge("cipherbox-login:v2:deadbeef");
        assert_eq!(sig.len(), 128, "compact r||s is 64 bytes");
        assert_eq!(sig, sig.to_lowercase(), "lowercase hex");
        // RFC 6979 determinism: same key + challenge => same signature.
        assert_eq!(s.sign_challenge("cipherbox-login:v2:deadbeef"), sig);
        // A different challenge produces a different signature.
        assert_ne!(s.sign_challenge("cipherbox-login:v2:0000"), sig);
    }

    #[test]
    fn zero_scalar_is_rejected() {
        assert!(IdentityChallengeSigner::from_scalar(&[0u8; 32]).is_none());
    }
}
