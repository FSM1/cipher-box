//! X25519 keys and ECDH (blueprint/core.md "Crypto suite": pairwise secrets;
//! HPKE's KEM builds on the same primitive in [`super::hpke`]).
//!
//! Secrets are stored in `x25519_dalek::StaticSecret`, which zeroizes on drop
//! (its `zeroize` feature is enabled and it exposes no `Debug`); [`X25519Secret`]
//! adds a redacted `Debug` for defence in depth. Scalars are constructed from
//! injected bytes — the catalog's `enc-subkey` / `ascent-keypair` edges — never
//! from an internal RNG.

use core::fmt;

use x25519_dalek::{PublicKey, StaticSecret};

use super::secret::{SECRET_LEN, SecretBytes};

/// An X25519 secret scalar. Dalek clamps it on use, so any 32 injected bytes
/// are a valid secret.
#[derive(Clone)]
pub struct X25519Secret(StaticSecret);

/// An X25519 public key (Montgomery u-coordinate). Public material; freely
/// `Debug`/`Clone`/`Eq`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct X25519Public(PublicKey);

impl X25519Secret {
    /// Adopt an injected 32-byte scalar as the secret.
    pub fn from_scalar(scalar: [u8; SECRET_LEN]) -> Self {
        Self(StaticSecret::from(scalar))
    }

    /// The matching public key.
    pub fn public(&self) -> X25519Public {
        X25519Public(PublicKey::from(&self.0))
    }

    /// X25519 ECDH shared secret with `peer`. The result is key material, so
    /// it comes back in the zeroizing owning type.
    pub fn diffie_hellman(&self, peer: &X25519Public) -> SecretBytes {
        SecretBytes::new(self.0.diffie_hellman(&peer.0).to_bytes())
    }
}

impl fmt::Debug for X25519Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("X25519Secret(redacted)")
    }
}

impl X25519Public {
    /// Adopt a 32-byte public key. Every 32-byte string is a well-formed
    /// Montgomery u-coordinate (the curve performs no point validation here),
    /// so this is total.
    pub fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        Self(PublicKey::from(bytes))
    }

    /// The 32-byte encoding.
    pub fn to_bytes(&self) -> [u8; SECRET_LEN] {
        self.0.to_bytes()
    }
}

impl fmt::Debug for X25519Public {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "X25519Public({})", hex_lower(&self.to_bytes()))
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
    fn ecdh_is_symmetric_and_deterministic() {
        let a = X25519Secret::from_scalar([1u8; 32]);
        let b = X25519Secret::from_scalar([2u8; 32]);
        let ab = a.diffie_hellman(&b.public());
        let ba = b.diffie_hellman(&a.public());
        assert_eq!(ab.as_bytes(), ba.as_bytes(), "ECDH must be symmetric");
        // Deterministic: recomputing gives the same shared secret.
        let ab2 = a.diffie_hellman(&b.public());
        assert_eq!(ab.as_bytes(), ab2.as_bytes());
    }

    #[test]
    fn public_round_trips_and_debug_is_public() {
        let p = X25519Secret::from_scalar([3u8; 32]).public();
        assert_eq!(X25519Public::from_bytes(p.to_bytes()), p);
        // Public keys are not secret; Debug shows them.
        assert!(format!("{p:?}").starts_with("X25519Public("));
    }

    #[test]
    fn secret_debug_is_redacted() {
        let s = X25519Secret::from_scalar([9u8; 32]);
        assert_eq!(format!("{s:?}"), "X25519Secret(redacted)");
    }
}
