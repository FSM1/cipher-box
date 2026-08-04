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
use crate::hex::lower as hex_lower;

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

    /// X25519 ECDH shared secret with `peer`. `None` when the exchange is
    /// **non-contributory** — the all-zero result a low-order `peer` forces
    /// (RFC 9180 §7.1.4). This is the exhaustive contributory backstop the
    /// KDF `blinded-tag` edge and HPKE decap rely on; a real shared secret is
    /// never all-zero, so it has no false positives. The result is key material,
    /// so it comes back in the zeroizing owning type.
    pub fn diffie_hellman(&self, peer: &X25519Public) -> Option<SecretBytes> {
        let shared = self.0.diffie_hellman(&peer.0);
        if !shared.was_contributory() {
            return None;
        }
        Some(SecretBytes::new(shared.to_bytes()))
    }
}

impl fmt::Debug for X25519Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("X25519Secret(redacted)")
    }
}

impl X25519Public {
    /// Adopt a 32-byte public key, **rejecting** the RFC 7748 small-order
    /// u-coordinates. Holding an `X25519Public` therefore means "not low-order",
    /// so [`super::hpke::dhkem_encap`] (seal) needs no separate check. This
    /// rejects the canonical chosen-key encodings up front, before contact
    /// import or decap; the exhaustive gate is the contributory check in
    /// [`Self::diffie_hellman`].
    pub fn from_bytes(bytes: [u8; SECRET_LEN]) -> Option<Self> {
        if is_small_order(&bytes) {
            return None;
        }
        Some(Self(PublicKey::from(bytes)))
    }

    /// The 32-byte encoding.
    pub fn to_bytes(&self) -> [u8; SECRET_LEN] {
        self.0.to_bytes()
    }
}

/// One p-form small-order u-coordinate: `first || 0xff×30 || 0x7f` (the p-1/p/p+1
/// encodings, high bit already clear).
const fn p_form(first: u8) -> [u8; 32] {
    let mut a = [0xff; 32];
    a[0] = first;
    a[31] = 0x7f;
    a
}

/// The RFC 7748 small-order u-coordinate encodings (the identity and every
/// order-2/4/8 point), in canonical + mod-p wraparound form, with the ignored
/// high bit cleared (libsodium's blacklist). A peer of order dividing 8 forces an
/// all-zero ECDH result; these are the encodings a chosen-key attacker uses.
const SMALL_ORDER_POINTS: [[u8; 32]; 7] = [
    [0u8; 32],
    {
        let mut a = [0u8; 32];
        a[0] = 1;
        a
    },
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    p_form(0xec),
    p_form(0xed),
    p_form(0xee),
];

/// Whether `bytes` encodes an X25519 point of order dividing 8. X25519 ignores
/// bit 255 of the u-coordinate, so it is masked before the table compare.
fn is_small_order(bytes: &[u8; SECRET_LEN]) -> bool {
    let mut masked = *bytes;
    masked[31] &= 0x7f;
    SMALL_ORDER_POINTS.contains(&masked)
}

/// Construct a public key **without** the low-order guard, so a test can drive
/// the ECDH contributory backstop against a point `from_bytes` refuses.
#[cfg(test)]
pub(crate) fn testonly_public_from_bytes(bytes: [u8; SECRET_LEN]) -> X25519Public {
    X25519Public(PublicKey::from(bytes))
}

impl fmt::Debug for X25519Public {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "X25519Public({})", hex_lower(&self.to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdh_is_symmetric_and_deterministic() {
        let a = X25519Secret::from_scalar([1u8; 32]);
        let b = X25519Secret::from_scalar([2u8; 32]);
        let ab = a.diffie_hellman(&b.public()).expect("contributory");
        let ba = b.diffie_hellman(&a.public()).expect("contributory");
        assert_eq!(ab.as_bytes(), ba.as_bytes(), "ECDH must be symmetric");
        // Deterministic: recomputing gives the same shared secret.
        let ab2 = a.diffie_hellman(&b.public()).expect("contributory");
        assert_eq!(ab.as_bytes(), ab2.as_bytes());
    }

    #[test]
    fn public_round_trips_and_debug_is_public() {
        let p = X25519Secret::from_scalar([3u8; 32]).public();
        assert_eq!(X25519Public::from_bytes(p.to_bytes()), Some(p));
        // Public keys are not secret; Debug shows them.
        assert!(format!("{p:?}").starts_with("X25519Public("));
    }

    #[test]
    fn rfc7748_low_order_points_are_rejected() {
        // The canonical RFC 7748 small-order u-coordinates (identity and the
        // order-2/4/8 points) plus their ignored-high-bit variants must all be
        // rejected by the constructor and, defensively, by ECDH.
        let low_order: [[u8; 32]; 7] = [
            [0u8; 32],
            {
                let mut a = [0u8; 32];
                a[0] = 1;
                a
            },
            hex32("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
            hex32("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
            hex32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            hex32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            hex32("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ];
        let probe = X25519Secret::from_scalar([7u8; 32]);
        for enc in low_order {
            assert_eq!(X25519Public::from_bytes(enc), None, "canonical low-order");
            // The same encoding with the ignored high bit set is also rejected.
            let mut high = enc;
            high[31] |= 0x80;
            assert_eq!(X25519Public::from_bytes(high), None, "high-bit variant");
            // Backstop: `from_bytes` guards the encoding, so drive the peer
            // through dalek's total `PublicKey` to reach the ECDH check.
            let peer = crate::suite::x25519::testonly_public_from_bytes(enc);
            assert!(probe.diffie_hellman(&peer).is_none(), "non-contributory");
        }
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut a = [0u8; 32];
        for (i, byte) in a.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex");
        }
        a
    }

    #[test]
    fn secret_debug_is_redacted() {
        let s = X25519Secret::from_scalar([9u8; 32]);
        assert_eq!(format!("{s:?}"), "X25519Secret(redacted)");
    }
}
