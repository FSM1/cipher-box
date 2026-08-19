//! X25519 keys and ECDH (blueprint/core.md "Crypto suite": pairwise secrets;
//! HPKE's KEM builds on the same primitive in [`super::hpke`]).
//!
//! Secrets are stored in `x25519_dalek::StaticSecret`, which zeroizes on drop
//! (its `zeroize` feature is enabled and it exposes no `Debug`); [`X25519Secret`]
//! adds a redacted `Debug` for defence in depth. Scalars are constructed from
//! injected bytes — the catalog's `enc-subkey` / `ascent-keypair` edges — never
//! from an internal RNG.

use core::fmt;

use curve25519_dalek::montgomery::MontgomeryPoint;
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
    /// Adopt a 32-byte public key, rejecting anything that is not the canonical
    /// encoding of a prime-order point — see [`is_adoptable`] for why both
    /// halves are load-bearing. Holding an `X25519Public` therefore carries that
    /// invariant, so [`super::hpke::dhkem_encap`] (seal) needs no separate check
    /// and the contributory backstop in [`Self::diffie_hellman`] can never fire
    /// for a peer adopted here.
    pub fn from_bytes(bytes: [u8; SECRET_LEN]) -> Option<Self> {
        if !is_adoptable(&bytes) {
            return None;
        }
        Some(Self(PublicKey::from(bytes)))
    }

    /// The 32-byte encoding.
    pub fn to_bytes(&self) -> [u8; SECRET_LEN] {
        self.0.to_bytes()
    }
}

/// Whether `bytes` is the canonical encoding of a Curve25519 point of prime
/// order `l`. Both halves close the same attack: ECDH decides on the point,
/// HPKE binds the supplied bytes into `kem_context`, so anything that lets two
/// encodings share a point lets a sealed blob be addressed to a key whose real
/// holder can never open it.
///
/// - **Prime order.** The u-coordinate is lifted to Edwards — which rejects the
///   twist, where the birational map has no preimage — and the lift tested for a
///   torsion component. A small-order blacklist would not do: clamping makes the
///   scalar a multiple of 8, so every cofactor twin `P + t` (`t` in `E[8]`)
///   yields `P`'s shared secret, and the cheapest twin `1/u` is computable from
///   public data.
/// - **Canonical.** X25519 ignores bit 255 and reduces mod `p`, so several
///   distinct byte strings reach one point while `to_bytes` re-emits whichever
///   arrived. Re-encoding the lift and demanding the input back refuses them
///   all in one step.
///
/// The Edwards sign bit passed to the lift is arbitrary: `P` and `-P` share an
/// order, and `to_montgomery` discards the sign again.
fn is_adoptable(bytes: &[u8; SECRET_LEN]) -> bool {
    MontgomeryPoint(*bytes)
        .to_edwards(0)
        .is_some_and(|p| p.is_torsion_free() && p.to_montgomery().to_bytes() == *bytes)
}

/// Every cofactor twin `P + t` of `public`, for the seven non-identity `t` in
/// `E[8]`, in ascending byte order: distinct encodings of one cofactor class,
/// which each clamped X25519 exchange collapses back onto `P`. The fixture the
/// prime-order half of [`is_adoptable`] exists to refuse.
///
/// `#[doc(hidden)]`: `pub` only for the cross-crate tests and the `kat_gen`
/// example, not supported API.
#[doc(hidden)]
pub fn cofactor_twins(public: &X25519Public) -> [[u8; SECRET_LEN]; 7] {
    let lifted = MontgomeryPoint(public.to_bytes())
        .to_edwards(0)
        .expect("an adopted public key lifts to Edwards");
    let mut twins = [[0u8; SECRET_LEN]; 7];
    let mut found = 0;
    for torsion in curve25519_dalek::constants::EIGHT_TORSION.iter() {
        let twin = (lifted + torsion).to_montgomery().to_bytes();
        if twin != public.to_bytes() {
            twins[found] = twin;
            found += 1;
        }
    }
    assert_eq!(found, 7, "E[8] has seven non-identity points");
    // Sorted, so a caller picking one twin picks it lexicographically rather
    // than by `EIGHT_TORSION`'s array order — the KAT vectors bake these bytes in.
    twins.sort_unstable();
    twins
}

/// Construct a public key **without** the adoption guard, so a test can drive
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
    fn cofactor_twins_are_rejected_yet_share_the_shared_secret() {
        // Each twin is on-curve, not low-order, and drives the identical X25519
        // output — so neither the RFC 7748 blacklist nor the contributory
        // backstop can see it, while HPKE binds the key bytes and would seal to
        // something `honest`'s holder can never open.
        let honest = X25519Secret::from_scalar([0x5a; 32]).public();
        let peer = X25519Secret::from_scalar([0x6b; 32]);
        let honest_dh = peer.diffie_hellman(&honest).expect("contributory");

        for twin in cofactor_twins(&honest) {
            assert_eq!(X25519Public::from_bytes(twin), None, "twin must be refused");
            let dh = peer
                .diffie_hellman(&testonly_public_from_bytes(twin))
                .expect("a twin is not low-order");
            assert_eq!(dh.as_bytes(), honest_dh.as_bytes());
        }
    }

    #[test]
    fn no_second_encoding_of_an_accepted_key_is_ever_accepted() {
        // The canonical half of the gate. X25519 ignores bit 255 and reduces mod
        // p, so a point has more than one spelling; each one re-derives the
        // honest key's blinded tag while `to_bytes` re-emits whichever arrived,
        // which is what `kem_context` then binds.
        let honest = X25519Secret::from_scalar([0x5a; 32]).public();
        let mut high_bit = honest.to_bytes();
        high_bit[31] |= 0x80;

        for enc in cofactor_twins(&honest).into_iter().chain([high_bit]) {
            assert_ne!(enc, honest.to_bytes(), "a second encoding, not the key");
            assert_eq!(X25519Public::from_bytes(enc), None);
        }
    }

    #[test]
    fn a_mod_p_wraparound_encoding_is_rejected() {
        // The other canonical case, which needs `u < 19` to have a second
        // encoding below 2^255 at all: the basepoint `u = 9` is prime-order, and
        // `9 + p == 2^255 - 10` is its only other sub-2^255 spelling.
        let mut basepoint = [0u8; SECRET_LEN];
        basepoint[0] = 9;
        let mut wrapped = [0xffu8; SECRET_LEN];
        wrapped[0] = 0xf6;
        wrapped[31] = 0x7f;

        assert!(
            X25519Public::from_bytes(basepoint).is_some(),
            "the basepoint"
        );
        assert_eq!(
            X25519Public::from_bytes(wrapped),
            None,
            "u + p is not canonical"
        );

        // Invisible to the contributory backstop: both reach the same secret.
        let probe = X25519Secret::from_scalar([0x77; 32]);
        let via_wrapped = probe
            .diffie_hellman(&testonly_public_from_bytes(wrapped))
            .expect("contributory");
        let via_canonical = probe
            .diffie_hellman(&testonly_public_from_bytes(basepoint))
            .expect("contributory");
        assert_eq!(via_wrapped.as_bytes(), via_canonical.as_bytes());
    }

    #[test]
    fn every_derived_public_key_survives_its_own_decoder() {
        // Produce/decode symmetry: `X25519Secret::public()` is the one
        // constructor that skips `from_bytes`, so what it emits must always be
        // re-adoptable. Clamping is what guarantees it for any injected scalar.
        for seed in [0x00u8, 0x5a, 0xff] {
            let derived = X25519Secret::from_scalar([seed; 32]).public();
            assert_eq!(
                X25519Public::from_bytes(derived.to_bytes()),
                Some(derived),
                "a derived public key must survive its own decoder"
            );
        }
    }

    #[test]
    fn secret_debug_is_redacted() {
        let s = X25519Secret::from_scalar([9u8; 32]);
        assert_eq!(format!("{s:?}"), "X25519Secret(redacted)");
    }
}
