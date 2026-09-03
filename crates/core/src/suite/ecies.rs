//! ECIES over secp256k1 (blueprint/core.md "Crypto suite"), the one seal whose
//! recipient key is a bare curve point rather than a CipherBox identity: the
//! device-approval rendezvous relays a compressed secp256k1 ephemeral key and
//! the approver seals a fresh factor to it (FSM1/cipher-box-next ADR 0009 D3/D5).
//!
//! HPKE ([`super::hpke`]) cannot serve it: its KEM is DHKEM(X25519) and the
//! rendezvous key is secp256k1, fixed by the API's own field constraint.
//!
//! Construction: ECDH on secp256k1, then one BLAKE3 `derive_key` per output
//! over `shared_x || enc || recipient` for the AEAD key and the nonce, then
//! XChaCha20-Poly1305. Binding the whole transcript into both derivations is
//! what makes a substituted `enc` open nothing. This key schedule is internal
//! to the primitive, in the same class as HPKE's — not a KDF-catalog edge
//! (FSM1/cipher-box-next ADR 0015 D2).
//!
//! Determinism (blueprint/core.md "Doctrine"): the sender's ephemeral scalar is
//! an injected parameter, never sampled here.

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, SecretKey};
use zeroize::Zeroizing;

use super::aead;
use super::hash::derive_key;
use super::secret::SECRET_LEN;
use crate::error::TrustViolation;

/// Length of a compressed secp256k1 public key (SEC1), which is both the
/// recipient key width and the encapsulated-key width.
pub const ENC_LEN: usize = 33;

/// BLAKE3 `derive_key` contexts. Two distinct contexts over one transcript, so
/// the AEAD key and the nonce cannot collide. The KAT manifest freezes both
/// (FSM1/cipher-box-next ADR 0015 D3).
pub const KEY_CONTEXT: &str = "cipherbox/device-factor-seal/v1 aead-key";
pub const NONCE_CONTEXT: &str = "cipherbox/device-factor-seal/v1 aead-nonce";

/// The output of a single-shot seal: the encapsulated ephemeral public key and
/// the AEAD ciphertext (`ciphertext || tag`). `enc` travels with the ciphertext
/// because the recipient re-derives the whole key schedule from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EciesCiphertext {
    pub enc: [u8; ENC_LEN],
    pub ciphertext: Vec<u8>,
}

/// Whether `recipient` is a point [`ecies_seal`] can seal to: on the curve, in
/// canonical SEC1 form, and not the identity. Exposed so a caller can refuse a
/// relayed key before it reaches a screen rather than at the seal.
pub fn ecies_recipient_is_a_point(recipient: &[u8; ENC_LEN]) -> bool {
    PublicKey::from_sec1_bytes(recipient).is_ok()
}

/// The compressed public key of `scalar`. `None` when the scalar is not a
/// valid secp256k1 scalar.
pub fn ecies_public_key(scalar: &[u8; SECRET_LEN]) -> Option<[u8; ENC_LEN]> {
    Some(compressed(
        &SecretKey::from_slice(scalar).ok()?.public_key(),
    ))
}

/// Seal `plaintext` to the compressed secp256k1 `recipient`. `None` when
/// `recipient` is not a valid point or `ephemeral_scalar` is not a valid
/// secp256k1 scalar — the produce-side refusals that match what [`ecies_open`]
/// hard-rejects, so a release build can never emit an envelope its own opener
/// refuses.
///
/// # Security — ephemeral scalar uniqueness (caller invariant)
///
/// `ephemeral_scalar` **must be fresh, uniformly-random 32 bytes on every
/// call**, exactly as [`hpke_seal`](super::hpke::hpke_seal) requires: reuse
/// against the same recipient re-derives the identical AEAD key *and* nonce,
/// and XChaCha20-Poly1305 under a repeated pair is a catastrophic break. Core
/// samples no entropy, so the calling seam owns it.
pub fn ecies_seal(
    recipient: &[u8; ENC_LEN],
    ephemeral_scalar: &[u8; SECRET_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Option<EciesCiphertext> {
    let recipient_key = PublicKey::from_sec1_bytes(recipient).ok()?;
    let ephemeral = SecretKey::from_slice(ephemeral_scalar).ok()?;
    let enc = compressed(&ephemeral.public_key());
    let shared =
        k256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), recipient_key.as_affine());
    let (key, nonce) = schedule(shared.raw_secret_bytes(), &enc, recipient);
    Some(EciesCiphertext {
        enc,
        ciphertext: aead::encrypt(&key, &nonce, aad, plaintext),
    })
}

/// Open an envelope sealed to `recipient_scalar`.
///
/// A malformed scalar, a malformed `enc` and a tag that does not verify all
/// answer with the one [`TrustViolation::EciesOpenFailed`], so no caller learns
/// which part of a relayed envelope was wrong. A tag mismatch is tampering,
/// never a retryable error, which is why the class is trust and not malformed.
pub fn ecies_open(
    recipient_scalar: &[u8; SECRET_LEN],
    enc: &[u8; ENC_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, TrustViolation> {
    const REFUSED: TrustViolation = TrustViolation::EciesOpenFailed;
    let recipient = SecretKey::from_slice(recipient_scalar).map_err(|_| REFUSED)?;
    let sender = PublicKey::from_sec1_bytes(enc).map_err(|_| REFUSED)?;
    let shared = k256::ecdh::diffie_hellman(recipient.to_nonzero_scalar(), sender.as_affine());
    let (key, nonce) = schedule(
        shared.raw_secret_bytes(),
        enc,
        &compressed(&recipient.public_key()),
    );
    aead::decrypt(&key, &nonce, aad, ciphertext)
        .map(Zeroizing::new)
        .ok_or(REFUSED)
}

/// The AEAD key and nonce for one envelope, both bound to the full transcript.
/// The key comes back zeroizing; the nonce is not secret.
fn schedule(
    shared_x: &[u8],
    enc: &[u8; ENC_LEN],
    recipient: &[u8; ENC_LEN],
) -> (Zeroizing<[u8; aead::KEY_LEN]>, [u8; aead::NONCE_LEN]) {
    let mut transcript = Zeroizing::new(Vec::with_capacity(shared_x.len() + 2 * ENC_LEN));
    transcript.extend_from_slice(shared_x);
    transcript.extend_from_slice(enc);
    transcript.extend_from_slice(recipient);
    let key = Zeroizing::new(*derive_key(KEY_CONTEXT, &transcript).as_bytes());
    let nonce_material = Zeroizing::new(*derive_key(NONCE_CONTEXT, &transcript).as_bytes());
    let mut nonce = [0u8; aead::NONCE_LEN];
    nonce.copy_from_slice(&nonce_material[..aead::NONCE_LEN]);
    (key, nonce)
}

fn compressed(key: &PublicKey) -> [u8; ENC_LEN] {
    let mut out = [0u8; ENC_LEN];
    out.copy_from_slice(key.to_encoded_point(true).as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid secp256k1 scalar for a test recipient or sender.
    fn scalar(byte: u8) -> [u8; SECRET_LEN] {
        [byte; SECRET_LEN]
    }

    fn recipient_public(scalar: &[u8; SECRET_LEN]) -> [u8; ENC_LEN] {
        ecies_public_key(scalar).expect("a valid scalar")
    }

    #[test]
    fn a_public_key_needs_a_scalar_inside_the_group() {
        assert!(ecies_public_key(&[0u8; SECRET_LEN]).is_none());
        assert!(ecies_public_key(&[0xffu8; SECRET_LEN]).is_none());
    }

    #[test]
    fn round_trips_under_the_matching_scalar() {
        let secret = scalar(7);
        let public = recipient_public(&secret);
        let sealed = ecies_seal(&public, &scalar(9), b"request-1", b"factor").expect("seal");
        assert_eq!(sealed.enc.len(), ENC_LEN);
        assert_eq!(
            ecies_open(&secret, &sealed.enc, b"request-1", &sealed.ciphertext)
                .expect("open")
                .as_slice(),
            b"factor"
        );
    }

    #[test]
    fn a_different_aad_fails_closed() {
        let secret = scalar(7);
        let sealed = ecies_seal(
            &recipient_public(&secret),
            &scalar(9),
            b"request-1",
            b"factor",
        )
        .expect("seal");
        assert!(ecies_open(&secret, &sealed.enc, b"request-2", &sealed.ciphertext).is_err());
    }

    #[test]
    fn a_substituted_enc_opens_nothing() {
        let secret = scalar(7);
        let sealed =
            ecies_seal(&recipient_public(&secret), &scalar(9), b"aad", b"factor").expect("seal");
        let other = ecies_seal(&recipient_public(&secret), &scalar(11), b"aad", b"factor")
            .expect("seal")
            .enc;
        assert!(ecies_open(&secret, &other, b"aad", &sealed.ciphertext).is_err());
    }

    #[test]
    fn another_recipient_opens_nothing() {
        let sealed =
            ecies_seal(&recipient_public(&scalar(7)), &scalar(9), b"aad", b"factor").expect("seal");
        assert!(ecies_open(&scalar(8), &sealed.enc, b"aad", &sealed.ciphertext).is_err());
    }

    /// The produce side refuses what the open side hard-rejects, in a release
    /// build: an off-curve recipient never reaches an envelope.
    #[test]
    fn seal_refuses_a_recipient_that_is_not_a_point() {
        let mut bogus = recipient_public(&scalar(7));
        bogus[0] = 0x04;
        assert!(ecies_seal(&bogus, &scalar(9), b"aad", b"factor").is_none());
        assert!(ecies_seal(&[0u8; ENC_LEN], &scalar(9), b"aad", b"factor").is_none());
    }

    #[test]
    fn seal_refuses_a_scalar_outside_the_group() {
        let public = recipient_public(&scalar(7));
        assert!(ecies_seal(&public, &[0u8; SECRET_LEN], b"aad", b"factor").is_none());
        assert!(ecies_seal(&public, &[0xffu8; SECRET_LEN], b"aad", b"factor").is_none());
    }

    /// Shorter than a tag: refused by the same one verdict, with no panic and
    /// no separate class a caller could distinguish.
    #[test]
    fn open_refuses_a_ciphertext_shorter_than_its_tag() {
        let secret = scalar(7);
        let sealed =
            ecies_seal(&recipient_public(&secret), &scalar(9), b"aad", b"factor").expect("seal");
        for short in [0usize, 1, aead::TAG_LEN - 1] {
            assert_eq!(
                ecies_open(&secret, &sealed.enc, b"aad", &sealed.ciphertext[..short]),
                Err(TrustViolation::EciesOpenFailed)
            );
        }
    }

    #[test]
    fn open_refuses_a_scalar_outside_the_group() {
        let secret = scalar(7);
        let sealed =
            ecies_seal(&recipient_public(&secret), &scalar(9), b"aad", b"factor").expect("seal");
        assert!(ecies_open(&[0u8; SECRET_LEN], &sealed.enc, b"aad", &sealed.ciphertext).is_err());
    }
}
