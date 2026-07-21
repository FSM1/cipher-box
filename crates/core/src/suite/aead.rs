//! XChaCha20-Poly1305 AEAD primitive (blueprint/core.md "Crypto suite":
//! symmetric sealing, 24-byte nonce).
//!
//! This is the raw AEAD only — the CipherBox seal/unseal layer (structured AAD
//! construction, the `cipherbox/v2` domain separator, envelope framing) is a
//! later slice and is deliberately *not* here. HPKE ([`super::hpke`]) composes
//! this primitive under a per-message derived key and nonce.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

/// XChaCha20-Poly1305 key length.
pub const KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce length (the extended 24-byte nonce).
pub const NONCE_LEN: usize = 24;
/// Poly1305 authentication tag length, appended to the ciphertext.
pub const TAG_LEN: usize = 16;

/// The largest single-message plaintext XChaCha20-Poly1305 can seal:
/// `64 * (2^32 - 1)` bytes (≈256 GiB), the ChaCha20 32-bit block-counter limit.
///
/// # Security — plaintext length (caller invariant)
///
/// [`encrypt`] treats sealing as **infallible** and would panic on a single
/// message strictly longer than this. Core exports the raw AEAD over
/// caller-framed chunks (the engine frames content well below this, at 1 MiB),
/// so the framing seam owns the ceiling — the same caller-invariant class as the
/// per-call ephemeral-scalar uniqueness [`hpke_seal`](super::hpke::hpke_seal)
/// documents. A `u64` keeps the constant representable on the 32-bit WASM leg,
/// where the value exceeds `usize::MAX`.
pub const MAX_PLAINTEXT_LEN: u64 = 64 * ((1u64 << 32) - 1);

/// Seal `plaintext` under `key`/`nonce` with additional authenticated data
/// `aad`. Returns `ciphertext || tag`. Infallible for in-memory inputs (the
/// AEAD only errors above [`MAX_PLAINTEXT_LEN`], which no caller reaches here).
pub fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption is infallible for in-memory inputs")
}

/// Open `ciphertext` (`ciphertext || tag`) under `key`/`nonce`/`aad`. `None`
/// when the authentication tag does not verify — the caller maps that to its
/// fail-closed error (never a silent degrade).
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_with_aad() {
        let key = [1u8; KEY_LEN];
        let nonce = [2u8; NONCE_LEN];
        let ct = encrypt(&key, &nonce, b"aad", b"hello");
        assert_eq!(ct.len(), 5 + TAG_LEN);
        assert_eq!(
            decrypt(&key, &nonce, b"aad", &ct).as_deref(),
            Some(&b"hello"[..])
        );
    }

    #[test]
    fn wrong_aad_fails_closed() {
        let key = [1u8; KEY_LEN];
        let nonce = [2u8; NONCE_LEN];
        let ct = encrypt(&key, &nonce, b"aad", b"hello");
        assert_eq!(decrypt(&key, &nonce, b"other", &ct), None);
    }

    #[test]
    fn content_chunk_size_is_far_below_the_plaintext_ceiling() {
        // The engine frames content into 1 MiB chunks (crates/engine content
        // profile); that is orders of magnitude below the AEAD ceiling, so the
        // infallible `encrypt` contract holds for every framed chunk.
        let engine_chunk_size: u64 = 1 << 20;
        let ceiling = MAX_PLAINTEXT_LEN;
        assert!(engine_chunk_size.saturating_mul(1000) < ceiling);
        // Sanity-pin the ceiling itself: 64 * (2^32 - 1) bytes.
        assert_eq!(ceiling, 274_877_906_880);
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let key = [1u8; KEY_LEN];
        let nonce = [2u8; NONCE_LEN];
        let mut ct = encrypt(&key, &nonce, b"", b"hello");
        ct[0] ^= 0x01;
        assert_eq!(decrypt(&key, &nonce, b"", &ct), None);
    }
}
