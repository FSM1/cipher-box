//! Content-seal: seal/open of caller-framed chunk bytes (blueprint/core.md
//! "Open edges": "core ships the content-seal primitive over caller-framed
//! chunks").
//!
//! A thin, deterministic wrapper over the frozen suite AEAD
//! ([`crate::suite::aead`], XChaCha20-Poly1305): the seal prefixes the
//! caller-injected 24-byte nonce so [`open_chunk`] can recover it, and the AEAD
//! authenticates it (a flipped nonce breaks the tag). The per-version content
//! key and the nonce are caller-supplied (KATs pin them; core samples no
//! entropy and reads no clock).
//!
//! No AAD is bound (chunk framing is engine-owned, and any index/order binding
//! would live there): a chunk's authenticity anchor is its `contentCid` — a
//! BLAKE3 digest over these sealed bytes ([`super::cid`]) that the metadata
//! read-body carries and the metadata envelope binds into its own AAD — so the
//! content plane inherits that binding transitively.

use crate::error::{CodecError, Malformed, TrustViolation};
use crate::suite::aead::{self, KEY_LEN, NONCE_LEN, TAG_LEN};

/// Seal one caller-framed chunk under `key`/`nonce`. Returns the wire blob
/// `nonce(24) || ciphertext||tag`.
///
/// `nonce` **must be unique for every seal performed under a given `key`** —
/// XChaCha20-Poly1305 nonce reuse under one key is a confidentiality and
/// integrity break (the content key is random per version; the caller sources a
/// fresh nonce per chunk from its injected entropy seam).
pub fn seal_chunk(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(NONCE_LEN + plaintext.len() + TAG_LEN);
    out.extend_from_slice(nonce);
    out.extend(aead::encrypt(key, nonce, &[], plaintext));
    out
}

/// Open a sealed chunk (`nonce(24) || ciphertext||tag`) under `key`. Returns the
/// recovered plaintext (the caller's to own and zeroize).
///
/// Fail-closed, two-class: a blob too short to hold the nonce and tag is
/// [`Malformed::Truncated`]; a tag that does not verify — tampered bytes or the
/// wrong content key — is [`TrustViolation::SealOpenFailed`], never a silent
/// degrade to staleness.
pub fn open_chunk(key: &[u8; KEY_LEN], sealed: &[u8]) -> Result<Vec<u8>, CodecError> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(Malformed::Truncated {
            offset: sealed.len(),
        }
        .into());
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let nonce: &[u8; NONCE_LEN] = nonce.try_into().expect("split_at NONCE_LEN");
    aead::decrypt(key, nonce, &[], ciphertext).ok_or_else(|| TrustViolation::SealOpenFailed.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let key = [7u8; KEY_LEN];
        let nonce = [9u8; NONCE_LEN];
        let sealed = seal_chunk(&key, &nonce, b"caller-framed chunk bytes");
        assert_eq!(&sealed[..NONCE_LEN], &nonce, "nonce is prefixed");
        assert_eq!(
            open_chunk(&key, &sealed).unwrap(),
            b"caller-framed chunk bytes"
        );
    }

    #[test]
    fn empty_chunk_round_trips() {
        let key = [1u8; KEY_LEN];
        let nonce = [2u8; NONCE_LEN];
        let sealed = seal_chunk(&key, &nonce, b"");
        assert_eq!(sealed.len(), NONCE_LEN + TAG_LEN, "nonce + tag floor");
        assert_eq!(open_chunk(&key, &sealed).unwrap(), b"");
    }

    #[test]
    fn deterministic_under_fixed_key_and_nonce() {
        let key = [3u8; KEY_LEN];
        let nonce = [4u8; NONCE_LEN];
        assert_eq!(
            seal_chunk(&key, &nonce, b"same"),
            seal_chunk(&key, &nonce, b"same"),
            "fixed key + nonce is deterministic"
        );
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let key = [5u8; KEY_LEN];
        let nonce = [6u8; NONCE_LEN];
        let mut sealed = seal_chunk(&key, &nonce, b"authentic");
        *sealed.last_mut().unwrap() ^= 0x01;
        assert_eq!(
            open_chunk(&key, &sealed).unwrap_err().check(),
            "seal-open-failed"
        );
    }

    #[test]
    fn wrong_key_fails_closed() {
        let nonce = [6u8; NONCE_LEN];
        let sealed = seal_chunk(&[5u8; KEY_LEN], &nonce, b"authentic");
        assert_eq!(
            open_chunk(&[6u8; KEY_LEN], &sealed).unwrap_err().check(),
            "seal-open-failed"
        );
    }

    #[test]
    fn truncated_below_floor_is_malformed() {
        let short = vec![0u8; NONCE_LEN + TAG_LEN - 1];
        assert_eq!(
            open_chunk(&[0u8; KEY_LEN], &short).unwrap_err().check(),
            "truncated"
        );
    }

    #[test]
    fn caller_key_is_not_zeroized() {
        // "Zeroize at the terminal owner only" (AGENTS.md rule 7): a callee-zero
        // of the caller's content key once failed 48/89 E2E.
        let key = [0xcd; KEY_LEN];
        let _ = seal_chunk(&key, &[1u8; NONCE_LEN], b"x");
        assert_eq!(key, [0xcd; KEY_LEN], "seal must not zero the caller's key");
    }
}
