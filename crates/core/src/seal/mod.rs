//! The seal layer (blueprint/core.md "Module map: seal", "Envelope and
//! structures").
//!
//! AAD construction, symmetric seal/unseal, the kind-uniform envelope codec,
//! and the read-body tagged union. Pure and deterministic: the sealing key and
//! the nonce are injected (KATs pin them); core samples no entropy and reads no
//! clock. Structure signatures, the write-body, the grant section, and the
//! pointer/mailbox payloads are later slices — this slice lands the symmetric
//! read-plane path end to end.
//!
//! The wire framing of a sealed body is `nonce(24) || ciphertext||tag`: the
//! XChaCha20-Poly1305 24-byte nonce is prefixed so [`unseal`] can recover it,
//! and it is authenticated by the AEAD itself (a flipped nonce breaks the tag).
//! The nonce is deliberately **not** in the AAD — only `(v, id, scope, epoch,
//! structTag)` is ([`aad`]).

pub mod aad;
pub mod body;
pub mod envelope;

pub use aad::{
    AAD_DOMAIN, AadContext, STRUCT_TAG_ASCENT_LINK, STRUCT_TAG_GRANT_BLOB, STRUCT_TAG_HISTORY_LINK,
    STRUCT_TAG_MAILBOX_PAYLOAD, STRUCT_TAG_OWNER_BLOB, STRUCT_TAG_POINTER_PAYLOAD,
    STRUCT_TAG_READ_BODY, STRUCT_TAG_WRITE_BODY, STRUCT_TAGS, StructTagSpec, build_aad,
};
pub use body::{
    ChildRef, NodeKind, ReadBody, Version, decode_read_body, encode_read_body, name_cmp,
};
pub use envelope::{Envelope, decode_envelope, encode_envelope, open_read_body, seal_read_body};

use crate::error::{CodecError, Malformed, TrustViolation};
use crate::suite::aead::{self, KEY_LEN, NONCE_LEN, TAG_LEN};

/// Seal `plaintext` under `key`/`nonce` with the structured AAD for `ctx`.
/// Returns the wire sealed blob `nonce(24) || ciphertext||tag`.
///
/// `nonce` **must be unique for every seal performed with a given `key`**:
/// XChaCha20-Poly1305 nonce reuse under one key is a confidentiality and
/// integrity break. It is caller-injected entropy (KATs pin it; production
/// callers source it from their injected entropy seam), prefixed so [`unseal`]
/// can recover it, and authenticated by the AEAD rather than by the AAD
/// (#39 D7). The caller owns `plaintext` and is its terminal owner for
/// zeroization (a callee never zeroizes a caller-owned buffer).
pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ctx: &AadContext,
    plaintext: &[u8],
) -> Vec<u8> {
    let aad = build_aad(ctx);
    let mut out = Vec::with_capacity(NONCE_LEN + plaintext.len() + TAG_LEN);
    out.extend_from_slice(nonce);
    out.extend(aead::encrypt(key, nonce, &aad, plaintext));
    out
}

/// Open a wire sealed blob (`nonce(24) || ciphertext||tag`) under `key` and the
/// structured AAD for `ctx`. Returns the recovered plaintext (the caller's to
/// own and zeroize).
///
/// Fail-closed, two-class: a blob too short to hold the nonce and tag is
/// [`Malformed::Truncated`]; a tag that does not verify — tampering, an AAD
/// transplant, or a `v` downgrade — is [`TrustViolation::SealOpenFailed`], never
/// a silent degrade.
pub fn unseal(key: &[u8; KEY_LEN], ctx: &AadContext, sealed: &[u8]) -> Result<Vec<u8>, CodecError> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(Malformed::Truncated { offset: 0 }.into());
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let nonce: &[u8; NONCE_LEN] = nonce.try_into().expect("split_at NONCE_LEN");
    let aad = build_aad(ctx);
    aead::decrypt(key, nonce, &aad, ciphertext).ok_or_else(|| TrustViolation::SealOpenFailed.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> AadContext {
        AadContext {
            v: 2,
            id: [1; 16],
            scope: [2; 16],
            epoch: 3,
            struct_tag: STRUCT_TAG_READ_BODY,
        }
    }

    #[test]
    fn seal_unseal_round_trip() {
        let key = [5u8; KEY_LEN];
        let nonce = [6u8; NONCE_LEN];
        let sealed = seal(&key, &nonce, &ctx(), b"hello body");
        assert_eq!(&sealed[..NONCE_LEN], &nonce, "nonce is prefixed");
        assert_eq!(unseal(&key, &ctx(), &sealed).unwrap(), b"hello body");
    }

    #[test]
    fn aad_transplant_fails_closed() {
        let key = [5u8; KEY_LEN];
        let nonce = [6u8; NONCE_LEN];
        let sealed = seal(&key, &nonce, &ctx(), b"hello body");
        // Unseal computing the AAD from a different struct tag: the tag fails.
        let mut wrong = ctx();
        wrong.struct_tag = STRUCT_TAG_WRITE_BODY;
        assert_eq!(
            unseal(&key, &wrong, &sealed).unwrap_err().check(),
            "seal-open-failed"
        );
    }

    #[test]
    fn truncated_sealed_blob_is_malformed() {
        let key = [5u8; KEY_LEN];
        // Below the nonce+tag floor: structurally too short.
        let short = vec![0u8; NONCE_LEN + TAG_LEN - 1];
        assert_eq!(
            unseal(&key, &ctx(), &short).unwrap_err().check(),
            "truncated"
        );
    }
}
