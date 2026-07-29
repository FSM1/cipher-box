//! The seal layer (blueprint/core.md "Module map: seal", "Envelope and
//! structures").
//!
//! AAD construction, symmetric seal/unseal, the kind-uniform envelope codec,
//! the read-body tagged union, the grant section, and the structure signatures.
//! Pure and deterministic: the sealing key and the nonce are injected (KATs pin
//! them); core samples no entropy and reads no clock.
//!
//! The wire framing of a sealed body is `nonce(24) || ciphertext||tag`: the
//! XChaCha20-Poly1305 24-byte nonce is prefixed so [`unseal`] can recover it,
//! and it is authenticated by the AEAD itself (a flipped nonce breaks the tag).
//! The nonce is deliberately **not** in the AAD — only `(v, id, scope, epoch,
//! structTag)` is ([`aad`]).

pub mod aad;
pub mod body;
pub mod envelope;
pub mod grant;
pub mod op_record;
pub mod section;
pub mod structure;
pub mod write_body;

pub use aad::{
    AAD_DOMAIN, AadContext, STRUCT_TAG_ASCENT_LINK, STRUCT_TAG_GRANT_BLOB, STRUCT_TAG_HISTORY_LINK,
    STRUCT_TAG_MAILBOX_PAYLOAD, STRUCT_TAG_OP_RECORD, STRUCT_TAG_OWNER_BLOB,
    STRUCT_TAG_OWNER_WRITE_BLOB, STRUCT_TAG_POINTER_PAYLOAD, STRUCT_TAG_READ_BODY,
    STRUCT_TAG_WRITE_BODY, STRUCT_TAGS, StructTagSpec, build_aad,
};
pub use body::{
    ChildRef, NodeKind, ReadBody, Version, decode_read_body, encode_read_body, name_cmp,
};
pub use envelope::{
    Envelope, decode_envelope, encode_envelope, grant_section_bytes, has_grant_section,
    open_read_body, seal_read_body,
};
pub use grant::{
    AscentLink, GrantBlobPayload, GrantSetCommitment, GrantSetEntry, HistoryLinkPayload,
    OverrideSeedPayload, OwnerWriteBlobPayload, Permission, decode_ascent_link,
    decode_grant_blob_payload, decode_grant_set_commitment, decode_history_link_payload,
    decode_override_seed_payload, decode_owner_write_blob_payload, encode_ascent_link,
    encode_grant_blob_payload, encode_grant_set_commitment, encode_history_link_payload,
    encode_override_seed_payload, encode_owner_write_blob_payload, open_ascent_link,
    open_grant_blob, open_history_link, open_owner_blob, open_owner_write_blob, seal_ascent_link,
    seal_grant_blob, seal_history_link, seal_owner_blob, seal_owner_write_blob, sign_grant_set,
    verify_grant_set,
};
pub use op_record::{
    OP_RECORD_HPKE_INFO, OP_RECORD_V, OpRecordHeader, decode_op_record_header, op_record_aad,
    open_op_record, seal_op_record,
};
pub use section::{
    GrantSection, SignedAscentLink, SignedGrantBlob, SignedOwnerBlob, SignedOwnerWriteBlob,
    SignedSealed, decode_grant_section, encode_grant_section,
};
pub use structure::{StructureSigInput, sign_structure, structure_sig_preimage, verify_structure};
pub use write_body::{
    ChildScopeRef, GrantLedgerEntry, WriteBody, decode_write_body, encode_write_body,
};

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
        return Err(Malformed::Truncated {
            offset: sealed.len(),
        }
        .into());
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
