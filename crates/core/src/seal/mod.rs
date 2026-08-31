//! The seal layer (blueprint/core.md "Module map: seal", "Envelope and
//! structures").
//!
//! AAD construction, symmetric seal/unseal, the kind-uniform envelope codec,
//! the read-body tagged union, the grant section, and the structure signatures.
//! Pure and deterministic: the sealing key and the nonce are injected (KATs pin
//! them); core samples no entropy and reads no clock.
//!
//! The wire framing of a sealed body is `nonce(24) || ciphertext||tag`; the
//! nonce is authenticated by the AEAD itself and deliberately **not** in the
//! AAD, which binds only `(v, id, scope, epoch, structTag)` ([`aad`]).

pub mod aad;
pub mod bin_index;
pub mod body;
pub mod content_key;
pub mod envelope;
pub mod grant;
pub mod op_record;
pub mod owner_local;
pub mod section;
pub mod settings_record;
pub mod structure;
pub mod write_body;

pub use aad::{
    AAD_DOMAIN, AadContext, STRUCT_TAG_ASCENT_LINK, STRUCT_TAG_BIN_INDEX, STRUCT_TAG_CONTENT_KEY,
    STRUCT_TAG_GRANT_BLOB, STRUCT_TAG_HISTORY_LINK, STRUCT_TAG_MAILBOX_PAYLOAD,
    STRUCT_TAG_OP_RECORD, STRUCT_TAG_OWNER_BLOB, STRUCT_TAG_OWNER_LOCAL,
    STRUCT_TAG_OWNER_WRITE_BLOB, STRUCT_TAG_POINTER_PAYLOAD, STRUCT_TAG_READ_BODY,
    STRUCT_TAG_SETTINGS_RECORD, STRUCT_TAG_WRITE_BODY, STRUCT_TAG_WRITE_HISTORY_LINK, STRUCT_TAGS,
    StructTagSpec, build_aad,
};
pub use bin_index::{
    BIN_INDEX_V, BinEntry, BinIndex, MAX_BIN_INDEX_BYTES, bin_index_aad, decode_bin_index,
    encode_bin_index, open_bin_index, seal_bin_index,
};
pub use body::{
    ChildRef, NodeKind, PreservedFields, ReadBody, Version, decode_read_body, encode_read_body,
    name_cmp,
};
pub use content_key::{
    CONTENT_KEY_HPKE_INFO, CONTENT_KEY_V, content_key_aad, open_content_key, seal_content_key,
};
pub use envelope::{
    CRITICAL_KEY_PREFIX, CarriedCut, Envelope, EnvelopeOverBound, MAX_BLOCK_BYTES,
    MAX_CRITICAL_CARRIED_BYTES, MAX_READ_SEALED_BYTES, READ_SEALED_ENVELOPE_HEADROOM_BYTES,
    UNCUTTABLE_KEYS, decode_envelope, encode_envelope, encode_envelope_within, envelope_over_bound,
    grant_section_bytes, has_grant_section, open_read_body, seal_read_body, set_grant_section,
};
pub use grant::{
    AscentLink, GrantBlobPayload, GrantSetBindingError, GrantSetCommitment, GrantSetEntry,
    HistoryLinkPayload, OverrideSeedPayload, OwnerWriteBlobPayload, Permission, decode_ascent_link,
    decode_grant_blob_payload, decode_grant_set_commitment, decode_history_link_payload,
    decode_override_seed_payload, decode_owner_write_blob_payload, encode_ascent_link,
    encode_grant_blob_payload, encode_grant_set_commitment, encode_history_link_payload,
    encode_override_seed_payload, encode_owner_write_blob_payload, open_ascent_link,
    open_grant_blob, open_history_link, open_owner_blob, open_owner_history_link,
    open_owner_write_blob, seal_ascent_link, seal_ascent_link_to, seal_grant_blob,
    seal_history_link, seal_owner_blob, seal_owner_history_link, seal_owner_write_blob,
    sign_grant_set, verify_grant_set, verify_grant_set_bound,
};
pub use op_record::{
    OP_RECORD_HPKE_INFO, OP_RECORD_V, OpRecordHeader, decode_op_record_header, op_record_aad,
    open_op_record, seal_op_record,
};
pub use owner_local::{
    OWNER_LOCAL_HPKE_INFO_PREFIX, OWNER_LOCAL_V, OwnerLocalHeader, OwnerLocalKind,
    open_owner_local, owner_local_aad, seal_owner_local,
};
pub use section::{
    GRANT_SECTION_ENVELOPE_HEADROOM_BYTES, GrantSection, MAX_GRANT_BLOBS, MAX_GRANT_SECTION_BYTES,
    MAX_HISTORY_LINKS, SignedAscentLink, SignedGrantBlob, SignedOwnerBlob, SignedOwnerWriteBlob,
    SignedSealed, decode_grant_section, encode_grant_section, is_grant_section_over_bound,
};
pub use settings_record::{
    SETTINGS_RECORD_HPKE_INFO, SETTINGS_RECORD_V, SettingsRecordHeader, open_settings_record,
    seal_settings_record, settings_record_aad,
};
pub use structure::{
    StructureSigInput, ascent_link_sig_body, sign_structure, structure_sig_preimage,
    verify_structure,
};
pub use write_body::{
    ChildScopeRef, GrantLedgerEntry, MAX_DIRECT_CHILD_SCOPES, MAX_WRITE_BODY_BYTES,
    MAX_WRITE_HISTORY_LINK_BYTES, WRITE_BODY_RESEAL_HEADROOM_BYTES, WriteBody, decode_write_body,
    encode_recipient_binding, encode_write_body, is_write_body_over_bound, sign_recipient_binding,
    verify_recipient_binding,
};

use crate::error::{CodecError, Malformed, TrustViolation};
use crate::suite::aead::{self, KEY_LEN, NONCE_LEN, TAG_LEN};

/// Seal `plaintext` under `key`/`nonce` with the structured AAD for `ctx`.
/// Returns the wire sealed blob `nonce(24) || ciphertext||tag`.
///
/// `nonce` **must be unique for every seal performed with a given `key`**:
/// XChaCha20-Poly1305 nonce reuse under one key is a confidentiality and
/// integrity break. It is caller-injected entropy (the KATs pin it), prefixed
/// so [`unseal`] can recover it, and authenticated by the AEAD rather than by
/// the AAD (#39 D7).
pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ctx: &AadContext,
    plaintext: &[u8],
) -> Vec<u8> {
    seal_framed(key, nonce, &build_aad(ctx), plaintext)
}

/// [`seal`] over raw AAD bytes, for the structures that bind their own clear
/// header instead of an [`AadContext`] ([`bin_index`]). The wire framing and the
/// nonce rule are [`seal`]'s.
pub fn seal_framed(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(NONCE_LEN + plaintext.len() + TAG_LEN);
    out.extend_from_slice(nonce);
    out.extend(aead::encrypt(key, nonce, aad, plaintext));
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
    open_framed(key, &build_aad(ctx), sealed)
}

/// [`unseal`] over raw AAD bytes, for the structures that bind their own clear
/// header instead of an [`AadContext`] ([`bin_index`]). The two-class
/// fail-closed policy is [`unseal`]'s.
pub fn open_framed(key: &[u8; KEY_LEN], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, CodecError> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(Malformed::Truncated {
            offset: sealed.len(),
        }
        .into());
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let nonce: &[u8; NONCE_LEN] = nonce.try_into().expect("split_at NONCE_LEN");
    aead::decrypt(key, nonce, aad, ciphertext).ok_or_else(|| TrustViolation::SealOpenFailed.into())
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
