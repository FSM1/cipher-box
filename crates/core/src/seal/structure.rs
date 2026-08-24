//! Structure signatures (blueprint/core.md "Envelope and structures: Structure
//! signatures", #39 D2/D3, CONTEXT.md "Structure signature").
//!
//! Every seed-bearing structure a scope root publishes — the grant blobs, the
//! owner blob, the ascent link, the history links, and the write-body — carries
//! a **detached** Ed25519 signature by the rotator's writer pseudonym over the
//! det-CBOR preimage `{scopeId, epoch, structTag, recipientTag?, H(ciphertext)}`.
//! Binding the whole context makes a signature non-transferable: `structTag`
//! closes transplanting it onto a different structure kind, `recipientTag`
//! (grant blobs only) closes replaying one recipient's grant-blob signature
//! under another recipient's tag, `H(ciphertext)` binds the exact sealed bytes,
//! and `scopeId + epoch` bind the structure to its scope and rotation.
//!
//! One structure signs over more than its ciphertext: an ascent link's signed
//! bytes are [`ascent_link_sig_body`], which folds the plaintext `ascentPublic`
//! and the HPKE `enc` in beside it.
//!
//! The preimage is a det-CBOR map, never decoded — only signed and verified — so
//! it carries no unknown-field tolerance. Verification is per-structure and
//! pure; the whole-record fail-closed policy over these verdicts (a missing or
//! invalid signature is a whole-record trust violation) is the engine's adoption
//! gate, which composes [`verify_structure`].

use crate::codec::{Map, Value, encode_fixed_depth};
use crate::error::{CodecError, TrustViolation};
use crate::suite::ed25519::{Ed25519Signature, Ed25519Signer, Ed25519Verifier};
use crate::suite::hash::hash;
use crate::suite::hpke::ENC_LEN;
use crate::suite::secret::SECRET_LEN;

/// The context a structure signature binds, alongside the ciphertext hash. The
/// `recipient_tag` is present only for grant blobs (the per-recipient blinded
/// tag); every other structure signs with `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructureSigInput {
    /// The scope-root node id (16-byte UUID).
    pub scope_id: [u8; 16],
    /// The scope-relative epoch the structure belongs to.
    pub epoch: u64,
    /// The structure tag (a [`super::STRUCT_TAGS`] byte).
    pub struct_tag: u8,
    /// The recipient's blinded tag — grant blobs only.
    pub recipient_tag: Option<[u8; SECRET_LEN]>,
    /// The BLAKE3 digest of the structure's signed bytes.
    pub ciphertext_hash: [u8; SECRET_LEN],
}

impl StructureSigInput {
    /// Build the input over a structure's signed bytes — its `ciphertext`, or
    /// [`ascent_link_sig_body`] for an ascent link — hashing them with the frozen
    /// BLAKE3 `H` so a caller can never sign a preimage over a differently
    /// computed digest.
    pub fn over_ciphertext(
        scope_id: [u8; 16],
        epoch: u64,
        struct_tag: u8,
        recipient_tag: Option<[u8; SECRET_LEN]>,
        signed_bytes: &[u8],
    ) -> Self {
        Self {
            scope_id,
            epoch,
            struct_tag,
            recipient_tag,
            ciphertext_hash: hash(signed_bytes),
        }
    }
}

/// Build the det-CBOR structure-signature preimage. The `recipientTag` key is
/// present iff `recipient_tag` is `Some`.
pub fn structure_sig_preimage(input: &StructureSigInput) -> Vec<u8> {
    let mut m = Map::new();
    m.insert(
        "ciphertextHash",
        Value::Bytes(input.ciphertext_hash.to_vec()),
    );
    m.insert("epoch", Value::Unsigned(input.epoch));
    if let Some(tag) = &input.recipient_tag {
        m.insert("recipientTag", Value::Bytes(tag.to_vec()));
    }
    m.insert("scopeId", Value::Bytes(input.scope_id.to_vec()));
    m.insert("structTag", Value::Unsigned(u64::from(input.struct_tag)));
    encode_fixed_depth(&Value::Map(m))
}

/// The bytes an **ascent link's** structure signature is taken over — the
/// det-CBOR binding `{ascentPublic, ciphertext, enc}` — in place of the bare
/// ciphertext every other structure signs.
///
/// `ascentPublic` is the key a re-sealer holding no ancestor seed addresses the
/// override seed to, so outside the signature it is authenticated by possession
/// of the scope's `writeScopeSeed` alone: a holder could swap it and leave every
/// ciphertext, structure signature and commitment byte-identical, and the next
/// honest scope-exit rotation would seal a freshly minted seed to the planted
/// key (blueprint/core.md "Structure signatures").
///
/// Any field added to the published link must be added here too, or it lands
/// outside the signature exactly as `ascentPublic` did.
pub fn ascent_link_sig_body(
    ascent_public: &[u8; ENC_LEN],
    enc: &[u8; ENC_LEN],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("ascentPublic", Value::Bytes(ascent_public.to_vec()));
    m.insert("ciphertext", Value::Bytes(ciphertext.to_vec()));
    m.insert("enc", Value::Bytes(enc.to_vec()));
    encode_fixed_depth(&Value::Map(m))
}

/// Sign a structure with the rotator's writer-pseudonym Ed25519 key.
pub fn sign_structure(signer: &Ed25519Signer, input: &StructureSigInput) -> Ed25519Signature {
    signer.sign(&structure_sig_preimage(input))
}

/// Verify a detached structure signature against the writer pseudonym public
/// key. Fails closed with [`TrustViolation::StructureSignatureInvalid`] on a
/// forgery or any transplant — everything the preimage binds (see the module
/// docs) recomputes differently. A pure per-structure check the adoption gate
/// composes.
pub fn verify_structure(
    verifier: &Ed25519Verifier,
    input: &StructureSigInput,
    sig: &Ed25519Signature,
) -> Result<(), CodecError> {
    if verifier.verify(&structure_sig_preimage(input), sig) {
        Ok(())
    } else {
        Err(TrustViolation::StructureSignatureInvalid.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(struct_tag: u8, recipient_tag: Option<[u8; 32]>) -> StructureSigInput {
        StructureSigInput::over_ciphertext([0xa0; 16], 5, struct_tag, recipient_tag, b"ciphertext")
    }

    #[test]
    fn sign_verify_round_trip() {
        let signer = Ed25519Signer::from_seed([7u8; 32]);
        let i = input(super::super::STRUCT_TAG_OWNER_BLOB, None);
        let sig = sign_structure(&signer, &i);
        assert!(verify_structure(&signer.verifying_key(), &i, &sig).is_ok());
    }

    #[test]
    fn recipient_tag_presence_changes_the_preimage() {
        // A grant blob (recipientTag present) and an owner blob (absent) never
        // share a preimage even at the same scope/epoch.
        let with_tag = input(super::super::STRUCT_TAG_GRANT_BLOB, Some([0x01; 32]));
        let without = input(super::super::STRUCT_TAG_GRANT_BLOB, None);
        assert_ne!(
            structure_sig_preimage(&with_tag),
            structure_sig_preimage(&without)
        );
    }

    #[test]
    fn bad_signature_rejects() {
        let signer = Ed25519Signer::from_seed([7u8; 32]);
        let i = input(super::super::STRUCT_TAG_OWNER_BLOB, None);
        let mut bytes = sign_structure(&signer, &i).to_bytes();
        bytes[0] ^= 0x01;
        let sig = Ed25519Signature::from_bytes(bytes);
        assert_eq!(
            verify_structure(&signer.verifying_key(), &i, &sig)
                .unwrap_err()
                .check(),
            "structure-signature-invalid"
        );
    }

    #[test]
    fn wrong_tag_rejects() {
        // A signature made over the grant-blob tag never verifies under the
        // owner-blob tag: the structTag is bound into the preimage.
        let signer = Ed25519Signer::from_seed([7u8; 32]);
        let signed = input(super::super::STRUCT_TAG_GRANT_BLOB, Some([0x01; 32]));
        let sig = sign_structure(&signer, &signed);
        let transplanted = StructureSigInput {
            struct_tag: super::super::STRUCT_TAG_OWNER_BLOB,
            ..signed
        };
        assert_eq!(
            verify_structure(&signer.verifying_key(), &transplanted, &sig)
                .unwrap_err()
                .check(),
            "structure-signature-invalid"
        );
    }

    /// Every field of the ascent link's signed body changes the signed bytes, so
    /// a swap of any of the three is a signature the committed writer never made.
    #[test]
    fn each_ascent_link_field_moves_the_signed_body() {
        let base = ascent_link_sig_body(&[0x01; 32], &[0x02; 32], b"ct");
        assert_ne!(base, ascent_link_sig_body(&[0x11; 32], &[0x02; 32], b"ct"));
        assert_ne!(base, ascent_link_sig_body(&[0x01; 32], &[0x12; 32], b"ct"));
        assert_ne!(base, ascent_link_sig_body(&[0x01; 32], &[0x02; 32], b"ct!"));
    }

    /// A signature over the honest link never verifies once `ascentPublic` is
    /// swapped — the plaintext public half is inside the preimage.
    #[test]
    fn a_swapped_ascent_public_never_verifies() {
        let signer = Ed25519Signer::from_seed([7u8; 32]);
        let honest = StructureSigInput::over_ciphertext(
            [0xa0; 16],
            5,
            super::super::STRUCT_TAG_ASCENT_LINK,
            None,
            &ascent_link_sig_body(&[0x01; 32], &[0x02; 32], b"ct"),
        );
        let sig = sign_structure(&signer, &honest);
        let swapped = StructureSigInput::over_ciphertext(
            [0xa0; 16],
            5,
            super::super::STRUCT_TAG_ASCENT_LINK,
            None,
            &ascent_link_sig_body(&[0xee; 32], &[0x02; 32], b"ct"),
        );
        assert_eq!(
            verify_structure(&signer.verifying_key(), &swapped, &sig)
                .unwrap_err()
                .check(),
            "structure-signature-invalid"
        );
    }

    #[test]
    fn recipient_tag_transplant_rejects() {
        // One recipient's grant-blob signature never verifies under another
        // recipient's tag.
        let signer = Ed25519Signer::from_seed([7u8; 32]);
        let signed = input(super::super::STRUCT_TAG_GRANT_BLOB, Some([0x01; 32]));
        let sig = sign_structure(&signer, &signed);
        let transplanted = StructureSigInput {
            recipient_tag: Some([0x02; 32]),
            ..signed
        };
        assert_eq!(
            verify_structure(&signer.verifying_key(), &transplanted, &sig)
                .unwrap_err()
                .check(),
            "structure-signature-invalid"
        );
    }
}
