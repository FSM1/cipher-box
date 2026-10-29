//! Stage 3 of the adoption gate: every seed-bearing structure of a grant
//! section authenticates under the commitment's owner pseudonym, never a write
//! grantee's (blueprint/core.md "One section, one signer"; ADR 0083 D1).
//!
//! The owner pseudonym comes from the section's commitment, so the verdict means
//! something only once the owner identity attested that commitment. The
//! predicate therefore takes a [`VerifiedGrantSet`], which only stage 2's verify
//! functions return. The whole-record fail-closed policy and the stage order
//! stay the engine gate's.

use std::collections::BTreeSet;

use crate::error::{CodecError, TrustViolation};
use crate::suite::ed25519::{Ed25519Signature, Ed25519Verifier};

use super::aad::{
    STRUCT_TAG_ASCENT_LINK, STRUCT_TAG_GRANT_BLOB, STRUCT_TAG_HISTORY_LINK, STRUCT_TAG_OWNER_BLOB,
    STRUCT_TAG_OWNER_WRITE_BLOB, STRUCT_TAG_WRITE_BODY,
};
use super::grant::{GrantSetCommitment, Permission, VerifiedGrantSet};
use super::section::GrantSection;
use super::structure::{StructureSigInput, verify_structure};

/// The committed write-capable pseudonym keys of a scope root: the owner
/// pseudonym plus every write-permission entry's. Read-only entries never
/// authorize a seed-bearing structure.
///
/// Deduplicated: only a tag is unique across committed entries, so one pseudonym
/// may be named by many. A repeat would cost another trial verification.
pub fn committed_write_pseudonyms(commitment: &GrantSetCommitment) -> Vec<[u8; 32]> {
    let writers = commitment
        .entries
        .iter()
        .filter(|e| e.permission == Permission::Write)
        .map(|e| e.pseudonym_pk);
    let mut seen = BTreeSet::new();
    core::iter::once(commitment.owner_pseudonym_pk)
        .chain(writers)
        .filter(|pk| seen.insert(*pk))
        .collect()
}

/// The committed pseudonym whose signature authenticates `section`'s write body
/// at `scope` and `epoch` — the author of the grant ledger that body carries, and
/// so the party an abuse event over a rewritten row names.
///
/// One trial verification over the committed write-capable pseudonyms, over the
/// input [`authenticate_section_structures`] recomputes. `None` where no committed
/// pseudonym verifies, which is a record stage 3 refuses outright.
///
/// Precondition: `section` passed the adoption gate. The lookup reads
/// `section.commitment` with no witness, so on any other section it names a
/// signer that nothing anchored.
pub fn write_body_signer(section: &GrantSection, scope: [u8; 16], epoch: u64) -> Option<[u8; 32]> {
    let body = &section.write_body;
    let input =
        StructureSigInput::over_ciphertext(scope, epoch, STRUCT_TAG_WRITE_BODY, None, &body.sealed);
    let signature = Ed25519Signature::from_bytes(body.signature);
    committed_write_pseudonyms(&section.commitment)
        .into_iter()
        .find(|pseudonym| {
            Ed25519Verifier::from_bytes(*pseudonym)
                .is_some_and(|key| verify_structure(&key, &input, &signature).is_ok())
        })
}

/// Visit every seed-bearing structure `section` carries — its `structTag`,
/// recipient tag, signed-over bytes and detached signature — short-circuit on
/// the first `Err`. The single definition of *what* stage 3 authenticates, so a
/// new structure kind cannot reach the wire covered by only some of the passes
/// that walk one. The signed-over bytes are the structure's ciphertext, except
/// for the ascent link ([`super::ascent_link_sig_body`]).
pub fn for_each_structure<E>(
    section: &GrantSection,
    mut visit: impl FnMut(u8, Option<[u8; 32]>, &[u8], &[u8; 64]) -> Result<(), E>,
) -> Result<(), E> {
    let owner = &section.owner_blob;
    visit(
        STRUCT_TAG_OWNER_BLOB,
        None,
        &owner.ciphertext,
        &owner.signature,
    )?;
    if let Some(b) = &section.owner_write_blob {
        visit(
            STRUCT_TAG_OWNER_WRITE_BLOB,
            None,
            &b.ciphertext,
            &b.signature,
        )?;
    }
    for b in &section.grant_blobs {
        visit(
            STRUCT_TAG_GRANT_BLOB,
            Some(b.tag),
            &b.ciphertext,
            &b.signature,
        )?;
    }
    for l in &section.history_links {
        visit(STRUCT_TAG_HISTORY_LINK, None, &l.sealed, &l.signature)?;
    }
    let body = &section.write_body;
    visit(STRUCT_TAG_WRITE_BODY, None, &body.sealed, &body.signature)?;
    if let Some(a) = &section.ascent_link {
        visit(STRUCT_TAG_ASCENT_LINK, None, &a.sig_body(), &a.signature)?;
    }
    Ok(())
}

/// Authenticate one structure under `owner`, recomputing the signed input **from
/// the record's actual bytes** at the caller's scope and epoch — never a
/// caller-supplied [`StructureSigInput`]. A signature therefore proves "the
/// owner pseudonym signed *these* bytes at *this* scope/epoch". Any other
/// outcome is a `structure-signature-invalid` trust violation.
fn authenticate_structure(
    owner: &Ed25519Verifier,
    scope: [u8; 16],
    epoch: u64,
    struct_tag: u8,
    recipient_tag: Option<[u8; 32]>,
    ciphertext: &[u8],
    signature: &[u8; 64],
) -> Result<(), CodecError> {
    let input =
        StructureSigInput::over_ciphertext(scope, epoch, struct_tag, recipient_tag, ciphertext);
    verify_structure(owner, &input, &Ed25519Signature::from_bytes(*signature))
}

/// Stage 3's predicate: every structure signature `section` carries verifies,
/// at `scope` and `epoch`, under the owner pseudonym `attested` names —
/// whatever epoch a structure's own sealed AAD binds (blueprint/core.md
/// "Structure signatures"). The engine passes the authenticated envelope's
/// scope and epoch.
///
/// A section whose commitment is not `attested`'s fails `commitment-invalid`.
///
/// ```
/// use cipherbox_core::error::CodecError;
/// use cipherbox_core::seal::{GrantSection, authenticate_section_structures, verify_grant_set};
/// use cipherbox_core::suite::ecdsa::{EcdsaSignature, EcdsaVerifier};
///
/// fn stages_two_and_three(
///     owner: &EcdsaVerifier,
///     sig: &EcdsaSignature,
///     section: &GrantSection,
/// ) -> Result<(), CodecError> {
///     let verified = verify_grant_set(owner, &section.commitment, sig)?;
///     authenticate_section_structures(&verified, section, [0; 16], 0)
/// }
/// ```
///
/// A caller that skips stage 2 has no witness to pass:
///
/// ```compile_fail,E0308
/// use cipherbox_core::error::CodecError;
/// use cipherbox_core::seal::{GrantSection, authenticate_section_structures};
///
/// fn stage_three_alone(section: &GrantSection) -> Result<(), CodecError> {
///     authenticate_section_structures(&section.commitment, section, [0; 16], 0)
/// }
/// ```
pub fn authenticate_section_structures(
    attested: &VerifiedGrantSet<'_>,
    section: &GrantSection,
    scope: [u8; 16],
    epoch: u64,
) -> Result<(), CodecError> {
    // The attested set must be this section's own, or the verdict would adopt a
    // section whose commitment nothing anchored.
    if *attested.commitment() != section.commitment {
        return Err(TrustViolation::CommitmentInvalid.into());
    }
    // An owner key that is not a valid point verifies nothing.
    let owner = Ed25519Verifier::from_bytes(attested.commitment().owner_pseudonym_pk)
        .ok_or(TrustViolation::StructureSignatureInvalid)?;
    for_each_structure(section, |tag, recipient, ct, sig| {
        authenticate_structure(&owner, scope, epoch, tag, recipient, ct, sig)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::{
        GrantSetEntry, PreservedFields, SignedOwnerBlob, SignedSealed, sign_grant_set,
        sign_structure, verify_grant_set,
    };
    use crate::suite::ecdsa::EcdsaSigner;
    use crate::suite::ed25519::Ed25519Signer;

    const SCOPE: [u8; 16] = [0x11; 16];
    const EPOCH: u64 = 7;

    fn owner() -> Ed25519Signer {
        Ed25519Signer::from_seed([0x5a; 32])
    }

    fn grantee() -> Ed25519Signer {
        Ed25519Signer::from_seed([0x55; 32])
    }

    fn pk(signer: &Ed25519Signer) -> [u8; 32] {
        signer.verifying_key().to_bytes()
    }

    /// A section bound to `ipns_name` whose commitment names `owner_pk` as the
    /// owner pseudonym and [`grantee`] as a committed write entry. `blob_by`
    /// signs the owner blob, `body_by` the write body.
    fn section(
        ipns_name: &[u8],
        owner_pk: [u8; 32],
        blob_by: &Ed25519Signer,
        body_by: &Ed25519Signer,
    ) -> GrantSection {
        let owner_ct = b"owner blob".to_vec();
        let body = b"write body".to_vec();
        let sign = |signer: &Ed25519Signer, tag: u8, bytes: &[u8]| {
            let input = StructureSigInput::over_ciphertext(SCOPE, EPOCH, tag, None, bytes);
            sign_structure(signer, &input).to_bytes()
        };
        GrantSection {
            commitment: GrantSetCommitment {
                ipns_name: ipns_name.to_vec(),
                owner_pseudonym_pk: owner_pk,
                cut_epoch: 0,
                entries: vec![GrantSetEntry::new(
                    &[0x66; 32],
                    [0x67; 32],
                    [0x68; 32],
                    Permission::Write,
                    pk(&grantee()),
                )],
                unknown: PreservedFields::new(),
            },
            commitment_sig: [0; 64],
            grant_blobs: Vec::new(),
            owner_blob: SignedOwnerBlob {
                enc: [0x20; 32],
                signature: sign(blob_by, STRUCT_TAG_OWNER_BLOB, &owner_ct),
                ciphertext: owner_ct,
                unknown: PreservedFields::new(),
            },
            owner_write_blob: None,
            ascent_link: None,
            history_links: Vec::new(),
            write_body: SignedSealed {
                signature: sign(body_by, STRUCT_TAG_WRITE_BODY, &body),
                sealed: body,
                unknown: PreservedFields::new(),
            },
            unknown: PreservedFields::new(),
        }
    }

    /// Stages 2 then 3 over `section`, under an owner identity that signs its
    /// commitment, so stage 3 owns the verdict.
    fn stage_three(section: &GrantSection) -> Result<(), CodecError> {
        let identity = EcdsaSigner::from_scalar(&[0x11; 32]).unwrap();
        let sig = sign_grant_set(&identity, &section.commitment).unwrap();
        let witness =
            verify_grant_set(&identity.verifying_key(), &section.commitment, &sig).unwrap();
        authenticate_section_structures(&witness, section, SCOPE, EPOCH)
    }

    fn check(section: &GrantSection) -> &'static str {
        stage_three(section).unwrap_err().check()
    }

    #[test]
    fn a_section_the_owner_pseudonym_signs_throughout_authenticates() {
        stage_three(&section(b"root", pk(&owner()), &owner(), &owner()))
            .expect("the owner pseudonym signs the whole section");
    }

    #[test]
    fn a_section_a_committed_write_grantee_signs_throughout_is_refused() {
        let by_grantee = section(b"root", pk(&owner()), &grantee(), &grantee());
        assert!(
            committed_write_pseudonyms(&by_grantee.commitment).contains(&pk(&grantee())),
            "the grantee is a committed write-capable pseudonym"
        );
        assert_eq!(check(&by_grantee), "structure-signature-invalid");
    }

    #[test]
    fn a_section_signed_by_the_owner_and_a_grantee_is_refused() {
        for (blob_by, body_by) in [(owner(), grantee()), (grantee(), owner())] {
            assert_eq!(
                check(&section(b"root", pk(&owner()), &blob_by, &body_by)),
                "structure-signature-invalid"
            );
        }
    }

    #[test]
    fn a_section_signed_by_no_committed_pseudonym_is_refused() {
        let outsider = Ed25519Signer::from_seed([0x99; 32]);
        assert_eq!(
            check(&section(b"root", pk(&owner()), &outsider, &outsider)),
            "structure-signature-invalid"
        );
    }

    #[test]
    fn an_owner_pseudonym_that_is_not_a_point_authenticates_nothing() {
        let not_a_point = (0u8..=u8::MAX)
            .map(|b| [b; 32])
            .find(|pk| Ed25519Verifier::from_bytes(*pk).is_none())
            .expect("some 32-byte string is not a curve point");
        assert_eq!(
            check(&section(b"root", not_a_point, &grantee(), &grantee())),
            "structure-signature-invalid"
        );
    }

    #[test]
    fn a_witness_for_another_commitment_authenticates_nothing() {
        let identity = EcdsaSigner::from_scalar(&[0x11; 32]).unwrap();
        let attested = section(b"scope-root-a", pk(&owner()), &owner(), &owner());
        let other = section(b"scope-root-b", pk(&owner()), &owner(), &owner());
        let sig = sign_grant_set(&identity, &attested.commitment).unwrap();
        let witness =
            verify_grant_set(&identity.verifying_key(), &attested.commitment, &sig).unwrap();

        authenticate_section_structures(&witness, &attested, SCOPE, EPOCH)
            .expect("the witness authenticates its own section");
        // Every structure of `other` verifies under the owner pseudonym the
        // witness names, so only the binding refuses it.
        assert_eq!(
            authenticate_section_structures(&witness, &other, SCOPE, EPOCH)
                .unwrap_err()
                .check(),
            "commitment-invalid"
        );
    }
}
