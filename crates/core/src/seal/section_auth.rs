//! Stage 3 of the adoption gate: every seed-bearing structure of a grant
//! section authenticates under **one** committed write-capable pseudonym
//! (blueprint/core.md "One section, one signer", ADR 0052).
//!
//! The pseudonyms come from the section's commitment, so the verdict means
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
/// may be named by many. A repeat authenticates nothing the first copy did not,
/// and each copy would cost another trial verification.
///
/// Left compressed. A commitment may name 1024 writers while the pin means at
/// most one is ever used, so decompressing eagerly would reinstate an
/// O(pseudonyms) cost the scan itself no longer pays.
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

/// Whether `pseudonym_pk` is one of a scope root's committed write-capable
/// pseudonyms — [`committed_write_pseudonyms`]'s membership test, without
/// materialising the set. A re-seal binds its own signer to it (fail-closed
/// symmetry).
pub fn is_committed_write_pseudonym(
    commitment: &GrantSetCommitment,
    pseudonym_pk: &[u8; 32],
) -> bool {
    commitment.owner_pseudonym_pk == *pseudonym_pk
        || commitment
            .entries
            .iter()
            .any(|e| e.permission == Permission::Write && e.pseudonym_pk == *pseudonym_pk)
}

/// The committed pseudonym whose signature authenticates `section`'s write body
/// at `scope` and `epoch` — the author of the grant ledger that body carries, and
/// so the party an abuse event over a rewritten row names.
///
/// One trial verification over the set [`authenticate_section_structures`] pins
/// its single signer from, over the same recomputed input, so the two cannot
/// disagree about which key signed the section. `None` where no committed
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

/// Trial-verifier over the committed write-capable pseudonyms, pinning the one
/// that authenticated the section's first structure. The scan therefore runs at
/// most once per record, so worst-case work is `pseudonyms + structures` rather
/// than their product.
struct StructureAuthenticator {
    committed: Vec<[u8; 32]>,
    pinned: Option<Ed25519Verifier>,
}

impl StructureAuthenticator {
    /// Authenticate one structure, recomputing the signed input **from the
    /// record's actual bytes** at the caller's scope and epoch — never a
    /// caller-supplied [`StructureSigInput`]. A signature therefore proves "the
    /// committed writer signed *these* bytes at *this* scope/epoch".
    ///
    /// The first structure is trusted iff it verifies under at least one
    /// committed pseudonym, which pins that pseudonym; every later structure must
    /// verify under **that** key alone. Any other outcome is a
    /// `structure-signature-invalid` trust violation.
    fn authenticate(
        &mut self,
        scope: [u8; 16],
        epoch: u64,
        struct_tag: u8,
        recipient_tag: Option<[u8; 32]>,
        ciphertext: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), CodecError> {
        let input =
            StructureSigInput::over_ciphertext(scope, epoch, struct_tag, recipient_tag, ciphertext);
        let sig = Ed25519Signature::from_bytes(*signature);
        if let Some(pinned) = &self.pinned {
            return verify_structure(pinned, &input, &sig);
        }
        // A pseudonym that is not a valid point verifies nothing, so a failed
        // decompression falls through exactly as a failed signature does.
        for pseudonym in self
            .committed
            .iter()
            .filter_map(|pk| Ed25519Verifier::from_bytes(*pk))
        {
            if verify_structure(&pseudonym, &input, &sig).is_ok() {
                self.pinned = Some(pseudonym);
                return Ok(());
            }
        }
        Err(TrustViolation::StructureSignatureInvalid.into())
    }
}

/// Stage 3's predicate: every structure signature `section` carries verifies,
/// at `scope` and `epoch`, under **one** of the pseudonyms `attested` names —
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
    let mut auth = StructureAuthenticator {
        committed: committed_write_pseudonyms(attested.commitment()),
        pinned: None,
    };
    for_each_structure(section, |tag, recipient, ct, sig| {
        auth.authenticate(scope, epoch, tag, recipient, ct, sig)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::sign_structure;
    use crate::suite::ed25519::Ed25519Signer;

    const SCOPE: [u8; 16] = [0x11; 16];
    const EPOCH: u64 = 7;

    fn committed_signers() -> Vec<Ed25519Signer> {
        (0u8..4)
            .map(|i| Ed25519Signer::from_seed([i; 32]))
            .collect()
    }

    fn authenticator(signers: &[Ed25519Signer]) -> StructureAuthenticator {
        StructureAuthenticator {
            committed: signers
                .iter()
                .map(|s| s.verifying_key().to_bytes())
                .collect(),
            pinned: None,
        }
    }

    /// Sign `ciphertext` as an owner blob at the fixture scope/epoch.
    fn signed(signer: &Ed25519Signer, ciphertext: &[u8]) -> [u8; 64] {
        let input = StructureSigInput::over_ciphertext(
            SCOPE,
            EPOCH,
            STRUCT_TAG_OWNER_BLOB,
            None,
            ciphertext,
        );
        sign_structure(signer, &input).to_bytes()
    }

    fn authenticate(
        auth: &mut StructureAuthenticator,
        ciphertext: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), CodecError> {
        auth.authenticate(
            SCOPE,
            EPOCH,
            STRUCT_TAG_OWNER_BLOB,
            None,
            ciphertext,
            signature,
        )
    }

    #[test]
    fn any_committed_pseudonym_can_pin_the_sections_signer() {
        // Pinning must not narrow *who* may sign a section — only how many
        // signers one section may have. Every committed pseudonym, at whatever
        // index, still authenticates a section of its own.
        let signers = committed_signers();
        for signer in &signers {
            let mut auth = authenticator(&signers);
            for structure in [&b"first"[..], b"second", b"third"] {
                authenticate(&mut auth, structure, &signed(signer, structure))
                    .expect("one committed pseudonym signs the whole section");
            }
        }
    }

    #[test]
    fn a_section_signed_by_two_committed_pseudonyms_is_unadoptable() {
        let signers = committed_signers();
        let mut auth = authenticator(&signers);
        authenticate(&mut auth, b"first", &signed(&signers[0], b"first")).expect("pins signer 0");
        assert_eq!(
            authenticate(&mut auth, b"second", &signed(&signers[1], b"second"))
                .unwrap_err()
                .check(),
            "structure-signature-invalid",
            "a second committed signer must not authenticate the same section"
        );
    }

    #[test]
    fn a_commitment_naming_no_usable_write_pseudonym_authenticates_nothing() {
        // Zero candidates: nothing can pin, so nothing adopts.
        let signer = Ed25519Signer::from_seed([1; 32]);
        let mut auth = authenticator(&[]);
        assert_eq!(
            authenticate(&mut auth, b"first", &signed(&signer, b"first"))
                .unwrap_err()
                .check(),
            "structure-signature-invalid"
        );
    }

    #[test]
    fn a_signature_from_no_committed_pseudonym_is_rejected_pinned_or_not() {
        let signers = committed_signers();
        let outsider = Ed25519Signer::from_seed([0x99; 32]);
        let mut fresh = authenticator(&signers);
        let mut pinned = authenticator(&signers);
        authenticate(&mut pinned, b"first", &signed(&signers[2], b"first")).expect("pins signer 2");
        for auth in [&mut fresh, &mut pinned] {
            assert_eq!(
                authenticate(auth, b"forged", &signed(&outsider, b"forged"))
                    .unwrap_err()
                    .check(),
                "structure-signature-invalid"
            );
        }
    }

    /// A section wholly signed by `signer`, under a commitment that names it as
    /// the owner pseudonym and is bound to `ipns_name`.
    fn section_signed_by(signer: &Ed25519Signer, ipns_name: &[u8]) -> GrantSection {
        use crate::seal::{PreservedFields, SignedOwnerBlob, SignedSealed};
        let owner_ct = b"owner blob".to_vec();
        let body = b"write body".to_vec();
        let sign = |tag: u8, bytes: &[u8]| {
            let input = StructureSigInput::over_ciphertext(SCOPE, EPOCH, tag, None, bytes);
            sign_structure(signer, &input).to_bytes()
        };
        GrantSection {
            commitment: GrantSetCommitment {
                ipns_name: ipns_name.to_vec(),
                owner_pseudonym_pk: signer.verifying_key().to_bytes(),
                cut_epoch: 0,
                entries: Vec::new(),
                unknown: PreservedFields::new(),
            },
            commitment_sig: [0; 64],
            grant_blobs: Vec::new(),
            owner_blob: SignedOwnerBlob {
                enc: [0x20; 32],
                signature: sign(STRUCT_TAG_OWNER_BLOB, &owner_ct),
                ciphertext: owner_ct,
                unknown: PreservedFields::new(),
            },
            owner_write_blob: None,
            ascent_link: None,
            history_links: Vec::new(),
            write_body: SignedSealed {
                signature: sign(STRUCT_TAG_WRITE_BODY, &body),
                sealed: body,
                unknown: PreservedFields::new(),
            },
            unknown: PreservedFields::new(),
        }
    }

    #[test]
    fn a_witness_for_another_commitment_authenticates_nothing() {
        use crate::seal::{sign_grant_set, verify_grant_set};
        use crate::suite::ecdsa::EcdsaSigner;

        let owner = EcdsaSigner::from_scalar(&[0x11; 32]).unwrap();
        let pseudonym = Ed25519Signer::from_seed([0x5a; 32]);
        let attested = section_signed_by(&pseudonym, b"scope-root-a");
        let other = section_signed_by(&pseudonym, b"scope-root-b");
        let sig = sign_grant_set(&owner, &attested.commitment).unwrap();
        let witness = verify_grant_set(&owner.verifying_key(), &attested.commitment, &sig).unwrap();

        authenticate_section_structures(&witness, &attested, SCOPE, EPOCH)
            .expect("the witness authenticates its own section");
        // Every structure of `other` verifies under a pseudonym the witness
        // names, so only the binding refuses it.
        assert_eq!(
            authenticate_section_structures(&witness, &other, SCOPE, EPOCH)
                .unwrap_err()
                .check(),
            "commitment-invalid"
        );
    }
}
