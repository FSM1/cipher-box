//! Rotation triggers (blueprint/engine.md "Rotation primitives: Triggers",
//! #26 D7).
//!
//! A read-plane rotation fires from three sources, all driving the one
//! [`rotate_scope`](super::rotate::rotate_scope) primitive:
//!
//! | Trigger      | Committed-set change | Cascade                                 |
//! | ------------ | -------------------- | --------------------------------------- |
//! | Scope exit   | none (grantee flat)  | flat — the single root re-publishes     |
//! | Read revoke  | revokee removed      | root cut here; eager-set via the sweep  |
//! | Manual       | none                 | per-scope, same primitive               |
//!
//! This slice wires only the **root cut** for a read revoke; the descendant
//! eager-set scope-root re-key is delivered by the sweep (Slice 3) and the
//! resolver/tree wiring (#745/#746). Read-revoke is not end-to-end complete here.
//!
//! Scope-exit and manual rotations re-seal the **unchanged** committed set: a
//! grantee re-wraps blobs verbatim and can neither extend nor shrink the tag set
//! (#26 D5), so they feed the current commitment/ledger straight into
//! `rotate_scope`. The read-revoke trigger is the only one that mutates the set —
//! [`revoke_read_grant`] performs the owner-only cut (remove the revokee from the
//! commitment and the ledger, owner-re-sign) whose result then feeds
//! `rotate_scope`. The removed grantee is thereby absent from the re-wrapped grant
//! blobs: that absence **is** the revocation ("they keep what they saw; they lose
//! everything new, now").

use cipherbox_core::seal::{
    GrantLedgerEntry, GrantSetCommitment, sign_grant_set, verify_grant_set,
};
use cipherbox_core::suite::ecdsa::{EcdsaSignature, EcdsaSigner, SIGNATURE_LEN as ECDSA_SIG_LEN};

/// Which trigger fired a rotation — a host-facing classifier carrying no key
/// material. Scope-exit and manual rotations re-seal the unchanged committed set;
/// read-revoke first applies [`revoke_read_grant`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationTrigger {
    /// A grantee left a granted scope (a cross-scope move out of a granted
    /// source, full-depth detected). Flat, self-contained, no committed change.
    ScopeExit,
    /// The owner revoked a read grant — the immediate revoking rekey.
    ReadRevoke,
    /// Manual hygiene rotate-now. No committed change.
    Manual,
}

impl RotationTrigger {
    /// A stable, host-facing name (no key material).
    pub fn name(&self) -> &'static str {
        match self {
            RotationTrigger::ScopeExit => "scope-exit",
            RotationTrigger::ReadRevoke => "read-revoke",
            RotationTrigger::Manual => "manual",
        }
    }
}

/// The owner-only committed-set cut produced by [`revoke_read_grant`]: the new
/// commitment with the revokee removed, its fresh owner signature, and the
/// matching pruned ledger — ready to feed [`rotate_scope`](super::rotate::rotate_scope).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedCommittedSet {
    /// The commitment with the revokee's `(tag, permission, pseudonymPk)` removed.
    pub commitment: GrantSetCommitment,
    /// The fresh 64-byte compact ECDSA owner signature over `commitment`.
    pub commitment_sig: [u8; ECDSA_SIG_LEN],
    /// The grant ledger with the revokee's row removed.
    pub grant_ledger: Vec<GrantLedgerEntry>,
}

/// A fail-closed read-revoke failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeError {
    /// `owner_signer` did not sign the current commitment, so it is not the owner
    /// identity that authorized the set. Re-signing under it would mint a
    /// commitment the adoption gate rejects (an unreadable root); the encode-side
    /// mirror of the gate's owner-identity verify (fail-closed symmetry).
    UnauthorizedSigner,
    /// `revoked_tag` is not in the committed set — there is no grant to revoke.
    /// Rotating anyway would be a no-op cut, so this is rejected, not silent.
    NotGranted,
    /// Re-signing the pruned commitment failed (a duplicate tag survived — never
    /// possible after a single removal, but propagated fail-closed).
    Sign(cipherbox_core::error::CodecError),
}

impl core::fmt::Display for RevokeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RevokeError::UnauthorizedSigner => {
                f.write_str("owner signer did not authorize the current commitment")
            }
            RevokeError::NotGranted => f.write_str("no grant committed under the revoked tag"),
            RevokeError::Sign(e) => write!(f, "commitment re-sign failed: {}", e.check()),
        }
    }
}

impl std::error::Error for RevokeError {}

impl RevokeError {
    /// A stable, key-material-free classification name.
    pub fn check(&self) -> &'static str {
        match self {
            RevokeError::UnauthorizedSigner => "unauthorized-signer",
            RevokeError::NotGranted => "not-granted",
            RevokeError::Sign(_) => "commitment-sign-failed",
        }
    }
}

/// Perform the read-revoke committed-set cut: remove `revoked_tag`'s grant from
/// the owner-signed `commitment` and the write-body `grant_ledger`, and
/// owner-re-sign the pruned commitment with `owner_signer`.
///
/// Owner-only by construction: it requires the owner's identity signer, and only
/// the commitment (owner-signed) authorises the set. `commitment_sig` is the
/// current owner signature over `commitment`; `owner_signer` MUST be the identity
/// that produced it (fail-closed [`RevokeError::UnauthorizedSigner`] otherwise).
/// The `revoked_tag` MUST be committed (fail-closed [`RevokeError::NotGranted`]
/// otherwise). The result is the input a subsequent `rotate_scope` re-seals —
/// after which the revokee has no grant blob at the new epoch.
pub fn revoke_read_grant(
    commitment: &GrantSetCommitment,
    commitment_sig: &[u8; ECDSA_SIG_LEN],
    grant_ledger: &[GrantLedgerEntry],
    revoked_tag: &[u8; 32],
    owner_signer: &EcdsaSigner,
) -> Result<RevokedCommittedSet, RevokeError> {
    // Fail-closed BEFORE the cut: `owner_signer` MUST be the identity that signed
    // the current commitment, else the re-signed cut mints a commitment the
    // adoption gate rejects (an unreadable root). Encode-side mirror of the gate's
    // owner-identity verify (fail-closed symmetry). The current commitment is
    // owner-authentic (it passed the gate to resolve), so binding the new signer
    // to it transitively anchors the cut to the owner identity.
    let current_sig =
        EcdsaSignature::from_compact(commitment_sig).ok_or(RevokeError::UnauthorizedSigner)?;
    verify_grant_set(&owner_signer.verifying_key(), commitment, &current_sig)
        .map_err(|_| RevokeError::UnauthorizedSigner)?;

    // The commitment is the authoritative set; a tag absent there is not a grant.
    if !commitment.entries.iter().any(|e| &e.tag == revoked_tag) {
        return Err(RevokeError::NotGranted);
    }

    let mut new_commitment = commitment.clone();
    new_commitment.entries.retain(|e| &e.tag != revoked_tag);
    let grant_ledger: Vec<GrantLedgerEntry> = grant_ledger
        .iter()
        .filter(|e| &e.tag != revoked_tag)
        .cloned()
        .collect();

    let commitment_sig = sign_grant_set(owner_signer, &new_commitment)
        .map_err(RevokeError::Sign)?
        .to_compact();

    Ok(RevokedCommittedSet {
        commitment: new_commitment,
        commitment_sig,
        grant_ledger,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_core::seal::{GrantSetEntry, Permission, verify_grant_set};
    use cipherbox_core::suite::ecdsa::EcdsaSignature;

    fn owner() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[0x33; 32]).unwrap()
    }

    fn commitment() -> (
        GrantSetCommitment,
        [u8; ECDSA_SIG_LEN],
        Vec<GrantLedgerEntry>,
    ) {
        let entries = vec![
            GrantSetEntry::new([0xa1; 32], Permission::Read, [0x02; 32]),
            GrantSetEntry::new([0xb2; 32], Permission::Read, [0x04; 32]),
            GrantSetEntry::new([0xc3; 32], Permission::Write, [0x03; 32]),
        ];
        let c = GrantSetCommitment {
            ipns_name: b"n".to_vec(),
            owner_pseudonym_pk: [0x88; 32],
            entries,
            unknown: Vec::new(),
        };
        let sig = sign_grant_set(&owner(), &c).unwrap().to_compact();
        let ledger = vec![
            GrantLedgerEntry::new([0x02; 33], [0x11; 32], Permission::Read, [0xa1; 32]),
            GrantLedgerEntry::new([0x04; 33], [0x12; 32], Permission::Read, [0xb2; 32]),
            GrantLedgerEntry::new([0x03; 33], [0x13; 32], Permission::Write, [0xc3; 32]),
        ];
        (c, sig, ledger)
    }

    #[test]
    fn revoke_removes_tag_from_both_and_resigns() {
        let owner = owner();
        let (c, sig, ledger) = commitment();
        let cut = revoke_read_grant(&c, &sig, &ledger, &[0xb2; 32], &owner).expect("revoke");

        assert!(!cut.commitment.entries.iter().any(|e| e.tag == [0xb2; 32]));
        assert!(!cut.grant_ledger.iter().any(|e| e.tag == [0xb2; 32]));
        assert_eq!(cut.commitment.entries.len(), 2);
        assert_eq!(cut.grant_ledger.len(), 2);

        // The fresh signature verifies over the pruned commitment.
        let sig = EcdsaSignature::from_compact(&cut.commitment_sig).unwrap();
        verify_grant_set(&owner.verifying_key(), &cut.commitment, &sig).expect("fresh sig valid");
    }

    #[test]
    fn revoke_preserves_survivors_and_owner_fields() {
        let owner = owner();
        let (c, sig, ledger) = commitment();
        let cut = revoke_read_grant(&c, &sig, &ledger, &[0xc3; 32], &owner).expect("revoke");
        assert!(cut.commitment.entries.iter().any(|e| e.tag == [0xa1; 32]));
        assert!(cut.commitment.entries.iter().any(|e| e.tag == [0xb2; 32]));
        assert_eq!(cut.commitment.ipns_name, c.ipns_name);
        assert_eq!(cut.commitment.owner_pseudonym_pk, c.owner_pseudonym_pk);
    }

    #[test]
    fn revoke_unknown_tag_fails_closed() {
        let owner = owner();
        let (c, sig, ledger) = commitment();
        let err =
            revoke_read_grant(&c, &sig, &ledger, &[0xff; 32], &owner).expect_err("not granted");
        assert_eq!(err.check(), "not-granted");
    }

    #[test]
    fn revoke_wrong_signer_fails_closed() {
        // A signer that did not sign the current commitment is rejected before the
        // cut — the encode-side mirror of the gate's owner-identity verify.
        let (c, sig, ledger) = commitment();
        let wrong_owner = EcdsaSigner::from_scalar(&[0x44; 32]).unwrap();
        let err = revoke_read_grant(&c, &sig, &ledger, &[0xb2; 32], &wrong_owner)
            .expect_err("unauthorized signer");
        assert_eq!(err.check(), "unauthorized-signer");
    }

    #[test]
    fn trigger_names_are_stable() {
        assert_eq!(RotationTrigger::ScopeExit.name(), "scope-exit");
        assert_eq!(RotationTrigger::ReadRevoke.name(), "read-revoke");
        assert_eq!(RotationTrigger::Manual.name(), "manual");
    }
}
