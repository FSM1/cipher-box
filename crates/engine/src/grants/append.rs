//! Owner edits of a scope root that already stands: append a row
//! ([ADR 0026](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0026-a-scope-root-takes-many-grants.md)
//! D1), change a grantee's permission (ADR 0025 D6), and rename a grantee
//! (ADR 0027 D3).
//!
//! Each edit authorises against the owner's own signature over the set it
//! changes, re-signs the result, and leaves the publish to the caller: one
//! re-seal at the current epoch, with no new seed and no re-seal of the subtree
//! (blueprint/engine.md "Grant creation").

use core::fmt;

use cipherbox_core::error::CodecError;
use cipherbox_core::seal::{
    GrantLedgerEntry, GrantSetCommitment, GrantSetEntryKind, GranteeName, Permission,
    sign_grant_set, sign_recipient_binding,
};
use cipherbox_core::suite::ecdsa::{EcdsaSignature, EcdsaSigner, IDENTITY_PUBLIC_LEN};

use super::invite::{CommittedScope, InviteError, OwnerAuthority, check_publishable};
use super::ledger::{GrantRow, row_is_owner_attested};

/// One row on a scope's committed set, as the owner's commitment carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldRow {
    /// The committed tag.
    pub tag: [u8; 32],
    /// The committed permission.
    pub permission: Permission,
    /// Whether the row is a personal grant or a link.
    pub kind: GrantSetEntryKind,
}

/// A committed set after one owner edit, with the owner's signature over it.
pub struct EditedSet {
    /// The edited commitment.
    pub commitment: GrantSetCommitment,
    /// The owner's signature over [`commitment`](Self::commitment).
    pub commitment_sig: EcdsaSignature,
    /// The ledger that matches it.
    pub ledger: Vec<GrantLedgerEntry>,
}

/// A refused owner edit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantEditError {
    /// The grantee already holds the permission asked for, so nothing changes
    /// (ADR 0026 D4).
    SamePermission,
    /// No committed row answers to the grantee the edit names.
    NotGranted,
    /// The row is a link. Its permission is fixed at creation (ADR 0025 D7),
    /// and it names no grantee.
    LinkRow,
    /// The set refused: the caller did not sign it, or the edited set is one
    /// its own readers refuse.
    Invite(InviteError),
    /// Re-signing the edited commitment failed.
    Sign(CodecError),
}

impl GrantEditError {
    /// Every check this type owns, in variant declaration order — the surface
    /// `crates/engine/tests/kat_checks.rs` pins. The two wrapping variants
    /// surface another surface's verdict verbatim and stay off it.
    pub const CHECKS: &'static [&'static str] = &[
        "grant-recipient-already-has-access",
        "grant-recipient-not-granted",
        "grant-row-is-a-link",
    ];

    /// A stable, key-material-free classification name.
    pub fn check(&self) -> &'static str {
        match self {
            Self::SamePermission => "grant-recipient-already-has-access",
            Self::NotGranted => "grant-recipient-not-granted",
            Self::LinkRow => "grant-row-is-a-link",
            Self::Invite(e) => e.check(),
            Self::Sign(e) => e.check(),
        }
    }

    /// The class label used in reject vectors.
    pub fn class(&self) -> &'static str {
        match self {
            Self::SamePermission | Self::NotGranted | Self::LinkRow => "capability",
            Self::Invite(e) => e.class(),
            Self::Sign(e) => e.class(),
        }
    }
}

impl fmt::Display for GrantEditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "grant edit refused: {}", self.check())
    }
}

impl std::error::Error for GrantEditError {}

/// The row `scope` commits for a grantee: the entry of the owner-attested
/// ledger row that names `identity_pk`. A lookup only: the edit that acts on
/// the row authorises the set.
///
/// The identity comes only from a row the owner signed, so a name a committed
/// write grantee wrote into the ledger locates nothing (ADR 0027 D6).
pub fn held_row(
    owner: &OwnerAuthority<'_>,
    scope: &CommittedScope<'_>,
    identity_pk: &[u8; IDENTITY_PUBLIC_LEN],
) -> Option<HeldRow> {
    let owner_identity = owner.identity_signer.verifying_key();
    let name = scope.commitment.ipns_name.as_slice();
    let row = scope.ledger.iter().find(|row| {
        row.recipient_identity_pk == *identity_pk
            && row_is_owner_attested(&owner_identity, row, name)
    })?;
    let entry = scope.commitment.entries.iter().find(|e| e.tag == row.tag)?;
    Some(HeldRow {
        tag: entry.tag,
        permission: entry.permission,
        kind: entry.kind,
    })
}

/// Set `row`'s grantee name and re-sign its recipient binding, which covers
/// the name (ADR 0027 D3). `scope_root_name` is the name the row is minted at.
pub fn name_row(
    owner_identity_signer: &EcdsaSigner,
    scope_root_name: &[u8],
    row: &mut GrantLedgerEntry,
    name: GranteeName,
) {
    row.grantee_name = Some(name);
    row.owner_sig =
        sign_recipient_binding(owner_identity_signer, scope_root_name, row).to_compact();
}

/// Append `row` to `scope`'s committed set (ADR 0026 D1). `row` must be minted
/// at the scope root's own name.
pub fn append_row(
    owner: &OwnerAuthority<'_>,
    scope: &CommittedScope<'_>,
    row: GrantRow,
) -> Result<EditedSet, GrantEditError> {
    owner.authorise(scope).map_err(GrantEditError::Invite)?;
    let mut commitment = scope.commitment.clone();
    let mut ledger = scope.ledger.to_vec();
    commitment.entries.push(row.commitment_entry);
    ledger.push(row.ledger_entry);
    resign(owner, commitment, ledger)
}

/// Set the permission of the personal row at `tag` (ADR 0025 D6).
///
/// The row keeps its via-link reference and its grantee name: the permission
/// is not in the row's owner signature, and the commitment re-signs it.
pub fn set_permission(
    owner: &OwnerAuthority<'_>,
    scope: &CommittedScope<'_>,
    tag: &[u8; 32],
    permission: Permission,
) -> Result<EditedSet, GrantEditError> {
    owner.authorise(scope).map_err(GrantEditError::Invite)?;
    let mut commitment = scope.commitment.clone();
    let entry = commitment
        .entries
        .iter_mut()
        .find(|e| e.tag == *tag)
        .ok_or(GrantEditError::NotGranted)?;
    if entry.kind == GrantSetEntryKind::Link {
        return Err(GrantEditError::LinkRow);
    }
    if entry.permission == permission {
        return Err(GrantEditError::SamePermission);
    }
    entry.permission = permission;
    let mut ledger = scope.ledger.to_vec();
    for row in ledger.iter_mut().filter(|row| row.tag == *tag) {
        row.permission = permission;
    }
    resign(owner, commitment, ledger)
}

/// Set the grantee name of the personal row at `tag`, and re-sign that row
/// (ADR 0027 D3). Only the name, its source and the row signature change.
///
/// The row must be one the owner attested: re-signing it would otherwise put
/// the owner's signature over an identity a committed write grantee chose.
pub fn rename_grantee(
    owner: &OwnerAuthority<'_>,
    scope: &CommittedScope<'_>,
    tag: &[u8; 32],
    name: GranteeName,
) -> Result<EditedSet, GrantEditError> {
    owner.authorise(scope).map_err(GrantEditError::Invite)?;
    let entry = scope
        .commitment
        .entries
        .iter()
        .find(|e| e.tag == *tag)
        .ok_or(GrantEditError::NotGranted)?;
    if entry.kind == GrantSetEntryKind::Link {
        return Err(GrantEditError::LinkRow);
    }
    let owner_identity = owner.identity_signer.verifying_key();
    let scope_name = scope.commitment.ipns_name.as_slice();
    let mut ledger = scope.ledger.to_vec();
    let row = ledger
        .iter_mut()
        .find(|row| row.tag == *tag && row_is_owner_attested(&owner_identity, row, scope_name))
        .ok_or(GrantEditError::NotGranted)?;
    name_row(owner.identity_signer, scope_name, row, name);
    check_publishable(scope.commitment, &ledger).map_err(GrantEditError::Invite)?;
    Ok(EditedSet {
        commitment: scope.commitment.clone(),
        commitment_sig: scope.commitment_sig.clone(),
        ledger,
    })
}

/// Refuse a set its own readers refuse, then owner-sign it.
fn resign(
    owner: &OwnerAuthority<'_>,
    commitment: GrantSetCommitment,
    ledger: Vec<GrantLedgerEntry>,
) -> Result<EditedSet, GrantEditError> {
    check_publishable(&commitment, &ledger).map_err(GrantEditError::Invite)?;
    let commitment_sig =
        sign_grant_set(owner.identity_signer, &commitment).map_err(GrantEditError::Sign)?;
    Ok(EditedSet {
        commitment,
        commitment_sig,
        ledger,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::invite::{EphemeralInvitee, LinkTerms, mint_invite_row};
    use crate::grants::ledger::mint_grant_row;
    use cipherbox_core::seal::{ChildScopeRef, MAX_GRANT_BLOBS, NameSource, PreservedFields};
    use cipherbox_core::suite::ecdsa::EcdsaSigner;
    use cipherbox_core::suite::x25519::X25519Secret;

    const SCOPE: [u8; 16] = [0x5c; 16];
    const NAME: &[u8] = b"scope-root-name";
    const POINTER_READ_KEY: [u8; 32] = [0x66; 32];

    fn owner_identity() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[0x11; 32]).expect("valid scalar")
    }

    fn owner_enc() -> X25519Secret {
        X25519Secret::from_scalar([0x12; 32])
    }

    fn grantee(byte: u8) -> [u8; IDENTITY_PUBLIC_LEN] {
        EcdsaSigner::from_scalar(&[byte; 32])
            .expect("valid scalar")
            .verifying_key()
            .to_sec1()
    }

    fn row(byte: u8, permission: Permission) -> GrantRow {
        mint_grant_row(
            &owner_identity(),
            &owner_enc(),
            &POINTER_READ_KEY,
            grantee(byte),
            &X25519Secret::from_scalar([byte; 32]).public(),
            &SCOPE,
            NAME,
            permission,
        )
        .expect("a contributory recipient key")
    }

    fn link() -> GrantRow {
        mint_invite_row(
            &owner_identity(),
            &owner_enc(),
            &POINTER_READ_KEY,
            &EphemeralInvitee::from_secret(&[0x40; 32]).expect("a valid scalar"),
            &SCOPE,
            NAME,
            &LinkTerms {
                deadline: crate::seams::UnixMillis(1_800_000_000_000),
                conversion_permission: Permission::Write,
                admission_cap: 5,
            },
        )
        .expect("a contributory invitee key")
    }

    /// A committed set of `rows`, signed by `signer`.
    struct Set {
        scope: ChildScopeRef,
        commitment: GrantSetCommitment,
        sig: EcdsaSignature,
        ledger: Vec<GrantLedgerEntry>,
    }

    impl Set {
        fn of(rows: &[GrantRow], signer: &EcdsaSigner) -> Self {
            let commitment = GrantSetCommitment {
                ipns_name: NAME.to_vec(),
                owner_pseudonym_pk: [0x33; 32],
                cut_epoch: 0,
                entries: rows.iter().map(|r| r.commitment_entry.clone()).collect(),
                unknown: PreservedFields::new(),
            };
            let sig = sign_grant_set(signer, &commitment).expect("signable");
            Self {
                scope: ChildScopeRef::new(SCOPE, NAME.to_vec()),
                commitment,
                sig,
                ledger: rows.iter().map(|r| r.ledger_entry.clone()).collect(),
            }
        }

        fn scope(&self) -> CommittedScope<'_> {
            CommittedScope::bind(&self.scope, &self.commitment, &self.sig, &self.ledger)
                .expect("the commitment names the scope root")
        }
    }

    fn owner<'a>(identity: &'a EcdsaSigner, enc: &'a X25519Secret) -> OwnerAuthority<'a> {
        OwnerAuthority {
            identity_signer: identity,
            enc_secret: enc,
        }
    }

    #[test]
    fn an_append_adds_one_row_and_keeps_every_other() {
        let (identity, enc) = (owner_identity(), owner_enc());
        let set = Set::of(&[row(1, Permission::Read), link()], &identity);
        let edited = append_row(
            &owner(&identity, &enc),
            &set.scope(),
            row(2, Permission::Write),
        )
        .expect("the append signs");
        assert_eq!(edited.commitment.entries.len(), 3);
        assert_eq!(edited.commitment.entries[..2], set.commitment.entries[..]);
        assert_eq!(edited.ledger[..2], set.ledger[..]);
        assert!(
            cipherbox_core::seal::verify_grant_set(
                &identity.verifying_key(),
                &edited.commitment,
                &edited.commitment_sig
            )
            .is_ok()
        );
    }

    #[test]
    fn only_the_signer_of_the_set_edits_it() {
        let (identity, enc) = (owner_identity(), owner_enc());
        let stranger = EcdsaSigner::from_scalar(&[0x77; 32]).expect("valid scalar");
        let granted = row(1, Permission::Read);
        let set = Set::of(std::slice::from_ref(&granted), &stranger);
        let authority = owner(&identity, &enc);
        let name = GranteeName::new("Alice".to_owned(), NameSource::Owner).expect("a name");
        for refused in [
            append_row(&authority, &set.scope(), row(2, Permission::Read)),
            set_permission(&authority, &set.scope(), &granted.tag, Permission::Write),
            rename_grantee(&authority, &set.scope(), &granted.tag, name),
        ] {
            assert!(matches!(
                refused,
                Err(GrantEditError::Invite(InviteError::NotOwner))
            ));
        }
    }

    #[test]
    fn an_append_past_the_grant_set_ceiling_is_refused_release_active() {
        let (identity, enc) = (owner_identity(), owner_enc());
        let rows: Vec<GrantRow> = (0..MAX_GRANT_BLOBS)
            .map(|at| {
                let mut row = row(1, Permission::Read);
                row.commitment_entry.tag[..8].copy_from_slice(&(at as u64).to_be_bytes());
                row.ledger_entry.tag = row.commitment_entry.tag;
                row
            })
            .collect();
        let set = Set::of(&rows, &identity);
        assert!(matches!(
            append_row(
                &owner(&identity, &enc),
                &set.scope(),
                row(2, Permission::Read)
            ),
            Err(GrantEditError::Invite(InviteError::GrantSetFull))
        ));
    }

    #[test]
    fn a_grantee_is_found_by_an_attested_row_only() {
        let (identity, enc) = (owner_identity(), owner_enc());
        let mut forged = row(2, Permission::Read);
        forged.ledger_entry.owner_sig[0] ^= 0xff;
        let set = Set::of(&[row(1, Permission::Write), forged], &identity);
        let authority = owner(&identity, &enc);
        let held = held_row(&authority, &set.scope(), &grantee(1))
            .expect("the attested row names the grantee");
        assert_eq!(held.permission, Permission::Write);
        assert_eq!(held.kind, GrantSetEntryKind::Personal);
        assert_eq!(
            held_row(&authority, &set.scope(), &grantee(2)),
            None,
            "a row the owner did not sign names nobody"
        );
    }

    #[test]
    fn a_permission_change_moves_only_the_permission() {
        let (identity, enc) = (owner_identity(), owner_enc());
        let mut named = row(1, Permission::Read);
        named.ledger_entry.via_link = Some([0x44; 32]);
        named.ledger_entry.grantee_name =
            Some(GranteeName::new("Alice".to_owned(), NameSource::Claimant).expect("a name"));
        named.ledger_entry.owner_sig =
            sign_recipient_binding(&identity, NAME, &named.ledger_entry).to_compact();
        let set = Set::of(&[named.clone(), row(2, Permission::Read)], &identity);
        let edited = set_permission(
            &owner(&identity, &enc),
            &set.scope(),
            &named.tag,
            Permission::Write,
        )
        .expect("the upgrade signs");
        let mut expected = named.ledger_entry.clone();
        expected.permission = Permission::Write;
        assert_eq!(edited.ledger[0], expected);
        assert_eq!(edited.ledger[1], set.ledger[1]);
        assert_eq!(edited.commitment.entries[0].permission, Permission::Write);
        assert!(row_is_owner_attested(
            &identity.verifying_key(),
            &edited.ledger[0],
            NAME
        ));
    }

    #[test]
    fn a_link_permission_and_an_unchanged_permission_are_refused() {
        let (identity, enc) = (owner_identity(), owner_enc());
        let link = link();
        let granted = row(1, Permission::Read);
        let set = Set::of(&[granted.clone(), link.clone()], &identity);
        let authority = owner(&identity, &enc);
        assert!(matches!(
            set_permission(&authority, &set.scope(), &link.tag, Permission::Write),
            Err(GrantEditError::LinkRow)
        ));
        assert!(matches!(
            set_permission(&authority, &set.scope(), &granted.tag, Permission::Read),
            Err(GrantEditError::SamePermission)
        ));
        assert!(matches!(
            set_permission(&authority, &set.scope(), &[0x99; 32], Permission::Write),
            Err(GrantEditError::NotGranted)
        ));
    }

    #[test]
    fn a_rename_changes_only_the_name_and_its_source() {
        let (identity, enc) = (owner_identity(), owner_enc());
        let mut named = row(1, Permission::Read);
        named.ledger_entry.via_link = Some([0x44; 32]);
        named.ledger_entry.grantee_name =
            Some(GranteeName::new("al".to_owned(), NameSource::Claimant).expect("a name"));
        named.ledger_entry.owner_sig =
            sign_recipient_binding(&identity, NAME, &named.ledger_entry).to_compact();
        let other = row(2, Permission::Write);
        let set = Set::of(&[named.clone(), other], &identity);
        let name = GranteeName::new("Alice".to_owned(), NameSource::Owner).expect("a name");
        let edited = rename_grantee(
            &owner(&identity, &enc),
            &set.scope(),
            &named.tag,
            name.clone(),
        )
        .expect("the rename signs");

        let renamed = &edited.ledger[0];
        assert_eq!(renamed.grantee_name, Some(name));
        let mut unchanged = renamed.clone();
        unchanged.grantee_name = named.ledger_entry.grantee_name.clone();
        unchanged.owner_sig = named.ledger_entry.owner_sig;
        assert_eq!(
            unchanged, named.ledger_entry,
            "nothing else on the row moves"
        );
        assert!(row_is_owner_attested(
            &identity.verifying_key(),
            renamed,
            NAME
        ));
        assert_eq!(edited.ledger[1], set.ledger[1], "and no other row moves");
        assert_eq!(edited.commitment, set.commitment, "nor the commitment");
    }

    #[test]
    fn a_rename_of_a_link_or_an_unattested_row_is_refused() {
        let (identity, enc) = (owner_identity(), owner_enc());
        let link = link();
        let mut forged = row(2, Permission::Read);
        forged.ledger_entry.owner_sig[0] ^= 0xff;
        let set = Set::of(&[link.clone(), forged.clone()], &identity);
        let authority = owner(&identity, &enc);
        let name = || GranteeName::new("Alice".to_owned(), NameSource::Owner).expect("a name");
        assert!(matches!(
            rename_grantee(&authority, &set.scope(), &link.tag, name()),
            Err(GrantEditError::LinkRow)
        ));
        assert!(matches!(
            rename_grantee(&authority, &set.scope(), &forged.tag, name()),
            Err(GrantEditError::NotGranted)
        ));
    }
}
