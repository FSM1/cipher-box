//! The rows one owner revoke removes, read off the owner-signed set
//! ([ADR 0025](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0025-revocation-under-the-link-first-model.md)
//! D1, D3, D4), and the links the expired-link sweep cuts (D2).
//!
//! A grantee is found by the owner-attested ledger rows that name the
//! identity, so any owner device revokes. A row with no attested label is
//! found the way the sharing read labels it: by the committed
//! `recipientEncPk` of the one contact that holds it.

use std::collections::BTreeSet;

use cipherbox_core::seal::{GrantLedgerEntry, GrantSetEntry, GrantSetEntryKind};
use cipherbox_core::suite::ecdsa::{EcdsaVerifier, IDENTITY_PUBLIC_LEN};
use cipherbox_core::suite::secret::SECRET_LEN;

use super::contact_store::LinkSource;
use super::invite::{CommittedLink, CommittedScope, InviteError, OwnerAuthority, committed_links};
use super::ledger::{UNATTESTED_IDENTITY_PK, row_is_owner_attested};
use crate::seams::UnixMillis;

/// The personal entry `scope` commits under `tag`.
fn personal_entry<'a>(scope: &CommittedScope<'a>, tag: &[u8; 32]) -> Option<&'a GrantSetEntry> {
    scope
        .commitment
        .entries
        .iter()
        .find(|entry| entry.tag == *tag && entry.kind == GrantSetEntryKind::Personal)
}

/// Whether `row` is owner-attested and `scope` commits its tag as a personal
/// entry.
fn committed_personal(
    owner_identity: &EcdsaVerifier,
    scope: &CommittedScope<'_>,
    row: &GrantLedgerEntry,
) -> bool {
    row_is_owner_attested(owner_identity, row, scope.commitment.ipns_name.as_slice())
        && personal_entry(scope, &row.tag).is_some()
}

/// Every personal row `scope` commits for `identity_pk`. One identity can hold
/// rows under more than one tag.
pub fn committed_grantee<'a>(
    owner: &OwnerAuthority<'_>,
    scope: &CommittedScope<'a>,
    identity_pk: &[u8; IDENTITY_PUBLIC_LEN],
) -> Result<Vec<&'a GrantLedgerEntry>, InviteError> {
    owner.authorise(scope)?;
    let owner_identity = owner.identity_signer.verifying_key();
    Ok(scope
        .ledger
        .iter()
        .filter(|row| {
            row.recipient_identity_pk == *identity_pk
                && committed_personal(&owner_identity, scope, row)
        })
        .collect())
}

/// The person a revoke names.
pub struct RevokedPerson<'a> {
    /// The identity key the revoke names.
    pub identity_pk: &'a [u8; IDENTITY_PUBLIC_LEN],
    /// Every encryption subkey this device's contact book binds to the
    /// identity, now or before, and to no other contact. Each reaches a row
    /// whose label the owner does not attest.
    pub contact_enc_pks: Vec<[u8; SECRET_LEN]>,
    /// Unmasks each committed entry's `recipientEncPk`.
    pub pointer_read_key: &'a [u8; SECRET_LEN],
}

/// Every personal row `scope` commits for `person`, each with whether the
/// owner attests the row. A row the owner attests under a real label names
/// that label only.
fn revoked_rows<'a>(
    owner_identity: &EcdsaVerifier,
    scope: &CommittedScope<'a>,
    person: &RevokedPerson<'_>,
) -> Vec<(&'a GrantLedgerEntry, bool)> {
    let name = scope.commitment.ipns_name.as_slice();
    scope
        .ledger
        .iter()
        .filter_map(|row| {
            let entry = personal_entry(scope, &row.tag)?;
            let attested = row_is_owner_attested(owner_identity, row, name);
            let names = if attested && row.recipient_identity_pk != UNATTESTED_IDENTITY_PK {
                row.recipient_identity_pk == *person.identity_pk
            } else {
                person
                    .contact_enc_pks
                    .contains(&entry.recipient_enc_pk(person.pointer_read_key))
            };
            names.then_some((row, attested))
        })
        .collect()
}

/// The cut set of a grantee revoke: every row of the grantee and each
/// committed link a via-link reference of those rows names (ADR 0024 D3).
pub struct GranteeCut {
    /// Every tag the revoke removes.
    pub tags: BTreeSet<[u8; 32]>,
    /// The links that admitted the grantee, when the set still commits them.
    pub admitting_links: Vec<CommittedLink>,
}

/// The rows a revoke of `person` removes from `scope`. `None` when `scope`
/// commits no personal row for `person`.
///
/// Only an attested row's via-link reference is the owner's word, so only
/// that reference adds its link to the cut.
pub fn grantee_cut_set(
    owner: &OwnerAuthority<'_>,
    scope: &CommittedScope<'_>,
    person: &RevokedPerson<'_>,
) -> Result<Option<GranteeCut>, InviteError> {
    owner.authorise(scope)?;
    let rows = revoked_rows(&owner.identity_signer.verifying_key(), scope, person);
    if rows.is_empty() {
        return Ok(None);
    }
    let admitted: Vec<[u8; 32]> = rows
        .iter()
        .filter(|(_, attested)| *attested)
        .filter_map(|(row, _)| row.via_link)
        .collect();
    let admitting_links: Vec<CommittedLink> = if admitted.is_empty() {
        Vec::new()
    } else {
        committed_links(owner, scope)?
            .into_iter()
            .filter(|link| admitted.contains(&link.tag))
            .collect()
    };
    let tags = rows
        .iter()
        .map(|(row, _)| row.tag)
        .chain(admitting_links.iter().map(|link| link.tag))
        .collect();
    Ok(Some(GranteeCut {
        tags,
        admitting_links,
    }))
}

/// The owner's contact book as a link revoke reads it (ADR 0025 D1).
pub struct LinkSources<'a> {
    /// Each contact's encryption subkey with the link that sourced it, `None`
    /// for one the owner imported or granted directly.
    pub contacts: &'a [([u8; SECRET_LEN], Option<LinkSource>)],
    /// Unmasks each committed entry's `recipientEncPk`.
    pub pointer_read_key: &'a [u8; SECRET_LEN],
}

impl LinkSources<'_> {
    /// The encryption subkeys of the contacts `link` sourced, each bound to
    /// that contact only.
    fn joined_through(&self, link: &CommittedLink) -> Vec<[u8; SECRET_LEN]> {
        self.contacts
            .iter()
            .filter(|(enc, source)| {
                source.is_some_and(|source| source.names(link))
                    && self.contacts.iter().filter(|(held, _)| held == enc).count() == 1
            })
            .map(|(enc, _)| *enc)
            .collect()
    }
}

/// The rows a revoke of `link` removes from `scope`: the link row, and with
/// `remove_grantees` every committed personal row of a person who joined
/// through it (ADR 0025 D1).
///
/// A row whose via-link reference names the link counts even when its writer
/// broke the owner's signature: a write grantee who breaks its own row must
/// not keep a grant the owner removes. A row with no attested label also
/// counts when its committed `recipientEncPk` names a contact the link
/// sourced, so a write grantee that strips its via-link reference is still
/// found, before and after a wave re-mints the row. The cut can only grow.
pub fn link_cut_set(
    owner: &OwnerAuthority<'_>,
    scope: &CommittedScope<'_>,
    link: &CommittedLink,
    remove_grantees: Option<&LinkSources<'_>>,
) -> Result<BTreeSet<[u8; 32]>, InviteError> {
    owner.authorise(scope)?;
    let mut tags = BTreeSet::from([link.tag]);
    let Some(book) = remove_grantees else {
        return Ok(tags);
    };
    let owner_identity = owner.identity_signer.verifying_key();
    let name = scope.commitment.ipns_name.as_slice();
    let joined = book.joined_through(link);
    tags.extend(
        scope
            .ledger
            .iter()
            .filter(|row| {
                personal_entry(scope, &row.tag).is_some_and(|entry| {
                    let unlabelled = !row_is_owner_attested(&owner_identity, row, name)
                        || row.recipient_identity_pk == UNATTESTED_IDENTITY_PK;
                    row.via_link == Some(link.tag)
                        || (unlabelled
                            && joined.contains(&entry.recipient_enc_pk(book.pointer_read_key)))
                })
            })
            .map(|row| row.tag),
    );
    Ok(tags)
}

/// The links among `links` whose deadline `now` has reached, less every link
/// whose ephemeral identity sends a claim in `pending` (see the conversion
/// pass's `Running`).
pub fn expired_links(
    links: &[CommittedLink],
    now: UnixMillis,
    pending: &[[u8; IDENTITY_PUBLIC_LEN]],
) -> BTreeSet<[u8; 32]> {
    links
        .iter()
        .filter(|link| link.is_expired(now) && !pending.contains(&link.ephemeral_identity_pk))
        .map(|link| link.tag)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::invite::{EphemeralInvitee, LinkTerms, mint_invite_grant};
    use crate::grants::ledger::{GrantRow, mint_grant_row};
    use crate::rotation::derive_write_name;
    use cipherbox_core::seal::{
        GrantSetCommitment, Permission, PreservedFields, sign_grant_set, sign_recipient_binding,
    };
    use cipherbox_core::suite::ecdsa::{EcdsaSignature, EcdsaSigner};
    use cipherbox_core::suite::x25519::X25519Secret;

    const SCOPE: [u8; 16] = [0x01; 16];
    const WRITE_SCOPE_SEED: [u8; 32] = [0x5a; 32];
    const PRK: [u8; 32] = [0x66; 32];

    fn name() -> Vec<u8> {
        derive_write_name(&WRITE_SCOPE_SEED, &SCOPE)
            .as_str()
            .as_bytes()
            .to_vec()
    }

    struct Fixture {
        owner: EcdsaSigner,
        enc: X25519Secret,
        commitment: GrantSetCommitment,
        sig: EcdsaSignature,
        ledger: Vec<GrantLedgerEntry>,
        link: [u8; 32],
    }

    fn person(owner: &EcdsaSigner, enc: &X25519Secret, seed: u8) -> GrantRow {
        mint_grant_row(
            owner,
            enc,
            &PRK,
            [seed; 33],
            &X25519Secret::from_scalar([seed; 32]).public(),
            &SCOPE,
            &name(),
            Permission::Read,
        )
        .expect("a contributory key")
    }

    /// Joined through `link`, under the owner's row signature.
    fn joined(owner: &EcdsaSigner, mut row: GrantRow, link: [u8; 32]) -> GrantRow {
        row.ledger_entry.via_link = Some(link);
        row.ledger_entry.owner_sig =
            sign_recipient_binding(owner, &name(), &row.ledger_entry).to_compact();
        row
    }

    impl Fixture {
        /// A link, two people who joined through it, and one granted directly.
        fn new() -> Self {
            let owner = EcdsaSigner::from_scalar(&[0x33; 32]).unwrap();
            let enc = X25519Secret::from_scalar([0x5b; 32]);
            let invitee = EphemeralInvitee::from_secret(&[0x95; 32]).unwrap();
            let link = mint_invite_grant(
                &owner,
                &enc,
                &PRK,
                &invitee,
                &SCOPE,
                &WRITE_SCOPE_SEED,
                &LinkTerms {
                    deadline: UnixMillis(1_000),
                    conversion_permission: Permission::Read,
                    admission_cap: 5,
                },
            )
            .unwrap();
            let rows = [
                joined(&owner, person(&owner, &enc, 0x11), link.tag),
                joined(&owner, person(&owner, &enc, 0x12), link.tag),
                person(&owner, &enc, 0x13),
            ];
            let link_tag = link.tag;
            let all: Vec<GrantRow> = rows.into_iter().chain([link]).collect();
            let commitment = GrantSetCommitment {
                ipns_name: name(),
                owner_pseudonym_pk: [0x88; 32],
                cut_epoch: 0,
                entries: all.iter().map(|r| r.commitment_entry.clone()).collect(),
                unknown: PreservedFields::new(),
            };
            let sig = sign_grant_set(&owner, &commitment).unwrap();
            Self {
                owner,
                enc,
                commitment,
                sig,
                ledger: all.into_iter().map(|r| r.ledger_entry).collect(),
                link: link_tag,
            }
        }

        fn authority(&self) -> OwnerAuthority<'_> {
            OwnerAuthority {
                identity_signer: &self.owner,
                enc_secret: &self.enc,
            }
        }

        fn scope(&self) -> CommittedScope<'_> {
            CommittedScope {
                scope_id: &SCOPE,
                commitment: &self.commitment,
                commitment_sig: &self.sig,
                ledger: &self.ledger,
            }
        }

        fn tag_of(&self, seed: u8) -> [u8; 32] {
            self.ledger
                .iter()
                .find(|row| row.recipient_identity_pk == [seed; 33])
                .unwrap()
                .tag
        }

        fn committed_link(&self) -> CommittedLink {
            committed_links(&self.authority(), &self.scope()).unwrap()[0]
        }
    }

    /// The person `identity_pk` names, with no contact on this device.
    fn named(identity_pk: &[u8; IDENTITY_PUBLIC_LEN]) -> RevokedPerson<'_> {
        RevokedPerson {
            identity_pk,
            contact_enc_pks: Vec::new(),
            pointer_read_key: &PRK,
        }
    }

    /// The encryption subkey [`person`] grants for `seed`.
    fn enc_pk(seed: u8) -> [u8; SECRET_LEN] {
        X25519Secret::from_scalar([seed; 32]).public().to_bytes()
    }

    /// The person `identity_pk` names, held as a contact under the encryption
    /// subkey [`person`] granted for `seed`.
    fn contact(identity_pk: &[u8; IDENTITY_PUBLIC_LEN], seed: u8) -> RevokedPerson<'_> {
        RevokedPerson {
            contact_enc_pks: vec![enc_pk(seed)],
            ..named(identity_pk)
        }
    }

    /// A contact book that holds no contact.
    fn no_book() -> LinkSources<'static> {
        LinkSources {
            contacts: &[],
            pointer_read_key: &PRK,
        }
    }

    fn admitted(cut: &GranteeCut) -> Vec<[u8; 32]> {
        cut.admitting_links.iter().map(|link| link.tag).collect()
    }

    #[test]
    fn a_grantee_revoke_also_cuts_the_link_that_admitted_the_grantee() {
        let fx = Fixture::new();
        let cut = grantee_cut_set(&fx.authority(), &fx.scope(), &named(&[0x11; 33]))
            .unwrap()
            .expect("the grantee holds a row");
        assert_eq!(cut.tags, BTreeSet::from([fx.tag_of(0x11), fx.link]));
        assert_eq!(admitted(&cut), vec![fx.link]);
    }

    #[test]
    fn a_grantee_granted_directly_cuts_only_the_own_row() {
        let fx = Fixture::new();
        let cut = grantee_cut_set(&fx.authority(), &fx.scope(), &named(&[0x13; 33]))
            .unwrap()
            .expect("the grantee holds a row");
        assert_eq!(cut.tags, BTreeSet::from([fx.tag_of(0x13)]));
        assert!(cut.admitting_links.is_empty());
    }

    #[test]
    fn a_grantee_with_two_rows_loses_both_in_one_cut() {
        let mut fx = Fixture::new();
        let mut second = person(&fx.owner, &fx.enc, 0x21);
        second.ledger_entry.recipient_identity_pk = [0x13; 33];
        second.ledger_entry.owner_sig =
            sign_recipient_binding(&fx.owner, &name(), &second.ledger_entry).to_compact();
        fx.commitment.entries.push(second.commitment_entry);
        fx.sig = sign_grant_set(&fx.owner, &fx.commitment).unwrap();
        let second_tag = second.ledger_entry.tag;
        fx.ledger.push(second.ledger_entry);

        assert_eq!(
            committed_grantee(&fx.authority(), &fx.scope(), &[0x13; 33])
                .unwrap()
                .len(),
            2
        );
        let cut = grantee_cut_set(&fx.authority(), &fx.scope(), &named(&[0x13; 33]))
            .unwrap()
            .expect("the grantee holds rows");
        assert_eq!(cut.tags, BTreeSet::from([fx.tag_of(0x13), second_tag]));
    }

    #[test]
    fn a_row_the_owner_did_not_sign_names_nobody() {
        let mut fx = Fixture::new();
        for row in &mut fx.ledger {
            if row.recipient_identity_pk == [0x13; 33] {
                row.owner_sig = [0u8; 64];
            }
        }
        assert!(
            grantee_cut_set(&fx.authority(), &fx.scope(), &named(&[0x13; 33]))
                .unwrap()
                .is_none()
        );
        assert!(
            grantee_cut_set(&fx.authority(), &fx.scope(), &named(&[0x77; 33]))
                .unwrap()
                .is_none(),
            "nor does an identity the set never held"
        );
    }

    /// A write grantee authors the ledger, so it can break its own row's
    /// owner signature. The committed `recipientEncPk` still names the
    /// contact, as the sharing read labels the row.
    #[test]
    fn a_row_with_no_attested_label_is_reached_through_the_contacts_committed_key() {
        let mut fx = Fixture::new();
        let tag = fx.tag_of(0x13);
        for row in &mut fx.ledger {
            if row.tag == tag {
                row.recipient_identity_pk = [0x77; 33];
            }
        }
        assert!(
            grantee_cut_set(&fx.authority(), &fx.scope(), &named(&[0x13; 33]))
                .unwrap()
                .is_none(),
            "the rewritten label names nobody on its own"
        );
        let cut = grantee_cut_set(&fx.authority(), &fx.scope(), &contact(&[0x13; 33], 0x13))
            .unwrap()
            .expect("the committed key names the contact");
        assert_eq!(cut.tags, BTreeSet::from([tag]));
        assert!(
            grantee_cut_set(&fx.authority(), &fx.scope(), &contact(&[0x77; 33], 0x77))
                .unwrap()
                .is_none(),
            "and the label the writer chose names nobody"
        );
    }

    /// A person who rotated the encryption subkey holds an attested row under
    /// the new key and a stripped row under the former key. One revoke takes
    /// both rows.
    #[test]
    fn a_person_revoke_reaches_a_stripped_row_under_a_former_subkey() {
        let mut fx = Fixture::new();
        let attested = fx.tag_of(0x13);
        let mut stripped = person(&fx.owner, &fx.enc, 0x21);
        stripped.ledger_entry.recipient_identity_pk = [0x13; 33];
        fx.commitment.entries.push(stripped.commitment_entry);
        fx.sig = sign_grant_set(&fx.owner, &fx.commitment).unwrap();
        let stripped_tag = stripped.ledger_entry.tag;
        fx.ledger.push(stripped.ledger_entry);

        let current_only =
            grantee_cut_set(&fx.authority(), &fx.scope(), &contact(&[0x13; 33], 0x13))
                .unwrap()
                .expect("the attested row names the person");
        assert_eq!(current_only.tags, BTreeSet::from([attested]));

        let person = RevokedPerson {
            contact_enc_pks: vec![enc_pk(0x13), enc_pk(0x21)],
            ..named(&[0x13; 33])
        };
        let cut = grantee_cut_set(&fx.authority(), &fx.scope(), &person)
            .unwrap()
            .expect("the person holds rows");
        assert_eq!(cut.tags, BTreeSet::from([attested, stripped_tag]));
    }

    /// An unattested row's via-link reference is not the owner's word, so it
    /// adds no link to a person revoke.
    #[test]
    fn an_unattested_via_link_reference_cuts_no_link() {
        let mut fx = Fixture::new();
        for row in &mut fx.ledger {
            if row.recipient_identity_pk == [0x11; 33] {
                row.owner_sig = [0u8; 64];
            }
        }
        let cut = grantee_cut_set(&fx.authority(), &fx.scope(), &contact(&[0x11; 33], 0x11))
            .unwrap()
            .expect("the committed key names the contact");
        assert_eq!(cut.tags, BTreeSet::from([fx.tag_of(0x11)]));
        assert!(cut.admitting_links.is_empty());
    }

    /// The owner attests the label of a row, so the contact key of another
    /// person never reaches it.
    #[test]
    fn a_contact_key_never_reaches_a_row_attested_to_another_person() {
        let fx = Fixture::new();
        let mut person = contact(&[0x77; 33], 0x13);
        assert!(
            grantee_cut_set(&fx.authority(), &fx.scope(), &person)
                .unwrap()
                .is_none()
        );
        person.identity_pk = &[0x13; 33];
        assert!(
            grantee_cut_set(&fx.authority(), &fx.scope(), &person)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn a_link_revoke_with_remove_grantees_takes_a_row_its_writer_broke() {
        let mut fx = Fixture::new();
        for row in &mut fx.ledger {
            if row.recipient_identity_pk == [0x11; 33] {
                row.recipient_identity_pk = [0x77; 33];
            }
        }
        assert_eq!(
            link_cut_set(
                &fx.authority(),
                &fx.scope(),
                &fx.committed_link(),
                Some(&no_book())
            )
            .unwrap(),
            BTreeSet::from([fx.link, fx.tag_of(0x77), fx.tag_of(0x12)]),
        );
    }

    /// A write grantee that strips its via-link reference breaks the owner's
    /// signature over its row. The contact book still names the link that
    /// sourced the contact, so the link revoke still takes the row.
    #[test]
    fn a_link_revoke_with_remove_grantees_takes_a_row_whose_via_link_its_writer_stripped() {
        let mut fx = Fixture::new();
        for row in &mut fx.ledger {
            if row.recipient_identity_pk == [0x11; 33] {
                row.via_link = None;
            }
        }
        let enc = |seed: u8| X25519Secret::from_scalar([seed; 32]).public().to_bytes();
        let link = fx.committed_link();
        assert_eq!(
            link_cut_set(&fx.authority(), &fx.scope(), &link, Some(&no_book())).unwrap(),
            BTreeSet::from([fx.link, fx.tag_of(0x12)]),
            "the stripped row names the link nowhere in the ledger"
        );
        let source = Some(LinkSource::Identity(link.ephemeral_identity_pk));
        let contacts = [(enc(0x11), source), (enc(0x12), source), (enc(0x13), None)];
        let book = LinkSources {
            contacts: &contacts,
            pointer_read_key: &PRK,
        };
        assert_eq!(
            link_cut_set(&fx.authority(), &fx.scope(), &link, Some(&book)).unwrap(),
            BTreeSet::from([fx.link, fx.tag_of(0x11), fx.tag_of(0x12)]),
            "the contact the link sourced names the row, and the direct grantee stays"
        );
        let shared = [(enc(0x11), source), (enc(0x11), None)];
        let ambiguous = LinkSources {
            contacts: &shared,
            pointer_read_key: &PRK,
        };
        assert_eq!(
            link_cut_set(&fx.authority(), &fx.scope(), &link, Some(&ambiguous)).unwrap(),
            BTreeSet::from([fx.link, fx.tag_of(0x12)]),
            "a subkey two contacts bind names nobody"
        );
    }

    #[test]
    fn a_link_revoke_keeps_the_grantees_unless_the_owner_asks() {
        let fx = Fixture::new();
        let link = fx.committed_link();
        assert_eq!(
            link_cut_set(&fx.authority(), &fx.scope(), &link, None).unwrap(),
            BTreeSet::from([fx.link])
        );
        assert_eq!(
            link_cut_set(&fx.authority(), &fx.scope(), &link, Some(&no_book())).unwrap(),
            BTreeSet::from([fx.link, fx.tag_of(0x11), fx.tag_of(0x12)]),
            "remove_grantees adds every grantee who joined through the link, and no one else"
        );
    }

    #[test]
    fn a_stranger_cannot_read_a_cut_set() {
        let fx = Fixture::new();
        let stranger = EcdsaSigner::from_scalar(&[0x44; 32]).unwrap();
        let authority = OwnerAuthority {
            identity_signer: &stranger,
            enc_secret: &fx.enc,
        };
        assert!(grantee_cut_set(&authority, &fx.scope(), &named(&[0x11; 33])).is_err());
        assert!(
            link_cut_set(
                &authority,
                &fx.scope(),
                &fx.committed_link(),
                Some(&no_book())
            )
            .is_err()
        );
    }

    #[test]
    fn the_sweep_takes_a_link_at_its_deadline_and_never_one_with_a_pending_claim() {
        let fx = Fixture::new();
        let link = fx.committed_link();
        assert!(expired_links(&[link], UnixMillis(999), &[]).is_empty());
        assert_eq!(
            expired_links(&[link], UnixMillis(1_000), &[]),
            BTreeSet::from([fx.link])
        );
        assert!(
            expired_links(&[link], UnixMillis(5_000), &[link.ephemeral_identity_pk]).is_empty()
        );
    }
}
