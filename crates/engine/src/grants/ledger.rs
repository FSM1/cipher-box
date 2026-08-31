//! Grant ledger state, blinded-tag self-location, and owner-only authority
//! (blueprint/engine.md "Grants and ledger", #25 D1/D7, #26 D5, #39 D1).
//!
//! Grants live in the published scope root: grant blobs keyed by blinded tags,
//! the authoritative write-body ledger, and the owner-signed grant-set
//! commitment. This module composes core's codecs/KDF over those three; it mints
//! nothing (grant creation rides the rotation primitives) and holds no crypto.
//!
//! Two boundary rules it enforces:
//!
//! - **Self-location** — a recipient re-derives its own blinded tag from the
//!   pairwise ECDH of its encryption subkey with the sharer's, plus the scope
//!   root's `ipnsName`, then locates its blob by that public tag. Tags are public,
//!   so the lookup needs no constant-time guarantee.
//! - **Owner-only authority** — sharing, revoking, and every commitment change are
//!   owner-only; a write-grantee re-wraps blobs for the committed set but can
//!   neither add nor drop a tag. [`enforce_committed_ledger`] is the resolve-side
//!   check that a re-sealed ledger still matches the owner-signed committed set.

use std::collections::BTreeMap;

use cipherbox_core::kdf;
use cipherbox_core::seal::{
    GrantLedgerEntry, GrantSetCommitment, GrantSetEntry, Permission, SignedGrantBlob,
    sign_recipient_binding, verify_recipient_binding,
};
use cipherbox_core::suite::ecdsa::{
    EcdsaSigner, EcdsaVerifier, IDENTITY_PUBLIC_LEN, SIGNATURE_LEN as ECDSA_SIG_LEN,
};
use cipherbox_core::suite::secret::{SECRET_LEN, SecretBytes};
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};

use crate::seams::UnixMillis;

/// One grant blob as published in a scope root's envelope: its blinded `tag`
/// (the lookup key) and the HPKE `enc`/`ciphertext` the recipient opens. The
/// gate authenticates the blob's signature separately; this is only the
/// self-location surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedGrantBlob {
    /// The recipient's blinded tag — the public grant-section key.
    pub tag: [u8; 32],
    /// The HPKE encapsulated key.
    pub enc: [u8; 32],
    /// The HPKE ciphertext (`ciphertext || tag`).
    pub ciphertext: Vec<u8>,
}

/// Re-derive a recipient's own blinded tag from the pairwise ECDH of its
/// encryption subkey secret with the sharer's encryption subkey, plus the scope
/// root's opaque `ipnsName`. Both parties compute the identical shared secret,
/// so this reproduces the tag the owner filed the grant under.
///
/// Returns `None` on a non-contributory ECDH — a low-order sharer key that would
/// force a name-only tag; the caller treats that as an unusable sharer key.
pub fn recipient_blinded_tag(
    my_enc_secret: &X25519Secret,
    sharer_enc_pub: &X25519Public,
    scope_root_ipns_name: &[u8],
) -> Option<[u8; 32]> {
    Some(recipient_self_location(my_enc_secret, sharer_enc_pub, scope_root_ipns_name)?.1)
}

/// [`recipient_blinded_tag`] plus the pairwise secret it derived from — the one
/// ECDH a recipient needs for both its tag and its writer pseudonym, mirroring
/// the single derivation [`mint_grant_row`] makes on the owner's side.
pub fn recipient_self_location(
    my_enc_secret: &X25519Secret,
    sharer_enc_pub: &X25519Public,
    scope_root_ipns_name: &[u8],
) -> Option<(SecretBytes, [u8; 32])> {
    let shared = my_enc_secret.diffie_hellman(sharer_enc_pub)?;
    let tag = kdf::blinded_tag(shared.as_bytes(), scope_root_ipns_name);
    Some((shared, tag))
}

/// Whether the owner attested `entry`'s recipient binding at
/// `scope_root_ipns_name`.
///
/// The only owner authority over `recipientIdentityPk`, which no commitment
/// entry carries. A re-mint copies that label from an attested row and drops it
/// otherwise, rather than laundering a write-grantee's choice into the owner's
/// signature ([`mint_grant_row`]).
pub fn row_is_owner_attested(
    owner_identity: &EcdsaVerifier,
    entry: &GrantLedgerEntry,
    scope_root_ipns_name: &[u8],
) -> bool {
    verify_recipient_binding(owner_identity, scope_root_ipns_name, entry).is_ok()
}

/// Locate the grant blob filed under `tag` in a scope root's published grant
/// section. `None` at a fresh owner-signed record is the definitive
/// revocation signal (classified by [`super::revocation`]); the tag is public,
/// so a direct comparison is correct.
pub fn self_locate<'a>(
    blobs: &'a [PublishedGrantBlob],
    tag: &[u8; 32],
) -> Option<&'a PublishedGrantBlob> {
    blobs.iter().find(|b| &b.tag == tag)
}

/// [`self_locate`] over a grant section's signed blobs, for the readers that
/// hold the record itself rather than the published projection of it.
pub fn self_locate_signed<'a>(
    blobs: &'a [SignedGrantBlob],
    tag: &[u8; 32],
) -> Option<&'a SignedGrantBlob> {
    blobs.iter().find(|b| &b.tag == tag)
}

/// Whether a grant-ledger row is still live at `now` — the injected
/// [`Scheduler::now`](crate::seams::Scheduler::now) instant, never a clock this
/// layer reads. A row with no deadline never expires; one with a deadline dies
/// **at** it, not a tick later.
///
/// The predicate every reader of a resolved ledger applies, and the input the
/// discovered-expiry trigger prunes from. It decides nothing on its own — see
/// [`GrantLedgerEntry::expires_at`] for why a deadline is not a capability
/// boundary.
pub fn entry_is_live(entry: &GrantLedgerEntry, now: UnixMillis) -> bool {
    match entry.expires_at {
        Some(expires_at) => now.0 < expires_at.get(),
        None => true,
    }
}

/// The rows one grantee contributes to a scope root: the blinded tag, the entry
/// the owner signs into the grant-set commitment, and the authoritative ledger
/// row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRow {
    /// The grantee's blinded tag — the grant blob's public key in the envelope.
    pub tag: [u8; 32],
    /// The `(tag, recipientEncPk, permission, pseudonymPk)` entry for the
    /// owner-signed commitment.
    pub commitment_entry: GrantSetEntry,
    /// The authoritative ledger row.
    pub ledger_entry: GrantLedgerEntry,
}

/// The `recipientIdentityPk` a mint files when the owner cannot vouch for the
/// bytes the ledger carried. The field is a label — nothing derives from it —
/// so an owner-held re-mint that can prove `recipientEncPk` honest but not the
/// label files this rather than sign a label a write-grantee chose
/// ([`mint_grant_row`]).
pub const UNATTESTED_IDENTITY_PK: [u8; IDENTITY_PUBLIC_LEN] = [0u8; IDENTITY_PUBLIC_LEN];

/// Derive a grantee's [`GrantRow`] from the owner–recipient pairwise ECDH — the
/// one mint every grantee goes through, a contact's or an invite link's
/// ephemeral identity alike, so their tags and pseudonyms cannot drift apart.
///
/// The blinded tag binds `scope_root_ipns_name` and the writer pseudonym binds
/// `scope_id`, both off the same shared secret; the two MUST name the same scope
/// root, or the grantee derives a tag it can never self-locate. Callers derive
/// the name rather than accepting one (`create::create_grant` step 2).
///
/// A read entry's pseudonym never authorizes a structure but is derived honestly
/// so a later write upgrade stays consistent. `None` on a non-contributory ECDH —
/// a degenerate recipient key the caller refuses fail-closed.
///
/// `recipient_identity_pk` is carried into the row uninterpreted: nothing here
/// derives from it, and it is the one input a re-mint copies from a ledger row a
/// write-grantee authored, so rejecting bytes that are not a curve point would
/// hand that author a veto over the owner's own re-mint. It is still stamped
/// into the row's owner signature, so an author that alters it detaches the row
/// from the owner's authority ([`row_is_owner_attested`]) — pass
/// [`UNATTESTED_IDENTITY_PK`] where the caller cannot vouch for the bytes it
/// holds, rather than signing them.
///
/// The commitment entry masks the recipient under `pointer_read_key`, the
/// scope's stable pointer read key (see [`GrantSetEntry`]).
#[allow(clippy::too_many_arguments)]
pub fn mint_grant_row(
    owner_identity_signer: &EcdsaSigner,
    owner_enc_secret: &X25519Secret,
    pointer_read_key: &[u8; SECRET_LEN],
    recipient_identity_pk: [u8; IDENTITY_PUBLIC_LEN],
    recipient_enc_pub: &X25519Public,
    scope_id: &[u8; 16],
    scope_root_ipns_name: &[u8],
    permission: Permission,
) -> Option<GrantRow> {
    let shared = owner_enc_secret.diffie_hellman(recipient_enc_pub)?;
    let tag = kdf::blinded_tag(shared.as_bytes(), scope_root_ipns_name);
    let pseudonym_pk = kdf::pseudonym_sign(shared.as_bytes(), scope_id)
        .verifying_key()
        .to_bytes();
    let mut ledger_entry = GrantLedgerEntry::new(
        recipient_identity_pk,
        recipient_enc_pub.to_bytes(),
        permission,
        tag,
        [0u8; ECDSA_SIG_LEN],
    );
    ledger_entry.owner_sig =
        sign_recipient_binding(owner_identity_signer, scope_root_ipns_name, &ledger_entry)
            .ok()?
            .to_compact();
    Some(GrantRow {
        tag,
        commitment_entry: GrantSetEntry::new(
            pointer_read_key,
            tag,
            recipient_enc_pub.to_bytes(),
            permission,
            pseudonym_pk,
        ),
        ledger_entry,
    })
}

/// An owner-only authority violation discovered on resolve: a re-sealed
/// write-body whose grant ledger no longer matches the owner-signed committed
/// set. A write-grantee re-wraps blobs verbatim; changing the set is the owner's
/// alone, so any divergence is a trust violation surfaced to the host, never
/// silently adopted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityViolation {
    /// A stable, key-material-free description of what diverged.
    pub description: String,
}

impl AuthorityViolation {
    /// The stable classification name (host-facing, no key material).
    pub fn check(&self) -> &'static str {
        "ledger-diverges-from-commitment"
    }
}

/// The owner-committed `(tag → permission)` set — the authoritative grant set a
/// re-sealed ledger must reproduce exactly.
fn committed_permissions(commitment: &GrantSetCommitment) -> BTreeMap<[u8; 32], Permission> {
    commitment
        .entries
        .iter()
        .map(|e| (e.tag, e.permission))
        .collect()
}

/// Enforce that a write-body's grant ledger matches the owner-signed committed
/// set exactly — the owner-only-authority check on resolve. A write-grantee re-
/// seal preserves the set verbatim, so an added tag, a dropped tag, or a changed
/// permission is an [`AuthorityViolation`]. (Duplicate tags are already rejected
/// fail-closed at decode in core, so each side is a well-formed set here.)
///
/// `(tag, permission)` is the whole comparison because it is all that decides
/// authority. The owner signs each entry's `recipientEncPk` and `pseudonymPk`
/// too, and every consumer reads those off the commitment rather than off a row,
/// so a row that disagrees misdirects nothing and buys a committed writer no
/// veto over the record. `recipientIdentityPk` is under the row's own owner
/// signature ([`row_is_owner_attested`]); `expiresAt` is under none, and is not
/// a capability boundary ([`GrantLedgerEntry::expires_at`]).
pub fn enforce_committed_ledger(
    commitment: &GrantSetCommitment,
    ledger: &[GrantLedgerEntry],
) -> Result<(), AuthorityViolation> {
    let committed = committed_permissions(commitment);
    let ledgered: BTreeMap<[u8; 32], Permission> =
        ledger.iter().map(|e| (e.tag, e.permission)).collect();

    if committed == ledgered {
        return Ok(());
    }
    // Name the first concrete divergence (no key material — counts only).
    let description = if ledgered.len() != committed.len() {
        format!(
            "grant ledger has {} tags, commitment commits {}",
            ledgered.len(),
            committed.len()
        )
    } else {
        "grant ledger tag/permission set differs from the owner-signed commitment".to_string()
    };
    Err(AuthorityViolation { description })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_core::seal::{GrantSetEntry, PreservedFields};
    use core::num::NonZeroU64;

    /// The scope pointer read key every fixture masks its recipients under.
    const PRK: [u8; SECRET_LEN] = [0x66; SECRET_LEN];

    fn commitment(entries: Vec<GrantSetEntry>) -> GrantSetCommitment {
        GrantSetCommitment {
            ipns_name: b"scope-root".to_vec(),
            owner_pseudonym_pk: [0x88; 32],
            cut_epoch: 0,
            entries,
            unknown: PreservedFields::new(),
        }
    }

    fn owner_identity() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[0x66; 32]).expect("a valid identity scalar")
    }

    /// A row carrying no owner attestation — enough for the deadline and
    /// set-comparison predicates, which read neither recipient key.
    fn ledger_entry(tag: [u8; 32], permission: Permission) -> GrantLedgerEntry {
        GrantLedgerEntry::new(
            [0x02; IDENTITY_PUBLIC_LEN],
            [0x11; 32],
            permission,
            tag,
            [0u8; ECDSA_SIG_LEN],
        )
    }

    #[test]
    fn blinded_tag_is_symmetric_between_the_two_parties() {
        let owner_enc = X25519Secret::from_scalar([0x33; 32]);
        let recipient_enc = X25519Secret::from_scalar([0x44; 32]);
        let name = b"scope-root-name";

        // The recipient's self-derived tag equals what the owner would file it
        // under (owner secret ⨯ recipient public), because ECDH is symmetric.
        let recipient_side =
            recipient_blinded_tag(&recipient_enc, &owner_enc.public(), name).unwrap();
        let owner_side = recipient_blinded_tag(&owner_enc, &recipient_enc.public(), name).unwrap();
        assert_eq!(recipient_side, owner_side);
    }

    #[test]
    fn a_mint_commits_the_recipient_key_the_committed_tag_derives_from() {
        // Every consumer wraps a blob to the key the commitment entry names and
        // files it under the tag beside it, so the mint must derive both from
        // the one ECDH. A drift between them seals a grantee's blob to somebody
        // else under a tag the grantee still self-locates.
        let owner_enc = X25519Secret::from_scalar([0x33; 32]);
        let recipient = X25519Secret::from_scalar([0x44; 32]);
        let name = b"scope-root-name";

        let row = mint_grant_row(
            &owner_identity(),
            &owner_enc,
            &PRK,
            [0x02; IDENTITY_PUBLIC_LEN],
            &recipient.public(),
            &[0x07; 16],
            name,
            Permission::Read,
        )
        .expect("a contributory recipient key");

        assert_eq!(row.commitment_entry.tag, row.tag);
        assert_eq!(
            row.commitment_entry.recipient_enc_pk(&PRK),
            recipient.public().to_bytes()
        );
        assert_eq!(
            row.ledger_entry.recipient_enc_pk,
            row.commitment_entry.recipient_enc_pk(&PRK),
            "the row repeats what the owner committed"
        );
        assert_eq!(
            recipient_blinded_tag(&recipient, &owner_enc.public(), name),
            Some(row.commitment_entry.tag),
            "and the recipient self-locates under the committed tag"
        );
    }

    #[test]
    fn only_the_owner_minted_row_at_its_own_name_is_attested() {
        // The commitment carries no `recipientIdentityPk`, so the row's own
        // signature is the whole of the owner's authority over that label. It
        // needs no owner secret to read, which is
        // what lets a write-grantee re-sealer refuse a swap.
        let owner_identity = owner_identity();
        let owner_enc = X25519Secret::from_scalar([0x33; 32]);
        let victim = X25519Secret::from_scalar([0x44; 32]).public();
        let name = b"scope-root-name";

        let row = mint_grant_row(
            &owner_identity,
            &owner_enc,
            &PRK,
            [0x02; IDENTITY_PUBLIC_LEN],
            &victim,
            &[0x07; 16],
            name,
            Permission::Read,
        )
        .expect("a contributory recipient key")
        .ledger_entry;
        let verifier = owner_identity.verifying_key();
        assert!(row_is_owner_attested(&verifier, &row, name));

        let mut swapped_enc = row.clone();
        swapped_enc.recipient_enc_pk = X25519Secret::from_scalar([0x5f; 32]).public().to_bytes();
        assert!(
            !row_is_owner_attested(&verifier, &swapped_enc, name),
            "a swapped recipient key detaches the row from owner authority"
        );

        let mut swapped_identity = row.clone();
        swapped_identity.recipient_identity_pk = [0x03; IDENTITY_PUBLIC_LEN];
        assert!(
            !row_is_owner_attested(&verifier, &swapped_identity, name),
            "so does a swapped recipient identity key"
        );

        assert!(
            !row_is_owner_attested(&verifier, &row, b"another-scope-root"),
            "the name is in the preimage, so no row replays into another root"
        );

        let other_owner = EcdsaSigner::from_scalar(&[0x77; 32]).expect("a valid identity scalar");
        assert!(
            !row_is_owner_attested(&other_owner.verifying_key(), &row, name),
            "and only this vault's owner identity attests it"
        );
    }

    #[test]
    fn self_locate_finds_the_matching_blob() {
        let blobs = vec![
            PublishedGrantBlob {
                tag: [0x01; 32],
                enc: [0x0A; 32],
                ciphertext: b"a".to_vec(),
            },
            PublishedGrantBlob {
                tag: [0x02; 32],
                enc: [0x0B; 32],
                ciphertext: b"b".to_vec(),
            },
        ];
        assert_eq!(self_locate(&blobs, &[0x02; 32]).unwrap().ciphertext, b"b");
        assert!(self_locate(&blobs, &[0x03; 32]).is_none());
    }

    #[test]
    fn a_row_with_no_deadline_is_live_at_every_instant() {
        let entry = ledger_entry([0x21; 32], Permission::Read);
        assert!(entry_is_live(&entry, UnixMillis(0)));
        assert!(entry_is_live(&entry, UnixMillis(u64::MAX)));
    }

    #[test]
    fn a_deadline_row_dies_at_the_deadline_instant() {
        let mut entry = ledger_entry([0x21; 32], Permission::Read);
        entry.expires_at = NonZeroU64::new(1_000);
        assert!(entry_is_live(&entry, UnixMillis(999)));
        assert!(
            !entry_is_live(&entry, UnixMillis(1_000)),
            "dies at, not after"
        );
        assert!(!entry_is_live(&entry, UnixMillis(1_001)));
    }

    #[test]
    fn matching_ledger_passes_owner_authority() {
        let c = commitment(vec![
            GrantSetEntry::new(
                &[0x66; 32],
                [0x21; 32],
                [0x61; 32],
                Permission::Read,
                [0x02; 32],
            ),
            GrantSetEntry::new(
                &[0x66; 32],
                [0x22; 32],
                [0x62; 32],
                Permission::Write,
                [0x03; 32],
            ),
        ]);
        let ledger = vec![
            ledger_entry([0x21; 32], Permission::Read),
            ledger_entry([0x22; 32], Permission::Write),
        ];
        assert!(enforce_committed_ledger(&c, &ledger).is_ok());
    }

    #[test]
    fn write_grantee_added_tag_is_an_authority_violation() {
        // A write-grantee injects a row for a tag the owner never committed.
        let c = commitment(vec![GrantSetEntry::new(
            &[0x66; 32],
            [0x21; 32],
            [0x61; 32],
            Permission::Read,
            [0x02; 32],
        )]);
        let ledger = vec![
            ledger_entry([0x21; 32], Permission::Read),
            ledger_entry([0x77; 32], Permission::Write), // uncommitted
        ];
        let err = enforce_committed_ledger(&c, &ledger).unwrap_err();
        assert_eq!(err.check(), "ledger-diverges-from-commitment");
    }

    #[test]
    fn changed_permission_is_an_authority_violation() {
        let c = commitment(vec![GrantSetEntry::new(
            &[0x66; 32],
            [0x21; 32],
            [0x61; 32],
            Permission::Read,
            [0x02; 32],
        )]);
        let ledger = vec![ledger_entry([0x21; 32], Permission::Write)]; // upgraded self
        assert!(enforce_committed_ledger(&c, &ledger).is_err());
    }

    #[test]
    fn dropped_tag_is_an_authority_violation() {
        let c = commitment(vec![
            GrantSetEntry::new(
                &[0x66; 32],
                [0x21; 32],
                [0x61; 32],
                Permission::Read,
                [0x02; 32],
            ),
            GrantSetEntry::new(
                &[0x66; 32],
                [0x22; 32],
                [0x62; 32],
                Permission::Write,
                [0x03; 32],
            ),
        ]);
        let ledger = vec![ledger_entry([0x21; 32], Permission::Read)]; // dropped 0x22
        assert!(enforce_committed_ledger(&c, &ledger).is_err());
    }
}
