//! Grant ledger state, blinded-tag self-location, and owner-only authority
//! (blueprint/engine.md "Grants and ledger", #25 D1/D7, #26 D5, #39 D1).
//!
//! Grants live in the published scope root: grant blobs keyed by blinded tags,
//! the authoritative write-body ledger, and the epoch-free owner-signed grant-set
//! commitment. This module composes core's codecs/KDF over those three; it mints
//! nothing (grant creation rides the #635 rotation primitives) and holds no crypto.
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
use cipherbox_core::seal::{GrantLedgerEntry, GrantSetCommitment, Permission};
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};

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
    let shared = my_enc_secret.diffie_hellman(sharer_enc_pub)?;
    Some(kdf::blinded_tag(shared.as_bytes(), scope_root_ipns_name))
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
    use cipherbox_core::seal::GrantSetEntry;
    use cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN;

    fn commitment(entries: Vec<GrantSetEntry>) -> GrantSetCommitment {
        GrantSetCommitment {
            ipns_name: b"scope-root".to_vec(),
            owner_pseudonym_pk: [0x88; 32],
            entries,
            unknown: Vec::new(),
        }
    }

    fn ledger_entry(tag: [u8; 32], permission: Permission) -> GrantLedgerEntry {
        GrantLedgerEntry::new([0x02; IDENTITY_PUBLIC_LEN], [0x11; 32], permission, tag)
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
    fn matching_ledger_passes_owner_authority() {
        let c = commitment(vec![
            GrantSetEntry::new([0x21; 32], Permission::Read, [0x02; 32]),
            GrantSetEntry::new([0x22; 32], Permission::Write, [0x03; 32]),
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
            [0x21; 32],
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
            [0x21; 32],
            Permission::Read,
            [0x02; 32],
        )]);
        let ledger = vec![ledger_entry([0x21; 32], Permission::Write)]; // upgraded self
        assert!(enforce_committed_ledger(&c, &ledger).is_err());
    }

    #[test]
    fn dropped_tag_is_an_authority_violation() {
        let c = commitment(vec![
            GrantSetEntry::new([0x21; 32], Permission::Read, [0x02; 32]),
            GrantSetEntry::new([0x22; 32], Permission::Write, [0x03; 32]),
        ]);
        let ledger = vec![ledger_entry([0x21; 32], Permission::Read)]; // dropped 0x22
        assert!(enforce_committed_ledger(&c, &ledger).is_err());
    }
}
