//! Invite links — the ephemeral-key grant blob (blueprint/engine.md "Grants and
//! ledger: Invites", #25 D6).
//!
//! An invite is an ordinary grant wrapped to a throwaway identity instead of a
//! contact's. [`EphemeralInvitee`] derives that identity from one random invite
//! secret the way [`SessionIdentity`](crate::session::SessionIdentity) derives a
//! real one from a login secret — the secp256k1 scalar adopted directly, the
//! X25519 sealing half through the frozen `enc-subkey` edge — and then mints
//! through the same [`mint_grant_row`] every contact does. So on the envelope
//! surface — blinded tag, commitment entry, and the grant blob
//! [`reseal_scope_root`](crate::rotation::reseal_scope_root) wraps — an invite is
//! byte-shaped like a personal grantee's and an observer learns only blob count.
//! (The sealed write-body is longer by a row that carries a deadline; that
//! ciphertext length is the residual observable.)
//!
//! The invite secret is the whole capability — it rides the link's URL fragment,
//! so the link is honestly bearer and multi-claim. Its deadline lives on
//! [`GrantLedgerEntry::expires_at`], which states what a deadline does and does
//! not guarantee.

use cipherbox_core::seal::Permission;
use cipherbox_core::suite::ecdsa::{EcdsaSigner, EcdsaVerifier};
use cipherbox_core::suite::secret::{SECRET_LEN, SecretBytes};
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};
use cipherbox_core::{ipns::IpnsName, kdf};
use core::fmt;
use core::num::NonZeroU64;
use zeroize::Zeroizing;

use crate::entropy::{Entropy, EntropyError};
use crate::grants::{GrantRow, mint_grant_row};
use crate::rotation::derive_write_name;
use crate::seams::UnixMillis;

/// The throwaway identity an invite link's grant is wrapped to.
///
/// Every half derives from `secret` — the bearer capability the URL fragment
/// carries. Deliberately not `Clone`, like its
/// [`SessionIdentity`](crate::session::SessionIdentity) sibling: a second handle
/// is a second copy of the capability, and [`Self::from_secret`] re-derives one
/// losslessly when a claim genuinely needs it.
///
/// Being structurally a login identity is what buys the byte-shape parity, and it
/// cuts both ways: its holder can sign a login challenge like any keypair owner,
/// so a ledger's `recipientIdentityPk` is not a contact-anchored identity. Mint
/// one per scope — reusing an invitee across scopes gives distinct tags but a
/// ledger row that links the two grants to one link.
#[derive(Debug)]
pub struct EphemeralInvitee {
    secret: SecretBytes,
    identity: EcdsaSigner,
    enc_subkey: X25519Secret,
}

/// A fail-closed invite failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteError {
    /// Entropy acquisition failed; no invite is minted without fresh randomness.
    Entropy(EntropyError),
    /// The invite secret is not a valid secp256k1 scalar, so it has no ephemeral
    /// identity to commit — refused rather than derived to a silent default.
    InvalidSecret,
    /// The owner–invitee ECDH is non-contributory, so no blinded tag binds the
    /// grant to this link.
    UnusableInviteeKey,
    /// The deadline was `0`. Refused rather than mapped to "no deadline", which
    /// would silently mint a link that never expires
    /// ([`Malformed::InvalidExpiry`](cipherbox_core::error::Malformed::InvalidExpiry)).
    InvalidExpiry,
}

impl InviteError {
    /// A stable, key-material-free classification name (host/log facing).
    pub fn check(&self) -> &'static str {
        match self {
            Self::Entropy(_) => "entropy-error",
            Self::InvalidSecret => "invalid-invite-secret",
            Self::UnusableInviteeKey => "unusable-invitee-key",
            Self::InvalidExpiry => "invalid-expiry",
        }
    }
}

impl fmt::Display for InviteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invite failed: {}", self.check())
    }
}

impl std::error::Error for InviteError {}

impl EphemeralInvitee {
    /// Mint a fresh ephemeral identity from the injected entropy seam.
    ///
    /// Fails closed on an entropy error, and on the ~2^-128 chance that the
    /// sampled bytes are zero or at least the secp256k1 group order — never by
    /// re-sampling until one lands, which would make the entropy each mint draws
    /// variable and desynchronize every downstream draw from the same seam.
    pub fn mint<E: Entropy>(entropy: &mut E) -> Result<Self, InviteError> {
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        entropy
            .fill(secret.as_mut_slice())
            .map_err(InviteError::Entropy)?;
        Self::from_secret(&secret)
    }

    /// Reconstruct the ephemeral identity from a link fragment's invite secret.
    /// Fails closed ([`InviteError::InvalidSecret`]) when the bytes are not a
    /// valid secp256k1 scalar.
    ///
    /// Copies `secret` into its own zeroizing owner; wiping the caller's buffer
    /// stays the caller's job (they are its terminal owner).
    pub fn from_secret(secret: &[u8; SECRET_LEN]) -> Result<Self, InviteError> {
        let identity = EcdsaSigner::from_scalar(secret).ok_or(InviteError::InvalidSecret)?;
        Ok(Self {
            secret: SecretBytes::new(*secret),
            identity,
            enc_subkey: kdf::enc_subkey(secret),
        })
    }

    /// The invite secret the link's URL fragment carries — the bearer
    /// capability. Secret-bearing.
    pub fn secret(&self) -> &SecretBytes {
        &self.secret
    }

    /// The ephemeral compressed secp256k1 identity key committed in the ledger
    /// row; a claim's signature is verified against it.
    pub fn identity_pk(&self) -> EcdsaVerifier {
        self.identity.verifying_key()
    }

    /// The ephemeral X25519 public half the grant blob is HPKE-sealed to.
    pub fn enc_public(&self) -> X25519Public {
        self.enc_subkey.public()
    }

    /// The ephemeral sealing secret a link holder opens its grant blob with.
    /// Secret-bearing.
    pub fn enc_secret(&self) -> &X25519Secret {
        &self.enc_subkey
    }
}

/// Mint an invite link's [`GrantRow`] over the scope root at `scope_id`.
///
/// Owner-only by construction: it takes the owner's encryption subkey secret for
/// the pairwise ECDH, and only the owner's identity signature over the resulting
/// commitment authorises the set. The scope root's `ipnsName` is **derived** from
/// `write_scope_seed`, never accepted as input — the tag binds that name and the
/// link holder re-derives it from the record it resolves, so binding anything but
/// the real resolvable name would mint a link nobody can self-locate.
pub fn mint_invite_grant(
    owner_enc_secret: &X25519Secret,
    invitee: &EphemeralInvitee,
    scope_id: &[u8; 16],
    write_scope_seed: &[u8; SECRET_LEN],
    permission: Permission,
    expires_at: Option<UnixMillis>,
) -> Result<GrantRow, InviteError> {
    let expires_at = match expires_at {
        Some(deadline) => Some(NonZeroU64::new(deadline.0).ok_or(InviteError::InvalidExpiry)?),
        None => None,
    };
    let ipns_name: IpnsName = derive_write_name(write_scope_seed, scope_id);
    let mut row = mint_grant_row(
        owner_enc_secret,
        &invitee.identity_pk(),
        &invitee.enc_public(),
        scope_id,
        ipns_name.as_str().as_bytes(),
        permission,
    )
    .ok_or(InviteError::UnusableInviteeKey)?;
    row.ledger_entry.expires_at = expires_at;
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::{
        PublishedGrantBlob, enforce_committed_ledger, entry_is_live, recipient_blinded_tag,
        self_locate,
    };
    use crate::rotation::{
        CommittedSet, ResealError, ResealSeeds, ScopeRootIdentity, reseal_scope_root,
    };
    use crate::testkit::SeededEntropy;
    use cipherbox_core::seal::{
        AadContext, GrantLedgerEntry, GrantSection, GrantSetCommitment, PreservedFields,
        STRUCT_TAG_GRANT_BLOB, SignedGrantBlob, StructureSigInput, encode_grant_section,
        open_grant_blob, sign_grant_set, verify_structure,
    };
    use cipherbox_core::suite::ed25519::{Ed25519Signature, Ed25519Signer};
    use cipherbox_core::suite::secret::ct_eq;

    const V: u64 = 2;
    const SCOPE: [u8; 16] = [0x5c; 16];
    const EPOCH: u64 = 5;
    const OVERRIDE_SEED: [u8; 32] = [0x99; 32];
    const WRITE_SCOPE_SEED: [u8; 32] = [0x55; 32];
    const POINTER_READ_KEY: [u8; 32] = [0x66; 32];
    const EXPIRES_AT: UnixMillis = UnixMillis(1_700_000_000_000);

    fn owner_enc() -> X25519Secret {
        X25519Secret::from_scalar([0x11; 32])
    }

    fn owner_identity() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[0x33; 32]).expect("valid scalar")
    }

    fn owner_pseudonym() -> Ed25519Signer {
        Ed25519Signer::from_seed([0x22; 32])
    }

    fn invitee() -> EphemeralInvitee {
        EphemeralInvitee::mint(&mut SeededEntropy::new(7)).expect("mints")
    }

    fn scope_name() -> Vec<u8> {
        derive_write_name(&WRITE_SCOPE_SEED, &SCOPE)
            .as_str()
            .as_bytes()
            .to_vec()
    }

    fn invite(permission: Permission, expires_at: Option<UnixMillis>) -> GrantRow {
        mint_invite_grant(
            &owner_enc(),
            &invitee(),
            &SCOPE,
            &WRITE_SCOPE_SEED,
            permission,
            expires_at,
        )
        .expect("mints")
    }

    /// Re-seal a scope root committing exactly `grants` under `committed`'s
    /// pseudonym, signed by `signer` — the two differ only in the rogue-signer
    /// case.
    fn scope_root(
        grants: &[GrantRow],
        committed: &Ed25519Signer,
        signer: &Ed25519Signer,
    ) -> Result<GrantSection, ResealError> {
        let owner_pub = owner_enc().public();
        let name = scope_name();
        let commitment = GrantSetCommitment {
            ipns_name: name.clone(),
            owner_pseudonym_pk: committed.verifying_key().to_bytes(),
            entries: grants.iter().map(|g| g.commitment_entry.clone()).collect(),
            unknown: PreservedFields::new(),
        };
        let sig = sign_grant_set(&owner_identity(), &commitment)
            .expect("signs")
            .to_compact();
        let ledger: Vec<GrantLedgerEntry> = grants.iter().map(|g| g.ledger_entry.clone()).collect();
        reseal_scope_root(
            &mut SeededEntropy::new(1),
            &ScopeRootIdentity {
                v: V,
                scope_id: SCOPE,
                ipns_name: &name,
                owner_enc_pub: &owner_pub,
                parent_node_seed: None,
                pseudonym_signer: signer,
            },
            &ResealSeeds {
                override_seed: &OVERRIDE_SEED,
                read_epoch: EPOCH,
                prev: None,
                write_scope_seed: &WRITE_SCOPE_SEED,
                write_epoch: 1,
                pointer_read_key: &POINTER_READ_KEY,
            },
            &CommittedSet {
                commitment: &commitment,
                commitment_sig: &sig,
                grant_ledger: &ledger,
                write_history_link: b"",
                direct_child_scope_index: &[],
            },
            &[],
        )
    }

    fn blob_ctx(epoch: u64) -> AadContext {
        AadContext {
            v: V,
            id: SCOPE,
            scope: SCOPE,
            epoch,
            struct_tag: STRUCT_TAG_GRANT_BLOB,
        }
    }

    fn blob_at<'a>(section: &'a GrantSection, tag: &[u8; 32]) -> &'a SignedGrantBlob {
        section
            .grant_blobs
            .iter()
            .find(|b| &b.tag == tag)
            .expect("blob at tag")
    }

    #[test]
    fn the_ephemeral_identity_is_a_pure_function_of_the_invite_secret() {
        let secret = [0x4e; 32];
        let a = EphemeralInvitee::from_secret(&secret).expect("valid");
        let b = EphemeralInvitee::from_secret(&secret).expect("valid");
        assert_eq!(a.identity_pk().to_sec1(), b.identity_pk().to_sec1());
        assert_eq!(a.enc_public().to_bytes(), b.enc_public().to_bytes());
        assert!(ct_eq(a.secret().as_bytes(), &secret));

        let other = EphemeralInvitee::from_secret(&[0x4f; 32]).expect("valid");
        assert_ne!(a.enc_public().to_bytes(), other.enc_public().to_bytes());
        assert_ne!(a.identity_pk().to_sec1(), other.identity_pk().to_sec1());
    }

    #[test]
    fn minting_draws_the_secret_from_the_injected_entropy_seam() {
        let from_seam = EphemeralInvitee::mint(&mut SeededEntropy::new(7)).expect("mints");
        let mut expected = [0u8; 32];
        SeededEntropy::new(7).fill(&mut expected).expect("fills");
        assert!(
            ct_eq(from_seam.secret().as_bytes(), &expected),
            "the invite secret is exactly the seam's bytes — no direct RNG",
        );
    }

    #[test]
    fn from_secret_fails_closed_on_an_invalid_scalar() {
        assert_eq!(
            EphemeralInvitee::from_secret(&[0u8; 32]).unwrap_err(),
            InviteError::InvalidSecret,
            "the zero scalar has no secp256k1 identity",
        );
    }

    #[test]
    fn mint_fails_closed_when_entropy_fails() {
        struct DryEntropy;
        impl Entropy for DryEntropy {
            fn fill(&mut self, _dest: &mut [u8]) -> Result<(), EntropyError> {
                Err(EntropyError::new("exhausted"))
            }
        }
        assert_eq!(
            EphemeralInvitee::mint(&mut DryEntropy).unwrap_err().check(),
            "entropy-error",
        );
    }

    #[test]
    fn the_invite_blob_is_byte_shaped_like_a_personal_grant_blob() {
        // The contact goes through the same `mint_grant_row` the invite does, so
        // this compares two mints rather than a mint against a re-implementation.
        let contact = X25519Secret::from_scalar([0x77; 32]);
        let contact_identity = EcdsaSigner::from_scalar(&[0x78; 32]).expect("valid scalar");
        let personal = mint_grant_row(
            &owner_enc(),
            &contact_identity.verifying_key(),
            &contact.public(),
            &SCOPE,
            &scope_name(),
            Permission::Read,
        )
        .expect("contributory");
        let invite = invite(Permission::Read, Some(EXPIRES_AT));

        let section = scope_root(
            &[personal.clone(), invite.clone()],
            &owner_pseudonym(),
            &owner_pseudonym(),
        )
        .expect("reseal");

        assert_eq!(section.grant_blobs.len(), 2, "observer sees two blobs");
        assert_eq!(
            blob_at(&section, &personal.tag).ciphertext.len(),
            blob_at(&section, &invite.tag).ciphertext.len(),
            "an invite blob must not be distinguishable by length",
        );
        // The deadline is sealed in the write-body; the envelope must not carry it.
        let envelope = encode_grant_section(&section).expect("encodes");
        assert!(
            !envelope.windows(8).any(|w| w == EXPIRES_AT.0.to_be_bytes()),
            "the deadline must not ride the envelope in the clear",
        );
    }

    #[test]
    fn the_fragment_secret_unseals_the_scope_seeds_and_verifies_the_structure_signature() {
        let minted = invitee();
        let invite = mint_invite_grant(
            &owner_enc(),
            &minted,
            &SCOPE,
            &WRITE_SCOPE_SEED,
            Permission::Read,
            Some(EXPIRES_AT),
        )
        .expect("mints");
        let section =
            scope_root(&[invite.clone()], &owner_pseudonym(), &owner_pseudonym()).expect("reseal");

        // The link holder reconstructs from the fragment alone and self-locates
        // by re-deriving the same blinded tag from the owner's published enc key.
        let holder = EphemeralInvitee::from_secret(minted.secret().as_bytes()).expect("valid");
        let tag = recipient_blinded_tag(holder.enc_secret(), &owner_enc().public(), &scope_name())
            .expect("tag");
        assert_eq!(tag, invite.tag);

        let blobs: Vec<PublishedGrantBlob> = section
            .grant_blobs
            .iter()
            .map(|b| PublishedGrantBlob {
                tag: b.tag,
                enc: b.enc,
                ciphertext: b.ciphertext.clone(),
            })
            .collect();
        let located = self_locate(&blobs, &tag).expect("locates its own blob");

        let signed = blob_at(&section, &tag);
        verify_structure(
            &owner_pseudonym().verifying_key(),
            &StructureSigInput::over_ciphertext(
                SCOPE,
                EPOCH,
                STRUCT_TAG_GRANT_BLOB,
                Some(tag),
                &signed.ciphertext,
            ),
            &Ed25519Signature::from_bytes(signed.signature),
        )
        .expect("the invite blob carries a valid structure signature");

        let opened = open_grant_blob(
            holder.enc_secret(),
            &located.enc,
            &AadContext {
                v: V,
                id: SCOPE,
                scope: SCOPE,
                epoch: EPOCH,
                struct_tag: STRUCT_TAG_GRANT_BLOB,
            },
            &located.ciphertext,
        )
        .expect("the fragment secret opens the blob");
        assert!(ct_eq(opened.read_scope_seed(), &OVERRIDE_SEED));
        assert_eq!(
            opened.write_scope_seed(),
            None,
            "a read invite conveys no write seed",
        );
    }

    #[test]
    fn an_invite_committed_under_a_non_owner_pseudonym_is_refused() {
        let rogue = Ed25519Signer::from_seed([0x23; 32]);
        let err = scope_root(
            &[invite(Permission::Read, Some(EXPIRES_AT))],
            &owner_pseudonym(),
            &rogue,
        )
        .unwrap_err();
        assert_eq!(err.check(), "signer-not-committed");
    }

    #[test]
    fn a_zero_deadline_is_refused_at_the_mint() {
        assert_eq!(
            mint_invite_grant(
                &owner_enc(),
                &invitee(),
                &SCOPE,
                &WRITE_SCOPE_SEED,
                Permission::Read,
                Some(UnixMillis(0)),
            )
            .unwrap_err(),
            InviteError::InvalidExpiry,
            "zero must not silently become a link that never expires",
        );
    }

    #[test]
    fn the_minted_row_carries_the_deadline_the_caller_asked_for() {
        let expiring = invite(Permission::Write, Some(EXPIRES_AT));
        assert_eq!(
            expiring.ledger_entry.expires_at,
            NonZeroU64::new(EXPIRES_AT.0)
        );
        assert_eq!(expiring.ledger_entry.permission, Permission::Write);
        assert!(!entry_is_live(&expiring.ledger_entry, EXPIRES_AT));

        let perpetual = invite(Permission::Read, None);
        assert_eq!(perpetual.ledger_entry.expires_at, None);
    }

    #[test]
    fn the_blinded_tag_binds_the_derived_scope_root_name() {
        // The name is derived, never passed, so a different write scope is a
        // different name and therefore a different tag.
        let minted = invitee();
        let here = mint_invite_grant(
            &owner_enc(),
            &minted,
            &SCOPE,
            &WRITE_SCOPE_SEED,
            Permission::Read,
            None,
        )
        .expect("mints");
        let elsewhere = mint_invite_grant(
            &owner_enc(),
            &minted,
            &SCOPE,
            &[0x56; 32],
            Permission::Read,
            None,
        )
        .expect("mints");
        assert_ne!(here.tag, elsewhere.tag);
        // The pseudonym binds the scope id, not the name, so it is shared.
        assert_eq!(
            here.commitment_entry.pseudonym_pk,
            elsewhere.commitment_entry.pseudonym_pk
        );
    }

    #[test]
    fn a_write_invite_conveys_the_write_scope_seed_to_the_fragment_holder() {
        let minted = invitee();
        let row = mint_invite_grant(
            &owner_enc(),
            &minted,
            &SCOPE,
            &WRITE_SCOPE_SEED,
            Permission::Write,
            None,
        )
        .expect("mints");
        let section =
            scope_root(&[row.clone()], &owner_pseudonym(), &owner_pseudonym()).expect("reseal");
        let blob = blob_at(&section, &row.tag);
        let opened = open_grant_blob(
            minted.enc_secret(),
            &blob.enc,
            &blob_ctx(EPOCH),
            &blob.ciphertext,
        )
        .expect("opens");
        assert_eq!(
            opened.write_scope_seed(),
            Some(&WRITE_SCOPE_SEED),
            "a write link hands out an extractable subtree signing capability",
        );
    }

    #[test]
    fn an_invite_blob_transplanted_across_epoch_or_structure_fails_to_open() {
        let minted = invitee();
        let row = invite(Permission::Read, None);
        let section =
            scope_root(&[row.clone()], &owner_pseudonym(), &owner_pseudonym()).expect("reseal");
        let blob = blob_at(&section, &row.tag);
        // Same key, same ciphertext, a different AAD epoch: the tag must fail.
        assert_eq!(
            open_grant_blob(
                minted.enc_secret(),
                &blob.enc,
                &blob_ctx(EPOCH + 1),
                &blob.ciphertext
            )
            .unwrap_err()
            .check(),
            "hpke-open-failed",
        );
        // A different link's secret opens nothing.
        let stranger = EphemeralInvitee::from_secret(&[0x4f; 32]).expect("valid");
        assert_eq!(
            open_grant_blob(
                stranger.enc_secret(),
                &blob.enc,
                &blob_ctx(EPOCH),
                &blob.ciphertext
            )
            .unwrap_err()
            .check(),
            "hpke-open-failed",
        );
    }

    #[test]
    fn a_write_grantee_may_strip_a_deadline_without_failing_owner_authority() {
        // The honest bound on `expires_at`: it sits outside the owner-signed
        // commitment, so a write-grantee re-authoring the write-body can drop or
        // forge one and `enforce_committed_ledger` still passes. Pins the residual
        // this slice ships with, so tightening it has to update this test.
        let row = invite(Permission::Read, Some(EXPIRES_AT));
        let commitment = GrantSetCommitment {
            ipns_name: scope_name(),
            owner_pseudonym_pk: owner_pseudonym().verifying_key().to_bytes(),
            entries: vec![row.commitment_entry.clone()],
            unknown: PreservedFields::new(),
        };
        let mut stripped = row.ledger_entry.clone();
        stripped.expires_at = None;
        assert!(enforce_committed_ledger(&commitment, &[stripped]).is_ok());
    }

    #[test]
    fn debug_redacts_every_half_of_the_ephemeral_identity() {
        // A whole-string golden: any field added later — of any type — breaks
        // this and forces a redaction decision (security rule 2).
        assert_eq!(
            format!("{:?}", EphemeralInvitee::from_secret(&[0xab; 32]).unwrap()),
            "EphemeralInvitee { secret: SecretBytes(redacted), \
             identity: EcdsaSigner(redacted), enc_subkey: X25519Secret(redacted) }",
        );
    }
}
