//! Invite links — the ephemeral-key grant blob (blueprint/engine.md "Grants and
//! ledger: Invites", #25 D6).
//!
//! An invite is an ordinary grant wrapped to a throwaway identity instead of a
//! contact's. [`EphemeralInvitee`] derives that identity from one random invite
//! secret exactly as [`SessionIdentity`](crate::session::SessionIdentity)
//! derives a real one from a login secret — the secp256k1 scalar adopted
//! directly, the X25519 sealing half through the frozen `enc-subkey` edge. So
//! the blinded tag, the commitment entry, and the grant blob
//! [`reseal_scope_root`](crate::rotation::reseal_scope_root) wraps for the row
//! are byte-shaped like a personal grantee's: an observer learns only blob
//! count.
//!
//! The invite secret is the whole capability. It rides the link's URL fragment,
//! so the link is honestly bearer and multi-claim: anyone holding it unseals the
//! scope seeds. Expiry ([`GrantLedgerEntry::expires_at`]) is the deadline every
//! honest client honours against the injected clock.
//!
//! This module composes existing machinery only and holds no crypto of its own.

use cipherbox_core::kdf;
use cipherbox_core::seal::{GrantLedgerEntry, GrantSetEntry, Permission};
use cipherbox_core::suite::ecdsa::{EcdsaSigner, EcdsaVerifier};
use cipherbox_core::suite::secret::{SECRET_LEN, SecretBytes};
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};
use core::fmt;
use zeroize::Zeroizing;

use crate::entropy::{Entropy, EntropyError};
use crate::seams::UnixMillis;

/// The throwaway identity an invite link's grant is wrapped to.
///
/// Every half derives from `secret` — the bearer capability the URL fragment
/// carries. Hold it only as long as the mint or the claim needs it; it is
/// redacted from `Debug` and zeroized on drop, and must never be logged or sent
/// to the API.
#[derive(Clone, Debug)]
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
    /// The deadline was `0`, which the write-body codec rejects as a second
    /// spelling of "no deadline" — refused here so the mint never builds a
    /// ledger row that cannot encode (fail-closed symmetry, AGENTS.md rule 8).
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
    /// Fails closed on an entropy error, and on the vanishing chance that the
    /// sampled bytes are not a valid secp256k1 scalar — never by re-sampling
    /// until one lands, which would make the mint non-deterministic in its
    /// injected entropy.
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

/// One invite link's contribution to a scope root: its blinded tag, the entry
/// the owner signs into the grant-set commitment, and the ledger row carrying
/// the deadline. Feed both entries to `reseal_scope_root`, which wraps the grant
/// blob to the ephemeral key like any other committed grantee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteGrant {
    /// The link's blinded tag — the grant blob's public key in the envelope.
    pub tag: [u8; SECRET_LEN],
    /// The `(tag, permission, pseudonymPk)` entry for the owner-signed
    /// commitment.
    pub commitment_entry: GrantSetEntry,
    /// The authoritative ledger row, carrying `expires_at`.
    pub ledger_entry: GrantLedgerEntry,
}

/// Mint an invite link's grant rows over a scope root.
///
/// Owner-only by construction: it takes the owner's encryption subkey secret for
/// the pairwise ECDH, and only the owner's identity signature over the resulting
/// commitment authorises the set.
///
/// `scope_root_ipns_name` must be the scope root's real resolvable name — the
/// tag binds it, and a link holder re-derives the same tag from the record it
/// resolves, so a mismatch mints a grant nobody can self-locate.
pub fn mint_invite_grant(
    owner_enc_secret: &X25519Secret,
    invitee: &EphemeralInvitee,
    scope_id: &[u8; 16],
    scope_root_ipns_name: &[u8],
    permission: Permission,
    expires_at: Option<UnixMillis>,
) -> Result<InviteGrant, InviteError> {
    if matches!(expires_at, Some(UnixMillis(0))) {
        return Err(InviteError::InvalidExpiry);
    }
    let invitee_enc_pub = invitee.enc_public();
    let shared = owner_enc_secret
        .diffie_hellman(&invitee_enc_pub)
        .ok_or(InviteError::UnusableInviteeKey)?;
    let tag = kdf::blinded_tag(shared.as_bytes(), scope_root_ipns_name);
    let pseudonym_pk = kdf::pseudonym_sign(shared.as_bytes(), scope_id)
        .verifying_key()
        .to_bytes();

    Ok(InviteGrant {
        tag,
        commitment_entry: GrantSetEntry::new(tag, permission, pseudonym_pk),
        ledger_entry: GrantLedgerEntry {
            expires_at: expires_at.map(|d| d.0),
            ..GrantLedgerEntry::new(
                invitee.identity_pk().to_sec1(),
                invitee_enc_pub.to_bytes(),
                permission,
                tag,
            )
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::{entry_is_live, recipient_blinded_tag, self_locate};
    use crate::rotation::{CommittedSet, ResealSeeds, ScopeRootIdentity, reseal_scope_root};
    use crate::testkit::SeededEntropy;
    use cipherbox_core::seal::{
        AadContext, GrantSetCommitment, PreservedFields, STRUCT_TAG_GRANT_BLOB, StructureSigInput,
        open_grant_blob, sign_grant_set, verify_structure,
    };
    use cipherbox_core::suite::ed25519::{Ed25519Signature, Ed25519Signer};
    use cipherbox_core::suite::secret::ct_eq;

    const V: u64 = 2;
    const SCOPE: [u8; 16] = [0x5c; 16];
    const NAME: &[u8] = b"scope-root-name";
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

    fn invitee() -> EphemeralInvitee {
        EphemeralInvitee::mint(&mut SeededEntropy::new(7)).expect("mints")
    }

    /// A personal read grantee's rows, so an invite can be compared against a
    /// real one in the same scope root.
    fn personal_grant(owner: &X25519Secret, contact_enc: &X25519Secret) -> InviteGrant {
        let shared = owner
            .diffie_hellman(&contact_enc.public())
            .expect("contributory");
        let tag = kdf::blinded_tag(shared.as_bytes(), NAME);
        let pseudonym_pk = kdf::pseudonym_sign(shared.as_bytes(), &SCOPE)
            .verifying_key()
            .to_bytes();
        InviteGrant {
            tag,
            commitment_entry: GrantSetEntry::new(tag, Permission::Read, pseudonym_pk),
            ledger_entry: GrantLedgerEntry::new(
                [0x02; 33],
                contact_enc.public().to_bytes(),
                Permission::Read,
                tag,
            ),
        }
    }

    /// Re-seal a scope root committing exactly `grants`, signed by the owner.
    fn scope_root(
        grants: &[InviteGrant],
        pseudonym: &Ed25519Signer,
    ) -> cipherbox_core::seal::GrantSection {
        let owner_pub = owner_enc().public();
        let commitment = GrantSetCommitment {
            ipns_name: NAME.to_vec(),
            owner_pseudonym_pk: pseudonym.verifying_key().to_bytes(),
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
                ipns_name: NAME,
                owner_enc_pub: &owner_pub,
                parent_node_seed: None,
                pseudonym_signer: pseudonym,
            },
            &ResealSeeds {
                override_seed: &OVERRIDE_SEED,
                read_epoch: 5,
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
        .expect("reseal")
    }

    #[test]
    fn the_ephemeral_identity_is_a_pure_function_of_the_invite_secret() {
        let secret = [0x4e; 32];
        let a = EphemeralInvitee::from_secret(&secret).expect("valid");
        let b = EphemeralInvitee::from_secret(&secret).expect("valid");
        assert_eq!(a.identity_pk().to_sec1(), b.identity_pk().to_sec1());
        assert_eq!(a.enc_public().to_bytes(), b.enc_public().to_bytes());
        assert!(ct_eq(a.secret().as_bytes(), &secret));

        // A different secret is a different link.
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
        let owner = owner_enc();
        let contact = X25519Secret::from_scalar([0x77; 32]);
        let personal = personal_grant(&owner, &contact);
        let invite = mint_invite_grant(
            &owner,
            &invitee(),
            &SCOPE,
            NAME,
            Permission::Read,
            Some(EXPIRES_AT),
        )
        .expect("mints");

        let pseudonym = Ed25519Signer::from_seed([0x22; 32]);
        let section = scope_root(&[personal.clone(), invite.clone()], &pseudonym);

        assert_eq!(section.grant_blobs.len(), 2, "observer sees two blobs");
        let personal_blob = self_locate_signed(&section, &personal.tag);
        let invite_blob = self_locate_signed(&section, &invite.tag);
        assert_eq!(
            personal_blob.ciphertext.len(),
            invite_blob.ciphertext.len(),
            "an invite blob must not be distinguishable by length",
        );
        assert_eq!(personal_blob.enc.len(), invite_blob.enc.len());
        assert_eq!(
            personal_blob.signature.len(),
            invite_blob.signature.len(),
            "both are signed by the same owner pseudonym",
        );
        // The expiry lives in the sealed write-body, never in the envelope.
        let envelope = cipherbox_core::seal::encode_grant_section(&section).expect("encodes");
        assert!(
            !envelope.windows(8).any(|w| w == EXPIRES_AT.0.to_be_bytes()),
            "the deadline must not ride the envelope in the clear",
        );
    }

    fn self_locate_signed<'a>(
        section: &'a cipherbox_core::seal::GrantSection,
        tag: &[u8; 32],
    ) -> &'a cipherbox_core::seal::SignedGrantBlob {
        section
            .grant_blobs
            .iter()
            .find(|b| &b.tag == tag)
            .expect("blob at tag")
    }

    #[test]
    fn the_fragment_secret_unseals_the_scope_seeds_and_verifies_the_structure_signature() {
        let owner = owner_enc();
        let minted = invitee();
        let invite = mint_invite_grant(
            &owner,
            &minted,
            &SCOPE,
            NAME,
            Permission::Read,
            Some(EXPIRES_AT),
        )
        .expect("mints");
        let pseudonym = Ed25519Signer::from_seed([0x22; 32]);
        let section = scope_root(&[invite.clone()], &pseudonym);

        // The link holder reconstructs from the fragment alone and self-locates
        // by re-deriving the same blinded tag from the owner's published enc key.
        let holder = EphemeralInvitee::from_secret(minted.secret().as_bytes()).expect("valid");
        let tag = recipient_blinded_tag(holder.enc_secret(), &owner.public(), NAME).expect("tag");
        assert_eq!(tag, invite.tag);

        let blobs: Vec<crate::grants::PublishedGrantBlob> = section
            .grant_blobs
            .iter()
            .map(|b| crate::grants::PublishedGrantBlob {
                tag: b.tag,
                enc: b.enc,
                ciphertext: b.ciphertext.clone(),
            })
            .collect();
        let located = self_locate(&blobs, &tag).expect("locates its own blob");

        let signed = self_locate_signed(&section, &tag);
        verify_structure(
            &pseudonym.verifying_key(),
            &StructureSigInput::over_ciphertext(
                SCOPE,
                5,
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
                epoch: 5,
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
        let invite = mint_invite_grant(
            &owner_enc(),
            &invitee(),
            &SCOPE,
            NAME,
            Permission::Read,
            Some(EXPIRES_AT),
        )
        .expect("mints");
        let owner_pseudonym = Ed25519Signer::from_seed([0x22; 32]);
        let rogue = Ed25519Signer::from_seed([0x23; 32]);
        let owner_pub = owner_enc().public();
        let commitment = GrantSetCommitment {
            ipns_name: NAME.to_vec(),
            owner_pseudonym_pk: owner_pseudonym.verifying_key().to_bytes(),
            entries: vec![invite.commitment_entry.clone()],
            unknown: PreservedFields::new(),
        };
        let sig = sign_grant_set(&owner_identity(), &commitment)
            .expect("signs")
            .to_compact();
        let err = reseal_scope_root(
            &mut SeededEntropy::new(1),
            &ScopeRootIdentity {
                v: V,
                scope_id: SCOPE,
                ipns_name: NAME,
                owner_enc_pub: &owner_pub,
                parent_node_seed: None,
                pseudonym_signer: &rogue,
            },
            &ResealSeeds {
                override_seed: &OVERRIDE_SEED,
                read_epoch: 5,
                prev: None,
                write_scope_seed: &WRITE_SCOPE_SEED,
                write_epoch: 1,
                pointer_read_key: &POINTER_READ_KEY,
            },
            &CommittedSet {
                commitment: &commitment,
                commitment_sig: &sig,
                grant_ledger: &[invite.ledger_entry.clone()],
                write_history_link: b"",
                direct_child_scope_index: &[],
            },
            &[],
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
                NAME,
                Permission::Read,
                Some(UnixMillis(0)),
            )
            .unwrap_err(),
            InviteError::InvalidExpiry,
        );
    }

    #[test]
    fn the_minted_row_carries_the_deadline_and_expires_against_the_injected_clock() {
        let invite = mint_invite_grant(
            &owner_enc(),
            &invitee(),
            &SCOPE,
            NAME,
            Permission::Write,
            Some(EXPIRES_AT),
        )
        .expect("mints");
        assert_eq!(invite.ledger_entry.expires_at, Some(EXPIRES_AT.0));
        assert_eq!(invite.ledger_entry.permission, Permission::Write);
        assert!(entry_is_live(
            &invite.ledger_entry,
            UnixMillis(EXPIRES_AT.0 - 1)
        ));
        assert!(!entry_is_live(&invite.ledger_entry, EXPIRES_AT));

        // A link with no deadline expires only by revocation.
        let perpetual = mint_invite_grant(
            &owner_enc(),
            &invitee(),
            &SCOPE,
            NAME,
            Permission::Read,
            None,
        )
        .expect("mints");
        assert_eq!(perpetual.ledger_entry.expires_at, None);
        assert!(entry_is_live(&perpetual.ledger_entry, UnixMillis(u64::MAX)));
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
