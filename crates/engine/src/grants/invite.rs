//! Invite links — the link entry and the ephemeral key it is wrapped to
//! (blueprint/engine.md "Grants and ledger: Invites", ADR 0023, ADR 0024).
//!
//! A link is a row on a scope's committed set whose recipient is a throwaway
//! identity. [`EphemeralInvitee`] derives that identity from one random invite
//! secret the way [`SessionIdentity`](crate::session::SessionIdentity) derives a
//! real one — the secp256k1 scalar adopted directly, the X25519 sealing half
//! through the frozen `enc-subkey` edge — and then mints through the same
//! [`mint_grant_row`] every contact does, so its blinded tag, blob and ledger
//! row are byte-shaped like a personal grantee's.
//!
//! The commitment entry is what marks the row as a link (ADR 0023 D2): the
//! kind, the deadline, the conversion permission and the admission cap, all
//! under the owner's commitment signature. The owner device keeps no record of
//! a link: conversion and revoke read it off the owner-signed record.
//!
//! The invite secret is the whole capability. It rides the link's URL fragment
//! ([`InviteFragment`]) with the scope pointer and its read key, so a holder
//! reads the folder at once and follows it across a write wave.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as FRAGMENT_B64;
use cipherbox_core::codec::RedactedBytes;
use cipherbox_core::codec::{Map, Value, decode, encode_fixed_depth};
use cipherbox_core::error::{CodecError, Malformed};
use cipherbox_core::payload::{InviteNames, sign_invite_names, verify_invite_names};
use cipherbox_core::seal::{
    ChildScopeRef, GrantLedgerEntry, GrantSetCommitment, GrantSetEntryKind, MAX_GRANT_BLOBS,
    Permission, verify_grant_set,
};
use cipherbox_core::suite::ecdsa::{
    EcdsaSignature, EcdsaSigner, EcdsaVerifier, IDENTITY_PUBLIC_LEN, SIGNATURE_LEN as ECDSA_SIG_LEN,
};
use cipherbox_core::suite::secret::{SECRET_LEN, SecretBytes};
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};
use cipherbox_core::{ipns::IpnsName, kdf};
use core::fmt;
use core::num::NonZeroU64;
use std::collections::BTreeSet;
use zeroize::Zeroizing;

use crate::entropy::{Entropy, EntropyError, fresh_bytes, fresh_seed};
use crate::grants::accept::{fixed, req};
use crate::grants::contact::import_contact;
use crate::grants::{
    AuthorityViolation, Contact, GrantRow, enforce_committed_ledger, mint_grant_row,
    row_is_owner_attested,
};
use crate::mailbox::{VerifiedMailboxItem, post_sealed};
use crate::name::MAX_NODE_NAME_BYTES;
use crate::rotation::derive_write_name;
use crate::seams::{Mailbox, SeamResult, UnixMillis};

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
    /// The deadline was `0`, which a commitment entry cannot carry
    /// ([`Malformed::InvalidDeadline`](cipherbox_core::error::Malformed::InvalidDeadline)).
    InvalidExpiry,
    /// The claim payload did not decode.
    MalformedClaim(CodecError),
    /// The link fragment is not one this build encoded. Carries no detail: the
    /// bytes under it are the bearer capability, so a refusal that said which
    /// field failed would narrate them into a host's error surface.
    MalformedFragment,
    /// The fragment is past [`MAX_INVITE_FRAGMENT_BYTES`]. Raised on both sides
    /// of the same bound: a claim refuses one, and a mint refuses to hand out a
    /// link the claim path would refuse.
    FragmentTooLarge,
    /// A fragment name is past [`MAX_INVITE_NAME_BYTES`], on encode and on
    /// decode alike.
    NameTooLong,
    /// The claim names a scope pointer other than the one of the scope it is
    /// converted against.
    ScopeMismatch,
    /// The commitment offered for a scope does not name the scope root that
    /// scope answers at ([`CommittedScope::bind`]).
    ScopeUnbound,
    /// The caller's identity key did not sign the committed set it is acting on,
    /// so it is not this scope's owner. Converting and revoking are owner-only.
    NotOwner,
    /// No single owner-attested link row answers to the ephemeral identity: the
    /// row is absent, is not a link entry, or the owner did not attest it.
    LinkNotCommitted,
    /// A revoke named no link, and the set commits more than one, so no single
    /// link answers.
    LinkAmbiguous,
    /// The link entry's deadline is not later than `now`, so it admits nobody.
    LinkExpired,
    /// The claimant's contact code failed its mandatory binding verify.
    ClaimantContact(CodecError),
    /// The claim asked to be anchored to the link's own throwaway identity.
    /// Conversion exists to re-anchor a bearer link to a contact-anchored
    /// identity, so anchoring back to the ephemeral half is refused.
    ClaimantIsTheEphemeralHalf,
    /// The claim handed back the owner's own contact bundle, which the invite URL
    /// carries. The owner is not a grantee of its own scope.
    ClaimantIsTheOwner,
    /// The set is at the grant-set ceiling
    /// ([`MAX_GRANT_BLOBS`](cipherbox_core::seal::MAX_GRANT_BLOBS)); one more row
    /// could only ever mint a record its own decoder refuses.
    GrantSetFull,
    /// The claimant's encryption subkey is non-contributory, so no blinded tag
    /// binds a grant to it.
    UnusableClaimantKey,
    /// The produced set would file two rows under one tag — the shape core's
    /// decoder and [`sign_grant_set`](cipherbox_core::seal::sign_grant_set)
    /// reject, refused here rather than signed.
    DuplicateTag,
    /// The produced ledger and commitment do not agree.
    Authority(AuthorityViolation),
}

impl InviteError {
    /// Every invite check, in variant declaration order — the surface
    /// `crates/engine/tests/kat_checks.rs` pins (see the crate header). The
    /// three arms that surface another surface's verdict verbatim stay off it.
    pub const CHECKS: &'static [&'static str] = &[
        "invalid-invite-secret",
        "unusable-invitee-key",
        "malformed-claim",
        "malformed-invite-fragment",
        "invite-fragment-too-large",
        "invite-name-too-long",
        "claim-scope-mismatch",
        "commitment-names-another-scope-root",
        "not-owner",
        "link-not-committed",
        "link-ambiguous",
        "link-expired",
        "claimant-contact-invalid",
        "claimant-is-the-ephemeral-half",
        "claimant-is-the-owner",
        "grant-set-full",
        "unusable-claimant-key",
        "duplicate-tag",
    ];

    /// The class label used in reject vectors. An invite refuses on the owner's
    /// authority over the set or on a bound the recipient's own decoder
    /// enforces. A deadline the owner signed and that has passed is no trust
    /// verdict: the link is valid and no longer takes claims.
    pub fn class(&self) -> &'static str {
        match self {
            Self::InvalidSecret
            | Self::UnusableInviteeKey
            | Self::ScopeMismatch
            | Self::ScopeUnbound
            | Self::NotOwner
            | Self::LinkNotCommitted
            | Self::ClaimantIsTheEphemeralHalf
            | Self::ClaimantIsTheOwner
            | Self::UnusableClaimantKey
            | Self::DuplicateTag => "trust",
            Self::Entropy(error) => error.class(),
            Self::InvalidExpiry => CodecError::from(Malformed::InvalidDeadline).class(),
            Self::MalformedClaim(error) | Self::ClaimantContact(error) => error.class(),
            Self::MalformedFragment => "malformed",
            Self::LinkAmbiguous => "capability",
            Self::LinkExpired => "unsupported",
            Self::FragmentTooLarge | Self::NameTooLong | Self::GrantSetFull => "over-cap",
            Self::Authority(violation) => violation.class(),
        }
    }

    /// A stable, key-material-free classification name (host/log facing).
    pub fn check(&self) -> &'static str {
        match self {
            Self::Entropy(error) => error.check(),
            Self::InvalidSecret => "invalid-invite-secret",
            Self::UnusableInviteeKey => "unusable-invitee-key",
            Self::InvalidExpiry => Malformed::InvalidDeadline.check(),
            Self::MalformedClaim(_) => "malformed-claim",
            Self::MalformedFragment => "malformed-invite-fragment",
            Self::FragmentTooLarge => "invite-fragment-too-large",
            Self::NameTooLong => "invite-name-too-long",
            Self::ScopeMismatch => "claim-scope-mismatch",
            Self::ScopeUnbound => "commitment-names-another-scope-root",
            Self::NotOwner => "not-owner",
            Self::LinkNotCommitted => "link-not-committed",
            Self::LinkAmbiguous => "link-ambiguous",
            Self::LinkExpired => "link-expired",
            Self::ClaimantContact(_) => "claimant-contact-invalid",
            Self::ClaimantIsTheEphemeralHalf => "claimant-is-the-ephemeral-half",
            Self::ClaimantIsTheOwner => "claimant-is-the-owner",
            Self::GrantSetFull => "grant-set-full",
            Self::UnusableClaimantKey => "unusable-claimant-key",
            Self::DuplicateTag => "duplicate-tag",
            Self::Authority(v) => v.check(),
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
    /// Fails closed on an entropy error, on a seam that reports success having
    /// written nothing ([`fresh_seed`]), and on the ~2^-128 chance that the
    /// sampled bytes are at least the secp256k1 group order — never by
    /// re-sampling until one lands, which would make the entropy each mint draws
    /// variable and desynchronize every downstream draw from the same seam.
    pub fn mint<E: Entropy>(entropy: &mut E) -> Result<Self, InviteError> {
        let secret = fresh_seed(entropy).map_err(InviteError::Entropy)?;
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

/// The admission cap a link carries when the owner sets none (ADR 0023 D9).
pub const DEFAULT_ADMISSION_CAP: u64 = 25;

/// The lifetime of a link whose owner sets no deadline. A link entry must
/// carry one.
pub const DEFAULT_LINK_LIFETIME: core::time::Duration =
    core::time::Duration::from_secs(7 * 24 * 60 * 60);

/// The owner-signed terms of one link: the fields its commitment entry carries
/// beside the kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkTerms {
    /// The time by which an owner device must convert a claim through this
    /// link.
    pub deadline: UnixMillis,
    /// The permission conversion grants a claimant.
    pub conversion_permission: Permission,
    /// How many people this link may admit.
    pub admission_cap: u64,
}

/// Mint a link row over the scope root at `scope_id`: a `read` row to
/// `invitee` whose commitment entry carries the link kind and `terms`. The
/// entry is committed at `read` whatever it converts to, so the blob of a
/// write link carries read material only and the mint runs no write-scope cut
/// (ADR 0024 D4).
///
/// Owner-only by construction: it takes the owner's encryption subkey secret for
/// the pairwise ECDH, and only the owner's identity signature over the resulting
/// commitment authorises the set. The scope root's `ipnsName` is **derived** from
/// `write_scope_seed`, never accepted as input — the tag binds that name and the
/// link holder re-derives it from the record it resolves.
#[allow(clippy::too_many_arguments)]
pub fn mint_invite_grant(
    owner_identity_signer: &EcdsaSigner,
    owner_enc_secret: &X25519Secret,
    pointer_read_key: &[u8; SECRET_LEN],
    invitee: &EphemeralInvitee,
    scope_id: &[u8; 16],
    write_scope_seed: &[u8; SECRET_LEN],
    terms: &LinkTerms,
) -> Result<GrantRow, InviteError> {
    let ipns_name: IpnsName = derive_write_name(write_scope_seed, scope_id);
    mint_invite_row(
        owner_identity_signer,
        owner_enc_secret,
        pointer_read_key,
        invitee,
        scope_id,
        ipns_name.as_str().as_bytes(),
        terms,
    )
}

/// [`mint_invite_grant`] at a scope root that already stands, whose name the
/// caller read off the gated record rather than derived (ADR 0026 D1).
pub fn mint_invite_row(
    owner_identity_signer: &EcdsaSigner,
    owner_enc_secret: &X25519Secret,
    pointer_read_key: &[u8; SECRET_LEN],
    invitee: &EphemeralInvitee,
    scope_id: &[u8; 16],
    scope_root_ipns_name: &[u8],
    terms: &LinkTerms,
) -> Result<GrantRow, InviteError> {
    let deadline = NonZeroU64::new(terms.deadline.0).ok_or(InviteError::InvalidExpiry)?;
    let mut row = mint_grant_row(
        owner_identity_signer,
        owner_enc_secret,
        pointer_read_key,
        invitee.identity_pk().to_sec1(),
        &invitee.enc_public(),
        scope_id,
        scope_root_ipns_name,
        Permission::Read,
    )
    .ok_or(InviteError::UnusableInviteeKey)?;
    let entry = &mut row.commitment_entry;
    entry.kind = GrantSetEntryKind::Link;
    entry.deadline = Some(deadline);
    entry.conversion_permission = Some(terms.conversion_permission);
    entry.admission_cap = Some(terms.admission_cap);
    Ok(row)
}

/// The bound on an invite fragment's decoded blob. The two names and the
/// contact bundle take most of it.
pub const MAX_INVITE_FRAGMENT_BYTES: usize = 2048;

/// The bound on each name a fragment carries — the bound a share display name
/// has, since the folder name is one.
pub const MAX_INVITE_NAME_BYTES: usize = MAX_NODE_NAME_BYTES;

/// The bound on the fragment *text*, so a hostile one is refused before its
/// blob is allocated. base64url spends four characters per three bytes.
const MAX_FRAGMENT_TEXT_LEN: usize = MAX_INVITE_FRAGMENT_BYTES.div_ceil(3) * 4;

/// An invite link's URL fragment — **the whole bearer capability**, as one
/// opaque blob (ADR 0023 D2, ADR 0027 D5).
///
/// The engine encodes it at the mint and decodes it at the claim, so a host
/// only ever moves it between a URL and a command: it composes no link and
/// parses none, and so never holds the invite secret or the pointer read key
/// as something it could log or store (#25 D6).
///
/// The fragment is plain det-CBOR with no MAC. The two names are under
/// [`names_sig`](Self::names_sig), the owner identity's signature, so a
/// forwarder cannot relabel a working link. Every other field fails closed on
/// its own: a changed pointer name or read key opens no re-point object under
/// the owner code, and a changed owner code verifies no record.
#[derive(Clone, PartialEq, Eq)]
pub struct InviteFragment {
    /// The invite secret — the whole capability.
    pub invite_secret: SecretBytes,
    /// The owner's contact code, which a claimant seals its claim to.
    pub owner_contact_code: Vec<u8>,
    /// The scope's id, which the re-point object's AAD binds.
    pub scope_id: [u8; 16],
    /// The scope pointer name, which does not move when a write wave moves the
    /// scope root.
    pub scope_pointer_name: IpnsName,
    /// The scope's stable pointer read key. Secret-bearing.
    pub pointer_read_key: SecretBytes,
    /// The owner's name, as the owner gave it. May be empty.
    pub owner_name: String,
    /// The shared folder's name.
    pub folder_name: String,
    /// The owner identity's signature over the names ([`Self::names`]).
    pub names_sig: [u8; ECDSA_SIG_LEN],
}

impl fmt::Debug for InviteFragment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InviteFragment")
            .field("invite_secret", &self.invite_secret)
            .field(
                "owner_contact_code",
                &RedactedBytes::of(&self.owner_contact_code),
            )
            .field("scope_id", &RedactedBytes::of(&self.scope_id))
            .field("scope_pointer_name", &self.scope_pointer_name)
            .field("pointer_read_key", &self.pointer_read_key)
            .finish_non_exhaustive()
    }
}

fn malformed_fragment<E>(_: E) -> InviteError {
    InviteError::MalformedFragment
}

fn bounded_names(owner_name: &str, folder_name: &str) -> Result<(), InviteError> {
    if owner_name.len() > MAX_INVITE_NAME_BYTES || folder_name.len() > MAX_INVITE_NAME_BYTES {
        return Err(InviteError::NameTooLong);
    }
    Ok(())
}

impl InviteFragment {
    /// The names [`names_sig`](Self::names_sig) covers.
    pub fn names(&self) -> InviteNames<'_> {
        InviteNames {
            scope_pointer_name: &self.scope_pointer_name,
            owner_name: &self.owner_name,
            folder_name: &self.folder_name,
        }
    }

    /// Sign the names under the owner identity.
    pub fn sign_names(&mut self, owner: &EcdsaSigner) {
        self.names_sig = sign_invite_names(owner, &self.names()).to_compact();
    }

    /// The owner name and the folder name, when the signature over them
    /// verifies under `owner`; `None` otherwise. A bad signature hides the
    /// names and leaves the link working (ADR 0027 D5).
    pub fn verified_names(&self, owner: &EcdsaVerifier) -> Option<(&str, &str)> {
        let sig = EcdsaSignature::from_compact(&self.names_sig)?;
        verify_invite_names(owner, &self.names(), &sig).ok()?;
        Some((&self.owner_name, &self.folder_name))
    }

    /// Encode to the text a URL fragment carries: strict det-CBOR under
    /// base64url, which needs no percent-encoding.
    pub fn encode(&self) -> Result<Zeroizing<String>, InviteError> {
        bounded_names(&self.owner_name, &self.folder_name)?;
        let mut m = Map::new();
        m.insert("folderName", Value::Text(self.folder_name.clone()));
        m.insert(
            "inviteSecret",
            Value::Bytes(self.invite_secret.as_bytes().to_vec()),
        );
        m.insert("namesSig", Value::Bytes(self.names_sig.to_vec()));
        m.insert(
            "ownerContactCode",
            Value::Bytes(self.owner_contact_code.clone()),
        );
        m.insert("ownerName", Value::Text(self.owner_name.clone()));
        m.insert(
            "pointerReadKey",
            Value::Bytes(self.pointer_read_key.as_bytes().to_vec()),
        );
        m.insert("scopeId", Value::Bytes(self.scope_id.to_vec()));
        m.insert(
            "scopePointerName",
            Value::Text(self.scope_pointer_name.as_str().to_owned()),
        );
        // The tree holds verbatim copies of the capability and this codec is
        // their terminal owner (`crates/core/src/codec/scrub.rs`).
        let mut tree = Value::Map(m);
        let blob = Zeroizing::new(encode_fixed_depth(&tree));
        tree.zeroize_bytes();
        if blob.len() > MAX_INVITE_FRAGMENT_BYTES {
            return Err(InviteError::FragmentTooLarge);
        }
        Ok(Zeroizing::new(FRAGMENT_B64.encode(blob.as_slice())))
    }

    /// Decode a fragment a bearer handed in.
    pub fn decode(fragment: &str) -> Result<Self, InviteError> {
        // Ahead of the base64 allocation, so an oversize fragment is refused
        // before it is materialised.
        if fragment.len() > MAX_FRAGMENT_TEXT_LEN {
            return Err(InviteError::FragmentTooLarge);
        }
        let blob = Zeroizing::new(FRAGMENT_B64.decode(fragment).map_err(malformed_fragment)?);
        if blob.len() > MAX_INVITE_FRAGMENT_BYTES {
            return Err(InviteError::FragmentTooLarge);
        }
        let mut tree = decode(&blob).map_err(malformed_fragment)?;
        // Wiped on every exit of the read, terminal owner as above.
        let parsed = Self::from_tree(&tree);
        tree.zeroize_bytes();
        parsed
    }

    fn from_tree(tree: &Value) -> Result<Self, InviteError> {
        let map = tree.as_map().map_err(malformed_fragment)?;
        let field = |name: &'static str| req(map, name).map_err(malformed_fragment);
        let text = |name: &'static str| -> Result<String, InviteError> {
            Ok(field(name)?
                .as_text()
                .map_err(malformed_fragment)?
                .to_owned())
        };
        let owner_name = text("ownerName")?;
        let folder_name = text("folderName")?;
        bounded_names(&owner_name, &folder_name)?;
        let owner_contact_code = field("ownerContactCode")?
            .as_bytes()
            .map_err(malformed_fragment)?
            .to_vec();
        let scope_pointer_name =
            IpnsName::parse(&text("scopePointerName")?).map_err(malformed_fragment)?;
        let scope_id = fixed::<16>(field("scopeId")?, "scopeId").map_err(malformed_fragment)?;
        let names_sig =
            fixed::<ECDSA_SIG_LEN>(field("namesSig")?, "namesSig").map_err(malformed_fragment)?;
        let secret = Zeroizing::new(
            fixed::<SECRET_LEN>(field("inviteSecret")?, "inviteSecret")
                .map_err(malformed_fragment)?,
        );
        let read_key = Zeroizing::new(
            fixed::<SECRET_LEN>(field("pointerReadKey")?, "pointerReadKey")
                .map_err(malformed_fragment)?,
        );
        Ok(Self {
            invite_secret: SecretBytes::new(*secret),
            owner_contact_code,
            scope_id,
            scope_pointer_name,
            pointer_read_key: SecretBytes::new(*read_key),
            owner_name,
            folder_name,
            names_sig,
        })
    }
}

/// Byte length of an [`InviteClaim::claim_id`].
pub const CLAIM_ID_LEN: usize = 16;

/// The claim a link holder posts to the owner's mailbox: the scope pointer the
/// link names, the claimant's own contact code to be anchored to, and the
/// claim's own id.
///
/// Opaque application bytes inside the HPKE seal — app framing, not crypto. Its
/// authentication is the seal's inner sender signature, which the claimant makes
/// with the link's ephemeral identity key ([`post_invite_claim`]); the contact
/// code inside is self-authenticating and imported fail-closed.
#[derive(Clone, PartialEq, Eq)]
pub struct InviteClaim {
    /// Fresh per claim ([`Self::mint`]), inside the signed payload.
    pub claim_id: [u8; CLAIM_ID_LEN],
    /// The scope pointer name the fragment carried. It does not move when a
    /// write wave moves the scope root (ADR 0023 D3 item 2).
    pub scope_pointer_name: IpnsName,
    /// The claimant's contact code — `{identityPk, encSubkey, bindingSig}`.
    pub contact_code: Vec<u8>,
}

impl fmt::Debug for InviteClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InviteClaim")
            .field("claim_id", &RedactedBytes::of(&self.claim_id))
            .field("scope_pointer_name", &self.scope_pointer_name)
            .field("contact_code", &RedactedBytes::of(&self.contact_code))
            .finish()
    }
}

impl InviteClaim {
    /// Build a claim with a fresh id from the injected entropy seam.
    pub fn mint<E: Entropy>(
        entropy: &mut E,
        scope_pointer_name: IpnsName,
        contact_code: Vec<u8>,
    ) -> Result<Self, InviteError> {
        Ok(Self {
            claim_id: fresh_bytes(entropy, "claim id").map_err(InviteError::Entropy)?,
            scope_pointer_name,
            contact_code,
        })
    }

    /// Encode to det-CBOR (canonical key order).
    pub fn encode(&self) -> Vec<u8> {
        let mut m = Map::new();
        m.insert("claimId", Value::Bytes(self.claim_id.to_vec()));
        m.insert("contactCode", Value::Bytes(self.contact_code.clone()));
        m.insert(
            "scopePointerName",
            Value::Text(self.scope_pointer_name.as_str().to_owned()),
        );
        encode_fixed_depth(&Value::Map(m))
    }

    /// Decode a claim (strict det-CBOR). A missing or mistyped field is
    /// [`Malformed`]. Unknown fields are dropped rather than preserved: this is a
    /// consume-once engine payload, not a re-sealed shared structure.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let value = decode(bytes)?;
        let map = value.as_map()?;
        Ok(Self {
            claim_id: fixed::<CLAIM_ID_LEN>(req(map, "claimId")?, "claimId")?,
            scope_pointer_name: IpnsName::parse(req(map, "scopePointerName")?.as_text()?)?,
            contact_code: req(map, "contactCode")?.as_bytes()?.to_vec(),
        })
    }
}

/// Post a claim to the owner's mailbox, sealed to the owner's encryption subkey
/// and signed — as the mailbox sender — with the link's ephemeral identity key.
/// That signature is what [`convert_invite_claim`] binds to the owner-attested
/// link row, so only a link holder can claim.
///
/// `owner` is the contact bundle the invite URL carries; `ephemeral_scalar` is
/// fresh-per-call HPKE entropy from the injected seam.
///
/// Residual: the post is an authenticated API call addressed to the owner's
/// identity key, so the transport learns claimant→owner even for claims the owner
/// never converts. Inherent to the mailbox; the payload itself stays sealed.
#[allow(clippy::too_many_arguments)]
pub async fn post_invite_claim<M: Mailbox>(
    mailbox: &M,
    owner: &Contact,
    invitee: &EphemeralInvitee,
    ephemeral_scalar: &[u8; 32],
    v: u64,
    claim: &InviteClaim,
    idempotency_key: &str,
) -> SeamResult<()> {
    post_sealed(
        mailbox,
        &owner.enc_subkey(),
        &owner.identity_pk(),
        ephemeral_scalar,
        v,
        &invitee.identity,
        &claim.encode(),
        idempotency_key,
    )
    .await
}

/// The owner's authority over a scope's grant set: the identity key that signs
/// the commitment, and the encryption subkey secret every blinded tag derives
/// from. Holding both is what makes a caller the owner.
pub struct OwnerAuthority<'a> {
    /// Owner identity signer. Both the capability token — verifying the
    /// commitment against a *supplied* public key would prove nothing about who
    /// is calling — and the signer of each minted row's recipient binding.
    pub identity_signer: &'a EcdsaSigner,
    /// Owner encryption subkey secret — the pairwise ECDH half.
    pub enc_secret: &'a X25519Secret,
}

/// A scope root's owner-signed grant set as resolved: the commitment, its
/// signature, and the write-body ledger it must reproduce. The scope root's
/// `ipnsName` is the commitment's own, so no caller supplies one.
///
/// Must be the **currently adopted** record's set. The commitment carries no
/// read epoch (`CONTEXT.md`), so a stale one still verifies and re-signing it
/// resurrects every tag cut since; the adoption gate's floor law, the cut epoch
/// included, is what keeps a served-stale record out.
///
/// No field of the commitment carries a scope id, so [`bind`](Self::bind) is the
/// only constructor: the scope id is read off the gated scope reference the
/// commitment was resolved under, never taken beside it. An owner-authentic
/// commitment for one scope can therefore not be presented under another scope's
/// id.
pub struct CommittedScope<'a> {
    pub(super) scope_id: &'a [u8; 16],
    pub(super) commitment: &'a GrantSetCommitment,
    pub(super) commitment_sig: &'a EcdsaSignature,
    pub(super) ledger: &'a [GrantLedgerEntry],
}

impl<'a> CommittedScope<'a> {
    /// Bind `commitment` to the scope `scope` names, or fail closed.
    ///
    /// `scope` must be the reference the adoption gate proved the commitment's
    /// own record under, which is what makes its scope id the record's
    /// (`rotation/cascade.rs` — the resolver's binding contract). The refusal
    /// is the backstop for a reference no gate produced.
    pub fn bind(
        scope: &'a ChildScopeRef,
        commitment: &'a GrantSetCommitment,
        commitment_sig: &'a EcdsaSignature,
        ledger: &'a [GrantLedgerEntry],
    ) -> Result<Self, InviteError> {
        if commitment.ipns_name != scope.ipns_name {
            return Err(InviteError::ScopeUnbound);
        }
        Ok(Self {
            scope_id: &scope.scope_id,
            commitment,
            commitment_sig,
            ledger,
        })
    }
}

impl OwnerAuthority<'_> {
    /// Fail closed unless this caller's identity key signed the committed set it
    /// is about to act on. Every commitment change is owner-only.
    pub fn authorise(&self, scope: &CommittedScope<'_>) -> Result<(), InviteError> {
        verify_grant_set(
            &self.identity_signer.verifying_key(),
            scope.commitment,
            scope.commitment_sig,
        )
        .map_err(|_| InviteError::NotOwner)
    }
}

/// One link on a scope's committed set, read off the owner-signed record
/// (ADR 0023 D3 item 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommittedLink {
    /// The tag the current commitment carries for the link — what a cut names.
    pub tag: [u8; 32],
    /// The ephemeral identity a link holder signs its claim with, from the
    /// owner-attested ledger row.
    pub ephemeral_identity_pk: [u8; IDENTITY_PUBLIC_LEN],
    /// The ephemeral encryption subkey the link's blob is sealed to.
    pub ephemeral_enc_pk: [u8; SECRET_LEN],
    /// The owner-signed deadline. Core refuses a link entry without one.
    pub deadline: UnixMillis,
    /// The permission conversion grants a claimant.
    pub conversion_permission: Permission,
    /// The owner-signed admission cap. Core refuses a link entry without one.
    pub admission_cap: u64,
}

impl CommittedLink {
    /// Whether `now` has reached the deadline.
    pub fn is_expired(&self, now: UnixMillis) -> bool {
        now.reached(Some(self.deadline))
    }
}

/// Every link entry on `scope`'s committed set whose ledger row the owner
/// attested, in commitment order.
///
/// Owner-only: the set is read only under this caller's own signature over it.
/// A link entry with no attested row names no ephemeral identity the owner
/// vouched for, so it is left out rather than trusted.
pub fn committed_links(
    owner: &OwnerAuthority<'_>,
    scope: &CommittedScope<'_>,
) -> Result<Vec<CommittedLink>, InviteError> {
    owner.authorise(scope)?;
    let owner_identity = owner.identity_signer.verifying_key();
    let name = scope.commitment.ipns_name.as_slice();
    Ok(scope
        .commitment
        .entries
        .iter()
        .filter(|entry| entry.kind == GrantSetEntryKind::Link)
        .filter_map(|entry| {
            let row = scope.ledger.iter().find(|row| row.tag == entry.tag)?;
            let deadline = UnixMillis(entry.deadline?.get());
            let admission_cap = entry.admission_cap?;
            row_is_owner_attested(&owner_identity, row, name).then(|| CommittedLink {
                tag: entry.tag,
                ephemeral_identity_pk: row.recipient_identity_pk,
                ephemeral_enc_pk: row.recipient_enc_pk,
                deadline,
                conversion_permission: entry.conversion_permission.unwrap_or(Permission::Read),
                admission_cap,
            })
        })
        .collect())
}

/// The link on `scope` a revoke cuts: the one `tag` names, or with no tag the
/// only link the set commits. Two links and no tag give no defined cut, so
/// neither is picked.
pub fn locate_invite_link(
    owner: &OwnerAuthority<'_>,
    scope: &CommittedScope<'_>,
    tag: Option<&[u8; 32]>,
) -> Result<CommittedLink, InviteError> {
    let links = committed_links(owner, scope)?;
    match (tag, links.as_slice()) {
        (Some(tag), links) => links
            .iter()
            .find(|link| link.tag == *tag)
            .copied()
            .ok_or(InviteError::LinkNotCommitted),
        (None, [link]) => Ok(*link),
        (None, []) => Err(InviteError::LinkNotCommitted),
        (None, _) => Err(InviteError::LinkAmbiguous),
    }
}

/// What converting a claim did to the owner-signed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// The claimant had no grant on this scope; one was appended.
    Granted,
    /// The claimant already holds a row on this scope. The set comes back
    /// untouched and needs no republish (ADR 0023 D3).
    Unchanged,
}

/// A claim converted into a personal grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConvertedClaim {
    /// The personal grant for the claimant's contact-anchored identity. It
    /// inherits no deadline: the link expires, the grants it produced do not.
    pub row: GrantRow,
    /// The grant-set commitment the owner re-signs. The link's own entry stays,
    /// so one link yields a grant per claimant until it expires or is revoked.
    pub commitment: GrantSetCommitment,
    /// The grant ledger matching it.
    pub ledger: Vec<GrantLedgerEntry>,
    /// The claimant's verified contact, as the claim's own bundle imported. It
    /// is the only address the share pointer for this grant can be sent to: the
    /// item's sender is the link's ephemeral identity, not the claimant's.
    pub claimant: Contact,
    /// The committed tag of the link the claim came in on. The owner charges
    /// the contact it records to this link.
    pub link_tag: [u8; 32],
    /// The contact-code bytes [`claimant`](Self::claimant) imported from. The
    /// owner records them in the contact book before the grant publishes, so a
    /// later revoke or downgrade resolves the recipient it just granted.
    pub claimant_code: Vec<u8>,
    /// What this conversion changed.
    pub outcome: ClaimOutcome,
}

/// Convert a sender-verified invite claim into a personal grant for the
/// claimant's contact-anchored identity (ADR 0023 D3).
///
/// The link is the owner-attested ledger row whose `recipientIdentityPk` is the
/// item's sender and whose commitment entry is a link entry; the owner device
/// holds no other record of it. `scope_pointer_name` is the pointer of the
/// scope `scope` binds, which the claim must name. `now` is the injected
/// [`Scheduler::now`](crate::seams::Scheduler::now) instant.
///
/// The grant is minted at `read`.
///
/// The caller signs and publishes the returned set, and acks the mailbox item
/// only once that is durable.
pub fn convert_invite_claim(
    owner: &OwnerAuthority<'_>,
    scope: &CommittedScope<'_>,
    scope_pointer_name: &IpnsName,
    pointer_read_key: &[u8; SECRET_LEN],
    item: &VerifiedMailboxItem,
    now: UnixMillis,
) -> Result<ConvertedClaim, InviteError> {
    let links = committed_links(owner, scope)?;
    let claim = InviteClaim::decode(&item.payload).map_err(InviteError::MalformedClaim)?;
    if claim.scope_pointer_name != *scope_pointer_name {
        return Err(InviteError::ScopeMismatch);
    }
    let sender = item.sender_identity.to_sec1();
    let mut matches = links
        .iter()
        .filter(|link| link.ephemeral_identity_pk == sender);
    let link = *matches.next().ok_or(InviteError::LinkNotCommitted)?;
    if matches.next().is_some() {
        return Err(InviteError::LinkNotCommitted);
    }
    if link.is_expired(now) {
        return Err(InviteError::LinkExpired);
    }
    let contact = import_contact(&claim.contact_code).map_err(InviteError::ClaimantContact)?;
    let claimant_identity = contact.identity_pk().to_sec1();
    if claimant_identity == link.ephemeral_identity_pk
        || contact.enc_subkey().to_bytes() == link.ephemeral_enc_pk
    {
        return Err(InviteError::ClaimantIsTheEphemeralHalf);
    }
    // The invite URL carries the owner's own bundle; handing it back would file a
    // self-grant that consumes a slot and reads as a grantee in the host's UI.
    if contact.enc_subkey() == owner.enc_secret.public() {
        return Err(InviteError::ClaimantIsTheOwner);
    }
    let name = scope.commitment.ipns_name.as_slice();
    let mut row = mint_grant_row(
        owner.identity_signer,
        owner.enc_secret,
        pointer_read_key,
        claimant_identity,
        &contact.enc_subkey(),
        scope.scope_id,
        name,
        Permission::Read,
    )
    .ok_or(InviteError::UnusableClaimantKey)?;

    let owner_identity = owner.identity_signer.verifying_key();
    let held = scope
        .commitment
        .entries
        .iter()
        .find(|entry| entry.tag == row.tag)
        .map(|entry| entry.permission)
        .or_else(|| {
            scope
                .ledger
                .iter()
                .find(|entry| {
                    entry.recipient_identity_pk == claimant_identity
                        && row_is_owner_attested(&owner_identity, entry, name)
                })
                .map(|entry| entry.permission)
        });
    let mut commitment = scope.commitment.clone();
    let mut ledger = scope.ledger.to_vec();
    let outcome = match held {
        None => {
            commitment.entries.push(row.commitment_entry.clone());
            ledger.push(row.ledger_entry.clone());
            ClaimOutcome::Granted
        }
        // A known identity is a no-op: report the grant that stands.
        Some(permission) => {
            row.commitment_entry.permission = permission;
            row.ledger_entry.permission = permission;
            ClaimOutcome::Unchanged
        }
    };
    check_publishable(&commitment, &ledger)?;
    Ok(ConvertedClaim {
        row,
        commitment,
        ledger,
        claimant: contact,
        link_tag: link.tag,
        claimant_code: claim.contact_code,
        outcome,
    })
}

/// The produce-side mirror of what a resolver hard-rejects: the grant-set
/// ceiling, a repeated tag, and a ledger diverging from the commitment (core
/// rejects the first two at decode and before signing; the last is the adoption
/// gate's owner-authority check). Release-active, so no build can emit a set its
/// own readers refuse.
pub(super) fn check_publishable(
    commitment: &GrantSetCommitment,
    ledger: &[GrantLedgerEntry],
) -> Result<(), InviteError> {
    if commitment.entries.len() > MAX_GRANT_BLOBS || ledger.len() > MAX_GRANT_BLOBS {
        return Err(InviteError::GrantSetFull);
    }
    if !ids_are_unique(commitment.entries.iter().map(|e| e.tag))
        || !ids_are_unique(ledger.iter().map(|e| e.tag))
    {
        return Err(InviteError::DuplicateTag);
    }
    enforce_committed_ledger(commitment, ledger).map_err(InviteError::Authority)
}

fn ids_are_unique(ids: impl Iterator<Item = [u8; 32]>) -> bool {
    let mut seen = BTreeSet::new();
    ids.into_iter().all(|id| seen.insert(id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rotation::{
        CommittedSet, ResealSeeds, ScopeRootIdentity, WriteHistory, reseal_scope_root,
    };
    use crate::testkit::SeededEntropy;
    use cipherbox_core::codec::encode;
    use cipherbox_core::seal::{
        AadContext, GrantSection, PreservedFields, STRUCT_TAG_GRANT_BLOB, open_grant_blob,
        sign_grant_set,
    };
    use cipherbox_core::suite::contact::ContactCode;
    use cipherbox_core::suite::ed25519::Ed25519Signer;
    use cipherbox_core::suite::secret::ct_eq;

    const V: u64 = 2;
    const SCOPE: [u8; 16] = [0x5c; 16];
    const EPOCH: u64 = 5;
    const OVERRIDE_SEED: [u8; 32] = [0x99; 32];
    const WRITE_SCOPE_SEED: [u8; 32] = [0x55; 32];
    const POINTER_READ_KEY: [u8; 32] = [0x66; 32];
    const DEADLINE: UnixMillis = UnixMillis(1_700_000_000_000);

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

    fn pointer_name() -> IpnsName {
        IpnsName::from_public_key(&Ed25519Signer::from_seed([0x5d; 32]).verifying_key())
    }

    fn terms(deadline: UnixMillis, conversion_permission: Permission) -> LinkTerms {
        LinkTerms {
            deadline,
            conversion_permission,
            admission_cap: 4,
        }
    }

    fn link_row(invitee: &EphemeralInvitee) -> GrantRow {
        mint_invite_grant(
            &owner_identity(),
            &owner_enc(),
            &POINTER_READ_KEY,
            invitee,
            &SCOPE,
            &WRITE_SCOPE_SEED,
            &terms(DEADLINE, Permission::Write),
        )
        .expect("mints")
    }

    fn personal_row(identity: &EcdsaSigner, enc: &X25519Secret) -> GrantRow {
        mint_grant_row(
            &owner_identity(),
            &owner_enc(),
            &POINTER_READ_KEY,
            identity.verifying_key().to_sec1(),
            &enc.public(),
            &SCOPE,
            &scope_name(),
            Permission::Read,
        )
        .expect("contributory")
    }

    /// Re-seal a scope root committing exactly `grants`.
    fn scope_root(grants: &[GrantRow]) -> GrantSection {
        let owner_pub = owner_enc().public();
        let name = scope_name();
        let commitment = GrantSetCommitment {
            ipns_name: name.clone(),
            owner_pseudonym_pk: owner_pseudonym().verifying_key().to_bytes(),
            cut_epoch: 0,
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
                owner_enc_secret: None,
                ascent: None,
                owes_ascent_link: false,
                pseudonym_signer: &owner_pseudonym(),
            },
            &ResealSeeds {
                override_seed: &OVERRIDE_SEED,
                read_epoch: EPOCH,
                prev: None,
                write_scope_seed: &WRITE_SCOPE_SEED,
                write_epoch: 1,
                pointer_read_key: &POINTER_READ_KEY,
                write_history: WriteHistory::Genesis,
            },
            &CommittedSet {
                commitment: &commitment,
                commitment_sig: &sig,
                grant_ledger: &ledger,
                direct_child_scope_index: &[],
                revoked_recipients: &[],
            },
            &[],
        )
        .expect("reseal")
    }

    fn fragment() -> InviteFragment {
        let mut fragment = InviteFragment {
            invite_secret: SecretBytes::new([0x4e; 32]),
            owner_contact_code: ContactCode::create(&owner_identity(), owner_enc().public())
                .encode(),
            scope_id: SCOPE,
            scope_pointer_name: pointer_name(),
            pointer_read_key: SecretBytes::new(POINTER_READ_KEY),
            owner_name: "Ada".to_owned(),
            folder_name: "Photos".to_owned(),
            names_sig: [0; ECDSA_SIG_LEN],
        };
        fragment.sign_names(&owner_identity());
        fragment
    }

    /// One owner, one committed set.
    struct Scope {
        name: Vec<u8>,
        reference: ChildScopeRef,
        commitment: GrantSetCommitment,
        sig: EcdsaSignature,
        ledger: Vec<GrantLedgerEntry>,
    }

    impl Scope {
        fn of(rows: &[&GrantRow]) -> Self {
            let name = scope_name();
            let commitment = GrantSetCommitment {
                ipns_name: name.clone(),
                owner_pseudonym_pk: owner_pseudonym().verifying_key().to_bytes(),
                cut_epoch: 0,
                entries: rows.iter().map(|r| r.commitment_entry.clone()).collect(),
                unknown: PreservedFields::new(),
            };
            let sig = sign_grant_set(&owner_identity(), &commitment).expect("signs");
            Self {
                reference: ChildScopeRef::new(SCOPE, name.clone()),
                name,
                commitment,
                sig,
                ledger: rows.iter().map(|r| r.ledger_entry.clone()).collect(),
            }
        }

        fn bound(&self) -> CommittedScope<'_> {
            CommittedScope::bind(&self.reference, &self.commitment, &self.sig, &self.ledger)
                .expect("names its own root")
        }
    }

    fn authority<'a>(identity: &'a EcdsaSigner, enc: &'a X25519Secret) -> OwnerAuthority<'a> {
        OwnerAuthority {
            identity_signer: identity,
            enc_secret: enc,
        }
    }

    fn claimant(seed: u8) -> (EcdsaSigner, X25519Secret) {
        (
            EcdsaSigner::from_scalar(&[seed; 32]).expect("valid scalar"),
            X25519Secret::from_scalar([seed.wrapping_add(1); 32]),
        )
    }

    fn claim_item(
        sender: &EcdsaSigner,
        contact: Vec<u8>,
        pointer: IpnsName,
    ) -> VerifiedMailboxItem {
        VerifiedMailboxItem {
            item_id: "claim".to_owned(),
            sender_identity: sender.verifying_key(),
            payload: InviteClaim {
                claim_id: [0x71; CLAIM_ID_LEN],
                scope_pointer_name: pointer,
                contact_code: contact,
            }
            .encode(),
        }
    }

    fn convert(
        scope: &Scope,
        sender: &EcdsaSigner,
        contact: Vec<u8>,
        now: UnixMillis,
    ) -> Result<ConvertedClaim, InviteError> {
        let (identity, enc) = (owner_identity(), owner_enc());
        convert_invite_claim(
            &authority(&identity, &enc),
            &scope.bound(),
            &pointer_name(),
            &POINTER_READ_KEY,
            &claim_item(sender, contact, pointer_name()),
            now,
        )
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
    }

    #[test]
    fn minting_draws_the_secret_from_the_injected_entropy_seam() {
        let from_seam = EphemeralInvitee::mint(&mut SeededEntropy::new(7)).expect("mints");
        let expected = fresh_seed(&mut SeededEntropy::new(7)).expect("fills");
        assert!(ct_eq(from_seam.secret().as_bytes(), &expected));
    }

    #[test]
    fn from_secret_fails_closed_on_an_invalid_scalar() {
        assert_eq!(
            EphemeralInvitee::from_secret(&[0u8; 32]).unwrap_err(),
            InviteError::InvalidSecret,
        );
    }

    /// ADR 0023 D2, ADR 0024 D4: the link entry carries its kind and terms
    /// under the commitment signature, and is committed at `read`.
    #[test]
    fn a_minted_link_entry_is_a_read_link_entry_carrying_its_terms() {
        let row = link_row(&invitee());
        let entry = &row.commitment_entry;
        assert_eq!(entry.kind, GrantSetEntryKind::Link);
        assert_eq!(entry.permission, Permission::Read);
        assert_eq!(row.ledger_entry.permission, Permission::Read);
        assert_eq!(entry.deadline.map(NonZeroU64::get), Some(DEADLINE.0));
        assert_eq!(entry.conversion_permission, Some(Permission::Write));
        assert_eq!(entry.admission_cap, Some(4));
    }

    #[test]
    fn a_zero_deadline_is_refused_at_the_mint() {
        assert_eq!(
            mint_invite_grant(
                &owner_identity(),
                &owner_enc(),
                &POINTER_READ_KEY,
                &invitee(),
                &SCOPE,
                &WRITE_SCOPE_SEED,
                &terms(UnixMillis(0), Permission::Read),
            )
            .unwrap_err(),
            InviteError::InvalidExpiry,
        );
    }

    /// The blob of a write link opens no write seed: a link is committed at
    /// `read`, and the committed permission alone selects the blob material.
    #[test]
    fn the_blob_of_a_write_link_opens_no_write_seed() {
        let holder = invitee();
        let row = link_row(&holder);
        let section = scope_root(&[row.clone()]);
        let blob = section
            .grant_blobs
            .iter()
            .find(|blob| blob.tag == row.tag)
            .expect("a blob at the link tag");
        let opened = open_grant_blob(
            holder.enc_secret(),
            &blob.enc,
            &AadContext {
                v: V,
                id: SCOPE,
                scope: SCOPE,
                epoch: EPOCH,
                struct_tag: STRUCT_TAG_GRANT_BLOB,
            },
            &blob.ciphertext,
        )
        .expect("the fragment secret opens the blob");
        assert!(ct_eq(opened.read_scope_seed(), &OVERRIDE_SEED));
        assert!(opened.write_scope_seed().is_none());
    }

    #[test]
    fn a_link_blob_is_byte_shaped_like_a_personal_grant_blob() {
        let (identity, enc) = claimant(0x77);
        let personal = personal_row(&identity, &enc);
        let link = link_row(&invitee());
        let section = scope_root(&[personal.clone(), link.clone()]);
        let len = |tag: [u8; 32]| {
            section
                .grant_blobs
                .iter()
                .find(|blob| blob.tag == tag)
                .expect("a blob")
                .ciphertext
                .len()
        };
        assert_eq!(len(personal.tag), len(link.tag));
    }

    /// The fragment round-trips with its signature, and the names verify under
    /// the owner code the fragment carries.
    #[test]
    fn a_fragment_round_trips_with_its_signature() {
        let minted = fragment();
        let text = minted.encode().expect("encodes");
        let decoded = InviteFragment::decode(&text).expect("decodes");
        assert!(decoded == minted);
        let owner = import_contact(&decoded.owner_contact_code).expect("a bound owner code");
        assert_eq!(
            decoded.verified_names(&owner.identity_pk()),
            Some(("Ada", "Photos")),
        );
    }

    /// ADR 0027 D5: a relabelled fragment shows no names, and every name is
    /// under the signature.
    #[test]
    fn a_changed_owner_name_fails_the_signature_check() {
        let owner = owner_identity().verifying_key();
        let mut relabelled = fragment();
        relabelled.owner_name = "Eve".to_owned();
        let decoded = InviteFragment::decode(&relabelled.encode().expect("encodes"))
            .expect("the link still decodes");
        assert_eq!(decoded.verified_names(&owner), None);

        let mut refoldered = fragment();
        refoldered.folder_name = "Taxes".to_owned();
        assert_eq!(refoldered.verified_names(&owner), None);

        let mut repointed = fragment();
        repointed.scope_pointer_name =
            IpnsName::from_public_key(&Ed25519Signer::from_seed([0x5e; 32]).verifying_key());
        assert_eq!(repointed.verified_names(&owner), None);

        let stranger = EcdsaSigner::from_scalar(&[0x34; 32]).expect("valid scalar");
        assert_eq!(fragment().verified_names(&stranger.verifying_key()), None);
    }

    /// Encode and decode refuse a name past its bound alike (AGENTS.md rule 8).
    #[test]
    fn a_name_past_its_bound_is_refused_at_both_ends() {
        let mut long = fragment();
        long.folder_name = "n".repeat(MAX_INVITE_NAME_BYTES + 1);
        assert_eq!(long.encode().unwrap_err(), InviteError::NameTooLong);

        let at_bound = {
            let mut f = fragment();
            f.owner_name = "o".repeat(MAX_INVITE_NAME_BYTES);
            f.folder_name = "n".repeat(MAX_INVITE_NAME_BYTES);
            f
        };
        let text = at_bound.encode().expect("a name at the bound encodes");
        assert!(InviteFragment::decode(&text).is_ok());

        // A hand-built blob one byte past the bound, which no encode emits.
        let blob = FRAGMENT_B64.decode(text.as_bytes()).expect("base64url");
        let mut tree = decode(&blob).expect("det-CBOR");
        let Value::Map(map) = &mut tree else {
            panic!("a fragment is a map");
        };
        map.insert(
            "ownerName",
            Value::Text("o".repeat(MAX_INVITE_NAME_BYTES + 1)),
        );
        let forged = FRAGMENT_B64.encode(encode(&tree).expect("encodes"));
        assert_eq!(
            InviteFragment::decode(&forged).unwrap_err(),
            InviteError::NameTooLong
        );
    }

    /// A fragment minted before the pointer fields existed names a scope root
    /// only, and is refused: such a link is unclaimable (ADR 0023 C2).
    #[test]
    fn a_fragment_without_the_scope_pointer_is_refused() {
        let mut m = Map::new();
        m.insert("inviteSecret", Value::Bytes(vec![0x4e; 32]));
        m.insert(
            "ownerContactCode",
            Value::Bytes(fragment().owner_contact_code),
        );
        m.insert("scopeRootName", Value::Bytes(scope_name()));
        let text = FRAGMENT_B64.encode(encode(&Value::Map(m)).expect("encodes"));
        assert_eq!(
            InviteFragment::decode(&text).unwrap_err(),
            InviteError::MalformedFragment
        );
    }

    #[test]
    fn a_fragment_that_is_not_one_is_refused() {
        assert_eq!(
            InviteFragment::decode("not a fragment!!").unwrap_err(),
            InviteError::MalformedFragment
        );
        assert_eq!(
            InviteFragment::decode(&"A".repeat(MAX_INVITE_FRAGMENT_BYTES * 2)).unwrap_err(),
            InviteError::FragmentTooLarge
        );
    }

    #[test]
    fn a_fragment_debug_withholds_its_secrets() {
        let rendered = format!("{:?}", fragment());
        assert!(!rendered.contains("Ada"));
        assert!(!rendered.contains("Photos"));
        assert!(!rendered.contains(&format!("{POINTER_READ_KEY:?}")));
    }

    #[test]
    fn the_claim_payload_round_trips_and_names_the_scope_pointer() {
        let claim = InviteClaim {
            claim_id: [0x71; CLAIM_ID_LEN],
            scope_pointer_name: pointer_name(),
            contact_code: vec![1, 2, 3],
        };
        assert!(InviteClaim::decode(&claim.encode()).expect("decodes") == claim);
        let mut m = Map::new();
        m.insert("claimId", Value::Bytes(vec![0x71; CLAIM_ID_LEN]));
        m.insert("contactCode", Value::Bytes(vec![1]));
        m.insert("scopeRootName", Value::Bytes(scope_name()));
        assert!(InviteClaim::decode(&encode(&Value::Map(m)).expect("encodes")).is_err());
    }

    /// ADR 0023 D3: the link is the owner-attested row the sender signs for,
    /// read off the record alone; one link converts one claimant per grant and
    /// stays live.
    #[test]
    fn a_claim_converts_against_the_link_row_on_the_record() {
        let link = invitee();
        let link_row = link_row(&link);
        let scope = Scope::of(&[&link_row]);
        let sender = EcdsaSigner::from_scalar(link.secret().as_bytes()).expect("valid");
        let (identity, enc) = claimant(0x40);

        let converted = convert(
            &scope,
            &sender,
            ContactCode::create(&identity, enc.public()).encode(),
            UnixMillis(0),
        )
        .expect("converts");

        assert_eq!(converted.outcome, ClaimOutcome::Granted);
        assert_eq!(converted.link_tag, link_row.tag);
        assert_eq!(
            converted.row.commitment_entry.kind,
            GrantSetEntryKind::Personal
        );
        assert_eq!(converted.row.commitment_entry.permission, Permission::Read);
        assert_eq!(
            converted.row.ledger_entry.recipient_identity_pk,
            identity.verifying_key().to_sec1()
        );
        assert_eq!(converted.commitment.entries.len(), 2);
        assert!(
            converted
                .commitment
                .entries
                .iter()
                .any(|entry| entry.tag == link_row.tag),
            "the link stays live"
        );
        assert_eq!(scope.name, converted.commitment.ipns_name);
    }

    /// A known identity is a no-op (ADR 0023 D3).
    #[test]
    fn a_claim_from_a_committed_grantee_changes_nothing() {
        let link = invitee();
        let link_row = link_row(&link);
        let (identity, enc) = claimant(0x40);
        let scope = Scope::of(&[&link_row, &personal_row(&identity, &enc)]);
        let sender = EcdsaSigner::from_scalar(link.secret().as_bytes()).expect("valid");

        let converted = convert(
            &scope,
            &sender,
            ContactCode::create(&identity, enc.public()).encode(),
            UnixMillis(0),
        )
        .expect("converts");

        assert_eq!(converted.outcome, ClaimOutcome::Unchanged);
        assert!(converted.commitment == scope.commitment);
    }

    #[test]
    fn a_claim_past_the_link_deadline_is_refused() {
        let link = invitee();
        let link_row = link_row(&link);
        let scope = Scope::of(&[&link_row]);
        let sender = EcdsaSigner::from_scalar(link.secret().as_bytes()).expect("valid");
        let (identity, enc) = claimant(0x40);
        let code = ContactCode::create(&identity, enc.public()).encode();

        assert!(convert(&scope, &sender, code.clone(), UnixMillis(DEADLINE.0 - 1)).is_ok());
        assert_eq!(
            convert(&scope, &sender, code, DEADLINE).unwrap_err(),
            InviteError::LinkExpired
        );
    }

    /// A sender whose row is personal, or whose link row the owner did not
    /// attest, signs for no link.
    #[test]
    fn only_an_attested_link_row_takes_a_claim() {
        let (identity, enc) = claimant(0x40);
        let code = ContactCode::create(&identity, enc.public()).encode();
        let (grantee, grantee_enc) = claimant(0x50);
        let personal = personal_row(&grantee, &grantee_enc);
        let scope = Scope::of(&[&personal]);
        assert_eq!(
            convert(&scope, &grantee, code.clone(), UnixMillis(0)).unwrap_err(),
            InviteError::LinkNotCommitted,
            "a personal row is no link"
        );

        let link = invitee();
        let mut forged = link_row(&link);
        forged.ledger_entry.owner_sig = [0x01; ECDSA_SIG_LEN];
        let scope = Scope::of(&[&forged]);
        let sender = EcdsaSigner::from_scalar(link.secret().as_bytes()).expect("valid");
        assert_eq!(
            convert(&scope, &sender, code, UnixMillis(0)).unwrap_err(),
            InviteError::LinkNotCommitted,
            "an unattested row names no identity the owner vouched for"
        );
    }

    #[test]
    fn a_claim_naming_another_scope_pointer_is_refused() {
        let link = invitee();
        let link_row = link_row(&link);
        let scope = Scope::of(&[&link_row]);
        let sender = EcdsaSigner::from_scalar(link.secret().as_bytes()).expect("valid");
        let (identity, enc) = claimant(0x40);
        let (owner, owner_enc) = (owner_identity(), owner_enc());
        let elsewhere =
            IpnsName::from_public_key(&Ed25519Signer::from_seed([0x5e; 32]).verifying_key());
        assert_eq!(
            convert_invite_claim(
                &authority(&owner, &owner_enc),
                &scope.bound(),
                &pointer_name(),
                &POINTER_READ_KEY,
                &claim_item(
                    &sender,
                    ContactCode::create(&identity, enc.public()).encode(),
                    elsewhere,
                ),
                UnixMillis(0),
            )
            .unwrap_err(),
            InviteError::ScopeMismatch
        );
    }

    #[test]
    fn a_non_owner_can_neither_convert_nor_locate() {
        let link = invitee();
        let link_row = link_row(&link);
        let scope = Scope::of(&[&link_row]);
        let (stranger, stranger_enc) = claimant(0x60);
        assert_eq!(
            locate_invite_link(&authority(&stranger, &stranger_enc), &scope.bound(), None)
                .unwrap_err(),
            InviteError::NotOwner
        );
        let (identity, enc) = (owner_identity(), owner_enc());
        let located = locate_invite_link(&authority(&identity, &enc), &scope.bound(), None)
            .expect("the owner locates its link");
        assert_eq!(located.tag, link_row.tag);
        assert_eq!(located.ephemeral_identity_pk, link.identity_pk().to_sec1());
    }

    /// Two link entries and no tag have no defined cut, so locate names
    /// neither. A tag picks one, and a tag no link carries picks nothing.
    #[test]
    fn two_links_locate_only_the_one_a_tag_names() {
        let first = link_row(&invitee());
        let second = link_row(&EphemeralInvitee::from_secret(&[0x4f; 32]).expect("valid"));
        let scope = Scope::of(&[&first, &second]);
        let (identity, enc) = (owner_identity(), owner_enc());
        assert_eq!(
            committed_links(&authority(&identity, &enc), &scope.bound())
                .expect("the owner reads its links")
                .len(),
            2
        );
        let owner = authority(&identity, &enc);
        assert_eq!(
            locate_invite_link(&owner, &scope.bound(), None).unwrap_err(),
            InviteError::LinkAmbiguous
        );
        assert_eq!(
            locate_invite_link(&owner, &scope.bound(), Some(&second.tag))
                .expect("the tag names a committed link")
                .tag,
            second.tag
        );
        assert_eq!(
            locate_invite_link(&owner, &scope.bound(), Some(&[0x11; 32])).unwrap_err(),
            InviteError::LinkNotCommitted
        );
    }
}
