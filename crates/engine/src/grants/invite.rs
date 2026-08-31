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
//! ciphertext length is the residual observable.) Parity is per record, not per
//! transaction: a link mints its scope exactly as a personal grant does but
//! posts no share pointer, so "a scope root registered with no mailbox post
//! behind it" still tells the API which folders were shared by link.
//!
//! The invite secret is the whole capability — it rides the link's URL fragment,
//! so the link is honestly bearer and multi-claim. Its deadline lives on
//! [`GrantLedgerEntry::expires_at`], which states what a deadline does and does
//! not guarantee.
//!
//! A holder claims by posting an [`InviteClaim`] to the owner's mailbox signed
//! with the ephemeral identity; [`convert_invite_claim`] re-anchors it to the
//! claimant's imported contact as an ordinary personal grant, leaving the link
//! itself live.
//!
//! A claim is single-use. The mailbox chooses what to redeliver, so a claim
//! carrying no identity of its own is a static blob the server can re-serve
//! after the owner cut the grant it made, and re-converting it would have the
//! owner re-sign a set that undoes its own revocation. [`InviteClaim::claim_id`]
//! is that identity, inside the signed payload, and [`ConvertedClaimRecord`] is
//! the owner-local memory of what it has spent.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as FRAGMENT_B64;
use cipherbox_core::codec::{Map, Value, decode, encode_fixed_depth};
use cipherbox_core::error::{CodecError, Malformed};
use cipherbox_core::seal::{
    GrantLedgerEntry, GrantSetCommitment, MAX_GRANT_BLOBS, Permission, verify_grant_set,
};
use cipherbox_core::suite::ecdsa::{
    EcdsaSignature, EcdsaSigner, EcdsaVerifier, IDENTITY_PUBLIC_LEN,
};
use cipherbox_core::suite::secret::{SECRET_LEN, SecretBytes};
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};
use cipherbox_core::{ipns::IpnsName, kdf};
use core::fmt;
use core::num::NonZeroU64;
use std::collections::BTreeSet;
use zeroize::{Zeroize, Zeroizing};

use crate::entropy::{Entropy, EntropyError, fresh_bytes, fresh_seed};
use crate::grants::accept::{fixed, req};
use crate::grants::contact::import_contact;
use crate::grants::{
    AuthorityViolation, Contact, GrantRow, enforce_committed_ledger, entry_is_live, mint_grant_row,
    recipient_blinded_tag,
};
use crate::mailbox::{VerifiedMailboxItem, post_sealed};
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
    /// The deadline was `0`. Refused rather than mapped to "no deadline", which
    /// would silently mint a link that never expires
    /// ([`Malformed::InvalidExpiry`](cipherbox_core::error::Malformed::InvalidExpiry)).
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
    /// The claim names a different scope root than the committed set it is
    /// converted against.
    ScopeMismatch,
    /// The scope id offered with a commitment is not the one whose write
    /// material derives the scope root name that commitment carries
    /// ([`CommittedScope::bind`]).
    ScopeUnbound,
    /// The caller's identity key did not sign the committed set it is acting on,
    /// so it is not this scope's owner. Minting, converting and revoking are all
    /// owner-only.
    NotOwner,
    /// No live owner-committed link answers to the claim's ephemeral identity —
    /// the row is absent, uncommitted, or not this owner's ECDH partner.
    LinkNotCommitted,
    /// The link's ledger row is past its deadline, so it grants nothing.
    LinkExpired,
    /// The claim's id is in the owner's spent set. Ack the item; publish
    /// nothing.
    ClaimAlreadyConverted,
    /// The claim carries an all-zero id, which [`InviteClaim::mint`] never
    /// draws. Converting it would spend the one id a client with a broken
    /// entropy seam emits, denying every later claimant on the link.
    ClaimIdIsZero,
    /// A fresh claim would re-mint a grant **this link** already produced and
    /// the owner has since cut. The record is per link, so a link the owner
    /// mints afterwards is a fresh authorization decision — this refuses only a
    /// transport-driven resurrection through the link that was cut.
    GrantWasCut,
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
    /// A stable, key-material-free classification name (host/log facing).
    pub fn check(&self) -> &'static str {
        match self {
            Self::Entropy(_) => "entropy-error",
            Self::InvalidSecret => "invalid-invite-secret",
            Self::UnusableInviteeKey => "unusable-invitee-key",
            Self::InvalidExpiry => "invalid-expiry",
            Self::MalformedClaim(_) => "malformed-claim",
            Self::MalformedFragment => "malformed-invite-fragment",
            Self::FragmentTooLarge => "invite-fragment-too-large",
            Self::ScopeMismatch => "claim-scope-mismatch",
            Self::ScopeUnbound => "scope-not-bound-to-the-commitment",
            Self::NotOwner => "not-owner",
            Self::LinkNotCommitted => "link-not-committed",
            Self::LinkExpired => "link-expired",
            Self::ClaimAlreadyConverted => "claim-already-converted",
            Self::ClaimIdIsZero => "claim-id-is-zero",
            Self::GrantWasCut => "grant-was-cut",
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

/// One invite link as the owner recorded it at mint — **owner-local state, never
/// network bytes**.
///
/// A published ledger row is deliberately byte-shaped like a personal grantee's,
/// so nothing in a resolved record says "this row is an invite", and the fields
/// that would say so (`recipientIdentityPk`, `expiresAt`) sit outside the owner's
/// signature and are re-authorable by any write-grantee. Conversion therefore
/// decides *what may be claimed* from this record and never from the record it
/// converts against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordedInvite {
    /// The scope the link was minted over. Written at mint so attributing a
    /// record to its scope is a comparison rather than a per-record ECDH, and
    /// epoch-stable where the tag's bound scope root name is not.
    pub scope_id: [u8; 16],
    /// The link's blinded tag.
    pub tag: [u8; 32],
    /// The ephemeral identity a fragment holder signs its claim with.
    pub ephemeral_identity_pk: [u8; IDENTITY_PUBLIC_LEN],
    /// The ephemeral encryption subkey the link's blob is sealed to.
    pub ephemeral_enc_pk: [u8; SECRET_LEN],
    /// The deadline as minted. This copy is the authority: the published
    /// `expiresAt` is a cooperating-reader hint a write-grantee can strip or
    /// forge ([`GrantLedgerEntry::expires_at`]).
    pub expires_at: Option<UnixMillis>,
}

/// A minted invite link: the rows the owner commits, the record the owner keeps,
/// and the capability flag the host renders and revocation must respect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintedInvite {
    /// The link's blinded tag, commitment entry and ledger row.
    pub row: GrantRow,
    /// The owner-local record [`convert_invite_claim`] and
    /// [`locate_invite_link`] act on. Persist it with the link.
    pub link: RecordedInvite,
}

/// Mint an invite link over the scope root at `scope_id`.
///
/// Owner-only by construction: it takes the owner's encryption subkey secret for
/// the pairwise ECDH, and only the owner's identity signature over the resulting
/// commitment authorises the set. The scope root's `ipnsName` is **derived** from
/// `write_scope_seed`, never accepted as input — the tag binds that name and the
/// link holder re-derives it from the record it resolves, so binding anything but
/// the real resolvable name would mint a link nobody can self-locate.
pub fn mint_invite_grant(
    owner_identity_signer: &EcdsaSigner,
    owner_enc_secret: &X25519Secret,
    invitee: &EphemeralInvitee,
    scope_id: &[u8; 16],
    write_scope_seed: &[u8; SECRET_LEN],
    permission: Permission,
    expires_at: Option<UnixMillis>,
) -> Result<MintedInvite, InviteError> {
    let deadline = match expires_at {
        Some(deadline) => Some(NonZeroU64::new(deadline.0).ok_or(InviteError::InvalidExpiry)?),
        None => None,
    };
    let ipns_name: IpnsName = derive_write_name(write_scope_seed, scope_id);
    let mut row = mint_grant_row(
        owner_identity_signer,
        owner_enc_secret,
        invitee.identity_pk().to_sec1(),
        &invitee.enc_public(),
        scope_id,
        ipns_name.as_str().as_bytes(),
        permission,
    )
    .ok_or(InviteError::UnusableInviteeKey)?;
    row.ledger_entry.expires_at = deadline;
    Ok(MintedInvite {
        link: RecordedInvite {
            scope_id: *scope_id,
            tag: row.tag,
            ephemeral_identity_pk: invitee.identity_pk().to_sec1(),
            ephemeral_enc_pk: invitee.enc_public().to_bytes(),
            expires_at,
        },
        row,
    })
}

/// The bound on an invite fragment's decoded blob: a 32-byte secret, a contact
/// bundle ([`MAX_CONTACT_CODE_BYTES`](super::MAX_CONTACT_CODE_BYTES)) and a
/// scope root's `ipnsName`, with room for the map around them.
pub const MAX_INVITE_FRAGMENT_BYTES: usize = 2048;

/// The bound on the fragment *text*, so a hostile one is refused before its
/// blob is allocated. base64url spends four characters per three bytes.
const MAX_FRAGMENT_TEXT_LEN: usize = MAX_INVITE_FRAGMENT_BYTES.div_ceil(3) * 4;

/// An invite link's URL fragment — **the whole bearer capability**, as one
/// opaque blob.
///
/// The engine encodes it at the mint and decodes it at the claim, so a host
/// only ever moves it between a URL and a command: it composes no link and
/// parses none, and so never holds the invite secret or the owner bundle as
/// something it could log or store (#25 D6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteFragment {
    /// The invite secret — the whole capability.
    pub invite_secret: SecretBytes,
    /// The owner's contact code, which a claimant seals its claim to.
    pub owner_contact_code: Vec<u8>,
    /// The scope root's opaque `ipnsName`, which a claim names.
    pub scope_root_name: Vec<u8>,
}

fn malformed_fragment<E>(_: E) -> InviteError {
    InviteError::MalformedFragment
}

impl InviteFragment {
    /// Encode to the text a URL fragment carries: strict det-CBOR under
    /// base64url, which needs no percent-encoding.
    pub fn encode(&self) -> Result<Zeroizing<String>, InviteError> {
        let mut m = Map::new();
        m.insert(
            "inviteSecret",
            Value::Bytes(self.invite_secret.as_bytes().to_vec()),
        );
        m.insert(
            "ownerContactCode",
            Value::Bytes(self.owner_contact_code.clone()),
        );
        m.insert("scopeRootName", Value::Bytes(self.scope_root_name.clone()));
        // The tree holds a verbatim copy of the capability and this codec is its
        // terminal owner (`crates/core/src/codec/scrub.rs`). Wiped after the
        // encode, since the mark makes every later encode refuse it.
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
        let field = |name: &'static str| -> Result<Vec<u8>, InviteError> {
            Ok(req(map, name)
                .map_err(malformed_fragment)?
                .as_bytes()
                .map_err(malformed_fragment)?
                .to_vec())
        };
        let owner_contact_code = field("ownerContactCode")?;
        let scope_root_name = field("scopeRootName")?;
        let mut secret = fixed::<SECRET_LEN>(
            req(map, "inviteSecret").map_err(malformed_fragment)?,
            "inviteSecret",
        )
        .map_err(malformed_fragment)?;
        let invite_secret = SecretBytes::new(secret);
        // `fixed` hands back a plain array; this frame is its terminal owner.
        secret.zeroize();
        Ok(Self {
            invite_secret,
            owner_contact_code,
            scope_root_name,
        })
    }
}

/// Byte length of an [`InviteClaim::claim_id`].
pub const CLAIM_ID_LEN: usize = 16;

/// One conversion the owner has already made — **owner-local state, never
/// network bytes**, persisted beside the [`RecordedInvite`] set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConvertedClaimRecord {
    /// The spent claim's id.
    pub claim_id: [u8; CLAIM_ID_LEN],
    /// The [`RecordedInvite::tag`] of the link the claim came in on.
    ///
    /// What makes the set collectable: no claim on a link the owner no longer
    /// records can convert ([`InviteError::LinkNotCommitted`]), so records whose
    /// `link_tag` names no live link are dead weight and dropping them re-admits
    /// nothing. Without that the set only grows, and a bearer-link holder could
    /// fill it to [`MAX_CONVERTED_CLAIMS`](super::MAX_CONVERTED_CLAIMS) and leave
    /// the owner unable to persist anything at all.
    pub link_tag: [u8; 32],
    /// The blinded tag of the personal grant the conversion minted.
    pub tag: [u8; 32],
}

/// The claim a link holder posts to the owner's mailbox: which scope root the
/// link points at, the claimant's own contact code to be anchored to, and the
/// claim's own id.
///
/// Opaque application bytes inside the HPKE seal — app framing, not crypto. Its
/// authentication is the seal's inner sender signature, which the claimant makes
/// with the link's ephemeral identity key ([`post_invite_claim`]); the contact
/// code inside is self-authenticating and imported fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteClaim {
    /// Fresh per claim ([`Self::mint`]), inside the signed payload — so a
    /// redelivery carries the same id, and no other party learns it.
    pub claim_id: [u8; CLAIM_ID_LEN],
    /// The scope root's opaque `ipnsName` the link points at.
    pub scope_root_name: Vec<u8>,
    /// The claimant's contact code — `{identityPk, encSubkey, bindingSig}`.
    pub contact_code: Vec<u8>,
}

impl InviteClaim {
    /// Build a claim with a fresh id from the injected entropy seam.
    pub fn mint<E: Entropy>(
        entropy: &mut E,
        scope_root_name: Vec<u8>,
        contact_code: Vec<u8>,
    ) -> Result<Self, InviteError> {
        Ok(Self {
            claim_id: fresh_bytes(entropy, "claim id").map_err(InviteError::Entropy)?,
            scope_root_name,
            contact_code,
        })
    }

    /// Encode to det-CBOR (canonical key order).
    pub fn encode(&self) -> Vec<u8> {
        let mut m = Map::new();
        m.insert("claimId", Value::Bytes(self.claim_id.to_vec()));
        m.insert("contactCode", Value::Bytes(self.contact_code.clone()));
        m.insert("scopeRootName", Value::Bytes(self.scope_root_name.clone()));
        encode_fixed_depth(&Value::Map(m))
    }

    /// Decode a claim (strict det-CBOR). A missing or mistyped field is
    /// [`Malformed`]. Unknown fields are dropped rather than preserved: this is a
    /// consume-once engine payload, not a re-sealed shared structure.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let value = decode(bytes)?;
        let map = value.as_map()?;
        let field = |name: &'static str| -> Result<Vec<u8>, CodecError> {
            Ok(map
                .get(name)
                .ok_or(CodecError::from(Malformed::MissingField { field: name }))?
                .as_bytes()?
                .to_vec())
        };
        Ok(Self {
            claim_id: fixed::<CLAIM_ID_LEN>(req(map, "claimId")?, "claimId")?,
            scope_root_name: field("scopeRootName")?,
            contact_code: field("contactCode")?,
        })
    }
}

/// Post a claim to the owner's mailbox, sealed to the owner's encryption subkey
/// and signed — as the mailbox sender — with the link's ephemeral identity key.
/// That signature is what [`convert_invite_claim`] binds to the ephemeral half the
/// owner recorded, so only a fragment holder can claim.
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
/// Must be the **currently adopted** record's set. The commitment is deliberately
/// epoch-free (`CONTEXT.md`), so a stale one still verifies and re-signing it
/// resurrects every tag cut since; the adoption gate's floor law is what keeps a
/// served-stale record out.
///
/// No field of the commitment carries a scope id, so [`bind`](Self::bind) is the
/// only constructor: it derives the scope root's name from the scope's own write
/// material and refuses a pair the commitment does not name. Without that an
/// owner-authentic commitment for one scope could be presented under another
/// scope's id, and every gate over it would pass.
pub struct CommittedScope<'a> {
    scope_id: &'a [u8; 16],
    commitment: &'a GrantSetCommitment,
    commitment_sig: &'a EcdsaSignature,
    ledger: &'a [GrantLedgerEntry],
}

impl<'a> CommittedScope<'a> {
    /// Bind `scope_id` to `commitment`, or fail closed.
    ///
    /// `write_scope_seed` is the scope's current write-scope seed, which with
    /// the scope id derives the name the scope root answers at
    /// ([`derive_write_name`]). The commitment carries that name, so only the
    /// pair that derives it is admitted.
    pub fn bind(
        scope_id: &'a [u8; 16],
        write_scope_seed: &[u8; SECRET_LEN],
        commitment: &'a GrantSetCommitment,
        commitment_sig: &'a EcdsaSignature,
        ledger: &'a [GrantLedgerEntry],
    ) -> Result<Self, InviteError> {
        if derive_write_name(write_scope_seed, scope_id)
            .as_str()
            .as_bytes()
            != commitment.ipns_name
        {
            return Err(InviteError::ScopeUnbound);
        }
        Ok(Self {
            scope_id,
            commitment,
            commitment_sig,
            ledger,
        })
    }
}

impl OwnerAuthority<'_> {
    /// Fail closed unless this caller's identity key signed the committed set it
    /// is about to change. Every commitment change is owner-only, and
    /// `mint_invite_grant` gets that from its arguments where these two do not.
    pub fn authorise(&self, scope: &CommittedScope<'_>) -> Result<(), InviteError> {
        verify_grant_set(
            &self.identity_signer.verifying_key(),
            scope.commitment,
            scope.commitment_sig,
        )
        .map_err(|_| InviteError::NotOwner)
    }
}

/// What converting a claim did to the owner-signed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// The claimant had no grant on this scope; one was appended.
    Granted,
    /// The claimant already held a read grant and claimed a write link, so the
    /// committed entry was raised to write. A claim never lowers a permission.
    Upgraded,
    /// The claimant already held this grant at this permission, from another
    /// link or a grant made outside the invite path. The set comes back
    /// untouched and needs no republish.
    Unchanged,
}

/// A claim converted into a personal grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConvertedClaim {
    /// The personal grant for the claimant's contact-anchored identity, at the
    /// permission the returned commitment carries. It inherits no deadline: the
    /// link expires, the grants it produced do not.
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
    /// the contact it records to this link, so revoking the link returns the
    /// headroom its claims took.
    pub link_tag: [u8; 32],
    /// The contact-code bytes [`claimant`](Self::claimant) imported from. The
    /// owner records them in the contact book before the grant publishes, so a
    /// later revoke or downgrade resolves the recipient it just granted.
    pub claimant_code: Vec<u8>,
    /// What this conversion changed.
    pub outcome: ClaimOutcome,
    /// What the owner must persist to keep this claim single-use, if anything.
    /// Record it durably before acking the mailbox item, on the same
    /// ack-after-durable rule the accept flow follows.
    ///
    /// `None` when the grantee tag is already recorded: one record per tag is
    /// what bounds the spent set by the grants the owner actually published,
    /// rather than by how many claims a bearer-link holder chooses to post.
    pub record: Option<ConvertedClaimRecord>,
}

/// Convert a sender-verified invite claim into a personal grant for the
/// claimant's contact-anchored identity.
///
/// `links` is the owner's own record of the live links on this scope
/// ([`RecordedInvite`]); a claim converts only against one of those. Nothing in a
/// resolved record marks a row as an invite, and the row fields that could
/// (`recipientIdentityPk`, `expiresAt`) sit outside the owner's signature, so
/// deciding claimability from the record would let any committed grantee — or any
/// write-grantee re-authoring the ledger — drive the owner into signing a grant
/// for an identity the owner never approved.
///
/// The ephemeral identity a link commits is structurally a login identity rather
/// than a contact-anchored one; re-anchoring is the whole point of conversion, so
/// the minted grant binds the claimant's imported contact and never the ephemeral
/// half. `now` is the injected [`Scheduler::now`](crate::seams::Scheduler::now)
/// instant. The owner's recorded deadline is the authority — the published one is
/// honoured as well, but only ever to shorten a link, since a write-grantee can
/// re-author that field.
///
/// The caller signs and publishes the returned set, and records
/// [`ConvertedClaim::record`] and acks the mailbox item only once that is durable
/// (`mailbox` ack-after-durable).
///
/// `converted` is the owner's spent set, which is what makes a claim single-use
/// against a transport that chooses what to redeliver — see
/// [`InviteError::ClaimAlreadyConverted`] and [`InviteError::GrantWasCut`] for
/// the two refusals it decides.
pub fn convert_invite_claim(
    owner: &OwnerAuthority<'_>,
    scope: &CommittedScope<'_>,
    links: &[RecordedInvite],
    converted: &[ConvertedClaimRecord],
    item: &VerifiedMailboxItem,
    now: UnixMillis,
) -> Result<ConvertedClaim, InviteError> {
    owner.authorise(scope)?;
    let claim = InviteClaim::decode(&item.payload).map_err(InviteError::MalformedClaim)?;
    let name = scope.commitment.ipns_name.as_slice();
    if claim.scope_root_name != name {
        return Err(InviteError::ScopeMismatch);
    }

    // The seal's inner sender signature is already verified; binding it to a link
    // the owner recorded is what makes it a claim rather than a re-share.
    // Ambiguity is refused rather than resolved to the first match.
    let sender = item.sender_identity.to_sec1();
    let mut matches = links.iter().filter(|l| l.ephemeral_identity_pk == sender);
    let link = matches.next().ok_or(InviteError::LinkNotCommitted)?;
    if matches.next().is_some() {
        return Err(InviteError::LinkNotCommitted);
    }
    if link.expires_at.is_some_and(|deadline| now.0 >= deadline.0) {
        return Err(InviteError::LinkExpired);
    }
    // The tag the set carries for this link, which a write wave re-mints at the
    // name it moves the scope root to. Deriving it at `name` is what binds the
    // record to this scope root: a record made against another one derives a tag
    // this commitment does not carry.
    let link_tag =
        derived_tag(owner.enc_secret, link, name).ok_or(InviteError::LinkNotCommitted)?;
    // Bound to a link the owner recorded, so the spent set can be consulted.
    if claim.claim_id == [0u8; CLAIM_ID_LEN] {
        return Err(InviteError::ClaimIdIsZero);
    }
    if converted.iter().any(|c| c.claim_id == claim.claim_id) {
        return Err(InviteError::ClaimAlreadyConverted);
    }
    // The owner-signed entry carries the authoritative permission, and its
    // absence is the link's revocation signal.
    let permission = scope
        .commitment
        .entries
        .iter()
        .find(|e| e.tag == link_tag)
        .map(|e| e.permission)
        .ok_or(InviteError::LinkNotCommitted)?;
    // The published deadline is honoured too, so an expired row is inert here
    // before any prune reaches it. Only ever an additional restriction: a
    // write-grantee re-authoring this field can shorten a link, never extend one.
    if scope
        .ledger
        .iter()
        .any(|e| e.tag == link_tag && !entry_is_live(e, now))
    {
        return Err(InviteError::LinkExpired);
    }

    let contact = import_contact(&claim.contact_code).map_err(InviteError::ClaimantContact)?;
    if contact.identity_pk().to_sec1() == link.ephemeral_identity_pk
        || contact.enc_subkey().to_bytes() == link.ephemeral_enc_pk
    {
        return Err(InviteError::ClaimantIsTheEphemeralHalf);
    }
    // The invite URL carries the owner's own bundle; handing it back would file a
    // self-grant that consumes a slot and reads as a grantee in the host's UI.
    if contact.enc_subkey() == owner.enc_secret.public() {
        return Err(InviteError::ClaimantIsTheOwner);
    }
    let mut row = mint_grant_row(
        owner.identity_signer,
        owner.enc_secret,
        contact.identity_pk().to_sec1(),
        &contact.enc_subkey(),
        scope.scope_id,
        name,
        permission,
    )
    .ok_or(InviteError::UnusableClaimantKey)?;

    let committed = scope
        .commitment
        .entries
        .iter()
        .position(|e| e.tag == row.tag);
    let already_recorded = converted
        .iter()
        .any(|c| c.link_tag == link.tag && c.tag == row.tag);
    if committed.is_none() && already_recorded {
        return Err(InviteError::GrantWasCut);
    }

    let mut commitment = scope.commitment.clone();
    let mut ledger = scope.ledger.to_vec();
    // The blinded tag does not depend on permission, so an existing grantee
    // claiming a write link is an upgrade of the entry already committed.
    let outcome = match committed {
        None => {
            commitment.entries.push(row.commitment_entry.clone());
            ledger.push(row.ledger_entry.clone());
            ClaimOutcome::Granted
        }
        Some(i)
            if commitment.entries[i].permission == Permission::Read
                && permission == Permission::Write =>
        {
            commitment.entries[i].permission = Permission::Write;
            for entry in ledger.iter_mut().filter(|e| e.tag == row.tag) {
                entry.permission = Permission::Write;
            }
            ClaimOutcome::Upgraded
        }
        Some(i) => {
            // A claim never lowers what the owner already committed; report the
            // grant that stands, not the one the link would have minted.
            let held = commitment.entries[i].permission;
            row.commitment_entry.permission = held;
            row.ledger_entry.permission = held;
            ClaimOutcome::Unchanged
        }
    };
    check_publishable(&commitment, &ledger)?;
    let record = (!already_recorded).then_some(ConvertedClaimRecord {
        claim_id: claim.claim_id,
        link_tag: link.tag,
        tag: row.tag,
    });
    Ok(ConvertedClaim {
        row,
        commitment,
        ledger,
        claimant: contact,
        link_tag: link.tag,
        claimant_code: claim.contact_code,
        outcome,
        record,
    })
}

/// The tag `link`'s own key material derives at `scope_root_name`, from the
/// owner's half of the pairwise ECDH.
///
/// A write rotation moves the scope root's name and re-mints every committed row
/// under a new tag ([`crate::net::rotation`]), so this is what the current set
/// carries — the record's stored tag is what it was minted under.
fn derived_tag(
    owner_enc_secret: &X25519Secret,
    link: &RecordedInvite,
    scope_root_name: &[u8],
) -> Option<[u8; 32]> {
    X25519Public::from_bytes(link.ephemeral_enc_pk)
        .and_then(|enc| recipient_blinded_tag(owner_enc_secret, &enc, scope_root_name))
}

/// One of this owner's link records against the set a scope currently commits.
///
/// The two tags differ whenever a write wave has moved the scope root since the
/// mint: the record keeps the tag it was minted under, and the commitment
/// carries the one re-minted at the moved name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommittedLink {
    /// The owner's record, as stored. Its [`tag`](RecordedInvite::tag) is the
    /// key the record set and the contact book file this link under.
    pub record: RecordedInvite,
    /// The tag the current commitment carries for this link — what a cut names
    /// and what a claim reads its permission from.
    pub tag: [u8; 32],
}

/// This owner's link records at one scope, split by whether the scope's own
/// commitment still carries them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeLinks {
    /// Records the commitment still carries — claimable, and what a revoke cuts.
    pub committed: Vec<CommittedLink>,
    /// Records it has dropped — cut, or superseded — and what a prune drops.
    pub spent: BTreeSet<[u8; 32]>,
}

/// Split this owner's records for the scope `scope_id`, against the set
/// `commitment` commits at the scope root it names.
///
/// A record the commitment still carries whose tag its own key material does not
/// re-derive is in neither half: it names a row that is not this link's, so it
/// is neither cuttable nor spent.
pub fn partition_scope_links(
    owner_enc_secret: &X25519Secret,
    links: &[RecordedInvite],
    commitment: &GrantSetCommitment,
    scope_id: &[u8; 16],
) -> ScopeLinks {
    let name = commitment.ipns_name.as_slice();
    let carried: BTreeSet<[u8; 32]> = commitment.entries.iter().map(|entry| entry.tag).collect();
    let mut split = ScopeLinks {
        committed: Vec::new(),
        spent: BTreeSet::new(),
    };
    // Attribution is the recorded scope id, so only this scope's records reach
    // the ECDH — and both halves are decided against the tag the record derives
    // at the name the set names, never the stored one, which a write wave
    // supersedes.
    for link in links.iter().filter(|link| link.scope_id == *scope_id) {
        match derived_tag(owner_enc_secret, link, name) {
            Some(tag) if carried.contains(&tag) => {
                split.committed.push(CommittedLink { record: *link, tag })
            }
            // A row the commitment carries under a stored tag this link's own key
            // material does not derive belongs to some other recipient.
            _ if carried.contains(&link.tag) => {}
            _ => {
                split.spent.insert(link.tag);
            }
        }
    }
    split
}

/// The one live link the owner recorded at `scope` — the link a revoke cuts.
///
/// Owner-only, and the committed half of [`partition_scope_links`], so what a
/// revoke cuts cannot disagree with what the sharing read renders. A tag that is
/// merely committed belongs to some grantee (a claim's personal grant among
/// them) and is not a link's to cut. Ambiguity is refused rather than resolved
/// to the first match.
pub fn locate_invite_link(
    owner: &OwnerAuthority<'_>,
    scope: &CommittedScope<'_>,
    links: &[RecordedInvite],
) -> Result<CommittedLink, InviteError> {
    owner.authorise(scope)?;
    let live =
        partition_scope_links(owner.enc_secret, links, scope.commitment, scope.scope_id).committed;
    match live.as_slice() {
        [link] => Ok(*link),
        _ => Err(InviteError::LinkNotCommitted),
    }
}

/// The produce-side mirror of what a resolver hard-rejects: the grant-set
/// ceiling, duplicate tags, and a ledger diverging from the commitment (core
/// rejects the first two at decode and before signing; the third is the adoption
/// gate's owner-authority check). Release-active, so no build can emit a set its
/// own readers refuse.
pub(super) fn check_publishable(
    commitment: &GrantSetCommitment,
    ledger: &[GrantLedgerEntry],
) -> Result<(), InviteError> {
    if commitment.entries.len() > MAX_GRANT_BLOBS || ledger.len() > MAX_GRANT_BLOBS {
        return Err(InviteError::GrantSetFull);
    }
    if !tags_are_unique(commitment.entries.iter().map(|e| e.tag))
        || !tags_are_unique(ledger.iter().map(|e| e.tag))
    {
        return Err(InviteError::DuplicateTag);
    }
    enforce_committed_ledger(commitment, ledger).map_err(InviteError::Authority)
}

fn tags_are_unique(tags: impl Iterator<Item = [u8; 32]>) -> bool {
    let mut seen = BTreeSet::new();
    tags.into_iter().all(|t| seen.insert(t))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::{PublishedGrantBlob, enforce_committed_ledger, self_locate};
    use crate::rotation::{
        CommittedSet, ResealError, ResealSeeds, ScopeRootIdentity, WriteHistory, reseal_scope_root,
    };
    use crate::testkit::{SeededEntropy, SilentEntropy};
    use cipherbox_core::seal::{
        AadContext, GrantLedgerEntry, GrantSection, GrantSetCommitment, GrantSetEntry,
        PreservedFields, STRUCT_TAG_GRANT_BLOB, SignedGrantBlob, StructureSigInput,
        encode_grant_section, open_grant_blob, sign_grant_set, verify_structure,
    };
    use cipherbox_core::suite::contact::ContactCode;
    use cipherbox_core::suite::ecdsa::{IDENTITY_PUBLIC_LEN, SIGNATURE_LEN as ECDSA_SIG_LEN};
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
            &owner_identity(),
            &owner_enc(),
            &invitee(),
            &SCOPE,
            &WRITE_SCOPE_SEED,
            permission,
            expires_at,
        )
        .expect("mints")
        .row
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
                owner_enc_secret: None,
                ascent: None,
                owes_ascent_link: false,
                pseudonym_signer: signer,
            },
            &ResealSeeds {
                override_seed: &OVERRIDE_SEED,
                read_epoch: EPOCH,
                prev: None,
                write_scope_seed: &WRITE_SCOPE_SEED,
                write_epoch: 1,
                pointer_read_key: &POINTER_READ_KEY,
                write_history: WriteHistory::Carried(&[]),
            },
            &CommittedSet {
                owner_identity: &owner_identity().verifying_key(),
                commitment: &commitment,
                commitment_sig: &sig,
                grant_ledger: &ledger,
                direct_child_scope_index: &[],
                revoked_recipients: &[],
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
        let expected = fresh_seed(&mut SeededEntropy::new(7)).expect("fills");
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
            &owner_identity(),
            &owner_enc(),
            contact_identity.verifying_key().to_sec1(),
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
            &owner_identity(),
            &owner_enc(),
            &minted,
            &SCOPE,
            &WRITE_SCOPE_SEED,
            Permission::Read,
            Some(EXPIRES_AT),
        )
        .expect("mints")
        .row;
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
                &owner_identity(),
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
            &owner_identity(),
            &owner_enc(),
            &minted,
            &SCOPE,
            &WRITE_SCOPE_SEED,
            Permission::Read,
            None,
        )
        .expect("mints")
        .row;
        let elsewhere = mint_invite_grant(
            &owner_identity(),
            &owner_enc(),
            &minted,
            &SCOPE,
            &[0x56; 32],
            Permission::Read,
            None,
        )
        .expect("mints")
        .row;
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
            &owner_identity(),
            &owner_enc(),
            &minted,
            &SCOPE,
            &WRITE_SCOPE_SEED,
            Permission::Write,
            None,
        )
        .expect("mints")
        .row;
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
        let row = mint_invite_grant(
            &owner_identity(),
            &owner_enc(),
            &minted,
            &SCOPE,
            &WRITE_SCOPE_SEED,
            Permission::Read,
            None,
        )
        .expect("mints")
        .row;
        let section =
            scope_root(&[row.clone()], &owner_pseudonym(), &owner_pseudonym()).expect("reseal");
        let blob = blob_at(&section, &row.tag);
        // Control: `minted` is the row's own recipient, so the two rejects below
        // isolate the AAD and the key rather than a recipient mismatch.
        open_grant_blob(
            minted.enc_secret(),
            &blob.enc,
            &blob_ctx(EPOCH),
            &blob.ciphertext,
        )
        .expect("the row's own recipient opens at the sealed epoch");
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
        let row = invite(Permission::Write, Some(EXPIRES_AT));
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

    // -- claim conversion, expiry and bearer flagging -----------------------

    /// The stored records behind a split's committed half.
    fn committed_records(split: &ScopeLinks) -> Vec<RecordedInvite> {
        split.committed.iter().map(|link| link.record).collect()
    }

    /// The owner-signed set committing exactly `rows`.
    fn committed(rows: &[GrantRow]) -> (GrantSetCommitment, EcdsaSignature, Vec<GrantLedgerEntry>) {
        committed_at(scope_name(), rows)
    }

    /// The owner-signed set committing exactly `rows` at the scope root `name`.
    fn committed_at(
        name: Vec<u8>,
        rows: &[GrantRow],
    ) -> (GrantSetCommitment, EcdsaSignature, Vec<GrantLedgerEntry>) {
        let commitment = GrantSetCommitment {
            ipns_name: name,
            owner_pseudonym_pk: owner_pseudonym().verifying_key().to_bytes(),
            entries: rows.iter().map(|r| r.commitment_entry.clone()).collect(),
            unknown: PreservedFields::new(),
        };
        let sig = sign_grant_set(&owner_identity(), &commitment).expect("signs");
        (
            commitment,
            sig,
            rows.iter().map(|r| r.ledger_entry.clone()).collect(),
        )
    }

    /// The owner's two halves, held so an [`OwnerAuthority`] can borrow them.
    struct Owner {
        identity: EcdsaSigner,
        enc: X25519Secret,
    }

    impl Owner {
        fn new() -> Self {
            Self {
                identity: owner_identity(),
                enc: owner_enc(),
            }
        }

        fn authority(&self) -> OwnerAuthority<'_> {
            OwnerAuthority {
                identity_signer: &self.identity,
                enc_secret: &self.enc,
            }
        }
    }

    fn committed_scope<'a>(
        commitment: &'a GrantSetCommitment,
        commitment_sig: &'a EcdsaSignature,
        ledger: &'a [GrantLedgerEntry],
    ) -> CommittedScope<'a> {
        committed_scope_under(&WRITE_SCOPE_SEED, commitment, commitment_sig, ledger)
    }

    /// The same, at the scope root `write_scope_seed` derives.
    fn committed_scope_under<'a>(
        write_scope_seed: &[u8; 32],
        commitment: &'a GrantSetCommitment,
        commitment_sig: &'a EcdsaSignature,
        ledger: &'a [GrantLedgerEntry],
    ) -> CommittedScope<'a> {
        CommittedScope::bind(&SCOPE, write_scope_seed, commitment, commitment_sig, ledger)
            .expect("the scope's own write seed derives the name the set carries")
    }

    /// A minted link over `SCOPE`, keyed by its fragment secret.
    fn link(secret: u8, permission: Permission, expires_at: Option<UnixMillis>) -> MintedInvite {
        link_under(secret, permission, expires_at, &WRITE_SCOPE_SEED)
    }

    /// The same, at the scope root `write_scope_seed` derives — the name a write
    /// rotation moves the scope to.
    fn link_under(
        secret: u8,
        permission: Permission,
        expires_at: Option<UnixMillis>,
        write_scope_seed: &[u8; 32],
    ) -> MintedInvite {
        mint_invite_grant(
            &owner_identity(),
            &owner_enc(),
            &EphemeralInvitee::from_secret(&[secret; 32]).expect("valid"),
            &SCOPE,
            write_scope_seed,
            permission,
            expires_at,
        )
        .expect("mints")
    }

    /// The ephemeral signer a fragment holder reconstructs to sign its claim.
    fn link_signer(secret: u8) -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[secret; 32]).expect("valid scalar")
    }

    /// A claimant's own keypair; the contact code binds the two halves.
    fn claimant(seed: u8) -> (EcdsaSigner, X25519Secret) {
        (
            EcdsaSigner::from_scalar(&[seed; 32]).expect("valid scalar"),
            X25519Secret::from_scalar([seed ^ 0xff; 32]),
        )
    }

    fn contact_code(identity: &EcdsaSigner, enc: &X25519Secret) -> Vec<u8> {
        ContactCode::create(identity, enc.public()).encode()
    }

    /// A claim as the mailbox hands it over: sender-verified, signed by `sender`.
    fn claim_item(sender: &EcdsaSigner, contact_code: Vec<u8>) -> VerifiedMailboxItem {
        claim_item_for(sender, contact_code, scope_name())
    }

    fn claim_item_for(
        sender: &EcdsaSigner,
        contact_code: Vec<u8>,
        scope_root_name: Vec<u8>,
    ) -> VerifiedMailboxItem {
        claim_item_id(sender, contact_code, scope_root_name, [0x99; CLAIM_ID_LEN])
    }

    fn claim_item_id(
        sender: &EcdsaSigner,
        contact_code: Vec<u8>,
        scope_root_name: Vec<u8>,
        claim_id: [u8; CLAIM_ID_LEN],
    ) -> VerifiedMailboxItem {
        VerifiedMailboxItem {
            item_id: "claim-1".to_string(),
            sender_identity: sender.verifying_key(),
            payload: InviteClaim {
                claim_id,
                scope_root_name,
                contact_code,
            }
            .encode(),
        }
    }

    #[test]
    fn one_link_converts_two_claimants_into_two_grants_and_stays_live() {
        let l = link(0x4e, Permission::Read, None);
        let (commitment, sig, ledger) = committed(&[l.row.clone()]);
        let keys = Owner::new();
        let owner = keys.authority();
        let signer = link_signer(0x4e);

        let (a_id, a_enc) = claimant(0x61);
        let first = convert_invite_claim(
            &owner,
            &committed_scope(&commitment, &sig, &ledger),
            &[l.link],
            &[],
            &claim_item(&signer, contact_code(&a_id, &a_enc)),
            UnixMillis(0),
        )
        .expect("converts");
        assert_eq!(first.outcome, ClaimOutcome::Granted);

        // The second claimant converts against the set the first produced: the
        // link's own entry is still there, so the link stays claimable.
        let second_sig = sign_grant_set(&owner_identity(), &first.commitment).expect("signs");
        let (b_id, b_enc) = claimant(0x62);
        let second = convert_invite_claim(
            &owner,
            &committed_scope(&first.commitment, &second_sig, &first.ledger),
            &[l.link],
            &[],
            &claim_item(&signer, contact_code(&b_id, &b_enc)),
            UnixMillis(0),
        )
        .expect("converts");

        assert_ne!(first.row.tag, second.row.tag, "two independent grants");
        assert_eq!(second.commitment.entries.len(), 3);
        assert_eq!(second.ledger.len(), 3);
        assert!(
            second
                .commitment
                .entries
                .iter()
                .any(|e| e.tag == l.link.tag),
            "the link itself stays live until it expires or is revoked",
        );
    }

    #[test]
    fn a_converted_grant_anchors_to_the_claimants_contact_never_the_ephemeral_half() {
        let l = link(0x4e, Permission::Write, None);
        let (commitment, sig, ledger) = committed(&[l.row.clone()]);
        let keys = Owner::new();
        let owner = keys.authority();
        let scope = committed_scope(&commitment, &sig, &ledger);
        let signer = link_signer(0x4e);
        let (id, enc) = claimant(0x63);

        let converted = convert_invite_claim(
            &owner,
            &scope,
            &[l.link],
            &[],
            &claim_item(&signer, contact_code(&id, &enc)),
            UnixMillis(0),
        )
        .expect("converts");

        assert_eq!(
            converted.row.ledger_entry.recipient_identity_pk,
            id.verifying_key().to_sec1(),
        );
        assert_eq!(
            converted.row.ledger_entry.recipient_enc_pk,
            enc.public().to_bytes()
        );
        assert_ne!(
            converted.row.ledger_entry.recipient_identity_pk,
            l.link.ephemeral_identity_pk,
        );
        assert_eq!(
            converted.row.commitment_entry.permission,
            Permission::Write,
            "the converted grant inherits the link's committed permission",
        );
        assert_eq!(
            converted.row.ledger_entry.expires_at, None,
            "the link expires; the grants it produced do not",
        );
        // The claimant may not hand back the link's own throwaway identity: it
        // self-signs a perfectly valid contact code, and re-anchoring is the
        // whole point of conversion.
        let eph_enc = X25519Secret::from_scalar([0u8; 32]);
        for (code, why) in [
            (
                contact_code(&signer, &eph_enc),
                "claimant-is-the-ephemeral-half",
            ),
            (
                contact_code(&id, &X25519Secret::from_scalar([0x11; 32])),
                "claimant-is-the-owner",
            ),
        ] {
            assert_eq!(
                convert_invite_claim(
                    &owner,
                    &scope,
                    &[l.link],
                    &[],
                    &claim_item(&signer, code),
                    UnixMillis(0)
                )
                .unwrap_err()
                .check(),
                why,
            );
        }
    }

    #[test]
    fn only_a_link_the_owner_recorded_can_be_claimed() {
        // An ordinary grantee posts a well-formed, honestly-signed claim naming a
        // sockpuppet contact. Its row is byte-shaped like a link's, so nothing in
        // the record distinguishes them — only the owner's own record does.
        let grantee_identity = EcdsaSigner::from_scalar(&[0x7a; 32]).expect("valid scalar");
        let grantee_enc = X25519Secret::from_scalar([0x7b; 32]);
        let grantee = mint_grant_row(
            &owner_identity(),
            &owner_enc(),
            grantee_identity.verifying_key().to_sec1(),
            &grantee_enc.public(),
            &SCOPE,
            &scope_name(),
            Permission::Write,
        )
        .expect("contributory");
        let l = link(0x4e, Permission::Read, None);
        let (commitment, sig, mut ledger) = committed(&[grantee, l.row.clone()]);
        let keys = Owner::new();
        let owner = keys.authority();
        let (id, enc) = claimant(0x7c);

        assert_eq!(
            convert_invite_claim(
                &owner,
                &committed_scope(&commitment, &sig, &ledger),
                &[l.link],
                &[],
                &claim_item(&grantee_identity, contact_code(&id, &enc)),
                UnixMillis(0),
            )
            .unwrap_err()
            .check(),
            "link-not-committed",
            "a grantee cannot re-delegate its own row as if it were a link",
        );

        // Nor by re-authoring the ledger: a write-grantee pointing a committed
        // row's recipientIdentityPk — a field outside the owner's signature — at
        // an ephemeral identity it holds still matches no recorded link.
        ledger[0].recipient_identity_pk = link_signer(0x4f).verifying_key().to_sec1();
        assert_eq!(
            convert_invite_claim(
                &owner,
                &committed_scope(&commitment, &sig, &ledger),
                &[l.link],
                &[],
                &claim_item(&link_signer(0x4f), contact_code(&id, &enc)),
                UnixMillis(0),
            )
            .unwrap_err()
            .check(),
            "link-not-committed",
        );
    }

    #[test]
    fn a_claim_signed_by_an_uncommitted_key_is_refused() {
        let l = link(0x4e, Permission::Read, None);
        let (commitment, sig, ledger) = committed(&[l.row.clone()]);
        let keys = Owner::new();
        let owner = keys.authority();
        let scope = committed_scope(&commitment, &sig, &ledger);
        let (id, enc) = claimant(0x64);

        // A different ephemeral identity than the one the owner recorded.
        assert_eq!(
            convert_invite_claim(
                &owner,
                &scope,
                &[l.link],
                &[],
                &claim_item(&link_signer(0x4f), contact_code(&id, &enc)),
                UnixMillis(0),
            )
            .unwrap_err()
            .check(),
            "link-not-committed",
        );
        // The recorded one converts, so the reject above isolates the signer.
        assert!(
            convert_invite_claim(
                &owner,
                &scope,
                &[l.link],
                &[],
                &claim_item(&link_signer(0x4e), contact_code(&id, &enc)),
                UnixMillis(0),
            )
            .is_ok()
        );
        // Two records answering to one ephemeral identity refuse rather than
        // resolve to the first match.
        assert_eq!(
            convert_invite_claim(
                &owner,
                &scope,
                &[l.link, l.link],
                &[],
                &claim_item(&link_signer(0x4e), contact_code(&id, &enc)),
                UnixMillis(0),
            )
            .unwrap_err()
            .check(),
            "link-not-committed",
        );
        // A link the owner revoked from the committed set no longer converts.
        let (cut, cut_sig, cut_ledger) = committed(&[]);
        assert_eq!(
            convert_invite_claim(
                &owner,
                &committed_scope(&cut, &cut_sig, &cut_ledger),
                &[l.link],
                &[],
                &claim_item(&link_signer(0x4e), contact_code(&id, &enc)),
                UnixMillis(0),
            )
            .unwrap_err()
            .check(),
            "link-not-committed",
        );
    }

    #[test]
    fn a_claim_against_an_expired_link_is_refused_at_the_deadline() {
        let l = link(0x4e, Permission::Read, Some(EXPIRES_AT));
        let (commitment, sig, ledger) = committed(&[l.row.clone()]);
        let keys = Owner::new();
        let owner = keys.authority();
        let scope = committed_scope(&commitment, &sig, &ledger);
        let (id, enc) = claimant(0x65);
        let item = claim_item(&link_signer(0x4e), contact_code(&id, &enc));

        assert!(
            convert_invite_claim(
                &owner,
                &scope,
                &[l.link],
                &[],
                &item,
                UnixMillis(EXPIRES_AT.0 - 1)
            )
            .is_ok(),
            "live one tick before the deadline",
        );
        assert_eq!(
            convert_invite_claim(&owner, &scope, &[l.link], &[], &item, EXPIRES_AT)
                .unwrap_err()
                .check(),
            "link-expired",
        );
        assert_eq!(ledger.len(), 1, "the expired row is inert, not pruned");

        // A stripped published deadline does not extend the link: the owner's own
        // record is the authority.
        let mut stripped = ledger.clone();
        stripped[0].expires_at = None;
        assert_eq!(
            convert_invite_claim(
                &owner,
                &committed_scope(&commitment, &sig, &stripped),
                &[l.link],
                &[],
                &item,
                EXPIRES_AT,
            )
            .unwrap_err()
            .check(),
            "link-expired",
        );

        // And a published deadline alone makes the row inert before any prune.
        let unrecorded = link(0x4e, Permission::Read, None);
        assert_eq!(
            convert_invite_claim(&owner, &scope, &[unrecorded.link], &[], &item, EXPIRES_AT)
                .unwrap_err()
                .check(),
            "link-expired",
        );
    }

    #[test]
    fn a_non_owner_can_neither_convert_nor_revoke() {
        let l = link(0x4e, Permission::Read, None);
        let (commitment, sig, ledger) = committed(&[l.row.clone()]);
        let scope = committed_scope(&commitment, &sig, &ledger);
        let (id, enc) = claimant(0x66);
        let item = claim_item(&link_signer(0x4e), contact_code(&id, &enc));

        // A stranger's identity key never signed this committed set.
        let rogue_id = EcdsaSigner::from_scalar(&[0x34; 32]).expect("valid scalar");
        let owner_e = owner_enc();
        let rogue = OwnerAuthority {
            identity_signer: &rogue_id,
            enc_secret: &owner_e,
        };
        assert_eq!(
            convert_invite_claim(&rogue, &scope, &[l.link], &[], &item, UnixMillis(0))
                .unwrap_err()
                .check(),
            "not-owner",
        );
        assert_eq!(
            locate_invite_link(&rogue, &scope, &[l.link])
                .unwrap_err()
                .check(),
            "not-owner",
        );

        // Defense in depth: the owner identity with a foreign encryption subkey
        // cannot re-derive the recorded link tag either.
        let owner_id = owner_identity();
        let foreign_enc = X25519Secret::from_scalar([0x12; 32]);
        let half = OwnerAuthority {
            identity_signer: &owner_id,
            enc_secret: &foreign_enc,
        };
        assert_eq!(
            convert_invite_claim(&half, &scope, &[l.link], &[], &item, UnixMillis(0))
                .unwrap_err()
                .check(),
            "link-not-committed",
        );
    }

    /// The gate's own binding: no field of a commitment carries a scope id, so
    /// pairing an owner-authentic commitment for one scope with another scope's
    /// id would pass every check the owner authority runs.
    #[test]
    fn a_commitment_authorises_nothing_under_a_scope_it_does_not_name() {
        const OTHER_SCOPE: [u8; 16] = [0xa1; 16];
        const OTHER_SEED: [u8; 32] = [0x5b; 32];
        let l = link(0x71, Permission::Read, None);
        let (commitment, sig, ledger) = committed(&[l.row.clone()]);

        let refusal = |scope_id: &[u8; 16], seed: &[u8; 32]| {
            CommittedScope::bind(scope_id, seed, &commitment, &sig, &ledger)
                .err()
                .map(|e| e.check())
        };
        assert_eq!(
            refusal(&OTHER_SCOPE, &WRITE_SCOPE_SEED),
            Some("scope-not-bound-to-the-commitment"),
        );
        assert_eq!(
            refusal(&SCOPE, &OTHER_SEED),
            Some("scope-not-bound-to-the-commitment"),
            "and the scope's write material is half of the pair, not a formality"
        );
        assert!(
            CommittedScope::bind(&SCOPE, &WRITE_SCOPE_SEED, &commitment, &sig, &ledger).is_ok(),
            "only the pair that derives the name the commitment carries is admitted"
        );
    }

    #[test]
    fn a_link_is_located_only_when_recorded_and_still_committed() {
        let read = link(0x71, Permission::Read, None);
        let write = link(0x72, Permission::Write, None);
        let keys = Owner::new();
        let owner = keys.authority();
        let (commitment, sig, ledger) = committed(&[read.row.clone(), write.row.clone()]);
        let scope = committed_scope(&commitment, &sig, &ledger);

        assert_eq!(
            locate_invite_link(&owner, &scope, &[write.link]).expect("locates"),
            CommittedLink {
                record: write.link,
                tag: write.link.tag,
            },
        );
        // A link the owner never recorded is nobody's to cut, and neither is a
        // recorded one the commitment has already dropped.
        let unknown = link(0x73, Permission::Read, None);
        assert_eq!(
            locate_invite_link(&owner, &scope, &[]).unwrap_err().check(),
            "link-not-committed",
        );
        assert_eq!(
            locate_invite_link(&owner, &scope, &[unknown.link])
                .unwrap_err()
                .check(),
            "link-not-committed",
        );
        // A record carrying a committed tag its own ephemeral key does not derive
        // is refused, so an owner-side mix-up cannot cut an ordinary grantee.
        let mixed = RecordedInvite {
            tag: read.row.tag,
            ..unknown.link
        };
        assert_eq!(
            locate_invite_link(&owner, &scope, &[mixed])
                .unwrap_err()
                .check(),
            "link-not-committed",
        );
        // Two live links on one scope have no defined cut, so the ambiguity is
        // refused rather than resolved to the first match.
        assert_eq!(
            locate_invite_link(&owner, &scope, &[read.link, write.link])
                .unwrap_err()
                .check(),
            "link-not-committed",
        );
    }

    /// A record minted elsewhere is neither cuttable nor prunable here, even
    /// where this scope's commitment happens to carry its tag and its own key
    /// material re-derives it.
    #[test]
    fn a_record_minted_at_another_scope_is_neither_half_nor_locatable() {
        let l = link(0x71, Permission::Read, None);
        let keys = Owner::new();
        let owner = keys.authority();
        let (commitment, sig, ledger) = committed(&[l.row.clone()]);
        let scope = committed_scope(&commitment, &sig, &ledger);
        let elsewhere = RecordedInvite {
            scope_id: [0xa1; 16],
            ..l.link
        };

        let split = partition_scope_links(owner.enc_secret, &[elsewhere], &commitment, &SCOPE);
        assert!(split.committed.is_empty() && split.spent.is_empty());
        assert_eq!(
            locate_invite_link(&owner, &scope, &[elsewhere])
                .unwrap_err()
                .check(),
            "link-not-committed",
        );

        // Only the recorded id differs, so it is what decided the refusal.
        let split = partition_scope_links(owner.enc_secret, &[l.link], &commitment, &SCOPE);
        assert_eq!(committed_records(&split), vec![l.link]);
    }

    /// A record whose tag this scope's own commitment has dropped is spent — a
    /// revoke cut it, or a later mint at the same node superseded it.
    #[test]
    fn a_record_the_commitment_dropped_is_spent() {
        let live = link(0x71, Permission::Read, None);
        let dropped = link(0x73, Permission::Read, None);
        let (commitment, ..) = committed(&[live.row.clone()]);

        let split = partition_scope_links(
            &owner_enc(),
            &[live.link, dropped.link],
            &commitment,
            &SCOPE,
        );
        assert_eq!(split.spent, BTreeSet::from([dropped.link.tag]));
        assert_eq!(committed_records(&split), vec![live.link]);
    }

    /// A write rotation moves the scope root's name and re-mints every committed
    /// row under a new tag, so a record from an earlier epoch holds a tag the
    /// current set does not carry while its row is still live. The record stays
    /// the owner's note that the row is a link, and a cut names the tag the
    /// record re-derives at the moved name.
    #[test]
    fn a_record_whose_row_was_re_minted_at_a_moved_name_is_cut_by_its_derived_tag() {
        const MOVED_WRITE_SEED: [u8; 32] = [0x5b; 32];
        let before = link(0x71, Permission::Read, None);
        let after = link_under(0x71, Permission::Read, None, &MOVED_WRITE_SEED);
        assert_ne!(
            before.link.tag, after.link.tag,
            "the rotation moved the tag"
        );

        let moved = derive_write_name(&MOVED_WRITE_SEED, &SCOPE)
            .as_str()
            .as_bytes()
            .to_vec();
        let (commitment, ..) = committed_at(moved, &[after.row.clone()]);

        let split = partition_scope_links(&owner_enc(), &[before.link], &commitment, &SCOPE);
        assert!(
            split.spent.is_empty(),
            "the link's row is live at the moved name"
        );
        assert_eq!(
            split.committed,
            vec![CommittedLink {
                record: before.link,
                tag: after.link.tag,
            }],
            "and a cut names the tag the moved set carries, not the stored one"
        );
    }

    /// The claim half of the same rule the split follows: a write rotation
    /// re-mints the link's row at the moved name, and the permission the claim
    /// converts at is read off that row rather than the recorded tag.
    #[test]
    fn a_claim_converts_against_a_row_re_minted_at_a_moved_name() {
        const MOVED_WRITE_SEED: [u8; 32] = [0x5b; 32];
        let before = link(0x4e, Permission::Read, None);
        let after = link_under(0x4e, Permission::Read, None, &MOVED_WRITE_SEED);
        assert_ne!(before.link.tag, after.link.tag);

        let moved = derive_write_name(&MOVED_WRITE_SEED, &SCOPE)
            .as_str()
            .as_bytes()
            .to_vec();
        let (commitment, sig, ledger) = committed_at(moved.clone(), &[after.row.clone()]);
        let keys = Owner::new();
        let (id, enc) = claimant(0x67);

        let converted = convert_invite_claim(
            &keys.authority(),
            &committed_scope_under(&MOVED_WRITE_SEED, &commitment, &sig, &ledger),
            &[before.link],
            &[],
            &claim_item_for(&link_signer(0x4e), contact_code(&id, &enc), moved),
            UnixMillis(0),
        )
        .expect("the recorded link still converts after the rotation");
        assert_eq!(
            converted.link_tag, before.link.tag,
            "the conversion is charged to the record the owner holds"
        );
    }

    #[test]
    fn a_second_claim_from_a_committed_grantee_changes_nothing() {
        let l = link(0x4e, Permission::Read, None);
        let (commitment, sig, ledger) = committed(&[l.row.clone()]);
        let keys = Owner::new();
        let owner = keys.authority();
        let (id, enc) = claimant(0x67);
        let name = scope_name();
        let first_item = claim_item_id(
            &link_signer(0x4e),
            contact_code(&id, &enc),
            name.clone(),
            [0x11; CLAIM_ID_LEN],
        );

        let first = convert_invite_claim(
            &owner,
            &committed_scope(&commitment, &sig, &ledger),
            &[l.link],
            &[],
            &first_item,
            UnixMillis(0),
        )
        .expect("converts");
        let spent = first.record.expect("the first conversion is recorded");

        let resigned = sign_grant_set(&owner_identity(), &first.commitment).expect("signs");
        let again = convert_invite_claim(
            &owner,
            &committed_scope(&first.commitment, &resigned, &first.ledger),
            &[l.link],
            &[spent],
            &claim_item_id(
                &link_signer(0x4e),
                contact_code(&id, &enc),
                name,
                [0x22; CLAIM_ID_LEN],
            ),
            UnixMillis(0),
        )
        .expect("converts");

        assert_eq!(again.outcome, ClaimOutcome::Unchanged);
        assert_eq!(again.commitment, first.commitment);
        assert_eq!(again.ledger, first.ledger);
        assert_eq!(
            again.record, None,
            "one record per grantee per link, so a second claim adds nothing to spend"
        );
    }

    /// An all-zero id is the one a client with a broken entropy seam emits.
    /// Spending it would deny every later claimant on the link, so conversion
    /// refuses it — the consume side of the draw [`InviteClaim::mint`] refuses.
    #[test]
    fn a_claim_carrying_an_all_zero_id_is_refused() {
        let l = link(0x4e, Permission::Read, None);
        let (commitment, sig, ledger) = committed(&[l.row.clone()]);
        let keys = Owner::new();
        let (id, enc) = claimant(0x67);
        assert_eq!(
            convert_invite_claim(
                &keys.authority(),
                &committed_scope(&commitment, &sig, &ledger),
                &[l.link],
                &[],
                &claim_item_id(
                    &link_signer(0x4e),
                    contact_code(&id, &enc),
                    scope_name(),
                    [0; CLAIM_ID_LEN],
                ),
                UnixMillis(0),
            )
            .unwrap_err()
            .check(),
            "claim-id-is-zero",
        );
    }

    #[test]
    fn claiming_a_write_link_upgrades_an_existing_read_grant_and_never_lowers_one() {
        let read_link = link(0x4e, Permission::Read, None);
        let write_link = link(0x4f, Permission::Write, None);
        let keys = Owner::new();
        let owner = keys.authority();
        let (id, enc) = claimant(0x68);

        let (commitment, sig, ledger) = committed(&[read_link.row.clone(), write_link.row.clone()]);
        let read_grant = convert_invite_claim(
            &owner,
            &committed_scope(&commitment, &sig, &ledger),
            &[read_link.link],
            &[],
            &claim_item(&link_signer(0x4e), contact_code(&id, &enc)),
            UnixMillis(0),
        )
        .expect("converts");
        assert_eq!(read_grant.outcome, ClaimOutcome::Granted);

        // Same claimant, same tag, now claiming the write link.
        let resigned = sign_grant_set(&owner_identity(), &read_grant.commitment).expect("signs");
        let upgraded = convert_invite_claim(
            &owner,
            &committed_scope(&read_grant.commitment, &resigned, &read_grant.ledger),
            &[write_link.link],
            &[],
            &claim_item(&link_signer(0x4f), contact_code(&id, &enc)),
            UnixMillis(0),
        )
        .expect("converts");
        assert_eq!(upgraded.outcome, ClaimOutcome::Upgraded);
        let committed_permission = |c: &GrantSetCommitment, tag: [u8; 32]| {
            c.entries.iter().find(|e| e.tag == tag).unwrap().permission
        };
        assert_eq!(
            committed_permission(&upgraded.commitment, upgraded.row.tag),
            Permission::Write,
        );
        assert_eq!(
            upgraded.row.commitment_entry.permission,
            committed_permission(&upgraded.commitment, upgraded.row.tag),
            "the reported row never contradicts the returned commitment",
        );

        // Claiming the read link back does not lower the write grant.
        let resigned = sign_grant_set(&owner_identity(), &upgraded.commitment).expect("signs");
        let held = convert_invite_claim(
            &owner,
            &committed_scope(&upgraded.commitment, &resigned, &upgraded.ledger),
            &[read_link.link],
            &[],
            &claim_item(&link_signer(0x4e), contact_code(&id, &enc)),
            UnixMillis(0),
        )
        .expect("converts");
        assert_eq!(held.outcome, ClaimOutcome::Unchanged);
        assert_eq!(held.row.commitment_entry.permission, Permission::Write);
        assert_eq!(held.commitment, upgraded.commitment);
    }

    #[test]
    fn a_claim_naming_another_scope_root_is_refused() {
        let l = link(0x4e, Permission::Read, None);
        let (commitment, sig, ledger) = committed(&[l.row.clone()]);
        let keys = Owner::new();
        let owner = keys.authority();
        let (id, enc) = claimant(0x69);
        assert_eq!(
            convert_invite_claim(
                &owner,
                &committed_scope(&commitment, &sig, &ledger),
                &[l.link],
                &[],
                &claim_item_for(
                    &link_signer(0x4e),
                    contact_code(&id, &enc),
                    b"k51elsewhere".to_vec(),
                ),
                UnixMillis(0),
            )
            .unwrap_err()
            .check(),
            "claim-scope-mismatch",
        );
    }

    #[test]
    fn a_malformed_or_unbindable_claim_is_refused() {
        let l = link(0x4e, Permission::Read, None);
        let (commitment, sig, ledger) = committed(&[l.row.clone()]);
        let keys = Owner::new();
        let owner = keys.authority();
        let scope = committed_scope(&commitment, &sig, &ledger);
        let (id, enc) = claimant(0x6b);

        let junk = VerifiedMailboxItem {
            item_id: "claim-1".to_string(),
            sender_identity: link_signer(0x4e).verifying_key(),
            payload: b"not det-cbor".to_vec(),
        };
        assert_eq!(
            convert_invite_claim(&owner, &scope, &[l.link], &[], &junk, UnixMillis(0))
                .unwrap_err()
                .check(),
            "malformed-claim",
        );

        let mut code = contact_code(&id, &enc);
        let last = code.len() - 1;
        code[last] ^= 0x01;
        assert_eq!(
            convert_invite_claim(
                &owner,
                &scope,
                &[l.link],
                &[],
                &claim_item(&link_signer(0x4e), code),
                UnixMillis(0),
            )
            .unwrap_err()
            .check(),
            "claimant-contact-invalid",
        );
    }

    #[test]
    fn a_conversion_that_would_publish_an_unreadable_set_returns_err() {
        // Encode-side symmetry: core rejects a duplicate-tag commitment and one
        // past the grant-set ceiling at decode and before signing, and the gate
        // rejects a ledger that diverges from the commitment. All three are
        // refused here rather than signed — a `return Err`, not an assertion a
        // release build strips.
        let l = link(0x4e, Permission::Read, None);
        let keys = Owner::new();
        let owner = keys.authority();
        let (id, enc) = claimant(0x6a);
        let item = claim_item(&link_signer(0x4e), contact_code(&id, &enc));

        // A ledger the commitment does not cover diverges once the new row lands.
        let (commitment, sig, _) = committed(&[l.row.clone()]);
        let mut stray = l.row.ledger_entry.clone();
        stray.tag = [0x7e; 32];
        stray.recipient_identity_pk = [0x02; IDENTITY_PUBLIC_LEN];
        assert_eq!(
            convert_invite_claim(
                &owner,
                &committed_scope(&commitment, &sig, &[l.row.ledger_entry.clone(), stray]),
                &[l.link],
                &[],
                &item,
                UnixMillis(0),
            )
            .unwrap_err()
            .check(),
            "ledger-diverges-from-commitment",
        );

        // A set already at the ceiling cannot take one more row.
        let mut full_commitment = commitment.clone();
        let mut full_ledger = vec![l.row.ledger_entry.clone()];
        for i in 1..MAX_GRANT_BLOBS {
            let mut tag = [0u8; 32];
            tag[..8].copy_from_slice(&(i as u64).to_be_bytes());
            full_commitment
                .entries
                .push(GrantSetEntry::new(tag, Permission::Read, [0x02; 32]));
            // Ceiling padding: never read as a live grant, so it carries no
            // owner attestation.
            full_ledger.push(GrantLedgerEntry::new(
                [0x02; IDENTITY_PUBLIC_LEN],
                [0x11; 32],
                Permission::Read,
                tag,
                [0u8; ECDSA_SIG_LEN],
            ));
        }
        let full_sig = sign_grant_set(&owner_identity(), &full_commitment).expect("signs");
        assert_eq!(
            convert_invite_claim(
                &owner,
                &committed_scope(&full_commitment, &full_sig, &full_ledger),
                &[l.link],
                &[],
                &item,
                UnixMillis(0),
            )
            .unwrap_err()
            .check(),
            "grant-set-full",
        );
    }

    #[test]
    fn the_claim_payload_round_trips_byte_stable_and_rejects_a_missing_field() {
        let claim = InviteClaim {
            claim_id: [0x99; CLAIM_ID_LEN],
            scope_root_name: b"k51scoperoot".to_vec(),
            contact_code: b"contact".to_vec(),
        };
        let bytes = claim.encode();
        let decoded = InviteClaim::decode(&bytes).expect("decodes");
        assert_eq!(decoded, claim);
        assert_eq!(decoded.encode(), bytes, "byte-stable");

        let mut m = cipherbox_core::codec::decode(&bytes)
            .unwrap()
            .as_map()
            .unwrap()
            .clone();
        m.remove("contactCode");
        let short = cipherbox_core::codec::encode(&Value::Map(m)).unwrap();
        assert_eq!(
            InviteClaim::decode(&short).unwrap_err().check(),
            "missing-field"
        );
    }

    /// A claim whose id is the wrong width is not a claim this build can spend
    /// once — the store keys on a fixed-width id, so a short one would truncate
    /// or a long one would not round-trip.
    #[test]
    fn a_claim_id_of_the_wrong_width_is_refused() {
        for width in [CLAIM_ID_LEN - 1, CLAIM_ID_LEN + 1] {
            let mut m = Map::new();
            m.insert("claimId", Value::Bytes(vec![0x01; width]));
            m.insert("contactCode", Value::Bytes(b"contact".to_vec()));
            m.insert("scopeRootName", Value::Bytes(b"k51scoperoot".to_vec()));
            assert_eq!(
                InviteClaim::decode(&encode_fixed_depth(&Value::Map(m)))
                    .unwrap_err()
                    .check(),
                "invalid-field-length",
            );
        }
    }

    /// The fragment is the one channel between a mint and a claim, and the host
    /// in between reads none of it — so what the mint encodes has to be exactly
    /// what the claim path decodes.
    #[test]
    fn a_fragment_round_trips_through_the_text_a_url_carries() {
        let fragment = InviteFragment {
            invite_secret: SecretBytes::new([0x4e; SECRET_LEN]),
            owner_contact_code: b"owner-bundle".to_vec(),
            scope_root_name: b"k51scoperoot".to_vec(),
        };
        let text = fragment.encode().expect("encodes");

        // A URL fragment carries these characters verbatim: anything outside
        // base64url would have to be percent-encoded by the host, which is
        // exactly the composing this type exists to remove.
        assert!(
            text.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "the fragment needs no percent-encoding",
        );
        assert_eq!(InviteFragment::decode(&text).expect("decodes"), fragment);
    }

    /// Every way a fragment can fail to be one is the same fail-closed refusal:
    /// a bearer hands this in off a URL, so a decode that guessed at a missing
    /// or short field would reconstruct an identity nobody committed.
    #[test]
    fn a_fragment_that_is_not_one_is_refused() {
        let mut m = Map::new();
        m.insert("inviteSecret", Value::Bytes(vec![0x01; SECRET_LEN - 1]));
        m.insert("ownerContactCode", Value::Bytes(b"owner".to_vec()));
        m.insert("scopeRootName", Value::Bytes(b"name".to_vec()));
        let short_secret = FRAGMENT_B64.encode(encode_fixed_depth(&Value::Map(m)));

        let mut m = Map::new();
        m.insert("inviteSecret", Value::Bytes(vec![0x01; SECRET_LEN]));
        m.insert("scopeRootName", Value::Bytes(b"name".to_vec()));
        let no_owner = FRAGMENT_B64.encode(encode_fixed_depth(&Value::Map(m)));

        for bad in ["", "not base64!!", "Zm9v", &short_secret, &no_owner] {
            assert_eq!(
                InviteFragment::decode(bad).unwrap_err().check(),
                "malformed-invite-fragment",
                "{bad}",
            );
        }
    }

    /// Both sides of the same wire (AGENTS.md rule 8).
    #[test]
    fn an_oversize_fragment_is_refused_at_both_ends() {
        let oversize = InviteFragment {
            invite_secret: SecretBytes::new([0x4e; SECRET_LEN]),
            owner_contact_code: vec![0x2a; MAX_INVITE_FRAGMENT_BYTES],
            scope_root_name: b"k51scoperoot".to_vec(),
        };
        assert_eq!(
            oversize.encode().unwrap_err().check(),
            "invite-fragment-too-large",
        );
        assert_eq!(
            InviteFragment::decode(&"A".repeat(MAX_FRAGMENT_TEXT_LEN + 1))
                .unwrap_err()
                .check(),
            "invite-fragment-too-large",
        );
    }

    /// A fresh id per claim is what a redelivery cannot fake, so the mint must
    /// take it from the injected entropy seam rather than any constant.
    #[test]
    fn a_minted_claim_takes_its_id_from_the_injected_entropy() {
        let mut entropy = SeededEntropy::new(3);
        let first =
            InviteClaim::mint(&mut entropy, b"name".to_vec(), b"contact".to_vec()).expect("mints");
        let second =
            InviteClaim::mint(&mut entropy, b"name".to_vec(), b"contact".to_vec()).expect("mints");
        assert_ne!(first.claim_id, second.claim_id);
        assert_ne!(first.claim_id, [0u8; CLAIM_ID_LEN]);

        assert!(matches!(
            InviteClaim::mint(&mut SilentEntropy, b"name".to_vec(), b"contact".to_vec()),
            Err(InviteError::Entropy(_))
        ));
    }
}
