//! Grants — the ledger, commitment, contact import, share lists, and the accept
//! flow (blueprint/engine.md "Grants and ledger", grants-in-metadata #25 D1).
//!
//! The engine layer that *composes* `crates/core`'s grant/contact/mailbox codecs
//! and KDF edges into stateful behaviour — self-location, owner-only authority,
//! contact import, the accept flow, revocation classification, and the owner seed
//! cross-check. Read-grant *creation* ([`create`]) composes the sweep + re-seal +
//! mailbox primitives into the owner-side mint; [`invite`] mints the ephemeral
//! identity a bearer link's grant is wrapped to and converts its claims into
//! personal grants. Write grants are not implemented here. Every trust decision
//! is a composed core verdict or the adoption gate's; this layer holds no crypto.

pub mod accept;
pub mod append;
pub mod child_index;
pub mod contact;
pub mod contact_store;
pub mod conversion;
pub mod create;
pub mod cut_set;
pub(crate) mod grafted;
pub(crate) mod inbox;
pub mod invite;
pub mod invite_mint;
pub mod ledger;
pub(crate) mod link_read;
pub mod name_cache;
pub mod owner_entry;
pub mod received_share_store;
pub(crate) mod received_status;
pub mod revocation;

pub use accept::{
    AcceptError, AcceptOutcome, BookmarkKey, CLAIM_KEY_LEN, CLAIM_REPOST_FIRST_WAIT,
    CLAIM_REPOST_MAX_WAIT, HeldClaim, LinkHold, MAX_RECEIVED_SHARES, ReceivedShare,
    ReceivedShareStore, ReceivedShareStoreError, ReceivedSharesCodecError, ReceivedSharesList,
    SentIndex, SentShare, SharePointer, TooLong, accept_share,
};
pub use append::{
    EditedSet, GrantEditError, HeldRow, append_row, held_row, name_row, rename_grantee,
    set_permission,
};
pub use child_index::{
    DestIndexVersion, UndoDestAdd, canonicalize, insert_child, move_child, remove_child,
    repair_observed, undo_dest_add_versioned,
};
pub use contact::{Contact, MAX_CONTACT_CODE_BYTES, fingerprint_identity_key, import_contact};
pub use contact_store::{
    BookCodecError, CONTACTS_PREFIX, ContactStore, ContactStoreError, LinkSource, MAX_CONTACTS,
    MAX_LINK_CONTACT_SCOPES, MAX_LINK_CONTACTS, StagingContactStore, link_budget_full,
    resolve_recipient,
};
pub use create::{
    ConvergedSubtree, CreateGrantError, CreateGrantOutcome, GrantRecipient, GrantResumeResolver,
    GrantSubtree, GrantedReadScope, GranteeScopePlan, InteriorRecord, InteriorResealer, MintNet,
    MovingChild, OwnerGrantKeys, ParentScopePlan, PromotedScopeRoot, PromotedSubtree,
    ScopePointerVoucher, ScopeRootPromoter, converge_grant_subtree, create_grant,
    mint_grantee_scope, post_share_pointer, post_share_pointer_at, resume_grantee_scope,
};
pub use cut_set::{
    GranteeCut, LinkSources, RevokedPerson, committed_grantee, expired_links, grantee_cut_set,
    link_cut_set,
};
pub use invite::{
    AckedClaim, CLAIM_ID_LEN, ClaimDisposition, ClaimOutcome, CommittedLink, CommittedScope,
    ConvertedClaim, DEFAULT_ADMISSION_CAP, DEFAULT_LINK_LIFETIME, EphemeralInvitee, InviteClaim,
    InviteError, InviteFragment, LinkTerms, MAX_INVITE_FRAGMENT_BYTES, MAX_INVITE_NAME_BYTES,
    OwnerAuthority, committed_links, convert_invite_claim, link_of_sender, locate_invite_link,
    mint_invite_grant, mint_invite_row, post_invite_claim,
};
pub use invite_mint::{
    FragmentNames, InviteMintError, InviteMintOutcome, InviteMintPlan, MintedInviteLink,
    mint_invite_link, seal_fragment,
};
pub use ledger::{
    AuthorityViolation, GrantRow, PublishedGrantBlob, UNATTESTED_IDENTITY_PK,
    enforce_committed_ledger, mint_grant_row, recipient_blinded_tag, recipient_self_location,
    row_is_owner_attested, self_locate, self_locate_signed,
};
pub use name_cache::{
    GRANTEE_NAMES_PREFIX, GranteeNameCache, MAX_CACHED_NAMES, StagingGranteeNameCache,
};
pub use owner_entry::{AbuseEvent, OwnerEntry, OwnerSeedCache, OwnerSeedEntry, cross_check};
pub use received_share_store::{RECEIVED_SHARES_PREFIX, StagingReceivedShareStore};
pub use revocation::{ResolutionClass, ResolutionFacts, classify};
