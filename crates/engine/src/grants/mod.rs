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
pub mod child_index;
pub mod contact;
pub mod contact_store;
pub mod create;
pub(crate) mod grafted;
pub(crate) mod inbox;
pub mod invite;
pub mod invite_mint;
pub mod invite_store;
pub mod ledger;
pub mod owner_entry;
pub mod received_share_store;
pub(crate) mod received_status;
pub mod revocation;

pub use accept::{
    AcceptError, AcceptOutcome, BookmarkKey, MAX_RECEIVED_SHARES, ReceivedShare,
    ReceivedShareStore, ReceivedShareStoreError, ReceivedSharesCodecError, ReceivedSharesList,
    SentIndex, SentShare, SharePointer, TooLong, accept_share,
};
pub use child_index::{
    DestIndexVersion, UndoDestAdd, canonicalize, insert_child, move_child, remove_child,
    repair_observed, undo_dest_add_versioned,
};
pub use contact::{Contact, MAX_CONTACT_CODE_BYTES, import_contact};
pub use contact_store::{
    BookCodecError, CONTACTS_PREFIX, ContactStore, ContactStoreError, MAX_CONTACTS,
    MAX_LINK_CONTACT_SCOPES, MAX_LINK_CONTACTS, StagingContactStore, link_budget_full,
    resolve_recipient,
};
pub use create::{
    ConvergedSubtree, CreateGrantError, CreateGrantOutcome, GrantRecipient, GrantResumeResolver,
    GranteeScopePlan, InteriorRecord, InteriorResealer, OwnerGrantKeys, ParentScopePlan,
    PromotedScopeRoot, ScopeRootPromoter, converge_grant_subtree, create_grant, mint_grantee_scope,
    post_share_pointer,
};
pub use invite::{
    CLAIM_ID_LEN, ClaimOutcome, CommittedLink, CommittedScope, ConvertedClaim,
    ConvertedClaimRecord, EphemeralInvitee, InviteClaim, InviteError, InviteFragment,
    MAX_INVITE_FRAGMENT_BYTES, MintedInvite, OwnerAuthority, RecordedInvite, ScopeLinks,
    convert_invite_claim, locate_invite_link, mint_invite_grant, partition_scope_links,
    post_invite_claim,
};
pub use invite_mint::{
    InviteMintError, InviteMintPlan, MintedInviteLink, PendingInviteLink, mint_invite_link,
};
pub use invite_store::{
    INVITE_RECORDS_PREFIX, InviteRecords, InviteRecordsCodecError, InviteStore, InviteStoreError,
    MAX_CONVERTED_CLAIMS, MAX_INVITE_RECORDS, StagingInviteStore,
};
pub use ledger::{
    AuthorityViolation, GrantRow, PublishedGrantBlob, UNATTESTED_IDENTITY_PK,
    enforce_committed_ledger, entry_is_live, mint_grant_row, recipient_blinded_tag,
    recipient_self_location, row_is_owner_attested, self_locate, self_locate_signed,
};
pub use owner_entry::{AbuseEvent, OwnerEntry, OwnerSeedCache, OwnerSeedEntry, cross_check};
pub use received_share_store::{RECEIVED_SHARES_PREFIX, StagingReceivedShareStore};
pub use revocation::{ResolutionClass, ResolutionFacts, classify};
