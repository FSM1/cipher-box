//! Grants — the ledger, commitment, contact import, share lists, and the accept
//! flow (blueprint/engine.md "Grants and ledger", grants-in-metadata #25 D1).
//!
//! The engine layer that *composes* `crates/core`'s grant/contact/mailbox codecs
//! and KDF edges into stateful behaviour — self-location, owner-only authority,
//! contact import, the accept flow, revocation classification, and the owner seed
//! cross-check. Read-grant *creation* ([`create`]) composes the sweep + re-seal +
//! mailbox primitives into the owner-side mint; [`invite`] mints the ephemeral
//! identity a bearer link's grant is wrapped to. Write grants, claim conversion,
//! and revoke *actions* ride further slices of #635. Every trust decision is a composed core
//! verdict or the adoption gate's; this layer holds no crypto.

pub mod accept;
pub mod child_index;
pub mod contact;
pub mod create;
pub mod invite;
pub mod ledger;
pub mod owner_entry;
pub mod revocation;

pub use accept::{
    AcceptError, AcceptOutcome, ReceivedShare, ReceivedShareStore, ReceivedSharesList, SentIndex,
    SentShare, SharePointer, accept_share,
};
pub use child_index::{
    DestIndexVersion, UndoDestAdd, canonicalize, insert_child, move_child, remove_child,
    repair_observed, undo_dest_add_versioned,
};
pub use contact::{Contact, import_contact};
pub use create::{
    CreateGrantError, CreateGrantOutcome, GrantRecipient, GranteeScopePlan, OwnerGrantKeys,
    ParentScopePlan, create_read_grant,
};
pub use invite::{EphemeralInvitee, InviteError, mint_invite_grant};
pub use ledger::{
    AuthorityViolation, GrantRow, PublishedGrantBlob, enforce_committed_ledger, entry_is_live,
    mint_grant_row, recipient_blinded_tag, self_locate,
};
pub use owner_entry::{AbuseEvent, OwnerEntry, OwnerSeedCache, OwnerSeedEntry, cross_check};
pub use revocation::{ResolutionClass, ResolutionFacts, classify};
