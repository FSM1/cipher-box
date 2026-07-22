//! Grants — the ledger, commitment, pseudonyms, contact import, share lists,
//! and the accept flow (blueprint/engine.md "Grants and ledger").
//!
//! Grants live in the published scope root (grants-in-metadata, #25 D1): grant
//! blobs keyed by blinded tags, the authoritative ledger in the write-body, and
//! the epoch-free owner-signed grant-set commitment. This module is the engine
//! layer that *composes* `crates/core`'s grant/contact/mailbox codecs and KDF
//! edges into the stateful behaviour — self-location, owner-only authority,
//! contact import, the accept flow, revocation classification, and the owner
//! seed cross-check. It mints no grants: grant *creation*, invites, and revoke
//! *actions* ride the rotation primitives of a sibling slice (#635). Every trust
//! decision here is a composed core verdict or the adoption gate's; this layer
//! holds no crypto.

pub mod accept;
pub mod contact;
pub mod ledger;
pub mod owner_entry;
pub mod revocation;

pub use accept::{
    AcceptError, AcceptOutcome, ReceivedShare, ReceivedShareStore, ReceivedSharesList, SentIndex,
    SentShare, SharePointer, accept_share,
};
pub use contact::{Contact, import_contact};
pub use ledger::{
    AuthorityViolation, PublishedGrantBlob, enforce_committed_ledger, recipient_blinded_tag,
    self_locate,
};
pub use owner_entry::{AbuseEvent, OwnerEntry, OwnerSeedCache, OwnerSeedEntry, cross_check};
pub use revocation::{ResolutionClass, ResolutionFacts, classify};
