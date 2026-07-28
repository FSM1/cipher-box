//! CipherBox engine: the one stateful brain — sync, key lifecycle, and the
//! seam traits through which entropy, time, and policy are injected.
//!
//! Normative design: blueprint/engine.md
//!
//! This slice freezes the architecture surface: the nine host seam traits
//! and the whole-set constructor bundle ([`seams`]), injected entropy
//! ([`entropy`]), the environment-scoped sync timing profile ([`profile`]),
//! and the facade skeleton ([`facade`]) — one async command-and-event
//! surface with start of secret. The [`api`] module lands the single
//! hand-written API client and token lifecycle. The rest of the pipeline
//! (gate, sync, rotation, grants, pointer, mailbox, net, content) lands in
//! later slices behind this exact surface.
//!
//! The `test-kit` feature adds [`testkit`]: in-memory fakes for every seam,
//! a virtual-clock scheduler, seeded entropy, and the reusable per-seam
//! conformance kits that real host implementations must pass.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// Deliberate: seam traits use native `async fn`. The engine is consumed as
// a concrete generic (no `dyn` seams), runs single-writer pinned to one
// execution context, and must compile for wasm32 where futures are !Send —
// so no auto-trait bound flexibility is lost.
#![allow(async_fn_in_trait)]

pub mod api;
pub mod content;
pub mod entropy;
pub mod facade;
pub mod gate;
pub mod grants;
mod hex;
pub mod mailbox;
pub mod net;
pub mod profile;
pub mod rotation;
pub mod seams;
pub mod secret_util;
mod session;
pub mod storage_policy;
pub mod sync;
#[cfg(feature = "test-kit")]
pub mod testkit;

pub use api::{
    ApiClient, ApiError, ChallengeSigner, IdentityChallengeSigner, LoginOutcome, MailboxItem,
    NameRegistration, Quota, SiweNonce, TestLoginOutcome, UploadResult,
};
pub use content::{
    ByoIpfsConfig, ByoKind, ContentDag, ContentKey, ContentPlane, ContentProfile, ContentVersion,
    DAG_ROOT_CODEC, DagError, Gateway, GatewayConfig, GatewaySource, PinMode, ProviderError,
    PrunePlan, QuotaExceeded, ROOT_FORMAT_VERSION, ReadError, RootManifest, SealError, SealedChunk,
    SealedContent, assemble, decode_root, frame_and_seal, leaf_range_for_byte_range, plan_prune,
    pre_flight_quota_check, read_block, seal_content, test_connection, validate_endpoint,
};
pub use entropy::{Entropy, EntropyError};
pub use facade::{
    Breadcrumb, Command, Engine, EngineError, Event, EventStream, LoginSecret, NodeId, NodeKind,
    OpPhase, Permission, PlaintextContent, SnapshotChild, SnapshotView, Staleness,
};
pub use gate::{
    Adopted, Candidate, GateError, GateRejection, GateStage, ReaderContext, RejectionReason,
    SeedBlob, adopt,
};
pub use grants::{
    AbuseEvent, AcceptError, AcceptOutcome, AuthorityViolation, Contact, OwnerEntry,
    OwnerSeedCache, PublishedGrantBlob, ReceivedShare, ReceivedShareStore, ReceivedSharesList,
    ResolutionClass, ResolutionFacts, SentIndex, SentShare, SharePointer, accept_share,
    cross_check, enforce_committed_ledger, import_contact, recipient_blinded_tag, self_locate,
};
pub use mailbox::{VerifiedMailboxItem, poll_verified, post_sealed};
pub use net::{
    AdoptOutcome, Adopter, HeldRecord, HeldRecords, PublishError, PublishOutcome, PublishRequest,
    RePutResult, RecordPointerFetch, ResolveOutcome, Resolved, ReviveError, ReviveRequest,
    RootAdopter, publish, resolve, revive,
};
pub use profile::SyncTimingProfile;
pub use rotation::{
    ChildIndexResolver, CommittedSet, EagerSet, EnumerationError, PrevEpochSeed, ResealError,
    ResealSeeds, ResealedScopeRoot, ResolveFailure, RevokeError, RevokedCommittedSet, RotateError,
    RotateScopePlan, RotationOutcome, RotationTrigger, ScopeRootIdentity, ScopeRootPublishError,
    ScopeRootPublisher, enumerate_eager_set, reseal_scope_root, revoke_read_grant, rotate_scope,
};
pub use seams::{SeamError, SeamResult, SeamSet, SeamTypes};
pub use storage_policy::{StoragePlatform, StoragePolicy};
pub use sync::{
    AppliedOp, Connectivity, DeadLetterReason, DropReason, FocusTarget, FocusWindow,
    HeadReconciliation, Link, NodeMeta, Op, OpKind, OpRecordError, OpResolution, PointerError,
    PointerFetch, RecordClass, RecordReader, RecordSeal, Repair, ReplayReport, SessionRole,
    Snapshot, StageOutcome, TickCause, TickControl, VaultPointerAdoption, apply_overlay,
    apply_repairs, classify, decode_queue, encode_op_record, focus_set, observed_repair,
    rebase_one, reconcile_head, record_content_root_cid, replay, resolve_vault_pointer, stage_op,
};

/// Placeholder identity item; kept for the sibling crate stubs' dependency
/// tests until real cross-crate surface replaces it.
pub const CRATE: &str = "cipherbox-engine";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name() {
        assert_eq!(super::CRATE, "cipherbox-engine");
    }
}
