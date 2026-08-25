//! CipherBox engine: the one stateful brain — sync, key lifecycle, and the
//! seam traits through which entropy, time, and policy are injected.
//!
//! Normative design: blueprint/engine.md
//!
//! The architecture surface: the eight host seam traits and their whole-set
//! constructor bundle ([`seams`]), injected entropy ([`entropy`]), the
//! environment-scoped sync timing profile ([`profile`]) and storage policy
//! ([`storage_policy`]), the hand-written API client and token lifecycle
//! ([`api`]), and the facade ([`facade`]) — one async command-and-event
//! surface with start of secret. The pipeline modules ([`gate`], [`sync`],
//! [`rotation`], [`grants`], [`mailbox`], [`net`], [`content`]) sit behind it.
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
pub mod mailbox;
pub mod net;
mod owner_keys;
pub mod profile;
pub mod rotation;
pub mod seams;
mod session;
pub mod settings;
pub mod storage_policy;
pub mod sync;
#[cfg(feature = "test-kit")]
pub mod testkit;

pub use api::{
    ApiClient, ApiError, ChallengeSigner, IdentityChallengeSigner, LoginOutcome, MailboxItem,
    NameRegistration, QUOTA_EXCEEDED, Quota, RetireResult, SiweNonce, TestLoginOutcome,
    UPLOAD_TOO_LARGE, UploadResult,
};
pub use content::{
    ByoIpfsConfig, ByoKind, ContentDag, ContentKey, ContentPlane, ContentProfile, ContentVersion,
    ContentWriter, DAG_ROOT_CODEC, DagError, ExpandError, Expansion, FinishedContent, Gateway,
    GatewayConfig, GatewaySource, PinMode, ProviderError, PrunePlan, QuotaExceeded,
    ROOT_FORMAT_VERSION, ReadError, RetentionPolicy, RetireTarget, RootManifest, SealError,
    SealedChunk, SealedContent, SessionBearer, assemble, decode_root, expand_retire_targets,
    frame_and_seal, leaf_range_for_byte_range, plan_prune, pre_flight_quota_check, read_block,
    seal_one_chunk, test_connection, validate_byo_config,
};
pub use entropy::{Entropy, EntropyError};
pub use facade::{
    ApiBaseUrl, BlankApiBaseUrl, BlockProgress, Breadcrumb, Command, CommandOutcome, DeadLetter,
    Engine, EngineError, EngineView, Event, EventStream, LoginSecret, MAX_CONTACT_CODE_BYTES,
    MAX_OPEN_STREAMS, NodeAttrs, NodeId, NodeKind, OpPhase, OverBudgetCause, Permission,
    ReceivedShareRow, RefusedBudget, SessionStatus, SharingContact, SharingGrant,
    SharingInviteLinks, SharingView, SnapshotChild, SnapshotView, Staleness, StatFs, StreamHandle,
    WriteHandle, WriteTarget,
};
pub use gate::{
    Adopted, Candidate, GateError, GateRejection, GateStage, ReaderContext, RejectionReason,
    SeedBlob, adopt,
};
pub use grants::{
    AbuseEvent, AcceptError, AcceptOutcome, AuthorityViolation, Contact, MintedInviteLink,
    OwnerEntry, OwnerSeedCache, PublishedGrantBlob, ReceivedShare, ReceivedShareStore,
    ReceivedShareStoreError, ReceivedSharesCodecError, ReceivedSharesList, ResolutionClass,
    ResolutionFacts, SentIndex, SentShare, SharePointer, StagingReceivedShareStore, accept_share,
    cross_check, enforce_committed_ledger, import_contact, recipient_blinded_tag, self_locate,
};
pub use mailbox::{VerifiedMailboxItem, poll_verified, post_sealed};
pub use net::{
    AdoptOutcome, Adopter, HeldRecord, HeldRecords, OrphanHeads, PreflightError, PublishError,
    PublishOutcome, PublishRequest, RePutResult, RecordPointerFetch, RecordPublishError,
    ResolveOutcome, Resolved, ReviveError, ReviveRequest, RootAdopter, StagingRetireLedger,
    publish, resolve, revive,
};
pub use profile::SyncTimingProfile;
pub use rotation::{
    ChildIndexResolver, CommittedSet, CutRotationReport, CutRotator, EagerSet, EnumerationError,
    GrantCutPlan, PrevEpochSeed, ResealError, ResealSeeds, ResealedScopeRoot, ResolveFailure,
    RevokeError, RevokedCommittedSet, RotateError, RotateOnCutError, RotateScopePlan,
    RotationOutcome, RotationPlanes, RotationPublishError, RotationTrigger, ScopeExitReport,
    ScopeExitRotator, ScopeRootIdentity, ScopeRootPublisher, SweepError, SweepOutcome,
    WriteHistory, WriteRevokeKind, consume_scope_exit_triggers, enumerate_eager_set,
    prune_expired_grants, reseal_scope_root, revoke_read_grant, revoke_write_grant, rotate_on_cut,
    rotate_scope, run_sweep_job,
};
pub use seams::{OwedRetire, RetireLedger, SeamError, SeamResult, SeamSet, SeamTypes};
pub use settings::{
    DefaultsReason, Placement, PlacementDecision, PlacementRefusal, PlacementSource,
    SessionPlacement, SettingsLoad, SettingsPublishError, SettingsRefusal, VaultSettings,
    decide_placement, load_settings, placement_of, publish_settings, settings_name,
};
pub use storage_policy::{Headroom, StoragePlatform, StoragePolicy};
pub use sync::{
    AppliedOp, BlockedOp, Connectivity, DeadLetterReason, DropReason, FocusTarget, FocusWindow,
    HeadReconciliation, Link, NewNode, NodeMeta, Op, OpKind, OpRecordError, OpResolution,
    PointerError, PointerFetch, RecordClass, RecordReader, RecordSeal, Repair, Replaced,
    ReplayReport, ScopeCrossing, SessionRole, SettingsHold, Snapshot, StagedContent, TickCause,
    TickControl, VaultPointerAdoption, apply_overlay, apply_repairs, classify, decode_queue,
    encode_op_record, focus_set, observed_repair, rebase_one, reconcile_head,
    record_content_root_cid, replay, resolve_vault_pointer, stage_op,
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
