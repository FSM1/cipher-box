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
pub mod entropy;
pub mod facade;
pub mod gate;
pub mod net;
pub mod profile;
pub mod seams;
pub mod sync;
#[cfg(feature = "test-kit")]
pub mod testkit;

pub use api::{
    ApiClient, ApiError, ChallengeSigner, IdentityChallengeSigner, LoginOutcome, MailboxItem,
    NameRegistration, Quota, SiweNonce, TestLoginOutcome, UploadResult,
};
pub use entropy::{Entropy, EntropyError};
pub use facade::{
    Command, Engine, EngineError, Event, EventStream, LoginSecret, NodeId, NodeKind, Permission,
    PlaintextContent, Staleness,
};
pub use gate::{
    Adopted, AscentCheck, Candidate, GateError, GateRejection, GateStage, ReaderContext,
    RejectionReason, SeedBlob, SignedStructure, adopt,
};
pub use net::{
    Adopter, HeldRecord, PublishError, PublishOutcome, PublishRequest, RePutResult, ResolveOutcome,
    Resolved, ReviveError, ReviveRequest, publish, resolve, revive,
};
pub use profile::SyncTimingProfile;
pub use seams::{SeamError, SeamResult, SeamSet, SeamTypes};
pub use sync::{
    AppliedOp, Connectivity, DeadLetterReason, DropReason, FocusTarget, FocusWindow,
    HeadReconciliation, Link, NodeMeta, Op, OpKind, OpResolution, PointerError, PointerFetch,
    Repair, ReplayReport, SessionRole, Snapshot, StageOutcome, TickCause, TickControl,
    VaultPointerAdoption, apply_overlay, apply_repairs, classify, cold_seed_floors, decode_queue,
    focus_set, observed_repair, rebase_one, reconcile_head, replay, resolve_vault_pointer,
    stage_op,
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
