//! Rotation primitives (blueprint/engine.md "Rotation primitives").
//!
//! Home of the F-4 read-plane rotation cascade:
//!
//! - [`eager_set`] — the transitive-closure walk that names every descendant
//!   scope root a revocation rotation must touch.
//! - [`reseal`] — the shared per-scope-root re-seal helper: assemble one scope
//!   root's signed grant section at a given epoch/seed, re-wrapping grant blobs
//!   for exactly the committed set. Consumed by `rotate_scope` (the root cut), by
//!   the [`cascade`] (each eager-set descendant, fresh seed), and by the sweep.
//! - [`rotate`] — `rotateScope`, the read-plane root cut: mint a fresh override
//!   seed, re-seal, publish CAS, raise `minReadEpoch`, enqueue the sweep.
//! - [`trigger`] — the blueprint's five triggers: the owner-only committed-set
//!   cuts (read revoke, write revoke/downgrade, discovered link expiry), the
//!   driver that turns a replay's queued scope-exit triggers into one flat
//!   `rotateScope` per source scope root, and the driver that takes a cut
//!   through the planes it demands.
//! - [`sweep`] — the lazy wave over a scope's **interior nodes**: re-seal every
//!   node whose epoch lags its scope's, plus the idle-cadence `Scheduler` job
//!   that drives it and the direct-child-scope index self-heal. Descendant scope
//!   roots are eager-set members it stops at — their re-key is the
//!   [`cascade`]'s job.
//! - [`cascade`] — the owner-revocation eager cascade (`rotateScope` on a read
//!   revoke): re-key the root **and every transitively-reachable descendant scope
//!   root** with a **fresh** override seed (`prev = Some`), threaded top-down.
//!   This — not the sweep — completes a read revoke by locking out cached
//!   descendant seeds.
//!
//! - [`rotate_write`] — `rotateScopeWrite`, the owner-only write-plane rotation:
//!   a fresh write override seed, a bumped `writeEpoch`, and a child-first name
//!   wave (root re-pointed last) with the three-channel re-point, register-first
//!   inventory swap, and root linger. The write-plane sibling of `rotate_scope`.
//!
//! [`ChildIndexResolver`], [`CascadeResealResolver`], [`ScopeRootPublisher`],
//! [`ScopeExitRotator`], [`SweepResolver`], [`SweepPublisher`],
//! [`WriteSubtreeResolver`] and [`WriteWavePublisher`] have production
//! implementations over the real transport in [`crate::net::rotation`], and
//! [`CutRotator`] in [`crate::net::cut`].

pub mod cascade;
pub mod eager_set;
pub mod reseal;
pub mod retry;
pub mod rotate;
pub mod rotate_write;
pub mod sweep;
pub mod trigger;

pub use cascade::{
    CascadeError, CascadeOutcome, CascadeResealResolver, CascadeTarget, RekeyedScope,
    cascade_rotate_scope,
};
pub use eager_set::{
    ChildIndexResolver, EagerSet, EnumerationError, ResolveFailure, enumerate_eager_set,
};
pub use reseal::{
    AscentAuthority, CommittedSet, PrevEpochSeed, ResealError, ResealSeeds, ScopeRootIdentity,
    WriteHistory, published_override_seed, reseal_scope_root, seed_at_epoch,
};
pub use retry::{MAX_ROTATION_ATTEMPTS, Retryable, bounded};
pub use rotate::{
    ResealedScopeRoot, RotateError, RotateScopePlan, RotationOutcome, RotationPublishError,
    ScopeRootPublisher, rotate_scope,
};
pub use rotate_write::{
    RepointChannel, RepublishedNode, ResumedRoot, ResumedWriteWave, RotateScopeWritePlan,
    WritePublishError, WriteRotateError, WriteRotationOutcome, WriteScopeNode,
    WriteSubtreeResolver, WriteWavePublisher, build_repoint_object, derive_write_name,
    rotate_scope_write,
};
pub use sweep::{
    LaggingNode, NodeRef, SweepError, SweepOutcome, SweepPublisher, SweepResolveFailure,
    SweepResolver, SweptChild, SweptNode, SweptScope, converge_subtree, run_sweep, run_sweep_job,
    sweep_pass,
};
pub use trigger::{
    CutRotationReport, CutRotator, GrantCutPlan, RevokeError, RevokedCommittedSet,
    RotateOnCutError, RotationPlanes, RotationTrigger, ScopeExitReport, ScopeExitRotator,
    WriteRevokeKind, consume_scope_exit_triggers, prune_expired_grants, revoke_read_grant,
    revoke_write_grant, rotate_on_cut,
};
