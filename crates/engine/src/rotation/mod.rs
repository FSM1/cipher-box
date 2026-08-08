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
//! - [`trigger`] — the read-revoke / scope-exit / manual trigger surface, and
//!   the driver that turns a replay's queued scope-exit triggers into one flat
//!   `rotateScope` per source scope root.
//! - [`sweep`] — the lazy wave over a scope's **interior nodes**: re-seal every
//!   node whose epoch lags its scope's, plus the idle-cadence driver and the
//!   direct-child-scope index self-heal. Descendant scope roots are eager-set
//!   members it stops at — their re-key is the [`cascade`]'s job.
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
//! [`SweepResolver`], [`SweepPublisher`], [`WriteSubtreeResolver`] and
//! [`WriteWavePublisher`] have production implementations over the real
//! transport in [`crate::net::rotation`]. [`ScopeExitRotator`] has no production
//! implementation yet; tests fake it.

pub mod cascade;
pub mod eager_set;
pub mod reseal;
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
    CommittedSet, PrevEpochSeed, ResealError, ResealSeeds, ScopeRootIdentity, WriteHistory,
    reseal_scope_root, seed_at_epoch,
};
pub use rotate::{
    ResealedScopeRoot, RotateError, RotateScopePlan, RotationOutcome, ScopeRootPublishError,
    ScopeRootPublisher, rotate_scope,
};
pub use rotate_write::{
    RepointChannel, RepublishedNode, ResumedWriteWave, RotateScopeWritePlan, WritePublishError,
    WriteRotateError, WriteRotationOutcome, WriteScopeNode, WriteSubtreeResolver,
    WriteWavePublisher, build_repoint_object, derive_write_name, rotate_scope_write,
};
pub use sweep::{
    LaggingNode, NodeRef, SweepError, SweepOutcome, SweepPublisher, SweepResolveFailure,
    SweepResolver, SweptChild, SweptNode, SweptScope, converge_subtree, run_sweep, sweep_pass,
};
pub use trigger::{
    RevokeError, RevokedCommittedSet, RotationTrigger, ScopeExitReport, ScopeExitRotator,
    consume_scope_exit_triggers, revoke_read_grant,
};
