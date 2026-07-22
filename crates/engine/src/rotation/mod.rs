//! Rotation primitives (blueprint/engine.md "Rotation primitives").
//!
//! Home of the F-4 read-plane rotation cascade:
//!
//! - [`eager_set`] — the transitive-closure walk that names every descendant
//!   scope root a revocation rotation must touch (#744).
//! - [`reseal`] — the shared per-scope-root re-seal helper: assemble one scope
//!   root's signed grant section at a given epoch/seed, re-wrapping grant blobs
//!   for exactly the committed set. Consumed by `rotate_scope` (the root cut and,
//!   once the resolver wiring lands, each eager-set descendant) and by the sweep.
//! - [`rotate`] — `rotateScope`, the read-plane root cut: mint a fresh override
//!   seed, re-seal, publish CAS, raise `minReadEpoch`, enqueue the sweep.
//! - [`trigger`] — the read-revoke / scope-exit / manual trigger surface.
//! - [`sweep`] — the lazy-wave epoch-lag convergence pass (metadata-only,
//!   existing seed, `prev = None`) plus its idle-cadence driver and the
//!   direct-child-scope index self-heal. It does **not** mint fresh descendant
//!   seeds — that fresh-seed eager-set republish is `rotateScope`'s job on an
//!   owner-revocation rotation, deferred pending the resolver/tree wiring
//!   (#745/#746).
//!
//! `rotateScopeWrite` (the write-plane name wave) is a separate primitive, out
//! of this slice's read-plane scope.

pub mod eager_set;
pub mod reseal;
pub mod rotate;
pub mod sweep;
pub mod trigger;

pub use eager_set::{
    ChildIndexResolver, EagerSet, EnumerationError, ResolveFailure, enumerate_eager_set,
};
pub use reseal::{
    CommittedSet, PrevEpochSeed, ResealError, ResealSeeds, ScopeRootIdentity, reseal_scope_root,
};
pub use rotate::{
    ResealedScopeRoot, RotateError, RotateScopePlan, RotationOutcome, ScopeRootPublishError,
    ScopeRootPublisher, rotate_scope,
};
pub use sweep::{SweepError, SweepOutcome, SweepResolver, SweepTarget, run_sweep, sweep_pass};
pub use trigger::{RevokeError, RevokedCommittedSet, RotationTrigger, revoke_read_grant};
