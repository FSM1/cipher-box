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
//!
//! `sweep` (the epoch-lag work-list) is a sibling slice of #635 that consumes
//! [`reseal`]; it does not land here. `rotateScopeWrite` (the write-plane name
//! wave) is a separate primitive, out of this slice's read-plane scope.

pub mod eager_set;
pub mod reseal;
pub mod rotate;
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
pub use trigger::{RevokeError, RevokedCommittedSet, RotationTrigger, revoke_read_grant};
