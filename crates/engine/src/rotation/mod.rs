//! Rotation primitives (blueprint/engine.md "Rotation primitives").
//!
//! Home of the F-4 read-plane rotation cascade:
//!
//! - [`eager_set`] — the transitive-closure walk that names every descendant
//!   scope root a revocation rotation must touch (#744).
//! - [`reseal`] — the shared per-scope-root re-seal helper: assemble one scope
//!   root's signed grant section at a given epoch/seed, re-wrapping grant blobs
//!   for exactly the committed set. Consumed by `rotate_scope` (the root cut), by
//!   the [`cascade`] (each eager-set descendant, fresh seed), and by the sweep.
//! - [`rotate`] — `rotateScope`, the read-plane root cut: mint a fresh override
//!   seed, re-seal, publish CAS, raise `minReadEpoch`, enqueue the sweep.
//! - [`trigger`] — the read-revoke / scope-exit / manual trigger surface.
//! - [`sweep`] — the lazy-wave epoch-lag convergence pass (metadata-only,
//!   existing seed, `prev = None`) plus its idle-cadence driver and the
//!   direct-child-scope index self-heal. It does **not** mint fresh descendant
//!   seeds — that fresh-seed eager-set republish is the [`cascade`]'s job.
//! - [`cascade`] — the owner-revocation eager cascade (`rotateScope` on a read
//!   revoke): re-key the root **and every transitively-reachable descendant scope
//!   root** with a **fresh** override seed (`prev = Some`), threaded top-down.
//!   This — not the sweep — completes a read revoke by locking out cached
//!   descendant seeds. Proven in simulation; production resolver wiring is
//!   #745/#746.
//!
//! - [`rotate_write`] — `rotateScopeWrite`, the owner-only write-plane rotation:
//!   a fresh write override seed, a bumped `writeEpoch`, and a child-first name
//!   wave (root re-pointed last) with the three-channel re-point, register-first
//!   inventory swap, and root linger. The write-plane sibling of `rotate_scope`;
//!   proven in simulation against faked resolve/publish seams (#745/#746).

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
    CommittedSet, PrevEpochSeed, ResealError, ResealSeeds, ScopeRootIdentity, reseal_scope_root,
};
pub use rotate::{
    ResealedScopeRoot, RotateError, RotateScopePlan, RotationOutcome, ScopeRootPublishError,
    ScopeRootPublisher, rotate_scope,
};
pub use rotate_write::{
    RepointChannel, RepublishedNode, RotateScopeWritePlan, WritePublishError, WriteRotateError,
    WriteRotationOutcome, WriteScopeNode, WriteSubtreeResolver, WriteWavePublisher,
    build_repoint_object, derive_write_name, rotate_scope_write,
};
pub use sweep::{SweepError, SweepOutcome, SweepResolver, SweepTarget, run_sweep, sweep_pass};
pub use trigger::{RevokeError, RevokedCommittedSet, RotationTrigger, revoke_read_grant};
