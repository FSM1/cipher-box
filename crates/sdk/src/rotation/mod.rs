//! Durable rotation high-water anti-rollback gate (ROT-07), the grant-root
//! scope-exit predicate (SC#3 / ROT-02), and the resumable read-key rotation
//! walk engine (ROT-01, `rotate_one` / `rotate_read_from_node`).
//!
//! Rust port of `@cipherbox/sdk`'s `state/rotation-high-water.ts` and
//! `@cipherbox/sdk-core`'s `rotation/scope.ts` and `rotation/engine.ts` —
//! see those files for the canonical TypeScript references this module
//! mirrors.

pub mod engine;
pub mod high_water;
pub mod scope;

pub use engine::{
    rotate_one, rotate_read_from_node, rotate_read_from_node_with_root_children,
    verify_subtree_clean, CommittedRotation, DirtyFrontierEntry, GrantRow, PublishAttempt,
    PublishOutcome, ResolvedRecord, RotateOneOutcome, RotateReadResult, RotationDeps,
    RotationJobRecord, RotationStatus,
};
pub use high_water::{EnforceResolvedParams, HighWaterStore, RotationError, RotationHighWater};
pub use scope::{
    has_covering_grant, maybe_rotate_on_scope_exit, CoverageParams, LocalGrantRecord,
    ScopeExitResult,
};
