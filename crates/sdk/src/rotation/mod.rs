//! Durable rotation high-water anti-rollback gate (ROT-07) and the
//! grant-root scope-exit predicate (SC#3 / ROT-02).
//!
//! Rust port of `@cipherbox/sdk`'s `state/rotation-high-water.ts` and
//! `@cipherbox/sdk-core`'s `rotation/scope.ts` — see those files for the
//! canonical TypeScript references this module mirrors.

pub mod high_water;
pub mod scope;

pub use high_water::{EnforceResolvedParams, HighWaterStore, RotationError, RotationHighWater};
pub use scope::{
    has_covering_grant, maybe_rotate_on_scope_exit, CoverageParams, LocalGrantRecord,
    ScopeExitResult,
};
