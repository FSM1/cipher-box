//! Durable rotation high-water anti-rollback gate (ROT-07).
//!
//! Rust port of `@cipherbox/sdk`'s `state/rotation-high-water.ts` — see that
//! file for the canonical TypeScript reference this module mirrors.

pub mod high_water;

pub use high_water::{
    EnforceResolvedParams, HighWaterStore, RotationError, RotationHighWater,
};
