//! Rotation primitives (blueprint/engine.md "Rotation primitives").
//!
//! Home of the F-4 read-plane rotation cascade. This slice lands only the
//! **eager-set enumeration walk** ([`eager_set`]) — the transitive-closure
//! traversal that names every descendant scope root a rotation must touch.
//! `rotateScope` (the rotation itself) and `sweep` (the epoch-lag work-list)
//! are sibling slices of #635 that *consume* this enumeration; neither lands
//! here.

pub mod eager_set;

pub use eager_set::{
    ChildIndexResolver, EagerSet, EnumerationError, ResolveFailure, enumerate_eager_set,
};
