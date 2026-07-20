//! The engine test kit (`test-kit` feature): in-memory seam fakes, the
//! virtual-clock scheduler, seeded entropy, and the per-seam conformance
//! kits (blueprint/testing.md "crates/engine — seam fakes and the
//! simulation harness", "Seam conformance kits").
//!
//! No network, no docker, no wall clock: engines built on [`FakeWorld`]
//! devices run entirely in memory on virtual time, so CAS races and
//! multi-day EOL timelines execute in milliseconds. Multiple devices share
//! one fake record store, mailbox hub, and clock — the seed of the
//! simulation harness.
//!
//! Host crates enable this feature from dev-dependencies and run each
//! [`conformance`] kit against their real seam implementations: browser
//! seams inside the merge-blocking browser suite, desktop seams in cargo
//! tests. One contract, every platform.

pub mod conformance;
mod entropy;
mod executor;
pub mod fakes;
mod world;

pub use entropy::SeededEntropy;
pub use executor::block_on;
pub use world::{FakeDevice, FakeSeamTypes, FakeWorld};
