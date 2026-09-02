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

pub mod account;
pub mod conformance;
mod content;
mod entropy;
mod executor;
pub mod fakes;
pub mod name_law;
mod owner_root;
mod world;

pub use account::retire_targets;
pub use content::{
    block_store, doomed_version, frame_version, frame_version_with, gateway, requested_cid, serve,
};
pub use entropy::{FailingEntropy, SeededEntropy, SilentAtWidth, SilentEntropy};

/// A preserved-field map of `bytes` padding under one key — the
/// attacker-sized run a committed write grantee puts on any structure it
/// authors, for a test that must prove the carry does not ride forward.
pub fn padding(bytes: usize) -> cipherbox_core::seal::PreservedFields {
    [(
        "zpad".to_string(),
        cipherbox_core::codec::Value::Bytes(vec![0u8; bytes]),
    )]
    .into_iter()
    .collect()
}
pub use executor::{block_on, poll_tasks_once, poll_tasks_until_parked};
pub use owner_root::{
    CARRIED_WRITE_HISTORY_LINK, OWNER_ROOT_EPOCH, OWNER_ROOT_POINTER_READ_KEY,
    OWNER_ROOT_PSEUDONYM_SEED, OWNER_ROOT_SCOPE_SEED, OWNER_ROOT_WRITE_SCOPE_SEED,
    OwnerRootFixture, OwnerRootSpec, owner_root_fixture,
};
pub use world::{FakeDevice, FakeSeamTypes, FakeWorld};
