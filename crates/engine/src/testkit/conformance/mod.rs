//! Per-seam conformance kits (blueprint/testing.md "Seam conformance
//! kits").
//!
//! One reusable behavioral suite per seam trait with seam-local semantics;
//! every real implementation must pass its kit — browser seams inside the
//! merge-blocking browser suite, desktop seams in cargo tests, the
//! in-memory fakes in this crate's own tests (which is what proves the kits
//! themselves). One contract, every platform: the v1 per-platform
//! store-drift class has no home.
//!
//! Shape: each kit is one `check` async function that panics (via
//! `assert!`) on the first contract violation, so it drops into any test
//! harness — `#[test]` + `block_on` natively, `wasm_bindgen_test` in the
//! browser. Kits for durable stores take an `AsyncFnMut() -> S` **factory**;
//! calling it again must "reopen" the same logical backing (new handle,
//! same durable state) — that is how durability is asserted without a
//! process restart. Kits for transports take a live instance.
//!
//! One seam ships no kit, deliberately: `Http` is a pure passthrough, so
//! its behavior is the live contract suite's job.

pub mod contact_store;
pub mod credential_store;
pub mod floor_store;
pub mod invite_store;
pub mod mailbox;
pub mod received_share_store;
pub mod record_transport;
pub mod retire_ledger;
pub mod scheduler;
pub mod snapshot_cache;
pub mod staging_store;
