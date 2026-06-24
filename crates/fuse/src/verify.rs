//! IPNS verify chokepoint — thin re-export of the `cipherbox-api-client` wrapper.
//!
//! `resolve_ipns_verified`, `VerifyError`, and `VerifiedResolve` have been relocated
//! to `crates/api-client/src/ipns.rs` (Plan 60-01, D-08) so all Rust consumers
//! (sdk, fuse, desktop) share one implementation.
//!
//! This file keeps the `crate::verify::*` import surface intact for the 9 FUSE caller
//! arms in `events.rs`, `metadata.rs`, `publish.rs`, `fs.rs`, and `replay.rs` until
//! Plan 03 migrates those callers directly to `cipherbox_api_client::ipns::*`.
//!
//! # Failure posture (D-04 strict cutover)
//!
//! - `VerifyError::Invalid` — all verification failures including absent sig fields,
//!   invalid/partial signature, CBOR binding mismatch, or expired record (D-04/D-07).
//!   No `Legacy` variant — all callers fail the operation on `Invalid`.
//! - `VerifyError::Api` — API-level error; callers propagate as-is.

pub use cipherbox_api_client::ipns::{VerifyError, VerifiedResolve, resolve_ipns_verified};
