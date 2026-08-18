//! The v2 load harness (blueprint/testing.md, dispatch tier).
//!
//! v1's `tests/load` vitest scenarios ported onto the v2 API surface. The
//! harness drives `cipherbox-engine`'s real API client, so a run measures the
//! shipping client path and the harness cannot drift from the contract.

#![forbid(unsafe_code)]

pub mod metrics;
pub mod plan;
pub mod report;
pub mod runner;
pub mod scenarios;
pub mod seams;
#[cfg(test)]
mod stub_http;
pub mod thresholds;
