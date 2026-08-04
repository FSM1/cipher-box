//! CipherBox core: wire formats, crypto primitives, and the frozen KDF edge
//! catalog. Pure, deterministic, no I/O — entropy and time are injected.
//!
//! Normative design: blueprint/core.md

#![forbid(unsafe_code)]

pub mod codec;
pub mod content;
pub mod error;
pub mod hex;
pub mod ipns;
pub mod kdf;
pub mod payload;
pub mod seal;
pub mod suite;
