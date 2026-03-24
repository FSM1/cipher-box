//! FUSE userspace library implementation
//!
//! This is an improved rewrite of the FUSE userspace library (lowlevel interface) to fully take
//! advantage of Rust's architecture. The only thing we rely on in the real libfuse are mount
//! and unmount calls which are needed to establish a fd to talk to the kernel driver.
//!
//! **Note:** This crate is Unix-only. On non-Unix platforms it compiles as an empty crate
//! because the workspace `[patch.crates-io]` forces Cargo to resolve it globally.

#![warn(missing_docs, missing_debug_implementations, rust_2018_idioms)]

// On non-Unix platforms, this crate is intentionally empty.
// The workspace [patch.crates-io] forces Cargo to resolve and compile
// this vendored fuser on all platforms, but fuser only works on Unix.
#[cfg(unix)]
include!("lib_impl.rs");
