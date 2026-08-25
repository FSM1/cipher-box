//! FUSE userspace library implementation
//!
//! This is an improved rewrite of the FUSE userspace library (lowlevel interface) to fully take
//! advantage of Rust's architecture. The only thing we rely on in the real libfuse are mount
//! and unmount calls which are needed to establish a fd to talk to the kernel driver.
//!
//! **Note:** This crate is Unix-only. On non-Unix platforms it compiles as an empty crate,
//! so a workspace build that selects it on Windows still succeeds.

#![warn(missing_docs, missing_debug_implementations, rust_2018_idioms)]

// On non-Unix platforms, this crate is intentionally empty: fuser only works
// on Unix, and a workspace build must still be able to select it.
#[cfg(unix)]
include!("lib_impl.rs");
