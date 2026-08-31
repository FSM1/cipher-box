//! The Windows security calls the vault mount cannot make in safe Rust.
//!
//! `crates/fuse` is `#![forbid(unsafe_code)]` and the WinFsp adapter lives
//! there, so the two FFI shapes it cannot express are here instead: reading the
//! mounting user's SID out of the process token, and copying a finished
//! security descriptor into the `&mut [c_void]` out-buffer WinFsp passes.
//!
//! Deliberately ignorant of what it moves. The descriptor is assembled — and
//! tested — in safe Rust by the adapter; this crate only carries bytes across
//! the FFI edge.

#![warn(missing_docs)]

#[cfg(windows)]
mod win32;

#[cfg(windows)]
pub use win32::{current_user_sid, write_descriptor};
