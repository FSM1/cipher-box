//! CipherBox FUSE filesystem crate.
//!
//! Provides platform-agnostic inode table and error types, plus
//! platform-specific mount implementations (macOS FUSE-T, Linux kernel FUSE,
//! Windows WinFSP).
//!
//! NOTE: This crate is under active extraction from the desktop app
//! (Phase 23-04). Only the inode table and error types are extracted so far.

pub mod error;
pub mod inode;
