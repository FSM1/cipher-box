//! File metadata types.
//!
//! Re-exports file-related types from the folder module for convenience.
//! FileMetadata, FilePointer, and VersionEntry are defined in folder.rs
//! since they share the same encryption context (parent folder's AES key).

pub use crate::folder::{
    FileMetadata, FilePointer, VersionEntry,
    encrypt_file_metadata, decrypt_file_metadata,
};
