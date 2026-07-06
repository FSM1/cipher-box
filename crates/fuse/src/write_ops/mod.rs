//! Write operations for macOS FUSE filesystem.
//!
//! Contains handler logic for: write, create, setattr, rename, unlink, rmdir, mkdir.
//!
//! `grant_scope` is platform-agnostic (`any(fuse, winfsp)`): it is consumed by
//! BOTH the Unix write handlers below (69-11) and the Windows write handlers
//! (69-14) — a single shared module, never duplicated per platform (69-07,
//! Pitfall 1).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub mod grant_scope;

#[cfg(feature = "fuse")]
pub(crate) mod implementation {
    mod file_data;
    mod delete;
    mod mkdir;
    mod rename;

    pub use file_data::{handle_setattr, handle_write, handle_create};
    pub use delete::{handle_unlink, handle_rmdir};
    pub use mkdir::handle_mkdir;
    pub use rename::handle_rename;
}
