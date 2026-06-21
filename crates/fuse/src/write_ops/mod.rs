//! Write operations for macOS FUSE filesystem.
//!
//! Contains handler logic for: write, create, setattr, rename, unlink, rmdir, mkdir.

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
