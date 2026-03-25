//! Windows WinFsp platform module for cipherbox-fuse.
//!
//! Contains all WinFsp operation implementations (FileSystemContext, read ops,
//! write ops, directory ops). Mount/unmount logic stays in the desktop app
//! since it depends on Tauri AppState.

#[cfg(feature = "winfsp")]
mod read_ops;
#[cfg(feature = "winfsp")]
mod write_ops;
#[cfg(feature = "winfsp")]
mod dir_ops;
#[cfg(feature = "winfsp")]
pub mod operations;
