//! CipherBox fuse: the filesystem projection over the engine facade, and the
//! host-adapter trait each mount technology implements — FUSE-T SMB on macOS,
//! libfuse3 on Linux, WinFsp on Windows.
//!
//! Normative design: blueprint/desktop.md.
//!
//! One operation core serves every platform: v1's duplicated per-host
//! operation trees produced a revocation bypass that existed in exactly one of
//! them. Everything platform-shaped lives behind [`HostAdapter`] and nothing
//! else does. The projection holds no key material — the inode and handle maps
//! carry identity only, and the plaintext its chunk cache holds is memory-only
//! and zeroized on the way out.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod adapter;
mod cache;
mod error;
mod handle;
mod inode;
mod name;
mod ops;

pub use adapter::{CacheTtls, HostAdapter, HostCapabilities, Invalidation};
pub use cache::CacheBudget;
pub use error::{OverBudgetCause, VfsError};
pub use handle::{Access, HandleId, HandleTable, OpenFile};
pub use inode::{InodeTable, ROOT_INO};
pub use name::{MAX_NAME_BYTES, NameError, is_emittable, is_platform_junk, validate_name};
pub use ops::{Attributes, DirEntry, OperationCore};
