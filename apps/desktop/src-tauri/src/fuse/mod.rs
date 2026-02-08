//! FUSE filesystem module for CipherBox Desktop.
//!
//! Mounts the encrypted vault at ~/CipherVault as a native macOS filesystem
//! using FUSE-T. All crypto operations happen in Rust via the crypto module.
//!
//! The cache and inode modules are always available (they don't depend on libfuse).
//! The operations module and mount/unmount functions require the `fuse` feature.

pub mod cache;
pub mod inode;
#[cfg(feature = "fuse")]
pub mod operations;

#[cfg(feature = "fuse")]
use std::collections::HashMap;
#[cfg(feature = "fuse")]
use std::path::PathBuf;
#[cfg(feature = "fuse")]
use std::sync::atomic::AtomicU64;
#[cfg(feature = "fuse")]
use std::sync::Arc;

#[cfg(feature = "fuse")]
use fuser::MountOption;

#[cfg(feature = "fuse")]
use crate::api::client::ApiClient;
#[cfg(feature = "fuse")]
use crate::state::AppState;

/// Open file handle for tracking active reads/writes.
#[cfg(feature = "fuse")]
pub struct OpenFileHandle {
    /// Inode number of the open file.
    pub ino: u64,
    /// Open flags (O_RDONLY, O_WRONLY, O_RDWR).
    pub flags: i32,
    /// Pre-fetched decrypted content (populated on first read).
    pub cached_content: Option<Vec<u8>>,
}

/// The main FUSE filesystem struct.
///
/// Implements `fuser::Filesystem` to serve decrypted folder listings
/// and file content from the CipherBox vault.
#[cfg(feature = "fuse")]
pub struct CipherVaultFS {
    /// Inode table mapping inode numbers to metadata.
    pub inodes: inode::InodeTable,
    /// Folder metadata cache with 30s TTL.
    pub metadata_cache: cache::MetadataCache,
    /// File content cache with 256 MiB LRU eviction.
    pub content_cache: cache::ContentCache,
    /// API client for IPFS/IPNS operations.
    pub api: Arc<ApiClient>,
    /// User's secp256k1 private key for ECIES decryption (32 bytes).
    pub private_key: Vec<u8>,
    /// Root folder AES-256 key (32 bytes).
    pub root_folder_key: Vec<u8>,
    /// Root IPNS name (k51... format).
    pub root_ipns_name: String,
    /// Tokio runtime handle for spawning async tasks from FUSE threads.
    pub rt: tokio::runtime::Handle,
    /// Next file handle counter.
    pub next_fh: AtomicU64,
    /// Map of open file handles.
    pub open_files: HashMap<u64, OpenFileHandle>,
}

/// Get the mount point path: ~/CipherVault
#[cfg(feature = "fuse")]
pub fn mount_point() -> PathBuf {
    dirs::home_dir()
        .expect("Could not determine home directory")
        .join("CipherVault")
}

/// Mount the FUSE filesystem after successful authentication.
///
/// Creates the ~/CipherVault directory if it doesn't exist, builds the
/// CipherVaultFS with keys from AppState, and spawns the FUSE event loop
/// on a dedicated std::thread (not tokio -- fuser runs its own event loop).
///
/// Returns a JoinHandle for the mount thread.
#[cfg(feature = "fuse")]
pub fn mount_filesystem(
    state: &AppState,
    rt: tokio::runtime::Handle,
    private_key: Vec<u8>,
    root_folder_key: Vec<u8>,
    root_ipns_name: String,
    root_ipns_private_key: Option<Vec<u8>>,
) -> Result<std::thread::JoinHandle<()>, String> {
    let mount_path = mount_point();

    // Create mount directory if it doesn't exist
    if !mount_path.exists() {
        std::fs::create_dir_all(&mount_path)
            .map_err(|e| format!("Failed to create mount point: {}", e))?;
    }

    // Build the filesystem
    let mut inodes = inode::InodeTable::new();

    // Set root inode's IPNS data
    if let Some(root) = inodes.get_mut(inode::ROOT_INO) {
        root.kind = inode::InodeKind::Root {
            ipns_private_key: root_ipns_private_key,
            ipns_name: Some(root_ipns_name.clone()),
        };
    }

    let fs = CipherVaultFS {
        inodes,
        metadata_cache: cache::MetadataCache::new(),
        content_cache: cache::ContentCache::new(),
        api: state.api.clone(),
        private_key,
        root_folder_key,
        root_ipns_name,
        rt,
        next_fh: AtomicU64::new(1),
        open_files: HashMap::new(),
    };

    let mount_path_clone = mount_path.clone();

    // Mount options
    let options = vec![
        MountOption::FSName("CipherBox".to_string()),
        MountOption::AutoUnmount,
        MountOption::DefaultPermissions,
    ];

    // Spawn FUSE event loop on a dedicated OS thread (not tokio)
    let handle = std::thread::Builder::new()
        .name("fuse-mount".to_string())
        .spawn(move || {
            log::info!(
                "Mounting CipherVaultFS at {}",
                mount_path_clone.display()
            );
            match fuser::mount2(fs, &mount_path_clone, &options) {
                Ok(()) => log::info!("FUSE filesystem unmounted cleanly"),
                Err(e) => log::error!("FUSE mount error: {}", e),
            }
        })
        .map_err(|e| format!("Failed to spawn FUSE thread: {}", e))?;

    log::info!("FUSE mount initiated at {}", mount_path.display());
    Ok(handle)
}

/// Unmount the FUSE filesystem.
///
/// Calls the system `umount` command to cleanly unmount ~/CipherVault.
#[cfg(feature = "fuse")]
pub fn unmount_filesystem() -> Result<(), String> {
    let mount_path = mount_point();
    log::info!("Unmounting CipherVaultFS at {}", mount_path.display());

    let status = std::process::Command::new("umount")
        .arg(mount_path.to_str().unwrap())
        .status()
        .map_err(|e| format!("Failed to run umount: {}", e))?;

    if status.success() {
        log::info!("FUSE filesystem unmounted successfully");
        Ok(())
    } else {
        // Try diskutil unmount as fallback on macOS
        let status = std::process::Command::new("diskutil")
            .args(["unmount", mount_path.to_str().unwrap()])
            .status()
            .map_err(|e| format!("Failed to run diskutil unmount: {}", e))?;

        if status.success() {
            log::info!("FUSE filesystem unmounted via diskutil");
            Ok(())
        } else {
            Err("Failed to unmount filesystem".to_string())
        }
    }
}
