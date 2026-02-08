//! FUSE filesystem module for CipherBox Desktop.
//!
//! Mounts the encrypted vault at ~/CipherBox as a native macOS filesystem
//! using FUSE-T. All crypto operations happen in Rust via the crypto module.
//!
//! The cache and inode modules are always available (they don't depend on libfuse).
//! The operations module and mount/unmount functions require the `fuse` feature.

pub mod cache;
pub mod file_handle;
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

/// The main FUSE filesystem struct.
///
/// Implements `fuser::Filesystem` to serve decrypted folder listings
/// and file content from the CipherBox vault.
#[cfg(feature = "fuse")]
pub struct CipherBoxFS {
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
    /// User's uncompressed secp256k1 public key (65 bytes, 0x04 prefix).
    pub public_key: Vec<u8>,
    /// Root folder AES-256 key (32 bytes).
    pub root_folder_key: Vec<u8>,
    /// Root IPNS name (k51... format).
    pub root_ipns_name: String,
    /// Tokio runtime handle for spawning async tasks from FUSE threads.
    pub rt: tokio::runtime::Handle,
    /// Next file handle counter.
    pub next_fh: AtomicU64,
    /// Map of open file handles (file_handle::OpenFileHandle for write buffering).
    pub open_files: HashMap<u64, file_handle::OpenFileHandle>,
    /// Temp directory for write-buffered files.
    pub temp_dir: PathBuf,
    /// TEE public key hex for encrypting IPNS private keys on new folder creation.
    pub tee_public_key: Option<Vec<u8>>,
    /// TEE key epoch for encrypting IPNS private keys on new folder creation.
    pub tee_key_epoch: Option<u32>,
}

#[cfg(feature = "fuse")]
impl CipherBoxFS {
    /// Rebuild, encrypt, and publish a folder's metadata after a mutation.
    ///
    /// This is called after any file/folder mutation (create, delete, rename).
    /// Steps:
    /// 1. Rebuild FolderMetadata from inode table children.
    /// 2. Encrypt with the folder key using `encrypt_folder_metadata`.
    /// 3. Upload encrypted metadata to IPFS (as JSON `{ iv, data }`) to get new CID.
    /// 4. Get Ed25519 IPNS private key from the parent inode.
    /// 5. Create IPNS record using `crypto::ipns::create_ipns_record`.
    /// 6. Marshal and base64-encode for the API.
    /// 7. Publish via `api::ipns::publish_ipns`.
    /// 8. Update metadata cache.
    /// 9. Fire-and-forget unpin of old CID.
    pub fn update_folder_metadata(&mut self, folder_ino: u64) -> Result<(), String> {
        // 1. Get folder data: key, IPNS private key, IPNS name, children
        let (folder_key, ipns_private_key, ipns_name, child_inos) = {
            let inode = self.inodes.get(folder_ino)
                .ok_or_else(|| format!("Folder inode {} not found", folder_ino))?;

            let children = inode.children.clone().unwrap_or_default();

            match &inode.kind {
                inode::InodeKind::Root { ipns_private_key, ipns_name } => {
                    let key = ipns_private_key.as_ref()
                        .ok_or("Root folder IPNS private key not available")?
                        .clone();
                    let name = ipns_name.as_ref()
                        .ok_or("Root folder IPNS name not available")?
                        .clone();
                    (self.root_folder_key.clone(), key, name, children)
                }
                inode::InodeKind::Folder { folder_key, ipns_private_key, ipns_name, .. } => {
                    let key = ipns_private_key.as_ref()
                        .ok_or("Subfolder IPNS private key not available")?
                        .clone();
                    (folder_key.clone(), key, ipns_name.clone(), children)
                }
                _ => return Err("Cannot update metadata for non-folder inode".to_string()),
            }
        };

        // 2. Rebuild FolderMetadata from children
        let mut metadata_children = Vec::new();
        for &child_ino in &child_inos {
            let child = self.inodes.get(child_ino)
                .ok_or_else(|| format!("Child inode {} not found", child_ino))?;

            match &child.kind {
                inode::InodeKind::Folder {
                    ipns_name: child_ipns_name,
                    encrypted_folder_key,
                    ipns_private_key: child_ipns_key,
                    ..
                } => {
                    // Re-encrypt IPNS private key with user's public key for storage
                    let ipns_key_encrypted = if let Some(key) = child_ipns_key {
                        let wrapped = crate::crypto::ecies::wrap_key(key, &self.public_key)
                            .map_err(|e| format!("Failed to wrap IPNS key: {}", e))?;
                        hex::encode(&wrapped)
                    } else {
                        // Use a placeholder -- should not happen for properly initialized folders
                        String::new()
                    };

                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let created_ms = child.attr.crtime
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let modified_ms = child.attr.mtime
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;

                    metadata_children.push(
                        crate::crypto::folder::FolderChild::Folder(
                            crate::crypto::folder::FolderEntry {
                                id: uuid_from_ino(child_ino),
                                name: child.name.clone(),
                                ipns_name: child_ipns_name.clone(),
                                folder_key_encrypted: encrypted_folder_key.clone(),
                                ipns_private_key_encrypted: ipns_key_encrypted,
                                created_at: if created_ms > 0 { created_ms } else { now_ms },
                                modified_at: if modified_ms > 0 { modified_ms } else { now_ms },
                            },
                        ),
                    );
                }
                inode::InodeKind::File { cid, encrypted_file_key, iv, size, encryption_mode } => {
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let created_ms = child.attr.crtime
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let modified_ms = child.attr.mtime
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;

                    metadata_children.push(
                        crate::crypto::folder::FolderChild::File(
                            crate::crypto::folder::FileEntry {
                                id: uuid_from_ino(child_ino),
                                name: child.name.clone(),
                                cid: cid.clone(),
                                file_key_encrypted: encrypted_file_key.clone(),
                                file_iv: iv.clone(),
                                size: *size,
                                created_at: if created_ms > 0 { created_ms } else { now_ms },
                                modified_at: if modified_ms > 0 { modified_ms } else { now_ms },
                                encryption_mode: encryption_mode.clone(),
                            },
                        ),
                    );
                }
                _ => {} // Ignore root (shouldn't be a child)
            }
        }

        let metadata = crate::crypto::folder::FolderMetadata {
            version: "v1".to_string(),
            children: metadata_children,
        };

        // 3. Encrypt folder metadata
        let folder_key_arr: [u8; 32] = folder_key.clone().try_into()
            .map_err(|_| "Invalid folder key length".to_string())?;
        let sealed = crate::crypto::folder::encrypt_folder_metadata(&metadata, &folder_key_arr)
            .map_err(|e| format!("Metadata encryption failed: {}", e))?;

        // Format as JSON `{ "iv": "<hex>", "data": "<base64>" }` matching TypeScript format
        let iv_hex = hex::encode(&sealed[..12]);
        use base64::Engine;
        let data_base64 = base64::engine::general_purpose::STANDARD.encode(&sealed[12..]);
        let json_metadata = serde_json::json!({
            "iv": iv_hex,
            "data": data_base64,
        });
        let json_bytes = serde_json::to_vec(&json_metadata)
            .map_err(|e| format!("JSON serialization failed: {}", e))?;

        // 4-7. Upload to IPFS and publish IPNS (async via runtime)
        let api = self.api.clone();
        let ipns_name_clone = ipns_name.clone();
        let rt = self.rt.clone();

        // Get current sequence number from cache (or start at 0)
        let old_cid = self.metadata_cache.get(&ipns_name)
            .map(|cached| cached.cid.clone());
        let current_seq: u64 = self.metadata_cache.get(&ipns_name)
            .and_then(|cached| {
                // We don't store seq in cache, so resolve to get it
                None::<u64>
            })
            .unwrap_or(0);

        let result: Result<(String, u64), String> = rt.block_on(async {
            // Resolve current sequence number from IPNS
            let seq = match crate::api::ipns::resolve_ipns(&api, &ipns_name_clone).await {
                Ok(resp) => resp.sequence_number.parse::<u64>().unwrap_or(0),
                Err(_) => 0,
            };

            // Upload encrypted metadata to IPFS
            let new_cid = crate::api::ipfs::upload_content(&api, &json_bytes).await?;

            Ok((new_cid, seq))
        });

        let (new_cid, seq) = result?;

        // Create and sign IPNS record
        let ipns_key_arr: [u8; 32] = ipns_private_key.clone().try_into()
            .map_err(|_| "Invalid IPNS private key length".to_string())?;
        let new_seq = seq + 1;
        let value = format!("/ipfs/{}", new_cid);

        let record = crate::crypto::ipns::create_ipns_record(
            &ipns_key_arr,
            &value,
            new_seq,
            86_400_000, // 24h lifetime for client publishes
        ).map_err(|e| format!("IPNS record creation failed: {}", e))?;

        let marshaled = crate::crypto::ipns::marshal_ipns_record(&record)
            .map_err(|e| format!("IPNS record marshaling failed: {}", e))?;

        let record_base64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);

        // Publish IPNS record
        let publish_request = crate::api::ipns::IpnsPublishRequest {
            ipns_name: ipns_name.clone(),
            record: record_base64,
            metadata_cid: new_cid.clone(),
            encrypted_ipns_private_key: None, // Only on first publish
            key_epoch: None,
        };

        let api = self.api.clone();
        let rt = self.rt.clone();
        rt.block_on(async {
            crate::api::ipns::publish_ipns(&api, &publish_request).await
        })?;

        // 8. Update metadata cache
        self.metadata_cache.set(&ipns_name, metadata, new_cid.clone());

        // 9. Fire-and-forget unpin of old CID
        if let Some(old_cid) = old_cid {
            let api = self.api.clone();
            self.rt.spawn(async move {
                if let Err(e) = crate::api::ipfs::unpin_content(&api, &old_cid).await {
                    log::debug!("Background unpin failed for {}: {}", old_cid, e);
                }
            });
        }

        Ok(())
    }
}

/// Generate a UUID-like string from an inode number (deterministic).
/// Used for folder/file IDs in metadata when we don't have the original UUID.
#[cfg(feature = "fuse")]
fn uuid_from_ino(ino: u64) -> String {
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (ino >> 32) as u32,
        ((ino >> 16) & 0xFFFF) as u16,
        (ino & 0xFFF) as u16,
        (0x8000 | (ino & 0x3FFF)) as u16,
        ino & 0xFFFFFFFFFFFF,
    )
}

/// Get the mount point path: ~/CipherBox
#[cfg(feature = "fuse")]
pub fn mount_point() -> PathBuf {
    dirs::home_dir()
        .expect("Could not determine home directory")
        .join("CipherBox")
}

/// Mount the FUSE filesystem after successful authentication.
///
/// Creates the ~/CipherBox directory if it doesn't exist, builds the
/// CipherBoxFS with keys from AppState, and spawns the FUSE event loop
/// on a dedicated std::thread (not tokio -- fuser runs its own event loop).
///
/// Returns a JoinHandle for the mount thread.
#[cfg(feature = "fuse")]
pub fn mount_filesystem(
    state: &AppState,
    rt: tokio::runtime::Handle,
    private_key: Vec<u8>,
    public_key: Vec<u8>,
    root_folder_key: Vec<u8>,
    root_ipns_name: String,
    root_ipns_private_key: Option<Vec<u8>>,
    tee_public_key: Option<Vec<u8>>,
    tee_key_epoch: Option<u32>,
) -> Result<std::thread::JoinHandle<()>, String> {
    let mount_path = mount_point();

    // Create mount directory if it doesn't exist
    if !mount_path.exists() {
        std::fs::create_dir_all(&mount_path)
            .map_err(|e| format!("Failed to create mount point: {}", e))?;
    }

    // Create temp directory for write buffering
    let temp_dir = std::env::temp_dir().join("cipherbox");
    std::fs::create_dir_all(&temp_dir)
        .map_err(|e| format!("Failed to create temp directory: {}", e))?;

    // Build the filesystem
    let mut inodes = inode::InodeTable::new();

    // Set root inode's IPNS data
    if let Some(root) = inodes.get_mut(inode::ROOT_INO) {
        root.kind = inode::InodeKind::Root {
            ipns_private_key: root_ipns_private_key,
            ipns_name: Some(root_ipns_name.clone()),
        };
    }

    let fs = CipherBoxFS {
        inodes,
        metadata_cache: cache::MetadataCache::new(),
        content_cache: cache::ContentCache::new(),
        api: state.api.clone(),
        private_key,
        public_key,
        root_folder_key,
        root_ipns_name,
        rt,
        next_fh: AtomicU64::new(1),
        open_files: HashMap::new(),
        temp_dir,
        tee_public_key,
        tee_key_epoch,
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
                "Mounting CipherBoxFS at {}",
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
/// Calls the system `umount` command to cleanly unmount ~/CipherBox.
#[cfg(feature = "fuse")]
pub fn unmount_filesystem() -> Result<(), String> {
    let mount_path = mount_point();
    log::info!("Unmounting CipherBoxFS at {}", mount_path.display());

    // Clean up temp directory
    let temp_dir = std::env::temp_dir().join("cipherbox");
    if temp_dir.exists() {
        if let Err(e) = std::fs::remove_dir_all(&temp_dir) {
            log::warn!("Failed to clean temp directory: {}", e);
        }
    }

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
