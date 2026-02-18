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
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "fuse")]
use std::time::Duration;

#[cfg(feature = "fuse")]
use fuser::MountOption;

#[cfg(feature = "fuse")]
use crate::api::client::ApiClient;
#[cfg(feature = "fuse")]
use crate::state::AppState;

/// Timeout for network I/O in FUSE callbacks to prevent blocking the NFS thread.
#[cfg(feature = "fuse")]
const NETWORK_TIMEOUT: Duration = Duration::from_secs(10);

/// Run an async future with a timeout on the tokio runtime.
/// Prevents FUSE-T NFS thread hangs from indefinite network I/O.
#[cfg(feature = "fuse")]
fn block_with_timeout<F, T>(rt: &tokio::runtime::Handle, fut: F) -> Result<T, String>
where
    F: std::future::Future<Output = Result<T, String>>,
{
    rt.block_on(async {
        match tokio::time::timeout(NETWORK_TIMEOUT, fut).await {
            Ok(result) => result,
            Err(_) => Err("Operation timed out".to_string()),
        }
    })
}

/// Pending folder refresh result sent from background tasks.
#[cfg(feature = "fuse")]
pub struct PendingRefresh {
    pub ino: u64,
    pub ipns_name: String,
    pub metadata: crate::crypto::folder::AnyFolderMetadata,
    pub cid: String,
}

/// Pending content prefetch result sent from background tasks.
#[cfg(feature = "fuse")]
pub struct PendingContent {
    pub cid: String,
    pub data: Vec<u8>,
}

/// Notification from a background upload thread that a file upload completed.
#[cfg(feature = "fuse")]
pub struct UploadComplete {
    pub ino: u64,
    pub new_cid: String,
}

/// Coordinates IPNS publish operations to prevent sequence number races
/// and maintain a monotonic sequence number cache per IPNS name.
///
/// Shared via `Arc` between `CipherBoxFS` and background publish threads.
#[cfg(feature = "fuse")]
pub struct PublishCoordinator {
    /// Per-IPNS-name sequence number cache (monotonically increasing).
    seq_cache: std::sync::Mutex<HashMap<String, u64>>,
    /// Per-IPNS-name publish locks to serialize concurrent publishes.
    publish_locks: std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

#[cfg(feature = "fuse")]
impl PublishCoordinator {
    pub fn new() -> Self {
        Self {
            seq_cache: std::sync::Mutex::new(HashMap::new()),
            publish_locks: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Get or create a per-folder publish lock.
    pub fn get_lock(&self, ipns_name: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.publish_locks.lock().unwrap();
        locks
            .entry(ipns_name.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Resolve current sequence number with monotonic cache fallback.
    ///
    /// - On successful resolve: returns max(resolved, cached)
    /// - On failed resolve with cached value: returns cached value with warning
    /// - On failed resolve with no cache: returns error (prevents seq rollback)
    pub async fn resolve_sequence(
        &self,
        api: &crate::api::client::ApiClient,
        ipns_name: &str,
    ) -> Result<u64, String> {
        match crate::api::ipns::resolve_ipns(api, ipns_name).await {
            Ok(resp) => {
                let resolved = match resp.sequence_number.parse::<u64>() {
                    Ok(v) => v,
                    Err(e) => {
                        log::warn!(
                            "Failed to parse IPNS sequence '{}' for {}: {}",
                            resp.sequence_number, ipns_name, e
                        );
                        0
                    }
                };
                let cached = self.get_cached(ipns_name).unwrap_or(0);
                let seq = std::cmp::max(resolved, cached);
                self.update_cache(ipns_name, seq);
                Ok(seq)
            }
            Err(e) => match self.get_cached(ipns_name) {
                Some(cached) => {
                    log::warn!(
                        "IPNS resolve failed for {}, using cached seq {}: {}",
                        ipns_name,
                        cached,
                        e
                    );
                    Ok(cached)
                }
                None => Err(format!(
                    "IPNS resolve failed and no cached sequence for {}: {}",
                    ipns_name, e
                )),
            },
        }
    }

    /// Record a successful publish — cache is monotonic (only increases).
    pub fn record_publish(&self, ipns_name: &str, published_seq: u64) {
        self.update_cache(ipns_name, published_seq);
    }

    fn get_cached(&self, ipns_name: &str) -> Option<u64> {
        self.seq_cache.lock().unwrap().get(ipns_name).copied()
    }

    fn update_cache(&self, ipns_name: &str, seq: u64) {
        let mut cache = self.seq_cache.lock().unwrap();
        let entry = cache.entry(ipns_name.to_string()).or_insert(0);
        if seq > *entry {
            *entry = seq;
        }
    }
}

/// Encrypt a FolderMetadata struct and package as JSON bytes ready for IPFS upload.
/// CPU-only, no network I/O.
#[cfg(feature = "fuse")]
fn encrypt_metadata_to_json(
    metadata: &crate::crypto::folder::FolderMetadata,
    folder_key: &[u8],
) -> Result<Vec<u8>, String> {
    let folder_key_arr: [u8; 32] = folder_key
        .try_into()
        .map_err(|_| "Invalid folder key length".to_string())?;
    let sealed = crate::crypto::folder::encrypt_folder_metadata(metadata, &folder_key_arr)
        .map_err(|e| format!("Metadata encryption failed: {}", e))?;
    let iv_hex = hex::encode(&sealed[..12]);
    use base64::Engine;
    let data_base64 = base64::engine::general_purpose::STANDARD.encode(&sealed[12..]);
    let json = serde_json::json!({ "iv": iv_hex, "data": data_base64 });
    serde_json::to_vec(&json).map_err(|e| format!("JSON serialization failed: {}", e))
}

/// Spawn a background OS thread to upload encrypted metadata and publish via IPNS.
/// Returns immediately — does NOT block the calling thread.
#[cfg(feature = "fuse")]
fn spawn_metadata_publish(
    api: Arc<ApiClient>,
    rt: tokio::runtime::Handle,
    metadata: crate::crypto::folder::FolderMetadata,
    folder_key: Vec<u8>,
    ipns_private_key: Vec<u8>,
    ipns_name: String,
    old_metadata_cid: Option<String>,
    coordinator: Arc<PublishCoordinator>,
) {
    std::thread::spawn(move || {
        let result = rt.block_on(async {
            // Acquire per-folder publish lock to serialize concurrent publishes
            let lock = coordinator.get_lock(&ipns_name);
            let _guard = lock.lock().await;

            // Encrypt metadata (CPU)
            let json_bytes = encrypt_metadata_to_json(&metadata, &folder_key)?;

            // Resolve current IPNS sequence number (monotonic cache fallback)
            let seq = coordinator.resolve_sequence(&api, &ipns_name).await?;

            // Upload encrypted metadata to IPFS
            let new_cid = crate::api::ipfs::upload_content(&api, &json_bytes).await?;

            // Create and sign IPNS record
            let ipns_key_arr: [u8; 32] = ipns_private_key
                .try_into()
                .map_err(|_| "Invalid IPNS private key length".to_string())?;
            let new_seq = seq + 1;
            let value = format!("/ipfs/{}", new_cid);
            let record = crate::crypto::ipns::create_ipns_record(
                &ipns_key_arr,
                &value,
                new_seq,
                86_400_000,
            )
            .map_err(|e| format!("IPNS record creation failed: {}", e))?;
            let marshaled = crate::crypto::ipns::marshal_ipns_record(&record)
                .map_err(|e| format!("IPNS record marshal failed: {}", e))?;

            use base64::Engine;
            let record_b64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);

            let req = crate::api::ipns::IpnsPublishRequest {
                ipns_name: ipns_name.clone(),
                record: record_b64,
                metadata_cid: new_cid.clone(),
                encrypted_ipns_private_key: None,
                key_epoch: None,
            };
            crate::api::ipns::publish_ipns(&api, &req).await?;

            // Record successful publish in coordinator cache
            coordinator.record_publish(&ipns_name, new_seq);

            // Unpin old metadata CID
            if let Some(old) = old_metadata_cid {
                let _ = crate::api::ipfs::unpin_content(&api, &old).await;
            }

            log::info!("Background metadata publish succeeded for {}", ipns_name);
            Ok::<(), String>(())
        });

        if let Err(e) = result {
            log::error!("Background metadata publish failed: {}", e);
        }
    });
}

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
    /// Wrapped in `Zeroizing` for automatic zeroization on drop.
    pub private_key: Zeroizing<Vec<u8>>,
    /// User's uncompressed secp256k1 public key (65 bytes, 0x04 prefix).
    /// Wrapped in `Zeroizing` for automatic zeroization on drop.
    pub public_key: Zeroizing<Vec<u8>>,
    /// Root folder AES-256 key (32 bytes).
    /// Wrapped in `Zeroizing` for automatic zeroization on drop.
    pub root_folder_key: Zeroizing<Vec<u8>>,
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
    /// Receiver for background refresh results.
    pub refresh_rx: std::sync::mpsc::Receiver<PendingRefresh>,
    /// Sender clone for spawning background refreshes.
    pub refresh_tx: std::sync::mpsc::Sender<PendingRefresh>,
    /// Folders with recent local mutations — skip background refreshes
    /// that would overwrite local state before IPNS publish propagates.
    /// Maps folder ino → mutation timestamp.
    pub mutated_folders: HashMap<u64, std::time::Instant>,
    /// CIDs currently being prefetched in background (to avoid duplicate fetches).
    pub prefetching: std::collections::HashSet<String>,
    /// Receiver for background content prefetch results.
    pub content_rx: std::sync::mpsc::Receiver<PendingContent>,
    /// Sender for background content prefetch tasks.
    pub content_tx: std::sync::mpsc::Sender<PendingContent>,
    /// Plaintext cache for files whose upload is still in flight (keyed by inode).
    pub pending_content: HashMap<u64, Vec<u8>>,
    /// Receiver for background upload completion notifications.
    pub upload_rx: std::sync::mpsc::Receiver<UploadComplete>,
    /// Sender for background upload threads to notify completion.
    pub upload_tx: std::sync::mpsc::Sender<UploadComplete>,
    /// Shared coordinator for IPNS publish sequencing and per-folder locking.
    pub publish_coordinator: Arc<PublishCoordinator>,
}

#[cfg(feature = "fuse")]
impl CipherBoxFS {
    /// Build a FolderMetadata struct from the current inode tree (CPU-only, no network I/O).
    /// Returns (metadata, folder_key, ipns_private_key, ipns_name, old_metadata_cid).
    pub fn build_folder_metadata(
        &self,
        folder_ino: u64,
    ) -> Result<
        (
            crate::crypto::folder::FolderMetadata,
            Vec<u8>,
            Vec<u8>,
            String,
            Option<String>,
        ),
        String,
    > {
        let (folder_key, ipns_private_key, ipns_name, child_inos) = {
            let inode = self
                .inodes
                .get(folder_ino)
                .ok_or_else(|| format!("Folder inode {} not found", folder_ino))?;

            let children = inode.children.clone().unwrap_or_default();

            match &inode.kind {
                inode::InodeKind::Root {
                    ipns_private_key,
                    ipns_name,
                } => {
                    let key = ipns_private_key
                        .as_ref()
                        .ok_or("Root folder IPNS private key not available")?
                        .to_vec();
                    let name = ipns_name
                        .as_ref()
                        .ok_or("Root folder IPNS name not available")?
                        .clone();
                    (self.root_folder_key.to_vec(), key, name, children)
                }
                inode::InodeKind::Folder {
                    folder_key,
                    ipns_private_key,
                    ipns_name,
                    ..
                } => {
                    let key = ipns_private_key
                        .as_ref()
                        .ok_or("Subfolder IPNS private key not available")?
                        .to_vec();
                    (folder_key.to_vec(), key, ipns_name.clone(), children)
                }
                _ => return Err("Cannot update metadata for non-folder inode".to_string()),
            }
        };

        let mut metadata_children = Vec::new();
        for &child_ino in &child_inos {
            let child = self
                .inodes
                .get(child_ino)
                .ok_or_else(|| format!("Child inode {} not found", child_ino))?;

            match &child.kind {
                inode::InodeKind::Folder {
                    ipns_name: child_ipns_name,
                    encrypted_folder_key,
                    ipns_private_key: child_ipns_key,
                    ..
                } => {
                    let ipns_key_encrypted = if let Some(key) = child_ipns_key {
                        let wrapped = crate::crypto::ecies::wrap_key(key, &self.public_key)
                            .map_err(|e| format!("Failed to wrap IPNS key: {}", e))?;
                        hex::encode(&wrapped)
                    } else {
                        String::new()
                    };

                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let created_ms = child
                        .attr
                        .crtime
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let modified_ms = child
                        .attr
                        .mtime
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;

                    metadata_children.push(crate::crypto::folder::FolderChild::Folder(
                        crate::crypto::folder::FolderEntry {
                            id: uuid_from_ino(child_ino),
                            name: child.name.clone(),
                            ipns_name: child_ipns_name.clone(),
                            folder_key_encrypted: encrypted_folder_key.clone(),
                            ipns_private_key_encrypted: ipns_key_encrypted,
                            created_at: if created_ms > 0 { created_ms } else { now_ms },
                            modified_at: if modified_ms > 0 { modified_ms } else { now_ms },
                        },
                    ));
                }
                inode::InodeKind::File {
                    cid,
                    encrypted_file_key,
                    iv,
                    size,
                    encryption_mode,
                    ..
                } => {
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let created_ms = child
                        .attr
                        .crtime
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let modified_ms = child
                        .attr
                        .mtime
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;

                    metadata_children.push(crate::crypto::folder::FolderChild::File(
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
                    ));
                }
                _ => {}
            }
        }

        let metadata = crate::crypto::folder::FolderMetadata {
            version: "v1".to_string(),
            children: metadata_children,
        };

        let old_cid = self.metadata_cache.get(&ipns_name).map(|c| c.cid.clone());

        Ok((metadata, folder_key, ipns_private_key, ipns_name, old_cid))
    }

    /// Non-blocking metadata update: build metadata (CPU), then spawn
    /// a background OS thread for encrypt + upload + IPNS publish.
    /// Returns immediately — does NOT block the FUSE NFS thread.
    pub fn update_folder_metadata(&mut self, folder_ino: u64) -> Result<(), String> {
        let (metadata, folder_key, ipns_private_key, ipns_name, old_cid) =
            self.build_folder_metadata(folder_ino)?;

        // Mark folder as locally mutated — prevents background refreshes
        // from overwriting local changes until IPNS publish propagates.
        self.mutated_folders.insert(folder_ino, std::time::Instant::now());

        spawn_metadata_publish(
            self.api.clone(),
            self.rt.clone(),
            metadata,
            folder_key,
            ipns_private_key,
            ipns_name,
            old_cid,
            self.publish_coordinator.clone(),
        );

        Ok(())
    }

    /// Drain completed upload notifications and update inode CIDs + caches.
    pub fn drain_upload_completions(&mut self) {
        while let Ok(result) = self.upload_rx.try_recv() {
            log::debug!(
                "Upload complete: ino {} -> CID {}",
                result.ino,
                result.new_cid
            );
            // Update inode CID from empty to real
            if let Some(inode) = self.inodes.get_mut(result.ino) {
                if let inode::InodeKind::File { ref mut cid, .. } = inode.kind {
                    if cid.is_empty() {
                        *cid = result.new_cid.clone();
                    }
                }
            }
            // Move plaintext from pending_content to content_cache
            if let Some(plaintext) = self.pending_content.remove(&result.ino) {
                self.content_cache.set(&result.new_cid, plaintext);
            }
        }
    }

    /// Drain background folder refresh results (non-blocking).
    /// Called from lookup() and readdir() to apply results from async folder fetches.
    /// Skips refreshes for folders with recent local mutations (prevents stale
    /// remote metadata from overwriting local changes before IPNS publish propagates).
    pub fn drain_refresh_completions(&mut self) {
        // Clean up expired mutation cooldowns (>30s old)
        let cutoff = std::time::Instant::now() - std::time::Duration::from_secs(30);
        self.mutated_folders.retain(|_, ts| *ts > cutoff);

        while let Ok(refresh) = self.refresh_rx.try_recv() {
            // Extract a v1 FolderMetadata for cache (or synthetic for v2)
            let cache_metadata = match &refresh.metadata {
                crate::crypto::folder::AnyFolderMetadata::V1(v1) => v1.clone(),
                crate::crypto::folder::AnyFolderMetadata::V2(_) => {
                    crate::crypto::folder::FolderMetadata {
                        version: "v2".to_string(),
                        children: vec![],
                    }
                }
            };

            // Skip stale refreshes for recently-mutated folders
            if self.mutated_folders.contains_key(&refresh.ino) {
                log::debug!(
                    "refresh skipped for ino {} (locally mutated, waiting for IPNS propagation)",
                    refresh.ino
                );
                // Still update cache so readdir doesn't re-fire refreshes
                self.metadata_cache.set(&refresh.ipns_name, cache_metadata, refresh.cid);
                continue;
            }

            self.metadata_cache.set(&refresh.ipns_name, cache_metadata, refresh.cid.clone());
            if let Err(e) = self.inodes.populate_folder_any(
                refresh.ino, &refresh.metadata, &self.private_key,
            ) {
                log::warn!("Drain refresh apply failed for ino {}: {}", refresh.ino, e);
            }

            // For v2 metadata, resolve FilePointers eagerly
            if matches!(&refresh.metadata, crate::crypto::folder::AnyFolderMetadata::V2(_)) {
                let unresolved = self.inodes.get_unresolved_file_pointers();
                eprintln!(">>> drain_refresh: v2 metadata, {} unresolved file pointers", unresolved.len());
                if !unresolved.is_empty() {
                    // Get folder key for FilePointer resolution
                    let folder_key = match self.inodes.get(refresh.ino) {
                        Some(inode) => match &inode.kind {
                            inode::InodeKind::Root { .. } => Some(self.root_folder_key.to_vec()),
                            inode::InodeKind::Folder { folder_key, .. } => Some(folder_key.to_vec()),
                            _ => None,
                        },
                        None => None,
                    };
                    if let Some(fk) = folder_key {
                        let api = self.api.clone();
                        let rt = self.rt.clone();
                        for (ino, ipns_name) in &unresolved {
                            let fk_arr: Result<[u8; 32], _> = fk.as_slice().try_into();
                            if let Ok(fk_arr) = fk_arr {
                                let resolve_result = block_with_timeout(&rt, async {
                                    let resp = crate::api::ipns::resolve_ipns(&api, ipns_name).await?;
                                    let bytes = crate::api::ipfs::fetch_content(&api, &resp.cid).await?;
                                    Ok::<Vec<u8>, String>(bytes)
                                });
                                match resolve_result {
                                    Ok(enc_bytes) => {
                                        match operations::decrypt_file_metadata_from_ipfs_public(&enc_bytes, &fk_arr) {
                                            Ok(fm) => {
                                                self.inodes.resolve_file_pointer(
                                                    *ino, fm.cid, fm.file_key_encrypted,
                                                    fm.file_iv, fm.size, fm.encryption_mode,
                                                );
                                            }
                                            Err(e) => log::warn!("Drain FilePointer decrypt failed for ino {}: {}", ino, e),
                                        }
                                    }
                                    Err(e) => log::warn!("Drain FilePointer resolve failed for ino {}: {}", ino, e),
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Drain background content prefetch results into the content cache (non-blocking).
    /// Called from read() and open() to apply results from async IPFS fetches.
    pub fn drain_content_prefetches(&mut self) {
        while let Ok(content) = self.content_rx.try_recv() {
            self.prefetching.remove(&content.cid);
            self.content_cache.set(&content.cid, content.data);
        }
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
pub async fn mount_filesystem(
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

    // Refuse to proceed if mount point is a symlink (TOCTOU defense)
    if mount_path.is_symlink() {
        return Err("Mount point is a symlink — refusing to proceed".to_string());
    }

    // Create mount directory if it doesn't exist
    if !mount_path.exists() {
        std::fs::create_dir_all(&mount_path)
            .map_err(|e| format!("Failed to create mount point: {}", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&mount_path, std::fs::Permissions::from_mode(0o700));
        }
    } else {
        // Clean stale files left after a crash (e.g. .DS_Store, .metadata_never_index).
        // FUSE mount will fail or behave unexpectedly if the directory isn't empty.
        if let Ok(entries) = std::fs::read_dir(&mount_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let _ = std::fs::remove_dir_all(&path);
                } else {
                    let _ = std::fs::remove_file(&path);
                }
            }
            log::info!("Cleaned stale mount point: {}", mount_path.display());
        }
    }

    // Prevent Spotlight from indexing the mount (creates .metadata_never_index)
    let never_index = mount_path.join(".metadata_never_index");
    if !never_index.exists() {
        let _ = std::fs::File::create(&never_index);
    }

    // Create temp directory for write buffering
    let temp_dir = std::env::temp_dir().join("cipherbox");
    std::fs::create_dir_all(&temp_dir)
        .map_err(|e| format!("Failed to create temp directory: {}", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&temp_dir, std::fs::Permissions::from_mode(0o700));
    }

    // Build the filesystem
    let mut inodes = inode::InodeTable::new();

    // Set root inode's IPNS data
    if let Some(root) = inodes.get_mut(inode::ROOT_INO) {
        root.kind = inode::InodeKind::Root {
            ipns_private_key: root_ipns_private_key.map(Zeroizing::new),
            ipns_name: Some(root_ipns_name.clone()),
        };
    }

    // Channels for background operations
    let (refresh_tx, refresh_rx) = std::sync::mpsc::channel::<PendingRefresh>();
    let (content_tx, content_rx) = std::sync::mpsc::channel::<PendingContent>();
    let (upload_tx, upload_rx) = std::sync::mpsc::channel::<UploadComplete>();

    // Pre-populate root folder BEFORE mounting so init()/readdir() have no network I/O.
    // This runs on the calling thread (tokio context available via rt handle).
    let mut metadata_cache = cache::MetadataCache::new();
    log::info!("Pre-populating root folder from IPNS...");
    let fetch_result: Result<(Vec<u8>, String), String> = async {
        let resolve_resp =
            crate::api::ipns::resolve_ipns(&state.api, &root_ipns_name).await?;
        let encrypted_bytes =
            crate::api::ipfs::fetch_content(&state.api, &resolve_resp.cid).await?;
        Ok((encrypted_bytes, resolve_resp.cid))
    }.await;
    match fetch_result {
        Ok((encrypted_bytes, cid)) => {
            match operations::decrypt_metadata_from_ipfs_public(&encrypted_bytes, &root_folder_key) {
                Ok(any_metadata) => {
                    // Cache metadata for readdir staleness checks
                    let cache_meta = match &any_metadata {
                        crate::crypto::folder::AnyFolderMetadata::V1(v1) => v1.clone(),
                        crate::crypto::folder::AnyFolderMetadata::V2(_) => {
                            crate::crypto::folder::FolderMetadata {
                                version: "v2".to_string(),
                                children: vec![],
                            }
                        }
                    };
                    metadata_cache.set(&root_ipns_name, cache_meta, cid);

                    // Populate inode table (dispatches v1/v2)
                    match inodes.populate_folder_any(inode::ROOT_INO, &any_metadata, &private_key) {
                        Ok(()) => {
                            log::info!("Root folder pre-populated successfully");

                            // For v2 metadata, resolve FilePointers eagerly before mount
                            let unresolved = inodes.get_unresolved_file_pointers();
                            if !unresolved.is_empty() {
                                log::info!("Resolving {} root FilePointer(s)...", unresolved.len());
                                let root_folder_key_arr: Result<[u8; 32], _> = root_folder_key.as_slice().try_into();
                                if let Ok(fk) = root_folder_key_arr {
                                    for (fp_ino, fp_ipns) in &unresolved {
                                        let fp_result: Result<Vec<u8>, String> = async {
                                            let resp = crate::api::ipns::resolve_ipns(&state.api, fp_ipns).await?;
                                            let bytes = crate::api::ipfs::fetch_content(&state.api, &resp.cid).await?;
                                            Ok(bytes)
                                        }.await;
                                        match fp_result {
                                            Ok(enc_bytes) => {
                                                match operations::decrypt_file_metadata_from_ipfs_public(&enc_bytes, &fk) {
                                                    Ok(fm) => {
                                                        inodes.resolve_file_pointer(
                                                            *fp_ino, fm.cid, fm.file_key_encrypted,
                                                            fm.file_iv, fm.size, fm.encryption_mode,
                                                        );
                                                    }
                                                    Err(e) => log::warn!("Root FilePointer decrypt failed for ino {}: {}", fp_ino, e),
                                                }
                                            }
                                            Err(e) => log::warn!("Root FilePointer resolve failed for ino {}: {}", fp_ino, e),
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => log::warn!("Root folder populate failed: {}", e),
                    }

                    // Pre-populate immediate subfolders so Finder's first READDIR
                    // returns correct data. NFS clients cache READDIR aggressively
                    // and won't re-fetch even when mtime changes, so returning empty
                    // on first access causes permanently stale Finder listings.
                    let subfolder_infos: Vec<(u64, String, Zeroizing<Vec<u8>>)> = inodes
                        .inodes
                        .values()
                        .filter_map(|inode| {
                            if inode.parent_ino != inode::ROOT_INO { return None; }
                            if let inode::InodeKind::Folder { ref ipns_name, ref folder_key, .. } = inode.kind {
                                Some((inode.ino, ipns_name.clone(), folder_key.clone()))
                            } else {
                                None
                            }
                        })
                        .collect();

                    for (sub_ino, sub_ipns, sub_key) in &subfolder_infos {
                        log::info!("Pre-populating subfolder ino={} ipns={}", sub_ino, sub_ipns);
                        let sub_result: Result<(Vec<u8>, String), String> = async {
                            let resp = crate::api::ipns::resolve_ipns(&state.api, sub_ipns).await?;
                            let bytes = crate::api::ipfs::fetch_content(&state.api, &resp.cid).await?;
                            Ok((bytes, resp.cid))
                        }.await;
                        match sub_result {
                            Ok((enc_bytes, sub_cid)) => {
                                match operations::decrypt_metadata_from_ipfs_public(&enc_bytes, sub_key) {
                                    Ok(sub_any_meta) => {
                                        let sub_cache_meta = match &sub_any_meta {
                                            crate::crypto::folder::AnyFolderMetadata::V1(v1) => v1.clone(),
                                            crate::crypto::folder::AnyFolderMetadata::V2(_) => {
                                                crate::crypto::folder::FolderMetadata {
                                                    version: "v2".to_string(),
                                                    children: vec![],
                                                }
                                            }
                                        };
                                        metadata_cache.set(sub_ipns, sub_cache_meta, sub_cid);
                                        match inodes.populate_folder_any(*sub_ino, &sub_any_meta, &private_key) {
                                            Ok(()) => {
                                                log::info!("Subfolder ino={} pre-populated", sub_ino);
                                                // Resolve FilePointers in subfolder
                                                let sub_unresolved = inodes.get_unresolved_file_pointers();
                                                if !sub_unresolved.is_empty() {
                                                    let sk_arr: Result<[u8; 32], _> = sub_key.as_slice().try_into();
                                                    if let Ok(sk) = sk_arr {
                                                        for (fp_ino, fp_ipns) in &sub_unresolved {
                                                            let fp_result: Result<Vec<u8>, String> = async {
                                                                let resp = crate::api::ipns::resolve_ipns(&state.api, fp_ipns).await?;
                                                                let bytes = crate::api::ipfs::fetch_content(&state.api, &resp.cid).await?;
                                                                Ok(bytes)
                                                            }.await;
                                                            match fp_result {
                                                                Ok(enc_bytes) => {
                                                                    match operations::decrypt_file_metadata_from_ipfs_public(&enc_bytes, &sk) {
                                                                        Ok(fm) => {
                                                                            inodes.resolve_file_pointer(
                                                                                *fp_ino, fm.cid, fm.file_key_encrypted,
                                                                                fm.file_iv, fm.size, fm.encryption_mode,
                                                                            );
                                                                        }
                                                                        Err(e) => log::warn!("Sub FilePointer decrypt failed: {}", e),
                                                                    }
                                                                }
                                                                Err(e) => log::warn!("Sub FilePointer resolve failed: {}", e),
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            Err(e) => log::warn!("Subfolder ino={} populate failed: {}", sub_ino, e),
                                        }
                                    }
                                    Err(e) => log::warn!("Subfolder ino={} decrypt failed: {}", sub_ino, e),
                                }
                            }
                            Err(e) => log::warn!("Subfolder ino={} fetch failed: {}", sub_ino, e),
                        }
                    }
                }
                Err(e) => log::warn!("Root metadata decryption failed: {}", e),
            }
        }
        Err(e) => log::warn!("Root folder fetch failed (mount will show empty): {}", e),
    }

    let fs = CipherBoxFS {
        inodes,
        metadata_cache,
        content_cache: cache::ContentCache::new(),
        api: state.api.clone(),
        private_key: Zeroizing::new(private_key),
        public_key: Zeroizing::new(public_key),
        root_folder_key: Zeroizing::new(root_folder_key),
        root_ipns_name,
        rt,
        next_fh: AtomicU64::new(1),
        open_files: HashMap::new(),
        temp_dir,
        tee_public_key,
        tee_key_epoch,
        refresh_rx,
        refresh_tx,
        prefetching: std::collections::HashSet::new(),
        content_rx,
        content_tx,
        pending_content: HashMap::new(),
        upload_rx,
        upload_tx,
        mutated_folders: HashMap::new(),
        publish_coordinator: Arc::new(PublishCoordinator::new()),
    };

    let mount_path_clone = mount_path.clone();

    // Mount options
    // Note: AutoUnmount and DefaultPermissions removed for FUSE-T compatibility.
    // FUSE-T is NFS-based and does not support kernel-level permission checks
    // or fusermount3-based auto-unmount.
    let options = vec![
        MountOption::FSName("CipherBox".to_string()),
        MountOption::CUSTOM("volname=CipherBox".to_string()),
        MountOption::CUSTOM("noappledouble".to_string()),
        MountOption::CUSTOM("noapplexattr".to_string()),
        MountOption::RW,
    ];

    // Spawn FUSE event loop on a dedicated OS thread (not tokio).
    // Use a channel so the thread can signal back if mount2 fails immediately
    // (e.g. macFUSE kext not loaded). If mount2 succeeds, it blocks until
    // unmount and never sends on the channel, so we use a recv_timeout.
    let (tx, rx) = std::sync::mpsc::sync_channel::<Result<(), String>>(1);

    let handle = std::thread::Builder::new()
        .name("fuse-mount".to_string())
        .spawn(move || {
            log::info!(
                "Mounting CipherBoxFS at {}",
                mount_path_clone.display()
            );
            match fuser::mount2(fs, &mount_path_clone, &options) {
                Ok(()) => {
                    log::info!("FUSE filesystem unmounted cleanly");
                    let _ = tx.send(Ok(()));
                }
                Err(e) => {
                    log::error!("FUSE mount error: {}", e);
                    let _ = tx.send(Err(format!("FUSE mount error: {}", e)));
                }
            }
        })
        .map_err(|e| format!("Failed to spawn FUSE thread: {}", e))?;

    // Wait up to 2 seconds for the mount to either fail or stabilize.
    // If mount2 fails (e.g. missing kext), the error arrives quickly.
    // If mount2 succeeds, it blocks (running the event loop) and we get a timeout.
    match rx.recv_timeout(std::time::Duration::from_secs(2)) {
        Ok(Ok(())) => {
            // Filesystem was unmounted immediately (unusual)
            Err("FUSE filesystem unmounted immediately after mounting".to_string())
        }
        Ok(Err(e)) => {
            // Mount failed — propagate the error
            Err(e)
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            // No response after 2s — mount is running
            log::info!("FUSE mount confirmed at {}", mount_path.display());
            Ok(handle)
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err("FUSE mount thread exited unexpectedly".to_string())
        }
    }
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
        // Try diskutil unmount force as fallback on macOS — Finder keeps handles open
        log::info!("umount failed (likely busy), trying diskutil unmount force");
        let status = std::process::Command::new("diskutil")
            .args(["unmount", "force", mount_path.to_str().unwrap()])
            .status()
            .map_err(|e| format!("Failed to run diskutil unmount force: {}", e))?;

        if status.success() {
            log::info!("FUSE filesystem force-unmounted via diskutil");
            Ok(())
        } else {
            Err(format!(
                "Failed to unmount {} — close Finder windows and retry",
                mount_path.display()
            ))
        }
    }
}
