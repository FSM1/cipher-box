//! CipherBox FUSE filesystem implementation.
//!
//! Platform-agnostic data structures (InodeTable, MetadataCache, ContentCache,
//! FileHandle) are shared across all platforms. Platform-specific mount/unmount
//! and FUSE callback implementations are behind feature flags.

pub mod inode;
pub mod cache;
pub mod file_handle;
pub mod helpers;
pub mod constants;
pub mod error;

// FUSE operations (macOS/Linux - fuser-based)
#[cfg(feature = "fuse")]
pub mod operations;
#[cfg(feature = "fuse")]
pub mod read_ops;
#[cfg(feature = "fuse")]
pub mod write_ops;
#[cfg(feature = "fuse")]
pub mod dir_ops;

// Platform-specific modules
pub mod platform;

// Re-exports
pub use inode::{InodeTable, InodeData};
pub use cache::{MetadataCache, ContentCache};
pub use file_handle::OpenFileHandle;
pub use error::FuseError;

// -- CipherBoxFS and supporting types (require filesystem feature) -----------

#[cfg(any(feature = "fuse", feature = "winfsp"))]
use std::collections::HashMap;
#[cfg(any(feature = "fuse", feature = "winfsp"))]
use std::path::PathBuf;
#[cfg(any(feature = "fuse", feature = "winfsp"))]
use std::sync::atomic::AtomicU64;
#[cfg(any(feature = "fuse", feature = "winfsp"))]
use std::sync::Arc;
#[cfg(any(feature = "fuse", feature = "winfsp"))]
use zeroize::Zeroizing;

#[cfg(any(feature = "fuse", feature = "winfsp"))]
use std::time::Duration;

#[cfg(any(feature = "fuse", feature = "winfsp"))]
use cipherbox_api_client::ApiClient;

/// Timeout for network I/O in filesystem callbacks to prevent blocking the mount thread.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
const NETWORK_TIMEOUT: Duration = Duration::from_secs(10);

/// Run an async future with a timeout on the tokio runtime.
/// Prevents filesystem thread hangs from indefinite network I/O.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn block_with_timeout<F, T>(rt: &tokio::runtime::Handle, fut: F) -> Result<T, String>
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
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub struct PendingRefresh {
    pub ino: u64,
    pub ipns_name: String,
    pub metadata: cipherbox_core::folder::FolderMetadata,
    pub cid: String,
}

/// Pending content prefetch result sent from background tasks.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub enum PendingContent {
    Success { cid: String, data: Vec<u8> },
    Failure { cid: String },
}

/// Pending FilePointer resolution result sent from background async tasks.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub enum PendingFilePointer {
    Success {
        ino: u64,
        cid: String,
        encrypted_file_key: String,
        iv: String,
        size: u64,
        encryption_mode: String,
        versions: Option<Vec<cipherbox_core::folder::VersionEntry>>,
    },
    Failure {
        ino: u64,
    },
}

/// Notification from a background upload thread that a file upload completed.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub struct UploadComplete {
    pub ino: u64,
    pub new_cid: String,
    pub parent_ino: u64,
    pub old_file_cid: Option<String>,
    /// CIDs of pruned versions (exceeded MAX_VERSIONS_PER_FILE) to unpin.
    pub pruned_cids: Vec<String>,
    /// Write generation at the time this upload was started.
    pub write_generation: u64,
}

/// Entry in the debounced publish queue.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub struct PublishQueueEntry {
    pub first_dirty: std::time::Instant,
    pub pending_uploads: usize,
}

pub fn next_file_publish_sequence(
    is_first_publish: bool,
    current_sequence: Option<u64>,
) -> Result<u64, String> {
    if is_first_publish {
        return Ok(0);
    }

    current_sequence
        .map(|seq| seq + 1)
        .ok_or_else(|| "Missing current sequence for existing file IPNS record".to_string())
}

/// Coordinates IPNS publish operations to prevent sequence number races.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub struct PublishCoordinator {
    seq_cache: std::sync::Mutex<HashMap<String, u64>>,
    publish_locks: std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

#[cfg(any(feature = "fuse", feature = "winfsp"))]
impl PublishCoordinator {
    pub fn new() -> Self {
        Self {
            seq_cache: std::sync::Mutex::new(HashMap::new()),
            publish_locks: std::sync::Mutex::new(HashMap::new()),
        }
    }

    pub fn get_lock(&self, ipns_name: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.publish_locks.lock().unwrap();
        locks
            .entry(ipns_name.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    pub async fn resolve_sequence(
        &self,
        api: &cipherbox_api_client::ApiClient,
        ipns_name: &str,
    ) -> Result<u64, String> {
        match cipherbox_api_client::ipns::resolve_ipns(api, ipns_name).await {
            Ok(resp) => {
                let resolved = resp.sequence_number.parse::<u64>().unwrap_or_else(|e| {
                    log::warn!("Failed to parse IPNS sequence '{}' for {}: {}", resp.sequence_number, ipns_name, e);
                    0
                });
                let cached = self.get_cached(ipns_name).unwrap_or(0);
                let seq = std::cmp::max(resolved, cached);
                self.update_cache(ipns_name, seq);
                Ok(seq)
            }
            Err(e) => match self.get_cached(ipns_name) {
                Some(cached) => {
                    log::warn!("IPNS resolve failed for {}, using cached seq {}: {}", ipns_name, cached, e);
                    Ok(cached)
                }
                None => Err(format!("IPNS resolve failed and no cached sequence for {}: {}", ipns_name, e)),
            },
        }
    }

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
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn encrypt_metadata_to_json(
    metadata: &cipherbox_core::folder::FolderMetadata,
    folder_key: &[u8],
) -> Result<Vec<u8>, String> {
    let folder_key_arr: [u8; 32] = folder_key
        .try_into()
        .map_err(|_| "Invalid folder key length".to_string())?;
    let sealed = cipherbox_core::folder::encrypt_folder_metadata(metadata, &folder_key_arr)
        .map_err(|e| format!("Metadata encryption failed: {}", e))?;
    let iv_hex = hex::encode(&sealed[..12]);
    use base64::Engine;
    let data_base64 = base64::engine::general_purpose::STANDARD.encode(&sealed[12..]);
    let json = serde_json::json!({ "iv": iv_hex, "data": data_base64 });
    serde_json::to_vec(&json).map_err(|e| format!("JSON serialization failed: {}", e))
}

/// Merge local children onto remote children to resolve a concurrent-edit conflict.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn merge_folder_children(
    local: &cipherbox_core::folder::FolderMetadata,
    remote: cipherbox_core::folder::FolderMetadata,
) -> cipherbox_core::folder::FolderMetadata {
    use cipherbox_core::folder::FolderChild;

    fn child_ipns_key(child: &FolderChild) -> &str {
        match child {
            FolderChild::Folder(f) => f.ipns_name.as_str(),
            FolderChild::File(f) => f.file_meta_ipns_name.as_str(),
        }
    }

    let local_by_ipns: std::collections::HashMap<String, &FolderChild> = local
        .children.iter().map(|c| (child_ipns_key(c).to_string(), c)).collect();

    let mut merged: Vec<FolderChild> = Vec::new();
    let mut seen_ipns: std::collections::HashSet<String> = std::collections::HashSet::new();

    for remote_child in &remote.children {
        let ipns = child_ipns_key(remote_child).to_string();
        if let Some(local_child) = local_by_ipns.get(&ipns) {
            merged.push((*local_child).clone());
        } else {
            merged.push(remote_child.clone());
        }
        seen_ipns.insert(ipns);
    }

    for local_child in &local.children {
        let ipns = child_ipns_key(local_child).to_string();
        if !seen_ipns.contains(&ipns) {
            merged.push(local_child.clone());
        }
    }

    cipherbox_core::folder::FolderMetadata { version: "v2".to_string(), children: merged }
}

/// Spawn a background OS thread to upload encrypted metadata and publish via IPNS.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn spawn_metadata_publish(
    api: Arc<ApiClient>,
    rt: tokio::runtime::Handle,
    metadata: cipherbox_core::folder::FolderMetadata,
    folder_key: Vec<u8>,
    ipns_private_key: Vec<u8>,
    ipns_name: String,
    old_metadata_cid: Option<String>,
    coordinator: Arc<PublishCoordinator>,
) {
    std::thread::spawn(move || {
        let result = rt.block_on(async {
            let lock = coordinator.get_lock(&ipns_name);
            let _guard = lock.lock().await;

            let json_bytes = encrypt_metadata_to_json(&metadata, &folder_key)?;
            let seq = coordinator.resolve_sequence(&api, &ipns_name).await?;
            let new_cid = cipherbox_api_client::ipfs::upload_content(&api, &json_bytes)
                .await.map_err(|e| format!("{}", e))?;

            let ipns_key_arr: [u8; 32] = ipns_private_key.try_into()
                .map_err(|_| "Invalid IPNS private key length".to_string())?;
            let new_seq = seq + 1;
            let value = format!("/ipfs/{}", new_cid);
            let record = cipherbox_core::create_ipns_record(&ipns_key_arr, &value, new_seq, 86_400_000)
                .map_err(|e| format!("IPNS record creation failed: {}", e))?;
            let marshaled = cipherbox_core::marshal_ipns_record(&record)
                .map_err(|e| format!("IPNS record marshal failed: {}", e))?;

            use base64::Engine;
            let record_b64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);

            let req = cipherbox_api_client::IpnsPublishRequest {
                ipns_name: ipns_name.clone(),
                record: record_b64,
                metadata_cid: new_cid.clone(),
                encrypted_ipns_private_key: None,
                key_epoch: None,
                expected_sequence_number: Some(seq.to_string()),
            };

            match cipherbox_api_client::ipns::publish_ipns(&api, &req).await.map_err(|e| format!("{}", e))? {
                cipherbox_api_client::PublishResult::Success => {
                    coordinator.record_publish(&ipns_name, new_seq);
                    if let Some(old) = old_metadata_cid {
                        let _ = cipherbox_api_client::ipfs::unpin_content(&api, &old).await;
                    }
                    log::info!("Background metadata publish succeeded for {}", ipns_name);
                }
                cipherbox_api_client::PublishResult::Conflict { current_sequence_number } => {
                    log::warn!("Conflict for {}: expected seq {}, server has {}", ipns_name, seq, current_sequence_number);

                    let fresh_seq = coordinator.resolve_sequence(&api, &ipns_name).await?;
                    let remote_resolve = cipherbox_api_client::ipns::resolve_ipns(&api, &ipns_name)
                        .await.map_err(|e| format!("{}", e))?;
                    let remote_bytes = cipherbox_api_client::ipfs::fetch_content(&api, &remote_resolve.cid)
                        .await.map_err(|e| format!("{}", e))?;
                    let remote_metadata = cipherbox_core::decrypt_metadata_from_ipfs_public(&remote_bytes, &folder_key)?;

                    let merged_metadata = merge_folder_children(&metadata, remote_metadata);

                    let jitter_ms = (std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default()
                        .subsec_nanos() % 400) as u64 + 100;
                    tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;

                    let retry_json = encrypt_metadata_to_json(&merged_metadata, &folder_key)?;
                    let retry_cid = cipherbox_api_client::ipfs::upload_content(&api, &retry_json)
                        .await.map_err(|e| format!("{}", e))?;

                    let retry_seq = fresh_seq + 1;
                    let retry_value = format!("/ipfs/{}", retry_cid);
                    let retry_record = cipherbox_core::create_ipns_record(&ipns_key_arr, &retry_value, retry_seq, 86_400_000)
                        .map_err(|e| format!("IPNS retry record failed: {}", e))?;
                    let retry_marshaled = cipherbox_core::marshal_ipns_record(&retry_record)
                        .map_err(|e| format!("IPNS retry marshal failed: {}", e))?;
                    let retry_b64 = base64::engine::general_purpose::STANDARD.encode(&retry_marshaled);

                    let retry_cid_for_cleanup = retry_cid.clone();
                    let retry_req = cipherbox_api_client::IpnsPublishRequest {
                        ipns_name: ipns_name.clone(),
                        record: retry_b64,
                        metadata_cid: retry_cid,
                        encrypted_ipns_private_key: None,
                        key_epoch: None,
                        expected_sequence_number: Some(fresh_seq.to_string()),
                    };

                    match cipherbox_api_client::ipns::publish_ipns(&api, &retry_req).await.map_err(|e| format!("{}", e))? {
                        cipherbox_api_client::PublishResult::Success => {
                            coordinator.record_publish(&ipns_name, retry_seq);
                            let _ = cipherbox_api_client::ipfs::unpin_content(&api, &new_cid).await;
                            if let Some(old) = old_metadata_cid {
                                let _ = cipherbox_api_client::ipfs::unpin_content(&api, &old).await;
                            }
                            log::info!("Conflict resolved for {} after retry (seq {})", ipns_name, retry_seq);
                        }
                        cipherbox_api_client::PublishResult::Conflict { .. } => {
                            let _ = cipherbox_api_client::ipfs::unpin_content(&api, &new_cid).await;
                            let _ = cipherbox_api_client::ipfs::unpin_content(&api, &retry_cid_for_cleanup).await;
                            return Err(format!("Persistent conflict for {}", ipns_name));
                        }
                    }
                }
            }
            Ok::<(), String>(())
        });
        if let Err(e) = result {
            log::error!("Background metadata publish failed: {}", e);
        }
    });
}

/// Add a BinEntry to the user's encrypted recycle bin IPNS record.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn spawn_bin_entry_publish(
    api: Arc<ApiClient>,
    rt: tokio::runtime::Handle,
    entry: cipherbox_core::bin::BinEntry,
    user_private_key: Zeroizing<Vec<u8>>,
    user_public_key: Vec<u8>,
    coordinator: Arc<PublishCoordinator>,
) {
    std::thread::spawn(move || {
        let result = rt.block_on(async {
            let pk_arr: [u8; 32] = user_private_key.as_slice().try_into()
                .map_err(|_| "Invalid private key length for bin derivation".to_string())?;
            let (bin_ipns_private_key, _bin_ipns_public_key, bin_ipns_name) =
                cipherbox_crypto::derive_bin_ipns_keypair(&pk_arr)
                    .map_err(|e| format!("Bin IPNS derivation failed: {}", e))?;

            let lock = coordinator.get_lock(&bin_ipns_name);
            let _guard = lock.lock().await;

            let (mut bin_metadata, existing_cid) = match cipherbox_api_client::ipns::resolve_ipns(&api, &bin_ipns_name).await {
                Ok(resp) => {
                    match cipherbox_api_client::ipfs::fetch_content(&api, &resp.cid).await {
                        Ok(bytes) => {
                            match cipherbox_core::decrypt_bin_metadata(&bytes, &user_private_key) {
                                Ok(meta) => (meta, Some(resp.cid)),
                                Err(e) => {
                                    log::warn!("Failed to decrypt bin metadata: {}", e);
                                    return Err(format!("Bin decrypt failed: {}", e));
                                }
                            }
                        }
                        Err(e) => {
                            log::warn!("Failed to fetch bin metadata blob: {}", e);
                            return Err(format!("Bin fetch failed: {}", e));
                        }
                    }
                }
                Err(e) => {
                    let e_str = format!("{}", e);
                    if e_str.to_lowercase().contains("not found") {
                        (cipherbox_core::empty_bin_metadata(), None)
                    } else {
                        log::warn!("Failed to resolve bin IPNS: {}", e);
                        return Err(format!("Bin resolve failed: {}", e));
                    }
                }
            };

            bin_metadata.sequence_number += 1;
            bin_metadata.entries.push(entry);

            let encrypted = cipherbox_core::encrypt_bin_metadata(&bin_metadata, &user_public_key)
                .map_err(|e| format!("Bin metadata encryption failed: {}", e))?;

            let new_cid = cipherbox_api_client::ipfs::upload_content(&api, &encrypted)
                .await.map_err(|e| format!("{}", e))?;

            let seq = coordinator.resolve_sequence(&api, &bin_ipns_name).await.unwrap_or(0);
            let new_seq = seq + 1;

            let bin_ipns_key_arr: [u8; 32] = bin_ipns_private_key.as_slice().try_into()
                .map_err(|_| "Invalid bin IPNS key length".to_string())?;
            let value = format!("/ipfs/{}", new_cid);
            let record = cipherbox_core::create_ipns_record(&bin_ipns_key_arr, &value, new_seq, 86_400_000)
                .map_err(|e| format!("Bin IPNS record creation failed: {}", e))?;
            let marshaled = cipherbox_core::marshal_ipns_record(&record)
                .map_err(|e| format!("Bin IPNS marshal failed: {}", e))?;

            use base64::Engine;
            let record_b64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);

            let req = cipherbox_api_client::IpnsPublishRequest {
                ipns_name: bin_ipns_name.clone(),
                record: record_b64,
                metadata_cid: new_cid,
                encrypted_ipns_private_key: None,
                key_epoch: None,
                expected_sequence_number: Some(seq.to_string()),
            };

            match cipherbox_api_client::ipns::publish_ipns(&api, &req).await.map_err(|e| format!("{}", e))? {
                cipherbox_api_client::PublishResult::Success => {
                    coordinator.record_publish(&bin_ipns_name, new_seq);
                    if let Some(old) = existing_cid {
                        let _ = cipherbox_api_client::ipfs::unpin_content(&api, &old).await;
                    }
                    log::info!("Bin entry published");
                }
                cipherbox_api_client::PublishResult::Conflict { current_sequence_number } => {
                    log::warn!("Bin IPNS publish conflict (expected {}, server {})", seq, current_sequence_number);
                }
            }

            Ok::<(), String>(())
        });
        if let Err(e) = result {
            log::error!("Background bin entry publish failed: {}", e);
        }
    });
}

/// The main filesystem struct.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub struct CipherBoxFS {
    pub inodes: inode::InodeTable,
    pub metadata_cache: cache::MetadataCache,
    pub content_cache: cache::ContentCache,
    pub api: Arc<ApiClient>,
    pub private_key: Zeroizing<Vec<u8>>,
    pub public_key: Zeroizing<Vec<u8>>,
    pub root_folder_key: Zeroizing<Vec<u8>>,
    pub root_ipns_name: String,
    pub rt: tokio::runtime::Handle,
    pub next_fh: AtomicU64,
    pub open_files: HashMap<u64, file_handle::OpenFileHandle>,
    pub temp_dir: PathBuf,
    pub tee_public_key: Option<Vec<u8>>,
    pub tee_key_epoch: Option<u32>,
    /// Maximum number of past versions to keep per file (from user vault settings).
    pub max_versions_per_file: usize,
    /// Version creation cooldown in milliseconds (from user vault settings).
    pub version_cooldown_ms: u64,
    pub refresh_rx: std::sync::mpsc::Receiver<PendingRefresh>,
    pub refresh_tx: std::sync::mpsc::Sender<PendingRefresh>,
    pub mutated_folders: HashMap<u64, std::time::Instant>,
    pub prefetching: std::collections::HashSet<String>,
    pub refreshing_metadata: std::collections::HashSet<String>,
    pub content_rx: std::sync::mpsc::Receiver<PendingContent>,
    pub content_tx: std::sync::mpsc::Sender<PendingContent>,
    pub filepointer_rx: std::sync::mpsc::Receiver<PendingFilePointer>,
    pub filepointer_tx: std::sync::mpsc::Sender<PendingFilePointer>,
    pub resolving_file_pointers: std::collections::HashSet<u64>,
    pub pending_content: HashMap<u64, Vec<u8>>,
    pub upload_rx: std::sync::mpsc::Receiver<UploadComplete>,
    pub upload_tx: std::sync::mpsc::Sender<UploadComplete>,
    pub publish_coordinator: Arc<PublishCoordinator>,
    pub publish_queue: HashMap<u64, PublishQueueEntry>,
}

#[cfg(any(feature = "fuse", feature = "winfsp"))]
impl CipherBoxFS {
    pub fn get_folder_key(&self, folder_ino: u64) -> Option<Vec<u8>> {
        self.inodes.get(folder_ino).and_then(|inode| match &inode.kind {
            inode::InodeKind::Root { .. } => Some(self.root_folder_key.to_vec()),
            inode::InodeKind::Folder { folder_key, .. } => Some(folder_key.to_vec()),
            _ => None,
        })
    }

    pub fn build_folder_metadata(&self, folder_ino: u64) -> Result<(cipherbox_core::FolderMetadata, Vec<u8>, Vec<u8>, String, Option<String>), String> {
        let (folder_key, ipns_private_key, ipns_name, child_inos) = {
            let inode = self.inodes.get(folder_ino).ok_or_else(|| format!("Folder inode {} not found", folder_ino))?;
            let children = inode.children.clone().unwrap_or_default();
            match &inode.kind {
                inode::InodeKind::Root { ipns_private_key, ipns_name } => {
                    let key = ipns_private_key.as_ref().ok_or("Root IPNS key not available")?.to_vec();
                    let name = ipns_name.as_ref().ok_or("Root IPNS name not available")?.clone();
                    (self.root_folder_key.to_vec(), key, name, children)
                }
                inode::InodeKind::Folder { folder_key, ipns_private_key, ipns_name, .. } => {
                    let key = ipns_private_key.as_ref().ok_or("Subfolder IPNS key not available")?.to_vec();
                    (folder_key.to_vec(), key, ipns_name.clone(), children)
                }
                _ => return Err("Cannot update metadata for non-folder inode".to_string()),
            }
        };

        let mut metadata_children = Vec::new();
        for &child_ino in &child_inos {
            let child = self.inodes.get(child_ino).ok_or_else(|| format!("Child inode {} not found", child_ino))?;
            match &child.kind {
                inode::InodeKind::Folder { ipns_name: child_ipns, encrypted_folder_key, ipns_private_key: child_ipns_key, .. } => {
                    let ipns_key_encrypted = if let Some(key) = child_ipns_key {
                        hex::encode(cipherbox_crypto::wrap_key(key, &self.public_key).map_err(|e| format!("Wrap IPNS key: {}", e))?)
                    } else { String::new() };
                    let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
                    let created_ms = child.attr.crtime.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
                    let modified_ms = child.attr.mtime.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
                    metadata_children.push(cipherbox_core::FolderChild::Folder(cipherbox_core::FolderEntry {
                        id: uuid_from_ino(child_ino), name: child.name.clone(), ipns_name: child_ipns.clone(),
                        folder_key_encrypted: encrypted_folder_key.clone(), ipns_private_key_encrypted: ipns_key_encrypted,
                        created_at: if created_ms > 0 { created_ms } else { now_ms },
                        modified_at: if modified_ms > 0 { modified_ms } else { now_ms },
                    }));
                }
                inode::InodeKind::File { file_meta_ipns_name, file_ipns_private_key, file_ipns_key_encrypted_hex, .. } => {
                    let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
                    let created_ms = child.attr.crtime.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
                    let modified_ms = child.attr.mtime.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
                    let ipns_name_val = match file_meta_ipns_name {
                        Some(name) if !name.is_empty() => name.clone(),
                        _ => { log::error!("File '{}' (ino {}) has no fileMetaIpnsName", child.name, child_ino); continue; }
                    };
                    let ipns_key_encrypted = if let Some(h) = file_ipns_key_encrypted_hex { Some(h.clone()) }
                        else if let Some(key) = file_ipns_private_key {
                            cipherbox_crypto::wrap_key(key, &self.public_key).ok().map(|w| hex::encode(&w))
                        } else { None };
                    metadata_children.push(cipherbox_core::FolderChild::File(cipherbox_core::FilePointer {
                        id: uuid_from_ino(child_ino), name: child.name.clone(), file_meta_ipns_name: ipns_name_val,
                        ipns_private_key_encrypted: ipns_key_encrypted,
                        created_at: if created_ms > 0 { created_ms } else { now_ms },
                        modified_at: if modified_ms > 0 { modified_ms } else { now_ms },
                    }));
                }
                _ => {}
            }
        }

        let metadata = cipherbox_core::FolderMetadata { version: "v2".to_string(), children: metadata_children };
        let old_cid = self.metadata_cache.get(&ipns_name).map(|c| c.cid.clone());
        Ok((metadata, folder_key, ipns_private_key, ipns_name, old_cid))
    }

    pub fn update_folder_metadata(&mut self, folder_ino: u64) -> Result<(), String> {
        self.mutated_folders.insert(folder_ino, std::time::Instant::now());
        let (metadata, folder_key, ipns_private_key, ipns_name, old_cid) = self.build_folder_metadata(folder_ino)?;
        spawn_metadata_publish(self.api.clone(), self.rt.clone(), metadata, folder_key, ipns_private_key, ipns_name, old_cid, self.publish_coordinator.clone());
        Ok(())
    }

    pub fn drain_upload_completions(&mut self) {
        while let Ok(result) = self.upload_rx.try_recv() {
            if let Some(inode) = self.inodes.get_mut(result.ino) {
                if inode.write_generation == result.write_generation {
                    if let inode::InodeKind::File { ref mut cid, .. } = inode.kind { *cid = result.new_cid.clone(); }
                }
            }
            if let Some(inode) = self.inodes.get(result.ino) {
                if inode.write_generation == result.write_generation {
                    if let Some(plaintext) = self.pending_content.remove(&result.ino) { self.content_cache.set(&result.new_cid, plaintext); }
                }
            }
            for pruned_cid in &result.pruned_cids {
                let api = self.api.clone(); let cid = pruned_cid.clone();
                self.rt.spawn(async move { let _ = cipherbox_api_client::ipfs::unpin_content(&api, &cid).await; });
            }
            if let Some(entry) = self.publish_queue.get_mut(&result.parent_ino) { entry.pending_uploads = entry.pending_uploads.saturating_sub(1); }
        }
        self.flush_publish_queue();
    }

    pub fn queue_publish(&mut self, folder_ino: u64, has_pending_upload: bool) {
        let entry = self.publish_queue.entry(folder_ino).or_insert(PublishQueueEntry { first_dirty: std::time::Instant::now(), pending_uploads: 0 });
        if has_pending_upload { entry.pending_uploads += 1; }
        self.mutated_folders.insert(folder_ino, std::time::Instant::now());
    }

    fn flush_publish_queue(&mut self) {
        let now = std::time::Instant::now();
        let debounce = std::time::Duration::from_millis(1500);
        let safety_valve = std::time::Duration::from_secs(10);
        let ready: Vec<u64> = self.publish_queue.iter()
            .filter(|(_, e)| { let elapsed = now.duration_since(e.first_dirty); elapsed >= safety_valve || (e.pending_uploads == 0 && elapsed >= debounce) })
            .map(|(&ino, _)| ino).collect();
        for folder_ino in ready {
            self.publish_queue.remove(&folder_ino);
            match self.build_folder_metadata(folder_ino) {
                Ok((m, fk, ipk, in_, oc)) => spawn_metadata_publish(self.api.clone(), self.rt.clone(), m, fk, ipk, in_, oc, self.publish_coordinator.clone()),
                Err(e) => log::error!("Failed to build folder metadata for publish (ino {}): {}", folder_ino, e),
            }
        }
    }

    pub fn drain_refresh_completions(&mut self) {
        let cutoff = std::time::Instant::now() - std::time::Duration::from_secs(30);
        self.mutated_folders.retain(|_, ts| *ts > cutoff);
        while let Ok(refresh) = self.refresh_rx.try_recv() {
            self.refreshing_metadata.remove(&refresh.ipns_name);
            if self.mutated_folders.contains_key(&refresh.ino) || self.publish_queue.contains_key(&refresh.ino) {
                self.metadata_cache.set(&refresh.ipns_name, refresh.metadata.clone(), refresh.cid);
                continue;
            }
            self.metadata_cache.set(&refresh.ipns_name, refresh.metadata.clone(), refresh.cid.clone());
            if let Err(e) = self.inodes.populate_folder(refresh.ino, &refresh.metadata, &self.private_key, &self.public_key, true) {
                log::warn!("Drain refresh apply failed for ino {}: {}", refresh.ino, e);
            }
            // Spawn async resolution for unresolved FilePointers in this folder
            let unresolved = self.inodes.get_unresolved_file_pointers_for_parent(refresh.ino);
            if !unresolved.is_empty() {
                let folder_key = self.inodes.get(refresh.ino).and_then(|i| match &i.kind {
                    inode::InodeKind::Root { .. } => Some(self.root_folder_key.to_vec()),
                    inode::InodeKind::Folder { folder_key, .. } => Some(folder_key.to_vec()),
                    _ => None,
                });
                if let Some(fk) = folder_key {
                    let fk_arr = match <[u8; 32]>::try_from(fk.as_slice()) {
                        Ok(arr) => arr,
                        Err(_) => {
                            log::warn!(
                                "FilePointer resolution skipped for folder ino {}: folder_key length is {} (expected 32)",
                                refresh.ino,
                                fk.len()
                            );
                            continue;
                        }
                    };
                    // Cap concurrent resolution tasks to avoid network thrashing in large folders
                    const MAX_CONCURRENT_FP_RESOLVES: usize = 10;
                    let mut spawned = 0;
                    for (ino, fp_ipns) in unresolved {
                        if self.resolving_file_pointers.contains(&ino) {
                            continue; // Already in-flight
                        }
                        if spawned >= MAX_CONCURRENT_FP_RESOLVES {
                            break; // Remaining will be picked up on next refresh cycle
                        }
                        self.resolving_file_pointers.insert(ino);
                        spawned += 1;
                        let api = self.api.clone();
                        let tx = self.filepointer_tx.clone();
                        self.rt.spawn(async move {
                            let result = tokio::time::timeout(
                                NETWORK_TIMEOUT,
                                async {
                                    let resp = cipherbox_api_client::ipns::resolve_ipns(&api, &fp_ipns)
                                        .await.map_err(|e| format!("{}", e))?;
                                    let enc_bytes = cipherbox_api_client::ipfs::fetch_content(&api, &resp.cid)
                                        .await.map_err(|e| format!("{}", e))?;
                                    cipherbox_core::decrypt_file_metadata_from_ipfs_public(&enc_bytes, &fk_arr)
                                },
                            ).await;

                            match result {
                                Ok(Ok(fm)) => {
                                    log::debug!("FilePointer async resolved for ino {} (cid={})", ino, &fm.cid[..fm.cid.len().min(12)]);
                                    let _ = tx.send(PendingFilePointer::Success {
                                        ino,
                                        cid: fm.cid,
                                        encrypted_file_key: fm.file_key_encrypted,
                                        iv: fm.file_iv,
                                        size: fm.size,
                                        encryption_mode: fm.encryption_mode,
                                        versions: fm.versions,
                                    });
                                }
                                Ok(Err(e)) => {
                                    log::warn!("FilePointer resolve failed for ino {}: {}", ino, e);
                                    let _ = tx.send(PendingFilePointer::Failure { ino });
                                }
                                Err(_) => {
                                    log::warn!("FilePointer resolve timed out for ino {} ({}s)", ino, NETWORK_TIMEOUT.as_secs());
                                    let _ = tx.send(PendingFilePointer::Failure { ino });
                                }
                            }
                        });
                    }
                }
            }
        }
    }

    pub fn drain_content_prefetches(&mut self) {
        while let Ok(msg) = self.content_rx.try_recv() {
            match msg {
                PendingContent::Success { cid, data } => { self.prefetching.remove(&cid); self.content_cache.set(&cid, data); }
                PendingContent::Failure { cid } => { self.prefetching.remove(&cid); }
            }
        }
    }

    /// Drain completed FilePointer async resolution results.
    /// Mirrors drain_content_prefetches() -- applies resolved metadata to inodes
    /// and removes entries from the resolving_file_pointers dedup guard.
    pub fn drain_filepointer_completions(&mut self) {
        while let Ok(msg) = self.filepointer_rx.try_recv() {
            match msg {
                PendingFilePointer::Success {
                    ino,
                    cid,
                    encrypted_file_key,
                    iv,
                    size,
                    encryption_mode,
                    versions,
                } => {
                    self.resolving_file_pointers.remove(&ino);
                    self.inodes.resolve_file_pointer(
                        ino,
                        cid,
                        encrypted_file_key,
                        iv,
                        size,
                        encryption_mode,
                        versions,
                    );
                    log::debug!("FilePointer resolved async for ino {}", ino);
                }
                PendingFilePointer::Failure { ino } => {
                    self.resolving_file_pointers.remove(&ino);
                    log::warn!("FilePointer async resolution failed for ino {}", ino);
                }
            }
        }
    }
}

#[cfg(any(feature = "fuse", feature = "winfsp"))]
fn uuid_from_ino(ino: u64) -> String {
    format!("{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}", (ino >> 32) as u32, ((ino >> 16) & 0xFFFF) as u16,
        (ino & 0xFFF) as u16, (0x8000 | (ino & 0x3FFF)) as u16, ino & 0xFFFFFFFFFFFF)
}

#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn mount_point() -> PathBuf {
    dirs::home_dir().expect("Could not determine home directory").join("CipherBox")
}

#[cfg(test)]
mod tests {
    use super::next_file_publish_sequence;

    #[test]
    fn next_file_publish_sequence_starts_new_records_at_zero() {
        assert_eq!(next_file_publish_sequence(true, None).unwrap(), 0);
        assert_eq!(next_file_publish_sequence(true, Some(99)).unwrap(), 0);
    }

    #[test]
    fn next_file_publish_sequence_increments_existing_records() {
        assert_eq!(next_file_publish_sequence(false, Some(0)).unwrap(), 1);
        assert_eq!(next_file_publish_sequence(false, Some(7)).unwrap(), 8);
    }

    #[test]
    fn next_file_publish_sequence_rejects_missing_existing_sequence() {
        assert!(next_file_publish_sequence(false, None).is_err());
    }
}
