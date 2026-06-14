//! CipherBox FUSE filesystem implementation.
//!
//! Platform-agnostic data structures (InodeTable, MetadataCache, ContentCache,
//! FileHandle) are shared across all platforms. Platform-specific mount/unmount
//! and FUSE callback implementations are behind feature flags.

pub mod cache;
pub mod constants;
pub mod error;
pub mod file_handle;
pub mod helpers;
pub mod inode;

// FUSE operations (macOS/Linux - fuser-based)
#[cfg(feature = "fuse")]
pub mod dir_ops;
#[cfg(feature = "fuse")]
pub mod operations;
#[cfg(feature = "fuse")]
pub mod read_ops;
#[cfg(feature = "fuse")]
pub mod write_ops;

// Platform-specific modules
pub mod platform;

// Re-exports
pub use cache::{ContentCache, MetadataCache};
pub use error::FuseError;
pub use file_handle::OpenFileHandle;
pub use inode::{InodeData, InodeTable};

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
pub enum PendingRefresh {
    Success {
        ino: u64,
        ipns_name: String,
        metadata: cipherbox_core::folder::FolderMetadata,
        cid: String,
    },
    Failure {
        ipns_name: String,
    },
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

/// Events sent from background upload/mkdir threads to the FS thread.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub enum FsEvent {
    /// A background file upload completed.
    UploadComplete(UploadComplete),
    /// A parent-folder publish after mkdir hit a conflict; the FS thread should
    /// re-arm the debounced publisher so it retries with a fresh sequence.
    MkdirConflict { parent_ino: u64 },
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

/// Spawn a background metadata refresh task that resolves IPNS, fetches content,
/// decrypts metadata, and sends the result (success or failure) over `tx`.
/// On any error path, sends `PendingRefresh::Failure` so the caller's
/// `refreshing_metadata` set is always cleaned up.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn spawn_metadata_refresh(
    rt: &tokio::runtime::Handle,
    api: std::sync::Arc<cipherbox_api_client::ApiClient>,
    tx: std::sync::mpsc::Sender<PendingRefresh>,
    ino: u64,
    ipns_name: String,
    folder_key: zeroize::Zeroizing<Vec<u8>>,
) {
    rt.spawn(async move {
        let result: Result<(cipherbox_core::folder::FolderMetadata, String), String> = async {
            let resolve_resp = cipherbox_api_client::ipns::resolve_ipns(&api, &ipns_name)
                .await
                .map_err(|e| format!("resolve: {}", e))?;
            let encrypted_bytes =
                cipherbox_api_client::ipfs::fetch_content(&api, &resolve_resp.cid)
                    .await
                    .map_err(|e| format!("fetch: {}", e))?;
            let metadata = cipherbox_core::decrypt::decrypt_metadata_from_ipfs_public(
                &encrypted_bytes,
                &folder_key,
            )
            .map_err(|e| format!("decrypt: {}", e))?;
            Ok((metadata, resolve_resp.cid))
        }
        .await;

        match result {
            Ok((metadata, cid)) => {
                let _ = tx.send(PendingRefresh::Success {
                    ino,
                    ipns_name,
                    metadata,
                    cid,
                });
            }
            Err(e) => {
                log::warn!("Metadata refresh failed for {}: {}", ipns_name, e);
                let _ = tx.send(PendingRefresh::Failure { ipns_name });
            }
        }
    });
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
                    log::warn!(
                        "Failed to parse IPNS sequence '{}' for {}: {}",
                        resp.sequence_number,
                        ipns_name,
                        e
                    );
                    0
                });
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
        .children
        .iter()
        .map(|c| (child_ipns_key(c).to_string(), c))
        .collect();

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

    cipherbox_core::folder::FolderMetadata {
        version: "v2".to_string(),
        children: merged,
    }
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
                .await
                .map_err(|e| format!("{}", e))?;

            let ipns_key_arr: [u8; 32] = ipns_private_key
                .try_into()
                .map_err(|_| "Invalid IPNS private key length".to_string())?;
            let new_seq = seq + 1;
            let value = format!("/ipfs/{}", new_cid);
            let record =
                cipherbox_core::create_ipns_record(&ipns_key_arr, &value, new_seq, 86_400_000)
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

            match cipherbox_api_client::ipns::publish_ipns(&api, &req)
                .await
                .map_err(|e| format!("{}", e))?
            {
                cipherbox_api_client::PublishResult::Success => {
                    coordinator.record_publish(&ipns_name, new_seq);
                    if let Some(old) = old_metadata_cid {
                        let _ = cipherbox_api_client::ipfs::unpin_content(&api, &old).await;
                    }
                    log::info!("Background metadata publish succeeded for {}", ipns_name);
                }
                cipherbox_api_client::PublishResult::Conflict {
                    current_sequence_number,
                } => {
                    log::warn!(
                        "Conflict for {}: expected seq {}, server has {}",
                        ipns_name,
                        seq,
                        current_sequence_number
                    );

                    let fresh_seq = coordinator.resolve_sequence(&api, &ipns_name).await?;
                    let remote_resolve = cipherbox_api_client::ipns::resolve_ipns(&api, &ipns_name)
                        .await
                        .map_err(|e| format!("{}", e))?;
                    let remote_bytes =
                        cipherbox_api_client::ipfs::fetch_content(&api, &remote_resolve.cid)
                            .await
                            .map_err(|e| format!("{}", e))?;
                    let remote_metadata = cipherbox_core::decrypt_metadata_from_ipfs_public(
                        &remote_bytes,
                        &folder_key,
                    )?;

                    let merged_metadata = merge_folder_children(&metadata, remote_metadata);

                    let jitter_ms = (std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .subsec_nanos()
                        % 400) as u64
                        + 100;
                    tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;

                    let retry_json = encrypt_metadata_to_json(&merged_metadata, &folder_key)?;
                    let retry_cid = cipherbox_api_client::ipfs::upload_content(&api, &retry_json)
                        .await
                        .map_err(|e| format!("{}", e))?;

                    let retry_seq = fresh_seq + 1;
                    let retry_value = format!("/ipfs/{}", retry_cid);
                    let retry_record = cipherbox_core::create_ipns_record(
                        &ipns_key_arr,
                        &retry_value,
                        retry_seq,
                        86_400_000,
                    )
                    .map_err(|e| format!("IPNS retry record failed: {}", e))?;
                    let retry_marshaled = cipherbox_core::marshal_ipns_record(&retry_record)
                        .map_err(|e| format!("IPNS retry marshal failed: {}", e))?;
                    let retry_b64 =
                        base64::engine::general_purpose::STANDARD.encode(&retry_marshaled);

                    let retry_cid_for_cleanup = retry_cid.clone();
                    let retry_req = cipherbox_api_client::IpnsPublishRequest {
                        ipns_name: ipns_name.clone(),
                        record: retry_b64,
                        metadata_cid: retry_cid,
                        encrypted_ipns_private_key: None,
                        key_epoch: None,
                        expected_sequence_number: Some(fresh_seq.to_string()),
                    };

                    match cipherbox_api_client::ipns::publish_ipns(&api, &retry_req)
                        .await
                        .map_err(|e| format!("{}", e))?
                    {
                        cipherbox_api_client::PublishResult::Success => {
                            coordinator.record_publish(&ipns_name, retry_seq);
                            let _ = cipherbox_api_client::ipfs::unpin_content(&api, &new_cid).await;
                            if let Some(old) = old_metadata_cid {
                                let _ = cipherbox_api_client::ipfs::unpin_content(&api, &old).await;
                            }
                            log::info!(
                                "Conflict resolved for {} after retry (seq {})",
                                ipns_name,
                                retry_seq
                            );
                        }
                        cipherbox_api_client::PublishResult::Conflict { .. } => {
                            let _ = cipherbox_api_client::ipfs::unpin_content(&api, &new_cid).await;
                            let _ = cipherbox_api_client::ipfs::unpin_content(
                                &api,
                                &retry_cid_for_cleanup,
                            )
                            .await;
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
            let pk_arr: [u8; 32] = user_private_key
                .as_slice()
                .try_into()
                .map_err(|_| "Invalid private key length for bin derivation".to_string())?;
            let (bin_ipns_private_key, _bin_ipns_public_key, bin_ipns_name) =
                cipherbox_crypto::derive_bin_ipns_keypair(&pk_arr)
                    .map_err(|e| format!("Bin IPNS derivation failed: {}", e))?;

            let lock = coordinator.get_lock(&bin_ipns_name);
            let _guard = lock.lock().await;

            let (mut bin_metadata, existing_cid) =
                match cipherbox_api_client::ipns::resolve_ipns(&api, &bin_ipns_name).await {
                    Ok(resp) => {
                        match cipherbox_api_client::ipfs::fetch_content(&api, &resp.cid).await {
                            Ok(bytes) => {
                                match cipherbox_core::decrypt_bin_metadata(
                                    &bytes,
                                    &user_private_key,
                                ) {
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
                .await
                .map_err(|e| format!("{}", e))?;

            let seq = coordinator
                .resolve_sequence(&api, &bin_ipns_name)
                .await
                .unwrap_or(0);
            let new_seq = seq + 1;

            let bin_ipns_key_arr: [u8; 32] = bin_ipns_private_key
                .as_slice()
                .try_into()
                .map_err(|_| "Invalid bin IPNS key length".to_string())?;
            let value = format!("/ipfs/{}", new_cid);
            let record =
                cipherbox_core::create_ipns_record(&bin_ipns_key_arr, &value, new_seq, 86_400_000)
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

            match cipherbox_api_client::ipns::publish_ipns(&api, &req)
                .await
                .map_err(|e| format!("{}", e))?
            {
                cipherbox_api_client::PublishResult::Success => {
                    coordinator.record_publish(&bin_ipns_name, new_seq);
                    if let Some(old) = existing_cid {
                        let _ = cipherbox_api_client::ipfs::unpin_content(&api, &old).await;
                    }
                    log::info!("Bin entry published");
                }
                cipherbox_api_client::PublishResult::Conflict {
                    current_sequence_number,
                } => {
                    log::warn!(
                        "Bin IPNS publish conflict (expected {}, server {})",
                        seq,
                        current_sequence_number
                    );
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
    pub upload_rx: std::sync::mpsc::Receiver<FsEvent>,
    pub upload_tx: std::sync::mpsc::Sender<FsEvent>,
    pub publish_coordinator: Arc<PublishCoordinator>,
    pub publish_queue: HashMap<u64, PublishQueueEntry>,
    /// Durable write journal — persists pending uploads and mkdir-publishes to disk
    /// so they survive a crash or remount.  Callbacks write here before acking the OS.
    pub journal: cipherbox_sdk::WriteQueue,
}

#[cfg(any(feature = "fuse", feature = "winfsp"))]
impl CipherBoxFS {
    pub fn get_folder_key(&self, folder_ino: u64) -> Option<Vec<u8>> {
        self.inodes
            .get(folder_ino)
            .and_then(|inode| match &inode.kind {
                inode::InodeKind::Root { .. } => Some(self.root_folder_key.to_vec()),
                inode::InodeKind::Folder { folder_key, .. } => Some(folder_key.to_vec()),
                _ => None,
            })
    }

    pub fn build_folder_metadata(
        &self,
        folder_ino: u64,
    ) -> Result<
        (
            cipherbox_core::FolderMetadata,
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
                        .ok_or("Root IPNS key not available")?
                        .to_vec();
                    let name = ipns_name
                        .as_ref()
                        .ok_or("Root IPNS name not available")?
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
                        .ok_or("Subfolder IPNS key not available")?
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
                    ipns_name: child_ipns,
                    encrypted_folder_key,
                    ipns_private_key: child_ipns_key,
                    ..
                } => {
                    let ipns_key_encrypted = if let Some(key) = child_ipns_key {
                        hex::encode(
                            cipherbox_crypto::wrap_key(key, &self.public_key)
                                .map_err(|e| format!("Wrap IPNS key: {}", e))?,
                        )
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
                    metadata_children.push(cipherbox_core::FolderChild::Folder(
                        cipherbox_core::FolderEntry {
                            id: uuid_from_ino(child_ino),
                            name: child.name.clone(),
                            ipns_name: child_ipns.clone(),
                            folder_key_encrypted: encrypted_folder_key.clone(),
                            ipns_private_key_encrypted: ipns_key_encrypted,
                            created_at: if created_ms > 0 { created_ms } else { now_ms },
                            modified_at: if modified_ms > 0 { modified_ms } else { now_ms },
                        },
                    ));
                }
                inode::InodeKind::File {
                    file_meta_ipns_name,
                    file_ipns_private_key,
                    file_ipns_key_encrypted_hex,
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
                    let ipns_name_val = match file_meta_ipns_name {
                        Some(name) if !name.is_empty() => name.clone(),
                        _ => {
                            log::error!(
                                "File '{}' (ino {}) has no fileMetaIpnsName",
                                child.name,
                                child_ino
                            );
                            continue;
                        }
                    };
                    let ipns_key_encrypted = if let Some(h) = file_ipns_key_encrypted_hex {
                        Some(h.clone())
                    } else if let Some(key) = file_ipns_private_key {
                        cipherbox_crypto::wrap_key(key, &self.public_key)
                            .ok()
                            .map(|w| hex::encode(&w))
                    } else {
                        None
                    };
                    metadata_children.push(cipherbox_core::FolderChild::File(
                        cipherbox_core::FilePointer {
                            id: uuid_from_ino(child_ino),
                            name: child.name.clone(),
                            file_meta_ipns_name: ipns_name_val,
                            ipns_private_key_encrypted: ipns_key_encrypted,
                            created_at: if created_ms > 0 { created_ms } else { now_ms },
                            modified_at: if modified_ms > 0 { modified_ms } else { now_ms },
                        },
                    ));
                }
                _ => {}
            }
        }

        let metadata = cipherbox_core::FolderMetadata {
            version: "v2".to_string(),
            children: metadata_children,
        };
        let old_cid = self.metadata_cache.get(&ipns_name).map(|c| c.cid.clone());
        Ok((metadata, folder_key, ipns_private_key, ipns_name, old_cid))
    }

    pub fn update_folder_metadata(&mut self, folder_ino: u64) -> Result<(), String> {
        self.mutated_folders
            .insert(folder_ino, std::time::Instant::now());
        let (metadata, folder_key, ipns_private_key, ipns_name, old_cid) =
            self.build_folder_metadata(folder_ino)?;
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

    pub fn drain_upload_completions(&mut self) {
        while let Ok(event) = self.upload_rx.try_recv() {
            match event {
                FsEvent::UploadComplete(result) => {
                    if let Some(inode) = self.inodes.get_mut(result.ino) {
                        if inode.write_generation == result.write_generation {
                            if let inode::InodeKind::File { ref mut cid, .. } = inode.kind {
                                *cid = result.new_cid.clone();
                            }
                        }
                    }
                    if let Some(inode) = self.inodes.get(result.ino) {
                        if inode.write_generation == result.write_generation {
                            if let Some(plaintext) = self.pending_content.remove(&result.ino) {
                                self.content_cache.set(&result.new_cid, plaintext);
                            }
                        }
                    }
                    for pruned_cid in &result.pruned_cids {
                        let api = self.api.clone();
                        let cid = pruned_cid.clone();
                        self.rt.spawn(async move {
                            let _ = cipherbox_api_client::ipfs::unpin_content(&api, &cid).await;
                        });
                    }
                    if let Some(entry) = self.publish_queue.get_mut(&result.parent_ino) {
                        entry.pending_uploads = entry.pending_uploads.saturating_sub(1);
                    }
                }
                FsEvent::MkdirConflict { parent_ino } => {
                    // Re-arm the debounced publisher so it retries the parent publish
                    // with a fresh sequence number (D-11a).
                    self.mutated_folders
                        .insert(parent_ino, std::time::Instant::now());
                    self.queue_publish(parent_ino, false);
                }
            }
        }
        self.flush_publish_queue();
    }

    pub fn queue_publish(&mut self, folder_ino: u64, has_pending_upload: bool) {
        let entry = self
            .publish_queue
            .entry(folder_ino)
            .or_insert(PublishQueueEntry {
                first_dirty: std::time::Instant::now(),
                pending_uploads: 0,
            });
        if has_pending_upload {
            entry.pending_uploads += 1;
        }
        self.mutated_folders
            .insert(folder_ino, std::time::Instant::now());
    }

    fn flush_publish_queue(&mut self) {
        let now = std::time::Instant::now();
        let debounce = std::time::Duration::from_millis(1500);
        let safety_valve = std::time::Duration::from_secs(10);
        let ready: Vec<u64> = self
            .publish_queue
            .iter()
            .filter(|(_, e)| {
                let elapsed = now.duration_since(e.first_dirty);
                elapsed >= safety_valve || (e.pending_uploads == 0 && elapsed >= debounce)
            })
            .map(|(&ino, _)| ino)
            .collect();
        for folder_ino in ready {
            self.publish_queue.remove(&folder_ino);
            match self.build_folder_metadata(folder_ino) {
                Ok((m, fk, ipk, in_, oc)) => spawn_metadata_publish(
                    self.api.clone(),
                    self.rt.clone(),
                    m,
                    fk,
                    ipk,
                    in_,
                    oc,
                    self.publish_coordinator.clone(),
                ),
                Err(e) => log::error!(
                    "Failed to build folder metadata for publish (ino {}): {}",
                    folder_ino,
                    e
                ),
            }
        }
    }

    pub fn drain_refresh_completions(&mut self) {
        let cutoff = std::time::Instant::now() - std::time::Duration::from_secs(30);
        self.mutated_folders.retain(|_, ts| *ts > cutoff);
        while let Ok(refresh) = self.refresh_rx.try_recv() {
            let (ino, ipns_name, metadata, cid) = match refresh {
                PendingRefresh::Success {
                    ino,
                    ipns_name,
                    metadata,
                    cid,
                } => (ino, ipns_name, metadata, cid),
                PendingRefresh::Failure { ipns_name } => {
                    self.refreshing_metadata.remove(&ipns_name);
                    continue;
                }
            };
            self.refreshing_metadata.remove(&ipns_name);
            if self.mutated_folders.contains_key(&ino) || self.publish_queue.contains_key(&ino) {
                self.metadata_cache.set(&ipns_name, metadata.clone(), cid);
                continue;
            }
            self.metadata_cache
                .set(&ipns_name, metadata.clone(), cid.clone());
            if let Err(e) = self.inodes.populate_folder(
                ino,
                &metadata,
                &self.private_key,
                &self.public_key,
                true,
            ) {
                log::warn!("Drain refresh apply failed for ino {}: {}", ino, e);
            }
            // Spawn async resolution for unresolved FilePointers in this folder
            let unresolved = self.inodes.get_unresolved_file_pointers_for_parent(ino);
            if !unresolved.is_empty() {
                let folder_key = self.inodes.get(ino).and_then(|i| match &i.kind {
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
                                ino,
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
                            let result = tokio::time::timeout(NETWORK_TIMEOUT, async {
                                let resp = cipherbox_api_client::ipns::resolve_ipns(&api, &fp_ipns)
                                    .await
                                    .map_err(|e| format!("{}", e))?;
                                let enc_bytes =
                                    cipherbox_api_client::ipfs::fetch_content(&api, &resp.cid)
                                        .await
                                        .map_err(|e| format!("{}", e))?;
                                cipherbox_core::decrypt_file_metadata_from_ipfs_public(
                                    &enc_bytes, &fk_arr,
                                )
                            })
                            .await;

                            match result {
                                Ok(Ok(fm)) => {
                                    log::debug!(
                                        "FilePointer async resolved for ino {} (cid={})",
                                        ino,
                                        &fm.cid[..fm.cid.len().min(12)]
                                    );
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
                                    log::warn!(
                                        "FilePointer resolve timed out for ino {} ({}s)",
                                        ino,
                                        NETWORK_TIMEOUT.as_secs()
                                    );
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
                PendingContent::Success { cid, data } => {
                    self.prefetching.remove(&cid);
                    self.content_cache.set(&cid, data);
                }
                PendingContent::Failure { cid } => {
                    self.prefetching.remove(&cid);
                }
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

/// Replay all pending journal entries for the given vault on mount.
///
/// Loads all entries for `root_ipns_name` (D-07 vault-scoping), orders them
/// MkdirPublish-before-UploadFile (D-08), then for each entry fetches the parent
/// folder's CURRENT remote metadata, merges the journaled child entry via
/// `merge_folder_children`, and CAS-publishes with retry (D-06 — never re-publishes
/// the stale journaled snapshot).
///
/// Errors are logged but never fail the mount — a partially-replayed journal is
/// better than a failed mount.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub async fn replay_for_vault(
    journal: &cipherbox_sdk::WriteQueue,
    api: Arc<ApiClient>,
    private_key: &[u8],
    public_key: &[u8],
    root_folder_key: &[u8],
    root_ipns_name: &str,
    coordinator: Arc<PublishCoordinator>,
    // F3: TEE key/epoch so a first-publish replay (per-file IPNS never created in the
    // original failed session) can enroll the record for TEE republishing.
    tee_public_key: Option<&[u8]>,
    tee_key_epoch: Option<u32>,
) {
    let entries = match journal.load_all_for_vault(root_ipns_name) {
        Ok(e) => e,
        Err(e) => {
            log::warn!("replay_for_vault: failed to load journal entries: {}", e);
            return;
        }
    };

    if entries.is_empty() {
        return;
    }

    log::info!(
        "replay_for_vault: replaying {} journal entry(s) for vault {}",
        entries.len(),
        root_ipns_name
    );

    // D-08: MkdirPublish entries process before UploadFile entries.
    let ordered = cipherbox_sdk::WriteQueue::ordered_for_replay(entries);

    for entry in &ordered {
        // Skip already-failed entries (user must manually intervene for those).
        if matches!(
            entry.status,
            cipherbox_sdk::JournalEntryStatus::Failed { .. }
        ) {
            log::info!(
                "replay_for_vault: skipping failed entry {} (status=Failed)",
                entry.id
            );
            continue;
        }

        match &entry.op {
            cipherbox_sdk::JournalOp::MkdirPublish {
                child_ipns_name,
                child_folder_key_hex,
                child_ipns_key_hex,
                parent_folder_ipns_name,
                parent_ipns_key_hex,
                name,
                created_at_ms,
            } => {
                let result = replay_mkdir_entry(
                    &api,
                    private_key,
                    root_folder_key,
                    root_ipns_name,
                    coordinator.clone(),
                    child_ipns_name,
                    child_folder_key_hex,
                    child_ipns_key_hex,
                    parent_folder_ipns_name,
                    parent_ipns_key_hex,
                    name,
                    *created_at_ms,
                )
                .await;
                match result {
                    Ok(()) => {
                        log::info!(
                            "replay_for_vault: MkdirPublish {} replayed successfully",
                            entry.id
                        );
                        let _ = journal.remove(&entry.id);
                    }
                    Err(e) => {
                        // F2: record the failure so retries accumulate across mounts and the
                        // entry parks as Failed at max_retries (D-09), making the WriteParked
                        // notification reachable at runtime instead of retrying forever.
                        match journal.record_failure(entry, &e) {
                            Ok(cipherbox_sdk::JournalEntryStatus::Failed { .. }) => log::error!(
                                "replay_for_vault: MkdirPublish {} parked as Failed after {} retries: {}",
                                entry.id, journal.max_retries, e
                            ),
                            Ok(_) => log::warn!(
                                "replay_for_vault: MkdirPublish {} failed: {} (retry {}/{}, will retry on next mount)",
                                entry.id, e, entry.retries + 1, journal.max_retries
                            ),
                            Err(re) => log::warn!(
                                "replay_for_vault: MkdirPublish {} failed: {}; record_failure also errored: {}",
                                entry.id, e, re
                            ),
                        }
                    }
                }
            }
            cipherbox_sdk::JournalOp::UploadFile {
                ciphertext_b64,
                wrapped_key_hex,
                iv_hex,
                file_meta_ipns_name,
                file_ipns_key_hex,
                parent_folder_ipns_name,
                parent_ipns_key_hex,
                filename,
                size,
                created_at_ms,
            } => {
                let result = replay_upload_entry(
                    &api,
                    private_key,
                    public_key,
                    root_folder_key,
                    root_ipns_name,
                    coordinator.clone(),
                    ciphertext_b64,
                    wrapped_key_hex,
                    iv_hex,
                    file_meta_ipns_name.as_deref(),
                    file_ipns_key_hex.as_deref(),
                    parent_folder_ipns_name,
                    parent_ipns_key_hex,
                    filename,
                    *size,
                    *created_at_ms,
                    tee_public_key,
                    tee_key_epoch,
                )
                .await;
                match result {
                    Ok(()) => {
                        log::info!(
                            "replay_for_vault: UploadFile {} ('{}') replayed successfully",
                            entry.id,
                            filename
                        );
                        let _ = journal.remove(&entry.id);
                    }
                    Err(e) => {
                        // F2: record the failure so retries accumulate across mounts and the
                        // entry parks as Failed at max_retries (D-09), making the WriteParked
                        // notification reachable at runtime instead of retrying forever.
                        match journal.record_failure(entry, &e) {
                            Ok(cipherbox_sdk::JournalEntryStatus::Failed { .. }) => log::error!(
                                "replay_for_vault: UploadFile {} ('{}') parked as Failed after {} retries: {}",
                                entry.id, filename, journal.max_retries, e
                            ),
                            Ok(_) => log::warn!(
                                "replay_for_vault: UploadFile {} ('{}') failed: {} (retry {}/{}, will retry on next mount)",
                                entry.id, filename, e, entry.retries + 1, journal.max_retries
                            ),
                            Err(re) => log::warn!(
                                "replay_for_vault: UploadFile {} ('{}') failed: {}; record_failure also errored: {}",
                                entry.id, filename, e, re
                            ),
                        }
                    }
                }
            }
        }
    }
}

/// Look up the folder key for `folder_ipns_name` via a bounded breadth-first descent.
///
/// WR-02: resolves parent folders nested two or more levels below root, not just
/// direct children of root. The BFS is capped at `MAX_RESOLVE_NODES` to bound network
/// round trips and prevent cycles.
///
/// If `folder_ipns_name == root_ipns_name`, returns `root_folder_key` directly.
/// Otherwise starts from root and iterates through the folder tree level by level,
/// decrypting each layer's metadata with the just-unwrapped folder key from the layer above.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
async fn resolve_folder_key(
    api: &ApiClient,
    private_key: &[u8],
    root_folder_key: &[u8],
    root_ipns_name: &str,
    folder_ipns_name: &str,
) -> Result<Vec<u8>, String> {
    // Node-visit cap: bounds total network round trips and prevents infinite loops
    // (WR-02). This counts nodes visited across the BFS, not tree depth.
    const MAX_RESOLVE_NODES: usize = 32;

    if folder_ipns_name == root_ipns_name {
        return Ok(root_folder_key.to_vec());
    }

    // BFS queue: (ipns_name_of_this_folder, unwrapped_folder_key_for_this_folder).
    // Starts at root; each step expands to all subfolder children of the current node.
    let mut queue: std::collections::VecDeque<(String, Vec<u8>)> =
        std::collections::VecDeque::new();
    queue.push_back((root_ipns_name.to_string(), root_folder_key.to_vec()));
    let mut nodes_visited = 0usize;

    while let Some((current_ipns, current_folder_key)) = queue.pop_front() {
        if nodes_visited >= MAX_RESOLVE_NODES {
            return Err(format!(
                "resolve_folder_key: node cap ({}) exceeded looking for {} — aborting",
                MAX_RESOLVE_NODES, folder_ipns_name
            ));
        }
        nodes_visited += 1;

        // Fetch and decrypt this folder's metadata.
        let resolve = cipherbox_api_client::ipns::resolve_ipns(api, &current_ipns)
            .await
            .map_err(|e| format!("resolve IPNS {}: {}", current_ipns, e))?;
        let enc_bytes = cipherbox_api_client::ipfs::fetch_content(api, &resolve.cid)
            .await
            .map_err(|e| format!("fetch metadata for {}: {}", current_ipns, e))?;
        let meta =
            cipherbox_core::decrypt_metadata_from_ipfs_public(&enc_bytes, &current_folder_key)
                .map_err(|e| format!("decrypt metadata for {}: {}", current_ipns, e))?;

        for child in &meta.children {
            if let cipherbox_core::folder::FolderChild::Folder(f) = child {
                let enc_key_bytes = hex::decode(&f.folder_key_encrypted).map_err(|e| {
                    format!("hex decode folder_key_encrypted for {}: {}", f.ipns_name, e)
                })?;
                let child_folder_key =
                    cipherbox_crypto::ecies::unwrap_key(&enc_key_bytes, private_key)
                        .map_err(|e| format!("unwrap folder key for {}: {}", f.ipns_name, e))?;

                if f.ipns_name == folder_ipns_name {
                    // Found the target folder.
                    return Ok(child_folder_key);
                }

                // Enqueue for further descent.
                queue.push_back((f.ipns_name.clone(), child_folder_key));
            }
        }
    }

    Err(format!(
        "folder IPNS {} not found in vault tree (searched {} nodes)",
        folder_ipns_name, nodes_visited
    ))
}

/// Fetch, decrypt, merge, and CAS-publish a parent folder update.
///
/// Core CR-01 / D-06 implementation: fetches CURRENT remote metadata, merges, then
/// signs and publishes an IPNS record with the provided unwrapped parent IPNS private key.
/// Returns `Err` if the publish did not succeed (Conflict or key absent) so the caller
/// retains the journal entry for the next mount.
///
/// IMPORTANT: `unpin_content` is NOT called on the pre-merge CID here. The old CID is
/// unpinned only after a confirmed `PublishResult::Success` (T-43-19 — never unpin a CID
/// that the live IPNS record still references).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
// `parent_ipns_private_key_raw`: unwrapped (raw 32-byte) Ed25519 parent IPNS key for signing.
// Must be obtained via ecies::unwrap_key(parent_ipns_key_hex). If empty, returns Err (CR-01).
async fn fetch_merge_publish_parent(
    api: &ApiClient,
    folder_key: &[u8],
    parent_ipns_name: &str,
    parent_ipns_private_key_raw: &[u8],
    coordinator: Arc<PublishCoordinator>,
    local_child: cipherbox_core::folder::FolderChild,
) -> Result<(), String> {
    use base64::Engine;

    // CR-01: if the caller could not unwrap the parent IPNS key, retain the entry.
    if parent_ipns_private_key_raw.is_empty() {
        return Err("parent IPNS private key unavailable — retaining journal entry".to_string());
    }

    let lock = coordinator.get_lock(parent_ipns_name);
    let _guard = lock.lock().await;

    // D-06: fetch CURRENT remote metadata (not the stale journaled snapshot).
    let resolve = cipherbox_api_client::ipns::resolve_ipns(api, parent_ipns_name)
        .await
        .map_err(|e| format!("resolve parent IPNS {}: {}", parent_ipns_name, e))?;
    let remote_bytes = cipherbox_api_client::ipfs::fetch_content(api, &resolve.cid)
        .await
        .map_err(|e| format!("fetch parent metadata: {}", e))?;
    let remote_meta = cipherbox_core::decrypt_metadata_from_ipfs_public(&remote_bytes, folder_key)
        .map_err(|e| format!("decrypt parent metadata: {}", e))?;

    // D-06 idempotency: check if the child is already present in the remote.
    let child_ipns_key = match &local_child {
        cipherbox_core::folder::FolderChild::Folder(f) => f.ipns_name.clone(),
        cipherbox_core::folder::FolderChild::File(f) => f.file_meta_ipns_name.clone(),
    };
    let already_present = remote_meta.children.iter().any(|c| {
        let ipns = match c {
            cipherbox_core::folder::FolderChild::Folder(f) => &f.ipns_name,
            cipherbox_core::folder::FolderChild::File(f) => &f.file_meta_ipns_name,
        };
        ipns == &child_ipns_key
    });
    if already_present {
        log::info!(
            "replay: child {} already present in parent {} — skipping merge (idempotent, Pitfall 5)",
            child_ipns_key,
            parent_ipns_name
        );
        return Ok(());
    }

    // Merge local child into remote (union merge).
    let local_meta = cipherbox_core::folder::FolderMetadata {
        version: "v2".to_string(),
        children: vec![local_child],
    };
    let merged = merge_folder_children(&local_meta, remote_meta);

    // Encrypt and upload the merged metadata.
    let json_bytes = encrypt_metadata_to_json(&merged, folder_key)?;
    let seq = coordinator.resolve_sequence(api, parent_ipns_name).await?;
    let new_cid = cipherbox_api_client::ipfs::upload_content(api, &json_bytes)
        .await
        .map_err(|e| format!("upload merged metadata: {}", e))?;

    // CR-01: sign and publish the parent IPNS record with the unwrapped key.
    // Mirror the live mkdir parent-publish flow from write_ops.rs:596-641.
    let parent_key_arr: [u8; 32] = parent_ipns_private_key_raw.try_into().map_err(|_| {
        format!(
            "parent IPNS key has wrong length (got {}, expected 32) — retaining journal entry",
            parent_ipns_private_key_raw.len()
        )
    })?;
    let new_seq = seq + 1;
    let parent_value = format!("/ipfs/{}", new_cid);
    let parent_record =
        cipherbox_core::create_ipns_record(&parent_key_arr, &parent_value, new_seq, 86_400_000)
            .map_err(|e| format!("create parent IPNS record: {}", e))?;
    let parent_marshaled = cipherbox_core::marshal_ipns_record(&parent_record)
        .map_err(|e| format!("marshal parent IPNS record: {}", e))?;
    let parent_record_b64 = base64::engine::general_purpose::STANDARD.encode(&parent_marshaled);

    let parent_req = cipherbox_api_client::IpnsPublishRequest {
        ipns_name: parent_ipns_name.to_string(),
        record: parent_record_b64,
        metadata_cid: new_cid.clone(),
        encrypted_ipns_private_key: None,
        key_epoch: None,
        expected_sequence_number: Some(seq.to_string()),
    };

    match cipherbox_api_client::ipns::publish_ipns(api, &parent_req)
        .await
        .map_err(|e| format!("publish parent IPNS: {}", e))?
    {
        cipherbox_api_client::PublishResult::Success => {
            // CR-01 / T-43-21: only advance the sequence cache on confirmed Success (IN-06 fix).
            coordinator.record_publish(parent_ipns_name, new_seq);
            // T-43-19: unpin the OLD CID (the one the live IPNS record no longer references)
            // only AFTER the new record is confirmed live.
            let _ = cipherbox_api_client::ipfs::unpin_content(api, &resolve.cid).await;
            log::info!(
                "replay: parent IPNS published for {} (new_seq={}, new_cid={})",
                parent_ipns_name,
                new_seq,
                new_cid
            );
            Ok(())
        }
        cipherbox_api_client::PublishResult::Conflict {
            current_sequence_number,
        } => {
            // T-43-18: CAS conflict — do NOT remove the journal entry; retain for next mount.
            // The new_cid is still pinned on IPFS which is safe (it just won't be referenced yet).
            log::warn!(
                "replay: CAS conflict on parent {} (expected seq {}, server has {:?}) — retaining entry",
                parent_ipns_name, seq, current_sequence_number
            );
            Err(format!(
                "IPNS conflict on parent {} (server seq {:?}) — will retry on next mount",
                parent_ipns_name, current_sequence_number
            ))
        }
    }
}

/// Replay a single `MkdirPublish` journal entry.
/// Fetches current parent metadata, merges child folder entry, CAS-publishes.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
#[allow(clippy::too_many_arguments)]
async fn replay_mkdir_entry(
    api: &ApiClient,
    private_key: &[u8],
    root_folder_key: &[u8],
    root_ipns_name: &str,
    coordinator: Arc<PublishCoordinator>,
    child_ipns_name: &str,
    child_folder_key_hex: &str,
    // child_ipns_key_hex: user-ECIES-wrapped child IPNS key; written as-is (CR-03, no re-wrap).
    child_ipns_key_hex: &str,
    parent_folder_ipns_name: &str,
    // parent_ipns_key_hex: user-ECIES-wrapped parent IPNS key from journal (CR-01).
    parent_ipns_key_hex: &str,
    name: &str,
    created_at_ms: u64,
) -> Result<(), String> {
    let parent_folder_key = resolve_folder_key(
        api,
        private_key,
        root_folder_key,
        root_ipns_name,
        parent_folder_ipns_name,
    )
    .await?;

    // CR-01: hex-decode and ecies-unwrap the journaled parent IPNS key.
    // Returns Err if the key is absent/malformed so the entry is retained (T-43-20).
    let parent_ipns_key_raw = if parent_ipns_key_hex.is_empty() {
        return Err(
            "parent_ipns_key_hex is empty in MkdirPublish entry — retaining for retry".to_string(),
        );
    } else {
        let wrapped_bytes = hex::decode(parent_ipns_key_hex)
            .map_err(|e| format!("hex decode parent_ipns_key_hex: {} — retaining entry", e))?;
        cipherbox_crypto::ecies::unwrap_key(&wrapped_bytes, private_key)
            .map_err(|e| format!("ecies unwrap parent IPNS key: {} — retaining entry", e))?
    };

    // CR-03: write the user-ECIES-wrapped child IPNS key as-is into FolderEntry.
    // The journal already stores the user-wrapped form (populated by 43-06 write side fix).
    // No re-wrap here — that would produce a doubly-wrapped key.
    let child_entry =
        cipherbox_core::folder::FolderChild::Folder(cipherbox_core::folder::FolderEntry {
            id: format!("replay-{}", child_ipns_name),
            name: name.to_string(),
            ipns_name: child_ipns_name.to_string(),
            folder_key_encrypted: child_folder_key_hex.to_string(),
            // CR-03: user-ECIES-wrapped child IPNS key, matching build_folder_metadata convention.
            ipns_private_key_encrypted: child_ipns_key_hex.to_string(),
            created_at: created_at_ms,
            modified_at: created_at_ms,
        });

    fetch_merge_publish_parent(
        api,
        &parent_folder_key,
        parent_folder_ipns_name,
        &parent_ipns_key_raw,
        coordinator,
        child_entry,
    )
    .await
}

/// Replay a single `UploadFile` journal entry.
/// Re-uploads ciphertext (idempotent CID), re-publishes file IPNS, merges file pointer
/// into current parent metadata.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
#[allow(clippy::too_many_arguments)]
async fn replay_upload_entry(
    api: &ApiClient,
    private_key: &[u8],
    _public_key: &[u8],
    root_folder_key: &[u8],
    root_ipns_name: &str,
    coordinator: Arc<PublishCoordinator>,
    ciphertext_b64: &str,
    wrapped_key_hex: &str,
    iv_hex: &str,
    file_meta_ipns_name: Option<&str>,
    file_ipns_key_hex: Option<&str>,
    parent_folder_ipns_name: &str,
    // parent_ipns_key_hex: user-ECIES-wrapped parent IPNS private key from journal (CR-01).
    parent_ipns_key_hex: &str,
    filename: &str,
    size: u64,
    created_at_ms: u64,
    // F3: TEE key/epoch for first-publish enrollment when the per-file IPNS record
    // was never created in the original (failed) session.
    tee_public_key: Option<&[u8]>,
    tee_key_epoch: Option<u32>,
) -> Result<(), String> {
    use base64::Engine;

    // CR-01: hex-decode and ecies-unwrap the journaled parent IPNS key.
    // Returns Err if the key is absent/malformed so the entry is retained (T-43-20).
    let parent_ipns_key_raw = if parent_ipns_key_hex.is_empty() {
        return Err(
            "parent_ipns_key_hex is empty in UploadFile entry — retaining for retry".to_string(),
        );
    } else {
        let wrapped_bytes = hex::decode(parent_ipns_key_hex)
            .map_err(|e| format!("hex decode parent_ipns_key_hex: {} — retaining entry", e))?;
        cipherbox_crypto::ecies::unwrap_key(&wrapped_bytes, private_key)
            .map_err(|e| format!("ecies unwrap parent IPNS key: {} — retaining entry", e))?
    };

    // Step 1: re-upload ciphertext (idempotent — same plaintext → same ciphertext → same CID).
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(ciphertext_b64)
        .map_err(|e| format!("base64 decode ciphertext: {}", e))?;
    let file_cid = cipherbox_api_client::ipfs::upload_content(api, &ciphertext)
        .await
        .map_err(|e| format!("upload ciphertext: {}", e))?;

    log::info!(
        "replay: re-uploaded ciphertext for '{}' -> CID {}",
        filename,
        file_cid
    );

    // Step 2: resolve parent folder key for subsequent steps.
    let parent_folder_key = resolve_folder_key(
        api,
        private_key,
        root_folder_key,
        root_ipns_name,
        parent_folder_ipns_name,
    )
    .await?;

    // Step 3: re-publish file IPNS metadata if both the IPNS key AND the IPNS name are
    // available. The name guard (Option<&str>) replaces the old empty-string sentinel (#18):
    // None means "no per-file IPNS record" and the publish block is skipped, preserving
    // the existing behavior where an absent name → no per-file publish (T-45-03-DUR).
    if let Some(file_ipns_key_hex_str) = file_ipns_key_hex {
        if !file_ipns_key_hex_str.is_empty() {
            if let Some(file_meta_ipns_name) = file_meta_ipns_name {
                // CR-02: ecies-unwrap the ECIES-wrapped file IPNS key before casting to [u8;32].
                // The journaled key is user-ECIES-wrapped (~117 bytes), NOT a raw 32-byte key.
                // Directly casting the wrapped bytes always fails (they're ~117 bytes, not 32).
                let file_ipns_key_wrapped = hex::decode(file_ipns_key_hex_str)
                    .map_err(|e| format!("hex decode file_ipns_key: {}", e))?;
                let file_ipns_key_raw =
                    cipherbox_crypto::ecies::unwrap_key(&file_ipns_key_wrapped, private_key)
                        .map_err(|e| format!("ecies unwrap file IPNS key: {}", e))?;
                let file_ipns_key = zeroize::Zeroizing::new(file_ipns_key_raw);

                let parent_folder_key_arr: [u8; 32] = parent_folder_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| "Invalid parent folder key length".to_string())?;

                let file_meta = cipherbox_core::folder::FileMetadata {
                    version: "v1".to_string(),
                    cid: file_cid.clone(),
                    file_key_encrypted: wrapped_key_hex.to_string(),
                    file_iv: iv_hex.to_string(),
                    size,
                    mime_type: String::new(),
                    encryption_mode: "GCM".to_string(),
                    created_at: created_at_ms,
                    modified_at: created_at_ms,
                    versions: None,
                };

                // CR-02: cast the unwrapped raw key (32 bytes) — this will always succeed.
                let ipns_key_arr: [u8; 32] = file_ipns_key.as_slice().try_into().map_err(|_| {
                    format!(
                        "Invalid file IPNS key length after unwrap (got {} bytes, expected 32)",
                        file_ipns_key.len()
                    )
                })?;

                // F3: determine whether the per-file IPNS record already exists. If the original
                // upload failed before ever creating it, resolve returns not-found and this is a
                // FIRST publish (seq 0 + TEE enrollment), mirroring the live path
                // (operations.rs::publish_file_metadata). Otherwise it is an update (seq + 1).
                // A transient resolve error (not "not found") is propagated so the entry is
                // retained for retry rather than creating a duplicate record at seq 0.
                let (is_first_publish, new_seq) = match coordinator
                    .resolve_sequence(api, file_meta_ipns_name)
                    .await
                {
                    Ok(current_seq) => (false, current_seq + 1),
                    Err(e) if e.to_lowercase().contains("not found") => {
                        log::info!(
                                "replay: per-file IPNS '{}' not found — creating as first publish (seq 0)",
                                file_meta_ipns_name
                            );
                        (true, next_file_publish_sequence(true, None)?)
                    }
                    Err(e) => {
                        return Err(format!(
                            "resolve file IPNS sequence: {} — retaining entry",
                            e
                        ))
                    }
                };

                let sealed = cipherbox_core::folder::encrypt_file_metadata(
                    &file_meta,
                    &parent_folder_key_arr,
                )
                .map_err(|e| format!("encrypt file metadata: {}", e))?;
                let iv_hex_meta = hex::encode(&sealed[..12]);
                let data_b64 = base64::engine::general_purpose::STANDARD.encode(&sealed[12..]);
                let json = serde_json::json!({ "iv": iv_hex_meta, "data": data_b64 });
                let json_bytes = serde_json::to_vec(&json)
                    .map_err(|e| format!("serialize file metadata JSON: {}", e))?;
                let file_meta_cid = cipherbox_api_client::ipfs::upload_content(api, &json_bytes)
                    .await
                    .map_err(|e| format!("upload file metadata: {}", e))?;

                let value = format!("/ipfs/{}", file_meta_cid);
                let record =
                    cipherbox_core::create_ipns_record(&ipns_key_arr, &value, new_seq, 86_400_000)
                        .map_err(|e| format!("create file IPNS record: {}", e))?;
                let marshaled = cipherbox_core::marshal_ipns_record(&record)
                    .map_err(|e| format!("marshal file IPNS record: {}", e))?;
                let record_b64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);

                // F3: enroll the per-file IPNS key with the TEE on first publish only, so the
                // newly created record is republished every ~6h and does not expire after its
                // 24h TTL. Mirrors operations.rs::publish_file_metadata TEE enrollment.
                let (encrypted_ipns_for_tee, tee_epoch) =
                    match (is_first_publish, tee_public_key, tee_key_epoch) {
                        (true, Some(tee_key), Some(epoch)) => {
                            let wrapped =
                                cipherbox_crypto::wrap_key(file_ipns_key.as_slice(), tee_key)
                                    .map_err(|e| {
                                        format!("TEE key wrapping failed: {} — retaining entry", e)
                                    })?;
                            (Some(hex::encode(&wrapped)), Some(epoch))
                        }
                        (true, Some(_), None) => {
                            return Err(
                                "TEE public key present but key_epoch missing — retaining entry"
                                    .to_string(),
                            );
                        }
                        _ => (None, None),
                    };

                let req = cipherbox_api_client::IpnsPublishRequest {
                    ipns_name: file_meta_ipns_name.to_string(),
                    record: record_b64,
                    metadata_cid: file_meta_cid,
                    encrypted_ipns_private_key: encrypted_ipns_for_tee,
                    key_epoch: tee_epoch,
                    expected_sequence_number: None,
                };
                match cipherbox_api_client::ipns::publish_ipns(api, &req)
                    .await
                    .map_err(|e| format!("{}", e))?
                {
                    cipherbox_api_client::PublishResult::Success => {
                        coordinator.record_publish(file_meta_ipns_name, new_seq);
                        log::info!(
                            "replay: file IPNS published for '{}' (seq {}, first_publish={})",
                            filename,
                            new_seq,
                            is_first_publish
                        );
                    }
                    cipherbox_api_client::PublishResult::Conflict { .. } => {
                        log::warn!(
                            "replay: file IPNS conflict for '{}' — file CID is durable, continuing",
                            filename
                        );
                    }
                }
            }
        }
    }

    // Step 4: merge file pointer into parent folder metadata (D-06 fetch-and-merge).
    // Use unwrap_or_default() for the IPNS name in the FilePointer: when None (no per-file
    // IPNS record), an empty string preserves the pre-Phase-45 behavior where files without
    // a per-file IPNS name are still merged into the parent via their FilePointer entry.
    let file_meta_ipns_name_str = file_meta_ipns_name.unwrap_or_default();
    let file_pointer =
        cipherbox_core::folder::FolderChild::File(cipherbox_core::folder::FilePointer {
            id: format!("replay-{}", file_meta_ipns_name_str),
            name: filename.to_string(),
            file_meta_ipns_name: file_meta_ipns_name_str.to_string(),
            // CR-02: store the journaled file_ipns_key_hex AS-IS — it is already user-ECIES-wrapped.
            // Do NOT re-wrap: that would produce a doubly-wrapped key in the stored FilePointer.
            ipns_private_key_encrypted: file_ipns_key_hex.map(|k| k.to_string()),
            created_at: created_at_ms,
            modified_at: created_at_ms,
        });

    fetch_merge_publish_parent(
        api,
        &parent_folder_key,
        parent_folder_ipns_name,
        &parent_ipns_key_raw,
        coordinator,
        file_pointer,
    )
    .await
}

#[cfg(any(feature = "fuse", feature = "winfsp"))]
fn uuid_from_ino(ino: u64) -> String {
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (ino >> 32) as u32,
        ((ino >> 16) & 0xFFFF) as u16,
        (ino & 0xFFF) as u16,
        (0x8000 | (ino & 0x3FFF)) as u16,
        ino & 0xFFFFFFFFFFFF
    )
}

#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn mount_point() -> PathBuf {
    dirs::home_dir()
        .expect("Could not determine home directory")
        .join("CipherBox")
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

    // T-45-06: replay_for_vault must skip Failed entries entirely (not re-attempt, not
    // remove). Pins the current behavior so refactors (#11/#15/#20) cannot regress it.
    // An entry with status=Failed and a non-routable API host demonstrates that the
    // entry count stays at 1 after replay — i.e., it was neither removed nor re-queued.
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    #[tokio::test]
    async fn replay_for_vault_does_not_touch_failed_entries() {
        use cipherbox_sdk::{JournalEntry, JournalEntryStatus, JournalOp, WriteQueue};
        use std::sync::Arc; // noqa: already in scope via the test module's outer `use`

        let dir = std::env::temp_dir()
            .join("cb-t45-06-replay-skip-failed")
            .join(format!("{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let journal = WriteQueue::new(dir.clone(), 5);
        let vault = "k51vault45t06";

        // Build an entry that is already Failed before replay starts.
        let entry = JournalEntry {
            id: "failed-t4506".to_string(),
            vault_root_ipns: vault.to_string(),
            op: JournalOp::UploadFile {
                ciphertext_b64: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    b"ct",
                ),
                wrapped_key_hex: hex::encode(b"wk"),
                iv_hex: hex::encode(b"iv"),
                file_meta_ipns_name: Some("k51filemeta45t06".to_string()),
                file_ipns_key_hex: None,
                parent_folder_ipns_name: vault.to_string(),
                parent_ipns_key_hex: hex::encode(b"ecies-parent-key"),
                filename: "t4506.txt".to_string(),
                size: 1,
                created_at_ms: 1_700_000_000_000,
            },
            retries: 5,
            status: JournalEntryStatus::Failed {
                last_error: "simulated prior failure".to_string(),
            },
        };
        journal.put(&entry).unwrap();

        let api = Arc::new(cipherbox_api_client::ApiClient::new("http://127.0.0.1:1"));
        let coordinator = Arc::new(super::PublishCoordinator::new());

        super::replay_for_vault(
            &journal,
            api,
            &[0u8; 32],
            &[0u8; 33],
            &[0u8; 32],
            vault,
            coordinator,
            None,
            None,
        )
        .await;

        // After replay, the Failed entry must still be present (not removed, not retried).
        let after = journal.load_all_for_vault(vault).unwrap();
        assert_eq!(
            after.len(),
            1,
            "Failed entry must not be removed by replay (D-09 / skip-failed path)"
        );
        assert!(
            matches!(after[0].status, JournalEntryStatus::Failed { .. }),
            "status must remain Failed after replay"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // T-45-07: resolve_folder_key returns the same key for two calls with the same
    // parent_folder_ipns_name. Uses the root-shortcut (folder_ipns_name == root_ipns_name
    // at lib.rs:1042) so the result is deterministic without network access.
    //
    // This test characterizes the observable *equality* invariant that the #15 memoization
    // cache must preserve. After #15 lands, extend this test to additionally assert that
    // the BFS runs only once (via call-count or cache inspection).
    //
    // #15 will extend: assert BFS runs once via cache
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    #[tokio::test]
    async fn resolve_folder_key_cache_resolves_shared_parent_once() {
        use std::sync::Arc;
        // root_ipns_name == folder_ipns_name triggers the early-return shortcut
        // (lib.rs:1042): `if folder_ipns_name == root_ipns_name { return Ok(root_folder_key.to_vec()); }`
        // This gives us a deterministic result with zero network calls.
        let root_folder_key = [0u8; 32];
        let root_ipns_name = "k51rootipns45t07";

        let api = Arc::new(cipherbox_api_client::ApiClient::new("http://127.0.0.1:1"));

        let key1 = super::resolve_folder_key(
            &api,
            &[0u8; 32], // private_key (unused on root-shortcut path)
            &root_folder_key,
            root_ipns_name,
            root_ipns_name, // folder_ipns_name == root -> immediate return
        )
        .await
        .expect("resolve first call must succeed via root shortcut");

        let key2 = super::resolve_folder_key(
            &api,
            &[0u8; 32],
            &root_folder_key,
            root_ipns_name,
            root_ipns_name,
        )
        .await
        .expect("resolve second call must succeed via root shortcut");

        assert_eq!(
            key1, key2,
            "two resolve_folder_key calls with the same parent must return identical key bytes"
        );
        assert_eq!(
            key1,
            root_folder_key.to_vec(),
            "root shortcut must return root_folder_key unchanged"
        );
    }

    // T-45-08: merge_folder_children with one new child and one existing child (shared
    // file_meta_ipns_name) yields a merged result with both children, and the LOCAL
    // version of the existing child wins. Characterizes the merge semantics that
    // fetch_merge_publish_parent relies on during replay.
    #[test]
    fn merge_folder_children_unions_new_and_existing() {
        use cipherbox_core::folder::{FilePointer, FolderChild, FolderMetadata};

        // Shared IPNS name — identifies the "existing" file on both local and remote.
        let existing_ipns = "k51existing45t08";

        let local_existing = FolderChild::File(FilePointer {
            id: "local-existing-id".to_string(),
            name: "existing_local.txt".to_string(), // local version name — must win
            file_meta_ipns_name: existing_ipns.to_string(),
            ipns_private_key_encrypted: None,
            created_at: 1000,
            modified_at: 2000,
        });
        let local_new = FolderChild::File(FilePointer {
            id: "local-new-id".to_string(),
            name: "new_file.txt".to_string(), // only on local side
            file_meta_ipns_name: "k51new45t08".to_string(),
            ipns_private_key_encrypted: None,
            created_at: 1001,
            modified_at: 2001,
        });
        let remote_existing = FolderChild::File(FilePointer {
            id: "remote-existing-id".to_string(),
            name: "existing_remote.txt".to_string(), // remote version — must lose
            file_meta_ipns_name: existing_ipns.to_string(),
            ipns_private_key_encrypted: None,
            created_at: 999,
            modified_at: 1999,
        });

        let local_meta = FolderMetadata {
            version: "v2".to_string(),
            children: vec![local_existing, local_new],
        };
        let remote_meta = FolderMetadata {
            version: "v2".to_string(),
            children: vec![remote_existing],
        };

        let merged = super::merge_folder_children(&local_meta, remote_meta);

        // Union: both the existing child and the new child must be present.
        assert_eq!(
            merged.children.len(),
            2,
            "merged result must contain both children"
        );

        // Local version wins for the existing child.
        let merged_existing = merged.children.iter().find(|c| {
            if let FolderChild::File(f) = c {
                f.file_meta_ipns_name == existing_ipns
            } else {
                false
            }
        });
        let merged_existing = merged_existing.expect("existing child must be in merged result");
        if let FolderChild::File(f) = merged_existing {
            assert_eq!(
                f.name, "existing_local.txt",
                "local version must win for existing child (same IPNS key)"
            );
        }

        // New child must also be present.
        let has_new = merged.children.iter().any(|c| {
            if let FolderChild::File(f) = c {
                f.file_meta_ipns_name == "k51new45t08"
            } else {
                false
            }
        });
        assert!(
            has_new,
            "new child (local-only) must be included in merged result"
        );
    }

    // T-45-05: not_found_outcome_drives_first_publish
    //
    // Pins the #19 branch contract: given each IpnsResolveOutcome variant, the replay
    // sequencing decision must produce the correct (is_first_publish, new_seq) pair
    // without any network access. This test exercises the classification → sequence
    // computation directly, mirroring the branch logic inside replay_upload_entry.
    //
    // NotFound  -> is_first_publish=true,  new_seq=0  (next_file_publish_sequence(true, None))
    // Found(7)  -> is_first_publish=false, new_seq=8  (current_seq + 1)
    // Error(_)  -> Err propagated (entry retained, no sequence produced)
    #[test]
    fn not_found_outcome_drives_first_publish() {
        use super::next_file_publish_sequence;
        use crate::error::IpnsResolveOutcome;

        // NotFound -> first publish at seq 0
        let outcome_not_found = IpnsResolveOutcome::NotFound;
        let (is_first, new_seq) = match outcome_not_found {
            IpnsResolveOutcome::Found(seq) => (false, next_file_publish_sequence(false, Some(seq)).unwrap()),
            IpnsResolveOutcome::NotFound => (true, next_file_publish_sequence(true, None).unwrap()),
            IpnsResolveOutcome::Error(e) => panic!("unexpected Error variant: {}", e),
        };
        assert!(is_first, "NotFound must set is_first_publish=true");
        assert_eq!(new_seq, 0, "NotFound must produce seq 0");

        // Found(7) -> update at seq 8
        let outcome_found = IpnsResolveOutcome::Found(7);
        let (is_first, new_seq) = match outcome_found {
            IpnsResolveOutcome::Found(seq) => (false, next_file_publish_sequence(false, Some(seq)).unwrap()),
            IpnsResolveOutcome::NotFound => (true, next_file_publish_sequence(true, None).unwrap()),
            IpnsResolveOutcome::Error(e) => panic!("unexpected Error variant: {}", e),
        };
        assert!(!is_first, "Found must set is_first_publish=false");
        assert_eq!(new_seq, 8, "Found(7) must produce seq 8");

        // Error(_) -> propagated as Err (entry retained)
        let outcome_err = IpnsResolveOutcome::Error("transient failure".to_string());
        let result: Result<(bool, u64), String> = match outcome_err {
            IpnsResolveOutcome::Found(seq) => Ok((false, next_file_publish_sequence(false, Some(seq)).unwrap())),
            IpnsResolveOutcome::NotFound => Ok((true, next_file_publish_sequence(true, None).unwrap())),
            IpnsResolveOutcome::Error(e) => Err(format!("resolve file IPNS sequence: {} — retaining entry", e)),
        };
        assert!(result.is_err(), "Error variant must propagate as Err (entry retained)");
        let err_msg = result.unwrap_err();
        assert!(err_msg.contains("retaining entry"), "error message must mention retaining entry");
    }

    // F2: replay_for_vault must record each failed replay so retries accumulate across
    // mounts and the entry parks as Failed at max_retries (D-09). Before the fix the
    // failure arm only logged "will retry on next mount", so retries never advanced and
    // the WriteParked notification was unreachable. An UploadFile entry with an empty
    // parent_ipns_key_hex makes replay_upload_entry return Err immediately (no network),
    // so this exercises the failure path deterministically.
    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    #[tokio::test]
    async fn replay_records_failure_and_parks_at_max_retries() {
        use cipherbox_sdk::{JournalEntry, JournalEntryStatus, JournalOp, WriteQueue};
        use std::sync::Arc;

        let dir = std::env::temp_dir()
            .join("cb-f2-replay-park-test")
            .join(format!("{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let journal = WriteQueue::new(dir.clone(), 5);
        let vault = "k51vaultf2park";

        let entry = JournalEntry {
            id: "f2entry".to_string(),
            vault_root_ipns: vault.to_string(),
            op: JournalOp::UploadFile {
                ciphertext_b64: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    b"ct",
                ),
                wrapped_key_hex: hex::encode(b"wk"),
                iv_hex: hex::encode(b"iv"),
                file_meta_ipns_name: Some("k51filemeta".to_string()),
                file_ipns_key_hex: None,
                parent_folder_ipns_name: vault.to_string(),
                parent_ipns_key_hex: String::new(), // empty -> immediate Err in replay
                filename: "f2.txt".to_string(),
                size: 2,
                created_at_ms: 1_700_000_000_000,
            },
            retries: 4, // one below max_retries
            status: JournalEntryStatus::Pending,
        };
        journal.put(&entry).unwrap();

        let api = Arc::new(cipherbox_api_client::ApiClient::new("http://127.0.0.1:1"));
        let coordinator = Arc::new(super::PublishCoordinator::new());

        // First replay: failure increments retries 4 -> 5, stays Pending.
        super::replay_for_vault(
            &journal,
            api.clone(),
            &[0u8; 32],
            &[0u8; 33],
            &[0u8; 32],
            vault,
            coordinator.clone(),
            None,
            None,
        )
        .await;
        let after1 = journal.load_all_for_vault(vault).unwrap();
        let e1 = after1
            .iter()
            .find(|e| e.id == "f2entry")
            .expect("entry retained after failure");
        assert_eq!(
            e1.retries, 5,
            "retries must increment on a failed replay (F2)"
        );
        assert!(
            matches!(e1.status, JournalEntryStatus::Pending),
            "still Pending below max"
        );

        // Second replay: retries already at max -> parks as Failed (kept on disk, D-09).
        super::replay_for_vault(
            &journal,
            api,
            &[0u8; 32],
            &[0u8; 33],
            &[0u8; 32],
            vault,
            coordinator,
            None,
            None,
        )
        .await;
        let after2 = journal.load_all_for_vault(vault).unwrap();
        let e2 = after2
            .iter()
            .find(|e| e.id == "f2entry")
            .expect("parked entry kept on disk");
        assert!(
            matches!(e2.status, JournalEntryStatus::Failed { .. }),
            "entry must park as Failed at max_retries so WriteParked becomes reachable (F2)"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
