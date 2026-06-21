//! Pending result types and background-task spawn helpers for the FUSE filesystem.

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
