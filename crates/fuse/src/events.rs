//! Pending result types and background-task spawn helpers for the FUSE filesystem.

/// Pending folder refresh result sent from background tasks.
///
/// node/v3 (69-09 Slice 5b(d)): the async half of the refresh pipeline resolves
/// the folder through the gated owned materialization
/// ([`cipherbox_sdk::list_folder_owned`]) and hands the resulting owned children
/// to the FS thread, which applies them synchronously via
/// `InodeTable::apply_owned_children`. The former decrypted `FolderMetadata` +
/// resolved `cid` payload is gone — children carry their own recovered keys.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub enum PendingRefresh {
    Success {
        ino: u64,
        ipns_name: String,
        children: Vec<cipherbox_sdk::ResolvedOwnedChild>,
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
///
/// node/v3 (69-09 Slice 5b(d)): a file's content descriptors (CID, IV hex, size,
/// encryption mode) are recovered by unsealing the file node's OWN read-body
/// (via [`cipherbox_sdk::fetch_node_gated`] → `resolve_file_descriptors`) — the
/// former legacy `encrypted_file_key` hex + `versions` fields are gone (the file
/// key lives sealed inside the node and is recovered lazily at content read).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub enum PendingFilePointer {
    Success {
        ino: u64,
        cid: String,
        iv: String,
        size: u64,
        encryption_mode: String,
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
/// On any error path (including timeout), sends `PendingRefresh::Failure` so the
/// caller's `refreshing_metadata` set is ALWAYS cleaned up (D-10).
///
/// D-10: the inner async block is wrapped in `tokio::time::timeout(NETWORK_TIMEOUT, ...)`
/// matching the FP-resolve timeout pattern in `fs.rs`. A hung resolve/fetch can no
/// longer hold `refreshing_metadata` indefinitely — the Elapsed arm sends Failure
/// so the next refresh cycle can proceed.
///
/// node/v3 (69-09 Slice 5b(d)): resolves the folder through the single gated
/// owned entrypoint [`cipherbox_sdk::list_folder_owned`] (SC#6 — NO raw
/// `resolve_ipns_verified`). The parent's symmetric `read_key`/`write_key` and
/// an OWNED `high_water` clone (5b(a)) are moved into the task; the recovered
/// `Vec<ResolvedOwnedChild>` is handed to the FS thread for synchronous apply.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
#[allow(clippy::too_many_arguments)]
pub fn spawn_metadata_refresh(
    rt: &tokio::runtime::Handle,
    api: std::sync::Arc<cipherbox_api_client::ApiClient>,
    tx: std::sync::mpsc::Sender<PendingRefresh>,
    ino: u64,
    ipns_name: String,
    parent_read_key: [u8; 32],
    parent_write_key: [u8; 32],
    high_water: cipherbox_sdk::RotationHighWater<cipherbox_sdk::JsonSidecarFloorStore>,
) {
    rt.spawn(async move {
        // D-10: bound the entire refresh with NETWORK_TIMEOUT so a hung resolve/fetch
        // never holds refreshing_metadata open indefinitely.
        let result: Result<Vec<cipherbox_sdk::ResolvedOwnedChild>, String> =
            match tokio::time::timeout(crate::runtime::NETWORK_TIMEOUT, async {
                // SC#6: the single gated owned read entrypoint (gate-first resolve
                // inside list_folder_owned) — no raw resolve on the read path.
                let fetcher = cipherbox_sdk::ApiNodeFetcher { api: &api };
                cipherbox_sdk::list_folder_owned(
                    &fetcher,
                    &high_water,
                    &ipns_name,
                    &parent_read_key,
                    &parent_write_key,
                )
                .await
                .map_err(|e| format!("list_folder_owned: {}", e))
            })
            .await
            {
                Ok(inner) => inner,
                Err(_elapsed) => {
                    // D-10: timeout elapsed — map to Err so the Failure arm below
                    // sends PendingRefresh::Failure and always clears refreshing_metadata.
                    Err(format!(
                        "metadata refresh timed out after {}s",
                        crate::runtime::NETWORK_TIMEOUT.as_secs()
                    ))
                }
            };

        match result {
            Ok(children) => {
                let _ = tx.send(PendingRefresh::Success {
                    ino,
                    ipns_name,
                    children,
                });
            }
            Err(e) => {
                log::warn!("Metadata refresh failed for {}: {}", ipns_name, e);
                let _ = tx.send(PendingRefresh::Failure { ipns_name });
            }
        }
    });
}
