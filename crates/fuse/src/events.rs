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
/// On any error path (including timeout), sends `PendingRefresh::Failure` so the
/// caller's `refreshing_metadata` set is ALWAYS cleaned up (D-10).
///
/// D-10: the inner async block is wrapped in `tokio::time::timeout(NETWORK_TIMEOUT, ...)`
/// matching the FP-resolve timeout pattern in `fs.rs`. A hung resolve/fetch can no
/// longer hold `refreshing_metadata` indefinitely — the Elapsed arm sends Failure
/// so the next refresh cycle can proceed.
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
        // D-10: bound the entire refresh with NETWORK_TIMEOUT so a hung resolve/fetch
        // never holds refreshing_metadata open indefinitely.
        let result: Result<(cipherbox_core::folder::FolderMetadata, String), String> =
            match tokio::time::timeout(
                crate::runtime::NETWORK_TIMEOUT,
                async {
                    // D-01: route through the verified chokepoint.
                    let verified = match crate::verify::resolve_ipns_verified(&api, &ipns_name).await {
                        Ok(v) => v,
                        Err(crate::verify::VerifyError::Legacy { cid, sequence_number }) => {
                            // D-04: all-absent legacy record — use the carried cid/sequence_number
                            // (no second resolve_ipns). T-59-04: eliminates the TOCTOU race window.
                            // 30s poll self-heals; D-02 scoped.
                            log::warn!(
                                "spawn_metadata_refresh: IPNS {} resolved without signature fields \
                                 — proceeding with DB CID (D-04)",
                                ipns_name
                            );
                            crate::verify::VerifiedResolve {
                                cid,
                                sequence_number: sequence_number.parse().unwrap_or(0),
                            }
                        }
                        Err(crate::verify::VerifyError::Invalid(msg)) => {
                            // D-02: fail only this operation; poll loop self-heals.
                            return Err(format!("IPNS {} verify failed: {}", ipns_name, msg));
                        }
                        Err(crate::verify::VerifyError::Api(e)) => {
                            return Err(format!("resolve: {}", e));
                        }
                    };
                    let encrypted_bytes =
                        cipherbox_api_client::ipfs::fetch_content(&api, &verified.cid)
                            .await
                            .map_err(|e| format!("fetch: {}", e))?;
                    let metadata = cipherbox_core::decrypt::decrypt_metadata_from_ipfs_public(
                        &encrypted_bytes,
                        &folder_key,
                    )
                    .map_err(|e| format!("decrypt: {}", e))?;
                    Ok((metadata, verified.cid))
                },
            )
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
