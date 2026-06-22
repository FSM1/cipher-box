//! The main CipherBoxFS filesystem struct and its inherent implementation.

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
use cipherbox_api_client::ApiClient;

#[cfg(any(feature = "fuse", feature = "winfsp"))]
use crate::events::{FsEvent, PendingContent, PendingFilePointer, PendingRefresh};
#[cfg(any(feature = "fuse", feature = "winfsp"))]
use crate::metadata::spawn_metadata_publish;
#[cfg(any(feature = "fuse", feature = "winfsp"))]
use crate::publish::{PublishCoordinator, PublishQueueEntry};
#[cfg(any(feature = "fuse", feature = "winfsp"))]
use crate::runtime::NETWORK_TIMEOUT;

/// The main filesystem struct.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub struct CipherBoxFS {
    pub inodes: crate::inode::InodeTable,
    pub metadata_cache: crate::cache::MetadataCache,
    pub content_cache: crate::cache::ContentCache,
    pub api: Arc<ApiClient>,
    pub private_key: Zeroizing<Vec<u8>>,
    pub public_key: Zeroizing<Vec<u8>>,
    pub root_folder_key: Zeroizing<Vec<u8>>,
    pub root_ipns_name: String,
    pub rt: tokio::runtime::Handle,
    pub next_fh: AtomicU64,
    pub open_files: HashMap<u64, crate::file_handle::OpenFileHandle>,
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
    /// D-09: continuation queue for FilePointer resolve entries that exceeded the
    /// MAX_CONCURRENT_FP_RESOLVES cap. Entries here are drained first on the next
    /// refresh cycle so nothing is silently dropped. Each entry carries its own
    /// parent folder key (`[u8; 32]`) so a drained entry is decrypted with the key
    /// of the folder it originated from, not whatever folder the draining cycle is
    /// refreshing (the two can differ across cycles).
    pub pending_fp_resolves: std::collections::VecDeque<(u64, String, [u8; 32])>,
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
    pub fn get_folder_key(&self, folder_ino: u64) -> Option<Zeroizing<Vec<u8>>> {
        self.inodes
            .get(folder_ino)
            .and_then(|inode| match &inode.kind {
                crate::inode::InodeKind::Root { .. } => {
                    Some(Zeroizing::new(self.root_folder_key.to_vec()))
                }
                crate::inode::InodeKind::Folder { folder_key, .. } => {
                    Some(Zeroizing::new(folder_key.to_vec()))
                }
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
                crate::inode::InodeKind::Root {
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
                crate::inode::InodeKind::Folder {
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
                crate::inode::InodeKind::Folder {
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
                crate::inode::InodeKind::File {
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
        // D-12: wrap owned clones in Zeroizing before passing to spawn_metadata_publish.
        // build_folder_metadata returns .to_vec()/.clone() copies — the inode's own
        // Zeroizing fields are NOT consumed. Ownership-transfer is safe here.
        spawn_metadata_publish(
            self.api.clone(),
            self.rt.clone(),
            metadata,
            Zeroizing::new(folder_key),
            Zeroizing::new(ipns_private_key),
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
                            if let crate::inode::InodeKind::File { ref mut cid, .. } = inode.kind {
                                *cid = result.new_cid.clone();
                            }
                        }
                    }
                    if let Some(inode) = self.inodes.get(result.ino) {
                        if inode.write_generation == result.write_generation {
                            if let Some(plaintext) = self.pending_content.remove(&result.ino) {
                                self.content_cache.set(&result.new_cid, plaintext);
                            }
                            // D-08: unpin pruned CIDs INSIDE the write_generation guard so a
                            // superseded write cannot unpin CIDs the current generation still
                            // references. A stale completion (write_generation mismatch) must
                            // not unpin anything — those CIDs may still be live.
                            for pruned_cid in &result.pruned_cids {
                                let api = self.api.clone();
                                let cid = pruned_cid.clone();
                                self.rt.spawn(async move {
                                    let _ =
                                        cipherbox_api_client::ipfs::unpin_content(&api, &cid)
                                            .await;
                                });
                            }
                        }
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
                    Zeroizing::new(fk), // D-12: wrap owned clone in Zeroizing
                    Zeroizing::new(ipk), // D-12: wrap owned clone in Zeroizing
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
                    crate::inode::InodeKind::Root { .. } => {
                        Some(self.root_folder_key.to_vec())
                    }
                    crate::inode::InodeKind::Folder { folder_key, .. } => {
                        Some(folder_key.to_vec())
                    }
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
                    // Cap concurrent resolution tasks to avoid network thrashing in large folders.
                    // D-09: entries exceeding the cap are pushed onto pending_fp_resolves (a
                    // VecDeque) instead of being silently dropped. The queue is drained first
                    // on each refresh cycle so nothing is lost between cycles.
                    const MAX_CONCURRENT_FP_RESOLVES: usize = 10;
                    let mut spawned = 0;

                    // Drain pending_fp_resolves first (entries that overflowed in a prior cycle).
                    // Each carries the folder key of the folder it originated from.
                    let mut pending_drain: Vec<(u64, String, [u8; 32])> = Vec::new();
                    while let Some(entry) = self.pending_fp_resolves.pop_front() {
                        if self.resolving_file_pointers.contains(&entry.0) {
                            continue; // Already in-flight from a prior cycle
                        }
                        if spawned >= MAX_CONCURRENT_FP_RESOLVES {
                            // Still over cap — put it back at the front and stop draining
                            self.pending_fp_resolves.push_front(entry);
                            break;
                        }
                        pending_drain.push(entry);
                        spawned += 1;
                    }

                    // Build the full list of entries to spawn: drained-from-queue first,
                    // then fresh unresolved entries (up to the remaining cap). Fresh entries
                    // belong to the folder being refreshed this cycle, so they carry fk_arr.
                    // Entries exceeding the cap are pushed onto pending_fp_resolves with fk_arr.
                    for (fp_ino, fp_ipns) in unresolved {
                        if self.resolving_file_pointers.contains(&fp_ino) {
                            continue; // Already in-flight
                        }
                        if spawned >= MAX_CONCURRENT_FP_RESOLVES {
                            // D-09: push to continuation queue instead of silent drop.
                            self.pending_fp_resolves.push_back((fp_ino, fp_ipns, fk_arr));
                            continue;
                        }
                        pending_drain.push((fp_ino, fp_ipns, fk_arr));
                        spawned += 1;
                    }

                    // Spawn tasks for all entries collected (drained queue + fresh, up to cap).
                    // Each entry decrypts with its OWN folder key (entry_fk), not the current
                    // cycle's fk_arr — drained entries may come from a different parent folder.
                    for (fp_ino, fp_ipns, entry_fk) in pending_drain {
                        self.resolving_file_pointers.insert(fp_ino);
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
                                    &enc_bytes, &entry_fk,
                                )
                            })
                            .await;

                            match result {
                                Ok(Ok(fm)) => {
                                    log::debug!(
                                        "FilePointer async resolved for ino {} (cid={})",
                                        fp_ino,
                                        &fm.cid[..fm.cid.len().min(12)]
                                    );
                                    let _ = tx.send(PendingFilePointer::Success {
                                        ino: fp_ino,
                                        cid: fm.cid,
                                        encrypted_file_key: fm.file_key_encrypted,
                                        iv: fm.file_iv,
                                        size: fm.size,
                                        encryption_mode: fm.encryption_mode,
                                        versions: fm.versions,
                                    });
                                }
                                Ok(Err(e)) => {
                                    log::warn!(
                                        "FilePointer resolve failed for ino {}: {}",
                                        fp_ino,
                                        e
                                    );
                                    let _ = tx.send(PendingFilePointer::Failure { ino: fp_ino });
                                }
                                Err(_) => {
                                    log::warn!(
                                        "FilePointer resolve timed out for ino {} ({}s)",
                                        fp_ino,
                                        NETWORK_TIMEOUT.as_secs()
                                    );
                                    let _ = tx.send(PendingFilePointer::Failure { ino: fp_ino });
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
