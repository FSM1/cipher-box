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
    /// node/v3 anti-rollback high-water gate (69-16/69-17). Persists the
    /// per-IPNS generation + sequence floors to JSON sidecars adjacent to the
    /// write journal, so `list_folder_owned` fails closed on a stale/rolled-back
    /// record. Constructed via `cipherbox_sdk::new_journal_high_water(<journal_dir>)`.
    ///
    /// NOTE (69-09 Slice 1): the node fetcher is intentionally NOT a stored
    /// field. `cipherbox_sdk::ApiNodeFetcher<'a>` borrows `&'a ApiClient`;
    /// storing it alongside the owned `api: Arc<ApiClient>` would be a
    /// self-referential struct. Read-path call sites (Slice 2) construct
    /// `ApiNodeFetcher { api: &self.api }` inline instead.
    pub high_water: cipherbox_sdk::RotationHighWater<cipherbox_sdk::JsonSidecarFloorStore>,
    /// Local cache of the authenticated user's sent shares (grant-root
    /// awareness, SC#3 / 69-07). Refreshed out-of-band via
    /// [`CipherBoxFS::refresh_sent_shares`] — mount init / periodic, NEVER a
    /// per-mutation network call (Pitfall 2 / T-69-07-01). Delete/rename
    /// scope-exit checks (69-11/69-14) read this synchronously via
    /// `crate::write_ops::grant_scope::build_coverage_params`.
    pub sent_shares: std::sync::RwLock<crate::write_ops::grant_scope::SentSharesCache>,
}

#[cfg(any(feature = "fuse", feature = "winfsp"))]
impl CipherBoxFS {
    /// Refresh the local sent-shares cache from the relay
    /// (`GET /shares/sent`, paginated via `collect_sent_shares`, 69-03).
    ///
    /// Intended call sites: mount init and a periodic background refresh —
    /// NEVER the delete/rename hot path (Pitfall 2 / T-69-07-01). Grant-root
    /// scope-exit checks read the resulting cache synchronously through
    /// `sent_shares` (see `write_ops::grant_scope::build_coverage_params`).
    pub async fn refresh_sent_shares(&self) -> Result<(), cipherbox_api_client::ApiError> {
        let cache = crate::write_ops::grant_scope::refresh_sent_shares(&self.api).await?;
        *self.sent_shares.write().expect("sent_shares lock poisoned") = cache;
        Ok(())
    }

    pub fn get_folder_key(&self, folder_ino: u64) -> Option<Zeroizing<Vec<u8>>> {
        self.inodes
            .get(folder_ino)
            .and_then(|inode| match &inode.kind {
                crate::inode::InodeKind::Root { .. } => {
                    Some(Zeroizing::new(self.root_folder_key.to_vec()))
                }
                // node/v3 (69-09): the folder's symmetric readKey replaces the
                // legacy `folder_key` (node-to-node key).
                crate::inode::InodeKind::Folder { read_key, .. } => {
                    Some(Zeroizing::new(read_key.to_vec()))
                }
                _ => None,
            })
    }

    /// Re-seal a folder/root node as a node/v3 `PublishedNode` from the current
    /// inode-table state (69-09 Slice 3 write emission).
    ///
    /// Splices EVERY child into BOTH planes (D-07): a read-plane `SealedChildRef`
    /// (child readKey sealed under the parent readKey, keyed by ipnsName) and a
    /// write-plane `WriteChildRef` (child writeKey sealed under the parent
    /// writeKey, keyed by `child_id = uuid_from_ino(child_ino)`). The child node
    /// itself is sealed with the SAME `uuid_from_ino` id (see the write helpers),
    /// so a reader recovering `child_id` from the resolved node round-trips the
    /// AAD. Returns the encoded `PublishedNode` bytes ready for IPFS upload, plus
    /// the parent's signing seed + ipns name + previous CID (for the publish).
    ///
    /// Legacy `FolderMetadata`/`FolderEntry`/`FilePointer` emission is GONE — the
    /// node-to-node keys now live ONLY inside the symmetric seals (crypto rule #7
    /// / NODE-06). The former per-child user-ECIES `wrap_key` hops are removed.
    pub fn build_folder_metadata(
        &self,
        folder_ino: u64,
    ) -> Result<(Vec<u8>, Vec<u8>, String, Option<String>), String> {
        use cipherbox_core::node::{
            encode_published_node, seal::seal_published_node, Node, NodeKind, NodeWriteBody,
            SealedChildRef, WriteChildRef,
        };

        let (parent_read_key, parent_write_key, ipns_private_key, ipns_name, is_root, child_inos) = {
            let inode = self
                .inodes
                .get(folder_ino)
                .ok_or_else(|| format!("Folder inode {} not found", folder_ino))?;
            let children = inode.children.clone().unwrap_or_default();
            match &inode.kind {
                crate::inode::InodeKind::Root {
                    read_key,
                    write_key,
                    ipns_private_key,
                    ipns_name,
                    ..
                } => (
                    **read_key,
                    **write_key,
                    ipns_private_key.to_vec(),
                    ipns_name.clone(),
                    true,
                    children,
                ),
                crate::inode::InodeKind::Folder {
                    read_key,
                    write_key,
                    ipns_private_key,
                    ipns_name,
                    ..
                } => (
                    **read_key,
                    **write_key,
                    ipns_private_key.to_vec(),
                    ipns_name.clone(),
                    false,
                    children,
                ),
                _ => return Err("Cannot update metadata for non-folder inode".to_string()),
            }
        };

        let mut sealed_children: Vec<SealedChildRef> = Vec::new();
        let mut write_children: Vec<WriteChildRef> = Vec::new();
        for &child_ino in &child_inos {
            let child = self
                .inodes
                .get(child_ino)
                .ok_or_else(|| format!("Child inode {} not found", child_ino))?;
            let (kind, child_ipns, child_read_key, child_write_key) = match &child.kind {
                crate::inode::InodeKind::Folder {
                    ipns_name,
                    read_key,
                    write_key,
                    ..
                } => (NodeKind::Folder, ipns_name.clone(), **read_key, **write_key),
                crate::inode::InodeKind::File {
                    ipns_name,
                    read_key,
                    write_key,
                    ..
                } => (NodeKind::File, ipns_name.clone(), **read_key, **write_key),
                _ => continue,
            };
            // Skip children with no IPNS identity yet (e.g. a freshly-created,
            // never-published file): nothing to link into the read chain.
            if child_ipns.is_empty() {
                continue;
            }
            let child_id = uuid_from_ino(child_ino);
            let (sealed_ref, write_ref) = cipherbox_sdk::build_child_refs(
                &child_read_key,
                &child_write_key,
                &parent_read_key,
                &parent_write_key,
                &child_id,
                &child_ipns,
                &child.name,
                kind,
                0,
                0,
            )
            .map_err(|e| format!("build_child_refs failed for child {}: {}", child_ino, e))?;
            sealed_children.push(sealed_ref);
            write_children.push(write_ref);
        }

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let node_id = uuid_from_ino(folder_ino);
        let node = if is_root {
            Node::Root {
                id: node_id,
                generation: 0,
                created_at: now_ms,
                modified_at: now_ms,
                children: sealed_children,
            }
        } else {
            Node::Folder {
                id: node_id,
                generation: 0,
                created_at: now_ms,
                modified_at: now_ms,
                children: sealed_children,
            }
        };
        let write_body = NodeWriteBody {
            ipns_private_key: ipns_private_key.clone(),
            write_children,
        };
        let published = seal_published_node(
            &node,
            &parent_read_key,
            &parent_write_key,
            Some(&write_body),
        )
        .map_err(|e| format!("seal_published_node failed for {}: {}", folder_ino, e))?;
        let published_bytes = encode_published_node(&published)
            .map_err(|e| format!("encode_published_node failed for {}: {}", folder_ino, e))?;

        let old_cid = self.metadata_cache.get(&ipns_name).map(|c| c.cid.clone());
        Ok((published_bytes, ipns_private_key, ipns_name, old_cid))
    }

    pub fn update_folder_metadata(&mut self, folder_ino: u64) -> Result<(), String> {
        self.mutated_folders
            .insert(folder_ino, std::time::Instant::now());
        let (published_node, ipns_private_key, ipns_name, old_cid) =
            self.build_folder_metadata(folder_ino)?;
        // D-12: wrap the owned signing-seed clone in Zeroizing before passing to
        // spawn_metadata_publish. build_folder_metadata returns owned copies — the
        // inode's own Zeroizing fields are NOT consumed. node/v3: the sealed
        // `published_node` bytes are uploaded verbatim (no folder_key needed by the
        // publisher; sealing already happened in build_folder_metadata).
        spawn_metadata_publish(
            self.api.clone(),
            self.rt.clone(),
            published_node,
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
                                        cipherbox_api_client::ipfs::unpin_content(&api, &cid).await;
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
                Ok((published_node, ipk, in_, oc)) => spawn_metadata_publish(
                    self.api.clone(),
                    self.rt.clone(),
                    published_node,
                    Zeroizing::new(ipk), // D-12: wrap owned signing-seed clone in Zeroizing
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
            let (ino, ipns_name, children) = match refresh {
                PendingRefresh::Success {
                    ino,
                    ipns_name,
                    children,
                } => (ino, ipns_name, children),
                PendingRefresh::Failure { ipns_name } => {
                    self.refreshing_metadata.remove(&ipns_name);
                    continue;
                }
            };
            self.refreshing_metadata.remove(&ipns_name);
            // node/v3 (69-09 Slice 5b(d)): the cache is now a pure freshness marker
            // (no metadata payload); record the refresh so staleness checks skip a
            // re-spawn within the TTL. The old-CID for unpin is not surfaced by the
            // gated owned resolve, so pass an empty cid (best-effort — E2E flag:
            // stale parent metadata CIDs may accumulate as GC-able orphan pins).
            self.metadata_cache.set(&ipns_name, String::new());
            if self.mutated_folders.contains_key(&ino) || self.publish_queue.contains_key(&ino) {
                // This folder has pending local mutations/publishes. Do NOT rebuild
                // its structure from remote metadata -- that would clobber the local
                // change with stale remote state before our own publish propagates
                // (folder-state desync). But a *remote* file edit (newer modified_at)
                // arriving in this same window must still surface, so mark only those
                // genuine remote edits for re-resolution -- local mutations (local
                // mtime >= remote) are left untouched -- then fall through to the
                // shared resolution-spawn block below.
                self.inodes
                    .mark_remotely_edited_files_unresolved(ino, &children);
            } else {
                // Synchronous apply of the owned children the background task
                // already fetched (async-fetch / sync-apply split).
                self.inodes.apply_owned_children(ino, children, true);
            }
            // Spawn async resolution for unresolved FilePointers in this folder.
            // Covers both the freshly-populated path and the locally-mutating
            // remote-edit path (marked just above).
            let unresolved = self.inodes.get_unresolved_file_pointers_for_parent(ino);
            if !unresolved.is_empty() {
                // Cap concurrent resolution tasks to avoid network thrashing in large folders.
                // D-09: entries exceeding the cap are pushed onto pending_fp_resolves (a
                // VecDeque) instead of being silently dropped. The queue is drained first
                // on each refresh cycle so nothing is lost between cycles.
                const MAX_CONCURRENT_FP_RESOLVES: usize = 10;
                let mut spawned = 0;
                // Inodes staged or re-queued THIS cycle. resolving_file_pointers is only
                // updated in the spawn loop below (after both passes), so without this a
                // drained entry and the same still-unresolved fresh entry would both be
                // staged → two resolve tasks racing on one inode. Also prevents re-queueing
                // an inode already sitting in pending_fp_resolves.
                let mut scheduled_this_cycle = std::collections::HashSet::<u64>::new();

                // Drain pending_fp_resolves first (entries that overflowed in a prior cycle).
                // node/v3: each carries the FILE's own symmetric read_key (5b(d)).
                let mut pending_drain: Vec<(u64, String, [u8; 32])> = Vec::new();
                while let Some(entry) = self.pending_fp_resolves.pop_front() {
                    if self.resolving_file_pointers.contains(&entry.0)
                        || !scheduled_this_cycle.insert(entry.0)
                    {
                        continue; // Already in-flight, or already drained this cycle
                    }
                    if spawned >= MAX_CONCURRENT_FP_RESOLVES {
                        // Still over cap — put it back at the front and stop draining
                        scheduled_this_cycle.remove(&entry.0);
                        self.pending_fp_resolves.push_front(entry);
                        break;
                    }
                    pending_drain.push(entry);
                    spawned += 1;
                }

                // Build the full list of entries to spawn: drained-from-queue first,
                // then fresh unresolved entries (up to the remaining cap). Each fresh
                // file carries its OWN node/v3 read_key (recovered from the inode).
                // Entries exceeding the cap are pushed onto pending_fp_resolves.
                for (fp_ino, fp_ipns) in unresolved {
                    if self.resolving_file_pointers.contains(&fp_ino)
                        || scheduled_this_cycle.contains(&fp_ino)
                    {
                        continue; // Already in-flight, or already staged/queued this cycle
                    }
                    // node/v3: recover this file's OWN symmetric read_key to unseal its
                    // node read-body. Skip if the inode is gone or not a file.
                    let read_key = match self.inodes.get(fp_ino).map(|i| &i.kind) {
                        Some(crate::inode::InodeKind::File { read_key, .. }) => **read_key,
                        _ => continue,
                    };
                    if spawned >= MAX_CONCURRENT_FP_RESOLVES {
                        // D-09: push to continuation queue instead of silent drop.
                        scheduled_this_cycle.insert(fp_ino);
                        self.pending_fp_resolves
                            .push_back((fp_ino, fp_ipns, read_key));
                        continue;
                    }
                    scheduled_this_cycle.insert(fp_ino);
                    pending_drain.push((fp_ino, fp_ipns, read_key));
                    spawned += 1;
                }

                // Spawn tasks for all entries collected (drained queue + fresh, up to cap).
                // Each entry unseals with its OWN file read_key via the gated single-node
                // fetch (SC#6, resolve_file_descriptors → fetch_node_gated) — no raw resolve.
                for (fp_ino, fp_ipns, entry_read_key) in pending_drain {
                    self.resolving_file_pointers.insert(fp_ino);
                    let api = self.api.clone();
                    let tx = self.filepointer_tx.clone();
                    // Owned high-water clone for the spawned resolve task (5b(a)).
                    let high_water = self.high_water.clone();
                    self.rt.spawn(async move {
                        let result = tokio::time::timeout(
                            NETWORK_TIMEOUT,
                            crate::content_ops::resolve_file_descriptors(
                                &api,
                                &high_water,
                                &fp_ipns,
                                &entry_read_key,
                            ),
                        )
                        .await;

                        match result {
                            Ok(Ok((cid, iv, size, encryption_mode))) => {
                                log::debug!(
                                    "FilePointer async resolved for ino {} (cid={})",
                                    fp_ino,
                                    &cid[..cid.len().min(12)]
                                );
                                let _ = tx.send(PendingFilePointer::Success {
                                    ino: fp_ino,
                                    cid,
                                    iv,
                                    size,
                                    encryption_mode,
                                });
                            }
                            Ok(Err(e)) => {
                                log::warn!("FilePointer resolve failed for ino {}: {}", fp_ino, e);
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
                    iv,
                    size,
                    encryption_mode,
                } => {
                    self.resolving_file_pointers.remove(&ino);
                    self.inodes
                        .resolve_file_pointer(ino, cid, iv, size, encryption_mode);
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

/// Derive a stable, deterministic node UUID from an inode number.
///
/// node/v3 (69-09): this is the CANONICAL node id used across the write path.
/// A child node is sealed with `id = uuid_from_ino(child_ino)` and the parent's
/// `SealedChildRef`/`WriteChildRef` are built with the same `child_id`, so the
/// read path (which recovers `child_id` from the resolved node's own `id`)
/// round-trips the AAD-bound seals. The value is a valid RFC-4122 v4-shaped
/// hyphenated UUID (D-07 write plane keyed by this UUID; read plane by ipnsName).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub(crate) fn uuid_from_ino(ino: u64) -> String {
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

/// Tests for `drain_refresh_completions` — the IPNS-refresh apply path and the
/// cross-client re-resolution fix (PR #558).
///
/// These drive the synchronous bookkeeping directly: a `PendingRefresh` is pushed
/// onto `refresh_tx`, `drain_refresh_completions()` is called, and the resulting
/// inode/cache/queue state is asserted. The per-file resolution task the drain
/// spawns is fire-and-forget and is never polled (the `#[tokio::test]` body does
/// not await after the drain, and the API host is unroutable), so only the
/// synchronous effects — which is exactly the patch under test — are observed.
#[cfg(all(test, feature = "fuse"))]
mod drain_refresh_completions_tests {
    use crate::events::PendingRefresh;
    use crate::inode::{FileAttrs, InodeData, InodeKind, ROOT_INO};
    use crate::test_support::make_test_fs;
    use std::time::{Duration, UNIX_EPOCH};
    use zeroize::Zeroizing;

    const FILE_IPNS: &str = "k51file-cross-client";
    const ROOT_IPNS: &str = "k51test-root";

    /// Insert a resolved `hello.txt` File child of root with mtime `mtime_ms`.
    fn insert_resolved_file(fs: &mut crate::CipherBoxFS, mtime_ms: u64) -> u64 {
        let ino = fs.inodes.allocate_ino();
        let mtime = UNIX_EPOCH + Duration::from_millis(mtime_ms);
        fs.inodes.insert(InodeData {
            ino,
            parent_ino: ROOT_INO,
            name: "hello.txt".to_string(),
            kind: InodeKind::File {
                cid: "bafyOLDcid".to_string(),
                encrypted_file_key: "deadbeef".to_string(),
                iv: "aabbccdd".to_string(),
                size: 42,
                encryption_mode: "GCM".to_string(),
                file_meta_ipns_name: Some(FILE_IPNS.to_string()),
                file_meta_resolved: true,
                file_ipns_private_key: Some(Zeroizing::new(vec![3u8; 32])),
                file_ipns_key_encrypted_hex: Some("abcd".to_string()),
                versions: None,
            },
            attr: FileAttrs {
                ino,
                size: 42,
                blocks: 1,
                atime: mtime,
                mtime,
                ctime: mtime,
                crtime: mtime,
                is_dir: false,
                perm: 0o644,
                nlink: 1,
            },
            children: None,
            write_generation: 0,
        });
        if let Some(root) = fs.inodes.get_mut(ROOT_INO) {
            root.children.get_or_insert_with(Vec::new).push(ino);
        }
        ino
    }

    /// Folder metadata listing `hello.txt` at the same IPNS identity with the
    /// given `modified_at`.
    fn refresh_metadata(file_mtime_ms: u64) -> cipherbox_core::FolderMetadata {
        cipherbox_core::FolderMetadata {
            version: "v2".to_string(),
            children: vec![cipherbox_core::FolderChild::File(
                cipherbox_core::FilePointer {
                    id: "file-1".to_string(),
                    name: "hello.txt".to_string(),
                    file_meta_ipns_name: FILE_IPNS.to_string(),
                    ipns_private_key_encrypted: None,
                    created_at: 1700000000000,
                    modified_at: file_mtime_ms,
                },
            )],
        }
    }

    fn is_unresolved(fs: &crate::CipherBoxFS, ino: u64) -> bool {
        matches!(
            &fs.inodes.get(ino).unwrap().kind,
            InodeKind::File {
                file_meta_resolved: false,
                cid,
                ..
            } if cid.is_empty()
        )
    }

    fn send_refresh(fs: &crate::CipherBoxFS, metadata: cipherbox_core::FolderMetadata) {
        fs.refresh_tx
            .send(PendingRefresh::Success {
                ino: ROOT_INO,
                ipns_name: ROOT_IPNS.to_string(),
                metadata,
                cid: "bafyREFRESHcid".to_string(),
            })
            .unwrap();
    }

    /// Gated branch (folder mid local-publish): a strictly-newer remote edit is
    /// flipped to unresolved WITHOUT a full populate_folder, and the fall-through
    /// spawn block enqueues it for resolution. Remote metadata is still cached.
    #[tokio::test]
    async fn gated_marks_remote_edit_and_spawns_resolution() {
        let mut fs = make_test_fs();
        let file_ino = insert_resolved_file(&mut fs, 1700000000000);
        fs.mutated_folders
            .insert(ROOT_INO, std::time::Instant::now());

        send_refresh(&fs, refresh_metadata(1700001000000));
        fs.drain_refresh_completions();

        assert!(
            is_unresolved(&fs, file_ino),
            "remote edit marked unresolved"
        );
        assert!(
            fs.resolving_file_pointers.contains(&file_ino),
            "fall-through spawn must enqueue the marked file for resolution"
        );
        assert!(
            fs.metadata_cache.get(ROOT_IPNS).is_some(),
            "remote metadata is cached even on the gated path"
        );
    }

    /// Gated branch must NOT clobber a pending local mutation: the local inode is
    /// newer than the (stale) remote refresh, so it stays resolved and is not
    /// queued for re-resolution.
    #[tokio::test]
    async fn gated_preserves_pending_local_mutation() {
        let mut fs = make_test_fs();
        let file_ino = insert_resolved_file(&mut fs, 1700001000000); // local is newer
        fs.mutated_folders
            .insert(ROOT_INO, std::time::Instant::now());

        send_refresh(&fs, refresh_metadata(1700000000000)); // older remote
        fs.drain_refresh_completions();

        assert!(
            !is_unresolved(&fs, file_ino),
            "local mutation must stay resolved (not clobbered by stale remote)"
        );
        assert!(
            !fs.resolving_file_pointers.contains(&file_ino),
            "older remote must not trigger re-resolution of a local mutation"
        );
    }

    /// Non-gated branch (no pending local mutation): the full populate_folder path
    /// runs, applying the remote modified_at change, then the shared spawn block
    /// enqueues the file for resolution.
    #[tokio::test]
    async fn unmutated_populates_and_spawns_resolution() {
        let mut fs = make_test_fs();
        let file_ino = insert_resolved_file(&mut fs, 1700000000000);
        // No mutated_folders / publish_queue entry -> non-gated populate_folder path.

        send_refresh(&fs, refresh_metadata(1700001000000));
        fs.drain_refresh_completions();

        assert!(
            is_unresolved(&fs, file_ino),
            "populate_folder applies the remote edit and marks unresolved"
        );
        assert!(fs.resolving_file_pointers.contains(&file_ino));
        assert!(fs.metadata_cache.get(ROOT_IPNS).is_some());
    }

    /// A `PendingRefresh::Failure` clears the in-flight `refreshing_metadata`
    /// guard and applies no inode/cache changes.
    #[tokio::test]
    async fn failure_clears_refreshing_guard() {
        let mut fs = make_test_fs();
        fs.refreshing_metadata.insert(ROOT_IPNS.to_string());

        fs.refresh_tx
            .send(PendingRefresh::Failure {
                ipns_name: ROOT_IPNS.to_string(),
            })
            .unwrap();
        fs.drain_refresh_completions();

        assert!(
            !fs.refreshing_metadata.contains(ROOT_IPNS),
            "Failure must clear the in-flight refresh guard"
        );
        assert!(
            fs.metadata_cache.get(ROOT_IPNS).is_none(),
            "Failure applies no cache write"
        );
    }
}
