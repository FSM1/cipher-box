//! Shared IPNS prepopulate logic for macOS (fuse) and Windows (winfsp) mounts.
//!
//! Both `fuse/mod.rs` (macOS) and `fuse/windows/mod.rs` (Windows) mounts warm
//! the inode table at mount time: they resolve the root node, pre-populate the
//! root inode's children, and recursively pre-populate immediate subfolders so
//! the first `readdir` is instant. This module holds that single shared block.
//!
//! # node/v3 (69-09 Slice 5c)
//!
//! The legacy `FolderMetadata` + per-child ECIES + `resolve_ipns_verified` block
//! was replaced by the gated node/v3 owned-listing path:
//!   - `InodeTable::populate_folder` internally routes through
//!     `cipherbox_sdk::list_folder_owned` (SC#6 single gated read) and fills each
//!     child `InodeKind` with the recovered `{read_key, write_key,
//!     ipns_private_key}` (D-09 terminal owner — keys moved in, never zeroed here).
//!   - File descriptors (cid/iv/size/mode) live inside each file node's OWN
//!     sealed read-body and are recovered eagerly here via
//!     `content_ops::resolve_file_descriptors` (also gated, SC#6), then written
//!     back with `resolve_file_pointer`. Files left unresolved on failure are
//!     retried lazily by the FUSE loop (`get_unresolved_file_pointers`).
//!
//! Sequence-number seeding of the `PublishCoordinator` is no longer sourced here:
//! the node/v3 owned listing does not surface IPNS sequence numbers, and the
//! coordinator now records sequences as publishes happen (first publish embeds
//! seq 1). `prepopulate_filesystem` therefore returns an empty `initial_sequences`
//! vector, preserved as the return type for caller compatibility.

#[cfg(any(feature = "fuse", feature = "winfsp"))]
use cipherbox_fuse::inode::{InodeKind, InodeTable, ROOT_INO};

/// Warm the inode table from the root node's gated owned listing (node/v3).
///
/// Populates the root inode's children and every immediate subfolder, eagerly
/// resolving file descriptors. `root_read_key`/`root_write_key` are the root
/// node's symmetric node/v3 keys (caller-owned borrows, D-09). Returns an empty
/// `initial_sequences` vector (see module docs).
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub async fn prepopulate_filesystem(
    api: &std::sync::Arc<cipherbox_api_client::ApiClient>,
    inodes: &mut InodeTable,
    high_water: &cipherbox_sdk::RotationHighWater<cipherbox_sdk::JsonSidecarFloorStore>,
    root_ipns_name: &str,
    root_read_key: &[u8; 32],
    root_write_key: &[u8; 32],
) -> Vec<(String, u64)> {
    let initial_sequences: Vec<(String, u64)> = Vec::new();

    log::info!("Pre-populating root folder from IPNS (node/v3)...");

    // ── Populate root children via the gated owned listing (SC#6) ──────────
    if let Err(e) = inodes
        .populate_folder(
            ROOT_INO,
            root_ipns_name,
            root_read_key,
            root_write_key,
            api.as_ref(),
            high_water,
            false,
        )
        .await
    {
        log::warn!("Root folder populate failed (mount will show empty): {}", e);
        return initial_sequences;
    }
    log::info!("Root folder pre-populated successfully");

    // Eagerly resolve root-level file descriptors (each via its OWN read key).
    resolve_parent_file_pointers(api.as_ref(), inodes, high_water, ROOT_INO).await;

    // ── Pre-populate immediate subfolders ──────────────────────────────────
    // Snapshot (ino, ipns_name, read_key, write_key) for each root-level folder
    // before the mutating populate loop (avoids holding an inode borrow across
    // the async populate calls).
    let subfolder_infos: Vec<(u64, String, [u8; 32], [u8; 32])> = inodes
        .inodes
        .values()
        .filter_map(|inode| {
            if inode.parent_ino != ROOT_INO {
                return None;
            }
            match &inode.kind {
                InodeKind::Folder {
                    ipns_name,
                    read_key,
                    write_key,
                    ..
                } => Some((inode.ino, ipns_name.clone(), **read_key, **write_key)),
                _ => None,
            }
        })
        .collect();

    for (sub_ino, sub_ipns, sub_read_key, sub_write_key) in &subfolder_infos {
        log::info!("Pre-populating subfolder ino={} ipns={}", sub_ino, sub_ipns);
        match inodes
            .populate_folder(
                *sub_ino,
                sub_ipns,
                sub_read_key,
                sub_write_key,
                api.as_ref(),
                high_water,
                false,
            )
            .await
        {
            Ok(()) => {
                log::info!("Subfolder ino={} pre-populated", sub_ino);
                resolve_parent_file_pointers(api.as_ref(), inodes, high_water, *sub_ino).await;
            }
            Err(e) => log::warn!("Subfolder ino={} populate failed: {}", sub_ino, e),
        }
    }

    initial_sequences
}

/// Eagerly resolve the file descriptors (cid/iv/size/mode) of every unresolved
/// File inode under `parent_ino` via the gated single-node fetch (SC#6). Files
/// that fail here are left unresolved (empty cid) and retried lazily by the
/// FUSE loop. Each file unseals its own node read-body with its OWN read key.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
async fn resolve_parent_file_pointers(
    api: &cipherbox_api_client::ApiClient,
    inodes: &mut InodeTable,
    high_water: &cipherbox_sdk::RotationHighWater<cipherbox_sdk::JsonSidecarFloorStore>,
    parent_ino: u64,
) {
    let unresolved = inodes.get_unresolved_file_pointers_for_parent(parent_ino);
    if unresolved.is_empty() {
        return;
    }
    log::info!(
        "Resolving {} FilePointer(s) under ino={}...",
        unresolved.len(),
        parent_ino
    );
    for (fp_ino, fp_ipns) in unresolved {
        // Recover this file's OWN symmetric read key from its inode.
        let read_key = match inodes.get(fp_ino).map(|i| &i.kind) {
            Some(InodeKind::File { read_key, .. }) => **read_key,
            _ => continue,
        };
        match cipherbox_fuse::content_ops::resolve_file_descriptors(
            api, high_water, &fp_ipns, &read_key,
        )
        .await
        {
            Ok((cid, iv, size, encryption_mode)) => {
                inodes.resolve_file_pointer(fp_ino, cid, iv, size, encryption_mode);
            }
            Err(e) => log::warn!("FilePointer resolve failed for ino {}: {}", fp_ino, e),
        }
    }
}
