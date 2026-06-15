//! Filesystem module for CipherBox Desktop.
//!
//! Thin bridge between the Tauri application and cipherbox-fuse crate.
//! All FUSE data structures, operations, and platform logic live in the crate.
//! This module handles Tauri-specific mount orchestration (AppState -> CipherBoxFS).

// Re-export crate types and functions used by desktop FUSE submodules.
// These are consumed via `crate::fuse::inode::*`, `crate::fuse::helpers::*`, etc.
#[allow(unused_imports)]
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub use cipherbox_fuse::{
    CipherBoxFS, PublishCoordinator, PendingRefresh, PendingContent, PendingFilePointer, UploadComplete,
    encrypt_metadata_to_json, spawn_bin_entry_publish, mount_point,
};

#[allow(unused_imports)]
pub use cipherbox_fuse::inode;
#[allow(unused_imports)]
pub use cipherbox_fuse::cache;
#[allow(unused_imports)]
pub use cipherbox_fuse::file_handle;
#[allow(unused_imports)]
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub use cipherbox_fuse::helpers;
#[allow(unused_imports)]
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub use cipherbox_fuse::constants;
#[cfg(feature = "winfsp")]
pub mod windows;

#[cfg(feature = "winfsp")]
pub use windows::mount_filesystem;
#[cfg(feature = "winfsp")]
pub use windows::unmount_filesystem;

#[cfg(feature = "fuse")]
use fuser::MountOption;
#[cfg(any(feature = "fuse", feature = "winfsp"))]
use std::sync::Arc;
#[cfg(any(feature = "fuse", feature = "winfsp"))]
use zeroize::Zeroizing;
#[cfg(any(feature = "fuse", feature = "winfsp"))]
use std::collections::HashMap;

#[cfg(any(feature = "fuse", feature = "winfsp"))]
use crate::state::AppState;

/// Maximum retry count for journal entries before they are parked as `Failed`.
///
/// Both the FUSE mount path and the sync daemon pass this value to `WriteQueue::new`.
/// Defined once here so the two call sites cannot silently drift.
pub const JOURNAL_MAX_RETRIES: u32 = 5;

/// Return the canonical on-disk journal directory for this installation.
///
/// Resolves to `<data_local_dir>/cipherbox/cb-journal` with a `temp_dir` fallback
/// when `data_local_dir` is unavailable. The resolved path is identical to the
/// inline chain previously duplicated in `fuse/mod.rs` and `commands/sync.rs`.
///
/// **Note:** This function only constructs the `PathBuf`; callers are responsible
/// for calling `std::fs::create_dir_all` and applying `0o700` permissions.
pub fn default_journal_dir() -> std::path::PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| {
            log::warn!("data_local_dir unavailable; journal will use temp_dir (may not survive reboot)");
            std::env::temp_dir()
        })
        .join("cipherbox")
        .join("cb-journal")
}

/// Mount the FUSE filesystem after successful authentication (macOS/Linux).
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
    max_versions_per_file: usize,
    version_cooldown_ms: u64,
) -> Result<std::thread::JoinHandle<()>, String> {
    let mount_path = mount_point();

    if mount_path.is_symlink() {
        return Err("Mount point is a symlink -- refusing to proceed".to_string());
    }

    // Linux-only: a crash can leave the mount path as a disconnected/stale FUSE
    // mount where stat() returns ENOTCONN, so `exists()` lies (returns false)
    // and `create_dir_all` then fails with EEXIST. Authoritatively detect the
    // stale mount via /proc/self/mountinfo and unmount it before the create /
    // clean-stale decision below. Best-effort; never blocks the mount.
    #[cfg(target_os = "linux")]
    cipherbox_fuse::platform::linux::recover_stale_mount(&mount_path);

    if !mount_path.exists() {
        if let Err(e) = std::fs::create_dir_all(&mount_path) {
            // Belt-and-suspenders for the Linux stale-mount case: a disconnected
            // FUSE mount whose dirent still exists surfaces as EEXIST even though
            // `exists()` returned false. Recover once and retry before erroring.
            #[cfg(target_os = "linux")]
            if cipherbox_fuse::platform::linux::should_recover_then_retry(e.kind()) {
                cipherbox_fuse::platform::linux::recover_stale_mount(&mount_path);
                std::fs::create_dir_all(&mount_path)
                    .map_err(|e| format!("Failed to create mount point: {}", e))?;
            } else {
                return Err(format!("Failed to create mount point: {}", e));
            }
            #[cfg(not(target_os = "linux"))]
            return Err(format!("Failed to create mount point: {}", e));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&mount_path, std::fs::Permissions::from_mode(0o700));
        }
    } else {
        if let Ok(entries) = std::fs::read_dir(&mount_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() { let _ = std::fs::remove_dir_all(&path); }
                else { let _ = std::fs::remove_file(&path); }
            }
            log::info!("Cleaned stale mount point: {}", mount_path.display());
        }
    }

    #[cfg(target_os = "macos")]
    {
        let never_index = mount_path.join(".metadata_never_index");
        if !never_index.exists() { let _ = std::fs::File::create(&never_index); }
    }

    let temp_dir = std::env::temp_dir().join("cipherbox");
    std::fs::create_dir_all(&temp_dir).map_err(|e| format!("Failed to create temp directory: {}", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&temp_dir, std::fs::Permissions::from_mode(0o700));
    }

    // Stable journal dir: persists across remounts so entries survive crash/restart.
    let journal_dir = default_journal_dir();
    std::fs::create_dir_all(&journal_dir)
        .map_err(|e| format!("Failed to create journal directory: {}", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&journal_dir, std::fs::Permissions::from_mode(0o700));
    }
    let journal = cipherbox_sdk::WriteQueue::new(journal_dir, JOURNAL_MAX_RETRIES);

    let mut inodes = cipherbox_fuse::inode::InodeTable::new();
    if let Some(root) = inodes.get_mut(cipherbox_fuse::inode::ROOT_INO) {
        root.kind = cipherbox_fuse::inode::InodeKind::Root {
            ipns_private_key: root_ipns_private_key.map(Zeroizing::new),
            ipns_name: Some(root_ipns_name.clone()),
        };
    }

    let (refresh_tx, refresh_rx) = std::sync::mpsc::channel::<PendingRefresh>();
    let (content_tx, content_rx) = std::sync::mpsc::channel::<PendingContent>();
    let (filepointer_tx, filepointer_rx) = std::sync::mpsc::channel::<PendingFilePointer>();
    let (upload_tx, upload_rx) = std::sync::mpsc::channel::<cipherbox_fuse::FsEvent>();

    // Pre-populate root folder
    let mut metadata_cache = cipherbox_fuse::cache::MetadataCache::new();
    log::info!("Pre-populating root folder from IPNS...");
    let fetch_result: Result<(Vec<u8>, String, u64), String> = async {
        let resolve_resp = cipherbox_api_client::ipns::resolve_ipns(&state.sdk.api, &root_ipns_name).await.map_err(|e| format!("{}", e))?;
        let encrypted_bytes = cipherbox_api_client::ipfs::fetch_content(&state.sdk.api, &resolve_resp.cid).await.map_err(|e| format!("{}", e))?;
        let seq = resolve_resp.sequence_number.parse::<u64>().unwrap_or_else(|e| {
            log::warn!("Failed to parse root IPNS sequence '{}': {}", resolve_resp.sequence_number, e);
            0
        });
        Ok((encrypted_bytes, resolve_resp.cid, seq))
    }.await;

    // Track resolved sequence numbers to seed the PublishCoordinator after creation
    let mut initial_sequences: Vec<(String, u64)> = Vec::new();

    match fetch_result {
        Ok((encrypted_bytes, cid, root_seq)) => {
            initial_sequences.push((root_ipns_name.clone(), root_seq));
            match cipherbox_core::decrypt_metadata_from_ipfs_public(&encrypted_bytes, &root_folder_key) {
                Ok(metadata) => {
                    metadata_cache.set(&root_ipns_name, metadata.clone(), cid);
                    if let Ok(()) = inodes.populate_folder(cipherbox_fuse::inode::ROOT_INO, &metadata, &private_key, &public_key, false) {
                        log::info!("Root folder pre-populated successfully");
                        // Resolve root FilePointers
                        let unresolved = inodes.get_unresolved_file_pointers();
                        if !unresolved.is_empty() {
                            if let Ok(fk) = <[u8; 32]>::try_from(root_folder_key.as_slice()) {
                                for (fp_ino, fp_ipns) in &unresolved {
                                    let fp_result: Result<Vec<u8>, String> = async {
                                        let resp = cipherbox_api_client::ipns::resolve_ipns(&state.sdk.api, fp_ipns).await.map_err(|e| format!("{}", e))?;
                                        cipherbox_api_client::ipfs::fetch_content(&state.sdk.api, &resp.cid).await.map_err(|e| format!("{}", e))
                                    }.await;
                                    if let Ok(enc_bytes) = fp_result {
                                        if let Ok(fm) = cipherbox_core::decrypt_file_metadata_from_ipfs_public(&enc_bytes, &fk) {
                                            inodes.resolve_file_pointer(*fp_ino, fm.cid, fm.file_key_encrypted, fm.file_iv, fm.size, fm.encryption_mode, fm.versions);
                                        }
                                    }
                                }
                            }
                        }
                        // Pre-populate subfolders
                        let subfolder_infos: Vec<(u64, String, Zeroizing<Vec<u8>>)> = inodes.inodes.values()
                            .filter_map(|inode| {
                                if inode.parent_ino != cipherbox_fuse::inode::ROOT_INO { return None; }
                                if let cipherbox_fuse::inode::InodeKind::Folder { ref ipns_name, ref folder_key, .. } = inode.kind {
                                    Some((inode.ino, ipns_name.clone(), folder_key.clone()))
                                } else { None }
                            }).collect();
                        for (sub_ino, sub_ipns, sub_key) in &subfolder_infos {
                            let sub_result: Result<(Vec<u8>, String, u64), String> = async {
                                let resp = cipherbox_api_client::ipns::resolve_ipns(&state.sdk.api, sub_ipns).await.map_err(|e| format!("{}", e))?;
                                let bytes = cipherbox_api_client::ipfs::fetch_content(&state.sdk.api, &resp.cid).await.map_err(|e| format!("{}", e))?;
                                let seq = resp.sequence_number.parse::<u64>().unwrap_or_else(|e| {
                                    log::warn!("Failed to parse subfolder IPNS sequence '{}' for {}: {}", resp.sequence_number, sub_ipns, e);
                                    0
                                });
                                Ok((bytes, resp.cid, seq))
                            }.await;
                            if let Ok((enc_bytes, sub_cid, sub_seq)) = sub_result {
                                initial_sequences.push((sub_ipns.clone(), sub_seq));
                                if let Ok(sub_meta) = cipherbox_core::decrypt_metadata_from_ipfs_public(&enc_bytes, sub_key) {
                                    metadata_cache.set(sub_ipns, sub_meta.clone(), sub_cid);
                                    if let Ok(()) = inodes.populate_folder(*sub_ino, &sub_meta, &private_key, &public_key, false) {
                                        let sub_unresolved = inodes.get_unresolved_file_pointers();
                                        if let Ok(sk) = <[u8; 32]>::try_from(sub_key.as_slice()) {
                                            for (fp_ino, fp_ipns) in &sub_unresolved {
                                                let fp_result: Result<Vec<u8>, String> = async {
                                                    let resp = cipherbox_api_client::ipns::resolve_ipns(&state.sdk.api, fp_ipns).await.map_err(|e| format!("{}", e))?;
                                                    cipherbox_api_client::ipfs::fetch_content(&state.sdk.api, &resp.cid).await.map_err(|e| format!("{}", e))
                                                }.await;
                                                if let Ok(enc_bytes) = fp_result {
                                                    if let Ok(fm) = cipherbox_core::decrypt_file_metadata_from_ipfs_public(&enc_bytes, &sk) {
                                                        inodes.resolve_file_pointer(*fp_ino, fm.cid, fm.file_key_encrypted, fm.file_iv, fm.size, fm.encryption_mode, fm.versions);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => log::warn!("Root metadata decryption failed: {}", e),
            }
        }
        Err(e) => log::warn!("Root folder fetch failed (mount will show empty): {}", e),
    }

    // Construct coordinator before replay so it can be seeded and shared.
    let publish_coordinator = {
        let coord = Arc::new(PublishCoordinator::new());
        for (name, seq) in &initial_sequences {
            coord.record_publish(name, *seq);
        }
        if !initial_sequences.is_empty() {
            log::info!("PublishCoordinator seeded with {} sequence(s) from pre-populate", initial_sequences.len());
        }
        coord
    };

    // Replay journal entries for this vault before mounting (D-06, D-07, D-08).
    // Errors are logged but never fail the mount — partial replay is better than no mount.
    cipherbox_fuse::replay_for_vault(
        &journal,
        state.sdk.api.clone(),
        &private_key,
        &public_key,
        &root_folder_key,
        &root_ipns_name,
        publish_coordinator.clone(),
        tee_public_key.as_deref(),
        tee_key_epoch,
    )
    .await;

    let fs = CipherBoxFS {
        inodes, metadata_cache,
        content_cache: cipherbox_fuse::cache::ContentCache::new(),
        api: state.sdk.api.clone(),
        private_key: Zeroizing::new(private_key),
        public_key: Zeroizing::new(public_key),
        root_folder_key: Zeroizing::new(root_folder_key),
        root_ipns_name, rt,
        next_fh: std::sync::atomic::AtomicU64::new(1),
        open_files: HashMap::new(),
        temp_dir, tee_public_key, tee_key_epoch,
        max_versions_per_file, version_cooldown_ms,
        refresh_rx, refresh_tx,
        prefetching: std::collections::HashSet::new(),
        refreshing_metadata: std::collections::HashSet::new(),
        content_rx, content_tx,
        filepointer_rx, filepointer_tx,
        resolving_file_pointers: std::collections::HashSet::new(),
        pending_content: HashMap::new(),
        upload_rx, upload_tx,
        journal,
        mutated_folders: HashMap::new(),
        publish_coordinator,
        publish_queue: HashMap::new(),
    };

    let mount_path_clone = mount_path.clone();

    #[cfg(target_os = "linux")]
    let options = vec![MountOption::FSName("CipherBox".to_string()), MountOption::DefaultPermissions, MountOption::RW];
    #[cfg(target_os = "macos")]
    let options = vec![
        MountOption::FSName("CipherBox".to_string()),
        MountOption::CUSTOM("volname=CipherBox".to_string()),
        MountOption::CUSTOM("noappledouble".to_string()),
        MountOption::CUSTOM("noapplexattr".to_string()),
        MountOption::CUSTOM("backend=smb".to_string()),
        MountOption::RW,
    ];

    let (tx, rx) = std::sync::mpsc::sync_channel::<Result<(), String>>(1);
    let handle = std::thread::Builder::new()
        .name("fuse-mount".to_string())
        .spawn(move || {
            log::info!("Mounting CipherBoxFS at {}", mount_path_clone.display());
            match fuser::mount2(fs, &mount_path_clone, &options) {
                Ok(()) => { log::info!("FUSE filesystem unmounted cleanly"); let _ = tx.send(Ok(())); }
                Err(e) => { log::error!("FUSE mount error: {}", e); let _ = tx.send(Err(format!("FUSE mount error: {}", e))); }
            }
        })
        .map_err(|e| format!("Failed to spawn FUSE thread: {}", e))?;

    match rx.recv_timeout(std::time::Duration::from_secs(2)) {
        Ok(Ok(())) => Err("FUSE filesystem unmounted immediately after mounting".to_string()),
        Ok(Err(e)) => Err(e),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => { log::info!("FUSE mount confirmed at {}", mount_path.display()); Ok(handle) }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err("FUSE mount thread exited unexpectedly".to_string()),
    }
}

#[cfg(all(feature = "fuse", target_os = "macos"))]
pub fn unmount_filesystem() -> Result<(), String> {
    cipherbox_fuse::platform::macos::unmount_filesystem()
}

#[cfg(all(feature = "fuse", target_os = "linux"))]
pub fn unmount_filesystem() -> Result<(), String> {
    cipherbox_fuse::platform::linux::unmount_filesystem()
}

#[cfg(test)]
#[cfg(any(feature = "fuse", feature = "winfsp"))]
mod tests {
    use cipherbox_fuse::merge_folder_children;
    use cipherbox_core::folder::{FilePointer, FolderChild, FolderMetadata};

    fn make_file(ipns: &str, name: &str) -> FolderChild {
        FolderChild::File(FilePointer {
            id: format!("id-{}", name), name: name.to_string(), file_meta_ipns_name: ipns.to_string(),
            ipns_private_key_encrypted: None, created_at: 1000, modified_at: 2000,
        })
    }

    fn metadata(children: Vec<FolderChild>) -> FolderMetadata {
        FolderMetadata { version: "v2".to_string(), children }
    }

    fn child_name(child: &FolderChild) -> &str {
        match child { FolderChild::Folder(f) => &f.name, FolderChild::File(f) => &f.name }
    }

    #[test]
    fn merge_both_empty() {
        let merged = merge_folder_children(&metadata(vec![]), metadata(vec![]));
        assert!(merged.children.is_empty());
    }

    #[test]
    fn merge_disjoint_children_union() {
        let merged = merge_folder_children(&metadata(vec![make_file("a", "a.txt")]), metadata(vec![make_file("b", "b.txt")]));
        assert_eq!(merged.children.len(), 2);
    }

    #[test]
    fn merge_identical_uses_local() {
        let merged = merge_folder_children(&metadata(vec![make_file("a", "local.jpg")]), metadata(vec![make_file("a", "remote.jpg")]));
        assert_eq!(merged.children.len(), 1);
        assert_eq!(child_name(&merged.children[0]), "local.jpg");
    }

    #[test]
    fn default_journal_dir_ends_with_cipherbox_cb_journal() {
        use super::default_journal_dir;
        let dir = default_journal_dir();
        // Last component must be "cb-journal"
        assert_eq!(
            dir.file_name().and_then(|n| n.to_str()),
            Some("cb-journal"),
            "expected last component to be cb-journal, got {:?}",
            dir
        );
        // Parent component must be "cipherbox"
        assert_eq!(
            dir.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str()),
            Some("cipherbox"),
            "expected parent to be cipherbox, got {:?}",
            dir.parent()
        );
    }
}
