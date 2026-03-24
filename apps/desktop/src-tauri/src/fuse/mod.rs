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
    CipherBoxFS, PublishCoordinator, PendingRefresh, PendingContent, UploadComplete,
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
) -> Result<std::thread::JoinHandle<()>, String> {
    let mount_path = mount_point();

    if mount_path.is_symlink() {
        return Err("Mount point is a symlink -- refusing to proceed".to_string());
    }

    if !mount_path.exists() {
        std::fs::create_dir_all(&mount_path)
            .map_err(|e| format!("Failed to create mount point: {}", e))?;
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

    let mut inodes = cipherbox_fuse::inode::InodeTable::new();
    if let Some(root) = inodes.get_mut(cipherbox_fuse::inode::ROOT_INO) {
        root.kind = cipherbox_fuse::inode::InodeKind::Root {
            ipns_private_key: root_ipns_private_key.map(Zeroizing::new),
            ipns_name: Some(root_ipns_name.clone()),
        };
    }

    let (refresh_tx, refresh_rx) = std::sync::mpsc::channel::<PendingRefresh>();
    let (content_tx, content_rx) = std::sync::mpsc::channel::<PendingContent>();
    let (upload_tx, upload_rx) = std::sync::mpsc::channel::<UploadComplete>();

    // Pre-populate root folder
    let mut metadata_cache = cipherbox_fuse::cache::MetadataCache::new();
    log::info!("Pre-populating root folder from IPNS...");
    let fetch_result: Result<(Vec<u8>, String), String> = async {
        let resolve_resp = cipherbox_api_client::ipns::resolve_ipns(&state.sdk.api, &root_ipns_name).await.map_err(|e| format!("{}", e))?;
        let encrypted_bytes = cipherbox_api_client::ipfs::fetch_content(&state.sdk.api, &resolve_resp.cid).await.map_err(|e| format!("{}", e))?;
        Ok((encrypted_bytes, resolve_resp.cid))
    }.await;

    match fetch_result {
        Ok((encrypted_bytes, cid)) => {
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
                            let sub_result: Result<(Vec<u8>, String), String> = async {
                                let resp = cipherbox_api_client::ipns::resolve_ipns(&state.sdk.api, sub_ipns).await.map_err(|e| format!("{}", e))?;
                                let bytes = cipherbox_api_client::ipfs::fetch_content(&state.sdk.api, &resp.cid).await.map_err(|e| format!("{}", e))?;
                                Ok((bytes, resp.cid))
                            }.await;
                            if let Ok((enc_bytes, sub_cid)) = sub_result {
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
        refresh_rx, refresh_tx,
        prefetching: std::collections::HashSet::new(),
        content_rx, content_tx,
        pending_content: HashMap::new(),
        upload_rx, upload_tx,
        mutated_folders: HashMap::new(),
        publish_coordinator: Arc::new(PublishCoordinator::new()),
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
}
