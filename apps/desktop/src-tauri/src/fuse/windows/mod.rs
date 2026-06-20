//! Windows filesystem module for CipherBox Desktop.
//!
//! Provides WinFsp-based mount and unmount functions.
//! WinFsp operation implementations (FileSystemContext, read/write/dir ops)
//! live in the cipherbox-fuse crate at `cipherbox_fuse::platform::windows`.

#[cfg(feature = "winfsp")]
mod mount_impl {
    use std::collections::HashMap;
    use std::sync::atomic::AtomicU64;
    use std::sync::{Arc, Mutex};

    use zeroize::Zeroizing;

    use crate::fuse::{
        cache, inode, CipherBoxFS, PendingContent, PendingFilePointer, PendingRefresh,
        PublishCoordinator, UploadComplete,
    };
    use crate::state::AppState;

    /// Global handle to the WinFsp stop signal for clean shutdown.
    /// Replaced on each mount so remount after unmount works correctly.
    static WINFSP_STOP: Mutex<Option<Arc<std::sync::atomic::AtomicBool>>> = Mutex::new(None);

    /// Mount the WinFsp filesystem after successful authentication.
    ///
    /// Creates the CipherBoxFS with keys from AppState, pre-populates the root
    /// folder from IPNS, and spawns the WinFsp event loop on a dedicated thread.
    ///
    /// Returns a JoinHandle for the mount thread.
    ///
    /// Key differences from macOS mount:
    /// - WinFsp creates the mount directory as a reparse point -- do NOT pre-create it
    /// - No Spotlight suppression (Windows-specific)
    /// - Uses WinFsp FileSystemHost instead of fuser::mount2
    pub async fn mount_filesystem(
        state: &AppState,
        rt: tokio::runtime::Handle,
        private_key: Vec<u8>,
        public_key: Vec<u8>,
        root_folder_key: Zeroizing<Vec<u8>>,
        root_ipns_name: String,
        root_ipns_private_key: Option<Vec<u8>>,
        tee_public_key: Option<Vec<u8>>,
        tee_key_epoch: Option<u32>,
        max_versions_per_file: usize,
        version_cooldown_ms: u64,
    ) -> Result<std::thread::JoinHandle<()>, String> {
        let mount_path = crate::fuse::mount_point();

        // WinFsp creates the mount directory as a reparse point.
        // If a stale mount directory exists from a crash, clean it.
        if mount_path.exists() {
            match std::fs::remove_dir_all(&mount_path) {
                Ok(()) => log::info!("Cleaned stale mount point: {}", mount_path.display()),
                Err(e) => log::warn!("Failed to clean stale mount point {}: {}", mount_path.display(), e),
            }
        }

        // Create temp directory for write buffering
        let temp_dir = std::env::temp_dir().join("cipherbox");
        std::fs::create_dir_all(&temp_dir)
            .map_err(|e| format!("Failed to create temp directory: {}", e))?;

        // Stable journal dir for durable write journal
        let journal_dir = crate::fuse::default_journal_dir();
        std::fs::create_dir_all(&journal_dir)
            .map_err(|e| format!("Failed to create journal directory: {}", e))?;
        let journal = cipherbox_sdk::WriteQueue::new(journal_dir, crate::fuse::JOURNAL_MAX_RETRIES);

        // Build the inode table
        let mut inodes = inode::InodeTable::new();

        // Set root inode's IPNS data
        if let Some(root) = inodes.get_mut(inode::ROOT_INO) {
            root.kind = inode::InodeKind::Root {
                ipns_private_key: root_ipns_private_key.map(Zeroizing::new),
                ipns_name: Some(root_ipns_name.clone()),
            };
        }

        // Channels for background operations
        let (refresh_tx, refresh_rx) = std::sync::mpsc::channel::<PendingRefresh>();
        let (content_tx, content_rx) = std::sync::mpsc::channel::<PendingContent>();
        let (filepointer_tx, filepointer_rx) = std::sync::mpsc::channel::<PendingFilePointer>();
        let (upload_tx, upload_rx) = std::sync::mpsc::channel::<cipherbox_fuse::FsEvent>();

        // Pre-populate root folder BEFORE mounting so readdir has data immediately.
        let mut metadata_cache = cache::MetadataCache::new();
        log::info!("Pre-populating root folder from IPNS...");
        // CR-06: collect resolved sequence numbers to seed PublishCoordinator before replay,
        // mirroring apps/desktop/src-tauri/src/fuse/mod.rs:135-140.
        let fetch_result: Result<(Vec<u8>, String, u64), String> = async {
            let resolve_resp =
                cipherbox_api_client::ipns::resolve_ipns(&state.sdk.api, &root_ipns_name).await.map_err(|e| e.to_string())?;
            let encrypted_bytes =
                cipherbox_api_client::ipfs::fetch_content(&state.sdk.api, &resolve_resp.cid).await.map_err(|e| e.to_string())?;
            let seq = resolve_resp.sequence_number.parse::<u64>().unwrap_or_else(|e| {
                log::warn!("Failed to parse root IPNS sequence '{}': {}", resolve_resp.sequence_number, e);
                0
            });
            Ok((encrypted_bytes, resolve_resp.cid, seq))
        }
        .await;

        // Accumulate (ipns_name, sequence) pairs for coordinator seeding.
        let mut initial_sequences: Vec<(String, u64)> = Vec::new();

        match fetch_result {
            Ok((encrypted_bytes, cid, root_seq)) => {
                initial_sequences.push((root_ipns_name.clone(), root_seq));
                match cipherbox_core::decrypt::decrypt_metadata_from_ipfs_public(&encrypted_bytes, &root_folder_key) {
                    Ok(metadata) => {
                        metadata_cache.set(&root_ipns_name, metadata.clone(), cid);

                        match inodes.populate_folder(
                            inode::ROOT_INO,
                            &metadata,
                            &private_key,
                            &public_key,
                            false,
                        ) {
                            Ok(()) => {
                                log::info!("Root folder pre-populated successfully");

                                // Resolve FilePointers eagerly before mount
                                let unresolved = inodes.get_unresolved_file_pointers();
                                if !unresolved.is_empty() {
                                    log::info!(
                                        "Resolving {} root FilePointer(s)...",
                                        unresolved.len()
                                    );
                                    let root_folder_key_arr: Result<[u8; 32], _> =
                                        root_folder_key.as_slice().try_into();
                                    if let Ok(fk) = root_folder_key_arr {
                                        for (fp_ino, fp_ipns) in &unresolved {
                                            let fp_result: Result<Vec<u8>, String> = async {
                                                let resp = cipherbox_api_client::ipns::resolve_ipns(
                                                    &state.sdk.api,
                                                    fp_ipns,
                                                )
                                                .await.map_err(|e| e.to_string())?;
                                                let bytes = cipherbox_api_client::ipfs::fetch_content(
                                                    &state.sdk.api,
                                                    &resp.cid,
                                                )
                                                .await.map_err(|e| e.to_string())?;
                                                Ok(bytes)
                                            }
                                            .await;
                                            match fp_result {
                                                Ok(enc_bytes) => {
                                                    match cipherbox_core::decrypt::decrypt_file_metadata_from_ipfs_public(
                                                        &enc_bytes, &fk,
                                                    ) {
                                                        Ok(fm) => {
                                                            inodes.resolve_file_pointer(
                                                                *fp_ino,
                                                                fm.cid,
                                                                fm.file_key_encrypted,
                                                                fm.file_iv,
                                                                fm.size,
                                                                fm.encryption_mode,
                                                                fm.versions,
                                                            );
                                                        }
                                                        Err(e) => log::warn!(
                                                            "Root FilePointer decrypt failed for ino {}: {}",
                                                            fp_ino,
                                                            e
                                                        ),
                                                    }
                                                }
                                                Err(e) => log::warn!(
                                                    "Root FilePointer resolve failed for ino {}: {}",
                                                    fp_ino,
                                                    e
                                                ),
                                            }
                                        }
                                    }
                                }

                                // Pre-populate immediate subfolders
                                let subfolder_infos: Vec<(u64, String, Zeroizing<Vec<u8>>)> =
                                    inodes
                                        .inodes
                                        .values()
                                        .filter_map(|inode| {
                                            if inode.parent_ino != inode::ROOT_INO {
                                                return None;
                                            }
                                            if let inode::InodeKind::Folder {
                                                ref ipns_name,
                                                ref folder_key,
                                                ..
                                            } = inode.kind
                                            {
                                                Some((
                                                    inode.ino,
                                                    ipns_name.clone(),
                                                    folder_key.clone(),
                                                ))
                                            } else {
                                                None
                                            }
                                        })
                                        .collect();

                                for (sub_ino, sub_ipns, sub_key) in &subfolder_infos {
                                    log::info!(
                                        "Pre-populating subfolder ino={} ipns={}",
                                        sub_ino,
                                        sub_ipns
                                    );
                                    let sub_result: Result<(Vec<u8>, String, u64), String> = async {
                                        let resp =
                                            cipherbox_api_client::ipns::resolve_ipns(&state.sdk.api, sub_ipns)
                                                .await.map_err(|e| e.to_string())?;
                                        let bytes = cipherbox_api_client::ipfs::fetch_content(
                                            &state.sdk.api,
                                            &resp.cid,
                                        )
                                        .await.map_err(|e| e.to_string())?;
                                        let seq = resp.sequence_number.parse::<u64>().unwrap_or_else(|e| {
                                            log::warn!("Failed to parse subfolder IPNS sequence '{}' for {}: {}", resp.sequence_number, sub_ipns, e);
                                            0
                                        });
                                        Ok((bytes, resp.cid, seq))
                                    }
                                    .await;
                                    match sub_result {
                                        Ok((enc_bytes, sub_cid, sub_seq)) => {
                                            initial_sequences.push((sub_ipns.clone(), sub_seq));
                                            match cipherbox_core::decrypt::decrypt_metadata_from_ipfs_public(&enc_bytes, sub_key) {
                                                Ok(sub_metadata) => {
                                                    metadata_cache.set(
                                                        sub_ipns,
                                                        sub_metadata.clone(),
                                                        sub_cid,
                                                    );
                                                    match inodes.populate_folder(
                                                        *sub_ino,
                                                        &sub_metadata,
                                                        &private_key,
                                                        &public_key,
                                                        false,
                                                    ) {
                                                        Ok(()) => {
                                                            log::info!(
                                                                "Subfolder ino={} pre-populated",
                                                                sub_ino
                                                            );
                                                            let sub_unresolved =
                                                                inodes.get_unresolved_file_pointers_for_parent(*sub_ino);
                                                            if !sub_unresolved.is_empty() {
                                                                let sk_arr: Result<[u8; 32], _> =
                                                                    sub_key.as_slice().try_into();
                                                                if let Ok(sk) = sk_arr {
                                                                    for (fp_ino, fp_ipns) in
                                                                        &sub_unresolved
                                                                    {
                                                                        let fp_result: Result<
                                                                            Vec<u8>,
                                                                            String,
                                                                        > = async {
                                                                            let resp =
                                                                                cipherbox_api_client::ipns::resolve_ipns(
                                                                                    &state.sdk.api,
                                                                                    fp_ipns,
                                                                                )
                                                                                .await.map_err(|e| e.to_string())?;
                                                                            let bytes =
                                                                                cipherbox_api_client::ipfs::fetch_content(
                                                                                    &state.sdk.api,
                                                                                    &resp.cid,
                                                                                )
                                                                                .await.map_err(|e| e.to_string())?;
                                                                            Ok(bytes)
                                                                        }
                                                                        .await;
                                                                        match fp_result {
                                                                            Ok(enc_bytes) => {
                                                                                match cipherbox_core::decrypt::decrypt_file_metadata_from_ipfs_public(&enc_bytes, &sk) {
                                                                                    Ok(fm) => {
                                                                                        inodes.resolve_file_pointer(
                                                                                            *fp_ino,
                                                                                            fm.cid,
                                                                                            fm.file_key_encrypted,
                                                                                            fm.file_iv,
                                                                                            fm.size,
                                                                                            fm.encryption_mode,
                                                                                            fm.versions,
                                                                                        );
                                                                                    }
                                                                                    Err(e) => log::warn!(
                                                                                        "Sub FilePointer decrypt failed: {}",
                                                                                        e
                                                                                    ),
                                                                                }
                                                                            }
                                                                            Err(e) => log::warn!(
                                                                                "Sub FilePointer resolve failed: {}",
                                                                                e
                                                                            ),
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        Err(e) => log::warn!(
                                                            "Subfolder ino={} populate failed: {}",
                                                            sub_ino,
                                                            e
                                                        ),
                                                    }
                                                }
                                                Err(e) => log::warn!(
                                                    "Subfolder ino={} decrypt failed: {}",
                                                    sub_ino,
                                                    e
                                                ),
                                            }
                                        }
                                        Err(e) => log::warn!(
                                            "Subfolder ino={} fetch failed: {}",
                                            sub_ino,
                                            e
                                        ),
                                    }
                                }
                            }
                            Err(e) => log::warn!("Root folder populate failed: {}", e),
                        }
                    }
                    Err(e) => log::warn!("Root metadata decryption failed: {}", e),
                }
            }
            Err(e) => {
                log::warn!("Root folder fetch failed (mount will show empty): {}", e)
            }
        }

        // CR-06: construct PublishCoordinator seeded from resolved sequences before replay,
        // mirroring apps/desktop/src-tauri/src/fuse/mod.rs:219-229.
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

        // CR-06: replay journal entries for this vault before mounting.
        // Errors are logged inside replay and never fail the mount.
        // Mirrors apps/desktop/src-tauri/src/fuse/mod.rs:231-242.
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
            inodes,
            metadata_cache,
            content_cache: cache::ContentCache::new(),
            api: state.sdk.api.clone(),
            private_key: Zeroizing::new(private_key),
            public_key: Zeroizing::new(public_key),
            root_folder_key,
            root_ipns_name,
            rt: rt.clone(),
            next_fh: AtomicU64::new(1),
            open_files: HashMap::new(),
            temp_dir,
            tee_public_key,
            tee_key_epoch,
            max_versions_per_file,
            version_cooldown_ms,
            refresh_rx,
            refresh_tx,
            prefetching: std::collections::HashSet::new(),
            refreshing_metadata: std::collections::HashSet::new(),
            content_rx,
            content_tx,
            filepointer_rx,
            filepointer_tx,
            resolving_file_pointers: std::collections::HashSet::new(),
            pending_content: HashMap::new(),
            upload_rx,
            upload_tx,
            journal,
            mutated_folders: HashMap::new(),
            publish_coordinator,
            publish_queue: HashMap::new(),
        };

        // Create WinFsp context with Arc<Mutex<>> for interior mutability
        let context = cipherbox_fuse::platform::windows::operations::implementation::WinFspContext {
            inner: Arc::new(Mutex::new(fs)),
            rt: rt.clone(),
        };

        // Initialize WinFsp runtime
        // NOTE: winfsp_init_or_die() calls std::process::exit() on failure,
        // killing the process silently. Use winfsp_init() instead for proper error handling.
        log::info!("Initializing WinFsp runtime...");
        let _init = winfsp::winfsp_init()
            .map_err(|e| format!("WinFsp initialization failed (is WinFsp installed?): {:?}", e))?;
        log::info!("WinFsp runtime initialized successfully");

        // Create volume params
        log::info!("Creating WinFsp volume params...");
        let mut volume_params = winfsp::host::VolumeParams::new();
        volume_params
            .filesystem_name("CipherBox")
            .file_info_timeout(1000) // 1s attribute cache
            .case_sensitive_search(false) // Windows convention
            .case_preserved_names(true);

        log::info!("Creating WinFsp FileSystemHost...");
        let mut host = winfsp::host::FileSystemHost::new(
            volume_params,
            context,
        )
        .map_err(|e| format!("Failed to create WinFsp host: {:?}", e))?;
        log::info!("WinFsp FileSystemHost created");

        // Set mount point
        let mount_str = mount_path
            .to_str()
            .ok_or("Mount path is not valid UTF-8")?
            .to_string();
        log::info!("Mounting WinFsp at {}...", mount_str);
        host.mount(&mount_str)
            .map_err(|e| format!("Failed to set WinFsp mount point: {:?}", e))?;
        log::info!("WinFsp mount point set successfully");

        // Set up stop signal for clean shutdown (replaced on each mount for remount support)
        let stop_signal = Arc::new(std::sync::atomic::AtomicBool::new(false));
        *WINFSP_STOP.lock().unwrap() = Some(stop_signal.clone());
        let stop_clone = stop_signal.clone();

        // Start the dispatcher and spawn a keep-alive thread.
        //
        // FspFileSystemStartDispatcher starts background worker threads and
        // returns immediately (it does NOT block). The FileSystemHost must
        // remain alive for the mounted filesystem to keep working — dropping
        // it calls FspFileSystemStopDispatcher + FspFileSystemRemoveMountPoint.
        //
        // The dedicated thread holds ownership of `host` and parks until the
        // stop signal fires, at which point it drops the host (clean shutdown).
        let (tx, rx) = std::sync::mpsc::sync_channel::<Result<(), String>>(1);

        let handle = std::thread::Builder::new()
            .name("winfsp-mount".to_string())
            .spawn(move || {
                log::info!("WinFsp filesystem starting at {}", mount_str);
                match host.start() {
                    Ok(()) => {
                        // Dispatcher threads started — filesystem is live.
                        log::info!("WinFsp dispatcher started at {}", mount_str);
                        let _ = tx.send(Ok(()));

                        // Keep host alive until stop is signaled.
                        while !stop_clone.load(std::sync::atomic::Ordering::SeqCst) {
                            std::thread::sleep(std::time::Duration::from_millis(200));
                        }
                        log::info!("WinFsp stop signal received, shutting down...");
                        // host.stop() + host.unmount() happen in Drop
                    }
                    Err(e) => {
                        log::error!("WinFsp start error: {:?}", e);
                        let _ = tx.send(Err(format!("WinFsp start error: {:?}", e)));
                    }
                }
            })
            .map_err(|e| format!("Failed to spawn WinFsp thread: {}", e))?;

        // Wait for the start() result (should arrive almost immediately)
        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(Ok(())) => {
                // Dispatcher started, mount is live
                log::info!("WinFsp mount confirmed at {}", mount_path.display());
                Ok(handle)
            }
            Ok(Err(e)) => {
                // start() returned an error
                Err(e)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                Err("WinFsp dispatcher start timed out".to_string())
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                Err("WinFsp mount thread exited unexpectedly".to_string())
            }
        }
    }

    /// Unmount the WinFsp filesystem.
    ///
    /// Sets the stop signal which causes the mount keep-alive thread to exit.
    /// When the thread exits, the FileSystemHost is dropped, which calls
    /// FspFileSystemStopDispatcher() + FspFileSystemRemoveMountPoint().
    ///
    /// Also cleans up the temp directory and stale mount point.
    pub fn unmount_filesystem() -> Result<(), String> {
        let mount_path = crate::fuse::mount_point();
        log::info!("Unmounting WinFsp at {}", mount_path.display());

        // Signal the stop flag for the current mount's keep-alive thread
        if let Some(stop) = WINFSP_STOP.lock().unwrap().as_ref() {
            stop.store(true, std::sync::atomic::Ordering::SeqCst);
        }

        // Clean up temp directory
        let temp_dir = std::env::temp_dir().join("cipherbox");
        if temp_dir.exists() {
            if let Err(e) = std::fs::remove_dir_all(&temp_dir) {
                log::warn!("Failed to clean temp directory: {}", e);
            }
        }

        // WinFsp removes the reparse point mount directory on clean shutdown.
        // If it's still there after a crash, clean it up.
        if mount_path.exists() {
            if let Err(e) = std::fs::remove_dir_all(&mount_path) {
                log::warn!("Failed to remove stale mount path {}: {}", mount_path.display(), e);
            }
        }

        log::info!("WinFsp unmount cleanup complete");
        Ok(())
    }
}

#[cfg(feature = "winfsp")]
pub use mount_impl::mount_filesystem;
#[cfg(feature = "winfsp")]
pub use mount_impl::unmount_filesystem;
