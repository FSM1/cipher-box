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
                Err(e) => log::warn!(
                    "Failed to clean stale mount point {}: {}",
                    mount_path.display(),
                    e
                ),
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
        // node/v3 anti-rollback gate: sidecars live adjacent to the write journal
        // (69-09 Slice 1). Capture before `journal_dir` is moved into WriteQueue.
        let high_water = cipherbox_sdk::new_journal_high_water(&journal_dir);
        // Replay rebuilds its own high-water gate from this dir; clone before move.
        let replay_journal_dir = journal_dir.clone();
        let journal = cipherbox_sdk::WriteQueue::new(journal_dir, crate::fuse::JOURNAL_MAX_RETRIES);

        // node/v3 root symmetric keys (read_key/write_key) for the root node.
        // E2E-RISK (69-09 Slice 5c): mirrors the fuse (macOS/Linux) mount — the
        // real node/v3 root keys are server-persisted (sdk-core registration.ts)
        // and not yet recovered into desktop KeyState (v2.0 client stubbed, phase
        // 63). Bridged from the legacy root_folder_key; runtime correctness is
        // E2E-gated, not gated by this slice. See fuse/mod.rs for the full note.
        let root_read_key: Zeroizing<[u8; 32]> = {
            let mut k = [0u8; 32];
            let src = root_folder_key.as_slice();
            let n = src.len().min(32);
            k[..n].copy_from_slice(&src[..n]);
            Zeroizing::new(k)
        };
        let root_write_key: Zeroizing<[u8; 32]> = {
            let mut k = *root_read_key;
            for b in k.iter_mut() {
                *b ^= 0xA5;
            }
            Zeroizing::new(k)
        };

        // Build the inode table
        let mut inodes = inode::InodeTable::new();

        // Set root inode's node/v3 key material + IPNS data
        if let Some(root) = inodes.get_mut(inode::ROOT_INO) {
            root.kind = inode::InodeKind::Root {
                ipns_name: root_ipns_name.clone(),
                read_key: root_read_key.clone(),
                write_key: root_write_key.clone(),
                ipns_private_key: Zeroizing::new(root_ipns_private_key.clone().unwrap_or_default()),
            };
        }

        // Channels for background operations
        let (refresh_tx, refresh_rx) = std::sync::mpsc::channel::<PendingRefresh>();
        let (content_tx, content_rx) = std::sync::mpsc::channel::<PendingContent>();
        let (filepointer_tx, filepointer_rx) = std::sync::mpsc::channel::<PendingFilePointer>();
        let (upload_tx, upload_rx) = std::sync::mpsc::channel::<cipherbox_fuse::FsEvent>();

        // Pre-populate root folder and subfolders via shared prepopulate helper
        // (node/v3 gated owned listing). Returns initial_sequences for seeding the
        // PublishCoordinator (empty under node/v3 — see prepopulate module docs).
        // CR-06: mirroring apps/desktop/src-tauri/src/fuse/mod.rs pre-populate pattern.
        let metadata_cache = cache::MetadataCache::new();
        let initial_sequences = crate::fuse::prepopulate::prepopulate_filesystem(
            &state.sdk.api,
            &mut inodes,
            &high_water,
            &root_ipns_name,
            &root_read_key,
            &root_write_key,
        )
        .await;

        // CR-06: construct PublishCoordinator seeded from resolved sequences before replay,
        // mirroring apps/desktop/src-tauri/src/fuse/mod.rs:219-229.
        let publish_coordinator = {
            let coord = Arc::new(PublishCoordinator::new());
            for (name, seq) in &initial_sequences {
                coord.record_publish(name, *seq);
            }
            if !initial_sequences.is_empty() {
                log::info!(
                    "PublishCoordinator seeded with {} sequence(s) from pre-populate",
                    initial_sequences.len()
                );
            }
            coord
        };

        // D-02: GC parked Failed journal entries + orphaned sidecars at mount, mirroring the
        // Unix path in apps/desktop/src-tauri/src/fuse/mod.rs. Synchronous, fast (dir scan),
        // Failed-only, and non-fatal so it never blocks/fails the mount (T-52-16, DoS).
        match journal.gc_failed_entries(
            cipherbox_sdk::JOURNAL_GC_MAX_AGE_DAYS,
            cipherbox_sdk::JOURNAL_GC_MAX_SIZE_BYTES,
        ) {
            Ok(n) if n > 0 => {
                log::info!("Mount GC: removed {} parked/orphaned journal item(s)", n)
            }
            Ok(_) => {}
            Err(e) => log::warn!("Mount GC failed (will continue mount): {}", e),
        }

        // CR-06 / D-03 (WR-07): replay journal entries for this vault CONCURRENTLY with mount.
        // Previously this blocked the mount with `.await`; now replay runs on a background
        // tokio task (each entry's network ops are bounded by tokio::time::timeout inside
        // replay_for_vault) and the mount proceeds immediately. Errors are logged inside
        // replay and never fail the mount. Mirrors apps/desktop/src-tauri/src/fuse/mod.rs.
        //
        // Copy every argument into owned values for the replay task: the node/v3 root
        // read/write keys are `Copy` [u8;32]s and `replay_journal_dir` was cloned before
        // the journal dir moved into WriteQueue::new. Replay sends no FsEvent::UploadComplete,
        // so spawning before CipherBoxFS construction is race-free.
        {
            let replay_journal = journal.clone();
            let replay_api = state.sdk.api.clone();
            let replay_journal_dir = replay_journal_dir;
            let replay_root_read_key = *root_read_key;
            let replay_root_write_key = *root_write_key;
            let replay_root_ipns_name = root_ipns_name.clone();
            let replay_coordinator = publish_coordinator.clone();
            let replay_tee_public_key = tee_public_key.clone();
            let replay_tee_key_epoch = tee_key_epoch;
            rt.spawn(async move {
                cipherbox_fuse::replay_for_vault(
                    &replay_journal,
                    replay_api,
                    replay_journal_dir,
                    &replay_root_read_key,
                    &replay_root_write_key,
                    &replay_root_ipns_name,
                    replay_coordinator,
                    replay_tee_public_key.as_deref(),
                    replay_tee_key_epoch,
                )
                .await;
                log::info!("Background replay_for_vault complete");
            });
        }

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
            pending_fp_resolves: std::collections::VecDeque::new(), // D-09
            pending_content: HashMap::new(),
            upload_rx,
            upload_tx,
            journal,
            high_water,
            mutated_folders: HashMap::new(),
            publish_coordinator,
            publish_queue: HashMap::new(),
            sent_shares: std::sync::RwLock::new(
                cipherbox_fuse::write_ops::grant_scope::SentSharesCache::empty(),
            ),
        };

        // Create WinFsp context with Arc<Mutex<>> for interior mutability
        let context =
            cipherbox_fuse::platform::windows::operations::implementation::WinFspContext {
                inner: Arc::new(Mutex::new(fs)),
                rt: rt.clone(),
            };

        // Initialize WinFsp runtime
        // NOTE: winfsp_init_or_die() calls std::process::exit() on failure,
        // killing the process silently. Use winfsp_init() instead for proper error handling.
        log::info!("Initializing WinFsp runtime...");
        let _init = winfsp::winfsp_init().map_err(|e| {
            format!(
                "WinFsp initialization failed (is WinFsp installed?): {:?}",
                e
            )
        })?;
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
        let mut host = winfsp::host::FileSystemHost::new(volume_params, context)
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
                log::warn!(
                    "Failed to remove stale mount path {}: {}",
                    mount_path.display(),
                    e
                );
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
