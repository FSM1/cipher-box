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
    mount_point, spawn_bin_entry_publish, CipherBoxFS, PendingContent, PendingFilePointer,
    PendingRefresh, PublishCoordinator, UploadComplete,
};

#[allow(unused_imports)]
pub use cipherbox_fuse::cache;
#[allow(unused_imports)]
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub use cipherbox_fuse::constants;
#[allow(unused_imports)]
pub use cipherbox_fuse::file_handle;
#[allow(unused_imports)]
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub use cipherbox_fuse::helpers;
#[allow(unused_imports)]
pub use cipherbox_fuse::inode;
#[cfg(feature = "winfsp")]
pub mod windows;

#[cfg(feature = "winfsp")]
pub use windows::mount_filesystem;
#[cfg(feature = "winfsp")]
pub use windows::unmount_filesystem;

// Tier-2 dedup: shared IPNS pre-populate block extracted from macOS + Windows mount fns.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub mod prepopulate;

#[cfg(feature = "fuse")]
use fuser::MountOption;
// These are consumed only by the fuse-gated `mount_filesystem` below; the winfsp
// mount lives in `windows/mod.rs` with its own imports (narrowed from
// any(fuse,winfsp) so the winfsp build does not warn on unused imports).
#[cfg(feature = "fuse")]
use std::collections::HashMap;
#[cfg(feature = "fuse")]
use std::sync::Arc;
#[cfg(feature = "fuse")]
use zeroize::Zeroizing;

#[cfg(feature = "fuse")]
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
            log::warn!(
                "data_local_dir unavailable; journal will use temp_dir (may not survive reboot)"
            );
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
    root_folder_key: Zeroizing<Vec<u8>>,
    root_read_key: Zeroizing<Vec<u8>>,
    root_write_key: Zeroizing<Vec<u8>>,
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

    // A crash can leave the mount path as a stale FUSE mount backed by a dead
    // in-process server, blocking remount before the create / clean-stale
    // decision below. We authoritatively detect and clear it per platform:
    //   - Linux: stat() returns ENOTCONN so `exists()` lies (returns false) and
    //     `create_dir_all` then fails with EEXIST; detect via
    //     /proc/self/mountinfo and unmount via `fusermount3 -u`.
    //   - macOS (FUSE-T/SMB): mount lingers as a stale `smbfs` mount; detect via
    //     `mount(8)` and clear via `umount`, then `diskutil unmount force`.
    // Both are best-effort and never block the mount.
    #[cfg(target_os = "linux")]
    cipherbox_fuse::platform::linux::recover_stale_mount(&mount_path);
    #[cfg(target_os = "macos")]
    cipherbox_fuse::platform::macos::recover_stale_mount(&mount_path);

    if !mount_path.exists() {
        // On Linux this recovers once from a stale FUSE mount whose dirent still
        // exists (surfaces as EEXIST even though `exists()` returned false); on
        // other platforms it is a plain `create_dir_all`.
        #[cfg(target_os = "linux")]
        let create_result = cipherbox_fuse::platform::linux::create_mount_point_dir(&mount_path);
        #[cfg(not(target_os = "linux"))]
        let create_result = std::fs::create_dir_all(&mount_path);
        create_result.map_err(|e| format!("Failed to create mount point: {}", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&mount_path, std::fs::Permissions::from_mode(0o700));
        }
    }

    // Clean crash residue regardless of which branch created/recovered the mount
    // point: the Linux recovery path (stale mount -> exists() lies ->
    // create_mount_point_dir EEXIST retry) lands in the create branch above, not
    // only the plain-exists case. On a freshly created empty dir this is a no-op.
    if let Ok(entries) = std::fs::read_dir(&mount_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let _ = std::fs::remove_dir_all(&path);
            } else {
                let _ = std::fs::remove_file(&path);
            }
        }
        log::info!("Cleaned stale mount point: {}", mount_path.display());
    }

    #[cfg(target_os = "macos")]
    {
        let never_index = mount_path.join(".metadata_never_index");
        if !never_index.exists() {
            let _ = std::fs::File::create(&never_index);
        }
    }

    let temp_dir = std::env::temp_dir().join("cipherbox");
    std::fs::create_dir_all(&temp_dir)
        .map_err(|e| format!("Failed to create temp directory: {}", e))?;
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
    // node/v3 anti-rollback gate: sidecars live adjacent to the write journal
    // (69-09 Slice 1). Capture before `journal_dir` is moved into WriteQueue.
    let high_water = cipherbox_sdk::new_journal_high_water(&journal_dir);
    // Replay needs the journal dir to rebuild its own high-water gate; capture a
    // clone before `journal_dir` is moved into WriteQueue::new below.
    let replay_journal_dir = journal_dir.clone();
    let journal = cipherbox_sdk::WriteQueue::new(journal_dir, JOURNAL_MAX_RETRIES);

    // node/v3 root symmetric keys (read_key/write_key) for the root node.
    //
    // The REAL node/v3 root read/write keys are recovered into desktop KeyState
    // at login (69-22 KeyState fields, populated by 69-23 vault init/recovery)
    // and threaded in here by post_auth_finalize. They replace the earlier legacy
    // placeholder that fabricated the two keys from `root_folder_key`; a real
    // node/v3 vault now mounts under its own persisted keys. We only narrow the
    // passed 32-byte state keys into fixed `[u8; 32]` locals for InodeKind::Root,
    // prepopulate, and replay — no derivation.
    let root_read_key: Zeroizing<[u8; 32]> = {
        let mut k = [0u8; 32];
        let src = root_read_key.as_slice();
        let n = src.len().min(32);
        k[..n].copy_from_slice(&src[..n]);
        Zeroizing::new(k)
    };
    let root_write_key: Zeroizing<[u8; 32]> = {
        let mut k = [0u8; 32];
        let src = root_write_key.as_slice();
        let n = src.len().min(32);
        k[..n].copy_from_slice(&src[..n]);
        Zeroizing::new(k)
    };

    let mut inodes = cipherbox_fuse::inode::InodeTable::new();
    if let Some(root) = inodes.get_mut(cipherbox_fuse::inode::ROOT_INO) {
        root.kind = cipherbox_fuse::inode::InodeKind::Root {
            ipns_name: root_ipns_name.clone(),
            read_key: root_read_key.clone(),
            write_key: root_write_key.clone(),
            ipns_private_key: Zeroizing::new(root_ipns_private_key.clone().unwrap_or_default()),
        };
    }

    let (refresh_tx, refresh_rx) = std::sync::mpsc::channel::<PendingRefresh>();
    let (content_tx, content_rx) = std::sync::mpsc::channel::<PendingContent>();
    let (filepointer_tx, filepointer_rx) = std::sync::mpsc::channel::<PendingFilePointer>();
    let (upload_tx, upload_rx) = std::sync::mpsc::channel::<cipherbox_fuse::FsEvent>();

    // Pre-populate root folder and subfolders via shared prepopulate helper
    // (node/v3 gated owned listing). Returns initial_sequences for seeding the
    // PublishCoordinator (empty under node/v3 — see prepopulate module docs).
    let metadata_cache = cipherbox_fuse::cache::MetadataCache::new();
    let initial_sequences = crate::fuse::prepopulate::prepopulate_filesystem(
        &state.sdk.api,
        &mut inodes,
        &high_water,
        &root_ipns_name,
        &root_read_key,
        &root_write_key,
    )
    .await;

    // Construct coordinator before replay so it can be seeded and shared.
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

    // D-02: GC parked Failed journal entries + orphaned sidecars at mount. No background
    // scheduler exists for the journal, so mount is the natural sweep point (mirrors where
    // replay runs). This is synchronous and fast (a directory scan), only touches Failed
    // entries, and must never fail the mount — best-effort, non-fatal on Err (T-52-16, DoS).
    match journal.gc_failed_entries(
        cipherbox_sdk::JOURNAL_GC_MAX_AGE_DAYS,
        cipherbox_sdk::JOURNAL_GC_MAX_SIZE_BYTES,
    ) {
        Ok(n) if n > 0 => log::info!("Mount GC: removed {} parked/orphaned journal item(s)", n),
        Ok(_) => {}
        Err(e) => log::warn!("Mount GC failed (will continue mount): {}", e),
    }

    // Replay journal entries for this vault CONCURRENTLY with mount (D-03 / WR-07).
    // Previously this blocked the mount with `.await` — a hung IPNS/upload call could stall
    // the mount indefinitely. Now replay runs on a background tokio task (each entry's network
    // ops are individually bounded by `tokio::time::timeout` inside replay_for_vault), and the
    // mount proceeds immediately. Errors are logged but never fail the mount.
    //
    // Copy every argument into owned values for the replay task: the node/v3 root
    // read/write keys are `Copy` [u8;32]s and `replay_journal_dir` was cloned
    // before the journal dir moved into WriteQueue::new — so both the replay task
    // and the FS own their own copies (no move-then-borrow). Replay sends no
    // FsEvent::UploadComplete, so spawning before CipherBoxFS construction is race-free.
    {
        let replay_journal = journal.clone();
        let replay_api = state.sdk.api.clone();
        let replay_journal_dir = replay_journal_dir;
        // node/v3 root material (copies of the [u8;32] keys) — replaces the legacy
        // private_key/public_key/root_folder_key replay args.
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
        content_cache: cipherbox_fuse::cache::ContentCache::new(),
        api: state.sdk.api.clone(),
        private_key: Zeroizing::new(private_key),
        public_key: Zeroizing::new(public_key),
        root_folder_key,
        root_ipns_name,
        rt,
        next_fh: std::sync::atomic::AtomicU64::new(1),
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

    let mount_path_clone = mount_path.clone();

    #[cfg(target_os = "linux")]
    let options = vec![
        MountOption::FSName("CipherBox".to_string()),
        MountOption::DefaultPermissions,
        MountOption::RW,
    ];
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
                Ok(()) => {
                    log::info!("FUSE filesystem unmounted cleanly");
                    let _ = tx.send(Ok(()));
                }
                Err(e) => {
                    log::error!("FUSE mount error: {}", e);
                    let _ = tx.send(Err(format!("FUSE mount error: {}", e)));
                }
            }
        })
        .map_err(|e| format!("Failed to spawn FUSE thread: {}", e))?;

    match rx.recv_timeout(std::time::Duration::from_secs(2)) {
        Ok(Ok(())) => Err("FUSE filesystem unmounted immediately after mounting".to_string()),
        Ok(Err(e)) => Err(e),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            log::info!("FUSE mount confirmed at {}", mount_path.display());
            Ok(handle)
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err("FUSE mount thread exited unexpectedly".to_string())
        }
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
            dir.parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str()),
            Some("cipherbox"),
            "expected parent to be cipherbox, got {:?}",
            dir.parent()
        );
    }
}
