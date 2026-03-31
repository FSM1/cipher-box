//! Shared helper functions for the CipherBox FUSE filesystem.
//!
//! These functions are used by both macOS (fuser) and Windows (WinFsp)
//! filesystem implementations.

/// Returns true if this filename is a platform-specific special file
/// that should never be created, synced, or shown in directory listings.
///
/// Covers macOS, Windows, and Linux special files.
pub fn is_platform_special(name: &str) -> bool {
    // macOS
    name.starts_with("._")
        || name == ".DS_Store"
        || name == ".Trashes"
        || name == ".fseventsd"
        || name == ".Spotlight-V100"
        || name == ".hidden"
        || name == ".localized"
        || name == ".metadata_never_index"
        || name == ".metadata_never_index_unless_rootfs"
        || name == ".metadata_direct_scope_only"
        || name == ".ql_disablecache"
        || name == ".ql_disablethumbnails"
        || name == "DCIM"
    // Windows
        || name == "Thumbs.db"
        || name == "desktop.ini"
    // Linux
        || name == ".directory"             // KDE directory metadata
        || name.starts_with(".Trash-")      // Per-user trash dirs (.Trash-1000)
        || name == ".gvfs"                  // GNOME Virtual File System
        || name == ".xdg-volume-info"       // XDG volume info
}

/// Returns true if this filename is a Windows-specific special file
/// that should never be created, synced, or shown in directory listings.
///
/// This is a superset check for Windows: includes NTFS system files,
/// alternate data streams, and recycle bin artifacts in addition to
/// the cross-platform checks.
pub fn is_windows_special(name: &str) -> bool {
    let lower = name.to_lowercase();
    matches!(
        lower.as_str(),
        "desktop.ini"
            | "thumbs.db"
            | "$recycle.bin"
            | "system volume information"
            | "recycler"
            | "pagefile.sys"
            | "swapfile.sys"
            | "hiberfil.sys"
    ) || lower.contains(":zone.identifier")
        || lower.starts_with('$')
}

/// Detect MIME type from file extension.
///
/// Delegates to the shared implementation in `cipherbox_crypto::utils`.
pub fn mime_from_extension(filename: &str) -> String {
    cipherbox_crypto::utils::mime_from_extension(filename).to_string()
}

/// Build a human-readable breadcrumb path for a folder inode.
/// Walks parent_ino upward to root, concatenating names with " / ".
/// Example: "My Vault / Documents / Reports"
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn build_folder_path(fs: &crate::CipherBoxFS, folder_ino: u64) -> String {
    use crate::inode::InodeKind;
    let mut parts = Vec::new();
    let mut current = folder_ino;
    for _ in 0..20 { // Safety limit to prevent infinite loops
        match fs.inodes.get(current) {
            Some(inode) => {
                match &inode.kind {
                    InodeKind::Root { .. } => {
                        parts.push("My Vault".to_string());
                        break;
                    }
                    _ => {
                        parts.push(inode.name.clone());
                        current = inode.parent_ino;
                    }
                }
            }
            None => break,
        }
    }
    parts.reverse();
    parts.join(" / ")
}

/// Evaluate whether a new version should be created and prune excess versions.
///
/// Shared across all platforms (macOS, Linux, Windows) to ensure consistent
/// versioning behavior regardless of the FUSE/WinFSP backend.
///
/// Returns `(versions, pruned_cids)` where `pruned_cids` contains CIDs of
/// versions that exceeded `max_versions` and should be unpinned.
pub fn apply_versioning(
    existing_versions: Option<Vec<cipherbox_core::folder::VersionEntry>>,
    old_file_cid: &Option<String>,
    old_encrypted_key: &str,
    old_iv: &str,
    old_size: u64,
    old_mode: &str,
    now_ms: u64,
    max_versions: usize,
    cooldown_ms: u64,
    ino: u64,
) -> (Option<Vec<cipherbox_core::folder::VersionEntry>>, Vec<String>) {
    let should_version = if let Some(ref versions) = existing_versions {
        if let Some(newest) = versions.first() {
            now_ms.saturating_sub(newest.timestamp) >= cooldown_ms
        } else {
            old_file_cid.as_ref().is_some_and(|c| !c.is_empty())
        }
    } else {
        old_file_cid.as_ref().is_some_and(|c| !c.is_empty())
    };

    if !should_version {
        if existing_versions.is_some() {
            log::debug!("Version cooldown active for ino {} -- skipping version creation", ino);
        }
        return (existing_versions, vec![]);
    }

    match old_file_cid {
        Some(ref old_c) if !old_c.is_empty() => {
            let version_entry = cipherbox_core::folder::VersionEntry {
                cid: old_c.clone(),
                file_key_encrypted: old_encrypted_key.to_string(),
                file_iv: old_iv.to_string(),
                size: old_size,
                timestamp: now_ms,
                encryption_mode: old_mode.to_string(),
            };
            let mut versions = vec![version_entry];
            versions.extend(existing_versions.unwrap_or_default());
            let pruned: Vec<String> = if versions.len() > max_versions {
                versions.split_off(max_versions).into_iter().map(|v| v.cid).collect()
            } else {
                vec![]
            };
            if !pruned.is_empty() {
                log::info!("Pruned {} version(s) for ino {} (exceeded max {})", pruned.len(), ino, max_versions);
            }
            log::debug!("Created version entry for ino {} (total versions: {})", ino, versions.len());
            (Some(versions), pruned)
        }
        _ => (existing_versions, vec![]),
    }
}

/// Convert VersionEntry list to VersionCidEntry list for bin entries.
/// Filters out entries with empty CIDs and returns None if the result is empty.
pub fn versions_to_bin_entries(
    versions: &Option<Vec<cipherbox_core::folder::VersionEntry>>,
) -> Option<Vec<cipherbox_core::bin::VersionCidEntry>> {
    versions.as_ref().and_then(|items| {
        let mapped: Vec<cipherbox_core::bin::VersionCidEntry> = items
            .iter()
            .filter(|v| !v.cid.is_empty())
            .map(|v| cipherbox_core::bin::VersionCidEntry {
                cid: v.cid.clone(),
                size: v.size,
            })
            .collect();
        if mapped.is_empty() { None } else { Some(mapped) }
    })
}
