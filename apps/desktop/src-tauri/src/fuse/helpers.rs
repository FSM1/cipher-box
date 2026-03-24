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
pub fn build_folder_path(fs: &crate::fuse::CipherBoxFS, folder_ino: u64) -> String {
    use crate::fuse::inode::InodeKind;
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
