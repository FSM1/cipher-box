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
/// Delegates to the shared implementation in `crate::crypto::utils`.
pub fn mime_from_extension(filename: &str) -> String {
    crate::crypto::utils::mime_from_extension(filename).to_string()
}
