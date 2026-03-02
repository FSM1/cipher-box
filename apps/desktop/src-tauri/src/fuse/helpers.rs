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
pub fn mime_from_extension(filename: &str) -> String {
    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "bmp" => "image/bmp",
        "ico" => "image/x-icon",
        "pdf" => "application/pdf",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        "avi" => "video/x-msvideo",
        "mkv" => "video/x-matroska",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "flac" => "audio/flac",
        "aac" => "audio/aac",
        "txt" => "text/plain",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "zip" => "application/zip",
        "gz" | "gzip" => "application/gzip",
        "tar" => "application/x-tar",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "md" => "text/markdown",
        _ => "application/octet-stream",
    }
    .to_string()
}
