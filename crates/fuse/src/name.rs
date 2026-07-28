//! Name admission for the projection: syntax validation and the platform-junk
//! filter, decided once for every mount technology
//! (blueprint/desktop.md "Names and attributes").
//!
//! One rule set on all platforms is the point: a name a Linux mount accepts
//! must be creatable on Windows too, or a committed folder stops mounting
//! everywhere. Uniqueness itself is not decided here — that is the engine's
//! strict comparator.

/// The longest name the projection admits, in bytes. `statfs` advertises this
/// same constant, so what is advertised is what is enforced.
pub const MAX_NAME_BYTES: usize = 255;

/// Why a name was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    /// The name was empty.
    Empty,
    /// The name exceeded [`MAX_NAME_BYTES`].
    TooLong,
    /// The name was `.` or `..`.
    DotEntry,
    /// The name contained a path separator (`/` or `\`).
    Separator,
    /// The name contained NUL or another C0 control character.
    Control,
    /// The name contained a character Windows reserves (`< > : " | ? *`).
    ReservedCharacter,
    /// The name ended in a dot or a space, which Windows silently strips.
    TrailingDotOrSpace,
    /// The name is a Windows reserved device name (`CON`, `NUL`, `COM1`, …),
    /// with or without an extension.
    ReservedDevice,
    /// The name is platform junk (`.DS_Store`, `Thumbs.db`, …).
    PlatformJunk,
}

/// Characters Windows refuses in a path component. `/` and `\` are checked
/// separately so a caller sees [`NameError::Separator`].
const RESERVED_CHARACTERS: &[char] = &['<', '>', ':', '"', '|', '?', '*'];

/// Windows device names, reserved with or without an extension.
const RESERVED_DEVICES: &[&str] = &["con", "prn", "aux", "nul"];

/// Exact platform-junk names, ASCII-lowercased for comparison. One list for
/// every platform: v1 kept a POSIX list and a Windows list that disagreed, so
/// a `.DS_Store` rejected on macOS synced happily from Windows.
const JUNK_NAMES: &[&str] = &[
    // macOS
    ".ds_store",
    ".apdisk",
    ".documentrevisions-v100",
    ".fseventsd",
    ".hidden",
    ".localized",
    ".metadata_direct_scope_only",
    ".metadata_never_index",
    ".metadata_never_index_unless_rootfs",
    ".ql_disablecache",
    ".ql_disablethumbnails",
    ".spotlight-v100",
    ".temporaryitems",
    ".trashes",
    // Windows
    "$recycle.bin",
    "desktop.ini",
    "hiberfil.sys",
    "pagefile.sys",
    "recycler",
    "swapfile.sys",
    "system volume information",
    "thumbs.db",
    // Linux
    ".directory",
    ".gvfs",
    ".xdg-volume-info",
];

/// Platform-junk name prefixes, ASCII-lowercased for comparison.
const JUNK_PREFIXES: &[&str] = &["._", ".trash-"];

/// Whether the name is platform junk: refused on create, hidden from
/// listings, and still reachable by an explicit lookup or unlink so junk that
/// arrived from another client stays removable through the mount.
pub fn is_platform_junk(name: &str) -> bool {
    let folded = name.to_ascii_lowercase();
    JUNK_NAMES.contains(&folded.as_str())
        || JUNK_PREFIXES
            .iter()
            .any(|prefix| folded.starts_with(prefix))
}

/// Admit a name for create, mkdir, or a rename destination.
pub fn validate_name(name: &str) -> Result<(), NameError> {
    if name.is_empty() {
        return Err(NameError::Empty);
    }
    if name.len() > MAX_NAME_BYTES {
        return Err(NameError::TooLong);
    }
    if name == "." || name == ".." {
        return Err(NameError::DotEntry);
    }
    if name.contains('/') || name.contains('\\') {
        return Err(NameError::Separator);
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(NameError::Control);
    }
    if name.contains(RESERVED_CHARACTERS) {
        return Err(NameError::ReservedCharacter);
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return Err(NameError::TrailingDotOrSpace);
    }
    if is_reserved_device(name) {
        return Err(NameError::ReservedDevice);
    }
    if is_platform_junk(name) {
        return Err(NameError::PlatformJunk);
    }
    Ok(())
}

fn is_reserved_device(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).to_ascii_lowercase();
    if RESERVED_DEVICES.contains(&stem.as_str()) {
        return true;
    }
    let Some(digit) = stem
        .strip_prefix("com")
        .or_else(|| stem.strip_prefix("lpt"))
    else {
        return false;
    };
    matches!(digit, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_names_are_admitted() {
        for name in [
            "notes.txt",
            "Photos",
            "a",
            "naïve — ünïcode.md",
            "..leading",
        ] {
            assert_eq!(validate_name(name), Ok(()), "{name} should be admitted");
        }
    }

    #[test]
    fn the_advertised_length_limit_is_the_enforced_one() {
        let longest = "a".repeat(MAX_NAME_BYTES);
        assert_eq!(validate_name(&longest), Ok(()));
        assert_eq!(
            validate_name(&"a".repeat(MAX_NAME_BYTES + 1)),
            Err(NameError::TooLong)
        );
    }

    #[test]
    fn length_is_counted_in_bytes_not_characters() {
        // 128 two-byte characters: well under 255 chars, over 255 bytes.
        let name = "é".repeat(128);
        assert!(name.chars().count() < MAX_NAME_BYTES);
        assert_eq!(validate_name(&name), Err(NameError::TooLong));
    }

    #[test]
    fn structurally_impossible_names_are_refused() {
        assert_eq!(validate_name(""), Err(NameError::Empty));
        assert_eq!(validate_name("."), Err(NameError::DotEntry));
        assert_eq!(validate_name(".."), Err(NameError::DotEntry));
        assert_eq!(validate_name("a/b"), Err(NameError::Separator));
        assert_eq!(validate_name("a\\b"), Err(NameError::Separator));
        assert_eq!(validate_name("a\0b"), Err(NameError::Control));
        assert_eq!(validate_name("a\nb"), Err(NameError::Control));
    }

    #[test]
    fn windows_hostile_names_are_refused_on_every_platform() {
        for name in ["a<b", "a>b", "a:b", "a\"b", "a|b", "a?b", "a*b"] {
            assert_eq!(
                validate_name(name),
                Err(NameError::ReservedCharacter),
                "{name} must be refused everywhere, not only on Windows"
            );
        }
        assert_eq!(validate_name("report."), Err(NameError::TrailingDotOrSpace));
        assert_eq!(validate_name("report "), Err(NameError::TrailingDotOrSpace));
        for name in ["CON", "nul", "Aux", "prn", "COM1", "lpt9", "con.txt"] {
            assert_eq!(
                validate_name(name),
                Err(NameError::ReservedDevice),
                "{name} is a reserved device name"
            );
        }
        for name in ["com", "com0", "lpt10", "console"] {
            assert_eq!(validate_name(name), Ok(()), "{name} is not reserved");
        }
    }

    #[test]
    fn junk_is_refused_and_folds_case() {
        for name in [
            ".DS_Store",
            ".ds_store",
            "Thumbs.db",
            "THUMBS.DB",
            "desktop.ini",
            "._resource",
            ".Trash-1000",
            "$RECYCLE.BIN",
            "System Volume Information",
            ".gvfs",
        ] {
            assert!(is_platform_junk(name), "{name} is junk");
            assert_eq!(validate_name(name), Err(NameError::PlatformJunk));
        }
    }

    #[test]
    fn junk_matching_does_not_swallow_real_names() {
        for name in ["DCIM", "Desktop", "recycle.bin", "trash", "directory"] {
            assert!(!is_platform_junk(name), "{name} is a legitimate name");
            assert_eq!(validate_name(name), Ok(()));
        }
    }
}
