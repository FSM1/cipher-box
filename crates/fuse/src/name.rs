//! Name admission for the projection: syntax validation and the platform-junk
//! filter, decided once for every mount technology
//! (blueprint/desktop.md "Names and attributes").
//!
//! One rule set on all platforms is the point: a name a Linux mount accepts
//! must be creatable on Windows too, or a committed folder stops mounting
//! everywhere. Uniqueness itself is not decided here — that is the engine's
//! strict comparator.
//!
//! Admission is two-tier, because names also arrive *from* the engine and no
//! layer below validates them — a peer on any client can commit whatever CBOR
//! text string it likes. [`is_emittable`] is the narrow tier: names no kernel
//! protocol can carry at all. [`validate_name`] adds the create-only policy on
//! top. Everything the wider tier refuses stays listable and removable, or a
//! name another client committed would be stranded in the vault forever.

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
    /// The name contained NUL or another control character.
    Control,
    /// The name contained a bidi-override or zero-width character. These
    /// render as a different name than they compare as, so a hostile grant
    /// recipient could dress an executable up as a document.
    DeceptiveCharacter,
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

/// Whether the character reorders or hides the rest of the name when a file
/// manager draws it. `char::is_control` is category `Cc` only and misses all
/// of these; the engine's comparator folds case but not format characters, so
/// nothing downstream catches them either.
fn is_deceptive(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}' // zero-width space/joiners, LRM/RLM
            | '\u{202A}'..='\u{202E}' // bidi embeddings and overrides
            | '\u{2066}'..='\u{2069}' // bidi isolates
            | '\u{FEFF}' // zero-width no-break space
    )
}

/// Exact platform-junk names, already folded. One list for every platform: v1
/// kept a POSIX list and a Windows list that disagreed, so a `.DS_Store`
/// rejected on macOS synced happily from Windows.
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

/// Platform-junk name prefixes, already folded.
const JUNK_PREFIXES: &[&str] = &["._", ".trash-"];

/// Case-folded name equality, matching the engine's `collation_key` fold
/// rather than an ASCII one — U+212A KELVIN SIGN lowercases to `k`, so
/// `des\u{212A}top.ini` is `desktop.ini` to the engine's comparator and must
/// be to the junk filter too. Folds lazily so a listing allocates nothing.
fn folds_to(name: &str, folded: &str) -> bool {
    name.chars().flat_map(char::to_lowercase).eq(folded.chars())
}

/// Whether the name is platform junk: refused on create, hidden from
/// listings, and still reachable by an explicit lookup or unlink so junk that
/// arrived from another client stays removable through the mount.
pub fn is_platform_junk(name: &str) -> bool {
    JUNK_NAMES.iter().any(|junk| folds_to(name, junk))
        || JUNK_PREFIXES.iter().any(|prefix| {
            let head: String = name
                .chars()
                .flat_map(char::to_lowercase)
                .take(prefix.chars().count())
                .collect();
            head == *prefix
        })
}

/// Whether the name can be handed to a kernel at all: within the advertised
/// length, no separator, no NUL or other control character, not a synthesized
/// dot entry. A name failing this is not a listing the user could act on — it
/// is a malformed dirent, and every host protocol would mangle or misroute it.
pub fn is_emittable(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\'])
        && !name.chars().any(char::is_control)
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
    if name.chars().any(char::is_control) {
        return Err(NameError::Control);
    }
    if name.chars().any(is_deceptive) {
        return Err(NameError::DeceptiveCharacter);
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
    fn names_that_render_differently_than_they_compare_are_refused() {
        for name in [
            "invoice\u{202E}cod.exe", // right-to-left override: renders "invoiceexe.doc"
            "report\u{200B}.txt",     // zero-width space: a twin of "report.txt"
            "a\u{2066}b",
            "\u{FEFF}notes",
        ] {
            assert_eq!(
                validate_name(name),
                Err(NameError::DeceptiveCharacter),
                "{name:?} must not enter the vault"
            );
        }
        assert_eq!(validate_name("naïve — ünïcode.md"), Ok(()));
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
    fn junk_folds_the_way_the_engines_comparator_does() {
        // U+212A KELVIN SIGN lowercases to `k`, so the engine's comparator
        // sees `desktop.ini`. An ASCII-only fold here would let it through as
        // a distinct name that is nonetheless name-equal in the vault.
        assert!(is_platform_junk("des\u{212A}top.ini"));
        assert_eq!(
            validate_name("des\u{212A}top.ini"),
            Err(NameError::PlatformJunk)
        );
    }

    #[test]
    fn emittability_is_the_narrow_tier_of_admission() {
        // Names no kernel protocol can carry — the read path drops these.
        for name in ["", ".", "..", "a/b", "a\\b", "a\0b", &"x".repeat(256)] {
            assert!(!is_emittable(name), "{name:?} is not emittable");
        }
        // Refused at create, but still listable so they stay removable.
        for name in [".DS_Store", "re:port", "COM1", "report.", "a\u{202E}b"] {
            assert!(is_emittable(name), "{name:?} must stay reachable");
            assert!(validate_name(name).is_err(), "{name:?} is not creatable");
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
