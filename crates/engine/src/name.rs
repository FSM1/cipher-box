//! The one node-name law: what a name must be for every host CipherBox
//! projects onto to carry it (blueprint/desktop.md "Names and attributes").
//!
//! The law is the intersection of what macOS, Linux and Windows accept, and it
//! lives here rather than at a projection because the facade is the only
//! boundary every client crosses — a web caller reaches it with no mount in
//! front of it. Uniqueness is not decided here: that is the strict comparator
//! ([`crate::sync::collation_key`]).
//!
//! Admission is two-tier, because names also arrive *from* peers and no layer
//! below validates them — a peer on any client can commit whatever CBOR text
//! string it likes. [`is_emittable`] is the narrow tier: names no kernel
//! protocol can carry at all. [`validate_name`] adds the create-time policy on
//! top. Everything the wider tier refuses stays listable and removable, or a
//! name another client committed would be stranded in the vault forever.

/// The longest node name a command may carry, in bytes.
///
/// The projection advertises this same constant through `statfs`, so what a
/// mount advertises is what the facade enforces.
pub const MAX_NODE_NAME_BYTES: usize = 255;

/// Why a name was refused.
///
/// The law raises every variant but [`NameError::PlatformJunk`], which a
/// projection's junk filter adds on top of it (`crates/fuse/src/name.rs`): one
/// vocabulary, so one errno and NTSTATUS mapping serves both tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    /// The name was empty.
    Empty,
    /// The name exceeded [`MAX_NODE_NAME_BYTES`].
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

impl NameError {
    /// The stable check label a refusal reports to a host.
    pub fn check(self) -> &'static str {
        match self {
            Self::Empty => "node-name-empty",
            Self::TooLong => "node-name-too-long",
            Self::DotEntry => "node-name-dot-entry",
            Self::Separator => "node-name-separator",
            Self::Control => "node-name-control",
            Self::DeceptiveCharacter => "node-name-deceptive-character",
            Self::ReservedCharacter => "node-name-reserved-character",
            Self::TrailingDotOrSpace => "node-name-trailing-dot-or-space",
            Self::ReservedDevice => "node-name-reserved-device",
            Self::PlatformJunk => "node-name-platform-junk",
        }
    }
}

/// Characters Windows refuses in a path component. `/` and `\` are checked
/// separately so a caller sees [`NameError::Separator`].
const RESERVED_CHARACTERS: &[char] = &['<', '>', ':', '"', '|', '?', '*'];

/// Windows device names, reserved with or without an extension.
const RESERVED_DEVICES: &[&str] = &["con", "prn", "aux", "nul"];

/// Whether the character reorders or hides the rest of the name when a file
/// manager draws it. `char::is_control` is category `Cc` only and misses all
/// of these; the strict comparator folds case but not format characters, so
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

/// Whether the name can be handed to a kernel at all: within the advertised
/// length, no separator, no NUL or other control character, not a synthesized
/// dot entry. A name failing this is not a listing the user could act on — it
/// is a malformed dirent, and every host protocol would mangle or misroute it.
pub fn is_emittable(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NODE_NAME_BYTES
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\'])
        && !name.chars().any(char::is_control)
}

/// Admit a name for a create, a mkdir, or a rename destination.
pub fn validate_name(name: &str) -> Result<(), NameError> {
    if name.is_empty() {
        return Err(NameError::Empty);
    }
    if name.len() > MAX_NODE_NAME_BYTES {
        return Err(NameError::TooLong);
    }
    if name == "." || name == ".." {
        return Err(NameError::DotEntry);
    }
    if name.contains(['/', '\\']) {
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
    use crate::testkit::name_law::{name_law_vectors, verdict};

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
        let longest = "a".repeat(MAX_NODE_NAME_BYTES);
        assert_eq!(validate_name(&longest), Ok(()));
        assert_eq!(
            validate_name(&"a".repeat(MAX_NODE_NAME_BYTES + 1)),
            Err(NameError::TooLong)
        );
    }

    #[test]
    fn length_is_counted_in_bytes_not_characters() {
        // 128 two-byte characters: well under 255 chars, over 255 bytes.
        let name = "é".repeat(128);
        assert!(name.chars().count() < MAX_NODE_NAME_BYTES);
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
    fn emittability_is_the_narrow_tier_of_admission() {
        // Names no kernel protocol can carry — the read path drops these.
        for name in [
            "",
            ".",
            "..",
            "a/b",
            "a\\b",
            "a\0b",
            &"x".repeat(MAX_NODE_NAME_BYTES + 1),
        ] {
            assert!(!is_emittable(name), "{name:?} is not emittable");
        }
        assert!(
            is_emittable(&"x".repeat(MAX_NODE_NAME_BYTES)),
            "the advertised length is emittable"
        );
        // Refused at create, but still listable so they stay removable.
        for name in ["re:port", "COM1", "report.", "a\u{202E}b"] {
            assert!(is_emittable(name), "{name:?} must stay reachable");
            assert!(validate_name(name).is_err(), "{name:?} is not creatable");
        }
    }

    /// The frozen vector set is what the projection and the TypeScript client
    /// check against, so the law itself must answer every row.
    #[test]
    fn the_frozen_vectors_are_the_law() {
        let vectors = name_law_vectors();
        assert!(vectors.names.len() > 30, "the vector set is loaded");
        for row in &vectors.names {
            assert_eq!(
                verdict(validate_name(&row.name)),
                row.verdict,
                "{:?} must be {}",
                row.name,
                row.verdict
            );
            assert_eq!(
                is_emittable(&row.name),
                row.emittable,
                "{:?} emittability",
                row.name
            );
        }
    }

    #[test]
    fn every_refusal_reports_a_distinct_check_label() {
        let labels: std::collections::BTreeSet<&str> = [
            NameError::Empty,
            NameError::TooLong,
            NameError::DotEntry,
            NameError::Separator,
            NameError::Control,
            NameError::DeceptiveCharacter,
            NameError::ReservedCharacter,
            NameError::TrailingDotOrSpace,
            NameError::ReservedDevice,
            NameError::PlatformJunk,
        ]
        .into_iter()
        .map(NameError::check)
        .collect();
        assert_eq!(labels.len(), 10, "a host tells the refusals apart");
    }
}
