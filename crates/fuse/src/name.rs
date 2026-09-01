//! Name admission for the projection: the engine's name law, plus the
//! platform-junk filter that is the mount's own concern
//! (blueprint/desktop.md "Names and attributes").
//!
//! The law itself lives in the engine ([`cipherbox_engine::name`]) because the
//! facade is the boundary every client crosses. What stays here is projection
//! policy: junk a desktop host writes by itself is refused at create and hidden
//! from listings, and stays reachable by an explicit lookup or unlink so junk
//! another client committed is still removable through the mount.

use cipherbox_engine::name::validate_name as validate_law;
use cipherbox_engine::sync::case_fold;

pub use cipherbox_engine::name::{NameError, is_emittable};

/// The longest name the projection admits, in bytes. `statfs` advertises this
/// same constant, so what is advertised is what is enforced. Aliased from the
/// engine's command boundary rather than restated, so a name this mount admits
/// at create is one the facade takes.
pub const MAX_NAME_BYTES: usize = cipherbox_engine::MAX_NODE_NAME_BYTES;

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

/// Case-folded name equality against an already-folded ASCII literal, over
/// [`case_fold`] — U+212A KELVIN SIGN folds to `k`, so `des\u{212A}top.ini` is
/// `desktop.ini` to the comparator and must be to the junk filter too. It skips
/// the comparator's NFC step, which is safe because no junk literal holds `;`
/// or `` ` `` — the only two ASCII characters NFC reaches from a non-ASCII one
/// (U+037E and U+1FEF). Folds lazily so a listing allocates nothing.
fn folds_to(name: &str, folded: &str) -> bool {
    case_fold(name.chars()).eq(folded.chars())
}

/// Whether the name is platform junk: refused on create, hidden from
/// listings, and still reachable by an explicit lookup or unlink so junk that
/// arrived from another client stays removable through the mount.
pub fn is_platform_junk(name: &str) -> bool {
    JUNK_NAMES.iter().any(|junk| folds_to(name, junk))
        || JUNK_PREFIXES.iter().any(|prefix| {
            case_fold(name.chars())
                .take(prefix.chars().count())
                .eq(prefix.chars())
        })
}

/// Admit a name for create, mkdir, or a rename destination: the engine's law,
/// then the junk filter.
pub fn validate_name(name: &str) -> Result<(), NameError> {
    validate_law(name)?;
    if is_platform_junk(name) {
        return Err(NameError::PlatformJunk);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_engine::sync::collation_key;
    use cipherbox_engine::testkit::name_law::{name_law_vectors, verdict};

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
        // Each of these is name-equal to a junk literal under the engine's
        // comparator, so the filter must refuse it too — otherwise the mount
        // creates a name the vault already holds. U+212A KELVIN SIGN folds to
        // `k`; U+017F LATIN SMALL LETTER LONG S folds to `s`, which a lowercase
        // mapping does not do at all.
        for (name, junk) in [
            ("des\u{212A}top.ini", "desktop.ini"),
            (".d\u{17f}_store", ".ds_store"),
            (".\u{17f}potlight-v100", ".spotlight-v100"),
            // A prefix match folds by the same rule.
            (".tra\u{17f}h-1000", ".trash-1000"),
        ] {
            assert!(is_platform_junk(name), "{name:?} is junk to the comparator");
            assert_eq!(validate_name(name), Err(NameError::PlatformJunk));
            assert_eq!(
                collation_key(name),
                collation_key(junk),
                "{name:?} is one vault entry with {junk:?}, so the filter must agree"
            );
        }
    }

    /// Junk is refused at create and still listable, or a `.DS_Store` another
    /// client committed could never be unlinked through the mount.
    #[test]
    fn junk_stays_emittable() {
        for name in [".DS_Store", "Thumbs.db", "._resource"] {
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

    /// Both lists claim to be "already folded", and `folds_to` skips NFC on the
    /// strength of them being ASCII. Neither claim is checked anywhere else, so
    /// a non-ASCII or unfolded literal would silently never match.
    #[test]
    fn every_junk_literal_is_ascii_and_already_folded() {
        for literal in JUNK_NAMES.iter().chain(JUNK_PREFIXES) {
            assert!(literal.is_ascii(), "{literal:?} must be ASCII");
            assert!(
                folds_to(literal, literal),
                "{literal:?} must be its own fold"
            );
            assert!(
                !literal.contains([';', '`']),
                "{literal:?} holds an ASCII character NFC can reach"
            );
        }
    }

    /// The projection answers the frozen vector set exactly as the engine does:
    /// a mount that admitted a name the facade refuses would fail the create
    /// after the kernel had already been told the name was good.
    #[test]
    fn the_frozen_vectors_reach_the_projection_unchanged() {
        let vectors = name_law_vectors();
        assert!(vectors.names.len() > 30, "the vector set is loaded");
        for row in &vectors.names {
            assert!(
                !is_platform_junk(&row.name),
                "{:?} is junk, which is not a law verdict",
                row.name
            );
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
    fn the_advertised_length_is_the_engines_bound() {
        assert_eq!(MAX_NAME_BYTES, cipherbox_engine::MAX_NODE_NAME_BYTES);
        assert!(is_emittable(&"x".repeat(MAX_NAME_BYTES)));
        assert_eq!(
            validate_name(&"x".repeat(MAX_NAME_BYTES + 1)),
            Err(NameError::TooLong)
        );
    }
}
