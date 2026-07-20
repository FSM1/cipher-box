//! The two-class error surface (blueprint/core.md "Error surface").
//!
//! Two classes, disjoint types, no reused codes: [`TrustViolation`] for
//! failures the engine treats fail-closed (canonicality, uniqueness — and in
//! later slices signature, commitment, AAD), and [`Malformed`] for
//! structurally invalid or unsupported input. Every rejection names the check
//! that fired via [`TrustViolation::check`] / [`Malformed::check`]; the check
//! names are part of the frozen contract and are pinned by the KAT reject
//! vectors.

use core::fmt;

/// A fail-closed trust violation: the input is well-formed enough to prove a
/// writer did not follow the deterministic profile (or, in later slices,
/// failed a cryptographic check). Never mere staleness, never retried.
///
/// The codec-layer boundary between the classes, frozen by the KAT reject
/// vectors: a violation is *trust* when a canonical encoding of the same data
/// exists and the writer emitted a different one (non-shortest forms,
/// indefinite lengths, unsorted or duplicate keys) — the signature of a
/// tampering or non-conforming re-encode. Shapes the profile has no
/// representation for at all (tags, floats, extra simple values, non-text
/// keys) are [`Malformed`]: foreign data, not a non-canonical form of valid
/// data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustViolation {
    /// An integer (major type 0/1) used a longer encoding than the shortest
    /// form the deterministic profile requires.
    NonCanonicalUint { offset: usize },
    /// A string/array/map length argument used a longer encoding than the
    /// shortest form.
    NonCanonicalLength { offset: usize },
    /// An indefinite-length string, array, or map.
    IndefiniteLength { offset: usize },
    /// Map keys not in strictly ascending canonical order (RFC 8949 §4.2.1
    /// bytewise lexicographic over the encoded keys).
    UnsortedMapKeys { offset: usize },
    /// The same key encoded twice in one map.
    DuplicateMapKey { offset: usize, key: String },
}

impl TrustViolation {
    /// Every trust-violation check name this crate can emit. The KAT manifest
    /// asserts reject-vector coverage against this list.
    pub const CHECKS: &'static [&'static str] = &[
        "non-canonical-uint",
        "non-canonical-length",
        "indefinite-length",
        "unsorted-map-keys",
        "duplicate-map-key",
    ];

    /// The stable name of the check that fired.
    pub fn check(&self) -> &'static str {
        match self {
            Self::NonCanonicalUint { .. } => "non-canonical-uint",
            Self::NonCanonicalLength { .. } => "non-canonical-length",
            Self::IndefiniteLength { .. } => "indefinite-length",
            Self::UnsortedMapKeys { .. } => "unsorted-map-keys",
            Self::DuplicateMapKey { .. } => "duplicate-map-key",
        }
    }

    fn offset(&self) -> usize {
        match self {
            Self::NonCanonicalUint { offset }
            | Self::NonCanonicalLength { offset }
            | Self::IndefiniteLength { offset }
            | Self::UnsortedMapKeys { offset }
            | Self::DuplicateMapKey { offset, .. } => *offset,
        }
    }
}

impl fmt::Display for TrustViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "trust violation [{}] at byte {}",
            self.check(),
            self.offset()
        )?;
        if let Self::DuplicateMapKey { key, .. } = self {
            write!(f, " (key {:?})", DisplayKey(key))?;
        }
        Ok(())
    }
}

impl std::error::Error for TrustViolation {}

/// Map keys rendered into error messages are writer-controlled content —
/// post-unseal they are sealed-body plaintext. `{:?}` escaping neutralizes
/// log injection; this cap bounds how much plaintext a crafted key can push
/// into upstream logs. Full redaction policy belongs to the engine.
const DISPLAY_KEY_MAX_CHARS: usize = 64;

struct DisplayKey<'a>(&'a str);

impl fmt::Debug for DisplayKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.char_indices().nth(DISPLAY_KEY_MAX_CHARS) {
            Some((cut, _)) => write!(f, "{:?}…", &self.0[..cut]),
            None => write!(f, "{:?}", self.0),
        }
    }
}

/// Structurally invalid or profile-unsupported input. Not evidence of
/// tampering; never accepted either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Malformed {
    /// Input ended before the item it promised.
    Truncated { offset: usize },
    /// Bytes remained after the single top-level item.
    TrailingBytes { offset: usize },
    /// A text string that is not valid UTF-8.
    InvalidUtf8 { offset: usize },
    /// A map key that is not a text string.
    InvalidMapKeyType { offset: usize },
    /// Any CBOR tag; the profile admits none.
    TagForbidden { offset: usize },
    /// Any floating-point item; the profile admits none.
    FloatForbidden { offset: usize },
    /// A simple value other than `false`/`true`/`null` (incl. `undefined`).
    SimpleValueForbidden { offset: usize },
    /// Reserved additional-information values (28–30, or 31 where the spec
    /// forbids it).
    ReservedAdditionalInfo { offset: usize },
    /// A break stop code (0xff) outside any indefinite-length item.
    UnexpectedBreak { offset: usize },
    /// Nesting beyond [`crate::codec::MAX_DEPTH`].
    DepthExceeded { offset: usize },
    /// A decoded value had a different type than the caller required
    /// (schema-layer accessor failure).
    UnexpectedType {
        expected: &'static str,
        found: &'static str,
    },
    /// A rewrite supplied a known field that collides with a preserved
    /// unknown field of the same key (caller bug; rejected fail-closed).
    UnknownFieldCollision { key: String },
}

impl Malformed {
    /// Every malformed check name this crate can emit. Decode-reachable ones
    /// are pinned by KAT reject vectors; the rest by unit tests.
    pub const CHECKS: &'static [&'static str] = &[
        "truncated",
        "trailing-bytes",
        "invalid-utf8",
        "invalid-map-key-type",
        "tag-forbidden",
        "float-forbidden",
        "simple-value-forbidden",
        "reserved-additional-info",
        "unexpected-break",
        "depth-exceeded",
        "unexpected-type",
        "unknown-field-collision",
    ];

    /// The stable name of the check that fired.
    pub fn check(&self) -> &'static str {
        match self {
            Self::Truncated { .. } => "truncated",
            Self::TrailingBytes { .. } => "trailing-bytes",
            Self::InvalidUtf8 { .. } => "invalid-utf8",
            Self::InvalidMapKeyType { .. } => "invalid-map-key-type",
            Self::TagForbidden { .. } => "tag-forbidden",
            Self::FloatForbidden { .. } => "float-forbidden",
            Self::SimpleValueForbidden { .. } => "simple-value-forbidden",
            Self::ReservedAdditionalInfo { .. } => "reserved-additional-info",
            Self::UnexpectedBreak { .. } => "unexpected-break",
            Self::DepthExceeded { .. } => "depth-exceeded",
            Self::UnexpectedType { .. } => "unexpected-type",
            Self::UnknownFieldCollision { .. } => "unknown-field-collision",
        }
    }
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed [{}]", self.check())?;
        match self {
            Self::Truncated { offset }
            | Self::TrailingBytes { offset }
            | Self::InvalidUtf8 { offset }
            | Self::InvalidMapKeyType { offset }
            | Self::TagForbidden { offset }
            | Self::FloatForbidden { offset }
            | Self::SimpleValueForbidden { offset }
            | Self::ReservedAdditionalInfo { offset }
            | Self::UnexpectedBreak { offset }
            | Self::DepthExceeded { offset } => write!(f, " at byte {offset}"),
            Self::UnexpectedType { expected, found } => {
                write!(f, " (expected {expected}, found {found})")
            }
            Self::UnknownFieldCollision { key } => {
                write!(f, " (key {:?})", DisplayKey(key))
            }
        }
    }
}

impl std::error::Error for Malformed {}

/// A codec failure: exactly one of the two disjoint classes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    Trust(TrustViolation),
    Malformed(Malformed),
}

impl CodecError {
    /// The stable name of the check that fired.
    pub fn check(&self) -> &'static str {
        match self {
            Self::Trust(e) => e.check(),
            Self::Malformed(e) => e.check(),
        }
    }

    /// `"trust"` or `"malformed"` — the class label used in reject vectors.
    pub fn class(&self) -> &'static str {
        match self {
            Self::Trust(_) => "trust",
            Self::Malformed(_) => "malformed",
        }
    }
}

impl From<TrustViolation> for CodecError {
    fn from(e: TrustViolation) -> Self {
        Self::Trust(e)
    }
}

impl From<Malformed> for CodecError {
    fn from(e: Malformed) -> Self {
        Self::Malformed(e)
    }
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Trust(e) => e.fmt(f),
            Self::Malformed(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for CodecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Trust(e) => Some(e),
            Self::Malformed(e) => Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_bounds_writer_controlled_keys() {
        let err = TrustViolation::DuplicateMapKey {
            offset: 0,
            key: "k".repeat(200),
        };
        let msg = err.to_string();
        assert!(msg.contains('…'), "long keys must render truncated");
        assert!(
            msg.len() < 160,
            "a crafted key must not flood the message: {msg}"
        );
        // Short keys render in full.
        let short = Malformed::UnknownFieldCollision { key: "v".into() };
        assert!(short.to_string().contains("\"v\""));
    }

    #[test]
    fn check_names_are_unique_across_both_classes() {
        let mut all: Vec<&str> = TrustViolation::CHECKS
            .iter()
            .chain(Malformed::CHECKS)
            .copied()
            .collect();
        let n = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), n, "check names must never be reused");
    }
}
