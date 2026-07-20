//! The two-class error surface (blueprint/core.md "Error surface").
//!
//! Two classes, disjoint types, no reused codes: [`TrustViolation`] for
//! failures the engine treats fail-closed (canonicality, uniqueness, and the
//! cryptographic checks the suite layer contributes — subkey-binding verify,
//! HPKE open — with signature/commitment/AAD following in later slices) and
//! [`Malformed`] for structurally invalid or unsupported input. Every
//! rejection names the check that fired via [`TrustViolation::check`] /
//! [`Malformed::check`]; the check names are part of the frozen contract and
//! are pinned by the KAT reject vectors.
//!
//! The surface is crate-wide, not codec-only: the codec, the KDF catalog, and
//! the crypto suite all name their checks here so the two-class boundary and
//! the "no reused codes" law hold across the whole of `crates/core`.

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
    /// A subkey binding signature did not verify over the det-CBOR
    /// `{encSubkey, identityPk}` preimage. This is *trust*, never mere
    /// malformation: the contact code is structurally well-formed (both keys
    /// decode, the signature is a valid ECDSA encoding), yet the identity did
    /// not attest this encryption subkey — the exact forgery the mandatory
    /// import-time verify exists to reject fail-closed.
    SubkeyBindingInvalid,
    /// An HPKE ciphertext failed to open: the AEAD authentication tag did not
    /// verify under the derived key and AAD. *Trust*, not availability —
    /// unseal failure never silently degrades, and a tag mismatch is the
    /// signature of tampering or an AAD/enc transplant, not a retryable fetch
    /// error.
    HpkeOpenFailed,
    /// A symmetric sealed body failed to open: the XChaCha20-Poly1305 tag did
    /// not verify under the read/structure key and the structured AAD
    /// `(v, id, scope, epoch, structTag)`. *Trust*, not availability — the
    /// signature of tampering, an AAD transplant (a body re-hung under a
    /// different id/scope/epoch/tag), or a version downgrade (`v` is bound into
    /// the AAD, so a rolled-back `v` fails the tag). Unseal never silently
    /// degrades to staleness.
    SealOpenFailed,
    /// Two child refs in one folder read-body carried the same `id`. Uniqueness
    /// is fail-closed at decode (#39 D7): duplicate ids anywhere are a trust
    /// violation, never tolerated — a location-independent node id must name at
    /// most one child.
    DuplicateId,
    /// Two child refs in one folder read-body carried the same `ipnsName`.
    /// Uniqueness is fail-closed at decode (#39 D7): a duplicate name within a
    /// scope's child listing is the transplant closure the AAD deliberately
    /// leaves the name out for — rejected here instead of by the tag.
    DuplicateIpnsName,
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
        "subkey-binding-invalid",
        "hpke-open-failed",
        "seal-open-failed",
        "duplicate-id",
        "duplicate-ipns-name",
    ];

    /// The stable name of the check that fired.
    pub fn check(&self) -> &'static str {
        match self {
            Self::NonCanonicalUint { .. } => "non-canonical-uint",
            Self::NonCanonicalLength { .. } => "non-canonical-length",
            Self::IndefiniteLength { .. } => "indefinite-length",
            Self::UnsortedMapKeys { .. } => "unsorted-map-keys",
            Self::DuplicateMapKey { .. } => "duplicate-map-key",
            Self::SubkeyBindingInvalid => "subkey-binding-invalid",
            Self::HpkeOpenFailed => "hpke-open-failed",
            Self::SealOpenFailed => "seal-open-failed",
            Self::DuplicateId => "duplicate-id",
            Self::DuplicateIpnsName => "duplicate-ipns-name",
        }
    }
}

impl fmt::Display for TrustViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonCanonicalUint { offset }
            | Self::NonCanonicalLength { offset }
            | Self::IndefiniteLength { offset }
            | Self::UnsortedMapKeys { offset } => {
                write!(f, "trust violation [{}] at byte {offset}", self.check())
            }
            Self::DuplicateMapKey { offset, key } => write!(
                f,
                "trust violation [{}] at byte {offset} (key {:?})",
                self.check(),
                DisplayKey(key)
            ),
            // Cryptographic and post-decode structural checks carry no byte
            // offset: they fire on a decoded structure (or a whole ciphertext),
            // not a position in the encoded stream.
            Self::SubkeyBindingInvalid
            | Self::HpkeOpenFailed
            | Self::SealOpenFailed
            | Self::DuplicateId
            | Self::DuplicateIpnsName => {
                write!(f, "trust violation [{}]", self.check())
            }
        }
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
    /// A schema decode required a field that the map did not carry. *Malformed*,
    /// not trust: an absent field is structurally incomplete input, carrying no
    /// evidence a canonical form was tampered — the same class as a truncation.
    MissingField { field: &'static str },
    /// A contact code's `identityPk` field is not a valid compressed secp256k1
    /// point (wrong length, or not on the curve). *Malformed*: it is foreign
    /// bytes in an identity-key slot, not a non-canonical encoding of a real
    /// key — the class boundary the codec draws for shapes the profile cannot
    /// represent. Verify (a *trust* check) never runs on a key that cannot be
    /// parsed.
    InvalidIdentityKey,
    /// A contact code's `encSubkey` field is not a 32-byte X25519 public key.
    /// *Malformed* for the same reason as [`Self::InvalidIdentityKey`]: a
    /// length-wrong key slot is structurally invalid input, not tampering.
    InvalidEncSubkey,
    /// A contact code's `bindingSig` field is not a well-formed 64-byte compact
    /// ECDSA signature (wrong length, or `r`/`s` out of range). *Malformed*:
    /// the bytes cannot be parsed as a signature at all, which is distinct from
    /// a parseable signature that fails to verify — the latter is the *trust*
    /// check [`TrustViolation::SubkeyBindingInvalid`].
    InvalidBindingSigEncoding,
    /// A read-body's `kind` discriminant was a text string other than
    /// `"folder"`/`"file"`. *Malformed*: an unrecognized kind is foreign data
    /// in the tagged-union tag slot, not a non-canonical encoding of a known
    /// kind.
    InvalidNodeKind,
    /// A fixed-length byte field (a node `id`/`scope` at 16 bytes, a version
    /// `contentKey` at 32) carried the wrong number of bytes. *Malformed*: a
    /// length-wrong id/key slot is structurally invalid input, the same class
    /// as a truncation, not evidence a canonical form was tampered.
    InvalidFieldLength {
        field: &'static str,
        expected: usize,
        found: usize,
    },
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
        "missing-field",
        "invalid-identity-key",
        "invalid-enc-subkey",
        "invalid-binding-sig-encoding",
        "invalid-node-kind",
        "invalid-field-length",
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
            Self::MissingField { .. } => "missing-field",
            Self::InvalidIdentityKey => "invalid-identity-key",
            Self::InvalidEncSubkey => "invalid-enc-subkey",
            Self::InvalidBindingSigEncoding => "invalid-binding-sig-encoding",
            Self::InvalidNodeKind => "invalid-node-kind",
            Self::InvalidFieldLength { .. } => "invalid-field-length",
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
            Self::MissingField { field } => write!(f, " (field {field})"),
            Self::InvalidFieldLength {
                field,
                expected,
                found,
            } => write!(f, " (field {field}: expected {expected}, found {found})"),
            Self::InvalidIdentityKey
            | Self::InvalidEncSubkey
            | Self::InvalidBindingSigEncoding
            | Self::InvalidNodeKind => Ok(()),
        }
    }
}

impl std::error::Error for Malformed {}

/// A two-class failure: exactly one of the disjoint [`TrustViolation`] /
/// [`Malformed`] classes. Returned by the codec and by suite decoders that
/// can fail on either axis (contact-code import: structural `Malformed`
/// defects and the `SubkeyBindingInvalid` trust check share this union so a
/// single `.check()` / `.class()` pair describes every rejection).
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
