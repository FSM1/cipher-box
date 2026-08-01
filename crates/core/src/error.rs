//! The two-class error surface (blueprint/core.md "Error surface").
//!
//! Two classes, disjoint types, no reused codes: [`TrustViolation`] for
//! failures the engine treats fail-closed (canonicality, uniqueness, and the
//! cryptographic checks — signature, commitment, AAD, subkey-binding verify,
//! HPKE open) and [`Malformed`] for structurally invalid or unsupported input.
//! Every rejection names the check that fired via [`TrustViolation::check`] /
//! [`Malformed::check`]; the check names are part of the frozen contract and
//! are pinned by the KAT reject vectors.
//!
//! The surface is crate-wide, not codec-only: the codec, the KDF catalog, and
//! the crypto suite all name their checks here so the two-class boundary and
//! the "no reused codes" law hold across the whole of `crates/core`.

use core::fmt;

/// A fail-closed trust violation: the input is well-formed enough to prove a
/// writer did not follow the deterministic profile, or it failed a
/// cryptographic check. Never mere staleness, never retried.
///
/// The codec-layer boundary between the classes, frozen by the KAT reject
/// vectors: a violation is *trust* when a canonical encoding of the same data
/// exists and the writer emitted a different one (non-shortest forms,
/// indefinite lengths, unsorted or duplicate keys) — the signature of tampering
/// or a non-conforming re-encode. Shapes the profile has no representation for
/// at all (tags, floats, extra simple values, non-text keys) are [`Malformed`]:
/// foreign data, not a non-canonical form of valid data.
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
    /// `{encSubkey, identityPk}` preimage. *Trust*, not malformation: the code
    /// is structurally well-formed, yet the identity did not attest this
    /// encryption subkey — the forgery the mandatory import-time verify rejects.
    SubkeyBindingInvalid,
    /// An HPKE ciphertext failed to open: the AEAD tag did not verify under the
    /// derived key and AAD. *Trust*, not availability — a tag mismatch is the
    /// signature of tampering or an AAD/enc transplant, never a retryable error.
    HpkeOpenFailed,
    /// A low-order X25519 peer/recipient key forced a non-contributory (all-zero)
    /// DHKEM shared secret, or a contact code's `encSubkey` was such a point
    /// (RFC 9180 §7.1.4). *Trust*, not malformation: the bytes are a valid
    /// 32-byte key, so this is a **chosen-key** attack — a degenerate point
    /// picked so the derived AEAD key depends only on public material (the
    /// sealed seed becomes openable by anyone). Fires before any open, at HPKE
    /// decap and at contact import, distinct from a tag mismatch
    /// ([`Self::HpkeOpenFailed`]).
    HpkeNonContributory,
    /// A symmetric sealed body failed to open: the XChaCha20-Poly1305 tag did
    /// not verify under the read/structure key and the structured AAD
    /// `(v, id, scope, epoch, structTag)`. *Trust*, not availability — the
    /// signature of an AAD transplant (a body re-hung under a different
    /// id/scope/epoch/tag) or a `v` downgrade, both bound into the AAD. Unseal
    /// never silently degrades to staleness.
    SealOpenFailed,
    /// A sealed content blob did not content-address to its claimed `contentCid`
    /// (blueprint/core.md "Open edges"). *Trust*, never staleness: the CID is a
    /// BLAKE3 digest over the sealed bytes, so a mismatch is evidence the bytes
    /// were substituted — distinct from an unopened seal
    /// ([`Self::SealOpenFailed`]).
    ContentCidMismatch,
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
    /// Two rows of a grant ledger or grant-set commitment carried the same
    /// blinded `tag`. The exact analog of [`Self::DuplicateId`] (#39 D7): a tag
    /// locates its grant blob and its committed `(permission, pseudonymPk)`, so
    /// a duplicate is a confused-deputy over read-vs-write authority. Fail-closed
    /// at decode, never first-match.
    DuplicateGrantTag,
    /// An IPNS record's `signatureV2` did not verify over
    /// `"ipns-signature:" || data` under the Ed25519 key **extracted from the
    /// name itself** (#24). *Trust*: the record is structurally a well-formed
    /// IPNS V2 record, yet the named key did not author this data — the forgery
    /// the pure verify chain exists to reject fail-closed, never staleness.
    IpnsSignatureInvalid,
    /// An IPNS record's signed `data.Value` did not equal its top-level `value`
    /// field. *Trust*: `signatureV2` covers only `data`, so a disagreeing
    /// unsigned top-level `value` is evidence the envelope was tampered after
    /// signing — the data/Value consistency check the gate depends on.
    IpnsValueMismatch,
    /// An owner/sender secp256k1 **identity** signature did not verify over its
    /// det-CBOR preimage: the re-point object's owner signature or a mailbox
    /// item's sender signature (blueprint/core.md "Crypto suite": identity
    /// signing). *Trust*: the structure decoded and the signature is a valid
    /// ECDSA encoding, yet the claimed identity did not author it.
    IdentitySignatureInvalid,
    /// A detached structure signature did not verify over its det-CBOR preimage
    /// `{scopeId, epoch, structTag, recipientTag?, H(ciphertext)}` (#39 D2/D3).
    /// *Trust*, never staleness: the preimage binds the scope, epoch, structure
    /// tag, and (for grant blobs) the recipient tag, so this fires on a forged
    /// signature, a signature transplanted to a different structure tag, or a
    /// grant blob's signature replayed under a different recipient tag. The
    /// whole-record fail-closed policy over this verdict is the engine's gate.
    StructureSignatureInvalid,
    /// A grant-set commitment's identity ECDSA signature did not verify over its
    /// det-CBOR preimage `{ipnsName, ownerPseudonymPk, [(tag, permission,
    /// pseudonymPk)]}`. *Trust*: the commitment is structurally well-formed, yet
    /// the owner did not attest this tag/pseudonym set — the forgery the
    /// mandatory recipient-side commitment verify rejects fail-closed.
    CommitmentInvalid,
    /// An ascent link's plaintext public half did not match the X25519 public
    /// key re-derived from the parent node seed (the ascent-keypair edge). The
    /// derive-and-verify check (blueprint/core.md "Envelope and structures"):
    /// an ancestor reader re-derives the expected keypair and rejects a
    /// mismatched public half before opening. *Trust*, never staleness.
    AscentLinkMismatch,
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
        "hpke-non-contributory",
        "seal-open-failed",
        "content-cid-mismatch",
        "duplicate-id",
        "duplicate-ipns-name",
        "duplicate-grant-tag",
        "ipns-signature-invalid",
        "ipns-value-mismatch",
        "identity-signature-invalid",
        "structure-signature-invalid",
        "commitment-invalid",
        "ascent-link-mismatch",
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
            Self::HpkeNonContributory => "hpke-non-contributory",
            Self::SealOpenFailed => "seal-open-failed",
            Self::ContentCidMismatch => "content-cid-mismatch",
            Self::DuplicateId => "duplicate-id",
            Self::DuplicateIpnsName => "duplicate-ipns-name",
            Self::DuplicateGrantTag => "duplicate-grant-tag",
            Self::IpnsSignatureInvalid => "ipns-signature-invalid",
            Self::IpnsValueMismatch => "ipns-value-mismatch",
            Self::IdentitySignatureInvalid => "identity-signature-invalid",
            Self::StructureSignatureInvalid => "structure-signature-invalid",
            Self::CommitmentInvalid => "commitment-invalid",
            Self::AscentLinkMismatch => "ascent-link-mismatch",
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
            | Self::HpkeNonContributory
            | Self::SealOpenFailed
            | Self::ContentCidMismatch
            | Self::DuplicateId
            | Self::DuplicateIpnsName
            | Self::DuplicateGrantTag
            | Self::IpnsSignatureInvalid
            | Self::IpnsValueMismatch
            | Self::IdentitySignatureInvalid
            | Self::StructureSignatureInvalid
            | Self::CommitmentInvalid
            | Self::AscentLinkMismatch => {
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

pub(crate) struct DisplayKey<'a>(pub(crate) &'a str);

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
    /// An encode of a map [`crate::codec::Map::zeroize_bytes`] already wiped
    /// (caller bug; rejected fail-closed). The wipe is terminal: its fields are
    /// zero-length, and the variable-length ones re-decode as empty rather than
    /// failing, so emitting from one is silent data loss.
    WipedMap,
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
    /// A grant `permission` field was a text string other than `"read"`/`"write"`
    /// (the grant ledger and the grant-set commitment). *Malformed*: an
    /// unrecognized permission is foreign data in the permission slot, the same
    /// class boundary [`Self::InvalidNodeKind`] draws for the kind discriminant.
    InvalidPermission,
    /// A fixed-length byte field (a node `id`/`scope` at 16 bytes, a version
    /// `contentKey` at 32) carried the wrong number of bytes. *Malformed*: a
    /// length-wrong id/key slot is structurally invalid input, the same class
    /// as a truncation, not evidence a canonical form was tampered.
    InvalidFieldLength {
        field: &'static str,
        expected: usize,
        found: usize,
    },
    /// An `ipnsName` string was not the one canonical base36 CIDv1 libp2p-key
    /// encoding of a valid Ed25519 public key: wrong multibase prefix, non-base36
    /// characters, a wrong CID/multihash/protobuf layout, or a digest that is not
    /// a valid compressed Edwards point. *Malformed*: foreign bytes in a name
    /// slot, not a non-canonical encoding of a real name (the strict decode keeps
    /// the Rust side fail-closed).
    IpnsNameMalformed,
    /// A content-CID string was not the one canonical base32-lowercase multibase
    /// (`b`-prefixed) CIDv1 with the frozen content-plane framing (version 1, a
    /// single-byte multicodec, the BLAKE3 multihash code, 32-byte digest length):
    /// wrong/missing multibase prefix, a non-base32 or non-canonical body, a wrong
    /// length, or wrong framing bytes. *Malformed*: foreign bytes in a content-CID
    /// slot, not a non-canonical encoding of a real CID — the strict decode keeps
    /// the recovered head anchor fail-closed before a fetch trusts it.
    ContentCidStrMalformed,
    /// A durable op record at this build's version carried a key outside its
    /// frozen five. *Malformed*: the five keys are exhaustive at a given `v`
    /// (a bump is the extension mechanism), and anything else is unauthenticated
    /// — extra keys sit outside the AAD, so a local writer could hang arbitrary
    /// bytes off an otherwise integrity-protected record.
    UnknownRecordField { key: String },
    /// A durable op record declared a format version this build does not
    /// implement. *Malformed*, not trust: a forward-version record is intact
    /// input this decoder cannot interpret. A rewritten `v` lands here too —
    /// deliberately, since the gate runs before the AEAD; the AAD's version
    /// binding closes downgrade *between* supported versions instead. The
    /// distinction is load-bearing: the engine **retains** such a record rather
    /// than dead-lettering a queue it cannot yet read.
    UnsupportedRecordVersion { version: u64 },
    /// An IPNS record's protobuf could not be parsed, or it was missing a field
    /// the V2 verify chain requires (`value`, `signatureV2`, or `data`), or its
    /// `data` field was not the frozen det-CBOR shape. *Malformed*: structurally
    /// incomplete or foreign input, not evidence a canonical form was tampered —
    /// the signature check (a *trust* check) never runs on a record that cannot
    /// be parsed.
    IpnsRecordMalformed,
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
        "wiped-map",
        "missing-field",
        "invalid-identity-key",
        "invalid-enc-subkey",
        "invalid-binding-sig-encoding",
        "invalid-node-kind",
        "invalid-permission",
        "invalid-field-length",
        "ipns-name-malformed",
        "content-cid-str-malformed",
        "unknown-record-field",
        "unsupported-record-version",
        "ipns-record-malformed",
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
            Self::WipedMap => "wiped-map",
            Self::MissingField { .. } => "missing-field",
            Self::InvalidIdentityKey => "invalid-identity-key",
            Self::InvalidEncSubkey => "invalid-enc-subkey",
            Self::InvalidBindingSigEncoding => "invalid-binding-sig-encoding",
            Self::InvalidNodeKind => "invalid-node-kind",
            Self::InvalidPermission => "invalid-permission",
            Self::InvalidFieldLength { .. } => "invalid-field-length",
            Self::IpnsNameMalformed => "ipns-name-malformed",
            Self::ContentCidStrMalformed => "content-cid-str-malformed",
            Self::UnknownRecordField { .. } => "unknown-record-field",
            Self::UnsupportedRecordVersion { .. } => "unsupported-record-version",
            Self::IpnsRecordMalformed => "ipns-record-malformed",
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
            Self::UnknownRecordField { key } => write!(f, " (key {:?})", DisplayKey(key)),
            Self::UnsupportedRecordVersion { version } => write!(f, " (version {version})"),
            Self::WipedMap
            | Self::InvalidIdentityKey
            | Self::InvalidEncSubkey
            | Self::InvalidBindingSigEncoding
            | Self::InvalidNodeKind
            | Self::InvalidPermission
            | Self::IpnsNameMalformed
            | Self::ContentCidStrMalformed
            | Self::IpnsRecordMalformed => Ok(()),
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
