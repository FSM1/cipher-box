//! The sealed write-body: the scope-root write-plane payload
//! (blueprint/core.md "Envelope and structures: Write-body", #27 D6).
//!
//! Present **only at scope roots**: interior nodes publish no write-body at all
//! — their write material (write seed, `writeKey`, IPNS keypair) is derived flat
//! within the write scope. Sealed under the root's `writeKey` (struct tag
//! `write-body`), it carries the authoritative grant ledger, the write-plane
//! history link (opaque sealed bytes here; codec in [`super::grant`]), and the
//! `directChildScopeIndex` for the F-4 rotation cascade (#38 D6).
//!
//! Writers re-wrap grant blobs for the ledger's recorded set during re-seals but
//! cannot change the set; grant changes are owner-only.
//!
//! One strictness policy, everywhere (#27 D10): every map level decodes strict
//! det-CBOR and preserves unknown fields byte-stable, so an old client
//! re-sealing a write-body under shared write never strips a newer client's
//! fields.

use core::fmt;
use core::num::NonZeroU64;

use crate::codec::scrub::{ScrubOnDrop, ScrubOwned};
use crate::codec::{Map, RedactedBytes, Value, decode, encode};
use crate::error::{CodecError, Malformed};
use crate::suite::ecdsa::IDENTITY_PUBLIC_LEN;
use crate::suite::secret::SECRET_LEN;

use super::body::{
    PreservedFields, assert_grant_tags_unique, assert_unknown_disjoint, assert_within_bound,
    bytes_fixed, collect_unknown, merge_unknown, req,
};
use super::grant::Permission;

// ---------------------------------------------------------------------------
// Grant-ledger entry.
// ---------------------------------------------------------------------------

/// One authoritative grant-ledger row. The identity key is the 33-byte
/// compressed secp256k1 SEC1 form; the encryption subkey is a 32-byte X25519
/// public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantLedgerEntry {
    /// The recipient's compressed secp256k1 identity public key (SEC1).
    pub recipient_identity_pk: [u8; IDENTITY_PUBLIC_LEN],
    /// The recipient's X25519 encryption subkey public key.
    pub recipient_enc_pk: [u8; SECRET_LEN],
    /// The recipient's permission.
    pub permission: Permission,
    /// The recipient's blinded tag (the grant blob's key).
    pub tag: [u8; SECRET_LEN],
    /// The deadline past which this grant is inert, in Unix milliseconds;
    /// `None` for a grant that does not expire. Carried for invite links
    /// (blueprint/engine.md "Invites": expiry is a ledger field, lazily pruned).
    ///
    /// **Not a capability boundary.** The owner-signed grant-set commitment
    /// covers `(tag, permission, pseudonymPk)` only, so a write-grantee
    /// re-authoring this body can alter or drop the deadline undetectably. It is
    /// a deadline cooperating readers honour and the input to the
    /// discovered-expiry prune trigger; cutting a grantee off is the owner's
    /// re-signed commitment plus a rotation.
    ///
    /// `NonZeroU64` so zero is unrepresentable rather than checked, and no encode
    /// path can emit the [`Malformed::InvalidExpiry`] bytes the decoder rejects.
    pub expires_at: Option<NonZeroU64>,
    /// Preserved unknown fields (never any of the known keys).
    pub unknown: PreservedFields,
}

const LEDGER_ENTRY_KNOWN: &[&str] = &[
    "expiresAt",
    "permission",
    "recipientEncPk",
    "recipientIdentityPk",
    "tag",
];

impl GrantLedgerEntry {
    /// A ledger entry that never expires and preserves no unknown fields.
    pub fn new(
        recipient_identity_pk: [u8; IDENTITY_PUBLIC_LEN],
        recipient_enc_pk: [u8; SECRET_LEN],
        permission: Permission,
        tag: [u8; SECRET_LEN],
    ) -> Self {
        Self {
            recipient_identity_pk,
            recipient_enc_pk,
            permission,
            tag,
            expires_at: None,
            unknown: PreservedFields::new(),
        }
    }

    fn from_value(v: &Value) -> Result<Self, CodecError> {
        let map = v.as_map()?;
        let recipient_identity_pk = bytes_fixed::<IDENTITY_PUBLIC_LEN>(
            req(map, "recipientIdentityPk")?,
            "recipientIdentityPk",
        )?;
        let recipient_enc_pk =
            bytes_fixed::<SECRET_LEN>(req(map, "recipientEncPk")?, "recipientEncPk")?;
        let permission = Permission::from_value(req(map, "permission")?)?;
        let tag = bytes_fixed::<SECRET_LEN>(req(map, "tag")?, "tag")?;
        let expires_at = map
            .get("expiresAt")
            .map(|v| -> Result<NonZeroU64, CodecError> {
                NonZeroU64::new(v.as_unsigned()?).ok_or_else(|| Malformed::InvalidExpiry.into())
            })
            .transpose()?;
        Ok(Self {
            recipient_identity_pk,
            recipient_enc_pk,
            permission,
            tag,
            expires_at,
            unknown: collect_unknown(map, LEDGER_ENTRY_KNOWN),
        })
    }

    fn to_value(&self) -> Value {
        let mut m = Map::new();
        if let Some(expires_at) = self.expires_at {
            m.insert("expiresAt", Value::Unsigned(expires_at.get()));
        }
        m.insert(
            "permission",
            Value::Text(self.permission.as_wire().to_string()),
        );
        m.insert(
            "recipientEncPk",
            Value::Bytes(self.recipient_enc_pk.to_vec()),
        );
        m.insert(
            "recipientIdentityPk",
            Value::Bytes(self.recipient_identity_pk.to_vec()),
        );
        m.insert("tag", Value::Bytes(self.tag.to_vec()));
        merge_unknown(&mut m, &self.unknown);
        Value::Map(m)
    }
}

// ---------------------------------------------------------------------------
// Child-scope index entry.
// ---------------------------------------------------------------------------

/// One directly-descendant scope root, enumerated for the F-4 rotation cascade.
/// `ipns_name` is sealed-body plaintext, so it renders redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct ChildScopeRef {
    /// The child scope root's node id (16-byte UUID) = its scope id.
    pub scope_id: [u8; 16],
    /// The child scope root's opaque `ipnsName` bytes.
    pub ipns_name: Vec<u8>,
    /// Preserved unknown fields (never any of the known keys).
    pub unknown: PreservedFields,
}

const CHILD_SCOPE_KNOWN: &[&str] = &["ipnsName", "scopeId"];

impl fmt::Debug for ChildScopeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChildScopeRef")
            .field("scope_id", &self.scope_id)
            .field("ipns_name", &RedactedBytes::of(&self.ipns_name))
            .field("unknown", &self.unknown)
            .finish()
    }
}

impl ChildScopeRef {
    /// A child-scope ref with no preserved unknown fields.
    pub fn new(scope_id: [u8; 16], ipns_name: Vec<u8>) -> Self {
        Self {
            scope_id,
            ipns_name,
            unknown: PreservedFields::new(),
        }
    }

    fn from_value(v: &Value) -> Result<Self, CodecError> {
        let map = v.as_map()?;
        let scope_id = bytes_fixed::<16>(req(map, "scopeId")?, "scopeId")?;
        let ipns_name = req(map, "ipnsName")?.as_bytes()?.to_vec();
        Ok(Self {
            scope_id,
            ipns_name,
            unknown: collect_unknown(map, CHILD_SCOPE_KNOWN),
        })
    }

    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("ipnsName", Value::Bytes(self.ipns_name.clone()));
        m.insert("scopeId", Value::Bytes(self.scope_id.to_vec()));
        merge_unknown(&mut m, &self.unknown);
        Value::Map(m)
    }
}

// ---------------------------------------------------------------------------
// The write-body.
// ---------------------------------------------------------------------------

/// The sealed write-plane payload of a scope root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteBody {
    /// The authoritative grant ledger.
    pub grant_ledger: Vec<GrantLedgerEntry>,
    /// The sealed write-plane history-link blob (opaque, bounded at
    /// [`MAX_WRITE_HISTORY_LINK_BYTES`]). **Empty means no link** — the state at
    /// write epoch 1 — and a consumer must test that before opening, since an
    /// empty blob is below every seal's framing floor and reads as truncated.
    pub write_history_link: Vec<u8>,
    /// The directly-descendant scope roots (the F-4 cascade index).
    pub direct_child_scope_index: Vec<ChildScopeRef>,
    /// Preserved unknown top-level fields (never any of the known keys).
    pub unknown: PreservedFields,
}

const WRITE_BODY_KNOWN: &[&str] = &["directChildScopeIndex", "grantLedger", "writeHistoryLink"];

/// The frozen byte bound on [`WriteBody::write_history_link`] — the write
/// plane's analogue of the read plane's
/// [`MAX_HISTORY_LINKS`](super::MAX_HISTORY_LINKS).
///
/// Any committed writer authors the field and no owner signature covers it, so
/// it is bounded rather than trusted (blueprint/core.md "Write-body"). A
/// well-formed link is ~103 bytes; the rest is headroom for preserved unknown
/// fields.
pub const MAX_WRITE_HISTORY_LINK_BYTES: usize = 512;

/// Decode a write-body plaintext (strict det-CBOR, unknown fields preserved).
///
/// Scope-root-only by construction; this codec cannot enforce that — whether a
/// node is a scope root is the engine's decision.
///
/// The transient decoded tree copies the recipient keys, blinded tags and
/// child-scope `ipnsName`s, so it is scrubbed on drop.
pub fn decode_write_body(bytes: &[u8]) -> Result<WriteBody, CodecError> {
    let value = ScrubOwned(decode(bytes)?);
    let map = value.value().as_map()?;

    // Bound the writer-authored blob before the ledger walk allocates for it.
    let write_history_link = req(map, "writeHistoryLink")?.as_bytes()?;
    assert_within_bound(
        "writeHistoryLink",
        write_history_link.len(),
        MAX_WRITE_HISTORY_LINK_BYTES,
    )?;
    let write_history_link = write_history_link.to_vec();

    let mut grant_ledger = Vec::new();
    for item in req(map, "grantLedger")?.as_array()? {
        grant_ledger.push(GrantLedgerEntry::from_value(item)?);
    }
    assert_grant_tags_unique(grant_ledger.iter().map(|e| e.tag))?;
    let mut direct_child_scope_index = Vec::new();
    for item in req(map, "directChildScopeIndex")?.as_array()? {
        direct_child_scope_index.push(ChildScopeRef::from_value(item)?);
    }

    Ok(WriteBody {
        grant_ledger,
        write_history_link,
        direct_child_scope_index,
        unknown: collect_unknown(map, WRITE_BODY_KNOWN),
    })
}

/// Encode a write-body to its canonical det-CBOR plaintext (sealed under the
/// root's `writeKey` with struct tag `write-body` by the caller / seal path).
///
/// The write body is sealed outside core, so this encode is its release-active
/// fail-closed guard: a duplicate-tag ledger, or a `writeHistoryLink` past
/// [`MAX_WRITE_HISTORY_LINK_BYTES`], fails here with the same verdict
/// [`decode_write_body`] raises, so it never hands back bytes its own decoder
/// rejects. The decoder's other reject, `invalid-expiry`, needs no guard —
/// [`GrantLedgerEntry::expires_at`] is `NonZeroU64`, so those bytes are
/// unrepresentable rather than checked. Its key is optional, though, so each
/// row's preserved fields must not smuggle one in.
pub fn encode_write_body(body: &WriteBody) -> Result<Vec<u8>, CodecError> {
    assert_within_bound(
        "writeHistoryLink",
        body.write_history_link.len(),
        MAX_WRITE_HISTORY_LINK_BYTES,
    )?;
    assert_grant_tags_unique(body.grant_ledger.iter().map(|e| e.tag))?;
    for entry in &body.grant_ledger {
        assert_unknown_disjoint(&entry.unknown, LEDGER_ENTRY_KNOWN)?;
    }
    let mut m = Map::new();
    m.insert(
        "directChildScopeIndex",
        Value::Array(
            body.direct_child_scope_index
                .iter()
                .map(ChildScopeRef::to_value)
                .collect(),
        ),
    );
    m.insert(
        "grantLedger",
        Value::Array(
            body.grant_ledger
                .iter()
                .map(GrantLedgerEntry::to_value)
                .collect(),
        ),
    );
    m.insert(
        "writeHistoryLink",
        Value::Bytes(body.write_history_link.clone()),
    );
    merge_unknown(&mut m, &body.unknown);
    let mut value = Value::Map(m);
    let guard = ScrubOnDrop(&mut value);
    encode(guard.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> WriteBody {
        WriteBody {
            grant_ledger: vec![
                GrantLedgerEntry::new([0x02; 33], [0x11; 32], Permission::Read, [0x21; 32]),
                GrantLedgerEntry::new([0x03; 33], [0x12; 32], Permission::Write, [0x22; 32]),
            ],
            write_history_link: b"sealed-write-history".to_vec(),
            direct_child_scope_index: vec![ChildScopeRef::new(
                [0x55; 16],
                b"child-scope-name".to_vec(),
            )],
            unknown: PreservedFields::new(),
        }
    }

    /// The encode guard wipes its own transient tree, never the caller's body:
    /// one borrow encodes to the same bytes twice. The round-trip test cannot
    /// catch this — it encodes two distinct values.
    #[test]
    fn encoding_one_borrowed_body_twice_is_byte_identical() {
        let body = sample();
        assert_eq!(
            encode_write_body(&body).unwrap(),
            encode_write_body(&body).unwrap()
        );
    }

    /// A child scope's `ipnsName` is sealed-body plaintext, like a child ref's.
    #[test]
    fn debug_redacts_child_scope_names() {
        let rendered = format!("{:?}", sample());
        assert!(!rendered.contains("child-scope-name"), "{rendered}");
        assert!(rendered.contains("<16 bytes redacted>"), "{rendered}");
        assert!(
            rendered.contains("Read") && rendered.contains("Write"),
            "the ledger's public fields stay legible: {rendered}"
        );
    }

    #[test]
    fn write_body_round_trips_byte_stable() {
        let body = sample();
        let bytes = encode_write_body(&body).expect("encodes");
        let decoded = decode_write_body(&bytes).expect("decodes");
        assert_eq!(decoded, body);
        assert_eq!(encode_write_body(&decoded).unwrap(), bytes, "byte-stable");
    }

    #[test]
    fn write_body_epoch_one_has_empty_history_link() {
        let body = WriteBody {
            grant_ledger: Vec::new(),
            write_history_link: Vec::new(),
            direct_child_scope_index: Vec::new(),
            unknown: PreservedFields::new(),
        };
        let bytes = encode_write_body(&body).expect("encodes");
        assert_eq!(decode_write_body(&bytes).unwrap(), body);
    }

    /// Encode/decode symmetry on the byte bound (AGENTS.md rule 8): both sides
    /// admit exactly `MAX_WRITE_HISTORY_LINK_BYTES` and refuse one more with the
    /// same verdict. `assert_eq!`, not `debug_assert!` — this fires in release.
    #[test]
    fn a_write_history_link_past_its_byte_bound_is_refused_by_both_sides() {
        let at_bound = WriteBody {
            write_history_link: vec![0xab; MAX_WRITE_HISTORY_LINK_BYTES],
            ..sample()
        };
        let bytes = encode_write_body(&at_bound).expect("a link at the bound encodes");
        assert_eq!(decode_write_body(&bytes).unwrap(), at_bound);

        let over = WriteBody {
            write_history_link: vec![0xab; MAX_WRITE_HISTORY_LINK_BYTES + 1],
            ..sample()
        };
        assert_eq!(
            encode_write_body(&over).unwrap_err().check(),
            "too-many-structures"
        );

        let mut m = Map::new();
        m.insert("directChildScopeIndex", Value::Array(vec![]));
        m.insert("grantLedger", Value::Array(vec![]));
        m.insert(
            "writeHistoryLink",
            Value::Bytes(vec![0xab; MAX_WRITE_HISTORY_LINK_BYTES + 1]),
        );
        assert_eq!(
            decode_write_body(&encode(&Value::Map(m)).unwrap())
                .unwrap_err()
                .check(),
            "too-many-structures"
        );
    }

    #[test]
    fn invalid_permission_in_ledger_rejects() {
        let mut entry = Map::new();
        entry.insert("permission", Value::Text("owner".into()));
        entry.insert("recipientEncPk", Value::Bytes(vec![0x11; 32]));
        entry.insert("recipientIdentityPk", Value::Bytes(vec![0x02; 33]));
        entry.insert("tag", Value::Bytes(vec![0x21; 32]));
        let mut m = Map::new();
        m.insert("directChildScopeIndex", Value::Array(vec![]));
        m.insert("grantLedger", Value::Array(vec![Value::Map(entry)]));
        m.insert("writeHistoryLink", Value::Bytes(vec![]));
        let bytes = encode(&Value::Map(m)).unwrap();
        assert_eq!(
            decode_write_body(&bytes).unwrap_err().check(),
            "invalid-permission"
        );
    }

    #[test]
    fn wrong_identity_pk_length_rejects() {
        let mut entry = Map::new();
        entry.insert("permission", Value::Text("read".into()));
        entry.insert("recipientEncPk", Value::Bytes(vec![0x11; 32]));
        entry.insert("recipientIdentityPk", Value::Bytes(vec![0x02; 32])); // 32, not 33
        entry.insert("tag", Value::Bytes(vec![0x21; 32]));
        let mut m = Map::new();
        m.insert("directChildScopeIndex", Value::Array(vec![]));
        m.insert("grantLedger", Value::Array(vec![Value::Map(entry)]));
        m.insert("writeHistoryLink", Value::Bytes(vec![]));
        let bytes = encode(&Value::Map(m)).unwrap();
        assert_eq!(
            decode_write_body(&bytes).unwrap_err().check(),
            "invalid-field-length"
        );
    }

    #[test]
    fn duplicate_ledger_tag_rejects() {
        // The confused-deputy shape: the same tag appears twice with a different
        // permission and recipientEncPk (a shared-write holder injecting a second
        // row for a victim's tag). Hand-built wire bytes that never passed through
        // any encoder, so decode is what must reject them, the way a hostile
        // peer's bytes arrive.
        let mut a = Map::new();
        a.insert("permission", Value::Text("read".into()));
        a.insert("recipientEncPk", Value::Bytes(vec![0x11; 32]));
        a.insert("recipientIdentityPk", Value::Bytes(vec![0x02; 33]));
        a.insert("tag", Value::Bytes(vec![0x21; 32]));
        let mut b = Map::new();
        b.insert("permission", Value::Text("write".into()));
        b.insert("recipientEncPk", Value::Bytes(vec![0x99; 32]));
        b.insert("recipientIdentityPk", Value::Bytes(vec![0x03; 33]));
        b.insert("tag", Value::Bytes(vec![0x21; 32])); // same tag as `a`
        let mut m = Map::new();
        m.insert("directChildScopeIndex", Value::Array(vec![]));
        m.insert(
            "grantLedger",
            Value::Array(vec![Value::Map(a), Value::Map(b)]),
        );
        m.insert("writeHistoryLink", Value::Bytes(vec![]));
        let bytes = encode(&Value::Map(m)).unwrap();
        assert_eq!(
            decode_write_body(&bytes).unwrap_err().check(),
            "duplicate-grant-tag"
        );
    }

    #[test]
    fn missing_grant_ledger_rejects() {
        let mut m = Map::new();
        m.insert("directChildScopeIndex", Value::Array(vec![]));
        m.insert("writeHistoryLink", Value::Bytes(vec![]));
        let bytes = encode(&Value::Map(m)).unwrap();
        assert_eq!(
            decode_write_body(&bytes).unwrap_err().check(),
            "missing-field"
        );
    }

    #[test]
    fn unknown_top_level_field_preserved_byte_stable() {
        let mut m = Map::new();
        m.insert("directChildScopeIndex", Value::Array(vec![]));
        m.insert("grantLedger", Value::Array(vec![]));
        m.insert("writeHistoryLink", Value::Bytes(vec![]));
        m.insert("futureField", Value::Text("keep".into()));
        let bytes = encode(&Value::Map(m)).unwrap();
        let decoded = decode_write_body(&bytes).expect("tolerant decode");
        assert_eq!(decoded.unknown.len(), 1);
        assert_eq!(
            encode_write_body(&decoded).unwrap(),
            bytes,
            "unknown preserved"
        );
    }

    /// Wire bytes for a one-row ledger carrying `expiresAt: expiry`, hand-built
    /// the way a hostile peer's arrive.
    fn body_with_raw_expiry(expiry: Value) -> Vec<u8> {
        let mut entry = Map::new();
        entry.insert("expiresAt", expiry);
        entry.insert("permission", Value::Text("read".into()));
        entry.insert("recipientEncPk", Value::Bytes(vec![0x11; 32]));
        entry.insert("recipientIdentityPk", Value::Bytes(vec![0x02; 33]));
        entry.insert("tag", Value::Bytes(vec![0x21; 32]));
        let mut m = Map::new();
        m.insert("directChildScopeIndex", Value::Array(vec![]));
        m.insert("grantLedger", Value::Array(vec![Value::Map(entry)]));
        m.insert("writeHistoryLink", Value::Bytes(vec![]));
        encode(&Value::Map(m)).unwrap()
    }

    #[test]
    fn expiring_ledger_entry_round_trips_byte_stable() {
        let mut body = sample();
        body.grant_ledger[0].expires_at = NonZeroU64::new(1_700_000_000_000);
        let bytes = encode_write_body(&body).expect("encodes");
        let decoded = decode_write_body(&bytes).expect("decodes");
        assert_eq!(decoded, body);
        assert_eq!(decoded.grant_ledger[1].expires_at, None, "absence survives");
        assert_eq!(encode_write_body(&decoded).unwrap(), bytes, "byte-stable");
    }

    #[test]
    fn zero_expiry_rejects_at_decode() {
        assert_eq!(
            decode_write_body(&body_with_raw_expiry(Value::Unsigned(0)))
                .unwrap_err()
                .check(),
            "invalid-expiry"
        );
    }

    #[test]
    fn non_unsigned_expiry_rejects() {
        // Fail-closed, not fail-open: a wrong-typed deadline is a hard reject,
        // never silently read as absent-and-therefore-live.
        assert_eq!(
            decode_write_body(&body_with_raw_expiry(Value::Text("soon".into())))
                .unwrap_err()
                .check(),
            "unexpected-type"
        );
    }

    #[test]
    fn encode_rejects_an_expiry_smuggled_through_preserved_fields() {
        // Release-active guard: with `expires_at: None` the `expiresAt` key is
        // free, so a caller-built `unknown` could otherwise encode a deadline the
        // typed value denies. Exercised without relying on a `debug_assert`.
        let mut body = sample();
        body.grant_ledger[0].unknown =
            PreservedFields::from_iter([("expiresAt".to_string(), Value::Unsigned(0))]);
        assert_eq!(body.grant_ledger[0].expires_at, None);
        assert_eq!(
            encode_write_body(&body).unwrap_err().check(),
            "unknown-field-collision"
        );
    }

    #[test]
    fn encode_rejects_duplicate_ledger_tags() {
        // Release-active guard: a caller-built ledger with a repeated tag never
        // yields bytes, matching the decoder's fail-closed reject. Exercised
        // without relying on a `debug_assert`.
        let body = WriteBody {
            grant_ledger: vec![
                GrantLedgerEntry::new([0x02; 33], [0x11; 32], Permission::Read, [0x21; 32]),
                GrantLedgerEntry::new([0x03; 33], [0x12; 32], Permission::Write, [0x21; 32]),
            ],
            write_history_link: Vec::new(),
            direct_child_scope_index: Vec::new(),
            unknown: PreservedFields::new(),
        };
        assert_eq!(
            encode_write_body(&body).unwrap_err().check(),
            "duplicate-grant-tag"
        );
    }
}
