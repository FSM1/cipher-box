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

use crate::codec::{Map, Value, decode, encode};
use crate::error::{CodecError, Malformed};
use crate::suite::ecdsa::IDENTITY_PUBLIC_LEN;
use crate::suite::secret::SECRET_LEN;

use super::body::{
    PreservedFields, assert_grant_tags_unique, bytes_fixed, collect_unknown, merge_unknown, req,
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
    /// The grant-set commitment does not cover it, so it is a client-honoured
    /// deadline and a prune trigger, never the capability boundary — cutting a
    /// grantee off is the owner's re-signed commitment plus a rotation.
    pub expires_at: Option<u64>,
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

/// Reject `expiresAt: 0` on both the decode and the encode side
/// ([`Malformed::InvalidExpiry`]): absence is the sole encoding of "no
/// deadline", so a zero instant is a second spelling of it that is also
/// permanently expired.
fn check_expiry(expires_at: Option<u64>) -> Result<(), CodecError> {
    match expires_at {
        Some(0) => Err(Malformed::InvalidExpiry.into()),
        _ => Ok(()),
    }
}

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
        let expires_at = match map.get("expiresAt") {
            Some(v) => Some(v.as_unsigned()?),
            None => None,
        };
        check_expiry(expires_at)?;
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
            m.insert("expiresAt", Value::Unsigned(expires_at));
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildScopeRef {
    /// The child scope root's node id (16-byte UUID) = its scope id.
    pub scope_id: [u8; 16],
    /// The child scope root's opaque `ipnsName` bytes.
    pub ipns_name: Vec<u8>,
    /// Preserved unknown fields (never any of the known keys).
    pub unknown: PreservedFields,
}

const CHILD_SCOPE_KNOWN: &[&str] = &["ipnsName", "scopeId"];

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
    /// The sealed write-plane history-link blob (opaque; empty at write epoch 1).
    pub write_history_link: Vec<u8>,
    /// The directly-descendant scope roots (the F-4 cascade index).
    pub direct_child_scope_index: Vec<ChildScopeRef>,
    /// Preserved unknown top-level fields (never any of the known keys).
    pub unknown: PreservedFields,
}

const WRITE_BODY_KNOWN: &[&str] = &["directChildScopeIndex", "grantLedger", "writeHistoryLink"];

/// Decode a write-body plaintext (strict det-CBOR, unknown fields preserved).
///
/// Scope-root-only by construction; this codec cannot enforce that — whether a
/// node is a scope root is the engine's decision.
pub fn decode_write_body(bytes: &[u8]) -> Result<WriteBody, CodecError> {
    let value = decode(bytes)?;
    let map = value.as_map()?;

    let mut grant_ledger = Vec::new();
    for item in req(map, "grantLedger")?.as_array()? {
        grant_ledger.push(GrantLedgerEntry::from_value(item)?);
    }
    assert_grant_tags_unique(grant_ledger.iter().map(|e| e.tag))?;
    let write_history_link = req(map, "writeHistoryLink")?.as_bytes()?.to_vec();
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
/// fail-closed guard: a duplicate-tag ledger or a zero `expiresAt` fails here
/// with the same `duplicate-grant-tag` / `invalid-expiry` verdict
/// [`decode_write_body`] raises, so it never hands back bytes its own decoder
/// rejects.
pub fn encode_write_body(body: &WriteBody) -> Result<Vec<u8>, CodecError> {
    assert_grant_tags_unique(body.grant_ledger.iter().map(|e| e.tag))?;
    for entry in &body.grant_ledger {
        check_expiry(entry.expires_at)?;
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
    encode(&Value::Map(m))
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

    #[test]
    fn expiring_ledger_entry_round_trips_byte_stable() {
        let mut body = sample();
        body.grant_ledger[0].expires_at = Some(1_700_000_000_000);
        let bytes = encode_write_body(&body).expect("encodes");
        let decoded = decode_write_body(&bytes).expect("decodes");
        assert_eq!(decoded, body);
        assert_eq!(decoded.grant_ledger[1].expires_at, None, "absence survives");
        assert_eq!(encode_write_body(&decoded).unwrap(), bytes, "byte-stable");
    }

    #[test]
    fn zero_expiry_rejects_at_decode() {
        // Hand-built wire bytes, the way a hostile peer's arrive: `expiresAt: 0`
        // is a second spelling of "no deadline" that is also permanently expired.
        let mut entry = Map::new();
        entry.insert("expiresAt", Value::Unsigned(0));
        entry.insert("permission", Value::Text("read".into()));
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
            "invalid-expiry"
        );
    }

    #[test]
    fn encode_rejects_zero_expiry() {
        // Release-active guard, exercised without relying on a `debug_assert`.
        let mut body = sample();
        body.grant_ledger[0].expires_at = Some(0);
        assert_eq!(
            encode_write_body(&body).unwrap_err().check(),
            "invalid-expiry"
        );
    }

    #[test]
    fn non_unsigned_expiry_rejects() {
        let mut entry = Map::new();
        entry.insert("expiresAt", Value::Text("soon".into()));
        entry.insert("permission", Value::Text("read".into()));
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
            "unexpected-type"
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
