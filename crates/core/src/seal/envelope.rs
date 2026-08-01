//! The kind-uniform envelope codec (blueprint/core.md "Envelope and
//! structures", #27 D4).
//!
//! The envelope is a node's published plaintext wrapper:
//! `{v, id, epochTag{scope, epoch}, readSealed, writeSealed?, grantSection?}`.
//! It is kind-uniform — whether a node is a file or a folder is sealed inside
//! the read-body, so observers cannot distinguish them. The scope id is the
//! scope root's node UUID; `epochTag` is the plaintext, AAD-bound membership.
//!
//! This codec models only `{v, id, epochTag, readSealed}` as typed fields;
//! `writeSealed`/`grantSection` are carried through the unknown-field tolerance
//! (#27 D10), preserved in [`Envelope::unknown`] and never stripped on rewrite,
//! so an envelope written by a newer client round-trips byte-stable here.

use zeroize::Zeroize;

use crate::codec::{Map, Value, decode, encode};
use crate::error::CodecError;
use crate::suite::aead::{KEY_LEN, NONCE_LEN};

use super::aad::{AadContext, STRUCT_TAG_READ_BODY};
use super::body::{
    PreservedFields, ReadBody, bytes_fixed, collect_unknown, decode_read_body, encode_read_body,
    merge_unknown, req,
};

/// A node's kind-uniform envelope. `scope`/`epoch` are the flattened `epochTag`
/// (`epoch_tag_unknown` preserves any newer fields inside it); `unknown`
/// preserves newer top-level fields (`writeSealed`, `grantSection`, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// The format+suite version.
    pub v: u64,
    /// The node id (16-byte UUID).
    pub id: [u8; 16],
    /// The scope-root node id (16-byte UUID) — the epoch tag's scope.
    pub scope: [u8; 16],
    /// The epoch-tag epoch.
    pub epoch: u64,
    /// The sealed read-body: `nonce(24) || ciphertext||tag`.
    pub read_sealed: Vec<u8>,
    /// Preserved unknown top-level fields (`writeSealed`, `grantSection`, and
    /// any future additive field), re-emitted canonically on rewrite.
    pub unknown: PreservedFields,
    /// Preserved unknown fields inside `epochTag`.
    pub epoch_tag_unknown: PreservedFields,
}

const ENVELOPE_KNOWN: &[&str] = &["epochTag", "id", "readSealed", "v"];
const EPOCH_TAG_KNOWN: &[&str] = &["epoch", "scope"];

/// Decode a plaintext envelope (strict det-CBOR; unknown fields preserved).
pub fn decode_envelope(bytes: &[u8]) -> Result<Envelope, CodecError> {
    let value = decode(bytes)?;
    let map = value.as_map()?;

    let v = req(map, "v")?.as_unsigned()?;
    let id = bytes_fixed::<16>(req(map, "id")?, "id")?;
    let read_sealed = req(map, "readSealed")?.as_bytes()?.to_vec();

    let epoch_tag = req(map, "epochTag")?.as_map()?;
    let scope = bytes_fixed::<16>(req(epoch_tag, "scope")?, "scope")?;
    let epoch = req(epoch_tag, "epoch")?.as_unsigned()?;

    Ok(Envelope {
        v,
        id,
        scope,
        epoch,
        read_sealed,
        unknown: collect_unknown(map, ENVELOPE_KNOWN),
        epoch_tag_unknown: collect_unknown(epoch_tag, EPOCH_TAG_KNOWN),
    })
}

/// The `grantSection` bytes carried in the envelope's preserved unknown
/// top-level fields (#27 D10 — `grantSection` rides `unknown`, never a typed
/// field, so an envelope stays kind-uniform and byte-stable on rewrite). Raw
/// bytes for [`super::decode_grant_section`], so the engine never matches raw
/// `Value`s; `None` when the field is absent or not a byte string.
pub fn grant_section_bytes(env: &Envelope) -> Option<&[u8]> {
    env.unknown.get(GRANT_SECTION_KEY)?.as_bytes().ok()
}

/// Whether the envelope carries a `grantSection` key at all, regardless of its
/// value — the scope-root marker (a child envelope must carry none). Stricter
/// than [`grant_section_bytes`], which also requires a byte-string value.
pub fn has_grant_section(env: &Envelope) -> bool {
    env.unknown.get(GRANT_SECTION_KEY).is_some()
}

/// Attach the scope-root marker, the writer half of [`grant_section_bytes`].
/// The key and its byte-string shape live here rather than at each caller.
pub fn set_grant_section(env: &mut Envelope, section: Vec<u8>) {
    env.unknown
        .insert(GRANT_SECTION_KEY.to_string(), Value::Bytes(section));
}

const GRANT_SECTION_KEY: &str = "grantSection";

/// Encode an envelope to its canonical det-CBOR plaintext.
pub fn encode_envelope(env: &Envelope) -> Result<Vec<u8>, CodecError> {
    let mut epoch_tag = Map::new();
    epoch_tag.insert("epoch", Value::Unsigned(env.epoch));
    epoch_tag.insert("scope", Value::Bytes(env.scope.to_vec()));
    merge_unknown(&mut epoch_tag, &env.epoch_tag_unknown);

    let mut m = Map::new();
    m.insert("v", Value::Unsigned(env.v));
    m.insert("id", Value::Bytes(env.id.to_vec()));
    m.insert("epochTag", Value::Map(epoch_tag));
    m.insert("readSealed", Value::Bytes(env.read_sealed.clone()));
    merge_unknown(&mut m, &env.unknown);
    encode(&Value::Map(m))
}

/// Seal a read-body into a fresh envelope under the read key + injected nonce.
///
/// The struct tag is fixed to `read-body`; the AAD binds `(v, id, scope, epoch,
/// read-body)`. `nonce` must be unique per `key` (see [`super::seal`]) and is
/// caller-injected entropy the KATs pin.
///
/// The body is [`ReadBody::validate`]d first, so this never persists a folder
/// decode would refuse to reopen. The encoded plaintext carries inline content
/// keys and is zeroized here — this function is its terminal owner.
pub fn seal_read_body(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    v: u64,
    id: [u8; 16],
    scope: [u8; 16],
    epoch: u64,
    body: &ReadBody,
) -> Result<Envelope, CodecError> {
    body.validate()?;
    let mut plaintext = encode_read_body(body)?;
    let ctx = AadContext {
        v,
        id,
        scope,
        epoch,
        struct_tag: STRUCT_TAG_READ_BODY,
    };
    let read_sealed = super::seal(key, nonce, &ctx, &plaintext);
    plaintext.zeroize();
    Ok(Envelope {
        v,
        id,
        scope,
        epoch,
        read_sealed,
        unknown: PreservedFields::new(),
        epoch_tag_unknown: PreservedFields::new(),
    })
}

/// Open and decode an envelope's read-body under the read key. The AAD is
/// rebuilt from the envelope's own plaintext fields, so any transplant or `v`
/// downgrade fails the tag as [`crate::error::TrustViolation::SealOpenFailed`].
/// The recovered plaintext is zeroized here; the returned [`ReadBody`]'s content
/// keys are the caller's to own.
pub fn open_read_body(env: &Envelope, key: &[u8; KEY_LEN]) -> Result<ReadBody, CodecError> {
    let ctx = AadContext {
        v: env.v,
        id: env.id,
        scope: env.scope,
        epoch: env.epoch,
        struct_tag: STRUCT_TAG_READ_BODY,
    };
    let mut plaintext = super::unseal(key, &ctx, &env.read_sealed)?;
    let result = decode_read_body(&plaintext);
    plaintext.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::body::{ChildRef, NodeKind};

    fn folder() -> ReadBody {
        ReadBody::Folder {
            created_at: 10,
            modified_at: 20,
            children: vec![ChildRef {
                id: [7; 16],
                name: "doc.txt".into(),
                ipns_name: b"child-name".to_vec(),
                kind: NodeKind::File,
                link_counter: 1,
                unknown: PreservedFields::new(),
            }],
            unknown: PreservedFields::new(),
        }
    }

    #[test]
    fn seal_open_round_trip() {
        let key = [3u8; KEY_LEN];
        let nonce = [4u8; NONCE_LEN];
        let body = folder();
        let env = seal_read_body(&key, &nonce, 2, [1; 16], [2; 16], 5, &body).unwrap();
        assert_eq!(
            env.read_sealed.len(),
            NONCE_LEN + encode_read_body(&body).unwrap().len() + 16
        );
        let opened = open_read_body(&env, &key).expect("opens");
        assert_eq!(opened, body);
    }

    #[test]
    fn envelope_round_trips_byte_stable() {
        let key = [3u8; KEY_LEN];
        let nonce = [4u8; NONCE_LEN];
        let env = seal_read_body(&key, &nonce, 2, [1; 16], [2; 16], 5, &folder()).unwrap();
        let bytes = encode_envelope(&env).unwrap();
        let decoded = decode_envelope(&bytes).expect("decodes");
        assert_eq!(decoded, env);
        assert_eq!(encode_envelope(&decoded).unwrap(), bytes, "byte-stable");
    }

    #[test]
    fn downgrade_v_fails_the_tag() {
        let key = [3u8; KEY_LEN];
        let nonce = [4u8; NONCE_LEN];
        let mut env = seal_read_body(&key, &nonce, 2, [1; 16], [2; 16], 5, &folder()).unwrap();
        // Roll the plaintext version back to 1: the AAD recomputes with v=1 and
        // the tag fails (the downgrade defence).
        env.v = 1;
        assert_eq!(
            open_read_body(&env, &key).unwrap_err().check(),
            "seal-open-failed"
        );
    }

    #[test]
    fn scope_transplant_fails_the_tag() {
        let key = [3u8; KEY_LEN];
        let nonce = [4u8; NONCE_LEN];
        let mut env = seal_read_body(&key, &nonce, 2, [1; 16], [2; 16], 5, &folder()).unwrap();
        env.scope[0] ^= 0x01;
        assert_eq!(
            open_read_body(&env, &key).unwrap_err().check(),
            "seal-open-failed"
        );
    }

    #[test]
    fn unknown_envelope_field_preserved() {
        // A future top-level field (stand-in for writeSealed/grantSection):
        // decode preserves it, rewrite is byte-stable, and open still works.
        let key = [3u8; KEY_LEN];
        let nonce = [4u8; NONCE_LEN];
        let env = seal_read_body(&key, &nonce, 2, [1; 16], [2; 16], 5, &folder()).unwrap();
        let mut m = decode(&encode_envelope(&env).unwrap())
            .unwrap()
            .as_map()
            .unwrap()
            .clone();
        m.insert("writeSealed", Value::Bytes(b"future-write-body".to_vec()));
        let bytes = encode(&Value::Map(m)).unwrap();

        let decoded = decode_envelope(&bytes).expect("tolerant decode");
        assert_eq!(decoded.unknown.len(), 1);
        assert_eq!(decoded.unknown.entries()[0].0, "writeSealed");
        assert_eq!(
            encode_envelope(&decoded).unwrap(),
            bytes,
            "unknown field preserved"
        );
        // The read-body still opens despite the extra field.
        assert!(open_read_body(&decoded, &key).is_ok());
    }

    #[test]
    fn grant_section_bytes_pulls_the_unknown_field() {
        let key = [3u8; KEY_LEN];
        let nonce = [4u8; NONCE_LEN];
        let mut env = seal_read_body(&key, &nonce, 2, [1; 16], [2; 16], 5, &folder()).unwrap();
        assert_eq!(grant_section_bytes(&env), None, "absent without the field");

        set_grant_section(&mut env, b"section-bytes".to_vec());
        assert_eq!(
            grant_section_bytes(&env),
            Some(b"section-bytes".as_slice()),
            "pulls the grantSection bytes out of unknown"
        );
    }

    #[test]
    fn grant_section_bytes_none_when_not_a_byte_string() {
        let key = [3u8; KEY_LEN];
        let nonce = [4u8; NONCE_LEN];
        let mut env = seal_read_body(&key, &nonce, 2, [1; 16], [2; 16], 5, &folder()).unwrap();
        env.unknown
            .insert("grantSection".to_string(), Value::Unsigned(7));
        assert_eq!(
            grant_section_bytes(&env),
            None,
            "a non-bytes grantSection is not returned"
        );
    }

    #[test]
    fn has_grant_section_detects_the_raw_key_regardless_of_value() {
        let key = [3u8; KEY_LEN];
        let nonce = [4u8; NONCE_LEN];
        let mut env = seal_read_body(&key, &nonce, 2, [1; 16], [2; 16], 5, &folder()).unwrap();
        assert!(!has_grant_section(&env), "absent without the field");

        // A non-bytes value still marks the key present (stricter than
        // grant_section_bytes, which requires a byte string).
        env.unknown
            .insert("grantSection".to_string(), Value::Unsigned(7));
        assert!(has_grant_section(&env));
        assert_eq!(grant_section_bytes(&env), None);

        let mut env = seal_read_body(&key, &nonce, 2, [1; 16], [2; 16], 5, &folder()).unwrap();
        set_grant_section(&mut env, b"s".to_vec());
        assert!(has_grant_section(&env));
    }

    #[test]
    fn missing_v_rejects() {
        let key = [3u8; KEY_LEN];
        let nonce = [4u8; NONCE_LEN];
        let env = seal_read_body(&key, &nonce, 2, [1; 16], [2; 16], 5, &folder()).unwrap();
        let mut m = decode(&encode_envelope(&env).unwrap())
            .unwrap()
            .as_map()
            .unwrap()
            .clone();
        m.remove("v");
        let bytes = encode(&Value::Map(m)).unwrap();
        assert_eq!(
            decode_envelope(&bytes).unwrap_err().check(),
            "missing-field"
        );
    }

    #[test]
    fn seal_refuses_a_body_that_would_not_reopen() {
        // A folder with duplicate child ids must never be sealed: decode would
        // refuse to reopen it, so seal_read_body rejects it up front.
        let key = [3u8; KEY_LEN];
        let nonce = [4u8; NONCE_LEN];
        let dup = ReadBody::Folder {
            created_at: 1,
            modified_at: 2,
            children: vec![
                ChildRef {
                    id: [9; 16],
                    name: "a".into(),
                    ipns_name: b"x".to_vec(),
                    kind: NodeKind::File,
                    link_counter: 0,
                    unknown: PreservedFields::new(),
                },
                ChildRef {
                    id: [9; 16],
                    name: "b".into(),
                    ipns_name: b"y".to_vec(),
                    kind: NodeKind::File,
                    link_counter: 0,
                    unknown: PreservedFields::new(),
                },
            ],
            unknown: PreservedFields::new(),
        };
        assert_eq!(
            seal_read_body(&key, &nonce, 2, [1; 16], [2; 16], 5, &dup)
                .unwrap_err()
                .check(),
            "duplicate-id"
        );
    }
}
