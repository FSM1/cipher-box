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

use crate::codec::{Map, Value, decode, encode, encoded_key_len, encoded_len};
use crate::error::CodecError;
use crate::suite::aead::{KEY_LEN, NONCE_LEN};

use super::aad::{AadContext, STRUCT_TAG_READ_BODY};
use super::body::{
    PreservedFields, ReadBody, assert_unknown_disjoint, bytes_fixed, collect_unknown,
    decode_read_body, encode_read_body, merge_unknown, req,
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

/// The write plane's own carried payload, named here only so a cut cannot take
/// it; this codec models it nowhere else.
const WRITE_SEALED_KEY: &str = "writeSealed";

/// The carried fields a cut must never take (blueprint/core.md, "Carried
/// unknown fields").
const UNCUTTABLE: &[&str] = &[GRANT_SECTION_KEY, WRITE_SEALED_KEY];

/// What an [`encode_envelope_within`] cut destroyed: the carried keys it
/// dropped, in the order it dropped them. Empty when nothing was cut.
///
/// A cut fires only under attacker-sized pressure and it destroys data, so it is
/// something to report rather than something to do quietly (blueprint/engine.md
/// "never a silent failure"). The keys are safe to surface: they come off a
/// published record.
pub type CarriedCut = Vec<String>;

/// Encode `env`, cutting carried unknown fields until the block fits `limit`,
/// and report what the cut took. The block still exceeds `limit` when the typed
/// fields alone do — that part is the author's own work, and no cut shrinks it.
///
/// A carried set is **truncated, never refused** (blueprint/core.md, "Carried
/// unknown fields"): it comes off a resolved record, so anyone who can publish
/// at a name could otherwise stop every later publish there. `env` is left
/// holding exactly what the returned block encodes, so no caller can pair a cut
/// block with an uncut envelope.
pub fn encode_envelope_within(
    env: &mut Envelope,
    limit: usize,
) -> Result<(Vec<u8>, CarriedCut), CodecError> {
    let block = encode_envelope(env)?;
    let Some(excess) = block.len().checked_sub(limit) else {
        return Ok((block, CarriedCut::new()));
    };
    let cut = cut_carried_unknown(env, excess);
    if cut.is_empty() {
        return Ok((block, cut));
    }
    // One pass, not a fixpoint: a cut covers the whole excess in value bytes
    // alone, and dropping an entry frees its key and framing on top of that.
    Ok((encode_envelope(env)?, cut))
}

/// Cut cuttable carried fields until `excess` encoded bytes have gone or nothing
/// cuttable is left, reporting the keys taken.
///
/// Ranked and compacted rather than removed key by key: the carried set is
/// attacker-sized, and a removal per key is quadratic in what they carried.
///
/// Largest first, so the fewest fields go and one pass relieves the pressure
/// rather than leaving the next edit to cut again. That is a *count* bound, not
/// a byte bound: a party padding a record below the size of an honest field can
/// aim the first cut at it. What keeps that from mattering is that no cuttable
/// field carries a trust decision — the two that do are [`UNCUTTABLE`] — and the
/// fix for the day one does is a marker the field carries on the wire, not a
/// ranking this side can guess.
fn cut_carried_unknown(env: &mut Envelope, excess: usize) -> CarriedCut {
    // `entries()` is canonically ordered and the sort is stable, so ranking on
    // the cost alone is deterministic without carrying the keys along.
    let mut ranked: Vec<(usize, bool, usize)> = entry_costs(&env.unknown)
        .map(|(cost, index)| (cost, false, index))
        .chain(entry_costs(&env.epoch_tag_unknown).map(|(cost, index)| (cost, true, index)))
        .collect();
    ranked.sort_by_key(|&(cost, ..)| core::cmp::Reverse(cost));

    let mut top = vec![false; env.unknown.len()];
    let mut tag = vec![false; env.epoch_tag_unknown.len()];
    let mut taken = CarriedCut::new();
    let mut cut = 0usize;
    for (cost, in_epoch_tag, index) in ranked {
        if cut >= excess {
            break;
        }
        let (marks, fields) = if in_epoch_tag {
            (&mut tag, &env.epoch_tag_unknown)
        } else {
            (&mut top, &env.unknown)
        };
        marks[index] = true;
        taken.push(fields.entries()[index].0.clone());
        cut = cut.saturating_add(cost);
    }
    env.unknown.cut_at(&top);
    env.epoch_tag_unknown.cut_at(&tag);
    taken
}

/// What each cuttable field costs on the wire, with its index in `fields`.
/// [`encode_envelope`] runs first and refuses anything [`encoded_len`] cannot
/// measure, so an unmeasurable field never reaches the ranking.
fn entry_costs(fields: &PreservedFields) -> impl Iterator<Item = (usize, usize)> + '_ {
    fields
        .entries()
        .iter()
        .enumerate()
        .filter(|(_, (key, _))| !UNCUTTABLE.contains(&key.as_str()))
        .filter_map(|(index, (key, value))| {
            Some((encoded_len(value).ok()? + encoded_key_len(key), index))
        })
}

/// Encode an envelope to its canonical det-CBOR plaintext.
pub fn encode_envelope(env: &Envelope) -> Result<Vec<u8>, CodecError> {
    // [`merge_unknown`] skips a carried key that collides with a typed one, so
    // without this the block would decode back to a different envelope than the
    // one encoded — and a cut would budget for bytes never on the wire.
    assert_unknown_disjoint(&env.unknown, ENVELOPE_KNOWN)?;
    assert_unknown_disjoint(&env.epoch_tag_unknown, EPOCH_TAG_KNOWN)?;
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

#[cfg(test)]
mod truncation_tests {
    use super::*;

    fn envelope(unknown: PreservedFields, epoch_tag_unknown: PreservedFields) -> Envelope {
        Envelope {
            v: 1,
            id: [1u8; 16],
            scope: [2u8; 16],
            epoch: 5,
            read_sealed: vec![0u8; 32],
            unknown,
            epoch_tag_unknown,
        }
    }

    fn fields(entries: &[(&str, usize)]) -> PreservedFields {
        entries
            .iter()
            .map(|(key, len)| ((*key).to_string(), Value::Bytes(vec![0xab; *len])))
            .collect()
    }

    fn keys(fields: &PreservedFields) -> Vec<&str> {
        fields.entries().iter().map(|(k, _)| k.as_str()).collect()
    }

    /// The exact limit an envelope carrying `unknown` and `epoch_tag_unknown`
    /// meets — so each case states the set it wants to survive rather than a
    /// number that drifts with the typed fields.
    fn limit_carrying(unknown: PreservedFields, epoch_tag_unknown: PreservedFields) -> usize {
        encode_envelope(&envelope(unknown, epoch_tag_unknown))
            .expect("encodes")
            .len()
    }

    /// The whole contract in one: the block comes back within the limit, the
    /// envelope is left holding exactly what that block encodes, and the cut
    /// took the fields that overflowed rather than the set.
    #[test]
    fn a_carried_set_over_the_limit_is_cut_to_fit_rather_than_refused() {
        let limit = limit_carrying(fields(&[("small", 8)]), PreservedFields::new());
        let mut env = envelope(
            fields(&[("bloat", 4096), ("small", 8), ("mid", 512)]),
            PreservedFields::new(),
        );
        let (block, _) = encode_envelope_within(&mut env, limit).expect("encodes");
        assert!(block.len() <= limit);
        assert_eq!(keys(&env.unknown), vec!["small"]);
        assert_eq!(
            decode_envelope(&block).expect("decodes"),
            env,
            "the envelope is left holding what the block encodes"
        );
    }

    #[test]
    fn a_set_already_within_the_limit_keeps_every_carried_field() {
        let carried = fields(&[("a", 8), ("b", 8)]);
        let tag = fields(&[("tag", 8)]);
        let limit = limit_carrying(carried.clone(), tag.clone());
        let mut env = envelope(carried, tag);
        let before = env.clone();
        let (block, _) = encode_envelope_within(&mut env, limit).expect("encodes");
        assert_eq!(env, before);
        assert_eq!(block, encode_envelope(&before).expect("encodes"));
    }

    /// The scope-root marker and the write plane's payload are protocol-bearing:
    /// cutting either publishes a record the reader rejects outright, which is
    /// the refusal the cut exists to avoid. Over the limit is where it stays.
    #[test]
    fn the_protocol_bearing_carried_fields_are_never_cut() {
        let limit = limit_carrying(PreservedFields::new(), PreservedFields::new());
        let mut env = envelope(
            fields(&[("grantSection", 512), ("writeSealed", 512)]),
            PreservedFields::new(),
        );
        let (block, _) = encode_envelope_within(&mut env, limit).expect("encodes");
        assert!(block.len() > limit, "the caller refuses; the cut does not");
        assert_eq!(keys(&env.unknown), vec!["writeSealed", "grantSection"]);
    }

    #[test]
    fn an_epoch_tag_field_is_cuttable_and_ranked_against_the_top_level() {
        let limit = limit_carrying(fields(&[("small", 8)]), PreservedFields::new());
        let mut env = envelope(fields(&[("small", 8)]), fields(&[("tagBloat", 4096)]));
        let (block, _) = encode_envelope_within(&mut env, limit).expect("encodes");
        assert!(block.len() <= limit);
        assert!(env.epoch_tag_unknown.is_empty());
        assert_eq!(keys(&env.unknown), vec!["small"]);
    }

    /// One pass covers the whole excess — cutting entry by entry against an
    /// attacker-sized set would be quadratic — so what the ranking must get
    /// right is that it stops as soon as the budget is met and no sooner.
    #[test]
    fn a_budget_no_single_field_covers_takes_as_many_as_it_needs_and_no_more() {
        let limit = limit_carrying(fields(&[("a", 64), ("b", 64)]), PreservedFields::new());
        let mut env = envelope(
            fields(&[("a", 64), ("b", 64), ("c", 64), ("d", 64)]),
            PreservedFields::new(),
        );
        let (block, _) = encode_envelope_within(&mut env, limit).expect("encodes");
        assert!(block.len() <= limit);
        assert_eq!(env.unknown.len(), 2, "and stops there");
    }

    /// Equal-sized fields fall to the set's own canonical order, so two builds
    /// cut the same one rather than whichever the ranking happened to yield.
    #[test]
    fn an_equal_sized_pair_cuts_deterministically() {
        let cut_once = || {
            let limit = limit_carrying(fields(&[("a", 64)]), PreservedFields::new());
            let mut env = envelope(fields(&[("a", 64), ("b", 64)]), PreservedFields::new());
            encode_envelope_within(&mut env, limit).expect("encodes");
            keys(&env.unknown).first().copied().map(str::to_owned)
        };
        assert_eq!(cut_once(), Some("b".to_owned()));
        assert_eq!(cut_once(), cut_once());
    }

    /// A cut destroys data under pressure someone else applied, so what it took
    /// has to be reportable rather than inferable.
    #[test]
    fn a_cut_reports_the_carried_keys_it_dropped() {
        let limit = limit_carrying(fields(&[("small", 8)]), PreservedFields::new());
        let mut env = envelope(
            fields(&[("bloat", 4096), ("small", 8), ("mid", 512)]),
            PreservedFields::new(),
        );
        let (_, cut) = encode_envelope_within(&mut env, limit).expect("encodes");
        assert_eq!(cut, vec!["bloat".to_owned(), "mid".to_owned()]);
    }

    #[test]
    fn an_encode_that_cuts_nothing_reports_nothing() {
        let carried = fields(&[("a", 8)]);
        let limit = limit_carrying(carried.clone(), PreservedFields::new());
        let mut env = envelope(carried, PreservedFields::new());
        let (_, cut) = encode_envelope_within(&mut env, limit).expect("encodes");
        assert!(cut.is_empty());
    }

    /// Release-active (AGENTS.md rule 8): [`merge_unknown`] skips a carried key
    /// that collides with a typed one, so encoding it would emit a block that
    /// decodes back to a different envelope.
    #[test]
    fn a_carried_key_that_collides_with_a_typed_one_is_refused_at_encode() {
        for (unknown, tag) in [
            (fields(&[("v", 8)]), PreservedFields::new()),
            (PreservedFields::new(), fields(&[("epoch", 8)])),
        ] {
            let env = envelope(unknown, tag);
            assert_eq!(
                encode_envelope(&env).unwrap_err().check(),
                "unknown-field-collision"
            );
        }
    }

    /// A future refactor routing the cut through [`Map::zeroize_bytes`] would
    /// set the terminal wiped mark and make the map unencodable — the whole
    /// point of the cut being to leave it encodable.
    #[test]
    fn a_cut_leaves_the_surviving_carried_values_intact_and_encodable() {
        let limit = limit_carrying(fields(&[("small", 8)]), PreservedFields::new());
        let mut env = envelope(
            fields(&[("bloat", 4096), ("small", 8)]),
            PreservedFields::new(),
        );
        encode_envelope_within(&mut env, limit).expect("encodes");
        assert_eq!(env.unknown.get("small"), Some(&Value::Bytes(vec![0xab; 8])));
        encode_envelope(&env).expect("the surviving map still encodes");
    }

    #[test]
    fn a_cut_that_empties_both_carried_sets_still_round_trips() {
        let limit = limit_carrying(PreservedFields::new(), PreservedFields::new());
        let mut env = envelope(fields(&[("a", 512)]), fields(&[("t", 512)]));
        let (block, cut) = encode_envelope_within(&mut env, limit).expect("encodes");
        assert_eq!(cut.len(), 2);
        assert!(env.unknown.is_empty() && env.epoch_tag_unknown.is_empty());
        assert_eq!(decode_envelope(&block).expect("decodes"), env);
    }
}
