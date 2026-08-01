//! Unknown-field tolerance (blueprint/core.md, #27 D10): the single decode
//! tolerance in the profile. Fields a schema does not know are accepted,
//! ignored for logic, preserved byte-stable, and re-emitted canonically on
//! rewrite — an old client rewriting under shared write never strips newer
//! fields.
//!
//! Because the decoder admits canonical input only, a preserved raw slice is
//! canonical by construction, so re-emitting it verbatim keeps the whole
//! rewrite canonical.

use core::fmt;

use zeroize::Zeroizing;

use super::decode::Decoder;
use super::encode::{
    MAJOR_MAP, count_value, head_len, text_len, write_head, write_text, write_value,
};
use super::scrub::ScrubOnDrop;
use super::value::{Map, Value, canonical_key_cmp};
use crate::error::{CodecError, DisplayKey, Malformed};

/// The depth a top-level map's values sit at: the map itself is the enclosing
/// item, so its entries are one level in.
const MAP_ENTRY_DEPTH: usize = 1;

/// Fields preserved through a decode the caller's schema did not recognize:
/// key plus the exact canonical bytes of the value. Ordered canonically.
///
/// A preserved value is a verbatim copy of whatever the field carried, and this
/// set is that copy's terminal owner: the bytes sit in a zeroizing owner so the
/// wipe is type-enforced rather than a caller's to remember, and they are kept
/// out of every rendering (blueprint/core.md "Crypto suite"). Keys are field
/// names, never secret.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct UnknownFields {
    entries: Vec<(String, Zeroizing<Vec<u8>>)>,
}

impl fmt::Debug for UnknownFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_redacted_keys(f, self.entries.iter().map(|(key, _)| key.as_str()))
    }
}

/// Render a preserved-field set as keys only, with the field names bounded the
/// way the error surface bounds writer-controlled keys. Shared by both
/// preserve-unknowns carriers so neither can grow a value into a log line.
pub(crate) fn fmt_redacted_keys<'a>(
    f: &mut fmt::Formatter<'_>,
    keys: impl Iterator<Item = &'a str>,
) -> fmt::Result {
    let mut m = f.debug_map();
    for key in keys {
        m.key(&DisplayKey(key)).value(&"<redacted>");
    }
    m.finish()
}

impl UnknownFields {
    /// Preserved entries in canonical key order. Borrowed as plain bytes: the
    /// wipe belongs to this set, so a borrow cannot carry it.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.entries
            .iter()
            .map(|(key, raw)| (key.as_str(), raw.as_slice()))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Decode a top-level map, splitting entries into known fields (decoded
/// values, selected by `is_known`) and unknown fields (raw canonical bytes).
/// Every entry — known or not — passes the full strict profile.
///
/// The returned [`Map`] is the caller's to wipe once it is done with it
/// ([`Map::zeroize_bytes`]); the preserved unknowns wipe themselves.
pub fn decode_map_partial(
    bytes: &[u8],
    is_known: impl Fn(&str) -> bool,
) -> Result<(Map, UnknownFields), CodecError> {
    let mut known = Map::new();
    let unknown = decode_entries(bytes, is_known, &mut known)?;
    Ok((known, unknown))
}

/// The entry loop, over a `known` the caller owns so it survives the success
/// path. Anything else — a reject, or a panic out of `is_known` — leaves it to
/// the scrub guard rather than stranding decoded secrets in freed heap.
fn decode_entries(
    bytes: &[u8],
    is_known: impl Fn(&str) -> bool,
    known: &mut Map,
) -> Result<UnknownFields, CodecError> {
    let mut d = Decoder::new(bytes);
    let head = d.read_head()?;
    if head.major != MAJOR_MAP {
        return Err(Malformed::UnexpectedType {
            expected: "map",
            found: "non-map item",
        }
        .into());
    }

    let known = ScrubOnDrop(known);
    let mut unknown = UnknownFields::default();
    let mut prev: Option<String> = None;
    for _ in 0..head.arg {
        let key = d.read_map_key(prev.as_deref())?;
        let start = d.pos();
        let mut value = d.read_value(MAP_ENTRY_DEPTH)?;
        if is_known(&key) {
            known.0.insert(key.clone(), value);
        } else {
            // An unknown entry is decoded and *also* copied verbatim; the
            // decoded tree is this loop's to discard, so it goes wiped.
            unknown
                .entries
                .push((key.clone(), Zeroizing::new(bytes[start..d.pos()].to_vec())));
            value.zeroize_bytes();
        }
        prev = Some(key);
    }
    d.expect_end()?;
    core::mem::forget(known);
    Ok(unknown)
}

/// Canonically re-encode a map from re-built known fields plus preserved
/// unknown fields: one merged map in canonical key order, unknown values
/// emitted byte-stable. A key present on both sides is a caller bug and
/// rejects fail-closed.
pub fn encode_map_partial(known: &Map, unknown: &UnknownFields) -> Result<Vec<u8>, CodecError> {
    // This writes the merged head itself, so the known side's mark is read here.
    known.reject_if_wiped()?;
    let merged = merge(known, unknown)?;
    let mut out = Vec::with_capacity(merged_len(&merged)?);
    write_head(&mut out, MAJOR_MAP, merged.len() as u64);
    for (key, value) in &merged {
        write_text(&mut out, key);
        match value {
            MergedValue::Known(v) => write_value(&mut out, v, MAP_ENTRY_DEPTH)?,
            MergedValue::Raw(raw) => out.extend_from_slice(raw),
        }
    }
    Ok(out)
}

/// A merged entry's value: a re-built known value, or a preserved unknown
/// value's raw canonical bytes.
enum MergedValue<'a> {
    Known(&'a Value),
    Raw(&'a [u8]),
}

/// Interleave the two canonically-ordered sides into the emit sequence. Holds
/// borrows only, so no secret bytes are copied into it. Walking the merge here
/// rather than in each pass is what lets both rejects — collision and
/// `depth-exceeded` — fire before the output buffer exists.
fn merge<'a>(
    known: &'a Map,
    unknown: &'a UnknownFields,
) -> Result<Vec<(&'a str, MergedValue<'a>)>, CodecError> {
    let mut merged = Vec::with_capacity(known.len() + unknown.len());
    let mut k = known.entries().iter().peekable();
    let mut u = unknown.entries.iter().peekable();
    loop {
        let take_known = match (k.peek(), u.peek()) {
            (Some((kk, _)), Some((uk, _))) => match canonical_key_cmp(kk, uk) {
                core::cmp::Ordering::Less => true,
                core::cmp::Ordering::Greater => false,
                core::cmp::Ordering::Equal => {
                    return Err(Malformed::UnknownFieldCollision { key: kk.clone() }.into());
                }
            },
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => break,
        };
        if take_known {
            let (key, value) = k.next().expect("peeked");
            merged.push((key.as_str(), MergedValue::Known(value)));
        } else {
            let (key, raw) = u.next().expect("peeked");
            merged.push((key.as_str(), MergedValue::Raw(raw.as_slice())));
        }
    }
    Ok(merged)
}

/// The exact byte length of the merged map, sizing [`encode_map_partial`]'s one
/// allocation for the realloc-hygiene reason [`super::encode::encode`] documents.
/// Counting in emit order keeps `depth-exceeded`'s reported offset exact.
fn merged_len(merged: &[(&str, MergedValue<'_>)]) -> Result<usize, CodecError> {
    let mut len = head_len(merged.len() as u64);
    for (key, value) in merged {
        len += text_len(key);
        match value {
            MergedValue::Known(v) => count_value(&mut len, v, MAP_ENTRY_DEPTH)?,
            // AGENTS.md rule 8: an empty preserved value would splice a key
            // with nothing after it — bytes this codec's decoder rejects.
            MergedValue::Raw([]) => return Err(Malformed::Truncated { offset: len }.into()),
            MergedValue::Raw(raw) => len += raw.len(),
        }
    }
    Ok(len)
}

/// Convenience for schema codecs: `true` when `key` is in `known`.
pub fn known_key_set(known: &'static [&'static str]) -> impl Fn(&str) -> bool {
    move |key| known.contains(&key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decode, encode};

    fn sample_map() -> Map {
        let mut m = Map::new();
        m.insert("v", Value::Unsigned(2));
        m.insert("id", Value::Bytes(vec![0xaa; 4]));
        m.insert(
            "future",
            Value::Array(vec![Value::Unsigned(1), Value::Null]),
        );
        m.insert("zz-later", Value::Text("kept".into()));
        m
    }

    /// A merged map big enough to force several growths from an empty `Vec`,
    /// spanning both key-head size classes and a >23-entry map head.
    fn wide_secret_shaped_map() -> Map {
        let mut m = Map::new();
        for i in 0..40u8 {
            m.insert(format!("k{i:02}"), Value::Bytes(vec![0xAB; 32]));
            m.insert(
                format!("a-preserved-future-field-name-{i:02}"),
                Value::Text("x".repeat(40)),
            );
        }
        m
    }

    /// The security invariant, as `encode` pins it: the merged write runs
    /// inside one exact reservation, so no intermediate backing store is freed
    /// un-zeroized. `merged_len` being exact makes `capacity == len` the
    /// witness — growing from empty leaves a doubled capacity behind.
    #[test]
    fn merged_write_never_reallocates() {
        let original = encode(&Value::Map(wide_secret_shaped_map())).unwrap();
        let (known, unknown) = decode_map_partial(&original, |key| key.starts_with('k')).unwrap();
        assert_eq!(known.len(), 40);
        assert_eq!(unknown.len(), 40);

        let out = encode_map_partial(&known, &unknown).unwrap();
        assert!(out.len() > 1024, "test payload must force multiple growths");
        assert_eq!(out, original, "wire bytes unchanged");
        // Allocator-independent oracle, plus the witness that the reservation
        // was the one the buffer kept.
        let sized = merged_len(&merge(&known, &unknown).unwrap()).unwrap();
        assert_eq!(sized, out.len(), "sizing oracle diverged");
        assert_eq!(
            out.capacity(),
            out.len(),
            "buffer was resized after its up-front reservation"
        );
    }

    /// AGENTS.md rule 8: the merged encoder's `depth-exceeded` reject is
    /// release-active, and now fires from the sizing pass — before a byte is
    /// allocated for the output. The deep value sits behind two preserved
    /// unknowns, so its reported offset only matches the equivalent full-map
    /// encode's if the sizing pass counted in emit order.
    #[test]
    fn merged_encode_rejects_past_max_depth() {
        fn depth_offset(err: &CodecError) -> usize {
            match err {
                CodecError::Malformed(Malformed::DepthExceeded { offset }) => *offset,
                other => panic!("expected depth-exceeded, got {}", other.check()),
            }
        }

        let original = encode(&Value::Map(sample_map())).unwrap();
        let (mut known, unknown) =
            decode_map_partial(&original, known_key_set(&["v", "zz-later"])).unwrap();
        let mut deep = Value::Null;
        for _ in 0..crate::codec::MAX_DEPTH {
            deep = Value::Array(vec![deep]);
        }
        known.insert("zz-later", deep.clone());
        let mut full = sample_map();
        full.insert("zz-later", deep);

        assert_eq!(
            depth_offset(&encode_map_partial(&known, &unknown).unwrap_err()),
            depth_offset(&encode(&Value::Map(full)).unwrap_err()),
            "merged reject offset diverged from the full-map encode"
        );
    }

    /// A preserved value never reaches a log line, and a crafted field name
    /// cannot flood one.
    #[test]
    fn debug_redacts_preserved_values() {
        let mut m = Map::new();
        m.insert("v", Value::Unsigned(2));
        m.insert("futureKey", Value::Bytes(vec![0xAB; 32]));
        m.insert("z".repeat(200), Value::Unsigned(1));
        let bytes = encode(&Value::Map(m)).unwrap();

        let (_, unknown) = decode_map_partial(&bytes, known_key_set(&["v"])).unwrap();
        let rendered = format!("{unknown:?}");

        assert!(rendered.starts_with(r#"{"futureKey": "<redacted>", "zzz"#));
        assert!(rendered.ends_with(r#"…: "<redacted>"}"#), "{rendered}");
        assert!(rendered.len() < 160, "a crafted key flooded it: {rendered}");
    }

    /// A decode that rejects is the terminal owner of the known fields it had
    /// already lifted out of its input.
    #[test]
    fn a_failed_decode_wipes_what_it_already_lifted() {
        const SECRET: [u8; 32] = [0xAB; 32];
        let mut m = Map::new();
        m.insert("a", Value::Bytes(SECRET.to_vec()));
        let mut bytes = encode(&Value::Map(m)).unwrap();
        // A second entry the head promises and the input cuts off.
        bytes[0] = 0xa2;
        bytes.extend_from_slice(&[0x61, b'b', 0x18]);

        let mut known = Map::new();
        assert_eq!(
            decode_entries(&bytes, |_| true, &mut known)
                .unwrap_err()
                .check(),
            "truncated"
        );
        assert_eq!(known.get("a"), Some(&Value::Bytes(Vec::new())));
    }

    /// AGENTS.md rule 8: the encoder refuses to splice a preserved value that
    /// would leave a key with nothing after it, which its decoder rejects.
    #[test]
    fn merged_encode_rejects_an_empty_preserved_value() {
        let unknown = UnknownFields {
            entries: vec![("future".into(), Zeroizing::new(Vec::new()))],
        };
        let mut known = Map::new();
        known.insert("v", Value::Unsigned(2));

        let err = encode_map_partial(&known, &unknown).unwrap_err();
        assert_eq!(err.check(), "truncated");
    }

    /// The merged encoder reads the wiped mark on the known side it writes the
    /// head for; a rewrite after a scrub would otherwise publish a record whose
    /// variable-length fields silently came back empty.
    #[test]
    fn merged_encode_rejects_a_wiped_known_side() {
        let original = encode(&Value::Map(sample_map())).unwrap();
        let (mut known, unknown) =
            decode_map_partial(&original, known_key_set(&["v", "id"])).unwrap();
        known.zeroize_bytes();

        let err = encode_map_partial(&known, &unknown).unwrap_err();
        assert_eq!(err.check(), "wiped-map");
    }

    #[test]
    fn unknown_fields_round_trip_byte_stable() {
        let original = encode(&Value::Map(sample_map())).unwrap();
        let (known, unknown) = decode_map_partial(&original, known_key_set(&["v", "id"])).unwrap();
        assert_eq!(known.len(), 2);
        assert_eq!(unknown.len(), 2);
        let reencoded = encode_map_partial(&known, &unknown).unwrap();
        assert_eq!(reencoded, original, "rewrite must be byte-stable");
    }

    #[test]
    fn rewrite_of_known_field_keeps_unknowns_and_canonical_order() {
        let original = encode(&Value::Map(sample_map())).unwrap();
        let (mut known, unknown) =
            decode_map_partial(&original, known_key_set(&["v", "id"])).unwrap();
        known.insert("v", Value::Unsigned(3));
        let rewritten = encode_map_partial(&known, &unknown).unwrap();

        let mut expected = sample_map();
        expected.insert("v", Value::Unsigned(3));
        assert_eq!(rewritten, encode(&Value::Map(expected)).unwrap());
        // Still strict-profile decodable with everything present.
        let full = decode(&rewritten).unwrap();
        let m = full.as_map().unwrap();
        assert_eq!(m.get("v"), Some(&Value::Unsigned(3)));
        assert!(m.contains_key("future"));
        assert!(m.contains_key("zz-later"));
    }

    #[test]
    fn collision_between_known_and_unknown_rejects() {
        let original = encode(&Value::Map(sample_map())).unwrap();
        let (mut known, unknown) =
            decode_map_partial(&original, known_key_set(&["v", "id"])).unwrap();
        known.insert("future", Value::Unsigned(0));
        let err = encode_map_partial(&known, &unknown).unwrap_err();
        assert_eq!(err.check(), "unknown-field-collision");
    }

    #[test]
    fn non_map_top_level_rejects() {
        let bytes = encode(&Value::Unsigned(1)).unwrap();
        let err = decode_map_partial(&bytes, |_| true).unwrap_err();
        assert_eq!(err.check(), "unexpected-type");
    }

    #[test]
    fn strictness_applies_inside_unknown_values() {
        // {"a": <non-shortest-form 1>} — the unknown value must still reject.
        let bytes = [0xa1, 0x61, b'a', 0x18, 0x01];
        let err = decode_map_partial(&bytes, |_| false).unwrap_err();
        assert_eq!(err.check(), "non-canonical-uint");
    }

    #[test]
    fn indefinite_length_inside_unknown_value_rejects() {
        // {"a": <indefinite array>} — 9f ... ff.
        let bytes = [0xa1, 0x61, b'a', 0x9f, 0xff];
        let err = decode_map_partial(&bytes, |_| false).unwrap_err();
        assert_eq!(err.check(), "indefinite-length");
    }

    #[test]
    fn truncated_unknown_value_rejects() {
        // {"a": <uint head with its argument byte cut off>} — no partial
        // UnknownFields may escape a failed decode.
        let bytes = [0xa1, 0x61, b'a', 0x18];
        let err = decode_map_partial(&bytes, |_| false).unwrap_err();
        assert_eq!(err.check(), "truncated");
    }

    #[test]
    fn trailing_bytes_after_partial_map_reject() {
        // {"a": 1} followed by a stray byte — expect_end guards the partial
        // path exactly like the full decode.
        let bytes = [0xa1, 0x61, b'a', 0x01, 0x00];
        let err = decode_map_partial(&bytes, |_| true).unwrap_err();
        assert_eq!(err.check(), "trailing-bytes");
    }
}
