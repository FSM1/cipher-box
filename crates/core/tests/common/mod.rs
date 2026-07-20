//! Test-support: a tiny standalone CBOR "defect encoder".
//!
//! Each helper re-encodes a [`Value`] with exactly one deliberate
//! deterministic-profile violation and returns `(bytes, expected_check)`,
//! so the property suite can assert the strict decoder rejects every
//! defect with the named check. Deliberately independent of the crate's
//! encoder internals: heads are written by hand here, and only the
//! canonical payload bytes come from the public [`encode`].

use cipherbox_core::codec::{Value, canonical_key_cmp, encode};

const MAJOR_TEXT: u8 = 3;
const MAJOR_MAP: u8 = 5;

/// Shortest-form head (RFC 8949 §4.2.1): an argument below 24 rides the
/// initial byte; otherwise the smallest of 1/2/4/8 following big-endian
/// bytes that holds it.
fn write_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let mt = major << 5;
    match arg {
        0..=23 => out.push(mt | arg as u8),
        24..=0xff => {
            out.push(mt | 24);
            out.push(arg as u8);
        }
        0x100..=0xffff => {
            out.push(mt | 25);
            out.extend_from_slice(&(arg as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(mt | 26);
            out.extend_from_slice(&(arg as u32).to_be_bytes());
        }
        _ => {
            out.push(mt | 27);
            out.extend_from_slice(&arg.to_be_bytes());
        }
    }
}

/// Canonical definite-length text item.
fn write_text(out: &mut Vec<u8>, s: &str) {
    write_head(out, MAJOR_TEXT, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

/// `[0, value]` with the leading 0 emitted as `0x18 0x00`: major 0 with
/// ai 24 (one following argument byte) carrying 0, which shortest form
/// requires on the initial byte (`0x00`). The array head `0x82` is
/// canonical; rejection must fire at the widened integer head, before
/// `value` is ever reached.
pub fn widen_head(value: &Value) -> (Vec<u8>, &'static str) {
    let mut out = vec![0x82, 0x18, 0x00];
    out.extend_from_slice(&encode(value));
    (out, "non-canonical-uint")
}

/// `["x", value]` with the text length 1 emitted in 8-bit form:
/// `0x78 0x01 'x'` (major 3, ai 24, argument 1) instead of the canonical
/// `0x61 'x'`. Length arguments obey the same shortest-form rule as
/// integers but reject with their own check name.
pub fn widen_length(value: &Value) -> (Vec<u8>, &'static str) {
    let mut out = vec![0x82, 0x78, 0x01, b'x'];
    out.extend_from_slice(&encode(value));
    (out, "non-canonical-length")
}

/// `0x9f <value> 0xff`: major 4 with ai 31 opens an indefinite-length
/// array, terminated by the break byte `0xff`. The profile admits definite
/// lengths only; rejection fires on the `0x9f` head before any element.
pub fn indefinite_array(value: &Value) -> (Vec<u8>, &'static str) {
    let mut out = vec![0x9f];
    out.extend_from_slice(&encode(value));
    out.push(0xff);
    (out, "indefinite-length")
}

/// A two-entry map emitted as `{hi: v1, lo: v2}` where `lo < hi` in
/// canonical key order (length-first, then bytewise — the caller must
/// supply two DISTINCT keys). Every entry is individually canonical; only
/// the ordering is wrong, so the decoder rejects at the second key.
pub fn swap_map_keys(lo: &str, hi: &str, v1: &Value, v2: &Value) -> (Vec<u8>, &'static str) {
    debug_assert_eq!(canonical_key_cmp(lo, hi), core::cmp::Ordering::Less);
    let mut out = Vec::new();
    write_head(&mut out, MAJOR_MAP, 2);
    write_text(&mut out, hi);
    out.extend_from_slice(&encode(v1));
    write_text(&mut out, lo);
    out.extend_from_slice(&encode(v2));
    (out, "unsorted-map-keys")
}

/// `{k: v1, k: v2}`: the same canonically-encoded key twice. Relative to
/// the first key the second compares Equal (not strictly ascending), so
/// uniqueness is the check that fires.
pub fn duplicate_key(k: &str, v1: &Value, v2: &Value) -> (Vec<u8>, &'static str) {
    let mut out = Vec::new();
    write_head(&mut out, MAJOR_MAP, 2);
    write_text(&mut out, k);
    out.extend_from_slice(&encode(v1));
    write_text(&mut out, k);
    out.extend_from_slice(&encode(v2));
    (out, "duplicate-map-key")
}

/// `0xc6 <value>`: major 6 (tag number 6 on the initial byte) prefixing an
/// otherwise-canonical item. The profile admits no tags whatever their
/// number; rejection fires on the initial byte.
pub fn wrap_tag(value: &Value) -> (Vec<u8>, &'static str) {
    let mut out = vec![0xc6];
    out.extend_from_slice(&encode(value));
    (out, "tag-forbidden")
}

/// `[1.0f16, value]`: array(2) head `0x82`, then `0xf9` (major 7, ai 25 =
/// half-precision float) with big-endian payload `0x3c00` (= 1.0). Floats
/// are forbidden whatever their width or value.
pub fn inject_float(value: &Value) -> (Vec<u8>, &'static str) {
    let mut out = vec![0x82, 0xf9, 0x3c, 0x00];
    out.extend_from_slice(&encode(value));
    (out, "float-forbidden")
}

/// A canonical item followed by one extra `0x00` byte: decode must consume
/// the input as exactly one item spanning the whole slice.
pub fn trailing_junk(value: &Value) -> (Vec<u8>, &'static str) {
    let mut out = encode(value);
    out.push(0x00);
    (out, "trailing-bytes")
}

/// A canonical item minus its final byte. A canonical encoding's parse
/// consumes every byte deterministically, so any strict prefix leaves the
/// last read short (an empty result — one-byte encodings — still rejects
/// as truncated at offset 0).
pub fn truncate(value: &Value) -> (Vec<u8>, &'static str) {
    let mut out = encode(value);
    out.pop();
    (out, "truncated")
}
