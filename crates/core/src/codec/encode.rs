//! The deterministic encoder. Canonical by construction: shortest-form
//! arguments, definite lengths, and [`super::Map`]'s ordering invariant are
//! the only forms this module can emit, so encoding is infallible.

use super::value::{Map, Value};

pub(super) const MAJOR_UNSIGNED: u8 = 0;
pub(super) const MAJOR_NEGATIVE: u8 = 1;
pub(super) const MAJOR_BYTES: u8 = 2;
pub(super) const MAJOR_TEXT: u8 = 3;
pub(super) const MAJOR_ARRAY: u8 = 4;
pub(super) const MAJOR_MAP: u8 = 5;
pub(super) const MAJOR_SIMPLE: u8 = 7;

pub(super) const SIMPLE_FALSE: u8 = 20;
pub(super) const SIMPLE_TRUE: u8 = 21;
pub(super) const SIMPLE_NULL: u8 = 22;

/// Encode a value in the deterministic profile.
///
/// Two-pass: [`encoded_len`] sizes the buffer up front so the single allocation
/// is exact and the write never reallocates. A grow-from-empty `Vec` frees each
/// intermediate backing store un-zeroized, stranding secret bytes (content keys,
/// scope/override/history seeds) in freed heap; with one right-sized buffer only
/// the terminal owner's plaintext ever holds them, and that owner zeroizes it.
///
/// Callers must respect [`super::MAX_DEPTH`]: a deeper `Value` still encodes
/// (encoding is infallible), but its bytes reject as `depth-exceeded` on
/// decode — debug builds assert the bound to catch that divergence early.
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::with_capacity(encoded_len(value));
    write_value(&mut out, value, 0);
    out
}

/// The exact number of bytes [`encode`] emits for `value`. Mirrors
/// [`write_value`] head-for-head; the codec property suite pins the two in
/// lockstep (`encoded_len == encode().len()`), which is what makes [`encode`]'s
/// single up-front reservation provably realloc-free.
pub fn encoded_len(value: &Value) -> usize {
    match value {
        Value::Unsigned(n) | Value::Negative(n) => head_len(*n),
        Value::Bytes(b) => head_len(b.len() as u64) + b.len(),
        Value::Text(t) => text_len(t),
        Value::Array(items) => {
            head_len(items.len() as u64) + items.iter().map(encoded_len).sum::<usize>()
        }
        Value::Map(map) => {
            head_len(map.len() as u64)
                + map
                    .entries()
                    .iter()
                    .map(|(k, v)| text_len(k) + encoded_len(v))
                    .sum::<usize>()
        }
        Value::Bool(_) | Value::Null => 1,
    }
}

/// The byte length of a text item: its head plus its UTF-8 bytes.
fn text_len(t: &str) -> usize {
    head_len(t.len() as u64) + t.len()
}

/// The byte length of a shortest-form head for `arg` (mirrors [`write_head`]).
fn head_len(arg: u64) -> usize {
    match arg {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

pub(super) fn write_value(out: &mut Vec<u8>, value: &Value, depth: usize) {
    debug_assert!(
        depth < super::MAX_DEPTH,
        "Value nesting exceeds MAX_DEPTH; the encoding would be undecodable"
    );
    match value {
        Value::Unsigned(n) => write_head(out, MAJOR_UNSIGNED, *n),
        Value::Negative(n) => write_head(out, MAJOR_NEGATIVE, *n),
        Value::Bytes(b) => {
            write_head(out, MAJOR_BYTES, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(t) => write_text(out, t),
        Value::Array(items) => {
            write_head(out, MAJOR_ARRAY, items.len() as u64);
            for item in items {
                write_value(out, item, depth + 1);
            }
        }
        Value::Map(map) => write_map_head_and_entries(out, map, depth),
        Value::Bool(false) => out.push((MAJOR_SIMPLE << 5) | SIMPLE_FALSE),
        Value::Bool(true) => out.push((MAJOR_SIMPLE << 5) | SIMPLE_TRUE),
        Value::Null => out.push((MAJOR_SIMPLE << 5) | SIMPLE_NULL),
    }
}

pub(super) fn write_text(out: &mut Vec<u8>, t: &str) {
    write_head(out, MAJOR_TEXT, t.len() as u64);
    out.extend_from_slice(t.as_bytes());
}

fn write_map_head_and_entries(out: &mut Vec<u8>, map: &Map, depth: usize) {
    write_head(out, MAJOR_MAP, map.len() as u64);
    for (k, v) in map.entries() {
        write_text(out, k);
        write_value(out, v, depth + 1);
    }
}

/// Shortest-form head: the argument rides the initial byte below 24, then
/// the smallest of 1/2/4/8 following bytes that holds it (RFC 8949 §4.2.1).
pub(super) fn write_head(out: &mut Vec<u8>, major: u8, arg: u64) {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A file-body-shaped value: a version list whose 32-byte `contentKey`
    /// entries are the secret bytes the realloc-hygiene fix protects. Sized to
    /// force many reallocations if encoded from an empty `Vec`.
    fn secret_shaped_value(versions: usize) -> Value {
        let mut items = Vec::new();
        for i in 0..versions {
            let mut m = Map::new();
            m.insert("contentCid", Value::Bytes(vec![i as u8; 36]));
            m.insert("contentKey", Value::Bytes(vec![0xAB; 32]));
            m.insert("size", Value::Unsigned(4096));
            m.insert("modifiedAt", Value::Unsigned(1_700_000_000));
            items.push(Value::Map(m));
        }
        let mut body = Map::new();
        body.insert("kind", Value::Text("file".into()));
        body.insert("versions", Value::Array(items));
        body.insert("createdAt", Value::Unsigned(1));
        body.insert("modifiedAt", Value::Unsigned(2));
        Value::Map(body)
    }

    /// `encoded_len` is exact across every head size class and nesting, so the
    /// up-front reservation is neither short (would realloc) nor slack.
    #[test]
    fn encoded_len_is_exact() {
        let cases = [
            Value::Unsigned(0),
            Value::Unsigned(23),
            Value::Unsigned(24),
            Value::Unsigned(0xff),
            Value::Unsigned(0x100),
            Value::Unsigned(0xffff),
            Value::Unsigned(0x1_0000),
            Value::Unsigned(0xffff_ffff),
            Value::Unsigned(0x1_0000_0000),
            Value::Negative(0),
            Value::Negative(u64::MAX),
            Value::Bytes(vec![0; 23]),
            Value::Bytes(vec![0; 300]),
            Value::Text("a".repeat(24)),
            Value::Bool(true),
            Value::Null,
            Value::Array(vec![Value::Unsigned(1), Value::Null]),
            secret_shaped_value(40),
        ];
        for v in &cases {
            assert_eq!(encoded_len(v), encode(v).len(), "len oracle diverged");
        }
    }

    /// The security invariant: encoding secret-bearing bytes performs a single
    /// allocation and never reallocates, so no intermediate backing store is
    /// freed un-zeroized. Capturing the pointer and capacity after the reserve
    /// and asserting both are unchanged after the write proves the buffer never
    /// moved (a realloc would move it and/or grow capacity), independent of any
    /// allocator over-allocation.
    #[test]
    fn secret_bearing_encode_never_reallocates() {
        let value = secret_shaped_value(64);
        let mut out = Vec::with_capacity(encoded_len(&value));
        let ptr = out.as_ptr();
        let reserved_cap = out.capacity();
        write_value(&mut out, &value, 0);
        assert!(out.len() > 1024, "test payload must force multiple growths");
        assert_eq!(
            out.capacity(),
            reserved_cap,
            "capacity grew — a realloc ran"
        );
        assert_eq!(out.as_ptr(), ptr, "backing store moved — a realloc ran");
        assert_eq!(
            encode(&value),
            out,
            "public two-pass path is byte-identical"
        );
    }
}
