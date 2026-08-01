//! The deterministic encoder. Canonical by construction: shortest-form
//! arguments, definite lengths, and [`super::Map`]'s ordering invariant are
//! the only forms this module can emit, so [`check_depth`] is the one way
//! encoding fails.

use super::value::{Map, Value};
use crate::error::{CodecError, Malformed};

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
/// intermediate backing store un-zeroized, stranding secret bytes in freed heap;
/// one right-sized buffer keeps them to the terminal owner's plaintext, which
/// that owner zeroizes. Sizing first is also what makes [`check_depth`] fail
/// closed instead of overflowing the stack: it runs before anything is allocated.
pub fn encode(value: &Value) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::with_capacity(encoded_len(value)?);
    write_value(&mut out, value, 0)?;
    Ok(out)
}

/// [`encode`] for a tree whose nesting is fixed by its construction site — an
/// AAD or signature preimage, a schema map of scalars — so the bound is
/// unreachable and the surrounding seal/sign surface stays infallible.
///
/// # Panics
///
/// If `value` nests to [`super::MAX_DEPTH`]. Use [`encode`] for any tree whose
/// depth comes from input rather than from the schema.
pub fn encode_fixed_depth(value: &Value) -> Vec<u8> {
    encode(value).expect("fixed-shape tree is within MAX_DEPTH")
}

/// The exact number of bytes [`encode`] emits for `value`. Mirrors
/// [`write_value`] head-for-head; the codec property suite pins the two in
/// lockstep (`encoded_len == encode().len()`), which is what makes [`encode`]'s
/// single up-front reservation provably realloc-free.
pub fn encoded_len(value: &Value) -> Result<usize, CodecError> {
    let mut len = 0;
    count_value(&mut len, value, 0)?;
    Ok(len)
}

pub(super) fn count_value(len: &mut usize, value: &Value, depth: usize) -> Result<(), CodecError> {
    check_depth(depth, *len)?;
    match value {
        Value::Unsigned(n) | Value::Negative(n) => *len += head_len(*n),
        Value::Bytes(b) => *len += head_len(b.len() as u64) + b.len(),
        Value::Text(t) => *len += text_len(t),
        Value::Array(items) => {
            *len += head_len(items.len() as u64);
            for item in items {
                count_value(len, item, depth + 1)?;
            }
        }
        Value::Map(map) => {
            reject_wiped(map)?;
            *len += head_len(map.len() as u64);
            for (k, v) in map.entries() {
                *len += text_len(k);
                count_value(len, v, depth + 1)?;
            }
        }
        Value::Bool(_) | Value::Null => *len += 1,
    }
    Ok(())
}

/// The produce-side half of the decoder's `depth-exceeded` reject (AGENTS.md
/// encode/decode fail-closed symmetry), and the recursion guard on both passes.
/// `offset` is the emitted-byte position the bound fired at.
fn check_depth(depth: usize, offset: usize) -> Result<(), CodecError> {
    if depth >= super::MAX_DEPTH {
        return Err(Malformed::DepthExceeded { offset }.into());
    }
    Ok(())
}

/// The terminal half of [`Map::zeroize_bytes`]: a wiped map's fields are all
/// zero-length, and a variable-length schema read round-trips one as empty
/// instead of rejecting it, so emitting from a wiped map is silent data loss.
/// Release-active on both passes, like [`check_depth`].
pub(super) fn reject_wiped(map: &Map) -> Result<(), CodecError> {
    if map.is_wiped() {
        return Err(Malformed::WipedMap.into());
    }
    Ok(())
}

/// The byte length of a text item: its head plus its UTF-8 bytes.
pub(super) fn text_len(t: &str) -> usize {
    head_len(t.len() as u64) + t.len()
}

/// The byte length of a shortest-form head for `arg` (mirrors [`write_head`]).
pub(super) fn head_len(arg: u64) -> usize {
    match arg {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

pub(super) fn write_value(
    out: &mut Vec<u8>,
    value: &Value,
    depth: usize,
) -> Result<(), CodecError> {
    check_depth(depth, out.len())?;
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
                write_value(out, item, depth + 1)?;
            }
        }
        Value::Map(map) => write_map_head_and_entries(out, map, depth)?,
        Value::Bool(false) => out.push((MAJOR_SIMPLE << 5) | SIMPLE_FALSE),
        Value::Bool(true) => out.push((MAJOR_SIMPLE << 5) | SIMPLE_TRUE),
        Value::Null => out.push((MAJOR_SIMPLE << 5) | SIMPLE_NULL),
    }
    Ok(())
}

pub(super) fn write_text(out: &mut Vec<u8>, t: &str) {
    write_head(out, MAJOR_TEXT, t.len() as u64);
    out.extend_from_slice(t.as_bytes());
}

fn write_map_head_and_entries(
    out: &mut Vec<u8>,
    map: &Map,
    depth: usize,
) -> Result<(), CodecError> {
    reject_wiped(map)?;
    write_head(out, MAJOR_MAP, map.len() as u64);
    for (k, v) in map.entries() {
        write_text(out, k);
        write_value(out, v, depth + 1)?;
    }
    Ok(())
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
            assert_eq!(
                encoded_len(v).unwrap(),
                encode(v).unwrap().len(),
                "len oracle diverged"
            );
        }
    }

    fn nested(n: usize) -> Value {
        let mut v = Value::Null;
        for _ in 0..n {
            v = Value::Array(vec![v]);
        }
        v
    }

    /// The bound is release-active on both passes, at the same boundary the
    /// decoder rejects.
    #[test]
    fn encode_rejects_past_max_depth() {
        let deep = nested(crate::codec::MAX_DEPTH);
        assert_eq!(encoded_len(&deep).unwrap_err().check(), "depth-exceeded");
        assert_eq!(encode(&deep).unwrap_err().check(), "depth-exceeded");

        // The other half of the boundary: what the encoder admits, the decoder
        // reopens — an off-by-one either way would break one of these.
        let deepest = nested(crate::codec::MAX_DEPTH - 1);
        let bytes = encode(&deepest).expect("the deepest admissible tree encodes");
        assert_eq!(encoded_len(&deepest).unwrap(), bytes.len());
        assert_eq!(super::super::decode(&bytes).unwrap(), deepest);
    }

    /// AGENTS.md rule 8's misuse-resistance sibling, release-active: a wiped map
    /// re-encodes to fields its own decoder accepts as empty, so the wipe is
    /// terminal and both passes refuse it — at every nesting level, since the
    /// hazard is a version map inside a body, not only a top-level map.
    #[test]
    fn a_wiped_map_refuses_to_encode() {
        let mut value = secret_shaped_value(2);
        assert!(encode(&value).is_ok(), "encodes before the wipe");

        // Wipe one nested version map, the way a caller scrubbing decoded known
        // fields would, and leave the enclosing tree untouched.
        let Value::Map(body) = &mut value else {
            panic!("expected a map body")
        };
        let Some(Value::Array(versions)) = body.get_mut("versions") else {
            panic!("expected a version list")
        };
        let Value::Map(version) = &mut versions[0] else {
            panic!("expected a version map")
        };
        version.zeroize_bytes();
        assert!(version.is_wiped());

        assert_eq!(encoded_len(&value).unwrap_err().check(), "wiped-map");
        assert_eq!(encode(&value).unwrap_err().check(), "wiped-map");
        let mut out = Vec::new();
        assert_eq!(
            write_value(&mut out, &value, 0).unwrap_err().check(),
            "wiped-map"
        );
    }

    /// The security invariant: encoding secret-bearing bytes never reallocates,
    /// so no intermediate backing store is freed un-zeroized. An unchanged
    /// pointer *and* capacity across the write proves it, independent of any
    /// allocator over-allocation.
    #[test]
    fn secret_bearing_encode_never_reallocates() {
        let value = secret_shaped_value(64);
        let mut out = Vec::with_capacity(encoded_len(&value).unwrap());
        let ptr = out.as_ptr();
        let reserved_cap = out.capacity();
        write_value(&mut out, &value, 0).unwrap();
        assert!(out.len() > 1024, "test payload must force multiple growths");
        assert_eq!(
            out.capacity(),
            reserved_cap,
            "capacity grew — a realloc ran"
        );
        assert_eq!(out.as_ptr(), ptr, "backing store moved — a realloc ran");
        assert_eq!(
            encode(&value).unwrap(),
            out,
            "public two-pass path is byte-identical"
        );
    }
}
