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
/// Callers must respect [`super::MAX_DEPTH`]: a deeper `Value` still encodes
/// (encoding is infallible), but its bytes reject as `depth-exceeded` on
/// decode — debug builds assert the bound to catch that divergence early.
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_value(&mut out, value, 0);
    out
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
