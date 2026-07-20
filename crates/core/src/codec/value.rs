//! The det-CBOR data model.
//!
//! The profile is a strict subset of DAG-CBOR: definite lengths only,
//! text-string map keys only, no tags, no floats, no simple values beyond
//! `false`/`true`/`null`. Integers cover the full CBOR range (major 0/1);
//! [`Value::Negative(n)`] represents `-1 - n`.

use core::cmp::Ordering;
use core::fmt;

use crate::error::Malformed;

/// A value in the deterministic profile's data model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Major type 0: `0 ..= u64::MAX`.
    Unsigned(u64),
    /// Major type 1: represents `-1 - n`, so the full range down to `-2^64`.
    Negative(u64),
    /// Major type 2: a definite-length byte string.
    Bytes(Vec<u8>),
    /// Major type 3: a definite-length UTF-8 text string.
    Text(String),
    /// Major type 4: a definite-length array.
    Array(Vec<Value>),
    /// Major type 5: a map with unique text keys in canonical order.
    Map(Map),
    /// Major type 7, simple values 20/21.
    Bool(bool),
    /// Major type 7, simple value 22.
    Null,
}

impl Value {
    /// The type label used in [`Malformed::UnexpectedType`] diagnostics.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Unsigned(_) => "unsigned",
            Self::Negative(_) => "negative",
            Self::Bytes(_) => "bytes",
            Self::Text(_) => "text",
            Self::Array(_) => "array",
            Self::Map(_) => "map",
            Self::Bool(_) => "bool",
            Self::Null => "null",
        }
    }

    /// The value as a `u64`, or an [`Malformed::UnexpectedType`] naming what
    /// was found.
    pub fn as_unsigned(&self) -> Result<u64, Malformed> {
        match self {
            Self::Unsigned(n) => Ok(*n),
            other => Err(unexpected("unsigned", other)),
        }
    }

    /// The value as bytes.
    pub fn as_bytes(&self) -> Result<&[u8], Malformed> {
        match self {
            Self::Bytes(b) => Ok(b),
            other => Err(unexpected("bytes", other)),
        }
    }

    /// The value as text.
    pub fn as_text(&self) -> Result<&str, Malformed> {
        match self {
            Self::Text(t) => Ok(t),
            other => Err(unexpected("text", other)),
        }
    }

    /// The value as an array.
    pub fn as_array(&self) -> Result<&[Value], Malformed> {
        match self {
            Self::Array(a) => Ok(a),
            other => Err(unexpected("array", other)),
        }
    }

    /// The value as a map.
    pub fn as_map(&self) -> Result<&Map, Malformed> {
        match self {
            Self::Map(m) => Ok(m),
            other => Err(unexpected("map", other)),
        }
    }

    /// The value as a bool.
    pub fn as_bool(&self) -> Result<bool, Malformed> {
        match self {
            Self::Bool(b) => Ok(*b),
            other => Err(unexpected("bool", other)),
        }
    }

    /// The value as a signed integer, when it fits `i64`.
    pub fn as_i64(&self) -> Result<i64, Malformed> {
        match self {
            Self::Unsigned(n) => i64::try_from(*n).map_err(|_| unexpected("i64", self)),
            Self::Negative(n) => {
                let m = i128::from(*n);
                i64::try_from(-1 - m).map_err(|_| unexpected("i64", self))
            }
            other => Err(unexpected("i64", other)),
        }
    }

    /// A `Value` from any `i64`.
    pub fn from_i64(n: i64) -> Self {
        if n >= 0 {
            Self::Unsigned(n as u64)
        } else {
            Self::Negative(!(n as u64))
        }
    }
}

fn unexpected(expected: &'static str, found: &Value) -> Malformed {
    Malformed::UnexpectedType {
        expected,
        found: found.type_name(),
    }
}

/// The canonical map-key ordering: RFC 8949 §4.2.1 bytewise-lexicographic
/// comparison of the encoded keys. With text-only keys this is exactly
/// length-first, then bytewise — asserted by test, relied on by the encoder.
pub fn canonical_key_cmp(a: &str, b: &str) -> Ordering {
    a.len()
        .cmp(&b.len())
        .then_with(|| a.as_bytes().cmp(b.as_bytes()))
}

/// A map whose entries are always unique-keyed and canonically ordered.
/// Building one cannot produce a non-canonical encoding.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Map {
    entries: Vec<(String, Value)>,
}

impl Map {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace, keeping canonical order. Returns the value a
    /// replaced entry held.
    pub fn insert(&mut self, key: impl Into<String>, value: Value) -> Option<Value> {
        let key = key.into();
        match self
            .entries
            .binary_search_by(|(k, _)| canonical_key_cmp(k, &key))
        {
            Ok(i) => Some(core::mem::replace(&mut self.entries[i].1, value)),
            Err(i) => {
                self.entries.insert(i, (key, value));
                None
            }
        }
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries
            .binary_search_by(|(k, _)| canonical_key_cmp(k, key))
            .ok()
            .map(|i| &self.entries[i].1)
    }

    pub fn remove(&mut self, key: &str) -> Option<Value> {
        self.entries
            .binary_search_by(|(k, _)| canonical_key_cmp(k, key))
            .ok()
            .map(|i| self.entries.remove(i).1)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Entries in canonical order.
    pub fn entries(&self) -> &[(String, Value)] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl FromIterator<(String, Value)> for Map {
    /// Later duplicates replace earlier ones, like `BTreeMap`.
    fn from_iter<I: IntoIterator<Item = (String, Value)>>(iter: I) -> Self {
        let mut map = Map::new();
        for (k, v) in iter {
            map.insert(k, v);
        }
        map
    }
}

impl fmt::Display for Value {
    /// CBOR diagnostic notation (RFC 8949 §8), restricted to the profile's
    /// data model. KAT accept vectors pin this rendering via their `diag`
    /// field.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsigned(n) => write!(f, "{n}"),
            Self::Negative(n) => write!(f, "{}", -1 - i128::from(*n)),
            Self::Bytes(b) => {
                write!(f, "h'")?;
                for byte in b {
                    write!(f, "{byte:02x}")?;
                }
                write!(f, "'")
            }
            Self::Text(t) => write_diag_text(f, t),
            Self::Array(items) => {
                write!(f, "[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{item}")?;
                }
                write!(f, "]")
            }
            Self::Map(map) => {
                write!(f, "{{")?;
                for (i, (k, v)) in map.entries().iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write_diag_text(f, k)?;
                    write!(f, ": {v}")?;
                }
                write!(f, "}}")
            }
            Self::Bool(true) => write!(f, "true"),
            Self::Bool(false) => write!(f, "false"),
            Self::Null => write!(f, "null"),
        }
    }
}

fn write_diag_text(f: &mut fmt::Formatter<'_>, s: &str) -> fmt::Result {
    write!(f, "\"")?;
    for c in s.chars() {
        match c {
            '"' => write!(f, "\\\"")?,
            '\\' => write!(f, "\\\\")?,
            '\n' => write!(f, "\\n")?,
            '\r' => write!(f, "\\r")?,
            '\t' => write!(f, "\\t")?,
            c if (c as u32) < 0x20 => write!(f, "\\u{:04x}", c as u32)?,
            c => write!(f, "{c}")?,
        }
    }
    write!(f, "\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The (len, bytes) shortcut must agree with RFC 8949's bytewise
    /// comparison of encoded keys across every header-size class.
    #[test]
    fn canonical_key_cmp_matches_encoded_bytewise_order() {
        let keys = [
            String::new(),
            "a".to_string(),
            "b".to_string(),
            "a".repeat(23),
            "a".repeat(24),
            "z".repeat(24),
            "a".repeat(255),
            "a".repeat(256),
            "a".repeat(65535),
            "a".repeat(65536),
        ];
        for x in &keys {
            for y in &keys {
                let enc_x = crate::codec::encode(&Value::Text(x.clone()));
                let enc_y = crate::codec::encode(&Value::Text(y.clone()));
                assert_eq!(
                    canonical_key_cmp(x, y),
                    enc_x.cmp(&enc_y),
                    "diverged on lens {} vs {}",
                    x.len(),
                    y.len()
                );
            }
        }
    }

    #[test]
    fn map_insert_keeps_canonical_order_and_replaces() {
        let mut m = Map::new();
        m.insert("bb", Value::Unsigned(1));
        m.insert("a", Value::Unsigned(2));
        m.insert("ca", Value::Unsigned(3));
        m.insert("bb", Value::Unsigned(9));
        let keys: Vec<&str> = m.entries().iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["a", "bb", "ca"]);
        assert_eq!(m.get("bb"), Some(&Value::Unsigned(9)));
    }

    #[test]
    fn i64_round_trip() {
        for n in [i64::MIN, -1, 0, 1, i64::MAX] {
            assert_eq!(Value::from_i64(n).as_i64().unwrap(), n);
        }
        assert!(Value::Negative(u64::MAX).as_i64().is_err());
        assert_eq!(
            Value::Negative(u64::MAX).to_string(),
            "-18446744073709551616"
        );
    }
}
