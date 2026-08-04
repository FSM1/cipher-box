//! The det-CBOR data model.
//!
//! The profile is a strict subset of DAG-CBOR: definite lengths only,
//! text-string map keys only, no tags, no floats, no simple values beyond
//! `false`/`true`/`null`. Integers cover the full CBOR range (major 0/1);
//! [`Value::Negative(n)`] represents `-1 - n`.

use core::cmp::Ordering;
use core::fmt;

use zeroize::Zeroize;

use super::redact::{RedactedBytes, RedactedText};
use crate::error::{CodecError, DisplayKey, Malformed};

/// A value in the deterministic profile's data model.
#[derive(Clone, PartialEq, Eq)]
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

    /// Scrub every owned byte and text buffer in this value tree in place: each
    /// [`Value::Bytes`] and each [`Value::Text`] is wiped from memory and cleared
    /// to empty (`Vec`/`String` `zeroize` semantics), while the tree's shape and
    /// every other value are left intact.
    ///
    /// The codec builds and owns the transient `Value` tree of a sealed-body
    /// encode/decode, which carries verbatim copies of secret material — inline
    /// content-key bytes ([`encode_read_body`]) and scope seed bytes — so the
    /// codec is that tree's terminal owner and wipes it before it drops
    /// (blueprint/core.md "Crypto suite": key material lives only in zeroizing
    /// owners). Non-secret buffers are wiped too — every buffer here is a
    /// transient copy, so a whole-tree wipe needs no per-field secret
    /// classification and stays correct as later bodies add secret fields; text
    /// included, since a filename is user-private metadata in a ZK system.
    ///
    /// [`encode_read_body`]: crate::seal::encode_read_body
    pub fn zeroize_bytes(&mut self) {
        match self {
            Self::Bytes(b) => b.zeroize(),
            Self::Text(s) => s.zeroize(),
            Self::Array(items) => {
                for item in items {
                    item.zeroize_bytes();
                }
            }
            Self::Map(map) => map.zeroize_bytes(),
            Self::Unsigned(_) | Self::Negative(_) | Self::Bool(_) | Self::Null => {}
        }
    }

    /// CBOR diagnostic notation (RFC 8949 §8), restricted to the profile's data
    /// model. KAT accept vectors pin this rendering via their `diag` field.
    ///
    /// Deliberately not a [`fmt::Display`] impl — a verbatim rendering has to be
    /// asked for by name. The returned `String` carries whatever the tree does,
    /// so a caller rendering secret-bearing input owns wiping it.
    pub fn to_diag(&self) -> String {
        Diag(self).to_string()
    }
}

/// A decoded tree is sealed-body plaintext, so it renders shape and lengths
/// only; [`Value::to_diag`] is the deliberate full rendering.
impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsigned(n) => f.debug_tuple("Unsigned").field(n).finish(),
            Self::Negative(n) => f.debug_tuple("Negative").field(n).finish(),
            Self::Bytes(b) => f.debug_tuple("Bytes").field(&RedactedBytes::of(b)).finish(),
            Self::Text(t) => f.debug_tuple("Text").field(&RedactedText::of(t)).finish(),
            Self::Array(items) => f.debug_tuple("Array").field(items).finish(),
            Self::Map(map) => f.debug_tuple("Map").field(map).finish(),
            Self::Bool(b) => f.debug_tuple("Bool").field(b).finish(),
            Self::Null => f.write_str("Null"),
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
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Map {
    entries: Vec<(String, Value)>,
    wiped: bool,
}

/// Keys are field names, so they render — bounded the way the error surface
/// bounds writer-controlled keys; the values redact themselves.
impl fmt::Debug for Map {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut m = f.debug_map();
        for (key, value) in &self.entries {
            m.key(&DisplayKey(key)).value(value);
        }
        m.finish()
    }
}

impl Map {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace, keeping canonical order. A replaced value is wiped
    /// rather than handed back: the map is its terminal owner unless a caller
    /// takes ownership, which is what [`Map::remove`] is for.
    pub fn insert(&mut self, key: impl Into<String>, value: Value) {
        let key = key.into();
        match self
            .entries
            .binary_search_by(|(k, _)| canonical_key_cmp(k, &key))
        {
            Ok(i) => core::mem::replace(&mut self.entries[i].1, value).zeroize_bytes(),
            Err(i) => self.entries.insert(i, (key, value)),
        }
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries
            .binary_search_by(|(k, _)| canonical_key_cmp(k, key))
            .ok()
            .map(|i| &self.entries[i].1)
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        self.entries
            .binary_search_by(|(k, _)| canonical_key_cmp(k, key))
            .ok()
            .map(|i| &mut self.entries[i].1)
    }

    /// Take an entry out, transferring its buffers: the caller becomes their
    /// terminal owner. The way to get at a value [`Map::insert`] would wipe.
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

    /// Zeroize every entry value's owned byte buffers in place (keys are text,
    /// never secret). The wipe for a caller holding decoded known fields — see
    /// [`Value::zeroize_bytes`].
    ///
    /// Terminal: the map is marked wiped and every encoder then refuses it.
    /// Without that mark a wiped map still encodes — fixed-length fields fail
    /// their schema decode afterwards, but variable-length ones round-trip
    /// empty, which is silent data loss. The mark rides the map, not its
    /// values, so a value lifted back out through [`Map::remove`] carries none.
    pub fn zeroize_bytes(&mut self) {
        for (_, v) in &mut self.entries {
            v.zeroize_bytes();
        }
        self.wiped = true;
    }

    /// The encoders' read of that mark, release-active on both passes.
    pub(crate) fn reject_if_wiped(&self) -> Result<(), CodecError> {
        if self.wiped {
            return Err(Malformed::WipedMap.into());
        }
        Ok(())
    }
}

impl FromIterator<(String, Value)> for Map {
    /// Later duplicates replace earlier ones; the replaced value is wiped.
    fn from_iter<I: IntoIterator<Item = (String, Value)>>(iter: I) -> Self {
        let mut map = Map::new();
        for (k, v) in iter {
            map.insert(k, v);
        }
        map
    }
}

/// The diagnostic-notation renderer behind [`Value::to_diag`].
struct Diag<'a>(&'a Value);

impl fmt::Display for Diag<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Value::Unsigned(n) => write!(f, "{n}"),
            Value::Negative(n) => write!(f, "{}", -1 - i128::from(*n)),
            Value::Bytes(b) => {
                write!(f, "h'")?;
                for byte in b {
                    write!(f, "{byte:02x}")?;
                }
                write!(f, "'")
            }
            Value::Text(t) => write_diag_text(f, t),
            Value::Array(items) => {
                write!(f, "[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", Diag(item))?;
                }
                write!(f, "]")
            }
            Value::Map(map) => {
                write!(f, "{{")?;
                for (i, (k, v)) in map.entries().iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write_diag_text(f, k)?;
                    write!(f, ": {}", Diag(v))?;
                }
                write!(f, "}}")
            }
            Value::Bool(true) => write!(f, "true"),
            Value::Bool(false) => write!(f, "false"),
            Value::Null => write!(f, "null"),
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
                let enc_x = crate::codec::encode(&Value::Text(x.clone())).unwrap();
                let enc_y = crate::codec::encode(&Value::Text(y.clone())).unwrap();
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
    fn zeroize_bytes_wipes_every_nested_byte_buffer() {
        // Shaped like the sealed-body encode tree: nested maps carrying a
        // secret `Bytes` alongside non-byte fields.
        let mut version = Map::new();
        version.insert("contentKey", Value::Bytes(vec![0xab; SECRET_LEN_TEST]));
        version.insert("size", Value::Unsigned(4096));
        version.insert("contentCid", Value::Bytes(vec![0xcd; 5]));

        let mut root = Map::new();
        root.insert("versions", Value::Array(vec![Value::Map(version)]));
        root.insert("kind", Value::Text("file".into()));
        root.insert("id", Value::Bytes(vec![0xef; 16]));
        let mut tree = Value::Map(root);

        tree.zeroize_bytes();

        // Buffers scrubbed and cleared to empty; the tree keeps its shape and
        // every non-byte, non-text value is untouched.
        let root = tree.as_map().unwrap();
        assert_eq!(root.get("id"), Some(&Value::Bytes(Vec::new())));
        assert_eq!(root.get("kind"), Some(&Value::Text(String::new())));
        let versions = root.get("versions").unwrap().as_array().unwrap();
        let ver = versions[0].as_map().unwrap();
        assert_eq!(
            ver.get("contentKey"),
            Some(&Value::Bytes(Vec::new())),
            "content key buffer scrubbed and cleared"
        );
        assert_eq!(ver.get("contentCid"), Some(&Value::Bytes(Vec::new())));
        assert_eq!(ver.get("size"), Some(&Value::Unsigned(4096)));
    }

    const SECRET_LEN_TEST: usize = 32;

    #[test]
    fn i64_round_trip() {
        for n in [i64::MIN, -1, 0, 1, i64::MAX] {
            assert_eq!(Value::from_i64(n).as_i64().unwrap(), n);
        }
        assert!(Value::Negative(u64::MAX).as_i64().is_err());
        assert_eq!(Value::Negative(u64::MAX).to_diag(), "-18446744073709551616");
    }

    /// The rule-2 property: no `{:?}` of a decoded tree can carry the bytes or
    /// the text it decoded, however deeply they are nested.
    #[test]
    fn debug_redacts_every_buffer_but_keeps_shape() {
        let mut version = Map::new();
        version.insert("contentKey", Value::Bytes(vec![0xab; SECRET_LEN_TEST]));
        version.insert("size", Value::Unsigned(4096));
        let mut root = Map::new();
        root.insert("versions", Value::Array(vec![Value::Map(version)]));
        root.insert("name", Value::Text("tax-return-2026.pdf".into()));
        let rendered = format!("{:?}", Value::Map(root));

        assert!(!rendered.contains("171"), "no byte values: {rendered}");
        assert!(!rendered.contains("ab"), "no hex either: {rendered}");
        assert!(!rendered.contains("tax-return"), "no text: {rendered}");
        assert!(rendered.contains("<32 bytes redacted>"), "{rendered}");
        assert!(rendered.contains("<19 chars redacted>"), "{rendered}");
        assert!(
            rendered.contains("\"contentKey\"") && rendered.contains("4096"),
            "field names and scalars survive: {rendered}"
        );
    }

    /// The diagnostic rendering is the deliberate full one, and it is reachable
    /// only by name.
    #[test]
    fn to_diag_renders_verbatim() {
        let mut m = Map::new();
        m.insert("k", Value::Bytes(vec![0xab, 0xcd]));
        assert_eq!(Value::Map(m).to_diag(), "{\"k\": h'abcd'}");
    }
}
