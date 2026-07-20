//! The deterministic CBOR profile (blueprint/core.md "Wire format").
//!
//! One strictness policy, everywhere: encoders emit RFC 8949 §4.2.1
//! deterministic form only, and [`decode`] accepts exactly that form —
//! duplicate map keys, non-canonical integer/length encodings, indefinite
//! lengths, tags, floats, and non-text map keys all reject fail-closed with
//! the named check that fired. The single tolerance is unknown fields, via
//! [`decode_map_partial`] / [`encode_map_partial`].
//!
//! The profile is a strict subset of DAG-CBOR, so every encoding this module
//! emits is a valid DAG-CBOR block. (With text-only map keys, RFC 8949's
//! bytewise key order and DAG-CBOR's length-first order coincide — pinned by
//! test.) Envelope, body, and structure schema codecs build on this module in
//! later slices; nothing outside it touches raw CBOR.

mod decode;
mod encode;
mod fields;
mod value;

pub use decode::decode;
pub use encode::encode;
pub use fields::{UnknownFields, decode_map_partial, encode_map_partial, known_key_set};
pub use value::{Map, Value, canonical_key_cmp};

/// Maximum nesting depth the decoder admits. A profile constant: deeper input
/// rejects as `depth-exceeded` (fail-closed, and bounds recursion).
pub const MAX_DEPTH: usize = 128;
