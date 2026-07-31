//! Property layer over the det-CBOR codec (blueprint/testing.md
//! "crates/core — KATs and property tests"): encode∘decode identity
//! including the unknown-field byte-stable round-trip, canonicality
//! rejection via the defect encoder in `common`, and the strict key
//! comparator's total-order laws. Case counts are bounded for CI speed;
//! failing seeds persist as regression vectors natively (persistence is
//! off under wasm, where the source tree may not be writable).

mod common;

// The browser-shaped KAT leg (wasm32-unknown-unknown) has no libtest harness;
// shadowing `test` routes the proptest-generated `#[test]` cases through
// wasm-bindgen-test-runner, exercising getrandom's `crypto.getRandomValues`
// backend (the getrandom parity surface). Native and wasm32-wasip1 are
// untouched.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test as test;

use core::cmp::Ordering;
use std::collections::HashMap;

use cipherbox_core::codec::{
    Map, Value, canonical_key_cmp, decode, decode_map_partial, encode, encode_map_partial,
    encoded_len,
};
use proptest::prelude::*;

#[cfg(not(target_family = "wasm"))]
fn config() -> ProptestConfig {
    ProptestConfig::default()
}

#[cfg(target_family = "wasm")]
fn config() -> ProptestConfig {
    ProptestConfig {
        // Bounded hard for the wasm32-wasip1 CI lane.
        cases: 16,
        // Writing regression files may not work under wasm.
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

/// Bounded text including non-ASCII: `\PC` is any non-control char.
fn arb_text() -> impl Strategy<Value = String> {
    prop::string::string_regex("\\PC{0,12}").expect("valid regex")
}

/// Map keys: shorter, still non-ASCII-capable.
fn arb_key() -> impl Strategy<Value = String> {
    prop::string::string_regex("\\PC{0,6}").expect("valid regex")
}

/// The full profile data model, depth ≤ 4 and breadth ≤ 5 (CI-bounded).
/// Maps are built through `Map`'s inserting collector, which dedups and
/// canonically orders keys by construction.
fn arb_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        any::<u64>().prop_map(Value::Unsigned),
        any::<u64>().prop_map(Value::Negative),
        prop::collection::vec(any::<u8>(), 0..24).prop_map(Value::Bytes),
        arb_text().prop_map(Value::Text),
        any::<bool>().prop_map(Value::Bool),
        Just(Value::Null),
    ];
    leaf.prop_recursive(4, 24, 5, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..=5).prop_map(Value::Array),
            prop::collection::vec((arb_key(), inner), 0..=5)
                .prop_map(|kvs| Value::Map(kvs.into_iter().collect())),
        ]
    })
}

/// Map entries plus a per-key known/unknown flag (later duplicates win on
/// both sides, mirroring `Map::insert`), so `decode_map_partial` sees a
/// well-defined `is_known` and both sides of the split get exercised.
type FlaggedEntries = Vec<(String, Value, bool)>;

fn arb_flagged_entries(min: usize) -> impl Strategy<Value = FlaggedEntries> {
    prop::collection::vec((arb_key(), arb_value(), any::<bool>()), min..=6)
}

fn build_map_and_flags(entries: &FlaggedEntries) -> (Map, HashMap<String, bool>) {
    let mut map = Map::new();
    let mut flags = HashMap::new();
    for (k, v, known) in entries {
        map.insert(k.clone(), v.clone());
        flags.insert(k.clone(), *known);
    }
    (map, flags)
}

proptest! {
    #![proptest_config(config())]

    /// (a) decode is a left inverse of encode, and re-encoding the decode
    /// is byte-identical (canonical form is a fixed point).
    #[test]
    fn round_trip(v in arb_value()) {
        let bytes = encode(&v).unwrap();
        let decoded = decode(&bytes).expect("own encoding must decode");
        prop_assert_eq!(&decoded, &v);
        prop_assert_eq!(encode(&decoded).unwrap(), bytes);
    }

    /// (b) unknown-field tolerance is byte-stable: split a map into known
    /// and unknown by an arbitrary per-key assignment, re-emit unmodified,
    /// and the bytes are identical to the direct encoding.
    #[test]
    fn unknown_field_round_trip(entries in arb_flagged_entries(0)) {
        let (map, flags) = build_map_and_flags(&entries);
        let bytes = encode(&Value::Map(map.clone())).unwrap();
        let (known, unknown) =
            decode_map_partial(&bytes, |k| flags.get(k).copied().unwrap_or(false))
                .expect("canonical map must decode");
        prop_assert_eq!(known.len() + unknown.len(), map.len());
        for (k, _) in known.entries() {
            prop_assert!(flags[k], "known side holds an unknown key {:?}", k);
        }
        for (k, _) in unknown.entries() {
            prop_assert!(!flags[k], "unknown side holds a known key {:?}", k);
        }
        let reencoded = encode_map_partial(&known, &unknown).expect("no collisions by construction");
        // The merged sizing pass is exact, so the write never reallocates.
        prop_assert_eq!(reencoded.capacity(), reencoded.len());
        prop_assert_eq!(reencoded, bytes);
    }

    /// (c) a rewrite through the partial codec re-encodes canonically:
    /// replacing one known field's value yields exactly the bytes of the
    /// fully-modified map encoded directly.
    #[test]
    fn rewrite_reencodes_canonically(
        entries in arb_flagged_entries(1),
        idx in any::<prop::sample::Index>(),
        replacement in arb_value(),
    ) {
        let target_key = entries[idx.index(entries.len())].0.clone();
        let (map, mut flags) = build_map_and_flags(&entries);
        // The rewritten key must be on the known side.
        flags.insert(target_key.clone(), true);

        let bytes = encode(&Value::Map(map.clone())).unwrap();
        let (mut known, unknown) =
            decode_map_partial(&bytes, |k| flags.get(k).copied().unwrap_or(false))
                .expect("canonical map must decode");
        known.insert(target_key.clone(), replacement.clone());
        let rewritten = encode_map_partial(&known, &unknown).expect("no collisions by construction");

        let mut full = map;
        full.insert(target_key, replacement);
        prop_assert_eq!(rewritten, encode(&Value::Map(full)).unwrap());
    }

    /// (d) every single-defect mutation of a canonical encoding rejects
    /// with exactly the named check, whatever the payload.
    #[test]
    fn canonicality_rejection(
        v in arb_value(),
        v2 in arb_value(),
        k1 in arb_key(),
        k2 in arb_key(),
    ) {
        prop_assume!(k1 != k2);
        let (lo, hi) = match canonical_key_cmp(&k1, &k2) {
            Ordering::Less => (&k1, &k2),
            _ => (&k2, &k1),
        };
        let cases = [
            common::widen_head(&v),
            common::widen_length(&v),
            common::indefinite_array(&v),
            common::swap_map_keys(lo, hi, &v, &v2),
            common::duplicate_key(&k1, &v, &v2),
            common::wrap_tag(&v),
            common::inject_float(&v),
            common::trailing_junk(&v),
            common::truncate(&v),
        ];
        for (bytes, expected) in cases {
            match decode(&bytes) {
                Ok(value) => prop_assert!(
                    false,
                    "defect {} was accepted as {} (bytes {:02x?})",
                    expected, value, bytes
                ),
                Err(err) => prop_assert_eq!(
                    err.check(),
                    expected,
                    "wrong check for defect bytes {:02x?}",
                    bytes
                ),
            }
        }
    }

    /// (f) the two-pass encoder's length oracle is exact for every value:
    /// `encoded_len` equals the emitted byte count, so `encode`'s single
    /// up-front reservation never reallocates mid-write — no intermediate
    /// backing store is freed un-zeroized to strand secret bytes.
    #[test]
    fn encoded_len_matches_emitted_bytes(v in arb_value()) {
        prop_assert_eq!(encoded_len(&v).unwrap(), encode(&v).unwrap().len());
    }

    /// (e) `canonical_key_cmp` is a total order that agrees with bytewise
    /// comparison of the encoded keys — the strict-comparator groundwork
    /// (idempotence, antisymmetry, transitivity, platform stability).
    #[test]
    fn map_key_order_is_total_and_platform_stable(
        a in arb_key(),
        b in arb_key(),
        c in arb_key(),
    ) {
        // Idempotence / reflexivity.
        prop_assert_eq!(canonical_key_cmp(&a, &a), Ordering::Equal);
        // Antisymmetry.
        prop_assert_eq!(canonical_key_cmp(&a, &b), canonical_key_cmp(&b, &a).reverse());
        // Equality is identity: no two distinct keys compare Equal.
        if canonical_key_cmp(&a, &b) == Ordering::Equal {
            prop_assert_eq!(&a, &b);
        }
        // Transitivity of ≤.
        if canonical_key_cmp(&a, &b) != Ordering::Greater
            && canonical_key_cmp(&b, &c) != Ordering::Greater
        {
            prop_assert!(canonical_key_cmp(&a, &c) != Ordering::Greater);
        }
        // Platform stability: the (len, bytes) shortcut equals RFC 8949's
        // bytewise-lexicographic order over the full encoded key items.
        prop_assert_eq!(
            canonical_key_cmp(&a, &b),
            encode(&Value::Text(a.clone())).unwrap().cmp(&encode(&Value::Text(b.clone())).unwrap())
        );
    }
}
