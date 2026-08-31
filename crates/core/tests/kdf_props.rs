//! Property layer over the KDF edge catalog (blueprint/testing.md
//! "crates/core — KATs and property tests"): the mechanical separation law
//! under arbitrary inputs — no two edges ever produce equal
//! output for equal inputs — plus per-edge determinism. Case counts are bounded
//! for CI speed; failing seeds persist natively but not under wasm, where the
//! source tree may be read-only (mirrors tests/codec_props.rs).

use std::collections::BTreeSet;

use cipherbox_core::kdf::{EDGES, EdgeProbe, edge_probe_outputs};
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

proptest! {
    #![proptest_config(config())]

    /// Whatever the inputs — even with every seed/id slot filled from the same
    /// bytes — the whole edge table is pairwise separated. The `cipherbox/v2`
    /// context strings alone guarantee it, so a collision is a domain-separation
    /// failure, not an input coincidence.
    #[test]
    fn edges_are_pairwise_separated(
        seed in any::<[u8; 32]>(),
        id in any::<[u8; 16]>(),
        struct_tag in any::<u8>(),
        index in any::<u64>(),
        ipns_name in prop::collection::vec(any::<u8>(), 0..40),
        identity_pk in any::<[u8; 33]>(),
    ) {
        let probe = EdgeProbe {
            seed: &seed,
            id: &id,
            struct_tag,
            index,
            ipns_name: &ipns_name,
            identity_pk: &identity_pk,
        };
        let out = edge_probe_outputs(&probe);
        prop_assert_eq!(out.len(), EDGES.len());
        let distinct: BTreeSet<[u8; 32]> = out.iter().map(|o| o.output).collect();
        prop_assert_eq!(
            distinct.len(),
            EDGES.len(),
            "two edges collided for inputs seed={:02x?} id={:02x?}",
            seed,
            id
        );
    }

    /// Every edge is a deterministic function of its inputs.
    #[test]
    fn edges_are_deterministic(
        seed in any::<[u8; 32]>(),
        id in any::<[u8; 16]>(),
        struct_tag in any::<u8>(),
        index in any::<u64>(),
        ipns_name in prop::collection::vec(any::<u8>(), 0..40),
        identity_pk in any::<[u8; 33]>(),
    ) {
        let probe = EdgeProbe {
            seed: &seed,
            id: &id,
            struct_tag,
            index,
            ipns_name: &ipns_name,
            identity_pk: &identity_pk,
        };
        prop_assert_eq!(edge_probe_outputs(&probe), edge_probe_outputs(&probe));
    }
}
