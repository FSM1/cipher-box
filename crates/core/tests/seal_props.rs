//! Property layer over the seal module (blueprint/testing.md "crates/core —
//! KATs and property tests": envelope round-trip and the strict name
//! comparator).
//!
//! Covers: read-body and envelope encode∘decode identity (byte-stable), the
//! full symmetric seal∘open round-trip, the adversarial property that any AAD
//! transplant fails the tag fail-closed, and the strict `name_cmp` total-order
//! laws (idempotence, antisymmetry, transitivity, platform agreement). Case
//! counts are bounded for CI speed; failing seeds persist natively (persistence
//! is off under wasm, where the source tree may not be writable).

// The browser-shaped KAT leg (wasm32-unknown-unknown) has no libtest harness;
// shadowing `test` routes the proptest-generated `#[test]` cases through
// wasm-bindgen-test-runner, exercising getrandom's `crypto.getRandomValues`
// backend. Native and wasm32-wasip1 are untouched.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test as test;

use core::cmp::Ordering;
use std::collections::BTreeSet;

use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid, open_chunk, seal_chunk, verify_cid};
use cipherbox_core::seal::{
    AadContext, ChildRef, NodeKind, ReadBody, STRUCT_TAG_READ_BODY, Version, decode_envelope,
    decode_read_body, encode_envelope, encode_read_body, name_cmp, open_read_body, seal,
    seal_read_body, unseal,
};
use proptest::prelude::*;

#[cfg(not(target_family = "wasm"))]
fn config() -> ProptestConfig {
    ProptestConfig::default()
}

#[cfg(target_family = "wasm")]
fn config() -> ProptestConfig {
    ProptestConfig {
        // Bounded hard for the wasm CI lanes.
        cases: 16,
        // Writing regression files may not work under wasm.
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

fn arb_text() -> impl Strategy<Value = String> {
    prop::string::string_regex("\\PC{0,10}").expect("valid regex")
}

fn arb_kind() -> impl Strategy<Value = NodeKind> {
    prop_oneof![Just(NodeKind::Folder), Just(NodeKind::File)]
}

fn arb_child() -> impl Strategy<Value = ChildRef> {
    (
        prop::array::uniform16(any::<u8>()),
        arb_text(),
        prop::collection::vec(any::<u8>(), 0..12),
        arb_kind(),
        any::<u64>(),
    )
        .prop_map(|(id, name, ipns_name, kind, link_counter)| ChildRef {
            id,
            name,
            ipns_name,
            kind,
            link_counter,
            unknown: Vec::new(),
        })
}

fn arb_version() -> impl Strategy<Value = Version> {
    (
        prop::collection::vec(any::<u8>(), 0..12),
        prop::array::uniform32(any::<u8>()),
        any::<u64>(),
        any::<u64>(),
    )
        .prop_map(|(cid, key, size, modified_at)| Version::new(cid, key, size, modified_at))
}

/// Keep only children with pairwise-distinct ids and pairwise-distinct
/// ipnsNames, so the folder always satisfies the decode-time uniqueness law.
fn dedup_children(children: Vec<ChildRef>) -> Vec<ChildRef> {
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    children
        .into_iter()
        .filter(|c| {
            let id_new = ids.insert(c.id);
            let name_new = names.insert(c.ipns_name.clone());
            id_new && name_new
        })
        .collect()
}

fn arb_read_body() -> impl Strategy<Value = ReadBody> {
    let folder = (
        any::<u64>(),
        any::<u64>(),
        prop::collection::vec(arb_child(), 0..=6),
    )
        .prop_map(|(created_at, modified_at, children)| ReadBody::Folder {
            created_at,
            modified_at,
            children: dedup_children(children),
            unknown: Vec::new(),
        });
    let file = (
        any::<u64>(),
        any::<u64>(),
        prop::collection::vec(arb_version(), 0..=6),
    )
        .prop_map(|(created_at, modified_at, versions)| ReadBody::File {
            created_at,
            modified_at,
            versions,
            unknown: Vec::new(),
        });
    prop_oneof![folder, file]
}

fn arb_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..20)
}

proptest! {
    #![proptest_config(config())]

    /// (a) the read-body codec is a byte-stable round-trip: decode is a left
    /// inverse of encode, and re-encoding the decode is byte-identical.
    #[test]
    fn read_body_round_trip(body in arb_read_body()) {
        let bytes = encode_read_body(&body);
        let decoded = decode_read_body(&bytes).expect("own encoding must decode");
        prop_assert_eq!(&decoded, &body);
        prop_assert_eq!(encode_read_body(&decoded), bytes);
    }

    /// (b) the envelope codec round-trips byte-stable, and the sealed read-body
    /// opens back to the original under the sealing key (the full symmetric
    /// seal∘open path).
    #[test]
    fn envelope_seal_open_round_trip(
        body in arb_read_body(),
        key in prop::array::uniform32(any::<u8>()),
        nonce in prop::array::uniform24(any::<u8>()),
        v in any::<u64>(),
        id in prop::array::uniform16(any::<u8>()),
        scope in prop::array::uniform16(any::<u8>()),
        epoch in any::<u64>(),
    ) {
        // `arb_read_body` only yields uniqueness-valid folders, so the seal
        // never rejects.
        let env = seal_read_body(&key, &nonce, v, id, scope, epoch, &body)
            .expect("a valid read-body must seal");
        // Envelope codec identity + byte stability.
        let bytes = encode_envelope(&env);
        let decoded = decode_envelope(&bytes).expect("own envelope must decode");
        prop_assert_eq!(&decoded, &env);
        prop_assert_eq!(encode_envelope(&decoded), bytes);
        // The read-body opens back to the original.
        let opened = open_read_body(&decoded, &key).expect("must open under the sealing key");
        prop_assert_eq!(opened, body);
    }

    /// (c) any AAD transplant fails the tag fail-closed: sealing under one
    /// context and opening under a context that differs in any single bound
    /// field (`v` downgrade included) rejects as `seal-open-failed`.
    #[test]
    fn aad_transplant_always_fails_closed(
        key in prop::array::uniform32(any::<u8>()),
        nonce in prop::array::uniform24(any::<u8>()),
        plaintext in arb_bytes(),
        v in 1u64..u64::MAX,
        id in prop::array::uniform16(any::<u8>()),
        scope in prop::array::uniform16(any::<u8>()),
        epoch in any::<u64>(),
        which in 0usize..5,
    ) {
        let base = AadContext { v, id, scope, epoch, struct_tag: STRUCT_TAG_READ_BODY };
        let sealed = seal(&key, &nonce, &base, &plaintext);
        prop_assert_eq!(unseal(&key, &base, &sealed).unwrap(), plaintext);

        // Flip exactly one bound field; every flip is a real change.
        let mut bad = base;
        match which {
            0 => bad.v -= 1,               // downgrade
            1 => bad.id[0] ^= 0x01,
            2 => bad.scope[0] ^= 0x01,
            3 => bad.epoch ^= 0x01,
            _ => bad.struct_tag ^= 0x01,
        }
        let err = unseal(&key, &bad, &sealed).expect_err("transplant must fail closed");
        prop_assert_eq!(err.check(), "seal-open-failed");
    }

    /// (c2) the content-seal round-trips and its content CID is a deterministic
    /// 36-byte CIDv1 that verify accepts; tampering any sealed byte breaks the
    /// content address fail-closed (ticket #691). Runs under the wasm32
    /// harness too, so the CID is byte-identical across targets.
    #[test]
    fn content_seal_and_cid_round_trip(
        key in prop::array::uniform32(any::<u8>()),
        nonce in prop::array::uniform24(any::<u8>()),
        plaintext in arb_bytes(),
    ) {
        let sealed = seal_chunk(&key, &nonce, &plaintext);
        prop_assert_eq!(&sealed[..24], &nonce);
        prop_assert_eq!(open_chunk(&key, &sealed).unwrap(), plaintext);

        let cid = compute_cid(CONTENT_CID_CODEC, &sealed);
        prop_assert_eq!(cid.len(), 36);
        prop_assert_eq!(compute_cid(CONTENT_CID_CODEC, &sealed), cid.clone());
        prop_assert!(verify_cid(&cid, &sealed).is_ok());

        // Flipping any sealed byte changes the content address → fail-closed.
        let mut tampered = sealed.clone();
        tampered[0] ^= 0x01;
        prop_assert_eq!(
            verify_cid(&cid, &tampered).unwrap_err().check(),
            "content-cid-mismatch"
        );
    }

    /// (d) the strict name comparator is a total order that agrees with bytewise
    /// comparison of the raw name bytes — the strict-name-comparator groundwork
    /// (idempotence, antisymmetry, transitivity, platform stability).
    #[test]
    fn name_cmp_is_total_and_platform_stable(
        a in arb_bytes(),
        b in arb_bytes(),
        c in arb_bytes(),
    ) {
        // Idempotence / reflexivity.
        prop_assert_eq!(name_cmp(&a, &a), Ordering::Equal);
        // Antisymmetry.
        prop_assert_eq!(name_cmp(&a, &b), name_cmp(&b, &a).reverse());
        // Equality is identity: no two distinct names compare Equal.
        if name_cmp(&a, &b) == Ordering::Equal {
            prop_assert_eq!(&a, &b);
        }
        // Transitivity of ≤.
        if name_cmp(&a, &b) != Ordering::Greater && name_cmp(&b, &c) != Ordering::Greater {
            prop_assert!(name_cmp(&a, &c) != Ordering::Greater);
        }
        // Platform stability: it is exactly bytewise `Ord`, deterministic across
        // native and WASM.
        prop_assert_eq!(name_cmp(&a, &b), a.cmp(&b));
    }
}
