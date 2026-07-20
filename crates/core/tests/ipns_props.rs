//! Property layer over the IPNS name codec (blueprint/testing.md "crates/core
//! — KATs and property tests", ticket #622): the base36 CIDv1 libp2p-key
//! encode∘decode round-trip over arbitrary Ed25519 keys, and strict-decode
//! totality (parse never panics and only ever accepts the one canonical form).
//! Case counts are bounded for CI speed; the same suite runs under
//! wasm32-unknown-unknown (the getrandom parity surface).

// The browser-shaped KAT leg (wasm32-unknown-unknown) has no libtest harness;
// shadowing `test` routes the proptest-generated `#[test]` cases through
// wasm-bindgen-test-runner, exercising getrandom's `crypto.getRandomValues`
// backend. Native and wasm32-wasip1 are untouched.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test as test;

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use proptest::prelude::*;

#[cfg(not(target_family = "wasm"))]
fn config() -> ProptestConfig {
    ProptestConfig::default()
}

#[cfg(target_family = "wasm")]
fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 16,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

/// Input for the totality property. Two shapes, so the strict decoder is driven
/// both deep and wide: plausible names (an optional `k` multibase prefix over
/// base36 characters, sometimes past the canonical length so the length guard
/// fires), and genuinely arbitrary strings — Unicode, uppercase, punctuation,
/// whitespace and newlines (`(?s)`), and lengths well beyond a real name.
fn arb_name_like() -> impl Strategy<Value = String> {
    prop_oneof![
        prop::string::string_regex("k?[0-9a-z]{0,90}").expect("valid regex"),
        prop::string::string_regex("(?s).{0,120}").expect("valid regex"),
    ]
}

proptest! {
    #![proptest_config(config())]

    /// (a) encode∘decode is the identity on keys: every Ed25519 key's canonical
    /// name parses back to the same key, and the text is byte-stable.
    #[test]
    fn name_round_trip(seed in proptest::array::uniform32(any::<u8>())) {
        let key = Ed25519Signer::from_seed(seed).verifying_key();
        let name = IpnsName::from_public_key(&key);
        let parsed = IpnsName::parse(name.as_str()).expect("own name must parse");
        prop_assert_eq!(parsed.public_key(), key, "pubkey comes from the name");
        prop_assert_eq!(parsed.as_str(), name.as_str(), "byte-stable text");
    }

    /// (b) strict decode is total and canonical: parse never panics on arbitrary
    /// input, and any name it accepts is exactly the canonical string (idempotent
    /// re-parse to the same key) — the fail-closed strictness the name wave and
    /// the verify chain depend on.
    #[test]
    fn parse_is_total_and_canonical(s in arb_name_like()) {
        if let Ok(name) = IpnsName::parse(&s) {
            prop_assert_eq!(name.as_str(), s.as_str(), "an accepted name is canonical");
            let reparsed = IpnsName::parse(name.as_str()).expect("canonical name re-parses");
            prop_assert_eq!(reparsed.public_key(), name.public_key());
        }
    }
}
