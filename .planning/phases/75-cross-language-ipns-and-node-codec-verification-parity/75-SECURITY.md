---
phase: 75
name: Cross-Language IPNS and Node-Codec Verification Parity
status: SECURED
date: 2026-07-11
reviews:
  - .planning/security/REVIEW-2026-07-11-phase75-parity.md
---

# Phase 75 Security Review

## Threat model

Phase 75 is verification-**hardening**: it tightens the fail-closed reject domain
for IPNS records (RFC3339 Validity, `ValidityType`), locks the node-codec
`fileIv` encoding to base64, and canonicalizes UUID acceptance. It adds **no new
attack surface** — no new endpoints, keys, data flows, or persisted material.

The relevant threat class is a **cross-language verdict divergence (parser
differential / split-brain)**: the Rust verifier (`crates/api-client/src/ipns.rs`,
`crates/core/src/ipns.rs`) and the TS verifier (`packages/sdk-core/src/ipns/index.ts`)
reaching different accept/reject verdicts on the same Ed25519-signed record. Every
divergence is signature-gated (an attacker must present a validly-signed record),
so these are soundness/availability parity bugs, not key/plaintext exposure.

## Findings and dispositions (crypto/privacy review — full report linked above)

| # | Severity | Finding | Disposition |
|---|----------|---------|-------------|
| 1 | MEDIUM | Duplicate CBOR map keys: TS `cborDecode` defaulted to last-wins; a signed `ValidityType:[1,0]` decoded to `0` and was accepted while Rust rejects duplicate keys | **Fixed** — `cborDecode(..., { rejectDuplicateMapKeys: true })`; locked by an integration test (`throws on a duplicate CBOR map key`) |
| 2 | MEDIUM | Leading `+`/`-`: Rust `parse::<T>()` accepted a signed field (`+2099-…`); TS rejected it | **Fixed** — `parse_fixed_digits` fixed-width check on both sides; locked by parser tests |
| 3 | LOW | Year length: neither side enforced the RFC3339 4-digit year; huge/overflowing years diverged | **Fixed** — fixed-width fields (year 4, others 2) on both sides; locked by parser tests |
| 4 | LOW | Float `ValidityType` 0.0: cborg collapses float-0.0 and int-0 to JS `0`, passing the TS gate; Rust requires an integer major type | **Todo** — benign direction (0.0 still means EOL); clean fix needs CBOR-type introspection. See `.planning/todos/pending/2026-07-11-ts-validitytype-float-vs-integer-cbor-parity.md` |
| 6 | INFO | Confirm both languages decode `fileIv` strictly as base64 | **Discarded** — codec stores `fileIv` as a string (`packages/core/src/node/decode.ts`); the SC2 KAT (green on both languages) already locks the base64 samples incl. `==` padding |

**Clean (no action):** UUID canonical-only parity (Rust `is_canonical_uuid_form`
== TS `CANONICAL_UUID_RE`, oracle matches both); no panic/overflow in either
parser (impossible-date guard fail-closed on both); `build_node_aad` check
ordering.

## Built-in security review (general sweep — Step 2c)

Not separately run: the phase diff is RFC3339 parsers, a CBOR-decode option, and
test vectors — no injection, authz, secret-handling, or deserialization-of-
untrusted-object surface beyond the IPNS record parsing already covered in depth
by the crypto/privacy review above. No general-vulnerability findings apply.

## Verdict

**SECURED.** The two MEDIUM parity divergences are fixed and locked with tests on
both languages; one LOW divergence (benign-direction) is deferred with a todo;
the rest are clean or discarded. Verification is now strictly fail-closed and
cross-language-consistent for every case exercised by the shared oracle and the
added parity tests.
