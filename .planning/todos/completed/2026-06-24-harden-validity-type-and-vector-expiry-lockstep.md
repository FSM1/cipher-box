---
created: 2026-06-24
title: Enforce ValidityType==0 in IPNS verify and keep cross-language vectors in expiry lockstep
area: crates/core, sdk-core, tests/vectors
files:
  - crates/core/src/ipns.rs
  - crates/api-client/src/ipns.rs
  - packages/sdk-core/src/ipns/index.ts
  - crates/fuse/tests/ipns_verify_vectors.rs
  - scripts/gen-ipns-verify-vectors.ts
  - tests/vectors/ipns/verify.json
resolves_phase: 75
---

## Problem

Two related Validity/expiry-completeness gaps in the strict verify stack, surfaced by
CodeRabbit on PR #555 (findings #7 and #9). Both deferred from the Phase 60 strict-cutover
PR as cross-layer / heavy-lift hardening on the currently-green verify path.

**#7 — ValidityType not bound (Major, security/defense-in-depth).** `decode_ipns_cbor_validity`
(`crates/core/src/ipns.rs`) extracts only the `Validity` bytes and never reads `ValidityType`;
`bind_verified` (`crates/api-client/src/ipns.rs`) then treats that timestamp as an EOL expiry
unconditionally. The TS verifier (`packages/sdk-core/src/ipns/index.ts`) likewise reads only
`cborFields['Validity']`, never `ValidityType`. So a record with a missing or non-EOL
`ValidityType` would have its `Validity` misinterpreted as an EOL timestamp. **Both layers
currently ignore `ValidityType`, so they are in PARITY** — fixing only Rust would make Rust
stricter than TS and break the documented lockstep. Mitigants today: the Ed25519 signature
covers the whole CBOR (incl. `ValidityType`), so it is not forgeable, and CipherBox only ever
creates `ValidityType == 0` (EOL) records.

**#9 — vector classifier omits expiry (Major correctness, latent).** The cross-language
classifier in `crates/fuse/tests/ipns_verify_vectors.rs` (`classify_vector`) mirrors strict
CID + sequence binding but NOT the resolve-side EOL/expiry check that `bind_verified` now
performs (D-07). An expired vector with a valid signature and matching CID/sequence would be
classified `"valid"` here while `resolve_ipns_verified` rejects it. Currently **latent** — no
existing vector in `tests/vectors/ipns/verify.json` is expired-with-valid-sig, so nothing is
mis-classified today; it is a test-fidelity gap that would bite when an expiry/ValidityType
vector is added.

## Solution

Do these together so Rust + TS + vectors stay in lockstep (the whole point of the cutover):

1. Read and require `ValidityType == 0` (EOL) before treating `Validity` as an expiry, in BOTH
   `decode_ipns_cbor_validity` (Rust) and the TS `resolveIpnsRecord` Validity path. Missing or
   non-zero `ValidityType` → fail closed. Keep the 5-minute skew buffer.
2. Add the EOL/expiry (and ValidityType) leg to the vector classifier
   (`crates/fuse/tests/ipns_verify_vectors.rs`) — ideally by exporting a single binding helper
   from `cipherbox-api-client` and reusing it, rather than duplicating `decode_ipns_cbor_validity`
   + RFC3339 logic in the test.
3. Add `expired` and `wrong-validity-type` vectors to `tests/vectors/ipns/verify.json` (via
   `scripts/gen-ipns-verify-vectors.ts`) classified `invalid`, and confirm Rust + TS agree.

Verify with: `cargo test --workspace`, the cross-language vector parity job, and SDK E2E.
