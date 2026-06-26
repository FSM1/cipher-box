---
phase: 58-ipns-signature-verify-coverage
plan: 04
subsystem: infra
tags: [ipns, cbor, crypto, fuse, sdk-core, security, cross-language, test-vectors]

requires:
  - phase: 58-ipns-signature-verify-coverage
    plan: 01
    provides: decode_ipns_cbor_data in cipherbox-core, verify_ipns_resolve_signature in api-client, CBOR binding in sdk-core resolveIpnsRecord

provides:
  - Shared cross-language IPNS verify fixture (7 cases) at tests/vectors/ipns/verify.json
  - Rust consumer test in crates/fuse/tests/ipns_verify_vectors.rs
  - JS consumer appended to packages/sdk-core/src/__tests__/ipns.test.ts
  - D-12: Rust and JS agree on all 7 vectors via existing CI gates

affects:
  - D-11/D-12 cross-language byte-construction drift now caught by cargo test + sdk-core vitest

tech-stack:
  added:
    - scripts/gen-ipns-verify-vectors.mjs (ESM generator using @noble/ed25519 + cborg for CBOR encoding)
  patterns:
    - load_vectors convention from crates/crypto/tests/cross_language.rs mirrored in fuse integration test
    - cid-swapped and seq-mismatch carry valid Ed25519 sigs over mismatching CBOR data to pin binding layer

key-files:
  created:
    - scripts/gen-ipns-verify-vectors.mjs
    - tests/vectors/ipns/verify.json
    - crates/fuse/tests/ipns_verify_vectors.rs
  modified:
    - packages/sdk-core/src/__tests__/ipns.test.ts

key-decisions:
  - 'Generator location: scripts/gen-ipns-verify-vectors.mjs at repo root; uses pathToFileURL absolute imports for @noble/ed25519 and cborg from pnpm virtual store (avoids package resolution issues across workspaces)'
  - 'Rust test location: crates/fuse/tests/ to avoid dependency cycle (api-client+core both depend on crypto; fuse depends on all three, making it cycle-free)'
  - 'JS fixture import path: ../../../../tests/vectors/ipns/verify.json (4 levels up from packages/sdk-core/src/__tests__/); resolveJsonModule already true in tsconfig.base.json'
  - 'cid-swapped and seq-mismatch: verifyEd25519 mock returns true so only the binding path is tested; REAL data bytes from fixture flow through cborDecode unchanged'
  - 'Generator uses cborg directly for CBOR encoding (not @cipherbox/core createIpnsRecord) for cid-swapped and seq-mismatch cases so wrong values can be embedded'

requirements-completed: [HARD-09]

duration: 25min
completed: 2026-06-22
---

# Phase 58 Plan 04: Shared Cross-Language IPNS Verify Vectors Summary

**Single shared JSON fixture (7 cases) consumed by both Rust cargo test and sdk-core vitest, closing the Rust-JS byte-construction drift gap per D-11/D-12**

## Performance

- **Duration:** ~25 min
- **Started:** 2026-06-22
- **Completed:** 2026-06-22
- **Tasks:** 3 (Task 0: fixture generator; Task 1: Rust consumer; Task 2: JS consumer)
- **Files modified:** 4

## Accomplishments

- `scripts/gen-ipns-verify-vectors.mjs`: deterministic ESM generator using `@noble/ed25519` and `cborg`, runs from repo root via pnpm virtual store paths
- `tests/vectors/ipns/verify.json`: 7-case shared fixture covering all D-11 cases; cid-swapped and seq-mismatch carry real Ed25519 signatures over mismatching CBOR data
- `crates/fuse/tests/ipns_verify_vectors.rs`: Rust integration test in cycle-free fuse crate; calls real `verify_ipns_resolve_signature` + `decode_ipns_cbor_data`; all 7 cases pass
- `packages/sdk-core/src/__tests__/ipns.test.ts`: appended D-11/D-12 describe block; cid-swapped/seq-mismatch pass REAL fixture `data` bytes through `cborDecode` so the binding layer is exercised against genuine vector bytes; all 26 ipns tests pass

## Task Commits

Each task was committed atomically:

1. **Task 0 fixture generator** - `f882d02ea`
2. **Task 1 Rust consumer** - `a9be5bef1`
3. **Task 2 JS consumer** - `4aa7412d0`

## Files Created/Modified

- `scripts/gen-ipns-verify-vectors.mjs` - New: one-shot ESM generator
- `tests/vectors/ipns/verify.json` - New: 7-case shared fixture
- `crates/fuse/tests/ipns_verify_vectors.rs` - New: Rust integration test consumer
- `packages/sdk-core/src/__tests__/ipns.test.ts` - Modified: appended D-11/D-12 vector describe block

## Generator Approach

The generator (`scripts/gen-ipns-verify-vectors.mjs`) uses explicit `pathToFileURL` imports for packages not directly resolvable from the repo root:

- `@noble/ed25519` from `node_modules/.pnpm/@noble+ed25519@2.3.0/node_modules/@noble/ed25519/index.js`
- `cborg` from `node_modules/.pnpm/cborg@4.5.8/node_modules/cborg/cborg.js`
- `@cipherbox/core` from `packages/core/dist/index.mjs`

For normal cases (valid, tampered-sig, name-mismatch, partial-fields, legacy-absent), CBOR is built with the correct cid/seq then signed. For the critical cid-swapped and seq-mismatch cases, CBOR embeds the wrong value (CID_B or seq=99) and the Ed25519 signature is computed over THAT mismatching CBOR — meaning the signature genuinely covers the wrong data, so the Ed25519 check passes but the binding check (embedded vs response field) fails.

## Rust Test Details

`classify_vector()` in `ipns_verify_vectors.rs` implements the same two-step binding logic as `bind_verified` in `crates/fuse/src/verify.rs`:

1. Call `cipherbox_api_client::ipns::verify_ipns_resolve_signature` → `Option<bool>`
2. For `Ok(Some(true))`: base64-decode `data`, call `cipherbox_core::ipns::decode_ipns_cbor_data`, compare embedded value and seq to response fields

This explicitly pins both the api-client signature check and the core CBOR decode path against JS-generated bytes.

## JS Test Details

The D-11/D-12 describe block in `ipns.test.ts`:

- Imports `vectors from '../../../../tests/vectors/ipns/verify.json'` (path depth confirmed correct)
- For each case, mocks `verifyEd25519` and `deriveIpnsName` to reflect the case posture
- Passes the real fixture `data` bytes (base64 from the generator) through to `cborDecode` UNMOCKED
- cid-swapped and seq-mismatch: `verifyEd25519` mock returns `true` so only the binding layer rejects

## CI Gate Compliance (D-12)

Both consumers run in already-required CI checks:

- `cargo test -p cipherbox-fuse` includes `ipns_verify_vectors.rs` (no new gate)
- `pnpm --filter @cipherbox/sdk-core test` includes the new describe block (no new gate)

A divergence between JS-generated CBOR bytes and Rust expectations now fails an existing CI check.

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

None — all 7 vectors carry genuine data; the `null` fields in partial-fields and legacy-absent cases are intentional fixtures, not stubs.

## Threat Flags

None — test-only artifacts introduced; no new network endpoints, auth paths, or schema changes.

## Self-Check: PASSED

- `tests/vectors/ipns/verify.json` exists with 7 entries
- `crates/fuse/tests/ipns_verify_vectors.rs` exists and contains `fn ipns_verify_cross_language`
- `grep -q "verify.json" packages/sdk-core/src/__tests__/ipns.test.ts` — true
- All commits exist:
  - `f882d02ea` feat(58-04): add shared IPNS verify test vector fixture
  - `a9be5bef1` feat(58-04): add Rust IPNS verify vector consumer
  - `4aa7412d0` feat(58-04): add sdk-core vitest consumer
- `cargo test -p cipherbox-fuse --test ipns_verify_vectors` — 1 passed
- `pnpm --filter @cipherbox/sdk-core test -- ipns` — 26 passed (7 new vector cases + 19 prior)
- `grep -rn "ipns_verify_cross_language" crates/crypto/` returns nothing (no dependency cycle)

Phase: 58-ipns-signature-verify-coverage
Completed: 2026-06-22
