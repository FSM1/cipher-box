---
phase: 58-ipns-signature-verify-coverage
verified: 2026-06-22T15:39:58Z
status: passed
score: 7/7 must-haves verified
overrides_applied: 0
---

# Phase 58: IPNS Signature Verify Coverage Verification Report

**Phase Goal:** Finish the IPNS signed-record verification story: bind every resolved record to its CID/sequence by decoding the signed CBOR and comparing (closing the swap gap on both Rust and JS), fold verification into a single Rust `resolve_ipns_verified` chokepoint so all ~9 resolve sites are safe-by-default, validate the embedded publish sequence even when CAS is omitted without regressing the non-CAS publish paths, de-duplicate the web vs sdk-core resolve/verify copies, and add shared cross-language verify test vectors.
**Verified:** 2026-06-22T15:39:58Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | A resolved IPNS record whose response cid differs from the cid embedded in its signed CBOR data is refused (verify failure), not used. | VERIFIED | `bind_verified` in `crates/fuse/src/verify.rs` (lines 82–88): decodes CBOR via `decode_ipns_cbor_data`, checks `embedded_value != format!("/ipfs/{}", resp.cid)` → `VerifyError::Invalid("IPNS cid binding mismatch…")`. JS: `packages/sdk-core/src/ipns/index.ts` lines 254–258 throw `IPNS cid binding mismatch`. Both confirmed by cid-swapped vector (expected_result: "invalid"). |
| 2 | A resolved IPNS record whose response sequenceNumber differs from the embedded CBOR Sequence is refused (verify failure). | VERIFIED | `bind_verified` lines 91–99 compares `embedded_seq != resp_seq` → `VerifyError::Invalid("IPNS sequence binding mismatch…")`. JS lines 262–266 throw `IPNS sequence binding mismatch`. Confirmed by seq-mismatch vector (expected_result: "invalid"). |
| 3 | All 9 Rust FUSE resolve sites obtain their CID through `resolve_ipns_verified` — none calls `resolve_ipns` directly and trusts the cid. | VERIFIED | `grep -rn "resolve_ipns_verified" crates/fuse/src/` returns 13 hits: events.rs (1), fs.rs (1), publish.rs (2), metadata.rs (3), replay.rs (2), verify.rs (4 internal). Remaining bare `resolve_ipns()` calls exist only inside `VerifyError::Legacy` arms (D-04 authorized fallback) — never as a cid-trusting entry point. No bare calls in `crates/fuse/src/platform/` either. |
| 4 | A legacy record (all three signature fields absent) is still allowed and flagged `signatureVerified=false` (D-04). | VERIFIED | Rust: `VerifyError::Legacy` arm in all 9 sites re-resolves via `resolve_ipns()` with logged warning and proceeds. JS: `packages/sdk-core/src/ipns/index.ts` line 213 sets `signatureVerified = false` in the `else` branch (all fields absent), no binding performed. legacy-absent vector expected_result "legacy" confirmed. |
| 5 | `replay.rs resolve_folder_key` keeps hard fail-closed behavior (D-03): Legacy warns and continues; Invalid/Api returns Err. | VERIFIED | `crates/fuse/src/replay.rs` lines 338–360: `VerifyError::Legacy` → logs warn + re-resolves for DB CID + continues. `VerifyError::Invalid` → `return Err(format!("IPNS {} signature verification failed — refusing to use CID (D-02): {}"))`. `VerifyError::Api` → `return Err(...)`. Hard fail-closed on Invalid is preserved. |
| 6 | The D-09 unconditional embedded-sequence gate runs even when `expectedSequenceNumber` (CAS) is omitted. | VERIFIED | `apps/api/src/ipns/ipns.service.ts` lines 274–304: the D-09 gate block (`let isIdempotentRepublish = false; if (!existing) { … } else { … }`) is NOT wrapped in `if (expectedSequenceNumber !== undefined)`. That condition only guards the CAS 409 check at line 245. `ipns.service.spec.ts` line 1867 test: "rejects first publish with embedded=2n even when expectedSequenceNumber is undefined" passes. |
| 7 | Web `resolveIpnsRecord` delegates to `@cipherbox/sdk-core` and no longer defines its own `verifyIpnsSignature` or resolve body; shared cross-language verify vectors (7 cases) consumed by both Rust and JS suites. | VERIFIED | Web: `grep -c "function verifyIpnsSignature" apps/web/src/services/ipns.service.ts` = 0; line 17 imports `resolveIpnsRecord as resolveIpnsRecordCore` from `@cipherbox/sdk-core`; lines 144–152 are a 3-line delegating wrapper threading `apiAxios`. Shared fixture: `tests/vectors/ipns/verify.json` exists with exactly 7 cases. Rust consumer: `crates/fuse/tests/ipns_verify_vectors.rs` `fn ipns_verify_cross_language` loads fixture and asserts all 7. JS consumer: `packages/sdk-core/src/__tests__/ipns.test.ts` line 387 imports the same fixture; 7 individual `it()` cases exercise real binding bytes. |

**Score:** 7/7 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/core/src/ipns.rs` | `pub fn decode_ipns_cbor_data` | VERIFIED | Line 81: `pub fn decode_ipns_cbor_data(data: &[u8]) -> Result<(String, u64), IpnsError>`. Unit tests at lines 410–470 cover round-trip, non-map rejection, missing-key rejection, negative-sequence rejection. |
| `crates/fuse/src/verify.rs` | `resolve_ipns_verified` chokepoint + `VerifyError` + `VerifiedResolve` | VERIFIED | File exists; line 18 `pub enum VerifyError { Api, Legacy, Invalid }`, line 41 `pub struct VerifiedResolve { cid, sequence_number, signature_verified }`, line 130 `pub async fn resolve_ipns_verified`. `bind_verified` unit tests for all 5 cases present. |
| `crates/fuse/src/lib.rs` | `pub mod verify;` | VERIFIED | Line 71: `pub mod verify;` |
| `packages/sdk-core/src/ipns/index.ts` | CBOR binding with `cid binding mismatch` + `sequence binding mismatch` | VERIFIED | Lines 254–267 implement both binding checks on the full-signature branch only (inside `if (hasSignatureV2 \|\| hasData \|\| hasPubKey)` → `signatureVerified = true` path). `cborg` added as explicit dep at `^4.5.8`. |
| `apps/api/src/ipns/ipns.service.ts` | Unconditional D-09 gate with `isIdempotentRepublish` | VERIFIED | Lines 274–304 implement unconditional gate. `isIdempotentRepublish` flag gates only the sequenceNumber increment (line 314); `latestCid` and `signedRecord` unconditionally updated (lines 317–318). |
| `apps/web/src/services/ipns.service.ts` | Delegates to `@cipherbox/sdk-core`; no local `verifyIpnsSignature` | VERIFIED | No `function verifyIpnsSignature` definition. Lines 17–152: imports core function, thin wrapper with axios injection. |
| `tests/vectors/ipns/verify.json` | 7-case shared fixture (including cid-swapped, seq-mismatch) | VERIFIED | File exists; node confirms exactly 7 cases with correct expected_results: valid→"valid", tampered-sig/name-mismatch/cid-swapped/seq-mismatch/partial-fields→"invalid", legacy-absent→"legacy". |
| `crates/fuse/tests/ipns_verify_vectors.rs` | Rust cross-language consumer | VERIFIED | File exists; `fn ipns_verify_cross_language` loads `../../tests/vectors/ipns/verify.json`, calls real `cipherbox_api_client::ipns::verify_ipns_resolve_signature` and `cipherbox_core::ipns::decode_ipns_cbor_data`. Not in `crates/crypto` (no dep cycle). |
| `packages/sdk-core/src/__tests__/ipns.test.ts` | JS cross-language consumer | VERIFIED | Line 387 imports from `../../../../tests/vectors/ipns/verify.json`. 7 distinct `it()` cases exercise real CBOR bytes (cid-swapped and seq-mismatch pass real `data` bytes from fixture to `cborDecode`). |
| `scripts/gen-ipns-verify-vectors.mjs` | Reproducible vector generator | VERIFIED | File exists; header documents cid-swapped/seq-mismatch cases carry real Ed25519 sigs over mismatching CBOR data so only binding check fails. |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `crates/fuse/src/verify.rs` | `cipherbox_core::ipns::decode_ipns_cbor_data` | `bind_verified` CBOR decode after `Ok(Some(true))` | WIRED | Line 107: `cipherbox_core::ipns::decode_ipns_cbor_data(&data_bytes)` |
| `crates/fuse/src/{events,fs,publish,metadata,replay}.rs` | `crate::verify::resolve_ipns_verified` | All 9 resolve sites routed through wrapper | WIRED | grep confirms 9 call sites across 5 files; all cid/sequence consumed via `verified.cid` and `verified.sequence_number` (D-08 authoritative) |
| `packages/sdk-core/src/ipns/index.ts` | `cborDecode` (from `cborg`) | `parseCborData` binding compare after `signatureVerified = true` | WIRED | Line 247: `const cborFields = cborDecode(dataBytes)`. `cborg` at `^4.5.8` in sdk-core package.json. Binding runs on full-signature branch only. |
| `apps/web/src/services/ipns.service.ts` | `@cipherbox/sdk-core resolveIpnsRecord` | import + `ctx.axiosInstance` injection | WIRED | Line 17 import, lines 147–151 call with `{ apiUrl, getAccessToken, axiosInstance: apiAxios }` |
| `crates/fuse/tests/ipns_verify_vectors.rs` | `tests/vectors/ipns/verify.json` | `load_vectors("ipns/verify.json")` | WIRED | Line 160: `load_vectors("ipns/verify.json")` |
| `packages/sdk-core/src/__tests__/ipns.test.ts` | `tests/vectors/ipns/verify.json` | relative import `../../../../tests/vectors/ipns/verify.json` | WIRED | Line 387: import statement confirmed |

### Data-Flow Trace (Level 4)

Not applicable: phase artifacts are security/verification middleware (not UI components rendering dynamic data). The data flow is: API resolve response → binding verification → caller uses verified CID. Verified at Level 3 (wired).

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| `decode_ipns_cbor_data` round-trips `build_cbor_data` | `cargo test -p cipherbox-core decode_ipns_cbor` (gate observed green per execution: 75 tests passed) | Passes: round-trip, non-map, missing-key, negative-seq cases | PASS |
| `bind_verified` rejects cid-swap and seq-mismatch | `cargo test -p cipherbox-fuse verify` (observed green: 87 tests passed incl. new ipns_verify_vectors test asserting all 7 cross-language vectors) | All 5 bind_verified cases pass | PASS |
| All 9 FUSE resolve sites compile through chokepoint | `cargo build -p cipherbox-fuse` (observed green per gate) | No bare cid-trusting `resolve_ipns()` calls outside Legacy arms or `verify.rs` | PASS |
| D-09 gate covers 9 service cases | `pnpm --filter @cipherbox/api test -- ipns.service` (913/913 api jest passed per gate) | All 9 D-09 cases in `describe('upsertFolderIpns D-09 embedded-sequence gate', …)` pass | PASS |
| JS binding throws on cid/seq mismatch | `pnpm --filter @cipherbox/sdk-core test -- ipns` (observed green per gate, incl. 7 cross-language vector cases) | cid-swapped/seq-mismatch throw with correct messages | PASS |
| Full SDK E2E (non-CAS publish paths no regression) | `SDK_E2E_SECRET=… pnpm --filter @cipherbox/sdk-e2e test` (89/89 passed per human-verified D-10 gate) | Zero regressions; vault-init/per-file/bin/folder flows all pass | PASS |

### Probe Execution

No probe scripts declared. Phase uses cargo test + jest + sdk-e2e as the execution gates; all observed green per gate_results_already_observed.

### Requirements Coverage

| Requirement | Source Plans | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| HARD-09 | 58-01, 58-02, 58-03, 58-04 | IPNS signature-verify coverage — CBOR cid/sequence binding + Rust `resolve_ipns_verified` chokepoint covering all resolve sites, non-CAS embedded-sequence validation, web/sdk-core resolve dedup, and shared cross-language verify test vectors | SATISFIED | All four sub-deliverables implemented and verified: (1) `decode_ipns_cbor_data` + `resolve_ipns_verified` + 9-site routing; (2) unconditional D-09 gate in `upsertFolderIpns`; (3) web dedup to sdk-core; (4) 7-case shared vectors in `tests/vectors/ipns/verify.json` consumed by both Rust and JS suites. |

### Anti-Patterns Found

None. No `TBD`, `FIXME`, `XXX`, `TODO`, `HACK`, or `PLACEHOLDER` markers found in phase-modified files. No stub patterns (empty returns, hardcoded empty arrays, placeholder components). The remaining bare `resolve_ipns()` calls in FUSE source files are exclusively inside `VerifyError::Legacy` handler arms — the D-04 authorized path for pre-signing records — and are not stubs.

### Human Verification Required

None. All must-haves are mechanically verifiable via code inspection and test execution. The D-10 full SDK E2E gate was already run and observed 89/89 passed (noted in gate_results_already_observed).

### Gaps Summary

No gaps. All 7 observable truths are verified. HARD-09 is fully satisfied.

---

_Verified: 2026-06-22T15:39:58Z_
_Verifier: Claude (gsd-verifier)_
