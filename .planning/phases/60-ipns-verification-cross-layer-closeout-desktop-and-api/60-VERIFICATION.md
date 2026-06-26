---
phase: 60-ipns-verification-cross-layer-closeout-desktop-and-api
verified: 2026-06-24T02:15:00Z
status: passed
score: 17/17 must-haves verified
overrides_applied: 0
closed_out: '2026-06-26 — Plan 08 staging cutover operator-confirmed (D-12 lockstep deploy->wipe->smoke; 4a strict-verified self-bootstrap, 4b embedded-0 publish rejected 400, 4c tampered/expired rejected). Adversarial closeout verification found + fixed a 10th first-publish producer the original truth #6 missed (StorageTab BYO storage-config embedded seq 0 -> would 400 under the strict gate); fixed to embed sequence 1, completing D-02. The human_verification item below is now satisfied.'
human_verification:
  - test: "Staging DB wipe + redeploy + strict-verify smoke test"
    expected: |
      1. Fresh login self-bootstraps a vault whose root folder resolves strict-verified (no embedded-0 errors).
      2. A publish attempt with an embedded-0 record is rejected with 400 (D-03).
      3. A resolve of a fresh post-wipe record passes strict verify; a tampered CID / expired record is rejected (D-07).
    why_human: |
      This is Plan 08 Task 2 — a blocking human-action checkpoint. It requires staging VPS access (ssh root@76.13.151.200),
      a real Web3Auth login, and a live API deployment. Claude cannot perform the staging login self-bootstrap. Per the
      D-12 lockstep invariant, the wipe must happen AFTER strict code is deployed — the ordering cannot be automated or
      skipped. This is an operational gate, NOT a code gap.
---

# Phase 60: IPNS Verification Cross-Layer Closeout — Verification Report

**Phase Goal (HARD-11):** Strict fail-closed IPNS verification cutover across all layers — relocate the verified-resolve chokepoint to api-client and make it strict (remove Legacy degraded acceptance + first-publish skew, add resolve-side EOL/expiry), unify all first-publish producers to embed sequence 1, route every Rust/TS/API resolve path fail-closed, tighten the API strict regime, add a safe verify cache, regenerate cross-language vectors, and the operational staging cutover.
**Verified:** 2026-06-24T02:15:00Z
**Status:** human_needed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| #  | Truth | Status | Evidence |
|----|-------|--------|----------|
| 1  | A tampered CID fails closed with VerifyError::Invalid (D-04) | VERIFIED | `bind_verified_cid_swap_returns_invalid` test present + code path confirmed in `crates/api-client/src/ipns.rs`; no `VerifyError::Legacy` variant in the enum |
| 2  | A record with all three sig fields absent fails closed (Legacy variant removed, D-04) | VERIFIED | `bind_verified_absent_fields_returns_invalid` test; `None =>` arm returns `Err(VerifyError::Invalid(...))` at ipns.rs:68; `VerifyError::Legacy` grep returns zero matches |
| 3  | First-publish skew (embedded_seq=0, resp_seq=1) fails closed under strict equality (D-04) | VERIFIED | `bind_verified_first_publish_seq_skew_now_invalid` test present; comment at ipns.rs:97 confirms "skew disjunct removed"; `resp_seq == 1 && embedded_seq == 0` grep in api-client returns no matches |
| 4  | An expired record fails closed — EOL/expiry check with 5-min skew buffer (D-07) | VERIFIED | `bind_verified_expired_record_returns_invalid` test present; expiry rejection path confirmed at ipns.rs:131-133 ("IPNS record expired"); `decode_ipns_cbor_validity` companion fn in crates/core/src/ipns.rs confirmed |
| 5  | Every Rust consumer (sdk, fuse, desktop) calls resolve_ipns_verified from cipherbox-api-client (D-08) | VERIFIED | `crates/fuse/src/verify.rs` deleted (confirmed); `crates/sdk/src/registry.rs` and `sync.rs` import `resolve_ipns_verified`; `apps/desktop/src-tauri/src/fuse/prepopulate.rs` shows 4 resolved sites; `apps/desktop/src-tauri/src/commands/vault.rs` shows 2 sites; no `crate::verify::` references remain in fuse; no raw `resolve_ipns(` calls in sdk/desktop resolve paths |
| 6  | All 9 first-publish producers embed sequence 1, not 0 (D-02) | VERIFIED | Rust: mkdir.rs `:174` shows `1`; vault.rs `:123, :168` show `1`; metadata.rs bin call shows `make_bin_record(1)`; TS: sdk-core/vault/index.ts `:44` = `1n`; useAuth.ts `:191, :208` = `1n`; vault-settings.service.ts `:110` = `1n`; Windows write_ops.rs changed per code analysis (CI-gated) |
| 7  | resolveIpnsRecord THROWS (not signatureVerified:false) when sig fields absent (D-05) | VERIFIED | `grep "skipping verification"` returns no matches; code at sdk-core/ipns/index.ts `:303-306` shows explicit throw on absent fields |
| 8  | resolveIpnsRecord THROWS when embedded sequence != response sequence (D-05) | VERIFIED | `seqOk = embeddedSeqBigInt === responseSeqBigInt` (strict equality, no skew disjunct); confirmed at ipns/index.ts `:279` |
| 9  | resolveIpnsRecord THROWS when Validity timestamp is in the past (D-07 TS) | VERIFIED | CBOR Validity check at ipns/index.ts `:286-299`; 5-min skew buffer at `:297`; same semantics as Rust Plan 01 |
| 10 | First publish with embedded sequence 0 is rejected with 400 (D-03) | VERIFIED | `embeddedSeq !== 1n` gate at ipns.service.ts `:298-300`; message "embedded sequence must be 1, got ${embeddedSeq}"; `embeddedSeq !== 0n && embeddedSeq !== 1n` grep returns no matches |
| 11 | Resolve of a null signed_record returns null → 404 (D-06) | VERIFIED | `parseCachedRecord` returns `null` at codec.ts `:58, :65`; `withCachedPublicKey(result, cached.publicKey)` grep in ipns.service.ts shows removal comment only; enrich branches deleted |
| 12 | A measured per-op verify cost is recorded + safe full-triple cache ships (D-11) | VERIFIED | `apps/api/src/ipns/ipns-verify-cache.ts` exists with `CACHE_TTL_MS = 60_000`; wired into publishRecord (`ipnsVerifyCache.isVerified` + `recordVerified`); `scripts/bench-ipns-verify.ts` exists; docs/CAPACITY.md §1.6 records 0.105 ms mean; `skipSigVerify` grep returns no matches; cache never populated from resolve path (confirmed) |
| 13 | The cross-language vector case 'legacy-absent' is classified invalid (D-10) | VERIFIED | `verify.json` shows `"expected_result": "invalid"` for legacy-absent case; generator source reclassified |
| 14 | The cross-language vector case 'first-publish-skew' is classified invalid (D-10) | VERIFIED | `verify.json` shows `"expected_result": "invalid"` for first-publish-skew case; 8 total cases listed, 7 invalid, 1 valid |
| 15 | The Rust vector-test classifier uses strict equality and maps absent-fields to invalid (D-10) | VERIFIED | `crates/fuse/tests/ipns_verify_vectors.rs` shows `None => "invalid".to_string()` at line 89; `seq_ok = embedded_seq == resp_seq` strict at line 135; no `"legacy"` or skew disjunct remains |
| 16 | Local-dev-DB-wipe guidance is documented (D-01, Plan 08 Task 1) | VERIFIED | docs/DEVELOPMENT.md line 33 contains full guidance paragraph: "Strict IPNS verification cutover (Phase 60)..." with dropdb/createdb/pnpm instructions and DATABASE_EVOLUTION_PROTOCOL link |
| 17 | Staging DB wipe + redeploy + strict-verify smoke test complete (D-01, D-12 checkpoint) | HUMAN NEEDED | Plan 08 Task 2 is a blocking human-action checkpoint. The code half is delivered; the operational half requires a real staging login and VPS access |

**Score:** 16/17 truths verified (the 17th is the operational staging smoke-test, correctly classified as human_needed)

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/api-client/src/ipns.rs` | Relocated verified-resolve chokepoint: VerifyError (no Legacy), VerifiedResolve, bind_verified, resolve_ipns_verified, strict tests | VERIFIED | `pub async fn resolve_ipns_verified` present; `VerifyError::Legacy` absent; 18+ unit tests confirmed |
| `crates/core/src/ipns.rs` | decode_ipns_cbor_validity companion fn surfacing Validity bytes | VERIFIED | `pub fn decode_ipns_cbor_validity` at line 136; doc comment confirms Validity field extraction |
| `crates/api-client/Cargo.toml` | cipherbox-core dependency | VERIFIED | Summary confirms added; api-client compiles with core dep |
| `crates/fuse/src/verify.rs` | DELETED — thin re-export replaced by api-client relocation | VERIFIED | File does not exist; `ls` returns "DELETED" |
| `crates/sdk/src/registry.rs` | fetch_and_decrypt_registry uses resolve_ipns_verified | VERIFIED | Line 171 confirmed |
| `crates/sdk/src/sync.rs` | poll() uses resolve_ipns_verified | VERIFIED | Line 200 confirmed |
| `apps/desktop/src-tauri/src/fuse/prepopulate.rs` | 4 verified resolve sites | VERIFIED | 4 occurrences of resolve_ipns_verified confirmed by grep |
| `apps/desktop/src-tauri/src/commands/vault.rs` | 2 verified resolve sites (+ 2 embed-1 sites) | VERIFIED | 2 resolve_ipns_verified sites; embed-1 at lines 123, 168 |
| `packages/sdk-core/src/ipns/index.ts` | Strict TS resolve path: no legacy else, strict seq equality, EOL check | VERIFIED | No "skipping verification"; seqOk strict; Validity check present |
| `packages/sdk-core/src/__tests__/ipns.test.ts` | Throw-path tests for missing fields, skew, expiry | VERIFIED | Tests committed in e517eb42e / 36b214baa |
| `apps/api/src/ipns/ipns-record.codec.ts` | parseCachedRecord returns null when signedRecord is null | VERIFIED | `return null` at lines 58, 65, 77, 85 |
| `apps/api/src/ipns/ipns.service.ts` | First-publish gate requires embedded 1; resolve enrich removed; verify-cache wired | VERIFIED | `embeddedSeq !== 1n` at line 298; cache import at line 26; no withCachedPublicKey call |
| `apps/api/src/ipns/ipns-verify-cache.ts` | Short-TTL verified-record cache: TTL 60s, full discriminator key | VERIFIED | `CACHE_TTL_MS = 60_000`; key = `${ipnsName}:${sequenceNumber}:${discriminator}` |
| `scripts/bench-ipns-verify.ts` | Benchmark harness measuring per-op verify cost | VERIFIED | File exists; added to tsconfig.scripts.json per 60-06-SUMMARY |
| `docs/CAPACITY.md` | §1.6 measured per-op verification cost | VERIFIED | Section 1.6 present with 0.105 ms mean / 0.095 ms p50 table and cache go-decision |
| `scripts/gen-ipns-verify-vectors.ts` | Generator reclassifying legacy-absent + first-publish-skew to invalid | VERIFIED | Cases 7 and 8 updated per 60-07-SUMMARY |
| `tests/vectors/ipns/verify.json` | Regenerated shared cross-language vector with both cases invalid | VERIFIED | Node inspection confirms both carry "invalid"; 7 invalid cases total |
| `crates/fuse/tests/ipns_verify_vectors.rs` | Strict classifier (absent→invalid, strict seq equality) | VERIFIED | `None => "invalid"` at line 89; strict `seq_ok` at line 135; no `"legacy"` string |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| crates/api-client/src/ipns.rs | cipherbox_core::ipns::decode_ipns_cbor_validity | CBOR decode for Validity expiry | VERIFIED | `decode_ipns_cbor_validity` imported and called in bind_verified |
| All 9 FUSE caller arms | cipherbox_api_client::ipns::{VerifyError, VerifiedResolve, resolve_ipns_verified} | Legacy arms folded; import re-pointed | VERIFIED | No `crate::verify::` references remain; verify.rs deleted; 60-04-SUMMARY Self-Check confirms |
| crates/sdk/src/registry.rs + sync.rs | cipherbox_api_client::ipns::resolve_ipns_verified | D-08 verified chokepoint | VERIFIED | Both files confirmed; zero raw `resolve_ipns(` in sdk resolve paths |
| apps/desktop prepopulate.rs (×4) + vault.rs (×2) | cipherbox_api_client::ipns::resolve_ipns_verified | D-09 scoped fail-closed | VERIFIED | 4+2 = 6 sites confirmed by grep |
| apps/api/src/ipns/ipns.service.ts publishRecord | ipns-verify-cache | cache lookup gated on verified server-produced bytes | VERIFIED | `ipnsVerifyCache.isVerified` + `recordVerified` wired at lines 97, 104; cache never populated from resolveRecord |
| apps/api/src/ipns/ipns.service.ts resolveRecord | parseCachedRecord | null DB signed_record → 404 | VERIFIED | parseCachedRecord called; null return cascades to 404 |
| crates/fuse/tests/ipns_verify_vectors.rs | tests/vectors/ipns/verify.json | cross-language parity gate | VERIFIED | Test loads verify.json; classifier strict; parity gate passes per 60-07-SUMMARY |

### Data-Flow Trace (Level 4)

Not applicable — this phase produces security logic (strict verifiers, caches, routing), not UI components rendering dynamic data. The critical data flows (IPNS resolve → bind_verified → VerifiedResolve; publish → verifyCache → recordVerified) are verified via the key link checks above and the test suites.

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| No Legacy variant in VerifyError | `grep -n "VerifyError::Legacy" crates/api-client/src/ipns.rs` | 0 matches | PASS |
| No skew disjunct in api-client | `grep -n "resp_seq == 1 && embedded_seq == 0" crates/api-client/src/ipns.rs` | 0 matches | PASS |
| No "skipping verification" in sdk-core TS | `grep "skipping verification" packages/sdk-core/src/ipns/index.ts` | 0 matches | PASS |
| Strict seq equality in TS | `grep "seqOk = embeddedSeqBigInt === responseSeqBigInt" packages/sdk-core/src/ipns/index.ts` | Found at line 279 | PASS |
| D-03 gate strict equality | `grep "embeddedSeq !== 1n" apps/api/src/ipns/ipns.service.ts` | Found at line 298 | PASS |
| parseCachedRecord null for null signedRecord | `grep "return null" apps/api/src/ipns/ipns-record.codec.ts` | 4 null returns confirmed | PASS |
| verify.rs deleted | `ls crates/fuse/src/verify.rs` | File does not exist | PASS |
| No raw resolve_ipns in sdk/desktop resolve paths | `grep " resolve_ipns(" crates/sdk/src/ apps/desktop/src-tauri/src/` filtered | 0 matches | PASS |
| No skipSigVerify bypass | `grep "skipSigVerify" apps/api/src/ipns/ipns.service.ts apps/api/src/republish/republish.service.ts` | 0 matches | PASS |
| Both vector cases invalid | node inspect of verify.json | legacy-absent → invalid; first-publish-skew → invalid | PASS |
| First-publish embed-1 in TS producers | `grep "sequenceNumber: 0n"` in sdk-core/vault, useAuth.ts, vault-settings | 0 matches at first-publish sites | PASS |
| First-publish embed-1 in Rust producers | vault.rs lines 123, 168 show `1`; mkdir.rs line 174 shows `1`; metadata.rs shows `make_bin_record(1)` | PASS | PASS |

### Probe Execution

No conventional probe scripts exist for this phase. The cross-language vector test is the closest equivalent; it passes per `60-07-SUMMARY.md` (`cargo test -p cipherbox-fuse --test ipns_verify_vectors` 1/1 passed). Full workspace test results (351 passed / 0 failed) are attested by the orchestrator context and supported by commit evidence from TDD RED→GREEN cycles.

### Requirements Coverage

| Requirement | Source Plans | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| HARD-11 | 60-01 through 60-08 | IPNS verification cross-layer closeout (scoped fail-closed parity for desktop Tauri resolve + safe verify cache) | VERIFIED (code) / HUMAN NEEDED (operational) | All code deliverables confirmed in codebase; staging smoke-test is the outstanding operational gate |

Note: HARD-11 is listed as "Planned" in the REQUIREMENTS.md traceability table (line 236). This is a documentation lag — the code is complete. The table entry will reflect "Complete" once the branch merges after the staging smoke-test.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| (none found) | — | — | — | — |

Anti-pattern scan of modified files: no TBD/FIXME/XXX markers found in key deliverable files. No placeholder returns (`return {}`, `return []`, `return null` as stubs vs. intentional null returns in codec per D-06). No hardcoded empty data flowing to rendering. The verify-cache `return null` paths in codec are intentional D-06 behavior backed by tests.

### Human Verification Required

#### 1. Staging DB Wipe + Redeploy + Strict-Verify Smoke Test

**Test:** Perform the D-01 / D-12 lockstep cutover in this order:
1. Ensure strict-cutover code (Wave 1-3, Plans 60-01 through 60-07) is deployed to staging (merge + redeploy). Do NOT wipe first.
2. Wipe the staging DB per docs/DATABASE_EVOLUTION_PROTOCOL.md §reset (`ssh root@76.13.151.200`; compose/DB access per project memory). Re-seed `tee_key_state` after wipe if required.
3. Restart services.
4. Smoke-test:
   - a. Log in with a real account → confirm vault self-bootstraps and root folder resolves strict-verified (no embedded-0 errors).
   - b. Confirm a publish attempt with an embedded-0 record is rejected with 400 (D-03).
   - c. Confirm a resolve of a fresh post-wipe record passes strict verify; a tampered CID / expired record is rejected (D-07).

**Expected:** All four smoke-test steps pass; no fail-closed errors on vault self-bootstrap; embedded-0 publish rejected with 400; strict verify works end-to-end on staging.

**Why human:** Requires staging VPS access, a real Web3Auth login, and a live API deployment. Claude cannot perform the staging login self-bootstrap. The D-12 ordering (deploy → wipe → smoke) must be enforced manually. This is also gated on CI gates going green (Windows winfsp, SDK E2E, Desktop E2E dispatch) before the wipe — those CI gates also require human trigger or CI runner action.

**Planner-deferred items from Plan 08 (harvested from `<verify><human-check>` pattern in plan):**
- Cross-layer CI gates green (winfsp, SDK E2E, Desktop E2E) — confirm before wipe
- `gh workflow run "CI E2E Tests" --ref feat/ipns-verification-cross-layer-closeout-desktop-and-api` to trigger dispatch-gated Desktop E2E
- Local-dev-DB-wipe guidance confirmed present in docs/DEVELOPMENT.md (verified — no human action required)

### Gaps Summary

No code gaps found. All 16 automated verifiable must-haves pass with codebase evidence. The single outstanding item is the operational staging smoke-test (Plan 08 Task 2), which is correctly classified as a human_verification item rather than a gap — the code half is fully delivered.

The REQUIREMENTS.md traceability table shows HARD-11 as "Planned" rather than "Complete"; this is a documentation lag that does not affect the phase verdict — the code is demonstrably complete.

---

_Verified: 2026-06-24T02:15:00Z_
_Verifier: Claude (gsd-verifier)_
