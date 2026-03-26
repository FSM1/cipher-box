---
phase: 24-bug-fixes-test-infrastructure
verified: 2026-03-26T00:00:00Z
status: passed
score: 5/5 must-haves verified
---

# Phase 24: Bug Fixes & Test Infrastructure Verification Report

**Phase Goal:** Fix known bugs blocking user experience and strengthen test infrastructure with headless load tests, vault recovery E2E coverage, and load test auth refresh handling
**Verified:** 2026-03-26
**Status:** PASSED
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (from ROADMAP Success Criteria)

| #   | Truth                                                                                            | Status   | Evidence                                                                                                                                                                                                                             |
| --- | ------------------------------------------------------------------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | Bin IPNS name resolves correctly (no 404 errors on recycle bin operations)                       | VERIFIED | `packages/sdk/src/bin/index.ts`: `loadBin` auto-repairs null IPNS with `saveBinMetadata` + `publishWithVerify`; returns `sequenceNumber: 1`                                                                                          |
| 2   | Device registry parses without crypto format errors                                              | VERIFIED | `packages/core/src/registry/schema.ts`: `validateDeviceRegistry` routes v1 through `migrateV1ToV2` which fills empty `ipHash` with `'0'.repeat(64)`; `apps/web/src/hooks/useAuth.ts` now computes SHA-256 of `'0.0.0.0'` placeholder |
| 3   | Headless Node.js load tests call sdk-core functions directly without Playwright browser overhead | VERIFIED | `tests/load/src/workloads/sdk-core-workload.ts` imports `* as sdkCore from '@cipherbox/sdk-core'`; no `CipherBoxClient` import; 3 scenario files use `prepareSdkClient` -> `run*Workload`                                            |
| 4   | Vault v2 recovery tool has automated E2E test coverage                                           | VERIFIED | `tests/web-e2e/tests/recovery.spec.ts` seeds real vault via `createTestAccount` + `client.uploadFile`, navigates to `recovery.html`, verifies file in progress log                                                                   |
| 5   | Load tests handle 401 responses with automatic token refresh instead of failing                  | VERIFIED | `tests/load/src/harness/client-pool.ts`: `createSdkContext` uses `refreshAccessToken` with shared `refreshPromise` coalescing concurrent 401s; calls `reAuthenticate` -> `/auth/test-login`                                          |

**Score: 5/5 truths verified**

---

### Required Artifacts (Plan 01 — BUGFIX-01, BUGFIX-02)

| Artifact                                       | Expected                                                      | Status   | Details                                                                                                                                             |
| ---------------------------------------------- | ------------------------------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `packages/sdk/src/bin/index.ts`                | Auto-repair in loadBin + retry/verify in saveBinMetadata      | VERIFIED | `publishWithVerify` function (line 135), `loadBin` auto-repair block (line 188), `saveBinMetadata` calls `publishWithVerify` (line 116)             |
| `packages/sdk/src/__tests__/bin.test.ts`       | Unit tests for bin auto-repair and publishWithVerify behavior | VERIFIED | Tests: "auto-repairs when no IPNS record exists", "auto-repair calls saveBinMetadata", "publishWithVerify retries when verify fails"                |
| `packages/core/src/registry/schema.ts`         | Lenient v1/v2 read + strict v2 write                          | VERIFIED | `migrateV1ToV2` (line 57), `validateV2Registry` (line 89), `validateDeviceEntryBase` (line 112), `validateDeviceEntry` (line 186)                   |
| `packages/core/src/registry/types.ts`          | DeviceRegistry type with `'v1' \| 'v2'` version union         | VERIFIED | `DeviceRegistryVersion = 'v1' \| 'v2'` (line 55), `DeviceRegistry.version: DeviceRegistryVersion` (line 59)                                         |
| `packages/core/src/__tests__/registry.test.ts` | Unit tests for v1->v2 migration and strict v2 validation      | VERIFIED | 8 new tests including: v1 empty ipHash migration, v1 valid ipHash preserved, v2 strict rejects empty/non-hex ipHash, v2 acceptance, v3 still throws |
| `apps/web/src/hooks/useAuth.ts`                | Fixed ipHash value at device registration                     | VERIFIED | `crypto.subtle.digest('SHA-256', new TextEncoder().encode('0.0.0.0'))` then hex encoding (lines 335-341); passed as `ipHash: ipHashHex`             |
| `docs/METADATA_SCHEMAS.md`                     | Updated DeviceRegistry version history                        | VERIFIED | Section 12 header changed to "DeviceRegistry (v1/v2)"; Version History table added with v1 and v2 entries (line 364-369)                            |

### Required Artifacts (Plan 02 — TEST-01, TEST-03)

| Artifact                                               | Expected                                  | Status   | Details                                                                                                                                                                                                   |
| ------------------------------------------------------ | ----------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tests/load/src/harness/client-pool.ts`                | 401 interceptor + createSdkContext helper | VERIFIED | `createSdkContext` exported (line 217), `refreshPromise` coalescing (line 222), `reAuthenticate` (line 191), `fetch(API_URL/auth/test-login)` (line 197)                                                  |
| `tests/load/src/workloads/sdk-core-workload.ts`        | Shared headless workload helpers          | VERIFIED | Exports `prepareSdkClient`, `runIpnsPublishWorkload`, `runUploadPipelineWorkload`, `runFolderReadWorkload`; uses `sdkCore.createAndPublishIpnsRecord`, `sdkCore.uploadFile`, `sdkCore.loadFolderMetadata` |
| `tests/load/src/scenarios/sdk-upload-pipeline.test.ts` | Upload pipeline isolation test            | VERIFIED | Vitest describe/it pattern; calls `runUploadPipelineWorkload`; `expectThresholdsPassed` with `sdkUploadFile` threshold                                                                                    |
| `tests/load/src/scenarios/sdk-ipns-contention.test.ts` | IPNS publish/resolve contention test      | VERIFIED | 10 default clients; calls `runIpnsPublishWorkload`; thresholds for `sdkIpnsPublish` and `sdkIpnsResolve`                                                                                                  |
| `tests/load/src/scenarios/sdk-folder-read.test.ts`     | Folder metadata read path test            | VERIFIED | Calls `runFolderReadWorkload`; `sdkFolderRead` threshold at 4000ms p95                                                                                                                                    |

### Required Artifacts (Plan 03 — TEST-02)

| Artifact                               | Expected                                                    | Status   | Details                                                                                                                                                                                                                                                                       |
| -------------------------------------- | ----------------------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `apps/web/public/recovery.html`        | Simplified recovery tool with only IPFS-direct v2 blob mode | VERIFIED | Zero matches for `panel-export`, `From Export File`, `recovery-method`, `export-file`, `export-text`; 2-step flow (dot-1 "Setup", dot-2 "Recover"); v2 blob logic intact                                                                                                      |
| `tests/web-e2e/tests/recovery.spec.ts` | Playwright E2E test for vault recovery                      | VERIFIED | Seeds vault via `createTestAccount` + `client.uploadFile`; navigates to `/recovery.html`; fills `recovery-key-input`, `recovery-ipfs-gateway`, `recovery-ipns-gateway`; clicks `recovery-start-btn`; asserts progress log contains file name; asserts download button visible |

---

### Key Link Verification

| From                                            | To                                              | Via                                                                | Status | Details                                                                                                     |
| ----------------------------------------------- | ----------------------------------------------- | ------------------------------------------------------------------ | ------ | ----------------------------------------------------------------------------------------------------------- |
| `packages/sdk/src/bin/index.ts`                 | `@cipherbox/sdk-core`                           | `sdkCore.createAndPublishIpnsRecord` + `sdkCore.resolveIpnsRecord` | WIRED  | Both called inside `publishWithVerify` at lines 147 and 157                                                 |
| `packages/core/src/registry/schema.ts`          | `packages/core/src/registry/types.ts`           | `DeviceRegistry` type import                                       | WIRED  | `import type { DeviceRegistry, ... } from './types'` at line 14                                             |
| `tests/load/src/workloads/sdk-core-workload.ts` | `@cipherbox/sdk-core`                           | direct function imports                                            | WIRED  | `import * as sdkCore from '@cipherbox/sdk-core'` at line 8                                                  |
| `tests/load/src/harness/client-pool.ts`         | `/auth/test-login`                              | fetch re-auth on 401                                               | WIRED  | `fetch(\`${API_URL}/auth/test-login\`, ...)`inside`reAuthenticate` at line 197                              |
| `tests/load/src/scenarios/sdk-*.test.ts`        | `tests/load/src/workloads/sdk-core-workload.ts` | workload function imports                                          | WIRED  | All 3 scenarios import from `'../workloads/sdk-core-workload'`                                              |
| `tests/web-e2e/tests/recovery.spec.ts`          | `apps/web/public/recovery.html`                 | `page.goto` with recovery path                                     | WIRED  | `page.goto(\`${WEB_URL}/recovery.html\`)` at line 57                                                        |
| `tests/web-e2e/tests/recovery.spec.ts`          | `tests/sdk-e2e/src/fixtures/test-harness.ts`    | `createTestAccount` for vault seeding                              | WIRED  | `import { createTestAccount, deleteTestAccount } from '../../sdk-e2e/src/fixtures/test-harness'` at line 11 |

---

### Requirements Coverage

| Requirement | Source Plan   | Description                                                                                      | Status    | Evidence                                                                                                                                                                                                                                     |
| ----------- | ------------- | ------------------------------------------------------------------------------------------------ | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| BUGFIX-01   | 24-01-PLAN.md | Bin IPNS name resolves correctly (no 404 errors on recycle bin operations)                       | SATISFIED | `loadBin` auto-repair in `bin/index.ts`; `publishWithVerify` ensures IPNS propagation; unit tests in `bin.test.ts` verify `sequenceNumber: 1` and `createAndPublishIpnsRecord` called on auto-repair                                         |
| BUGFIX-02   | 24-01-PLAN.md | Device registry parses without crypto format errors                                              | SATISFIED | `validateDeviceRegistry` in `schema.ts` accepts v1 with empty `ipHash`, migrates to v2; `useAuth.ts` computes valid SHA-256 hex ipHash; `device-registry.service.ts` creates new registries as v2; unit tests verify migration and strict v2 |
| TEST-01     | 24-02-PLAN.md | Headless Node.js load tests call sdk-core functions directly without Playwright browser overhead | SATISFIED | 3 scenario files + `sdk-core-workload.ts` call sdk-core directly; no `CipherBoxClient` import in any headless test file                                                                                                                      |
| TEST-02     | 24-03-PLAN.md | Vault v2 recovery tool has automated E2E test coverage                                           | SATISFIED | `recovery.spec.ts` is a full Playwright E2E test with SDK-seeded vault and end-to-end recovery verification                                                                                                                                  |
| TEST-03     | 24-02-PLAN.md | Load tests handle 401 responses with automatic token refresh instead of failing                  | SATISFIED | `createSdkContext` in `client-pool.ts` provides `refreshAccessToken` with shared `refreshPromise` coalescing; `reAuthenticate` calls `/auth/test-login`                                                                                      |

All 5 requirement IDs from all 3 plans are accounted for and satisfied. No orphaned requirements found in REQUIREMENTS.md for Phase 24.

---

### Anti-Patterns Found

No anti-patterns detected:

- No TODO/FIXME/placeholder comments in modified files
- No empty return implementations
- No stubs (all implementations are substantive)
- No wiring gaps (all artifacts are imported and used)

---

### Human Verification Required

The following items require live runtime testing and cannot be verified statically:

#### 1. Recovery E2E test passes against live infrastructure

**Test:** Run `cd tests/web-e2e && pnpm test tests/recovery.spec.ts` with API + Kubo IPFS running locally
**Expected:** Test creates account, uploads file, opens recovery.html with private key, IPFS-direct recovery discovers the file name in the progress log
**Why human:** Requires live API + IPFS; IPNS propagation timing; browser JavaScript execution cannot be verified statically

#### 2. Load test 401 interceptor triggers in practice

**Test:** Run a load test scenario with `LOAD_TEST_ACCESS_TOKEN_TTL=1` to force token expiry, observe that the test continues without 401 errors
**Expected:** Expired tokens trigger `reAuthenticate`, load test continues to completion
**Why human:** Requires live API; token refresh only fires when actual 401 HTTP response is received

#### 3. Bin auto-repair works on first real login after DB wipe

**Test:** Log into CipherBox as a new account (no prior bin IPNS record), observe that the recycle bin loads without error
**Expected:** Bin loads with empty state (no 404 error in console); subsequent delete-to-bin succeeds
**Why human:** Requires live API + IPFS; IPNS publishing requires network; can't verify statically

---

### Gaps Summary

No gaps found. All 5 success criteria are met, all artifacts exist with substantive implementations, all key links are wired, all requirement IDs are satisfied.

Notable deviations from plans that were correctly auto-fixed during execution:

1. `apps/web/src/services/device-registry.service.ts` updated to create v2 registries (plan omitted this file but the truth "Device registry always writes v2 format" required it)
2. `sdkCore.uploadFile` parameter signature corrected to actual API (plan proposed incorrect params)
3. `sdkCore.fetchAndDecryptMetadata` usage corrected to `sdkCore.loadFolderMetadata` (plan proposed wrong function for the IPNS-resolve + fetch + decrypt full read path)
4. `@cipherbox/sdk` added to `web-e2e/package.json` devDependencies to enable test harness import

All deviations were necessary for correctness and do not affect goal achievement.

---

_Verified: 2026-03-26_
_Verifier: Claude (gsd-verifier)_
