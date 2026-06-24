---
phase: 60-ipns-verification-cross-layer-closeout-desktop-and-api
plan: "03"
subsystem: sdk-core/ipns
tags: [security, ipns, verification, strict-mode, tdd]
dependency_graph:
  requires: [60-01, 60-02]
  provides: [strict-ts-resolve-contract]
  affects: [sdk-core, apps/web]
tech_stack:
  added: []
  patterns: [fail-closed, tdd-red-green, cbor-validity-check]
key_files:
  created: []
  modified:
    - packages/sdk-core/src/ipns/index.ts
    - packages/sdk-core/src/__tests__/ipns.test.ts
    - packages/sdk-core/src/__tests__/vault.test.ts
decisions:
  - "D-05: resolveIpnsRecord throws on absent sig fields (fail closed); signatureVerified:false return state eliminated"
  - "D-05: Skew disjunct (embedded=0, resp=1) removed; strict equality only (producers unified to embed 1 in Plan 60-02)"
  - "D-07: CBOR Validity field parsed after CBOR decode; 5-minute skew buffer applied (mirrors Rust Plan 60-01 semantics)"
  - "Rule 1: vault.test.ts expectation updated from 0n to 1n (stale after Plan 60-02 changed publishVaultKeyBlob)"
  - "Blast-radius audit: no consumers read signatureVerified as non-throwing success indicator; all call sites propagate thrown errors as failures"
metrics:
  duration: 9min
  completed: "2026-06-24"
  tasks: 2
  files: 3
---

# Phase 60 Plan 03: Strict TS Resolve Fail-Closed Summary

**One-liner:** TS `resolveIpnsRecord` converted to strict fail-closed: absent-sig throws (D-05), skew disjunct removed (D-05), CBOR Validity EOL enforced with 5-min buffer (D-07).

## Tasks Completed

### Task 1: Strict TS resolve throw-path + EOL expiry (TDD)

RED commit `e517eb42e`: 4 new tests expressing strict D-05/D-07 behavior — all 3 behavioral tests
fail against the old implementation. Also fixed stale vault test (0n → 1n) from Plan 60-02.

GREEN commit `36b214baa`: Implementation changes to `resolveIpnsRecord`:

1. **D-05 — legacy else deleted:** The `else { console.warn('IPNS resolve returned without
   signature data, skipping verification'); }` branch is removed. When all three sig fields are
   absent, the new path throws `'IPNS resolve returned without signature fields — fail closed'`.
   The result can no longer carry `signatureVerified: false` as a non-error state.

2. **D-05 — skew disjunct removed:** The sequence binding check was:
   `seqOk = embedded === resp || (resp === 1n && embedded === 0n)`
   Now: `seqOk = embedded === resp` — strict equality only. Since Plan 60-02 unified all
   first-publish producers to embed sequence 1, the skew window no longer exists.

3. **D-07 — CBOR Validity EOL enforcement:** After CBOR decode of the `data` field (already
   decoded for CID/seq binding), `cborFields['Validity']` is read as `Uint8Array`, decoded as
   UTF-8 RFC3339 timestamp, and compared to `Date.now() - 300000ms` (5-min skew buffer). A
   present-but-unparseable Validity is fail-closed (throws). Mirrors the Rust Plan 60-01
   `decode_ipns_cbor_validity` semantics with the same 5-minute buffer.

Updated existing tests that relied on old behavior:

- `accepts first-publish skew (D-09)` → now `throws on first-publish skew (D-05 strict)`
- `legacy record is NOT subjected to CBOR binding (D-04)` → now `throws when all sig fields absent (D-05 fail closed)`
- `first-publish-skew vector` → now expects `rejects.toThrow(/sequence binding mismatch/)`
- `legacy-absent vector` → now expects `rejects.toThrow(/fail closed|signature fields/)`
- `resolves IPNS name and returns CID` → updated to provide a properly-signed response (D-05 means unsigned records throw)

### Task 2: Blast-Radius Consumer Audit

Grep scope: `packages/sdk-core/src` + `apps/web/src`, excluding test files.

#### Non-test `resolveIpnsRecord` / `signatureVerified` consumers

| File | Lines | Disposition | Reason |
|------|-------|-------------|--------|
| `packages/sdk-core/src/cas.ts` | 102 | audited-no-change | Uses `resolved.sequenceNumber`/`resolved.cid` only; thrown error propagates to CAS retry callers which have error handling |
| `packages/sdk-core/src/file/index.ts` | 198, 281 | audited-no-change | Uses `resolved.cid`/`resolved.sequenceNumber`; no `signatureVerified` read; callers have try/catch |
| `packages/sdk-core/src/folder/load.ts` | 61 | audited-no-change | Uses `resolved.cid`/`resolved.sequenceNumber`; no `signatureVerified` read |
| `packages/sdk-core/src/vault/index.ts` | 77 | audited-no-change | Uses `resolved.cid` only; no `signatureVerified` read |
| `apps/web/src/services/ipns.service.ts` | 144-152 | audited-no-change | Thin pass-through wrapper; type signature includes `signatureVerified: boolean` (type annotation only, not read) |
| `apps/web/src/components/settings/StorageTab.tsx` | 121, 188 | audited-no-change | Both calls inside `try { ... } catch { ... }` — thrown verification error treated as "no saved config" (safe conservative fallback) |
| `apps/web/src/components/file-browser/useFileBrowserActions.ts` | 112 | audited-no-change | Inside try/catch; error propagates to UI error handler |
| `apps/web/src/components/file-browser/DetailsDialog.tsx` | 67 | audited-no-change | Inside try/catch via React effect |
| `apps/web/src/components/file-browser/ShareDialog.tsx` | 262 | audited-no-change | Inside try/catch; error surfaces as save failure |
| `apps/web/src/hooks/useSharedNavigationActions.ts` | 113, 248, 516 | audited-no-change | All three inside try/catch (lines 104, 242, 511 respectively) |
| `apps/web/src/hooks/useAuth.ts` | 151, 245 | audited-no-change | Inside `doInit` async; callers catch and surface auth failure |
| `apps/web/src/hooks/folder-helpers.ts` | 21 | audited-no-change | Function is async; callers have error handling |
| `apps/web/src/services/file-metadata.service.ts` | 216, 320 | audited-no-change | No local try/catch; thrown error propagates to callers which are all inside try/catch blocks (TextEditorDialog, DetailsDialog, ShareDialog) |
| `apps/web/src/lib/crypto/key-wrapping.ts` | 128 | audited-no-change | Inside broader try/catch for key unwrap flow |
| `apps/web/src/services/device-registry.service.ts` | 63, 194 | audited-no-change | Registry init is non-blocking fire-and-forget with catch handler |
| `apps/web/src/services/invite.service.ts` | 139 | audited-no-change | Inside try/catch; invite load fails gracefully |
| `apps/web/src/services/vault-settings.service.ts` | 42, 112 | audited-no-change | Callers have error handling |

**Verdict:** No category-(b) sites found. No consumer reads `signatureVerified` as a runtime decision-making value. All call sites either sit in try/catch blocks or propagate errors to callers with proper error handling.

**Follow-up note (non-blocking):** The return type `{ signatureVerified: boolean }` in `apps/web/src/services/ipns.service.ts:146` still declares the field, but after D-05 it is always `true` (the `false` case now throws). This is a type hygiene item — safe since no consumer reads it — deferred to a cleanup pass.

## Acceptance Criteria

- `grep -n "skipping verification" packages/sdk-core/src/ipns/index.ts` → no matches (PASS)
- `grep -n "responseSeqBigInt === 1n && embeddedSeqBigInt === 0n" packages/sdk-core/src/ipns/index.ts` → no matches (PASS)
- `grep -n "Validity" packages/sdk-core/src/ipns/index.ts` → shows expiry check at lines 286-298 (PASS)
- `pnpm --filter @cipherbox/sdk-core test -- ipns` → 34 tests PASS, including all 4 new throw-path tests (PASS)
- `pnpm --filter @cipherbox/sdk-core test` → 251 tests PASS, no consumer regressions (PASS)
- `pnpm --filter @cipherbox/sdk-core build` → build success (PASS)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Stale vault test expectation (0n vs 1n)**

- **Found during:** Task 1 RED phase (running tests)
- **Issue:** `vault.test.ts` expected `createAndPublishIpnsRecord` to be called with `sequenceNumber: 0n`, but Plan 60-02 changed `publishVaultKeyBlob` to embed `1n`. The test was stale.
- **Fix:** Updated `vault.test.ts:139` expectation to `1n`.
- **Files modified:** `packages/sdk-core/src/__tests__/vault.test.ts`
- **Commit:** `e517eb42e`

**2. [Rule 1 - Bug] Existing `resolves IPNS name` test used unsigned response**

- **Found during:** Task 1 GREEN phase (implementing D-05)
- **Issue:** The baseline `resolves IPNS name and returns CID with sequence number` test mocked a response with no signature fields — after D-05 this throws instead of returning. The test needed to be updated to provide a signed response.
- **Fix:** Updated test to provide CBOR-encoded `data` field with matching cid/seq and future Validity, plus mock `verifyEd25519`/`deriveIpnsName`.
- **Files modified:** `packages/sdk-core/src/__tests__/ipns.test.ts`
- **Commit:** `36b214baa`

## Known Stubs

None. All changes are behavioral — no placeholder data or deferred wiring.

## Threat Flags

None. All changes are within the plan's threat model (T-60-08, T-60-09, T-60-10, T-60-11 all mitigated).

## Self-Check: PASSED

- `packages/sdk-core/src/ipns/index.ts` exists: FOUND
- `packages/sdk-core/src/__tests__/ipns.test.ts` exists: FOUND
- Commit `e517eb42e` exists: FOUND
- Commit `36b214baa` exists: FOUND
- 251 tests pass: CONFIRMED
