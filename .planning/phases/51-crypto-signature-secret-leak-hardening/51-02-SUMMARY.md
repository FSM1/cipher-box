---
phase: 51-crypto-signature-secret-leak-hardening
plan: "02"
subsystem: web-ipns-service
tags: [security, tdd, ipns, signature-verification, fail-closed]
dependency_graph:
  requires: []
  provides: [web-ipns-fail-closed-resolve]
  affects: [apps/web/src/services/ipns.service.ts]
tech_stack:
  added: []
  patterns: [fail-closed verification, TDD red-green, vi.mock top-level import pattern]
key_files:
  created:
    - apps/web/src/services/__tests__/ipns.service.test.ts
  modified:
    - apps/web/src/services/ipns.service.ts
decisions:
  - "Used top-level namespace import (`import * as apiClient`) instead of dynamic `await import()` in test bodies to avoid dist-not-built resolution failure with vitest"
  - "Built @cipherbox/api-client and @cipherbox/core dists before running tests (worktree missing builds)"
  - "Did not change outer 404 catch — verified it remains narrow (status === 404 only)"
metrics:
  duration: ~10 minutes
  completed: 2026-06-19
  tasks_completed: 3
  files_modified: 2
---

# Phase 51 Plan 02: Web IPNS Fail-Closed Resolve Summary

Web `resolveIpnsRecord` now mirrors the canonical sdk-core behavior: throw on present-but-invalid signature and on pubKey-to-name mismatch; allow+flag (`signatureVerified=false`) when signature fields absent; 404 still maps to null.

## What Was Built

Rewrote the inner verification block of `resolveIpnsRecord` in `apps/web/src/services/ipns.service.ts`:

- Removed the swallowing `try/catch` that called `logger.warn` and returned the CID on verification failure
- Added `throw new Error('IPNS signature verification failed - record may be tampered')` when `verifyIpnsSignature` returns false (D-02)
- Added `throw new Error('IPNS public key does not match requested name - possible key substitution')` on name mismatch (D-02)
- Preserved D-03 `logger.warn` + `signatureVerified=false` path for absent signature fields
- Left the outer `catch (error)` with `status === 404` gate completely unchanged

Created `apps/web/src/services/__tests__/ipns.service.test.ts` with 6 vitest cases covering all four required behaviors.

## Test Results

All 6 tests pass (GREEN). 60 total tests pass in the web suite.

- Test 1: present-but-invalid signature throws (D-02) — PASS
- Test 2: pubKey-to-name mismatch throws (D-02) — PASS
- Test 3: absent fields returns `signatureVerified=false` without throw (D-03) — PASS
- Test 4: valid signature returns `signatureVerified=true` — PASS
- Test 5: 404 maps to null (narrow catch preserved) — PASS
- Test 6: non-404 error propagates — PASS

Typecheck: `tsc --noEmit` exits 0 (no new type errors).

## Commits

| Task | Type | Hash | Description |
| ---- | ---- | ---- | ----------- |
| 1 RED | test | df35c5bdc | test 51-02: add failing web ipns.service resolve tests RED |
| 2 GREEN | feat | 6669f6567 | feat 51-02: make web resolveIpnsRecord fail-closed on invalid signatures |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Missing package dist builds in worktree**

- **Found during:** Task 1 RED — vitest could not resolve `@cipherbox/api-client` and `@cipherbox/core` entry points
- **Issue:** Worktree missing built dists for `@cipherbox/api-client` and `@cipherbox/core`
- **Fix:** Ran `pnpm --filter @cipherbox/api-client build` and `pnpm --filter @cipherbox/core build` to produce dist files
- **Files modified:** None (dist output not committed — gitignored)

**2. [Rule 3 - Blocking] Dynamic import pattern incompatible with unbuilt packages**

- **Found during:** Task 1 RED — dynamic `await import('@cipherbox/api-client')` inside test bodies failed even with `vi.mock` hoisted
- **Issue:** `vi.mock` hoisting intercepts module factory but vitest's vite resolver still tries to stat the package entry point before loading the mock; without a built dist this throws at collection time
- **Fix:** Changed test pattern from dynamic `await import()` inside tests to top-level `import * as apiClient from '@cipherbox/api-client'` and `import * as crypto from '@cipherbox/crypto'`, using `vi.mocked(apiClient.fn)` in each test body. This is equivalent and standard — `vi.mock` at top-level still hoists and intercepts correctly
- **Files modified:** `apps/web/src/services/__tests__/ipns.service.test.ts`

## TDD Gate Compliance

- RED commit (`test 51-02: ...`) exists before GREEN commit
- GREEN commit (`feat 51-02: ...`) follows RED commit
- No REFACTOR needed — implementation was clean in single pass

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced. The rewrite is a pure behavioral correction within the existing `resolveIpnsRecord` function boundary.

Threat mitigations from plan threat register applied:

| Threat ID | Status | Notes |
| --------- | ------ | ----- |
| T-51-04 | Mitigated | throw on present-but-invalid signature (was logger.warn + return) |
| T-51-05 | Mitigated | throw on pubKey-to-name mismatch (was logger.warn + return) |
| T-51-06 | Accepted | absent-fields allow+flag preserved (D-03 backward-compat) |

## Self-Check: PASSED

- `apps/web/src/services/__tests__/ipns.service.test.ts` exists: confirmed
- `apps/web/src/services/ipns.service.ts` contains `throw new Error`: confirmed (2 occurrences in resolveIpnsRecord)
- Outer catch narrows to `status === 404`: confirmed via grep
- Commits df35c5bdc and 6669f6567 exist: confirmed via git log
- All 60 web tests pass: confirmed
- `tsc --noEmit` passes: confirmed
