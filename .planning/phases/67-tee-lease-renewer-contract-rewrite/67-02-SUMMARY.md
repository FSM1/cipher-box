---
phase: 67-tee-lease-renewer-contract-rewrite
plan: "02"
subsystem: tee-worker
tags: [security, tee, epoch, key-management, tdd]
dependency_graph:
  requires: [67-01]
  provides: [getInternalCurrentEpoch, ReEnrollRequiredError, decryptWithFallback-2arg]
  affects: [apps/tee-worker/src/services/tee-keys.ts, apps/tee-worker/src/services/key-manager.ts]
tech_stack:
  added: []
  patterns: [clock-based epoch derivation, hard stale floor, structured error signal]
key_files:
  created: []
  modified:
    - apps/tee-worker/src/services/tee-keys.ts
    - apps/tee-worker/src/services/key-manager.ts
    - apps/tee-worker/src/__tests__/tee-keys.test.ts
    - apps/tee-worker/src/__tests__/key-manager.test.ts
decisions:
  - "Option-B epoch resolution: keyEpoch stays the ECIES decrypt hint; getInternalCurrentEpoch() used only for stale floor guard and mid-rotation fallback target"
  - "EPOCH_DURATION_MS = 4 weeks constant exported from tee-keys.ts for test reuse"
  - "getInternalCurrentEpoch() reads process.env.EPOCH_ZERO_TIMESTAMP_MS at call time (not module load) for testability"
  - "ReEnrollRequiredError message names both keyEpoch and currentEpoch integers — no key material"
  - "Fallback trial order: keyEpoch first, then internalCurrentEpoch (mid-rotation case)"
metrics:
  duration: "8 minutes"
  completed: "2026-07-01"
  tasks_completed: 2
  files_modified: 4
status: complete
---

# Phase 67 Plan 02: TEE Epoch Self-Derivation and Stale-Key Guard Summary

TEE derives `currentEpoch` from its own clock via `getInternalCurrentEpoch()` and refuses to renew keys older than `currentEpoch − 1`, emitting a structured `ReEnrollRequiredError` with no key material.

## Tasks Completed

### Task 1: getInternalCurrentEpoch() clock-based epoch derivation (RED→GREEN)

Added `EPOCH_DURATION_MS` (4-week constant) and `getInternalCurrentEpoch()` to `tee-keys.ts`. The function reads `EPOCH_ZERO_TIMESTAMP_MS` from the environment at call time (not module load), returns `MIN_EPOCH` (1) when the anchor is absent or in the future, and clamps via `Math.max(MIN_EPOCH, ...)`. Never reads a relay-supplied scalar.

Commits:
- `02e4c9552` — test(67-02): RED — 3 failing tests for getInternalCurrentEpoch
- `8852e05fe` — feat(67-02): GREEN — getInternalCurrentEpoch implementation

### Task 2: Reshape decryptWithFallback + ReEnrollRequiredError stale guard (RED→GREEN)

Reshaped `decryptWithFallback` from 3-arg `(encryptedIpnsKey, currentEpoch, previousEpoch)` to 2-arg `(encryptedIpnsKey, keyEpoch)`. Added `ReEnrollRequiredError` class. The new body derives `internalCurrentEpoch` internally, throws `ReEnrollRequiredError` BEFORE any unwrap when `keyEpoch < internalCurrentEpoch - 1`, then tries `keyEpoch` and falls through to `internalCurrentEpoch` on miss.

Commits:
- `5c258d07a` — test(67-02): RED — 6 failing tests for new API and ReEnrollRequiredError
- `5f6ae0aa7` — feat(67-02): GREEN — reshaped decryptWithFallback + ReEnrollRequiredError

## Verification

`pnpm --filter cipherbox-tee-worker test` final run: **64 passed, 1 failed, 8 todo**.

The 1 failure is in `src/__tests__/republish.test.ts > republish route > processes batch entries independently`. This is an EXPECTED mid-rewrite failure per the critical phase context. The `republish.ts` route (rewritten in plan 67-06) still calls `decryptWithFallback` with the old 3-arg signature. With the new 2-arg implementation, the previously-failing batch entry (tested with wrong-epoch credentials) now decrypts via `getInternalCurrentEpoch() = 1` (no `EPOCH_ZERO_TIMESTAMP_MS` set in tests). No action taken — do NOT touch `republish.ts` or `republish.test.ts` in this plan.

Suites that are clean (4 of 5 files pass):
- `tee-keys.test.ts` — all 15 tests pass (12 existing + 3 new epoch-derivation cases)
- `key-manager.test.ts` — all 14 tests pass (3 decryptIpnsKey + 8 new decryptWithFallback + 3 reEncryptForEpoch)
- `ipns-signer.test.ts` — unchanged, passes
- `tee.test.ts` — unchanged, passes

## Security Invariants Satisfied

| Threat | Mitigation | Verified |
|--------|-----------|---------|
| T-67-02-E: relay-supplied currentEpoch elevation | `getInternalCurrentEpoch()` never reads relay scalar | grep returns nothing for `relay` in implementation logic |
| T-67-02-E2: stale epoch-N-2 key survival | `keyEpoch < internalCurrentEpoch-1` throws BEFORE any `decryptIpnsKey` call | spy test asserts `getKeypair` call-count 0 |
| T-67-02-I: key bytes in error message | Message contains epoch integers only | test asserts no `/[0-9a-f]{32,}/i` match |

## Deviations from Plan

### Rule 1 - Bug: error message missing currentEpoch integer

**Found during:** Task 2 GREEN verification
**Issue:** Initial message was `...older than currentEpoch-1 (${currentEpoch - 1})` which contained `9` but not `10` (the actual currentEpoch). The test `ReEnrollRequiredError message names epoch integers and no key material` asserted both `/8/` and `/10/` match.
**Fix:** Changed to `...older than grace floor ${currentEpoch - 1} (current epoch: ${currentEpoch})` — now names both the grace floor and the actual currentEpoch.
**Files modified:** `apps/tee-worker/src/services/key-manager.ts`
**Commit:** Part of `5f6ae0aa7`

### Accepted deviation: `pnpm --filter cipherbox-tee-worker test` exits 1

**Source:** Critical phase context supersedes plan acceptance criterion "`pnpm --filter cipherbox-tee-worker test` exits 0 (no other suite regressed)".
The `republish.test.ts` failure is explicitly called out as expected mid-rewrite state. This is not a regression in scope — it is the documented consequence of removing the 3-arg relay-epoch signature that `republish.ts` (plan 67-06) still uses.

## Known Stubs

None. All new code paths are fully implemented and tested.

## Threat Flags

No new network endpoints, auth paths, or schema changes introduced by this plan.

## Self-Check: PASSED

All 4 modified files found on disk. All 4 task commits verified in git log.
