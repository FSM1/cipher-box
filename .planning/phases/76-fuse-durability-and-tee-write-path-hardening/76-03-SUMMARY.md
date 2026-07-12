---
phase: 76-fuse-durability-and-tee-write-path-hardening
plan: 03
subsystem: tee-write-path
tags: [tee-worker, republish, error-handling, typed-errors, ci, hardening]
status: complete
requires:
  - renewIpnsRecordEol EOL-only CAS write-back (Phase 67 republish.service)
  - getKeypair internal-epoch authority + decryptWithFallback (Phase 67-02 key-manager)
provides:
  - renewIpnsRecordEol real-DB-error vs CAS-miss log-level distinction (error vs debug)
  - TeeKeyUnavailableError typed contract across tee-keys.ts / key-manager.ts
  - republish route per-entry null/non-object guard (no batch 500)
  - apps/tee-worker unit tests wired into the ci.yml Test job
affects:
  - apps/api/src/republish
  - apps/tee-worker/src/services
  - apps/tee-worker/src/routes
  - .github/workflows/ci.yml
tech-stack:
  added: []
  patterns:
    - typed-error instanceof-rethrow (mirrors ReEnrollRequiredError), never error.message string-matching
    - per-entry defense-in-depth guard before the try so the catch never dereferences a null entry
    - real-DB-error at logger.error, harmless CAS-miss stays logger.debug
key-files:
  created: []
  modified:
    - apps/api/src/republish/republish.service.ts
    - apps/api/src/republish/republish.service.spec.ts
    - apps/tee-worker/src/services/tee-keys.ts
    - apps/tee-worker/src/services/key-manager.ts
    - apps/tee-worker/src/routes/republish.ts
    - apps/tee-worker/src/__tests__/key-manager.test.ts
    - apps/tee-worker/src/__tests__/republish.test.ts
    - .github/workflows/ci.yml
decisions:
  - "TeeKeyUnavailableError thrown at getKeypair's two real config/infra guard sites only (simulator-in-production, unexpected DstackClient.getKey shape); NO MIN/MAX epoch throw invented"
  - "decryptWithFallback rethrows TeeKeyUnavailableError wrapped with { cause } from both trial catches; every other error falls through to the next trial unchanged"
  - "renewIpnsRecordEol catch elevated warn->error with a distinct 'DB write-back failed' message; affected===0 CAS-miss stays debug; totalSucceeded accounting untouched"
  - "route null/non-object guard runs BEFORE the try, pushes a per-entry failure with placeholder ipnsName 'unknown', and continues"
  - "null-entry route test added to the EXISTING republish.test.ts (the route's test file) instead of a new republish.route.test.ts, to avoid duplicating the express harness (deviation)"
  - "tee-worker tests wired into CI via a new 'Run TEE Worker tests' step in the existing Test job (RESEARCH open question: in-scope here)"
metrics:
  duration: 25min
  completed: 2026-07-12
  tasks: 3
  files: 8
---

# Phase 76 Plan 03: TEE Republish Write-Path Error-Handling Hardening Summary

One-liner: real DB write-back failures and TEE config/infra misconfigurations stop masquerading as harmless outcomes — `renewIpnsRecordEol` now logs a genuine DB error at `error` level distinct from the `affected===0` CAS-miss debug line, a new typed `TeeKeyUnavailableError` rethrows instead of being masked as a corrupted user key, the republish route survives a null/non-object batch entry without a 500, and the apps/tee-worker suite now runs in CI so all three SC3 regressions turn CI red.

## What Was Built

### Task 1 — renewIpnsRecordEol real-DB-error vs CAS-miss (republish.service.ts) — committed pre-resume

- The `renewIpnsRecordEol` catch branch elevated from `logger.warn` to `logger.error` with a distinct `DB write-back failed` message, clearly separable from the `affected===0` CAS-miss `logger.debug` line.
- Branch stays non-fatal (still returns, never rethrows); `totalSucceeded` accounting at the call site is unchanged (the IPNS publish already succeeded; only write-back observability changed).
- Tests (republish.service.spec.ts): a simulated repository throw logs at error level while the batch still reports success; a CAS miss (`affected===0`) logs at debug (not error) and stays non-fatal.
- This task was committed as `8df830ff7` before this resume session; verified green here.

### Task 2 — TeeKeyUnavailableError typed contract + decryptWithFallback rethrow (tee-keys.ts, key-manager.ts)

- Added `class TeeKeyUnavailableError extends Error` in tee-keys.ts (carries a `keyUnavailable` marker and accepts `{ cause }`), thrown at getKeypair's two real config/infra guard sites: the simulator-in-production guard and the unexpected `DstackClient.getKey()` return-shape guard. NO MIN/MAX epoch-range throw was invented (that check does not exist — RESEARCH Assumption A2).
- `decryptWithFallback` replaced both bare `catch {}` blocks with `catch (err)` blocks that `instanceof`-check `TeeKeyUnavailableError` and rethrow it wrapped with `{ cause }`; any other error (e.g. an epoch mismatch) falls through to the next trial exactly as before. No `error.message` string-matching.
- Tests (key-manager.test.ts): (a) getKeypair stubbed to throw `TeeKeyUnavailableError` -> decryptWithFallback rethrows the typed error with the original preserved as `cause`, and NOT the generic `ECIES decryption failed` message; (b) a genuinely byte-flipped `wrapKey` ciphertext throws a non-`ReEnrollRequiredError`, non-`TeeKeyUnavailableError` generic error. The prior "corrupted key" test was renamed to reflect that it only exercised an epoch mismatch.

### Task 3 — Route null-guard + CI wiring (republish.ts, republish.test.ts, ci.yml)

- Added a per-entry guard at the top of the `for (const entry of entries)` loop, BEFORE the `try`: a `null` or non-object entry pushes a `RepublishResult` failure (`ipnsName: 'unknown'`, `success: false`, `error: 'Invalid entry: expected a non-null object'`) and `continue`s, so the try/catch is never entered for a malformed entry and the catch's `entry.ipnsName` dereference can never hit a null.
- Test: a batch with `null` and a non-object string interleaved with a valid entry returns a 3-element mixed results array (200, no throw / no 500) — the valid entry processes normally, the two malformed entries become per-entry failures.
- CI: added a `Run TEE Worker tests` step (`pnpm --filter cipherbox-tee-worker test`) to the existing ci.yml Test job so all three SC3 test suites now gate CI. The crypto/core dist builds needed by the tee-worker tests already run in that job's build step.

## Deviations from Plan

### 1. Null-entry route test added to existing republish.test.ts, not a new republish.route.test.ts

- **Plan artifact named:** `apps/tee-worker/src/__tests__/republish.route.test.ts` (a new file).
- **What was done:** The route already has a dedicated test file, `republish.test.ts`, with the full express harness (`postJson` / `createTestApp` / `makeEntry`). The null/non-object defense-in-depth test was added there instead of duplicating the entire harness in a second file.
- **Rationale:** Global "prefer editing an existing file over creating a new one" rule + DRY; the plan's `verify` command `pnpm --filter cipherbox-tee-worker test -- republish` matches `republish.test.ts` identically. No behavior or coverage lost.

### 2. tee-worker CI wiring is a discrete Test-job step, not a package-list entry

- The plan described adding `apps/tee-worker` to "the Test job's package list". That job does not use a single shared filter list — it has one `run:` step per package (API, crypto, core, sdk-core, sdk, api-client). Followed the existing shape: added one `Run TEE Worker tests` step. Same net effect (`pnpm --filter cipherbox-tee-worker test` now runs in CI); no workflow restructuring.

## Threat Model Mitigations Applied

- **T-76-07 (Repudiation, EOL write-back):** a real DB error now logs at `error` level with a distinct message; CAS-miss stays `debug`; batch success accounting unchanged (Task 1).
- **T-76-08 (DoS, republish batch loop):** per-entry null/non-object guard prevents a single malformed entry from 500-ing the batch (Task 3).
- **T-76-09 (Tampering, key-decrypt error classification):** typed `TeeKeyUnavailableError` instanceof-rethrow prevents masking an infra misconfig as a corrupted key; no `error.message` string-matching (Task 2).
- **T-76-10 (Info disclosure, TEE error paths):** the new error class names config/infra conditions only — no key bytes in messages, causes, or logs (Task 2/3).

## Verification

- `pnpm --filter cipherbox-tee-worker test` — 6 test files passed, 79 tests passed (8 todo). Includes the new TeeKeyUnavailableError-rethrow, genuine-corruption, and null-entry cases.
- `pnpm --filter @cipherbox/api test -- republish.service` — 42 passed, incl. the error-level DB-error and debug-level CAS-miss assertions.
- `pnpm --filter cipherbox-tee-worker build` (tsc) — clean after building the `@cipherbox/crypto`, `@cipherbox/core`, `@cipherbox/sdk-core` dists (cross-package dist staleness only; not a code error).
- ci.yml Test job now runs `pnpm --filter cipherbox-tee-worker test`.
- No new external dependency added. TypeScript string literals used; no enums.

## Commits

- 8df830ff7: fix(api): surface real DB write-back errors in renewIpnsRecordEol at error level (Task 1, committed pre-resume)
- 26c1e1694: fix(tee-worker): rethrow typed TeeKeyUnavailableError instead of masking config failures as corrupted keys (Task 2)
- 9b6ab2dc4: fix(tee-worker): guard republish batch against null entries and wire tee-worker tests into CI (Task 3)

## Self-Check: PASSED

- SUMMARY file present on disk.
- All three commits (8df830ff7, 26c1e1694, 9b6ab2dc4) present in git history.
- All SC3-items-1/2/3 tests pass and now run in CI.
