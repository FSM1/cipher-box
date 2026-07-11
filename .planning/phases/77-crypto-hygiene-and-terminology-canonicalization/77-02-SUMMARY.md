---
phase: 77-crypto-hygiene-and-terminology-canonicalization
plan: 02
subsystem: crypto
tags: [aes, zeroization, memory-hygiene, tdd]

# Dependency graph
requires: []
provides:
  - "importAesKey(key, algorithm, usages) shared internal AES key-import helper (packages/crypto/src/aes/import-key.ts)"
  - "All 7 AES-GCM/AES-CTR key imports zeroize their local key-plaintext copy after crypto.subtle.importKey consumes it"
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Terminal-owner zeroization: a helper that allocates its own copy of a caller-owned buffer zeroes only that local copy in a finally block, never the caller's argument (D-09)"

key-files:
  created:
    - packages/crypto/src/aes/import-key.ts
  modified:
    - packages/crypto/src/aes/index.ts
    - packages/crypto/src/aes/encrypt.ts
    - packages/crypto/src/aes/decrypt.ts
    - packages/crypto/src/aes/encrypt-ctr.ts
    - packages/crypto/src/aes/decrypt-ctr.ts
    - packages/crypto/src/__tests__/aes.test.ts

key-decisions:
  - "importAesKey's algorithm param typed as AlgorithmIdentifier (not AesKeyAlgorithm) — AesKeyAlgorithm requires a `length` field that the existing GCM/CTR call sites never supplied, so it does not match the { name: string } literal already in use at every call site (Rule 1 fix, tsc build error)"
  - "importAesKey exported from the aes/ barrel only (not the top-level package index) per the plan's internal-helper scoping"

patterns-established:
  - "Shared key-import helper as the single zeroization choke point for a crypto module — future symmetric-key helpers in this package should route through the same pattern rather than duplicating an inline copy+importKey block"

requirements-completed: [SC1]

coverage:
  - id: T-77-02a
    description: "un-zeroed local key-plaintext copy lingering in heap after importKey (memory-dump exposure)"
    requirement: "SC1"
    verification:
      - kind: unit
        ref: "packages/crypto/src/aes/import-key.ts — finally block calls keyView.fill(0)"
        status: pass
      - kind: other
        ref: "grep -n \"finally\" packages/crypto/src/aes/import-key.ts"
        status: pass
    human_judgment: false
  - id: T-77-02b
    description: "accidental zeroization of the caller-owned key (D-09 violation)"
    requirement: "SC1"
    verification:
      - kind: unit
        ref: "packages/crypto/src/__tests__/aes.test.ts#importAesKey > leaves the caller-supplied key argument byte-for-byte unchanged (D-09)"
        status: pass
    human_judgment: false
  - id: T-77-02c
    description: "refactor silently alters encrypt/decrypt output"
    requirement: "SC1"
    verification:
      - kind: unit
        ref: "packages/crypto/src/__tests__/aes.test.ts and aes-ctr.test.ts full round-trip suites (207 tests total)"
        status: pass
    human_judgment: false

duration: ~5min
completed: 2026-07-11
status: complete
---

# Phase 77 Plan 02: AES Key-Import Zeroization Summary

**Extracted a single `importAesKey()` helper that owns and zeroes its local copy of the caller's AES key in a `finally` block, and routed all 7 AES-GCM/AES-CTR functions through it — closing the memory-exposure window on every AES key import with no behavior change.**

## Performance

- **Duration:** ~5 min (commit-to-commit)
- **Completed:** 2026-07-11T10:21:18+02:00
- **Tasks:** 2 (Task 1: TDD RED → GREEN for the helper; Task 2: routing refactor)
- **Files modified:** 6 (1 created, 5 modified)

## Accomplishments

- Added `packages/crypto/src/aes/import-key.ts` exporting `importAesKey(key, algorithm, usages)`: allocates a local `keyView` copy, calls `crypto.subtle.importKey` in a `try`, and `keyView.fill(0)` in a `finally` — the caller's `key` argument is never read after copying and never mutated (D-09).
- Exported `importAesKey` from the `aes/` barrel (`packages/crypto/src/aes/index.ts`) for test access only; it is intentionally not re-exported from the top-level `packages/crypto/src/index.ts`.
- Extended `packages/crypto/src/__tests__/aes.test.ts` with two new assertions: a caller-key-unchanged aliasing check (clone-and-compare after `importAesKey`), and a round-trip parity check (import via the helper, encrypt with the raw `crypto.subtle` API, decrypt via the existing public `decryptAesGcm`).
- Routed all 7 functions through the helper: `encryptAesGcm`, `encryptAesGcmAad` (encrypt.ts); `decryptAesGcm`, `decryptAesGcmAad` (decrypt.ts); `encryptAesCtr` (encrypt-ctr.ts); `decryptAesCtr`, `decryptAesCtrRange` (decrypt-ctr.ts) — removing the inline `const keyBuffer = new Uint8Array(key).buffer` copy + `crypto.subtle.importKey` block from each and replacing it with a one-line `importAesKey(key, { name: ... }, [...])` call. No IV/counter/AAD/tag/range logic touched.
- `packages/crypto/src/aes/seal.ts` left untouched (it has no independent key copy — it delegates to the encrypt/decrypt functions above).

## Task Commits

Each task was committed atomically:

1. **Task 1: importAesKey helper + aliasing/parity tests (RED)** - `8e4deea80` (test)
2. **Task 1: importAesKey helper + aliasing/parity tests (GREEN)** - `0dc988e52` (feat)
3. **Task 2: Route all 7 AES functions through importAesKey** - `5c99e1401` (refactor)

_TDD plan: Task 1 was RED (test) → GREEN (feat); Task 2 (routing) required no new behavior tests — the existing `aes.test.ts` + `aes-ctr.test.ts` round-trip suites are the no-behavior-change gate, confirmed green after the refactor._

## Files Created/Modified

- `packages/crypto/src/aes/import-key.ts` - New `importAesKey` helper; owns + zeroes its local key copy in a `finally` block
- `packages/crypto/src/aes/index.ts` - Barrel export added for `importAesKey` (internal/test access only)
- `packages/crypto/src/aes/encrypt.ts` - `encryptAesGcm`, `encryptAesGcmAad` now import their key via `importAesKey`
- `packages/crypto/src/aes/decrypt.ts` - `decryptAesGcm`, `decryptAesGcmAad` now import their key via `importAesKey`
- `packages/crypto/src/aes/encrypt-ctr.ts` - `encryptAesCtr` now imports its key via `importAesKey`
- `packages/crypto/src/aes/decrypt-ctr.ts` - `decryptAesCtr`, `decryptAesCtrRange` now import their key via `importAesKey`
- `packages/crypto/src/__tests__/aes.test.ts` - Added `importAesKey` aliasing + round-trip parity test suite

## Decisions Made

- Typed `importAesKey`'s `algorithm` parameter as `AlgorithmIdentifier` rather than the plan's suggested `AesKeyAlgorithm | string`. `AesKeyAlgorithm` requires a `length` field; every existing call site passes only `{ name: AES_GCM_ALGORITHM }` / `{ name: AES_CTR_ALGORITHM }`, which is the `Algorithm` shape (`AlgorithmIdentifier = string | Algorithm`). Using `AesKeyAlgorithm` broke the build with 7 `tsc` errors during Task 2; `AlgorithmIdentifier` is the correct Web Crypto type for `importKey`'s algorithm parameter and matches every call site with no other change. (Rule 1 — bug fix, build error.)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `AesKeyAlgorithm` type too strict for existing call-site algorithm objects**
- **Found during:** Task 2 (`pnpm --filter @cipherbox/crypto build`)
- **Issue:** The plan's suggested signature `importAesKey(key, algorithm: AesKeyAlgorithm | string, usages)` fails to typecheck because `AesKeyAlgorithm` requires a `length: number` field, but all 7 call sites pass only `{ name: 'AES-GCM' }` / `{ name: 'AES-CTR' }` (no `length`) — the same object shape the inline `crypto.subtle.importKey` calls used before the refactor.
- **Fix:** Changed the `algorithm` parameter type to `AlgorithmIdentifier` (`string | Algorithm`, where `Algorithm = { name: string }`), which is what `crypto.subtle.importKey` actually accepts and matches every existing call site with zero changes to the call sites themselves.
- **Files modified:** `packages/crypto/src/aes/import-key.ts`
- **Commit:** `5c99e1401`

Otherwise plan executed exactly as written.

## Issues Encountered

None beyond the type-signature fix above.

## Verification Evidence

- RED confirmed: with `import-key.ts` temporarily removed, `pnpm --filter @cipherbox/crypto test -- aes.test.ts` failed with "Cannot find module './import-key'" (3 test files failed to load: aes.test.ts, aes-ctr.test.ts, build-node-aad.test.ts — all import from the `aes` barrel).
- GREEN confirmed: after restoring `import-key.ts`, all 207 crypto package tests pass (32 in `aes.test.ts`, up from 30 baseline — the 2 new `importAesKey` assertions).
- After Task 2 routing: `pnpm --filter @cipherbox/crypto build` and `pnpm --filter @cipherbox/crypto typecheck` both exit 0; `pnpm --filter @cipherbox/crypto test -- aes.test.ts aes-ctr.test.ts` exits 0 (207 tests, all pass, byte-identical round-trip output preserved).
- `grep -rc "importAesKey" packages/crypto/src/aes/{encrypt,decrypt,encrypt-ctr,decrypt-ctr}.ts` — each file >= 1 (3, 2, 3, 3 respectively).
- `grep -rn "new Uint8Array(key).buffer" packages/crypto/src/aes/{encrypt,decrypt,encrypt-ctr,decrypt-ctr}.ts` — zero matches (no leftover inline copy).
- `git diff --stat packages/crypto/src/aes/seal.ts` — empty (seal.ts untouched).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `importAesKey` is the single choke point for AES key import in `@cipherbox/crypto`; any future AES helper should route through it rather than duplicating an inline copy+importKey block.
- No blockers for subsequent Phase 77 plans.

---
*Phase: 77-crypto-hygiene-and-terminology-canonicalization*
*Completed: 2026-07-11*

## Self-Check: PASSED

All created/modified files and all task commit hashes verified present on disk and in git log.
