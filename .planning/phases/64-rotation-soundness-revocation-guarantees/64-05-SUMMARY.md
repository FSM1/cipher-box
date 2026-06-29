---
phase: 64-rotation-soundness-revocation-guarantees
plan: "05"
subsystem: sdk-core/rotation
tags: [tdd, ecies, grant-remint, rot-04, high-3, d-04]
dependency_graph:
  requires: [64-04]
  provides: [reMintGrantsRootedAt-filled, GrantRemintCallbacks-type]
  affects: [packages/sdk-core/src/rotation/engine.ts]
tech_stack:
  added: []
  patterns: [transport-decoupled-callbacks, ecies-wrapkey, tdd-red-green]
key_files:
  created:
    - packages/sdk-core/src/__tests__/rotation/grant-remint.test.ts
  modified:
    - packages/sdk-core/src/rotation/engine.ts
    - packages/sdk-core/src/__tests__/rotation/engine.test.ts
decisions:
  - reMintGrantsRootedAt uses ECIES wrapKey + bytesToBase64 for readDescriptorRef encoding
  - GrantRemintCallbacks type exported for host injection in Phase 66
  - Local bytesToBase64 helper added to engine.ts (dedup with share/grant.ts deferred per CONTEXT.md)
  - engine.test.ts Phase-63 seam-throw test updated to reflect filled seam
metrics:
  duration: "5 minutes"
  completed: "2026-06-29"
  tasks_completed: 1
  files_changed: 3
status: complete
---

# Phase 64 Plan 05: Inner-Grant Re-Mint Summary

Filled the `reMintGrantsRootedAt` seam (ROT-04/HIGH-3/D-04) in `packages/sdk-core/src/rotation/engine.ts`. The function now enumerates grants via injected callbacks, ECIES-re-wraps `readDescriptorRef` under the new `readKey'` for non-revoked recipients, and deletes revoked recipients' grant rows — all behind the Phase-63 D-05 transport-decoupled callback seam.

## What Was Built

### `reMintGrantsRootedAt` (filled seam — ROT-04/HIGH-3)

- Accepts optional `GrantRemintCallbacks` as a trailing param (D-04 transport seam)
- When callbacks absent: clean no-op (no throw — preserves D-01 conditional-invocation contract)
- When callbacks present:
  1. `queryGrantsFn(nodeId)` enumerates all grants rooted at the rotated node
  2. For each revoked grant: `deleteGrantFn(shareId)` — never re-mints (T-64-04b)
  3. For each non-revoked grant: `wrapKey(newReadKey, recipientPublicKey)` (ECIES — T-64-04c), base64-encode, `updateGrantFn(shareId, readDescriptorRef, newGeneration)`
- Never zeros `newReadKey` — caller is terminal owner per D-09

### New Types

- `GrantRemintCallbacks` (exported) — the D-04 injectable callback shape:
  - `queryGrantsFn(nodeId) → Promise<ReadonlyArray<{ shareId, recipientPublicKey, isRevoked }>>`
  - `updateGrantFn(shareId, readDescriptorRef, newGeneration) → Promise<void>`
  - `deleteGrantFn(shareId) → Promise<void>`
- `grantCallbacks?: GrantRemintCallbacks` added to `RotateOneParams` for call-site threading

### New Test Suite

`packages/sdk-core/src/__tests__/rotation/grant-remint.test.ts`:
- Test 1: Non-revoked grant → `wrapKey` called + `updateGrantFn(shareId, base64Descriptor, gen)`; `deleteGrantFn` not called
- Test 2: Revoked grant → `deleteGrantFn(shareId)` only; no `wrapKey` or `updateGrantFn`
- Test 3: Mixed set → exactly one update + one delete with correct shareIds
- Test 4: No callbacks → resolves undefined (no-op, no crypto)

## TDD Gate Compliance

- RED commit: `test(64-05): add failing inner-grant re-mint tests` (226570cd8) — all 4 tests fail because `reMintGrantsRootedAt` threw "not implemented"
- GREEN commit: `feat(64-05): re-mint readDescriptorRef for rooted grants` (310f2fa4c) — all 4 tests pass

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Updated Phase-63 seam-throw test in engine.test.ts**

- **Found during:** GREEN phase test verification
- **Issue:** `engine.test.ts` line 370 asserted `reMintGrantsRootedAt` rejects with "phase 64" (the Phase-63 seam marker). Filling the seam made the function resolve instead of throw, causing the test to fail.
- **Fix:** Updated test to assert the new correct behavior — no-callbacks call resolves to `undefined`. Full behavior covered by `grant-remint.test.ts`.
- **Files modified:** `packages/sdk-core/src/__tests__/rotation/engine.test.ts`
- **Commit:** 310f2fa4c (included in GREEN commit)

## Verification

```
pnpm --filter @cipherbox/sdk-core test --run src/__tests__/rotation/grant-remint.test.ts
# 4 passed

pnpm --filter @cipherbox/sdk-core test --run src/__tests__/rotation/engine.test.ts
# 26 passed

npx tsc --noEmit -p packages/sdk-core/tsconfig.json
# Zero new errors in engine.ts, grant-remint.test.ts, engine.test.ts
# (pre-existing errors in cas.test.ts/grant.test.ts are not this plan's)

grep "shares\|api-client\|@cipherbox/api" packages/sdk-core/src/rotation/engine.ts
# (no output — no DB/API imports added)
```

## Self-Check: PASSED

- `packages/sdk-core/src/__tests__/rotation/grant-remint.test.ts` — FOUND
- `packages/sdk-core/src/rotation/engine.ts` (modified) — FOUND
- Commit `226570cd8` (RED) — FOUND
- Commit `310f2fa4c` (GREEN) — FOUND
