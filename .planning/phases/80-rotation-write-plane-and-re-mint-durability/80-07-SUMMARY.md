---
phase: 80-rotation-write-plane-and-re-mint-durability
plan: 07
subsystem: crypto
tags: [rotation, re-mint, recipient-pins, fail-closed, sdk-core, owner-reconcile, ECIES]

# Dependency graph
requires:
  - phase: 80-01
    provides: recipientPins field on NodeWriteBody wire codec
  - phase: 80-03
    provides: engine.ts/owner-reconcile.ts sequencing + closure-scoped listSentGrants memo
  - phase: 80-04
    provides: assertRecipientPinned helper + client getRecipientPubkeyPins read path
provides:
  - GrantRemintCallbacks.getPinsFn seam on reMintGrantsRootedAt (sdk-core)
  - Fail-closed assertRecipientPinned verification before wrapKey in the TS re-mint
  - getPinsFn wired via transport.getRecipientPubkeyPins in buildGrantRemintCallbacks (sdk)
affects: [80-08, ship, verify-work]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Fail-closed recipient-pin verification at a wrap site (D-03d consumer 2 of 3)"
    - "Reuse the shared sdk-core assertRecipientPinned helper across all enforcement consumers"

key-files:
  created: []
  modified:
    - packages/sdk-core/src/rotation/engine.ts
    - packages/sdk/src/share/owner-reconcile.ts
    - packages/sdk-core/src/__tests__/rotation/grant-remint.test.ts
    - packages/sdk/src/__tests__/owner-reconcile.test.ts

key-decisions:
  - "getPinsFn is optional on GrantRemintCallbacks but REQUIRED on the enforced (surviving-grant) path — absent seam throws (D-03e)"
  - "Pins fetched once per node, only when at least one surviving grant exists — an all-revoked node needs no pin source, preserving existing revoked-only callers"
  - "transport.getRecipientPubkeyPins kept OPTIONAL on OwnerReconcileTransport so the web wrapper (80-08) wires it separately; absent method fails closed, not open"

patterns-established:
  - "Normalize Uint8Array pins to base64 before assertRecipientPinned (its stored-pin encoding)"
  - "Enforcement is a hard throw that aborts the node's re-mint — NOT a per-grant skip like isRevoked"

requirements-completed:
  - "SC2 / D-03d (consumer 2 of 3): TS re-mint verifies grant.recipientPublicKey against the node's owner-sealed pin before wrapKey, fail-closed on mismatch"
  - "SC2 / D-03e: pin absent at TS re-mint is a hard fail-closed invariant violation"

coverage:
  - id: D1
    description: "TS re-mint fails closed when the relay-fed recipientPublicKey is not in the node's owner-sealed pin list (D-03d, T-80-18)"
    requirement: "SC2 / D-03d (consumer 2 of 3): TS re-mint verifies grant.recipientPublicKey against the node's owner-sealed pin before wrapKey, fail-closed on mismatch"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/grant-remint.test.ts#Test A (D-03d mismatch): throws and does NOT wrap when getPinsFn omits the grant recipient"
        status: pass
      - kind: unit
        ref: "packages/sdk/src/__tests__/owner-reconcile.test.ts#Test 5 (D-03d mismatch): reconcile fails closed when the pin list omits the surviving grant recipient"
        status: pass
    human_judgment: false
  - id: D2
    description: "Absent/empty pin list at TS re-mint is a hard fail-closed error, never a skip (D-03e, T-80-19)"
    requirement: "SC2 / D-03e: pin absent at TS re-mint is a hard fail-closed invariant violation"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/grant-remint.test.ts#Test B (D-03e absent): throws when getPinsFn returns an empty pin list"
        status: pass
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/grant-remint.test.ts#Test B2 (D-03e absent seam): throws when getPinsFn is missing for a surviving grant"
        status: pass
      - kind: unit
        ref: "packages/sdk/src/__tests__/owner-reconcile.test.ts#Test 6 (D-03e absent): reconcile fails closed when the pin list is empty"
        status: pass
    human_judgment: false
  - id: D3
    description: "getPinsFn seam sources pins from the client read path (getRecipientPubkeyPins); a pinned recipient wraps as before, 80-03 listSentGrants memo intact"
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/owner-reconcile.test.ts#Test 7 (pin source): getPinsFn resolves via getRecipientPubkeyPins, matching pin wraps as before"
        status: pass
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/rotation/grant-remint.test.ts#Test C (match): proceeds and wraps when getPinsFn includes the grant recipient"
        status: pass
    human_judgment: false

# Metrics
duration: 18min
completed: 2026-07-12
status: complete
---

# Phase 80 Plan 07: TS Re-mint Recipient-Pin Fail-Closed Enforcement Summary

**The TS owner re-mint now verifies each surviving grant's relay-round-tripped recipientPublicKey against the node's owner-sealed recipientPins (via a new getPinsFn seam reusing sdk-core's assertRecipientPinned) before wrapKey, and fails closed on mismatch or absent pins.**

## Performance

- **Duration:** ~18 min
- **Started:** 2026-07-12T20:47Z
- **Completed:** 2026-07-12T20:52Z
- **Tasks:** 3
- **Files modified:** 4

## Accomplishments
- Added `GrantRemintCallbacks.getPinsFn` seam to `reMintGrantsRootedAt` (sdk-core engine.ts) that resolves the node's owner-sealed pins.
- Inserted a fail-closed `assertRecipientPinned` (reused from 80-04) immediately before `wrapKey(newReadKey, grant.recipientPublicKey)` — a mismatch or absent/empty pin list throws and aborts the node's re-mint (NOT a per-grant skip like isRevoked).
- Wired `getPinsFn` to the client `getRecipientPubkeyPins` read path via `transport.getRecipientPubkeyPins` in `buildGrantRemintCallbacks` (sdk owner-reconcile.ts), preserving the 80-03 closure-scoped `listSentGrants` memo.
- Added mismatch + absent negative tests at both layers (sdk-core unit and sdk end-to-end).

## Task Commits

Executed as a single atomic commit per D-03d consumer-2 scope (TDD RED→GREEN across two packages):

1. **Tasks 1-3: RED tests + getPinsFn seam + owner-reconcile wiring** - see plan metadata commit below

**Plan metadata + code:** committed together (feat)

_All four files (engine, owner-reconcile, and both test files) plus this SUMMARY landed in one commit._

## Files Created/Modified
- `packages/sdk-core/src/rotation/engine.ts` - `GrantRemintCallbacks.getPinsFn` seam + fail-closed `assertRecipientPinned` before `wrapKey`; pins fetched once per node only when a surviving grant exists.
- `packages/sdk/src/share/owner-reconcile.ts` - optional `getRecipientPubkeyPins` on `OwnerReconcileTransport` + `getPinsFn` delegating to it (fail-closed if absent); 80-03 memo untouched.
- `packages/sdk-core/src/__tests__/rotation/grant-remint.test.ts` - Tests A (mismatch), B (empty), B2 (missing seam), C (match); Tests 1/3 updated to supply a matching `getPinsFn`.
- `packages/sdk/src/__tests__/owner-reconcile.test.ts` - crypto mock switched to `importOriginal` (keeps real base64/hex codecs for `assertRecipientPinned`); `makeTransport` supplies `getRecipientPubkeyPins`; Tests 5 (mismatch), 6 (empty), 7 (pin source) added.

## Decisions Made
- **getPinsFn optional in the type, required on the enforced path:** the type stays optional so all-revoked callers and the no-callbacks no-op keep compiling, but any surviving grant with a missing seam throws (D-03e). This keeps the existing revoked-only test (Test 2) green without a getPinsFn.
- **Pins fetched once, gated on `grants.some(!isRevoked)`:** an all-revoked node performs no wrap and needs no pin source, so the seam is only demanded when enforcement actually applies.
- **`transport.getRecipientPubkeyPins` kept optional:** the concrete web wrapper (`apps/web/.../owner-reconcile.service.ts`) is wired in 80-08; leaving it optional keeps the web package compiling now and makes the web re-mint fail closed (throw, caught+logged) until 80-08 completes the wiring — the safe direction.

## Deviations from Plan
None - plan executed exactly as written. Added one extra sdk-core test (B2: missing-seam throws) beyond the plan's A/B/C to explicitly cover the "absent getPinsFn" D-03e path, and one extra sdk test (Test 7: pin-source-resolves) to assert the getRecipientPubkeyPins wiring — both strengthen coverage without changing scope.

## Issues Encountered
- Bash cwd drifted to the primary checkout (main) between calls; re-targeted every command at the worktree path explicitly. The initial "4 tests passed" was the primary checkout running stale code — re-running inside the worktree correctly showed 4 failing RED tests.
- The sdk test resolves `@cipherbox/sdk-core` to its built dist, so `assertRecipientPinned` needs the real base64/hex codecs. Switched the owner-reconcile crypto mock to `importOriginal` (keeping only the ECIES/randomness stubs) and rebuilt sdk-core dist before running the sdk suite.

## User Setup Required
None - no external service configuration required. No API/DTO change, no api:generate, no DB migration.

## Next Phase Readiness
- 80-08 (web consumer 3 of 3) wires `getRecipientPubkeyPins` on the concrete web `OwnerReconcileTransport` (delegating to `client.getRecipientPubkeyPins`) and reuses the same `assertRecipientPinned` compare — the seam and helper are in place.
- Pre-ship: run the full sdk-core/sdk suites + sdk-e2e live round-trip before `/gsd-verify-work` (key-lifecycle change).

## Verification Results
- `pnpm --filter @cipherbox/sdk-core test grant-remint` → 8 passed (8)
- `pnpm --filter @cipherbox/sdk test owner-reconcile` → 9 passed (9)
- `pnpm --filter @cipherbox/sdk-core typecheck` → clean
- `pnpm --filter @cipherbox/sdk typecheck` → clean
- eslint + prettier on all 4 touched files → clean

---
*Phase: 80-rotation-write-plane-and-re-mint-durability*
*Completed: 2026-07-12*
