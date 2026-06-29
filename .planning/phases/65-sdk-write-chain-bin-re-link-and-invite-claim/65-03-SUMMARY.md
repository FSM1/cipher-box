---
phase: 65-sdk-write-chain-bin-re-link-and-invite-claim
plan: "03"
subsystem: sdk-core/share
status: complete
tags: [invite-claim, read-grant, tdd, sdk-core]
requires: []
provides: [claimInvite]
affects: [packages/sdk-core/src/share/grant.ts, packages/sdk-core/src/share/index.ts]
tech_stack:
  added: []
  patterns: [injected-callback-seam, tdd-red-green]
key_files:
  created: []
  modified:
    - packages/sdk-core/src/share/grant.ts
    - packages/sdk-core/src/share/index.ts
    - packages/sdk-core/src/__tests__/share/grant.test.ts
decisions:
  - "claimInvite composes the existing claimInviteReadKey primitive — not reimplemented"
  - "insertShareFn and getInviteDataFn injected as callbacks matching the D-02 transport seam"
  - "No encryptedChildKeys produced or consumed in sdk-core/sdk layer"
metrics:
  duration: "219s"
  completed: "2026-06-30"
  tasks_completed: 2
  tasks_total: 2
  files_modified: 3
---

# Phase 65 Plan 03: Invite-Claim Service Flow Summary

**One-liner:** `claimInvite` service flow wiring getInviteDataFn callback and claimInviteReadKey primitive into a single injected-seam grant persisted via insertShareFn

## What Was Built

Added `claimInvite` to `packages/sdk-core/src/share/grant.ts` — the thin service-flow function that wires together:

1. `getInviteDataFn(token)` — fetches `{ readDescriptorRef }` from invite storage (injected callback)
2. `claimInviteReadKey(...)` — existing primitive that re-wraps the share-root readKey from the URL-fragment ephemeral key to the claimer's public key
3. `insertShareFn(payload)` — persists one standard `ReadGrantPayload` grant row (injected callback)

The function returns `{ shareId, readDescriptorRef }`. Multi-claim invites yield one independent grant per claimer of the same root readKey — no fan-out array.

Barrel re-export added to `packages/sdk-core/src/share/index.ts`.

## TDD Gate Compliance

- RED commit `bfd3996d7`: `test(65-03): add failing claimInvite service-flow test` — 6 new tests fail with `claimInvite is not a function`
- GREEN commit `173772ba0`: `feat(65-03): implement claimInvite service flow and barrel export` — all 20 tests pass

## Tasks

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | RED — claimInvite service-flow test | bfd3996d7 | grant.test.ts |
| 2 | GREEN — implement claimInvite and barrel export | 173772ba0 | grant.ts, index.ts |

## Verification Results

- `pnpm --filter @cipherbox/sdk-core test run -- grant`: 20/20 tests pass
- `grep -n "export async function claimInvite" packages/sdk-core/src/share/grant.ts`: matches line 272
- `grep -c "claimInvite" packages/sdk-core/src/share/index.ts`: 1
- Non-test sdk-core/sdk source: zero `encryptedChildKeys` references (grep gate clean)

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

None. `claimInvite` is fully wired with injected callbacks per the D-02 mock seam design. Production callers will supply real API callbacks in Phase 66.

## Threat Flags

None. No new network endpoints, auth paths, file access patterns, or schema changes introduced. The threat register items T-65-09 through T-65-12 are all addressed:

- T-65-09: Link carries readKey by design (accepted, bounded to subtree)
- T-65-10: Replayed link re-wraps same readKey; revocation via rotation (Plan 06)
- T-65-11: `claimInvite` does not zero caller-owned buffers; `reWrapKey` zeros the intermediate
- T-65-12: Grep gate confirms zero sdk-layer fan-out consumption

## Self-Check: PASSED

- `packages/sdk-core/src/share/grant.ts` — exists, contains `claimInvite` at line 272
- `packages/sdk-core/src/share/index.ts` — exists, exports `claimInvite`
- `packages/sdk-core/src/__tests__/share/grant.test.ts` — exists, 16 tests
- Commit `bfd3996d7` — verified in git log
- Commit `173772ba0` — verified in git log
