---
phase: 72-sdk-write-plane-durability-and-correctness
plan: 03
subsystem: sdk
tags: [sdk-core, write-chain, cas-merge, deleteItem, write-body, node-v3]

# Dependency graph
requires:
  - phase: 68.1-sdk-owned-write-chain
    provides: WriteChildRef write-body model, moveItem's UUID-resolve + re-home pattern
provides:
  - Base-aware write-body CAS-merge (updateFolderMetadataAndPublish gains baseWriteChildren)
  - deleteItem drops the removed child's WriteChildRef by resolved UUID, fails open on resolve miss
affects: [72-04, 72-05, restoreFromBin re-homing (SC#3), future write-chain mutations]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Write-plane CAS merge base-aware prune: a childId present in baseWriteChildren but absent from local writeChildren is an intentional delete this transaction committed to, and is pruned even if a racing writer's stale remote snapshot still carries it — unlike the read-plane's mergeChildren, which keeps a one-sided absence."
    - "deleteItem UUID resolve + write-chain filter mirrors moveItem's 68.1-31 pattern: resolve the removed item's own PublishedNode.id (UUID) before touching writeChildren, since WriteChildRef.childId is never the ipnsName-based childId param."

key-files:
  created:
    - packages/sdk/src/__tests__/delete-item.test.ts
  modified:
    - packages/sdk-core/src/folder/registration.ts
    - packages/sdk-core/src/__tests__/folder/registration.test.ts
    - packages/sdk/src/client.ts

key-decisions:
  - "Write-plane base-aware merge treats a childId absent from LOCAL (relative to base) as an intentional delete regardless of what remote still holds — a stricter rule than the read-plane's mergeChildren (which keeps a one-sided delete). This is what makes SC#1's drop survive a CAS-409 race (72-RESEARCH.md Critical Finding 2)."
  - "baseWriteChildren is optional; omitting it falls back to the legacy naive union (back-compat for other write-chain callers not yet threading a base snapshot, e.g. moveItem/restoreFromBin, which Plan 05 will address for SC#3)."
  - "deleteItem's UUID-resolve-and-drop step fails OPEN (try/catch, console.warn, proceed unchanged) — this is a hygiene fix and must never make delete less reliable than it was before (Pitfall 2)."

patterns-established:
  - "Base-aware 3-way merge in the write-plane key space (childId/UUID), distinct from the read-plane's ipnsName-keyed mergeChildren."

requirements-completed: [SC#1]

coverage:
  - id: D1
    description: "updateFolderMetadataAndPublish's write-body CAS-merge is base-aware: prunes a childId dropped locally even when a racing writer's stale remote snapshot still carries it, while keeping genuine concurrent adds"
    requirement: "SC#1"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/folder/registration.test.ts#Test A/B/C (base-aware write-body CAS-merge)"
        status: pass
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/folder/write-body.test.ts (no seal-shape regression)"
        status: pass
    human_judgment: false
  - id: D2
    description: "deleteItem resolves the removed child's UUID and drops its WriteChildRef in the same publish that removes the read-plane SealedChildRef; fails open on a resolve miss"
    requirement: "SC#1"
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/delete-item.test.ts#drops the removed child WriteChildRef (write-chain length shrinks by exactly 1)"
        status: pass
      - kind: unit
        ref: "packages/sdk/src/__tests__/delete-item.test.ts#threads the pre-trim write-body as baseWriteChildren"
        status: pass
      - kind: unit
        ref: "packages/sdk/src/__tests__/delete-item.test.ts#fails OPEN on a UUID resolve failure"
        status: pass
  - id: D3
    description: "Live sdk-e2e confirmation that the write-body actually shrinks on the network (folder-crud/concurrent-operations)"
    requirement: "SC#1"
    verification: []
    human_judgment: true
    rationale: "Deferred to the phase/wave-level gate per plan's own <verification> section ('After the wave, run sdk-e2e ... if the stack is up'); this plan's sandbox blocked reading tests/sdk-e2e/.env to confirm SDK_E2E_SECRET/TEST_LOGIN_SECRET alignment, so the live round-trip was not exercised in this session even though docker+API were reachable."

# Metrics
duration: 25min
completed: 2026-07-10
status: complete
---

# Phase 72 Plan 03: Base-Aware Write-Body Merge and UUID-Keyed Delete Drop Summary

**deleteItem now drops its removed child's WriteChildRef by resolved UUID inside the same CAS publish, and updateFolderMetadataAndPublish's write-body merge is base-aware so a racing writer's stale snapshot can never resurrect the drop under a CAS-409 retry.**

## Performance

- **Duration:** ~25 min
- **Completed:** 2026-07-10T13:48:07Z
- **Tasks:** 2
- **Files modified:** 3 (+1 created)

## Accomplishments

- Fixed the write-plane CAS-merge landmine identified in 72-RESEARCH.md Critical Finding 2: `updateFolderMetadataAndPublish` now accepts an optional `baseWriteChildren` snapshot and, when supplied, prunes a childId present in base but absent from local (an intentional delete this transaction committed to) even when a racing writer's remote snapshot still carries it — while still keeping any genuinely concurrent remote-only add.
- `deleteItem` resolves the removed item's `PublishedNode.id` (UUID) via `resolvePublishedNode`, filters the matching `WriteChildRef` out of `writeChildren`, and threads the pre-trim snapshot as `baseWriteChildren` — closing the SC#1 gap (write-chain now shrinks by exactly one on hard-delete, with no resurrection under concurrency).
- Fails open on a UUID-resolve miss: the write-chain trim is skipped with a `console.warn`, but the already-succeeded read-plane delete is never aborted (72-RESEARCH.md Pitfall 2).
- Rewrote the now-falsified "write plane is add-only... deletes are preserved verbatim" comment block to state the new base-aware prune contract.

## Task Commits

Each task followed RED → GREEN (TDD):

1. **Task 1: Make the write-body CAS-merge base-aware**
   - `3560b397c` test(72-03): add failing base-aware write-body CAS-merge tests (RED)
   - `a8c3882d2` feat(72-03): make write-body CAS-merge base-aware to prevent resurrection (GREEN)
2. **Task 2: deleteItem drops the removed child's WriteChildRef by resolved UUID**
   - `2b2ccc857` test(72-03): add failing deleteItem write-chain trim tests (RED)
   - `3cd41b86b` feat(72-03): deleteItem drops the removed child's WriteChildRef by UUID (GREEN)

**Plan metadata:** (this commit)

## Files Created/Modified

- `packages/sdk-core/src/folder/registration.ts` — `updateFolderMetadataAndPublish` gained `baseWriteChildren?: WriteChildRef[]`; the CAS-409 merge callback now does a base-aware 3-way prune (falls back to the legacy naive union when `baseWriteChildren` is omitted)
- `packages/sdk-core/src/__tests__/folder/registration.test.ts` — Test A (clean publish omits a locally-dropped childId), Test B (concurrent add kept, local delete honored), Test C (resurrection guard: 409 with a racing writer's pre-delete snapshot does not resurrect the drop)
- `packages/sdk/src/client.ts` — `deleteItem` resolves `removedItem`'s UUID, filters `writeChildren`, threads `baseWriteChildren`, fails open on resolve failure
- `packages/sdk/src/__tests__/delete-item.test.ts` (new) — write-chain shrinks by exactly 1 with a fixture using genuinely distinct ipnsName vs UUID values (Pitfall 1's warning sign), `baseWriteChildren` threading, and fail-open on resolve miss

## Decisions Made

- The write-plane base-aware merge is intentionally STRICTER than the read-plane's `mergeChildren`: a one-sided absence (present in base, absent from local) is always pruned regardless of remote, whereas the read-plane keeps a one-sided delete (union wins). This asymmetry is required for SC#1's resurrection guard — see Test C in registration.test.ts.
- `baseWriteChildren` is optional and additive; other write-chain callers (`moveItem`, `restoreFromBin`) do not yet pass it and continue to get the pre-existing naive-union behavior. SC#3 (restoreFromBin re-homing, deferred to Plan 05) is the next candidate to thread it through.

## Deviations from Plan

None — plan executed exactly as written. Task 1's merge design (start from local, fold in only base-absent or already-present-in-local remote entries) was derived directly from the plan's Test A/B/C behavior spec and 72-RESEARCH.md's Critical Finding 2 discussion; no architectural surprises.

## Issues Encountered

- `pnpm --filter @cipherbox/sdk exec tsc --noEmit` initially failed on `client.ts`'s new `baseWriteChildren` field because `@cipherbox/sdk-core`'s dist was stale relative to the source change in Task 1 (project's known cross-package dist-staleness gotcha). Resolved by rebuilding `@cipherbox/sdk-core` (`pnpm --filter @cipherbox/sdk-core build`) before the sdk typecheck; no code change needed.
- All other `tsc --noEmit` errors surfaced in `packages/sdk-core`/`packages/sdk` (e.g. `grant.test.ts`, `client.test.ts`, `integration.test.ts`, retired `FolderChild`/`FolderEntry` type references) are pre-existing, in files untouched by this plan — confirmed via `git status --short` (no diff) — and are out of scope per the SCOPE BOUNDARY rule.
- Sandbox denied `cat`/`grep` access to `tests/sdk-e2e/.env` and `apps/api/.env`, so the live sdk-e2e round-trip (`folder-crud`/`concurrent-operations`) could not be run in this session to confirm `SDK_E2E_SECRET`/`TEST_LOGIN_SECRET` alignment, even though the local docker stack and API (`localhost:3000`, HTTP 200) were reachable. Deferred to the phase/wave-level gate per the plan's own verification note ("After the wave, run sdk-e2e ... if the stack is up").

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- SC#1 is now fully closed at the unit level: `deleteItem` shrinks the write-chain by exactly one, and the CAS-merge can no longer resurrect an intentional drop under a concurrent-write race.
- The base-aware `baseWriteChildren` plumbing is available for Plan 05's SC#3 (`restoreFromBin` re-homing), which will need the same base-snapshot threading when it drops a `WriteChildRef` from the original parent.
- Live sdk-e2e confirmation (`folder-crud`/`concurrent-operations`) remains open — recommended before `/gsd-verify-work` for this phase, per 72-RESEARCH.md's stated primary regression gate.

---
*Phase: 72-sdk-write-plane-durability-and-correctness*
*Completed: 2026-07-10*

## Self-Check: PASSED
