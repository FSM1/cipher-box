---
phase: 71-share-invite-security-and-ipns-data-integrity-api
plan: 07
subsystem: api
tags: [nestjs, typeorm, shares, share-invites, tdd]

requires:
  - phase: 71-06
    provides: post-71-01 renamed share plane fields (encryptedReadKey/encryptedWriteKey/shareRootIpnsName) and the createInvite root-ownership gate this plan's claimInvite branch builds on
provides:
  - Widen-only grant merge in claimInvite's existing-share branch (D-07/SC#2) -- a re-claim over an already-existing share upgrades encryptedWriteKey/encryptedReadKey/rootGeneration only when the later invite widens authority, and never downgrades write to read
affects: [71-08, share-invite security audit, share-claim e2e]

tech-stack:
  added: []
  patterns:
    - "Widen-only merge gate: isWriteUpgrade/isGenerationBump computed booleans, each field write individually gated -- never a blanket Object.assign"

key-files:
  created: []
  modified:
    - apps/api/src/shares/share-invite.service.ts
    - apps/api/src/shares/share-invite.service.spec.ts

key-decisions:
  - "isWriteUpgrade = inviteGrantsWrite && !existingHasWrite; isGenerationBump = BigInt(invite.rootGeneration) > BigInt(existingShare.rootGeneration) -- write authority stays presence-derived per T-66-E1"
  - "Merge runs inside the existing claimInvite transaction manager, after the atomic claim UPDATE, so a legitimate widen validly consumes the invite and a redundant re-claim still burns it without dropping or downgrading the existing grant"
  - "existingShare.id returned unconditionally regardless of merge outcome (widen, no-op, or negative backstop) -- callers always get the current share id"

patterns-established:
  - "Widen-only merge: gate every field write on a named boolean (isWriteUpgrade/isGenerationBump), never a blanket overwrite, so a non-widening path cannot silently downgrade a security-relevant field"

requirements-completed: [D-07, "SC#2"]

coverage:
  - id: D1
    description: "Same-level or lower-authority re-claim over an existing share is a true no-op (no manager.save, no field mutation)"
    requirement: D-07
    verification:
      - kind: unit
        ref: "apps/api/src/shares/share-invite.service.spec.ts#re-claim over an existing share — widen-only merge (D-07/SC#2) > same-level re-claim is a no-op"
        status: pass
    human_judgment: false
  - id: D2
    description: "read→write widen upgrades the existing share's encryptedWriteKey (and encryptedReadKey) via manager.save inside the claim transaction"
    requirement: "SC#2"
    verification:
      - kind: unit
        ref: "apps/api/src/shares/share-invite.service.spec.ts#re-claim over an existing share — widen-only merge (D-07/SC#2) > read→write widen upgrades the existing share and calls manager.save"
        status: pass
    human_judgment: false
  - id: D3
    description: "generation-bump widen (higher invite.rootGeneration) advances the existing share's rootGeneration and refreshes encryptedReadKey via manager.save"
    requirement: "SC#2"
    verification:
      - kind: unit
        ref: "apps/api/src/shares/share-invite.service.spec.ts#re-claim over an existing share — widen-only merge (D-07/SC#2) > generation-bump widen advances rootGeneration and calls manager.save"
        status: pass
    human_judgment: false
  - id: D4
    description: "BACKSTOP: a read-only re-claim over a write-capable existing share never downgrades encryptedWriteKey to null"
    requirement: D-07
    verification:
      - kind: unit
        ref: "apps/api/src/shares/share-invite.service.spec.ts#re-claim over an existing share — widen-only merge (D-07/SC#2) > BACKSTOP: a read-only re-claim over a write-capable share never downgrades encryptedWriteKey"
        status: pass
    human_judgment: false

duration: 8min
completed: 2026-07-09
status: complete
---

# Phase 71 Plan 07: Widen-Only Re-Claim Grant Merge (D-07/SC#2) Summary

**Closed SC#2 by replacing claimInvite's log-and-return existing-share branch with a widen-only merge that upgrades a stale share's write/read keys and rootGeneration only when the later invite grants more authority, never downgrading write to read.**

## Performance

- **Duration:** ~8 min
- **Tasks:** 1
- **Files modified:** 2

## Accomplishments

- `claimInvite`'s existing-share branch now computes `inviteGrantsWrite`/`existingHasWrite`/`isWriteUpgrade`/`isGenerationBump` and gates every field write (`encryptedReadKey`, `encryptedWriteKey`, `rootGeneration`) individually on those booleans, so a non-widening re-claim can structurally never clear an existing `encryptedWriteKey`
- Merge executes inside the already-open `claimInvite` transaction manager, after the atomic claim UPDATE, preserving the invariant that a legitimate widen (or even a redundant same-level re-claim) validly consumes the invite
- Extended the `share-invite.service.spec.ts` "idempotent re-claim" block into four cases: same-level no-op, read→write widen, generation-bump widen, and an explicit never-downgrade negative backstop
- TDD RED/GREEN cycle followed: two new positive-widen tests failed against the pre-existing log-and-return code (confirming the gap), then passed after the merge implementation landed; the no-op and backstop tests already passed incidentally (current code never called `manager.save`) but now assert the correct behavior explicitly rather than by accident

## Task Commits

Each task was committed atomically (TDD RED → GREEN):

1. **Task 1 (RED):** `test(71-07): add failing widen-only re-claim merge tests for D-07/SC#2` — `07c471ab3`
2. **Task 1 (GREEN):** `feat(71-07): widen-only grant merge in claimInvite existing-share branch` — `77ea5bc02`

## Files Created/Modified

- `apps/api/src/shares/share-invite.service.ts` — replaced the existing-share log-and-return with the widen-only merge gate
- `apps/api/src/shares/share-invite.service.spec.ts` — renamed/extended the re-claim describe block to cover no-op, read→write widen, generation-bump widen, and the never-downgrade backstop

## Decisions Made

- Write authority stays presence-derived (`invite.encryptedWriteKey !== null`), matching T-66-E1 from Phase 66 — `isWriteUpgrade` never trusts claimer-supplied fields alone
- `rootGeneration` comparison uses `BigInt(...)` on both sides since the entity column is `bigint` (returned as string by TypeORM)
- `existingShare.id` is always returned regardless of merge outcome, matching the pre-existing contract callers rely on

## Deviations from Plan

None — plan executed exactly as written. No DTO/endpoint shape change, so no `pnpm api:generate` regeneration was required (as flagged in the plan's project-specific notes).

## Issues Encountered

None. `pnpm install` was required once at worktree setup (no other blockers).

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- SC#2 fully closed; the widen-only merge pattern (`isWriteUpgrade`/`isGenerationBump`, individually-gated field writes) is now available as a documented pattern for any future re-claim-style merge logic
- `shares.service.ts` (bulk-revoke, D-08) is explicitly out of scope for this plan and remains untouched, per project-specific notes — reserved for 71-08
- Full `apps/api/src/shares/*` unit suite (86 tests across 5 spec files) verified green after this change; no regressions in the pre-existing T-66-E1/T-66-S1/self-claim/expiry/contention invariant tests

---
*Phase: 71-share-invite-security-and-ipns-data-integrity-api*
*Completed: 2026-07-09*

## Self-Check: PASSED

- FOUND: apps/api/src/shares/share-invite.service.ts
- FOUND: apps/api/src/shares/share-invite.service.spec.ts
- FOUND: .planning/phases/71-share-invite-security-and-ipns-data-integrity-api/71-07-SUMMARY.md
- FOUND: 07c471ab3 (test commit)
- FOUND: 77ea5bc02 (feat commit)
- FOUND: 20c7c15b4 (docs/summary commit)
