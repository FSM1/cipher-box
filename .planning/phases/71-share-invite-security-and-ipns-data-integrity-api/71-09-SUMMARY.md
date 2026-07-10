---
phase: 71-share-invite-security-and-ipns-data-integrity-api
plan: 09
subsystem: testing
tags: [nestjs, jest, share-invite, unit-testing, fixtures]

requires:
  - phase: 71-06
    provides: createInvite ownership tests + IpnsRecord provider mock in share-invite.service.spec.ts
  - phase: 71-07
    provides: widen-merge (D-07) re-claim tests in share-invite.service.spec.ts
provides:
  - Real unit coverage for ShareInviteService.getInvitesForItem (active-only result + expired auto-clean)
  - Real unit coverage for ShareInviteService.revokeInvite (NotFound / Forbidden / owner-success)
  - Contract-valid fixtures in shares.controller.spec.ts (UUIDs, full k51 IPNS names, full-length hex public keys)
  - D-03 documented-drop note recorded in shares.controller.spec.ts
affects: [share-invite-service, shares-controller]

tech-stack:
  added: []
  patterns:
    - "Contract-valid test fixtures: UUID-shaped ids, full k51qzi5uqu5-prefixed CIDv1 libp2p-key IPNS names (40-60 char suffix), full-length uncompressed secp256k1 public keys (04 + 128 hex chars) — matches DTO @Matches validators even though controller unit tests bypass the ValidationPipe"

key-files:
  created: []
  modified:
    - apps/api/src/shares/share-invite.service.spec.ts
    - apps/api/src/shares/shares.controller.spec.ts

key-decisions:
  - "D-03 documented as a comment in shares.controller.spec.ts: the ipns_records(user_id) WHERE is_root partial unique index is intentionally NOT added (vaults.owner_id uniqueness already enforces one-root-per-user)"

patterns-established:
  - "Fixture-hardening pass: replace placeholder test strings with values that would pass the real DTO validators, so a future contract-shape regression fails a test instead of silently passing on a placeholder"

requirements-completed: [D-09, D-03, SC#6]

coverage:
  - id: D1
    description: "ShareInviteService.getInvitesForItem returns only active, non-expired invites and auto-cleans (removes) expired ones"
    requirement: "D-09"
    verification:
      - kind: unit
        ref: "apps/api/src/shares/share-invite.service.spec.ts#getInvitesForItem"
        status: pass
    human_judgment: false
  - id: D2
    description: "ShareInviteService.revokeInvite enforces owner-only guard (NotFoundException for missing, ForbiddenException for non-sharer, status->revoked + save for owner)"
    requirement: "D-09"
    verification:
      - kind: unit
        ref: "apps/api/src/shares/share-invite.service.spec.ts#revokeInvite"
        status: pass
    human_judgment: false
  - id: D3
    description: "shares.controller.spec.ts placeholder fixtures replaced with contract-valid UUIDs, full k51 IPNS names, and full-length hex public keys; no placeholder strings remain"
    requirement: "SC#6"
    verification:
      - kind: unit
        ref: "apps/api/src/shares/shares.controller.spec.ts (all describe blocks)"
        status: pass
    human_judgment: false
  - id: D4
    description: "D-03 dropped-index decision documented in shares.controller.spec.ts so it is not mistaken for an omission"
    requirement: "D-03"
    verification: []
    human_judgment: true
    rationale: "Documentation-only deliverable (a code comment); no automated check can verify a comment's presence conveys the correct rationale to a future reader."

duration: 15min
completed: 2026-07-10
status: complete
---

# Phase 71 Plan 09: ShareInviteService Coverage and Controller Fixture Hardening Summary

**Restored real unit coverage for `ShareInviteService.getInvitesForItem`/`revokeInvite` and replaced non-contract-valid placeholder fixtures in `shares.controller.spec.ts` with realistic UUIDs, full k51 IPNS names, and full-length hex public keys.**

## Performance

- **Duration:** ~15 min
- **Tasks:** 2 completed
- **Files modified:** 2

## Accomplishments
- Added `describe('getInvitesForItem')` to `share-invite.service.spec.ts` asserting the active-only result set and the expired-invite auto-clean (`inviteRepo.remove` called with the expired subset)
- Added `describe('revokeInvite')` asserting `NotFoundException` (missing invite), `ForbiddenException` (non-sharer caller), and owner-success (`status` set to `'revoked'`, `inviteRepo.save` called)
- Replaced every placeholder fixture in `shares.controller.spec.ts` (`share-uuid-*`, `node-uuid-*`, `sharer-uuid-1`, `recipient-uuid-*`, `k51qzi5uqu5full`/`k51qzi5uqu5min`, `04sharerkey*`/`04recipientkey*`, and short truncated hex like `aabb`/`ccdd`/`eeff`/`1122`/`aabbcc`) with contract-valid constants: UUID-shaped ids, two distinct full-length k51 CIDv1 libp2p-key IPNS names (62 and 59 chars, both within the `k51qzi5uqu5[a-z0-9]{40,60}` validator range), full-length uncompressed secp256k1 public keys (`04` + 128 hex chars), and full-length hex-encoded key ciphertext
- Recorded the D-03 documented-drop decision as a top-of-file comment in `shares.controller.spec.ts`: the `ipns_records(user_id) WHERE is_root` partial unique index is intentionally not added because `vaults.owner_id` uniqueness already enforces one-root-per-user

## Task Commits

Each task was committed atomically:

1. **Task 1: Cover getInvitesForItem and revokeInvite (D-09)** - `bc6e0f0db` (test)
2. **Task 2: Contract-valid fixtures in shares.controller.spec.ts + D-03 documentation note** - `feb0b5bb9` (test)

**Plan metadata:** (this commit)

## Files Created/Modified
- `apps/api/src/shares/share-invite.service.spec.ts` - Added `getInvitesForItem` and `revokeInvite` describe blocks using the existing `makeInvite` fixture and `mockInviteRepo`
- `apps/api/src/shares/shares.controller.spec.ts` - Hardened all fixture constants to contract-valid shapes; added D-03 documentation comment

## Decisions Made
- D-03 documented inline (not just in CONTEXT.md): the `ipns_records(user_id) WHERE is_root` partial unique index is intentionally skipped since `vaults.owner_id` uniqueness already enforces one root per user — recorded as a comment in `shares.controller.spec.ts` so a future reader doesn't mistake the absence of that index for an omission
- Chose two distinct, real-shaped k51 IPNS name fixtures (62-char and 59-char suffixes, both inside the DTO's `[a-z0-9]{40,60}` validator range) rather than reusing a single value, preserving the original test's intent of exercising two distinct shares with distinct identities

## Deviations from Plan

None - plan executed exactly as written. Both tasks matched their `<action>` and `<acceptance_criteria>` blocks; `createInvite` coverage (owned by 71-06) and `claimInvite`/re-claim blocks (owned by 71-07) were left untouched.

## Issues Encountered

The worktree's `node_modules` was missing (fresh worktree checkout); ran `pnpm i` at the workspace root before the first test run. Not a plan deviation — infrastructure setup only, no code change.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

SC#6 is now fully satisfied: `ShareInviteService` lifecycle methods (`createInvite` via 71-06, `getInvitesForItem` + `revokeInvite` here) have realistic unit coverage, and `shares.controller.spec.ts` fixtures are contract-valid. No known blockers for downstream plans in this phase.

---
*Phase: 71-share-invite-security-and-ipns-data-integrity-api*
*Completed: 2026-07-10*

## Self-Check: PASSED

- FOUND: apps/api/src/shares/share-invite.service.spec.ts (modified, verified via git status)
- FOUND: apps/api/src/shares/shares.controller.spec.ts (modified, verified via git status)
- FOUND commit: bc6e0f0db (test(71-09): cover getInvitesForItem and revokeInvite)
- FOUND commit: feb0b5bb9 (test(71-09): harden shares.controller.spec fixtures and record D-03)
- Both `pnpm --filter @cipherbox/api test -- --testPathPattern` runs for share-invite.service and shares.controller passed (21 and 20 tests respectively; full shares/ suite: 91/91 passed)
