---
phase: 66-api-schema-cutover-publish-gate-and-tombstone
plan: "08"
subsystem: web
tags: [compile-gate, share, invite, phase-68-stub, cutover-hygiene]
status: complete

dependency_graph:
  requires: [66-06]
  provides: [web-typecheck-green]
  affects: [apps/web]

tech_stack:
  added: []
  patterns:
    - compile-gate-stub (Phase-68 throw pattern, matching Phase 62-08/63-65 precedent)

key_files:
  modified:
    - apps/web/src/services/share.service.ts
    - apps/web/src/services/invite.service.ts
    - apps/web/src/components/file-browser/ShareDialog.tsx

decisions:
  - "Removed three 'surviving but reshaped' imports (sharesControllerCreateShare,
    sharesControllerGetReceivedShares, sharesControllerGetSentShares) from the
    api-client import block in share.service.ts because noUnusedLocals:true would
    flag them — the stub bodies just throw and never call the functions."
  - "Stubbed fetchReceivedShares and fetchSentShares (not just the six deleted
    endpoints) because SentShareResponseDto/ReceivedShareResponseDto dropped all
    legacy fields (itemType, ipnsName, itemName, encryptedKey, permission,
    encryptedIpnsKey); accessing them would be a compile error."
  - "Stubbed invite.service claimInvite because ClaimInviteDto changed encryptedKey
    to readDescriptorRef and removed childKeys; InviteDataResponseDto removed
    encryptedChildKeys. Stubbed fetchInvitesForItem because InviteResponseDto
    removed itemType, ipnsName, itemName."
  - "Used _ prefix on unused stub parameters to satisfy noUnusedParameters:true."

metrics:
  duration: "~15 minutes"
  completed: "2026-06-30"
  tasks_completed: 1
  tasks_total: 1
  files_modified: 3

requirements: [DATA-01, DATA-02]
---

# Phase 66 Plan 08: Web Share/Invite Compile-Gate Stubs Summary

Compile-gate hygiene stubs for web share and invite service consumers of the six
deleted share endpoints and the reshaped share/invite response DTOs introduced by
plan 66-06 (api-client regeneration). `pnpm --filter @cipherbox/web exec tsc -b`
now passes against the regenerated client.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Compile-gate stub web share/invite consumers of deleted + reshaped endpoints | 87911fb59 | share.service.ts, invite.service.ts, ShareDialog.tsx |

## What Was Done

### Six Deleted Endpoint Imports Removed

Removed from `share.service.ts` import block:
- `sharesControllerGetShareKeys`
- `sharesControllerAddShareKeys`
- `sharesControllerGetPendingRotations`
- `sharesControllerUpdateShareEncryptedKey`
- `sharesControllerCompleteRotation`
- `sharesControllerUpdatePermission`

### Functions Stubbed with Phase-68 Throw

`share.service.ts` (9 stubs):
- `fetchReceivedShares` — `ReceivedShareResponseDto` no longer has `itemType`, `ipnsName`, `itemName`, `encryptedKey`, `permission`, `encryptedIpnsKey`
- `fetchSentShares` — `SentShareResponseDto` no longer has `itemType`, `ipnsName`, `itemName`, `permission`
- `createShare` — `CreateShareDto` reshaped (now `readDescriptorRef`/`rootNodeId`/`rootIpnsName`, no `encryptedKey`/`itemType`/`ipnsName`)
- `updateSharePermission` — `sharesControllerUpdatePermission` deleted
- `fetchShareKeys` — `sharesControllerGetShareKeys` deleted
- `addShareKeys` — `sharesControllerAddShareKeys` deleted
- `fetchPendingRotations` — `sharesControllerGetPendingRotations` deleted
- `updateShareKey` — `sharesControllerUpdateShareEncryptedKey` deleted
- `completeShareRotation` — `sharesControllerCompleteRotation` deleted

`invite.service.ts` (2 stubs):
- `claimInvite` — `ClaimInviteDto` now uses `readDescriptorRef` (not `encryptedKey`), removed `childKeys`; `InviteDataResponseDto` has no `encryptedChildKeys`
- `fetchInvitesForItem` — `InviteResponseDto` no longer has `itemType`, `ipnsName`, `itemName`

`ShareDialog.tsx` (1 stub):
- useEffect IIFE that paginated `sharesControllerGetSentShares` and accessed `s.ipnsName`, `s.itemType`, `s.itemName`, `s.permission` — all removed from `SentShareResponseDto`

### Functions Left Intact

These survived because they call still-existing endpoints with unchanged call shapes:
- `share.service.ts`: `decryptItemName`, `shouldBackfill`, `backfillSentShareItemNames`, `lookupUser`, `revokeShare`, `hideShare`, `getSentSharesForItem`, `ensureFreshSentShares`, `fetchAllSentShares`, `hasActiveShares`, `findCoveringShares`, `reWrapForRecipients`, `checkPendingRotation`, `executeLazyRotation` (cascade through stubs at runtime but compile clean)
- `invite.service.ts`: `buildInviteUrl`, `createInviteLink` (already phase-65 stub), `checkInviteStatus`, `revokeInvite`
- `ShareDialog.tsx`: `handleRevoke` (still calls `sharesControllerRevokeShare` which exists), `handleDowngradeConfirm` (calls `updateSharePermission` stub — compiles fine), all JSX

## Acceptance Criteria Verification

- `pnpm --filter @cipherbox/web exec tsc -b` exits 0: YES
- `grep -rc "GetShareKeys|AddShareKeys|GetPendingRotations|CompleteRotation|UpdatePermission|UpdateShareEncryptedKey" apps/web/src` all 0: YES
- `grep -rc "rotateReadFromNode|indexedDB|IDBDatabase" apps/web/src/services/share.service.ts` = 0: YES (no Phase-68 logic pulled forward)
- `grep -c "deferred to Phase 68" apps/web/src/services/share.service.ts` = 9: YES

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - noUnusedLocals compliance] Removed surviving-but-now-unused api-client imports**

- **Found during:** Task 1 (noUnusedLocals/noUnusedParameters: true in tsconfig.base.json)
- **Issue:** After stubbing `fetchReceivedShares`, `fetchSentShares`, `createShare`, the three corresponding api-client imports (`sharesControllerCreateShare`, `sharesControllerGetReceivedShares`, `sharesControllerGetSentShares`) would be unused under `noUnusedLocals: true`, causing compile errors.
- **Fix:** Removed those three from the import block. Also applied `_` prefix to all stub function parameters per `noUnusedParameters: true` (matching existing precedent in `createInviteLink(_params)` and `handleUpgrade(_share)`).
- **Files modified:** `apps/web/src/services/share.service.ts`

## Threat Flags

None. No new network endpoints, auth paths, file access patterns, or schema changes introduced. This plan only removes/stubs existing code paths.

## Known Stubs

The following Phase-68 stubs exist intentionally and are load-bearing for Phase 68 (ROT-07):

| Stub | File | Reason |
|------|------|--------|
| `fetchReceivedShares` | share.service.ts | Requires descriptor-ref read path (Phase 68) |
| `fetchSentShares` | share.service.ts | Requires descriptor-ref read path (Phase 68) |
| `createShare` | share.service.ts | Requires descriptor-ref grant path (Phase 68) |
| `updateSharePermission` | share.service.ts | Deleted endpoint — Phase 68 redesign |
| `fetchShareKeys` | share.service.ts | Deleted endpoint — Phase 68 redesign |
| `addShareKeys` | share.service.ts | Deleted endpoint — Phase 68 redesign |
| `fetchPendingRotations` | share.service.ts | Deleted endpoint — Phase 68 redesign |
| `updateShareKey` | share.service.ts | Deleted endpoint — Phase 68 redesign |
| `completeShareRotation` | share.service.ts | Deleted endpoint — Phase 68 redesign |
| `claimInvite` | invite.service.ts | ClaimInviteDto/InviteDataResponseDto reshaped (Phase 68) |
| `fetchInvitesForItem` | invite.service.ts | InviteResponseDto reshaped (Phase 68) |
| ShareDialog useEffect IIFE | ShareDialog.tsx | SentShareResponseDto reshaped (Phase 68) |

These stubs prevent the plan's goal only at runtime (app non-runnable mid-milestone by design); the typecheck gate is the concrete goal of this plan, and it passes.

## Self-Check

- [x] Modified files exist: share.service.ts, invite.service.ts, ShareDialog.tsx
- [x] Commit 87911fb59 exists: `git log --oneline | grep 87911fb59`
- [x] tsc -b passes (verified twice — before and after commit via lint-staged prettier reformat)
- [x] Zero deleted-function references in apps/web/src
- [x] No Phase-68 logic introduced
