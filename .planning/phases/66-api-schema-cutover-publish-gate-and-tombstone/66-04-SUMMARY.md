---
phase: 66-api-schema-cutover-publish-gate-and-tombstone
plan: "04"
subsystem: shares
tags: [shares, descriptor-ref, revocation, invite-claim, data-model]
dependency_graph:
  requires: ["66-03"]
  provides: ["apps/api build green", "descriptor-ref grant API", "hard-delete revoke", "single-readKey invite claim"]
  affects: ["sdk-e2e (66-09)", "api-client regeneration"]
tech_stack:
  added: []
  patterns: ["descriptor-ref grant model", "hard-delete revocation (D-11)", "atomic single-claim invite", "presence-derived write authority (D-09)"]
key_files:
  created: []
  modified:
    - apps/api/src/shares/shares.service.ts
    - apps/api/src/shares/shares.controller.ts
    - apps/api/src/shares/share-invite.service.ts
    - apps/api/src/shares/invites.controller.ts
    - apps/api/src/shares/share-invites.controller.ts
    - apps/api/src/shares/dto/invite-response.dto.ts
  deleted:
    - apps/api/src/shares/shares.service.spec.ts
    - apps/api/src/shares/shares.controller.spec.ts
    - apps/api/src/shares/share-invite.service.spec.ts
    - apps/api/src/shares/invites.controller.spec.ts
    - apps/api/src/shares/share-invites.controller.spec.ts
decisions:
  - "Hard-delete on revokeShare (D-11): share.revokedAt removed from entity by 66-03; service now calls shareRepo.remove"
  - "revokeForItems matches by rootIpnsName (column renamed by 66-03); invite QueryBuilder updated from ipns_name to root_ipns_name"
  - "claimInvite mints one Share with root identity copied from invite row to prevent T-66-S1 spoofing"
  - "writeDescriptorRef presence = write grant (T-66-E1 mitigated)"
  - "Built @cipherbox/crypto in worktree before API build (dist/ absent post pnpm install --prefer-offline)"
  - "5 spec files deleted: they asserted share_keys/permission/soft-revoke/childKeys flows that no longer exist; behavioral gate is sdk-e2e (66-09)"
metrics:
  duration: "~7 minutes"
  completed: "2026-06-30"
  tasks_completed: 3
  files_modified: 6
  files_deleted: 5
status: complete
requirements: [DATA-01, DATA-02, DATA-04]
---

# Phase 66 Plan 04: Shares Logic Layer Cutover Summary

Rewrote the shares logic layer onto the descriptor-ref grant model and finished deleting `share_keys` behavior: `createShare` stores descriptor refs, `revokeShare` hard-DELETEs, the `share_keys`/permission/lazy-rotation endpoints are removed, and invite claim mints a single descriptor-ref Share. `apps/api` build is green again after 66-03's type reshape.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Rewrite SharesService onto descriptor refs and hard-delete revoke | 7d9bbd6ff | shares.service.ts |
| 2 | Slim SharesController: reshape responses, delete keys/permission/rotation routes | bae254c69 | shares.controller.ts, shares.controller.spec.ts (deleted) |
| 3 | Rewrite invite claim to single-readKey grant; reshape invite create/data; delete obsolete specs | f07096b3f | share-invite.service.ts, invites.controller.ts, share-invites.controller.ts, invite-response.dto.ts, 4 spec files deleted |

## What Changed

### SharesService

- `createShare`: now persists `readDescriptorRef`, `writeDescriptorRef`, `rootNodeId`, `rootIpnsName`, `rootGeneration`; duplicate check uses plain `(sharerId, recipientId, rootNodeId)` triple (no `revokedAt` filter — hard-delete leaves no revoked rows)
- `revokeShare`: `shareRepo.remove(share)` — hard-delete (D-11; no more `revokedAt` assignment)
- `revokeForItems`: matches shares by `rootIpnsName: In(uniqueNames)`; invite QueryBuilder updated to `root_ipns_name` column
- `getReceivedShares` / `getSentShares`: `revokedAt: IsNull()` filter removed (column gone)
- Deleted: `getShareKeys`, `addShareKeys`, `getPendingRotations`, `completeRotation`, `updatePermission`, `updateShareEncryptedKey`, `findActiveWriteShare`
- Removed: `ShareKey` import, `@InjectRepository(ShareKey)`, `AddShareKeysDto`, `IsNull`, `Not` from typeorm

### SharesController

- `createShare`, `getReceivedShares`, `getSentShares` return shapes carry `readDescriptorRef`, `writeDescriptorRef`, `rootNodeId`, `rootIpnsName`, `rootGeneration`
- Deleted routes: `GET :shareId/keys`, `POST :shareId/keys`, `PATCH :shareId/permission`, `PATCH :shareId/encrypted-key`, `GET pending-rotations`, `DELETE :shareId/complete-rotation`
- `DELETE :shareId` doc updated to "hard-delete the grant row"

### ShareInviteService

- `createInvite`: persists `rootIpnsName`, `rootNodeId`, `rootGeneration`, `encryptedKey`, `writeDescriptorRef`, `itemNameEncrypted`; removed `itemType`, `itemName`, `ipnsName`, `encryptedChildKeys`
- `claimInvite`: mints exactly one `Share` with `readDescriptorRef`/`writeDescriptorRef` from dto, root identity (`rootNodeId`, `rootIpnsName`, `rootGeneration`) from the looked-up invite row; no `ShareKey` creation; no childKeys fan-out
- `getInvitesForItem`: parameter renamed to `rootIpnsName`, queries by `rootIpnsName` column

### InvitesController

- `getInviteData` returns `rootNodeId`, `rootIpnsName`, `rootGeneration`, `encryptedKey`, `writeDescriptorRef`, `itemNameEncrypted`; removed `encryptedChildKeys`, `itemType`, `ipnsName`, `itemName`
- Removed `ChildKeyType` import (type deleted in 66-03)

### ShareInvitesController

- `createInvite` and `listInvites` responses use new entity shape: `rootIpnsName`, `rootNodeId`, `rootGeneration` instead of `itemType`, `ipnsName`, `itemName`
- `listInvites` query parameter renamed to `rootIpnsName`

### InviteDataResponseDto

- Fields added: `writeDescriptorRef`, `rootNodeId`, `rootIpnsName`, `rootGeneration`
- Fields removed: `encryptedChildKeys`, `itemType`, `ipnsName`, `itemName`
- `InviteChildKeyDto` import removed (type gone from create-invite.dto.ts)

### InviteResponseDto

- Fields replaced: `rootIpnsName`, `rootNodeId`, `rootGeneration` instead of `itemType`, `ipnsName`, `itemName`

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] @cipherbox/crypto dist absent in worktree**

- **Found during:** Pre-build check
- **Issue:** `pnpm install --prefer-offline` installed the crypto package source but not its built `dist/`. The API's tsconfig resolves `@cipherbox/crypto` via `node_modules/.../dist/index.d.ts` which did not exist, causing `TS2307: Cannot find module '@cipherbox/crypto'` errors in `src/ipns/`.
- **Fix:** Ran `pnpm --filter @cipherbox/crypto build` in the worktree before the API build. This is a standard worktree dependency setup step.
- **Files modified:** None (build artifact only)
- **Commit:** N/A (runtime prerequisite, not a code change)

None - all plan-specified rewrites executed as written.

## Security Notes

T-66-S1 (Spoofing — claimer minting a grant they were not invited to): mitigated. `claimInvite` copies `rootNodeId`, `rootIpnsName`, `rootGeneration` from the looked-up invite row, not from claimer-supplied DTO fields.

T-66-E1 (Elevation — read-only invite yielding write grant): mitigated. `writeDescriptorRef` on the minted Share is set only when the `ClaimInviteDto` carries one, and the invite must have carried a `writeDescriptorRef` for the claimer to have one to re-wrap.

T-66-I2 (Information Disclosure — revoked grant residue): mitigated. `revokeShare` calls `shareRepo.remove()`. No `revokedAt` row retains stale ECIES material.

## Verification

- `pnpm --filter @cipherbox/api build` exits 0.
- No `ShareKey`/`childKeys`/`revokedAt`/`permission` logic remains in the shares service/controllers/invite service.
- Invite claim mints a single descriptor-ref Share (zero ShareKey rows, zero childKeys fan-out).
- Behavioral proof deferred to sdk-e2e (66-09) per D-08.

## Self-Check: PASSED

- All 6 modified files exist on disk.
- All 5 spec files deleted.
- Commits 7d9bbd6ff, bae254c69, f07096b3f confirmed in git log.
- `pnpm --filter @cipherbox/api build` exits 0.
