---
phase: 66-api-schema-cutover-publish-gate-and-tombstone
plan: "03"
subsystem: shares
tags: [shares, entities, dto, descriptor-ref, schema]
status: complete

dependency_graph:
  requires: []
  provides:
    - Share entity reshaped to descriptor-ref model
    - ShareInvite entity slimmed (root identity + single readKey + optional write ref)
    - ShareKey entity deleted (DATA-01)
    - Descriptor-ref DTOs for create/invite/claim/response
  affects:
    - apps/api/src/shares/entities/
    - apps/api/src/shares/dto/
    - apps/api/src/shares/shares.module.ts
    - apps/api/src/shares/types.ts

tech_stack:
  added: []
  patterns:
    - TypeORM @Unique class-level decorator for plain unique constraint
    - TypeORM bigint as string convention for rootGeneration
    - Descriptor-ref grant model (readDescriptorRef/writeDescriptorRef) replacing per-key grants

key_files:
  created: []
  modified:
    - apps/api/src/shares/entities/share.entity.ts
    - apps/api/src/shares/entities/share-invite.entity.ts
    - apps/api/src/shares/entities/index.ts
    - apps/api/src/shares/shares.module.ts
    - apps/api/src/shares/types.ts
    - apps/api/src/shares/dto/create-share.dto.ts
    - apps/api/src/shares/dto/create-invite.dto.ts
    - apps/api/src/shares/dto/claim-invite.dto.ts
    - apps/api/src/shares/dto/share-response.dto.ts
    - apps/api/src/shares/dto/index.ts
  deleted:
    - apps/api/src/shares/entities/share-key.entity.ts
    - apps/api/src/shares/dto/share-key.dto.ts
    - apps/api/src/shares/dto/update-permission.dto.ts

decisions:
  - "Deleted SHARE_KEY_TYPES/ShareKeyType and CHILD_KEY_TYPES/ChildKeyType from types.ts together in Task 1 since both become unused after Task 2; intermediate broken-import state is acceptable given build is intentionally red until 66-04"
  - "Share entity @Unique uses field names not column names per TypeORM convention"
  - "writeDescriptorRef presence is the sole write-vs-read signal (D-09); no separate permission column"
  - "itemName/itemType dropped from ShareInvite; itemNameEncrypted kept for zero-knowledge display"

metrics:
  duration: "6m"
  completed: "2026-06-30"
  tasks_completed: 2
  tasks_total: 2
  files_changed: 13
---

# Phase 66 Plan 03: Share/ShareInvite Entity and DTO Reshape Summary

**One-liner:** Reshaped Share/ShareInvite entities and DTOs to descriptor-ref grant model; deleted ShareKey entity and associated DTOs (DATA-01/DATA-02).

## What Was Built

The `shares` type layer is now the `node/v3` descriptor-ref grant model per D-05/D-06/D-09/D-11:

### Share entity (reshaped)

Five new columns replacing the old per-key grant model:

- `readDescriptorRef` (bytea, NOT NULL) — ECIES descriptor ref for read access
- `writeDescriptorRef` (bytea, nullable) — presence signals write grant (D-09)
- `rootNodeId` (uuid) — root node identity
- `rootIpnsName` (varchar 255) — IPNS name of root node
- `rootGeneration` (bigint, default 0) — generation at share time (TypeORM returns as string)

Dropped: `itemType`, `ipnsName`, `itemName`, `encryptedKey`, `permission`, `encryptedIpnsKey`, `revokedAt`, `shareKeys` OneToMany relation.

Plain `@Unique(['sharerId', 'recipientId', 'rootNodeId'])` replaces the old partial index comment (D-11: hard-delete means no revoked rows coexist).

### ShareInvite entity (slimmed)

Dropped: `itemType`, `itemName`, `encryptedChildKeys`.
Renamed: `ipnsName` → `rootIpnsName` (column `root_ipns_name`).
Added: `rootNodeId`, `rootGeneration`, `writeDescriptorRef` (nullable).
`encryptedKey` retained — semantics changed to single ephemeral-wrapped root readKey (D-05).

### Deleted

- `share-key.entity.ts` — ShareKey entity and `share_keys` table registration (DATA-01)
- `share-key.dto.ts` — AddShareKeysDto
- `update-permission.dto.ts` — UpdatePermissionDto

### DTOs (reshaped)

- `CreateShareDto`: `readDescriptorRef` + optional `writeDescriptorRef` + `rootNodeId`/`rootIpnsName`/`rootGeneration` + optional `itemNameEncrypted`
- `CreateInviteDto`: `rootIpnsName`/`rootNodeId`/`rootGeneration` + `encryptedKey` (single readKey) + optional `writeDescriptorRef`/`itemNameEncrypted`
- `ClaimInviteDto`: `readDescriptorRef` + optional `writeDescriptorRef` + optional `itemNameEncrypted`
- `share-response.dto.ts`: `CreateShareResponseDto`/`ReceivedShareResponseDto`/`SentShareResponseDto` expose descriptor refs + root identity; `PendingRotationResponseDto`/`ShareKeyResponseDto` deleted

### Module + barrel updates

- `shares.module.ts`: `TypeOrmModule.forFeature([Share, ShareInvite, User])` — ShareKey removed
- `entities/index.ts`: exports Share + ShareInvite only
- `dto/index.ts`: removed AddShareKeysDto, ShareKeyResponseDto, PendingRotationResponseDto; added RevokeForItemsResponseDto
- `types.ts`: removed SHARE_KEY_TYPES/ShareKeyType and CHILD_KEY_TYPES/ChildKeyType (both now unused)

## Threat Model Coverage

| Threat ID | Disposition | How Mitigated |
|-----------|-------------|---------------|
| T-66-I2 | mitigate | No `revoked_at` column; hard-delete on revoke eliminates stale ECIES material (D-11; enforced in 66-04) |
| T-66-I3 | mitigate | `item_name`/`item_type` columns dropped; only `item_name_encrypted` (bytea) remains |
| T-66-T5 | mitigate | Plain `UNIQUE(sharer_id,recipient_id,root_node_id)` prevents duplicate grant rows (D-06) |

## Build Status

`pnpm --filter @cipherbox/api build` is intentionally red until 66-04 (service/controller rewrite).
This plan is the schema/type-definition layer only.

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| 1 — entities + module | 74b027a52 | refactor(api): reshape Share/ShareInvite entities and delete ShareKey |
| 2 — DTOs | a656ec748 | refactor(api): reshape shares DTOs to descriptor-ref grant model |

## Deviations from Plan

### Auto-applied simplifications

**1. [Rule 2 - Missing critical functionality] Removed CHILD_KEY_TYPES from types.ts in Task 1**

- **Found during:** Task 1 scope analysis
- **Issue:** Plan noted CHILD_KEY_TYPES should be removed "only if still referenced after Task 2" — but types.ts is in Task 1 scope and Task 2 removes all DTO usages. Both exports become unused after both tasks.
- **Fix:** Removed both SHARE_KEY_TYPES/ShareKeyType and CHILD_KEY_TYPES/ChildKeyType in Task 1. Intermediate broken-import state between commits is acceptable (build was already intentionally red).
- **Files modified:** apps/api/src/shares/types.ts

No other deviations — plan executed as specified.

## Self-Check: PASSED

- share-key.entity.ts: confirmed deleted
- share-key.dto.ts: confirmed deleted
- update-permission.dto.ts: confirmed deleted
- share.entity.ts: contains read_descriptor_ref, write_descriptor_ref, root_node_id, root_ipns_name, root_generation, @Unique decorator, zero OneToMany decorators
- share-invite.entity.ts: contains root_ipns_name, zero jsonb columns
- shares.module.ts: zero ShareKey references
- entities/index.ts: zero ShareKey references
- create-share.dto.ts: readDescriptorRef, rootNodeId present
- claim-invite.dto.ts: readDescriptorRef present, childKeys absent
- dto/index.ts: no AddShareKeysDto, ShareKeyResponseDto, PendingRotationResponseDto
- Task 1 commit 74b027a52: verified in git log
- Task 2 commit a656ec748: verified in git log
