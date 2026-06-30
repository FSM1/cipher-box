---
phase: 66-api-schema-cutover-publish-gate-and-tombstone
plan: "06"
subsystem: api-client
tags: [api-client, openapi, regeneration, phase-66]
dependency_graph:
  requires: ["66-02", "66-04"]
  provides: ["66-07", "66-08", "66-09"]
  affects: [packages/api-client]
tech_stack:
  added: []
  patterns: [orval, openapi, pnpm-api-generate]
key_files:
  created:
    - packages/api-client/src/models/tombstoneIpnsDto.ts
    - packages/api-client/src/models/ipnsControllerPublishRecord410.ts
    - packages/api-client/src/models/ipnsControllerResolveRecord410.ts
  modified:
    - apps/api/scripts/generate-openapi.ts
    - packages/api-client/openapi.json
    - packages/api-client/src/generated/ipns/ipns.ts
    - packages/api-client/src/generated/shares/shares.ts
    - packages/api-client/src/generated/invites/invites.ts
    - packages/api-client/src/models/publishIpnsDto.ts
    - packages/api-client/src/models/index.ts
decisions:
  - "Removed ShareKey import from generate-openapi.ts as a Rule 3 auto-fix (entity deleted in Wave 1)"
metrics:
  duration: 7m
  completed: "2026-06-30T16:11:32Z"
  tasks_completed: 1
  tasks_total: 1
  files_changed: 109
status: complete
---

# Phase 66 Plan 06: API Client Regeneration Summary

Regenerated `@cipherbox/api-client` to reflect the full Phase-66 API surface: tombstone endpoint, `generation` field on publish, 410 markers, descriptor-ref share/invite DTOs, and removal of deleted share_keys/permission/rotation operations.

## Tasks

### Task 1: Regenerate and commit the API client

**Status:** Complete
**Commit:** 54be324de

Ran `pnpm openapi:generate && pnpm --filter @cipherbox/api-client generate && pnpm --filter @cipherbox/api-client build` successfully. All acceptance criteria verified.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Removed deleted ShareKey import from generate-openapi.ts**

- **Found during:** Task 1 — `pnpm openapi:generate` failed with TS2307 on `../src/shares/entities/share-key.entity`
- **Issue:** `apps/api/scripts/generate-openapi.ts` still imported `ShareKey` and registered `mockShareKeyRepository` despite `share-key.entity.ts` being deleted in Wave 1 (66-02)
- **Fix:** Removed `import { ShareKey }` line, removed `mockShareKeyRepository` const and its entry in the providers array
- **Files modified:** `apps/api/scripts/generate-openapi.ts`
- **Commit:** 54be324de (same commit, no separate fix commit needed as fix + regeneration ship together)

## Acceptance Criteria Verification

- `pnpm --filter @cipherbox/api-client build` exits 0: PASSED
- `grep -rci "tombstone" packages/api-client/src/generated packages/api-client/openapi.json` >= 1: PASSED (20 matches)
- `grep -rc "generation" packages/api-client/openapi.json` >= 1: PASSED (4 matches)
- `grep -rci "IPNS_TOMBSTONED\|410" packages/api-client/openapi.json` >= 1: PASSED (4 matches)
- `grep -rc "GetShareKeys\|AddShareKeys\|GetPendingRotations\|CompleteRotation\|UpdatePermission\|UpdateShareEncryptedKey" packages/api-client/src/generated` returns 0: PASSED
- `bash scripts/check-api-client.sh` exits 0: PASSED

New models added: `tombstoneIpnsDto.ts`, `ipnsControllerPublishRecord410.ts`, `ipnsControllerResolveRecord410.ts`

## Self-Check: PASSED

- `packages/api-client/openapi.json` exists: FOUND
- `packages/api-client/src/models/tombstoneIpnsDto.ts` exists: FOUND
- `packages/api-client/src/models/ipnsControllerPublishRecord410.ts` exists: FOUND
- Commit 54be324de: FOUND
