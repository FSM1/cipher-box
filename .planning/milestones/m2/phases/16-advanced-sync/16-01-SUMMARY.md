---
phase: 16-advanced-sync
plan: 01
subsystem: api
tags: [ipns, concurrency, conflict-detection, optimistic-locking, nestjs]

# Dependency graph
requires:
  - phase: 12.6-per-file-ipns
    provides: IPNS publish endpoints and FolderIpns entity with sequenceNumber
provides:
  - expectedSequenceNumber optional field on publish DTOs
  - ConflictException (409) on sequence mismatch in upsertFolderIpns
  - Batch publish fails entirely when folder record conflicts
  - 409 response body with currentSequenceNumber for client re-sync
  - Unit tests covering all conflict detection paths
affects: [16-02, 16-03, 16-04, web-sync-service, desktop-fuse-sync]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'Optimistic concurrency via expectedSequenceNumber on IPNS publish'
    - 'Application-level BigInt comparison for sequence mismatch detection'
    - 'Batch abort on ConflictException from any folder record'

key-files:
  created: []
  modified:
    - apps/api/src/ipns/dto/publish.dto.ts
    - apps/api/src/ipns/ipns.service.ts
    - apps/api/src/ipns/ipns.controller.ts
    - apps/api/src/ipns/ipns.service.spec.ts

key-decisions:
  - 'Application-level read-compare-write sufficient for v1 (TOCTOU risk mitigated by per-folder publish lock on desktop + sequential single-user API requests)'
  - 'Backward compatible: omitting expectedSequenceNumber preserves unconditional publish behavior'
  - 'Batch publish aborts entirely on folder conflict (not partial success)'

patterns-established:
  - 'Optimistic concurrency: client sends expectedSequenceNumber, server returns 409 with currentSequenceNumber on mismatch'
  - 'BigInt string comparison for sequence numbers (supports numbers beyond MAX_SAFE_INTEGER)'

# Metrics
duration: 2min
completed: 2026-03-03
---

# Phase 16 Plan 01: Optimistic Concurrency Control Summary

**expectedSequenceNumber conflict detection on IPNS publish endpoints with 409 Conflict response and full unit test coverage**

## Performance

- **Duration:** 2 min
- **Started:** 2026-03-03T11:58:37Z
- **Completed:** 2026-03-03T12:01:00Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- Added `expectedSequenceNumber` optional field to `PublishIpnsDto` and `PublishIpnsEntryDto` with numeric string validation
- Implemented conflict detection in `upsertFolderIpns` using BigInt comparison, throwing `ConflictException` with `currentSequenceNumber` in response body
- Batch publish propagates `ConflictException` to fail entire batch when any folder record has a stale sequence number
- 5 unit tests covering: stale rejection, matching acceptance, backward compat, batch conflict, batch success

## Task Commits

Each task was committed atomically:

1. **Task 1: Add expectedSequenceNumber to DTOs and conflict check to service** - `0272fef93` (feat)
2. **Task 2: Unit tests for conflict detection** - `8b1d78a0f` (test)

## Files Created/Modified

- `apps/api/src/ipns/dto/publish.dto.ts` - Added `expectedSequenceNumber` optional field to `PublishIpnsDto` and `PublishIpnsEntryDto`
- `apps/api/src/ipns/ipns.service.ts` - Added ConflictException conflict check in `upsertFolderIpns`, threaded `expectedSequenceNumber` through `publishRecord` and `publishBatch`
- `apps/api/src/ipns/ipns.controller.ts` - Added 409 Conflict `@ApiResponse` to both endpoints
- `apps/api/src/ipns/ipns.service.spec.ts` - Added 5 conflict detection unit tests in new `describe('conflict detection')` block

## Decisions Made

- Application-level read-compare-write is sufficient for v1 -- true simultaneous DB writes are extremely unlikely given per-folder publish lock on desktop client and sequential nature of single-user API requests
- Backward compatible by design: omitting `expectedSequenceNumber` preserves existing unconditional publish behavior unchanged
- Batch publish aborts entirely on folder conflict rather than partial success, so clients get a clear signal to re-sync

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- API conflict detection ready for client integration (Plan 02: web client sync service)
- OpenAPI spec will be regenerated in Plan 02 via `pnpm api:generate` to expose the new 409 response and `expectedSequenceNumber` field to the typed client
- Clients need: fetch current sequence number from resolve response, pass as `expectedSequenceNumber` on publish, handle 409 by re-resolving and retrying

---

_Phase: 16-advanced-sync_
_Completed: 2026-03-03_
