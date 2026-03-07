---
phase: 04-file-storage
plan: 04
subsystem: ui
tags: [react, zustand, ipfs, file-download, aes-256-gcm, ecies, delete]

# Dependency graph
requires:
  - phase: 04-01
    provides: IPFS relay endpoints (POST /ipfs/unpin)
  - phase: 04-03
    provides: Upload service types, quota store, auth store
  - phase: 03-01
    provides: '@cipherbox/crypto' with decryptAesGcm, unwrapKey, hexToBytes
provides:
  - File download service with IPFS gateway fetch and AES-256-GCM decryption
  - Download store for progress tracking (loaded/total bytes, status)
  - useFileDownload hook for React components
  - Delete service with quota update
  - useFileDelete hook for single and bulk delete
affects:
  - 05-folder-operations (will need download/delete integration for folder contents)
  - 06-metadata-management (file metadata display)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'Streaming download with progress via ReadableStream chunks'
    - 'File key cleared from memory immediately after decryption'
    - 'triggerBrowserDownload via Blob URL and anchor click'
    - 'Zustand download store mirrors upload store pattern'

key-files:
  created:
    - apps/web/src/services/download.service.ts
    - apps/web/src/stores/download.store.ts
    - apps/web/src/hooks/useFileDownload.ts
    - apps/web/src/services/delete.service.ts
    - apps/web/src/hooks/useFileDelete.ts
  modified:
    - apps/web/src/lib/api/ipfs.ts

key-decisions:
  - 'Pinata gateway direct fetch (no relay for download)'
  - 'ArrayBuffer cast for TypeScript 5.9 Blob compatibility'
  - 'Stream with progress only when Content-Length header present'

patterns-established:
  - 'download.service.ts pattern: fetch encrypted, unwrap key, decrypt, clear key'
  - 'useFileDownload hook pattern: matches useFileUpload for consistency'
  - 'delete.service.ts pattern: unpin then update quota'

# Metrics
duration: 3min
completed: 2026-01-20
---

# Phase 4 Plan 04: Frontend Download Summary

**IPFS gateway download with AES-256-GCM decryption, progress tracking via streaming, and file deletion with quota update**

## Performance

- **Duration:** 3 min
- **Started:** 2026-01-20T20:28:45Z
- **Completed:** 2026-01-20T20:31:31Z
- **Tasks:** 3
- **Files created:** 5, modified: 1

## Accomplishments

- Created download service with IPFS gateway fetch and client-side decryption
- Built download store tracking download status and progress (bytes loaded/total)
- Implemented useFileDownload hook providing unified download interface
- Created delete service that unpins from IPFS and updates quota
- Built useFileDelete hook supporting single and bulk delete operations

## Task Commits

Each task was committed atomically:

1. **Task 1: Create download service with decryption** - `2927e94` (feat)
2. **Task 2: Create download store and useFileDownload hook** - `516212f` (feat)
3. **Task 3: Add delete file functionality** - `097e564` (feat)

## Files Created/Modified

### Services

- `apps/web/src/services/download.service.ts` - Download from IPFS, decrypt with AES-256-GCM
- `apps/web/src/services/delete.service.ts` - Unpin from IPFS and update quota

### Stores

- `apps/web/src/stores/download.store.ts` - Download progress/status state management

### Hooks

- `apps/web/src/hooks/useFileDownload.ts` - React hook for file download with progress
- `apps/web/src/hooks/useFileDelete.ts` - React hook for single and bulk delete

### Modified

- `apps/web/src/lib/api/ipfs.ts` - Added fetchFromIpfs() with progress callback

## Decisions Made

1. **Pinata gateway direct fetch** - Downloads go directly to gateway URL (no backend relay needed for reading public IPFS content)
2. **ArrayBuffer cast for TypeScript 5.9** - Same pattern as upload service for Blob construction
3. **Stream progress only with Content-Length** - Falls back to simple arrayBuffer if header not present

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed TypeScript 5.9 ArrayBuffer type error in triggerBrowserDownload**

- **Found during:** Task 1 (download.service.ts verification)
- **Issue:** `Uint8Array` not directly assignable to `BlobPart` in TypeScript 5.9
- **Fix:** Added explicit cast `content.buffer as ArrayBuffer` in Blob constructor
- **Files modified:** apps/web/src/services/download.service.ts
- **Verification:** Build succeeds
- **Committed in:** 2927e94 (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 bug)
**Impact on plan:** Same TypeScript 5.9 issue encountered in 04-03. Documented pattern reused.

## Issues Encountered

None - the TypeScript ArrayBuffer issue was a known pattern from 04-03 and was applied proactively.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 4 (File Storage) is now complete with all 4 plans executed
- Upload and download infrastructure ready for folder operations (Phase 5)
- Delete functionality ready for folder delete cascades
- Ready for metadata management (Phase 6) which will display file info using these services

---

_Phase: 04-file-storage_
_Completed: 2026-01-20_
