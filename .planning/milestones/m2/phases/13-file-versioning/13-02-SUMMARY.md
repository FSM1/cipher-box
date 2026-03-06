---
phase: 13-file-versioning
plan: 02
subsystem: ui
tags: [typescript, versioning, ipns, file-metadata, cooldown, pruning]

# Dependency graph
requires:
  - phase: 13-01
    provides: VersionEntry type in TypeScript and Rust, FileMetadata versions array
  - phase: 12.6-per-file-ipns
    provides: updateFileMetadata service, per-file IPNS architecture
provides:
  - Version creation logic in updateFileMetadata with auto-push to versions array
  - shouldCreateVersion helper with 15-minute cooldown for text editor saves
  - Max 10 versions auto-pruning with pruned CID unpinning
  - handleUpdateFile preserves old CIDs as version history (VER-01)
affects:
  [
    13-03 version history UI (needs to read versions array),
    13-04 restore logic (calls updateFileMetadata with createVersion),
    13-05 retention/pruning UI (manual version deletion),
  ]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'Versioning in updateFileMetadata: push current to versions before overwriting, prune oldest beyond limit'
    - 'shouldCreateVersion cooldown pattern: forceVersion bypasses, timestamp check against 15min window'
    - 'prunedCids return value pattern: caller handles unpinning of excess versions'

key-files:
  created: []
  modified:
    - apps/web/src/services/file-metadata.service.ts
    - apps/web/src/hooks/useFolder.ts

key-decisions:
  - 'shouldCreateVersion returns true for first version (no existing versions) even without forceVersion'
  - 'Text editor save uses cooldown (forceVersion defaults to false); web re-upload path will pass forceVersion: true when added'
  - 'Pruned version CIDs returned to caller (not unpinned inside service) for separation of concerns'

patterns-established:
  - 'Version cooldown pattern: newest version timestamp compared against VERSION_COOLDOWN_MS (15min)'
  - 'createVersion boolean parameter on updateFileMetadata controls versioning per-call'

# Metrics
duration: 4min
completed: 2026-02-19
---

# Phase 13 Plan 02: Version Creation Service Summary

**updateFileMetadata pushes current metadata to versions array on content update with 15-min cooldown, max 10 auto-pruning, and old CID preservation (VER-01)**

## Performance

- **Duration:** 4 min
- **Started:** 2026-02-19T17:46:50Z
- **Completed:** 2026-02-19T17:50:27Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Added versioning logic to updateFileMetadata: pushes current state to versions array (newest first) before overwriting with new content
- Implemented shouldCreateVersion helper with 15-minute cooldown for text editor saves and forceVersion bypass for explicit re-uploads
- Enforced max 10 versions per file with auto-pruning (oldest pruned, CIDs returned for unpinning)
- Removed old CID unpinning from handleUpdateFile (VER-01: old CIDs stay pinned as version history)

## Task Commits

Each task was committed atomically:

1. **Task 1: Add versioning logic to updateFileMetadata service** - `57e5309d6` (feat)
2. **Task 2: Update useFolder handleUpdateFile to stop unpinning and use versioning** - `6e0f479ef` (feat)

## Files Created/Modified

- `apps/web/src/services/file-metadata.service.ts` - VersionEntry import, MAX_VERSIONS_PER_FILE/VERSION_COOLDOWN_MS constants, shouldCreateVersion helper, updateFileMetadata versioning logic with createVersion param and prunedCids return
- `apps/web/src/hooks/useFolder.ts` - shouldCreateVersion import, forceVersion parameter on handleUpdateFile, createVersion determination, pruned CID unpinning (replaces old CID unpinning)

## Decisions Made

- shouldCreateVersion returns true for first version (no existing versions) even without forceVersion -- first save always creates a baseline version
- Text editor save path defaults to cooldown behavior (forceVersion not set); web re-upload will pass forceVersion: true when the replace flow is implemented
- Pruned version CIDs are returned from updateFileMetadata to caller rather than unpinning inside the service, maintaining separation of concerns

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Version creation engine functional: any content update through handleUpdateFile creates version entries with proper cooldown logic
- versions array populated in FileMetadata for Plan 03 (version history UI) to read and display
- Pruned CID unpinning ready for Plan 05 (manual version deletion will use similar pattern)
- forceVersion parameter ready for future web re-upload "replace" action in file browser context menu

---

_Phase: 13-file-versioning_
_Completed: 2026-02-19_
