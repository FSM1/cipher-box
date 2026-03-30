---
phase: 36-inline-upload-progress
plan: 02
subsystem: ui
tags: [react, zustand, upload, inline-progress, css, accessibility]

# Dependency graph
requires:
  - 'Plan 36-01: Per-file upload store with Map-based tracking'
provides:
  - 'UploadListItem component rendering inline upload rows matching FileListItem grid layout'
  - 'FileList virtual entry merging with alphabetical sort and duplicate filtering'
  - 'Retry wiring from UploadListItem through FileList to useDropUpload handleFileDrop'
  - 'Inline upload CSS with progress bar, pulse animation, error state, reduced motion'
  - 'Old popup components (UploadModal, UploadItem) and popup CSS fully deleted'
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'Virtual entry merging: upload-in-progress entries injected as FolderChild-compatible objects sorted alongside real files'
    - 'Fine-grained Zustand selectors per upload row to prevent full FileList re-render on progress updates'
    - 'Completion flash timer with useRef cleanup to prevent memory leaks'
    - 'Discriminated union via _uploading flag to distinguish virtual upload entries from real FolderChild items'

key-files:
  created:
    - apps/web/src/components/file-browser/UploadListItem.tsx
  modified:
    - apps/web/src/components/file-browser/FileList.tsx
    - apps/web/src/components/file-browser/FileBrowser.tsx
    - apps/web/src/components/file-browser/index.ts
    - apps/web/src/styles/upload.css

key-decisions:
  - 'Upload entries filtered by targetFolderId === parentId so rows only appear in the folder where upload was initiated'
  - 'completingNames set prevents duplicate entries during completion-to-real-file transition'
  - 'handleRetryUpload in FileBrowser calls handleFileDrop([file], currentFolderId) to re-trigger the actual upload pipeline'
  - 'Select-all checkbox counts only real items (not upload virtual entries) to avoid confusion'

patterns-established:
  - 'Virtual entry merging: cast upload entries as FolderChild-compatible objects with _uploading discriminator, then sort with real items'
  - 'Per-row store subscription: UploadListItem uses useUploadStore(s => s.files.get(fileId)) so progress updates only re-render the affected row'

requirements-completed: []

# Metrics
duration: 5min
completed: 2026-03-30
---

# Phase 36 Plan 02: Inline Upload UI Components Summary

**Inline UploadListItem component with progress bar, cancel/retry/dismiss buttons, wired into FileList with virtual entry merging and old popup components deleted**

## Performance

- **Duration:** 5 min
- **Started:** 2026-03-30T02:33:09Z
- **Completed:** 2026-03-30T02:38:57Z
- **Tasks:** 2
- **Files modified:** 6 (1 created, 2 deleted, 3 modified)

## Accomplishments

- Created UploadListItem component with fine-grained Zustand selector, progress bar, cancel/retry/dismiss buttons, completion flash timer, and ARIA accessibility
- Wired UploadListItem into FileList with virtual entry merging (alphabetical sort), folder-scoped filtering, and duplicate prevention during completion swap
- Connected retry callback through FileBrowser to useDropUpload's handleFileDrop for actual re-upload on retry
- Deleted UploadModal.tsx, UploadItem.tsx, and all popup CSS rules; added inline upload CSS with pulse animation and reduced motion support

## Task Commits

Each task was committed atomically:

1. **Task 1: Create UploadListItem component and inline CSS** - `bb1210a` (feat)
2. **Task 2: Wire UploadListItem into FileList, delete old popup components** - `1fad01f` (feat)

## Files Created/Modified

- `apps/web/src/components/file-browser/UploadListItem.tsx` - New inline upload row component matching FileListItem grid, with fine-grained store selector per file ID
- `apps/web/src/components/file-browser/FileList.tsx` - Virtual entry merging with upload store, _uploading discriminator, completingNames duplicate filter, onRetryUpload prop
- `apps/web/src/components/file-browser/FileBrowser.tsx` - Removed UploadModal import/render, added handleRetryUpload callback wired to handleFileDrop
- `apps/web/src/components/file-browser/index.ts` - Removed UploadModal/UploadItem exports, added UploadListItem export
- `apps/web/src/styles/upload.css` - Deleted all popup CSS, added inline upload CSS (progress bar, pulse animation, error state, reduced motion, focus-visible)
- `apps/web/src/components/file-browser/UploadModal.tsx` - Deleted
- `apps/web/src/components/file-browser/UploadItem.tsx` - Deleted

## Decisions Made

- Upload entries filtered by `targetFolderId === parentId` so upload rows only appear in the folder where the upload was initiated (not in parent/sibling folders)
- `completingNames` set filters out real files whose name matches a completing upload to prevent visual duplication during the 1s green flash
- `handleRetryUpload` calls `handleFileDrop([file], currentFolderId)` to re-trigger the full upload pipeline (encrypt, IPFS upload, register), not just visual reset
- Select-all checkbox counts only real items (`items.length`), not `allItems.length`, so upload entries don't inflate the count

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed Prettier formatting in FileList.tsx and FileBrowser.tsx**

- **Found during:** Task 2 (verification)
- **Issue:** Long line in FileList.tsx (line 205) and extra blank line in FileBrowser.tsx (line 368) caused Prettier violations
- **Fix:** Ran Prettier auto-fix on both files
- **Files modified:** apps/web/src/components/file-browser/FileList.tsx, apps/web/src/components/file-browser/FileBrowser.tsx
- **Verification:** pnpm lint passes for our modified files (pre-existing errors in vite.config.d.ts/js are unrelated)
- **Committed in:** 1fad01f (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (formatting only)
**Impact on plan:** Trivial formatting fix. No scope creep.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Known Stubs

None - all data paths are fully wired. UploadListItem subscribes to live upload store data. Retry callback is wired to the actual upload pipeline.

## Next Phase Readiness

- Inline upload progress UI is complete and ready for visual verification
- All decisions D-01 through D-11 are implemented
- No further plans in this phase

## Self-Check: PASSED

- All created files exist on disk (UploadListItem.tsx)
- All deleted files confirmed removed (UploadModal.tsx, UploadItem.tsx)
- All modified files exist on disk (FileList.tsx, FileBrowser.tsx, index.ts, upload.css)
- Both task commits found in git history (bb1210a, 1fad01f)
- SUMMARY.md created at expected path

---

_Phase: 36-inline-upload-progress_
_Completed: 2026-03-30_
