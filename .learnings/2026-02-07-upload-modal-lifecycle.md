# Upload Modal Lifecycle Bugs

**Date:** 2026-02-07

## Original Prompt

> Todos #3 (upload modal no dismiss) and #4 (button text stuck on "uploading...") are related — fix them together.

## What I Learned

- The upload store has 7 statuses (`idle`, `encrypting`, `uploading`, `registering`, `success`, `error`, `cancelled`) but the UploadModal only had dismiss controls for `error` and `cancelled` — leaving `registering` as a dead-end with zero buttons
- The modal hid instantly on `success` (`isVisible = status !== 'idle' && status !== 'success'`) giving no user feedback that upload completed
- The real killer: `addFiles()` failures in UploadZone/EmptyState only set local component error state, never called `useUploadStore.setError()` — so the store stayed stuck in `registering` forever, modal stuck, button stuck
- Playwright verification caught a **separate bug** not in the original todos: failed `addFiles()` (duplicate filename) still consumed quota because uploaded CIDs were never unpinned on rollback — orphaned pins leak quota
- When tracing state machine bugs, always map every status to its available transitions AND its UI controls — dead-end states with no escape are the pattern to watch for

## What Would Have Helped

- A state machine diagram for the upload store showing all transitions and which UI controls are available in each state
- Knowing upfront that UploadZone and EmptyState have nearly identical `handleDrop` implementations — both needed the same fix, and this duplication is a maintenance risk

## Key Files

- `apps/web/src/stores/upload.store.ts` — upload state machine
- `apps/web/src/components/file-browser/UploadModal.tsx` — modal visibility and button logic
- `apps/web/src/components/file-browser/UploadZone.tsx` — toolbar upload with handleDrop
- `apps/web/src/components/file-browser/EmptyState.tsx` — empty state upload with identical handleDrop
- `apps/web/src/hooks/useFileUpload.ts` — `isUploading` derived state
