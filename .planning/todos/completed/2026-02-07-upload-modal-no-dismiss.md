---
created: 2026-02-07T09:00
title: Upload modal has no close button and doesn't auto-dismiss
area: ui
files:
  - apps/web/src/components/file-browser/UploadZone.tsx
  - apps/web/src/components/file-browser/EmptyState.tsx
  - apps/web/src/stores/upload.store.ts
---

## Problem

After upload completes (100%), the upload modal stays open with no way to dismiss it:

- No close/dismiss button on the modal
- Clicking outside (modal-backdrop) doesn't dismiss it
- Pressing Escape doesn't dismiss it
- Blocks all interaction with the rest of the UI (pointer events intercepted)

Currently worked around by calling `setSuccess()` after `addFiles()` in UploadZone and EmptyState (PR #56), which transitions the store status and removes the modal. But the modal itself should have proper dismiss UX.

**Note:** When this is properly fixed, the E2E test `3.3 Upload files to documents folder` (`tests/e2e/tests/full-workflow.spec.ts:322`) will likely need updating — it currently depends on `setSuccess()` dismissing the modal backdrop so the subsequent `dblclick` can proceed.

Pre-existing issue from Phase 6 upload modal design (V1 simplified modal).

## Solution

1. Add a close/dismiss button to the upload progress modal
2. Auto-dismiss modal after a short delay (e.g. 2s) on success
3. Allow clicking outside (backdrop) or pressing Escape to dismiss after completion
4. Ensure upload store resets to 'idle' after modal is dismissed
