---
created: 2026-02-07T09:05
title: Upload button text stuck on "uploading..." after completion
area: ui
files:
  - apps/web/src/components/file-browser/UploadZone.tsx
  - apps/web/src/hooks/useFileUpload.ts
  - apps/web/src/stores/upload.store.ts
---

## Problem

The toolbar upload button shows "uploading..." even after upload completes. It should reset to "--upload" after completion. The `isUploading` check in `useFileUpload.ts` includes multiple statuses (encrypting, uploading, registering) but the store status may not fully cycle back to 'idle' or 'success' in all paths, leaving the button text stuck.

Pre-existing issue — upload status lifecycle may not fully reset.

## Solution

1. Ensure upload store status transitions to 'success' then resets to 'idle' after a brief delay
2. Verify `isUploading` correctly returns `false` once the upload flow completes
3. Consider adding a `reset()` call after successful upload completion (with delay for success state visibility)
