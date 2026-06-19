---
created: 2026-02-07T10:00
title: Upload store stuck in "registering" if addFiles fails
area: ui
files:
  - apps/web/src/components/file-browser/UploadZone.tsx
  - apps/web/src/components/file-browser/EmptyState.tsx
  - apps/web/src/stores/upload.store.ts
---

## Problem

If `addFiles` (batch folder metadata registration) throws after `setRegistering()` is called, the upload store stays in `'registering'` status indefinitely. The catch block sets local component error state but never updates the upload store, so the upload modal remains stuck and `isUploading` continues returning `true`.

This affects both `UploadZone.tsx` and `EmptyState.tsx` which share the same pattern.

Discovered via CodeRabbit review on PR #56.

## Solution

Call `useUploadStore.getState().setError(message)` in the catch block when `addFiles` fails, so the store transitions out of `'registering'` and the UI can recover:

```diff
  } catch (err) {
    if ((err as Error).message !== 'Upload cancelled by user') {
+     useUploadStore.getState().setError((err as Error).message);
      setError((err as Error).message);
    }
  }
```

Apply to both UploadZone.tsx and EmptyState.tsx.
