---
created: 2026-02-07T15:30
title: Orphaned IPFS pins on failed folder registration leak quota
area: ui
files:
  - apps/web/src/components/file-browser/UploadZone.tsx:69-96
  - apps/web/src/components/file-browser/EmptyState.tsx:52-76
  - apps/web/src/services/upload.service.ts
---

## Problem

When file upload succeeds (encrypt + pin on IPFS) but `addFiles()` fails during folder metadata registration (e.g. duplicate filename, network error, IPNS publish failure), the already-pinned CIDs are never cleaned up. This leaks storage quota.

Observed during Playwright verification: uploading a duplicate file name caused `addFiles()` to reject with "A file with name X already exists", but quota increased by the full file size because the IPFS pin was never rolled back.

The catch block in UploadZone and EmptyState currently calls `setError()` on the upload store but does not unpin the uploaded CIDs.

Related: `2026-01-23-pre-upload-file-validation.md` addresses preventing the problem via pre-upload validation. This todo addresses cleanup when registration fails for any reason (network, IPNS, unexpected errors).

## Solution

In the catch block of UploadZone/EmptyState `handleDrop`, after `upload()` succeeds but `addFiles()` fails:

1. Collect the CIDs from `uploadedFiles` (returned by `upload()`)
2. Fire-and-forget unpin calls for each CID (consistent with existing delete pattern per decision 05-04)
3. Refresh quota after cleanup to reflect correct usage

Consider extracting this into a shared helper since both UploadZone and EmptyState have identical upload logic.
