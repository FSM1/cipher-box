---
created: 2026-01-23T12:00
title: Add native file overwrite/edit support
area: api
files:
  - apps/web/src/services/folder.service.ts:375-418
  - apps/web/src/components/file-browser/UploadZone.tsx
---

## Problem

Currently, CipherBox doesn't support native file overwriting. When a user tries to upload a file with the same name as an existing file, the system throws an error: "A file with this name already exists."

To "edit" or update a file, users must:

1. Delete the existing file
2. Re-upload the new version

This is a poor UX for users who want to update documents frequently. The E2E test suite (full-workflow.spec.ts) works around this by testing delete + re-upload as the "edit" workflow.

Reference: `addFileToFolder` in folder.service.ts lines 375-418 checks for name collision and throws error.

## Solution

TBD - Options to consider:

1. **Silent overwrite**: Detect existing file, delete old CID, update entry with new CID
2. **Confirmation dialog**: "File exists. Replace?" with option to rename or cancel
3. **Versioning**: Keep both versions (out of scope per PRD v1.0 - no file versioning)

For v1.0, option 2 (confirmation dialog) would be the simplest UX improvement without adding versioning complexity.

Implementation would involve:

- Check for name collision in upload flow before IPFS upload
- Show confirmation dialog if collision detected
- On confirm: delete old file entry (unpin CID), add new file entry
- Single IPNS publish with updated children array
