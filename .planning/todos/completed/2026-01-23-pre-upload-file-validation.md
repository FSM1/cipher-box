---
created: 2026-01-23T12:00
title: Pre-upload file name validation and duplicate prevention
area: ui
files:
  - apps/web/src/components/file-browser/UploadZone.tsx
  - apps/web/src/services/folder.service.ts:375-418
---

## Problem

Currently, file name validation happens **after** the file is uploaded to IPFS. When a user uploads a file with a name that already exists in the folder, the upload completes successfully but `addFileToFolder` throws: "A file with this name already exists."

This wastes:

- Time (uploading to IPFS before checking)
- Bandwidth (file encrypted and sent)
- Potentially storage quota (if unpin doesn't happen immediately)

The webapp should validate file names **before** starting the upload.

## Solution

Add pre-upload validation in the UploadZone component:

1. **Before upload starts**, check if any selected file names collide with existing items in the current folder
2. **If collision detected**, show error immediately: "File '[name]' already exists in this folder"
3. **Reject the upload** without hitting IPFS

Validation should check:

- Exact name matches against `currentFolder.children`
- Both files and folders (can't have file "foo" and folder "foo")
- Case sensitivity (match current system behavior)

Additional validation to consider:

- Invalid characters in file names
- Reserved names (if any)
- Maximum file name length

This prevents wasted uploads and provides immediate feedback to users.
