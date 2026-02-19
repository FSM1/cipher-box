---
created: 2026-02-18T22:15
title: Fix FUSE rename on SMB backend
area: desktop
files:
  - apps/desktop/src-tauri/src/fuse/operations.rs:1889
---

## Problem

File rename (`mv`) fails with "Permission denied" when using FUSE-T's SMB backend. The FUSE rename callback is never called — the macOS SMB client rejects the rename before sending it to the FUSE-T SMB server.

The SMB mount shows `(smbfs, nodev, nosuid, noowners, mounted by michael)`. The issue may be related to how the SMB client checks permissions for rename operations, or our `access()` callback's UID check (`req.uid() != attr.uid`) returning EACCES for SMB-sourced requests.

## Solution

TBD — investigate:

1. Whether SMB rename requires specific file/directory permissions
2. Whether our access() callback is being consulted and failing
3. Whether FUSE-T's SMB server needs a specific configuration for rename support
4. Check FUSE-T GitHub issues for known SMB rename limitations
