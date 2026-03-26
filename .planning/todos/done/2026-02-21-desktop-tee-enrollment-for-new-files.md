---
title: Desktop TEE enrollment for new files
area: desktop
created: 2026-02-21
files:
  - apps/desktop/src-tauri/src/fuse/operations.rs
  - apps/desktop/src-tauri/src/fuse/mod.rs
---

## Problem

Files created from the desktop FUSE mount are not enrolled with the TEE for automatic IPNS republishing. The web app wraps the IPNS private key with the TEE public key during `createFileMetadata()` and sends `encryptedIpnsPrivateKey` + `keyEpoch` in the IPNS publish payload. The desktop `create()` and `build_folder_metadata()` code paths skip this step entirely.

Without TEE enrollment, files created on the desktop will have their IPNS records expire after the IPNS lifetime (~48h) unless the desktop app re-publishes them. The TEE republisher only handles records it has keys for.

## Solution

In the desktop's metadata publish path (or at file creation time), wrap the file's IPNS private key with the TEE public key and include `encryptedIpnsPrivateKey` + `keyEpoch` in the IPNS publish API call. The TEE public key is already available in the auth state (`tee_keys` from the login response).

This also applies to subfolder IPNS keys created on desktop, though those are less common since most folder creation happens via the web app.
