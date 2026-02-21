---
title: Lazy migration of legacy FilePointers to random IPNS keys
area: web
created: 2026-02-21
files:
  - apps/web/src/services/file-metadata.service.ts
  - apps/web/src/services/folder.service.ts
  - apps/web/src/hooks/useFolder.ts
---

## Problem

Legacy FilePointers (created before the random IPNS key migration) lack the `ipnsPrivateKeyEncrypted` field. The `getFileIpnsPrivateKey()` helper falls back to HKDF derivation each time, but never writes the wrapped key back to the FilePointer. This means HKDF code paths must be maintained indefinitely and legacy files never migrate to the new format.

## Solution

When `getFileIpnsPrivateKey()` uses the HKDF fallback, wrap the derived key with the user's public key and update the FilePointer's `ipnsPrivateKeyEncrypted` field. Flag the parent folder for metadata re-publish so the updated FilePointer is persisted.

This requires passing `userPublicKey` into `getFileIpnsPrivateKey()` and having a mechanism to trigger folder metadata re-publish (e.g., returning a "dirty" flag that the caller uses to schedule a folder publish). Gradually, all actively-used folders will be migrated, allowing eventual removal of the HKDF code path.

The desktop Rust side should implement the same pattern: when `populate_folder()` derives a key via HKDF fallback, ECIES-wrap it and cache in `file_ipns_key_encrypted_hex` so the next `build_folder_metadata()` call writes it back.
