---
created: 2026-03-24T05:01:42.048Z
title: Separate vault key blob from root folder IPNS name
area: core
priority: high
files:
  - apps/web/src/hooks/useAuth.ts
  - apps/web/src/services/folder.service.ts:968
  - apps/desktop/src-tauri/src/commands/vault.rs
  - apps/desktop/src-tauri/src/fuse/mod.rs
  - packages/core/src/vault/blob.ts
  - packages/core/src/crypto/hkdf.ts
  - apps/web/public/recovery.html
---

## Problem

The vault IPNS name currently serves double duty: it stores a v2 blob (ECIES-wrapped rootFolderKey + encrypted root folder metadata) on vault init, but `updateFolderMetadata` on the web writes v1 JSON for ALL folders including root. After any root folder operation (create subfolder, upload file), the IPNS pointer gets overwritten with v1 JSON, and the next login throws "Vault blob is not v2 format".

The desktop avoids this because `encrypt_root_metadata_to_v2_blob` in `fuse/mod.rs` always wraps root publishes in v2, but the web client has no equivalent — it uses the same v1 path for every folder. This asymmetry means:

1. Desktop root folder publishes → v2 blob (correct, login works)
2. Web root folder publishes → v1 JSON (breaks next login)

The root cause is architectural: v2 blob format conflates key storage (rootFolderKey) with folder metadata into one IPNS record.

## Solution

Derive a **dedicated IPNS name** for the vault key blob using a different HKDF context (e.g., `"cipherbox-vault-key"` vs `"cipherbox-vault-ipns"` for the root folder). This cleanly separates concerns:

- **Vault key IPNS name**: stores v2 blob with ECIES-wrapped rootFolderKey. Written once on vault init. Read on every login. Never overwritten by folder operations.
- **Root folder IPNS name**: standard v1 JSON `{iv, data}` like every other folder. Updated on every root folder mutation.

Changes needed:

1. `hkdf.ts` / `hkdf.rs`: add `deriveVaultKeyIpnsKeypair` with distinct HKDF context
2. `useAuth.ts`: new user init publishes v2 blob to vault key IPNS; login reads from vault key IPNS; root folder init uses separate root folder IPNS with v1
3. `vault.rs`: same separation for desktop init and fetch
4. `folder.service.ts`: remove v2 detection from `fetchAndDecryptMetadata` (all folders are v1)
5. `recovery.html`: IPFS-direct path resolves vault key IPNS name, not root folder IPNS
6. API: vault record may need a second IPNS name field, or vault key IPNS can be derived client-side only
7. Remove `encrypt_root_metadata_to_v2_blob` from desktop FUSE — root folder uses v1 like everything else
