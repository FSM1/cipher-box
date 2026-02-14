---
created: 2026-02-14T06:00
title: Split file metadata into per-file IPNS objects (v2)
area: crypto
files:
  - packages/crypto/src/ipns/derive-name.ts
  - apps/web/src/services/folder.service.ts
  - apps/web/src/services/ipns.service.ts
  - 00-Preliminary-R&D/Documentation/DATA_FLOWS.md
  - 00-Preliminary-R&D/Documentation/TECHNICAL_ARCHITECTURE.md
---

## Problem

Currently, all file metadata (CID, fileKeyEncrypted, fileIv, size, timestamps) is embedded directly in folder metadata. This means:

1. **Every file content update requires a folder metadata republish** -- even though the folder structure didn't change, the entire folder blob must be re-encrypted and re-published via IPNS because the file's CID changed.
2. **Per-file sharing is impossible** without exposing the entire folder structure -- a recipient needs folder decryption just to get one file's key.
3. **Folder metadata grows linearly** with file count, increasing encrypt/decrypt/publish overhead.

## Solution

Split file metadata into separate per-file IPNS-addressed objects:

- **Folder metadata** retains only: `nameEncrypted`, `nameIv`, `fileMetaIpnsName` (pointer), timestamps
- **File metadata** (new, per-file IPNS record): `cid`, `fileKeyEncrypted`, `fileIv`, `size`, `mimeType`, optional `versionHistory`

Key benefits:

- File rename = folder-only publish (no file-meta change)
- Content update = file-meta-only publish (no folder change)
- Per-file sharing via `{fileMetaIpnsName, recipientFileKeyEncrypted}` bundle
- Folder listing latency unchanged (names still in folder)

Key design decisions needed:

- File IPNS keypair derivation: HKDF from user privateKey + fileId (like folder derivation)
- TEE re-publishing enrollment for file IPNS records (many more keys to manage)
- Backward compatibility: v1 vaults export with synthetic file-meta, recovery tool handles both formats
- Migration strategy: feature flag, opt-in for new vaults, manual migration for existing

Full specification with data model, operation flows, and implementation checklist provided in the Perplexity research output that prompted this todo.
