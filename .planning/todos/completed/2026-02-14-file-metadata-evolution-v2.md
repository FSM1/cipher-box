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

**Batching strategy:** Per-file IPNS records produced during batch operations (e.g., multi-file upload via `addFilesToFolder`) MUST be published together in a single `/ipns/publish` call — not as individual per-file publishes. This preserves the existing Phase 07.1 performance pattern (single publish call for N-file batch). The TEE enrollment API should accept multiple file IPNS records in one request.

Key design decisions needed:

- File IPNS keypair derivation: HKDF from user privateKey + fileId (like folder derivation)
- TEE re-publishing enrollment for file IPNS records — scalability considerations:
  - **Scale impact:** Per-file IPNS multiplies republish workload significantly. A vault with 1,000 files across 50 folders goes from ~50 IPNS republishes per cycle to ~1,050 (21x increase). At ~2s per publish, that's ~35 minutes per cycle.
  - **Capacity limits:** Define max files per vault before degradation (soft limit for warnings, hard limit for rejection). Evaluate whether this is ~5,000 or ~10,000 files.
  - **Parallelization:** TEE republisher must batch and parallelize IPNS publishes (e.g., 10-20 concurrent publishes) to stay within the 48h DHT TTL window.
  - **Fallback:** If TEE becomes overloaded — queue excess records, degrade to longer republish intervals, or offload to secondary republisher instances.
- Backward compatibility: v1 vaults export with synthetic file-meta, recovery tool handles both formats
- Migration strategy: feature flag, opt-in for new vaults, manual migration for existing

## Full specification

_The detailed data model, operation flows, and implementation checklist from the initial research are captured below. This replaces the previous reference to an external Perplexity research output._

**TODO:** Inline the full specification here when this todo is picked up for implementation planning. The research output covers:

- Per-file metadata IPNS record schema (CID, fileKeyEncrypted, fileIv, size, mimeType, versionHistory)
- Folder metadata v2 schema (nameEncrypted, nameIv, fileMetaIpnsName pointer, timestamps)
- HKDF derivation for file IPNS keypairs (same pattern as folder derivation)
- Upload flow (create file meta → publish file IPNS → update folder entry with pointer → publish folder IPNS)
- Content update flow (re-encrypt file meta → publish file IPNS only)
- Rename flow (update folder entry name fields → publish folder IPNS only)
- Per-file sharing flow (wrap fileKey for recipient → share fileMetaIpnsName + wrappedKey)
- Migration: v1→v2 converter creates file-meta records from embedded folder data
- Recovery tool: handle both v1 (embedded) and v2 (per-file IPNS) formats
