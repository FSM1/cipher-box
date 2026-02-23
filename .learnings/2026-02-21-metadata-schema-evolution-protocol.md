# Metadata Schema Evolution Protocol

**Date:** 2026-02-21

## Original Prompt

> Create a formal metadata schema evolution protocol for all metadata objects created by the system. Ensure that this documentation is referenced in claude memory for future tickets that make changes to the metadata.

## What I Learned

- CipherBox has 10 metadata objects across TypeScript and Rust that must produce byte-identical JSON
- Fields were added informally (optional + serde defaults) without version bumps through Phase 13 -- no protocol existed
- The `FileMetadata.version` field stayed at `'v1'` despite two additive changes (`encryptionMode`, `versions`) -- this is defensible but means the version field is useless for feature detection
- `FolderMetadata` had a clean-break v1->v2 migration (pre-production vault wipe) -- this strategy is only valid when all data can be wiped
- Changing a default value is a breaking change in disguise (e.g., changing `encryptionMode` default from `'GCM'` to `'CTR'` would silently decrypt old files with the wrong algorithm)
- Objects without their own version field (FolderEntry, FilePointer, VersionEntry, DeviceEntry) evolve through their parent's version
- The recovery tool (`apps/web/public/recovery.html`) has its own inline crypto implementations and must be updated independently for any change affecting file discovery or decryption

## What Would Have Helped

- A formal protocol from Phase 12.6 onward (when per-file IPNS was introduced) would have prevented the informal pattern
- Cross-platform round-trip tests (TS -> Rust -> TS) should be standard for every schema change

## Key Files

- `docs/METADATA_SCHEMAS.md` -- complete reference for all 10 metadata objects
- `docs/METADATA_EVOLUTION_PROTOCOL.md` -- formal evolution rules and checklist (Section 4 is the actionable checklist)
- `packages/crypto/src/file/types.ts` -- FileMetadata, VersionEntry, FilePointer types
- `packages/crypto/src/folder/types.ts` -- FolderMetadata, FolderEntry, FolderChild types
- `packages/crypto/src/registry/types.ts` -- DeviceRegistry, DeviceEntry types
- `packages/crypto/src/vault/types.ts` -- EncryptedVaultKeys, VaultInit types
- `apps/desktop/src-tauri/src/crypto/folder.rs` -- Rust equivalents for all FUSE-relevant types
- `apps/web/public/recovery.html` -- standalone recovery tool with inline metadata parsing
