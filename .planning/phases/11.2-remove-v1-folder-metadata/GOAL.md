# Phase 11.2: Remove v1 Folder Metadata, Make v2 Canonical

## Goal

Eliminate folder metadata v1/v2 dual-schema code -- make v2 (FilePointer) the only format, tighten validation to reject hybrid metadata, and implement per-file IPNS publishing in desktop FUSE.

## Context

A cross-device format oscillation bug causes the desktop FUSE mount to show empty directories. The root cause: the desktop writes v1 folder metadata (inline `FileEntry`), the web app loads it and re-saves as `version: "v2"` without converting the children, creating a hybrid format the desktop's strict v2 parser rejects.

Rather than patching the hybrid, we'll nuke the DB, make v2 the only format, and remove all v1/v2 branching. This eliminates ~500 lines of dual-schema code and the entire class of version mismatch bugs.

## Depends On

- Phase 11.1 (macOS Desktop Catch-Up)
- Phase 12.6 (Per-File IPNS Metadata Split)

## Requirements

- Data integrity
- Cross-device interop

## Success Criteria

1. Only v2 folder metadata (FilePointer children with fileMetaIpnsName) is written by all clients
2. v1 folder metadata (inline FileEntry with cid/fileKeyEncrypted) is rejected by validators on all platforms
3. All v1/v2 branching code removed: ~500 lines of dual-schema types, dispatch, and conversion
4. Desktop FUSE create() derives file IPNS keypair and release() publishes per-file FileMetadata
5. Desktop build_folder_metadata emits FilePointer (not FileEntry) -- cross-device format is consistent
6. TypeScript crypto package exports canonical names (FolderMetadata, FolderChild) -- no V2 suffix
7. Recovery tool (recovery.html) handles only v2 FilePointer path
8. All tests pass: pnpm test + cargo test --features fuse

## Key Decisions

- Keep `version: 'v2'` string literal in serialized JSON (future versions = 'v3', 'v4', etc.)
- Rename `FolderMetadataV2` -> `FolderMetadata`, `FolderChildV2` -> `FolderChild` everywhere
- No deprecated aliases -- single PR, rename everything at once
- `FileMetadata.version: 'v1'` (per-file IPNS records) is a SEPARATE schema -- do NOT change it
- Do NOT touch `FILE_HKDF_SALT = 'CipherBox-v1'` (cryptographic domain separator, not a version)

## Scope

### TypeScript (packages/crypto + apps/web)

- Delete v1 types (`FolderMetadata` v1, `FolderChild` v1, `FileEntry`, `AnyFolderMetadata`)
- Rename v2 types to canonical names
- Delete `isV2Metadata()`, tighten `validateFolderMetadata()` to reject v1
- Update all web app imports and remove v1 guards in FileBrowser, DetailsDialog, TextEditorDialog
- Update recovery.html, test vectors, test fixtures

### Rust (apps/desktop)

- Delete v1 types, `AnyFolderMetadata`, `to_v1()`, `decrypt_any_folder_metadata()`
- Rename v2 types to canonical
- Delete `populate_folder()` v1 path, rename `populate_folder_v2()` -> `populate_folder()`
- Rewrite `build_folder_metadata` to emit FilePointer instead of FileEntry
- Add per-file IPNS derivation in `create()` and FileMetadata publish in `release()`
- Update `init_vault` and `mkdir` to write `version: "v2"`

### Highest Risk

- Desktop `create()` + `release()` per-file IPNS publishing (mitigated by existing `derive_file_ipns_keypair` and `encrypt_file_metadata`)

## Future Migration Infrastructure

Pattern for next schema change (e.g. v3):

1. On folder load, detect old version -> silently convert + re-encrypt + re-publish IPNS
2. Client-side only (TEE has no folder key access)
3. Grace period -> remove old version support

## Verification

- `pnpm --filter @cipherbox/crypto test` (crypto package)
- `pnpm --filter web typecheck && pnpm --filter web build` (web app)
- `cargo test --features fuse` (desktop)
- Manual FUSE mount test: create file on desktop, verify readable from web app and vice versa

## Plans

TBD (run /gsd:plan-phase 11.2 to break down)

## Origin

Todo: `2026-02-18-fix-v2-metadata-version-mismatch.md` (URGENT)
