---
created: 2026-02-18T23:30
title: 'URGENT: Fix web app writing v2-tagged metadata with v1-style file entries'
area: crypto
priority: urgent
files:
  - packages/crypto/src/folder/types.ts
  - packages/crypto/src/folder/metadata.ts:40-86
  - apps/web/src/services/folder.service.ts
  - apps/desktop/src-tauri/src/crypto/folder.rs:245-271
---

## Problem

The web app writes folder metadata with `version: "v2"` but populates file children as v1-style inline `FileEntry` objects (containing `cid`, `fileKeyEncrypted`, `fileIv`, `size`, etc.) instead of v2-style `FilePointer` objects (which should only have `fileMetaIpnsName`).

This hybrid format is accepted by the TypeScript validator (`validateFolderMetadata` in `metadata.ts:40-86`) because it loosely checks for either `cid` OR `fileMetaIpnsName` on file children regardless of version. However, the Rust desktop client's strict v2 deserializer (`FolderMetadataV2` with `FilePointer` struct) rightfully rejects it — `FilePointer` requires `fileMetaIpnsName` which isn't present.

**Impact:** Desktop FUSE mount shows empty directory — all files invisible even though they exist in the vault. A fallback (try v1 parse when v2 fails) has been added to the Rust client as a workaround, but the root cause is in the web app.

**Discovered during:** Phase 11.1 UAT, 2026-02-18. Debug log showed:

```text
V2 metadata deserialization failed: missing field `fileMetaIpnsName`
Decrypted JSON: {"version":"v2","children":[{"type":"file","id":"...","name":"hello.txt","cid":"baf...","fileKeyEncrypted":"...","fileIv":"...","size":16,...
```

## Investigation needed

1. **Find where version is set to "v2"** — trace all code paths that create/update folder metadata and determine why `version: "v2"` is being written when the children are v1-style `FileEntry` objects.

2. **Determine correct fix direction:**
   - Option A: Fix web app to write `version: "v1"` when using inline `FileEntry` children (simpler, backward compat)
   - Option B: Fix web app to actually create proper v2 `FilePointer` entries with per-file IPNS records (bigger change, matches intended v2 architecture from Phase 12.6)
   - Option C: Make the TypeScript types and Rust types both accept the hybrid format explicitly (codifies the bug as a feature)

3. **Audit all metadata write paths** in `packages/crypto` and `apps/web` to ensure consistent version tagging.

4. **Check if existing vault data on staging is corrupted** — all metadata currently stored may have this mismatch.

## Workarounds in place (remove after web app fix)

The following Rust desktop changes work around the hybrid format. **All should be reverted** once the web app writes correct metadata:

- `crypto/folder.rs`: `FileEntry` fields (`cid`, `file_key_encrypted`, `file_iv`, `size`, `encryption_mode`) changed to `#[serde(default)]` — only needed because v2 pointers lack these fields
- `crypto/folder.rs`: `file_meta_ipns_name: Option<String>` added to `FileEntry` — carries pointer IPNS name through v1 parse path
- `crypto/folder.rs`: `decrypt_any_folder_metadata()` V2→V1 fallback — tries v1 parse when v2 fails
- `fuse/inode.rs`: `populate_folder()` `is_pointer` branch — handles pointer entries that arrived via v1 code path
- `crypto/tests.rs`, `fuse/mod.rs`, `fuse/inode.rs`: `file_meta_ipns_name: None` added to all `FileEntry` struct literals

Debug logging (`Decrypted folder metadata JSON` preview, specific serde error messages) can stay — useful regardless.

## Note: Metadata versioning consistency

The root issue is that `version` is set independently from the actual child format. There's no enforcement that `version: "v2"` → all file children are `FilePointer`, or `version: "v1"` → all file children are `FileEntry`. The TypeScript validator (`validateFolderMetadata`) accepts either shape regardless of version, which masks the mismatch.

When fixing this, ensure:

1. **Version tag is derived from child format, not set independently** — if any child is a `FilePointer`, version must be `"v2"`; if all children are inline `FileEntry`, version should be `"v1"`. Or if hybrid is intentional, define and document a `"v2-hybrid"` version.
2. **Strict validation per version** — `validateFolderMetadata` should reject `version: "v2"` children that lack `fileMetaIpnsName`, and `version: "v1"` children that lack `cid`.
3. **Single source of truth for version assignment** — find where `version` is set during metadata construction (`encryptFolderMetadata` callers) and ensure it's always consistent with the children being written.
4. **Migration path for existing data** — staging vault already has hybrid metadata. Either fix existing records (re-publish with correct version) or accept hybrid as a permanent format the desktop client must handle.
