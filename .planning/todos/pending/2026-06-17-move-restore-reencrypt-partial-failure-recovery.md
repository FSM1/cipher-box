---
created: 2026-06-17T00:00:00.000Z
title: Make move/restore file-metadata re-encryption recoverable across partial failures
area: reliability
severity: medium
source: CodeRabbit CLI review of PR fix/decrypt-fail-after-move (#507)
files:
  - packages/sdk/src/client.ts
  - packages/sdk/src/bin/index.ts
  - crates/fuse/src/lib.rs
  - crates/fuse/src/write_ops.rs
---

## Problem

Moving (or restoring to a different folder) a file re-encrypts its `FileMetadata`
IPNS record from the source folderKey to the destination folderKey. This spans
**two independent IPNS records** — the per-file `FileMetadata` record and the
folder metadata holding the `FilePointer` — which cannot be published atomically.

`CipherBoxClient.moveItem` is now **reorder-hardened** (publish dest → re-encrypt
→ publish source): the metadata is only re-keyed once the destination is durably
visible, so at every intermediate failure the file stays readable from a folder
that still lists it (from the source before re-encrypt, the destination after),
never readable from neither. Pinned by the failure-path tests in
`packages/sdk/src/__tests__/client-move-reencrypt.test.ts`. What remains:

- **`moveItem` clean retry isn't idempotent.** After a partial failure the file is
  still readable, but re-running `moveItem` can double-add to the destination or
  fail (`resolveFileMetadata` under the source key fails once the metadata is
  already re-keyed). A truly idempotent retry needs a dest-key fallback (below).
- **`restoreFromBin` still re-encrypts BEFORE the target publish.** It should get
  the same reorder (publish target → re-encrypt) so a failure can't strand a bin
  entry whose metadata is re-keyed while the file is not yet in any folder.
- **Desktop FUSE/WinFsp** re-encrypts fire-and-forget after the rename
  (`spawn_file_meta_reencrypt`) with no retry — a crash/transient publish error
  leaves the destination pointer over metadata still under the source key.

## When implementing

1. Apply the `moveItem` reorder to `restoreFromBin` (publish target before
   re-encrypt).
2. Make the re-encrypt resolve idempotent: if `resolveFileMetadata` under the
   source key fails, fall back to the destination key (meaning "already
   re-encrypted from a prior partial attempt") and treat the re-encryption as
   complete. That makes `moveItem`/`restoreFromBin` retry-safe — re-running
   completes a partially-applied move. Surface a real error only when both keys
   fail.
3. Desktop: add a bounded/persistent retry for `spawn_file_meta_reencrypt` (a
   journal entry retried on the next sync) so the key transition can't be silently
   lost.

Add tests asserting a retry after each partial-failure point completes the move
and the file decrypts under the destination key.
