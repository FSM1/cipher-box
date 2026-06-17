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
A failure between them leaves an unrecoverable-via-UI state:

- **SDK `moveItem` (re-encrypt → publish dest → publish source):** if the
  re-encrypt succeeds but the destination folder publish then fails, the
  `FileMetadata` is already sealed under the destination key while the
  `FilePointer` is still only in the source folder. Reading the file resolves the
  metadata under the *source* key and fails. A retry of `moveItem` calls
  `resolveFileMetadata` under the source key, which also fails — so the move can
  never complete and the file is stuck undecryptable.
- **Reordering to re-encrypt last** does not fix this: a re-encrypt failure then
  leaves the pointer in the destination with metadata still under the source key
  (undecryptable at the destination, no "re-encrypt in place" operation to
  recover).
- The desktop FUSE/WinFsp path re-encrypts fire-and-forget after the rename, so it
  has the same window with no retry.

Current behavior is pinned by the failure-path tests in
`packages/sdk/src/__tests__/client-move-reencrypt.test.ts` (the move rejects; the
gap is documented, not recovered).

## When implementing

Add a recovery/idempotency mechanism rather than a reorder. Candidate approach:
make the re-encrypt resolve tolerant — if `resolveFileMetadata` under the source
key fails, fall back to the destination key (meaning "already re-encrypted from a
prior partial attempt") and treat the re-encryption as complete, letting the
folder publishes finish. That makes `moveItem` (and `restoreFromBin`) retry-safe:
re-running the operation completes a partially-applied move. Surface a real error
only when both keys fail. Apply the same idempotent re-encrypt to the desktop
re-encrypt path (`spawn_file_meta_reencrypt`) and consider a bounded background
retry there. Add tests asserting a retry after each partial-failure point
completes the move and the file decrypts under the destination key.
