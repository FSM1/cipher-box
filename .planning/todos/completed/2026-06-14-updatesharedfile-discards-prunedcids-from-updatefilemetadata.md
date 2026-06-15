---
created: 2026-06-14T01:32:39.825Z
title: updateSharedFile discards prunedCids from updateFileMetadata causing pin leak
area: sdk
severity: medium
files:
  - packages/sdk/src/share/shared-write.ts
---

## Problem

After phase 44, `updateFileMetadata` returns `prunedCids` — version-history CIDs that
overflowed the per-file cap and should be unpinned. The owner path
(useFileOperations.ts) consumes and unpins them, but `updateSharedFile`
(shared-write.ts) calls `updateFileMetadata` and throws the entire return value away
(bare call, no destructure) with a "deferred leak" comment. Every shared-file update
that prunes a version therefore leaks pinned storage that is never unpinned.

This is a correctness / storage-cost issue, not just cleanup. Surfaced by `/simplify`
(2026-06-14) but flagged as `/code-review`-grade rather than a quality cleanup, so it
was not auto-fixed in that pass.

## Solution

TBD — key considerations:

- Consume `prunedCids` in `updateSharedFile` and unpin them (mirror
  useFileOperations.ts), OR move the unpin-of-pruned-CIDs INSIDE the shared publish
  helper so no caller can forget it (ties into the publishWithCas / folder-wrapper
  refactors).
- Confirm the share recipient has unpin authority for those CIDs (reference-count /
  ownership — see the phase-42 guarded-unpin work) before wiring it up, so a recipient
  cannot unpin a CID still referenced by the owner or other shares.
