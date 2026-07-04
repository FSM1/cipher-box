---
created: 2026-07-04T00:00:00Z
title: SealedChildRef size/modifiedAt display mirror lags after an in-place file replace/version
area: sdk
files:
  - packages/sdk/src/client.ts:2884
  - packages/sdk/src/client.ts:2965
  - packages/core/src/node/types.ts:83
source: Phase 68.1 size/date mirror feature (commit ba3e0229a — known limitation)
---

## Problem

The new `SealedChildRef.size` / `SealedChildRef.modifiedAt` display mirrors
(commit ba3e0229a) are populated at child creation (upload / folder create /
shared write) and preserved across move/rename/rotation. But `replaceFile` and
`restoreFileVersion` (client.ts:2884, :2965) publish ONLY the file's own IPNS
record via `updateFileMetadata` and deliberately do NOT re-publish the parent
folder (the file-only publish does not advance the folder sequence). So after an
in-place file edit/replace or a version restore, the parent's mirrored `size`
and `modifiedAt` keep their original upload-time values until the parent is next
written for some other reason.

Result: the file list shows the ORIGINAL size and an unchanged "modified" date
after an edit — mildly ironic for a "modified date" column, though far better
than the pre-fix "Jan 1, 1970"/"-" stubs, and correct for the dominant
upload-then-read case. The mirror is explicitly non-authoritative (like
`generation`); the source of truth is the child's own Node
(`NodeContent.size` / `Node.modifiedAt`).

## Solution

Decide the tradeoff explicitly rather than silently leaving it stale:

- Option A (preferred if cheap): on `replaceFile`/`restoreFileVersion`, also
  update the parent's SealedChildRef `size`/`modifiedAt` and re-publish the
  parent. Cost: one extra parent IPNS publish + sequence bump + CAS per edit
  (write amplification — the exact cost the mirror was introduced to avoid), so
  gate it behind a "did size/mtime actually change" check and reuse the existing
  `maybeRepublishFolderForFileMigration` piggyback seam where possible.
- Option B: leave the mirror as create-time-only and have the file DETAILS
  dialog (not the list) show authoritative size/mtime from the resolved Node
  read-chain, accepting list-level staleness after edits.

Add a web-e2e: upload a file, replace its content with a larger file, assert the
list size/date update (Option A) or that details reflect the new values
(Option B). Relates to
[[owner-stale-empty-snapshot-shared-out-folder]] (same "parent not re-resolved"
family) and the WEB-01 mirror in [[write-plane-keyed-by-uuid-read-plane-by-ipnsname]].
