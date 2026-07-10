---
created: 2026-07-10
title: Thread base-aware write-body merge through the shared-write path (parity with owned folders)
area: sdk
files:
  - packages/sdk/src/share/shared-write.ts
source: Phase 72 security review (LOW / informational) + CodeRabbit parity note
---

## Problem

Phase 72 made the owned-folder write-body CAS-merge base-aware (pass `baseWriteChildren` so a
locally- or remotely-deleted `WriteChildRef` is not resurrected on a CAS-409 retry), and threaded
it through `deleteItem`, `moveItem`, `restoreFromBin`, and `permanentDeleteFromBin`. But the
shared-write module `packages/sdk/src/share/shared-write.ts` (backing `deleteFromSharedFolder`,
`moveInSharedFolder`, etc.) has NONE of its `updateFolderMetadataAndPublish` call sites passing
`baseWriteChildren` — they still use the legacy naive-union merge.

Not a Phase 72 regression (this file was not touched by Phase 72 — confirmed empty in the phase
diff), so it pre-dates this work. But it is the SAME write-chain-resurrection exposure class on the
shared-folder path: a concurrent writer's stale snapshot can resurrect a `WriteChildRef` that a
share-mutation intended to drop, potentially leaving a moved/deleted item write-capable under an
old scope. The security review flagged it explicitly as a follow-up.

## Solution

Extend the base-aware pattern to every write-body-mutating `updateFolderMetadataAndPublish` call in
`shared-write.ts`: capture the pre-mutation `writeChildren` snapshot and pass it as
`baseWriteChildren` (mirroring the owned-folder fixes). Add concurrent-writer resurrection
regression coverage for the shared-write delete/move paths (the writable-shares web-e2e spec has no
concurrent-move test today). Relates to [[remove-legacy-moveinsharedfolder-sharekeys-branch]] and
the Phase 72 SC#1 base-aware merge (`registration.ts`).

## Resolution

NOT APPLICABLE — retired 2026-07-11 via pending-todo triage.

The premise does not hold against the current node/v3 shared-write code:
`packages/sdk/src/share/shared-write.ts` has **zero** `updateFolderMetadataAndPublish`
call sites and **no CAS-409 naive-union merge path**. Every write-body mutation
goes through `resealAndPublishParent` → `publishOrThrow`, which performs a strict
CAS publish (`sequenceNumber + 1n`) and throws `CannotWriteUntilRefetchError` on
conflict/tombstone (`shared-write.ts:224-286`). There is no merge-on-409 step that
could resurrect a dropped `WriteChildRef`, so the base-aware `baseWriteChildren`
threading that Phase 72 added to the owned-folder merge path has no analog to apply
here — the resurrection exposure class this todo describes cannot occur on the
shared-write path. Verified against HEAD (post-#603).
