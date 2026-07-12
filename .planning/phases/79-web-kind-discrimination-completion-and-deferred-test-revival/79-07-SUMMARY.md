---
phase: 79-web-kind-discrimination-completion-and-deferred-test-revival
plan: 07
subsystem: ui
tags: [react, typescript, file-browser, details, folder-store, kind-discrimination]

# Dependency graph
requires:
  - phase: 79-01
    provides: "ResolvedChild.createdAt mandatory field on the SDK-resolved listing model"
  - phase: 79-02
    provides: "Real itemType resolution flowing into the delete handler"
provides:
  - "Created-date row in FileDetails/FolderDetails rendered from item.createdAt"
  - "createdAt sentinel on DetailsDialog's synthetic ResolvedChild fallback (typechecks under mandatory field)"
  - "Recursive descendant-FolderNode store cleanup on folder delete (single + batch), parentId-walk only"
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Created row reuses the exact Number.isFinite(item.modifiedAt) guard pattern, swapped to item.createdAt"
    - "collectDescendantFolderIds: BFS over the store's parentId links; identity stays ipnsName-keyed (no Node.id re-key)"

key-files:
  created: []
  modified:
    - apps/web/src/components/file-browser/details/FileDetails.tsx
    - apps/web/src/components/file-browser/details/FolderDetails.tsx
    - apps/web/src/components/file-browser/DetailsDialog.tsx
    - apps/web/src/hooks/useFolderMutations.ts

key-decisions:
  - "Removed the FolderDetails JSDoc TODO(phase 63) 'wire read-chain navigation to load Node for full metadata' marker as stale: the ResolvedChild is already resolved via the SDK read chain, and the previously-missing display metadata (createdAt) now flows through ResolvedChild (Plan 01). No functional gap remained; reworded to describe the current state."
  - "The second delete marker (batch handleDeleteItems) was a GENUINE stale-subtree gap, not a stale comment: folder.store.removeFolder only drops the single keyed entry and does not cascade, so batch delete orphaned descendants exactly like single delete. Applied the same collectDescendantFolderIds walk there too (Set-deduped across the batch)."
  - "createdAt: 0 sentinel matches the existing modifiedAt: 0 precedent on DetailsDialog's miss-branch literal; Number.isFinite(0) is true so a genuine miss renders the epoch via formatDate exactly as modifiedAt: 0 already did — a pre-existing cosmetic quirk this plan neither introduces nor is scoped to fix. [Ship-time update, commit after 1b3b347d1: the createdAt path WAS hardened — the miss-branch literal now uses createdAt: Number.NaN, and both Details Created rows guard on `Number.isFinite(x) && x > 0` so both a NaN miss and the decoder's epoch-0 default (Number(obj.createdAt ?? 0)) render the dim '—' placeholder instead of January 1, 1970.]"

patterns-established:
  - "collectDescendantFolderIds(folders, rootId) module helper in useFolderMutations, reused by single + batch delete"

requirements-completed: []

coverage:
  - id: SC2-created-date-row
    description: "File and folder Details panes render a real Created date from item.createdAt"
    verification:
      - kind: other
        ref: "grep -rn \"phase 63|phase 65\" apps/web/src/components/file-browser/details returns zero; both files use the Number.isFinite guard + formatDate(item.createdAt)"
        status: pass
    human_judgment: true
    rationale: "apps/web UI is not unit-tested (logic lives in packages/sdk, UI via web-e2e); the rendered Created date is a phase-gate manual/Puppeteer check."
  - id: SC2-detailsdialog-createdat
    description: "DetailsDialog synthetic ResolvedChild carries createdAt so it typechecks under the mandatory field"
    verification:
      - kind: other
        ref: "tsc -b: the DetailsDialog.tsx TS2322 error is resolved (createdAt: 0 added to the literal)"
        status: pass
    human_judgment: false
  - id: SC1-folder-delete-subtree-cleanup
    description: "Deleting a folder recursively removes its already-loaded descendant FolderNode store entries"
    verification:
      - kind: other
        ref: "collectDescendantFolderIds BFS over parentId applied at both handleDelete and handleDeleteItems; no Node.id re-key"
        status: pass
    human_judgment: true
    rationale: "Store-cleanup correctness (no lingering descendant after parent delete) is observable only via a live delete of a folder with a loaded subfolder in the untested UI layer; verified by code inspection of the parentId walk."

# Metrics
duration: 15min
completed: 2026-07-12
status: complete
---

# Phase 79 Plan 07: Created-Date Display and Folder-Delete Subtree Cleanup Summary

**FileDetails/FolderDetails now render a real Created date from `item.createdAt`, DetailsDialog's synthetic fallback carries a `createdAt` sentinel so it typechecks under the mandatory field, and folder delete recursively purges already-loaded descendant FolderNodes from the store (parentId walk, no Node.id re-key).**

## Performance

- **Duration:** 15 min
- **Tasks:** 3 (committed atomically per task)
- **Files modified:** 4

## Accomplishments

- FileDetails and FolderDetails replace the "unavailable (phase 63)" Created stub with the identical `typeof item.createdAt === 'number' && Number.isFinite(item.createdAt)` guard used for the Modified row, rendering `formatDate(item.createdAt)`.
- DetailsDialog's still-loading/listing-miss synthetic ResolvedChild gains `createdAt: 0` next to `modifiedAt: 0`, resolving the `TS2322` assignability error under mandatory `ResolvedChild.createdAt`.
- `collectDescendantFolderIds` (BFS over the store's `parentId` links) added and applied at both the single-delete (`handleDelete`) and batch-delete (`handleDeleteItems`) folder branches, so no orphaned descendant FolderNode survives to be matched by `useFolderNavigation`'s `isLoaded` fast path.
- All 5 `TODO(phase 63)` markers removed (FileDetails 1, FolderDetails 2 incl. the JSDoc read-chain marker, useFolderMutations 2).

## Task Commits

1. **Task 1: Created-date rows in FileDetails/FolderDetails** — `345446dca` (feat)
2. **Task 2: createdAt sentinel on DetailsDialog synthetic ResolvedChild** — `f40c659eb` (fix)
3. **Task 3: recursive descendant-FolderNode store cleanup** — `7017c41b3` (feat)

_STATE.md/ROADMAP.md are updated in a batched wave-tracking commit per this worktree's convention; SUMMARY.md is committed separately._

## Files Created/Modified

- `apps/web/src/components/file-browser/details/FileDetails.tsx` — Created row via createdAt guard, marker removed
- `apps/web/src/components/file-browser/details/FolderDetails.tsx` — Created row via createdAt guard, stale JSDoc read-chain marker removed
- `apps/web/src/components/file-browser/DetailsDialog.tsx` — createdAt: 0 sentinel on the miss-branch ResolvedChild literal
- `apps/web/src/hooks/useFolderMutations.ts` — collectDescendantFolderIds helper + subtree cleanup at both delete sites

## Decisions Made

- The batch-delete marker was a genuine orphaning gap (removeFolder does not cascade), so the same descendant walk was applied there, not just deleted as stale.
- The FolderDetails JSDoc read-chain marker was stale — the ResolvedChild is already read-chain-resolved and its createdAt now flows via Plan 01 — so it was reworded, not left as a phase marker.
- Kept identity ipnsName-keyed throughout: the cleanup walks `parentId` only and never re-keys to Node.id (avoids the known orphaned-store bug class).

## Deviations from Plan

None on content. Prettier collapsed the `collectDescendantFolderIds` signature to one line (formatting only).

## Issues Encountered

- After this plan, `tsc -b` still reports 3 test-fixture errors (`useSharedWriteOps.test.ts`, `useSyncPolling.test.ts`, `folder.store.test.ts`) from Plan 01's mandatory `createdAt`. The first two are owned by Plan 79-08; `folder.store.test.ts` is an unowned gap folded into 79-08 as a compile-fix. The DetailsDialog error this plan owned is resolved.

## User Setup Required

None.

## Next Phase Readiness

- SC2 (Created date) satisfied; SC1 folder-delete subtree cleanup satisfied.
- apps/web `tsc -b` goes fully green after 79-08 lands (fixes the remaining 3 test fixtures).

---
*Phase: 79-web-kind-discrimination-completion-and-deferred-test-revival*
*Completed: 2026-07-12*

## Self-Check: PASSED

- FOUND: apps/web/src/components/file-browser/details/FileDetails.tsx
- FOUND: apps/web/src/components/file-browser/details/FolderDetails.tsx
- FOUND: apps/web/src/components/file-browser/DetailsDialog.tsx
- FOUND: apps/web/src/hooks/useFolderMutations.ts
- FOUND: .planning/phases/79-web-kind-discrimination-completion-and-deferred-test-revival/79-07-SUMMARY.md
- FOUND commit: 345446dca
- FOUND commit: f40c659eb
- FOUND commit: 7017c41b3
