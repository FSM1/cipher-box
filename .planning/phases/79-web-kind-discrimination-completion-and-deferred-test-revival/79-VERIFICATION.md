# Phase 79 Verification

Goal-backward verification of Phase 79 — web kind-discrimination completion and
deferred test revival. Verified against branch
`feat/web-kind-discrimination-completion-and-deferred-test-revival` at HEAD
`684df26fd`. Verify-only pass — no product code was modified.

## Overall verdict

PASS — all three success criteria MET, all hard gates and project invariants hold.

## Success criteria

### SC1 — kind discriminated at every listing/dialog/drag site — MET

File-vs-folder is read from `ResolvedChild.kind` (via the `isFileRefResolved`
lookup keyed by `ipnsName`) at every render/dialog site:

- Folders-first sort: `apps/web/src/components/file-browser/FileList.tsx:106`
  uses `isFileRefResolved(a, resolvedByIpnsName)` (uploads forced non-folder).
- Drag payload: `apps/web/src/components/file-browser/FileListItem.tsx:175,180`
  emits `type: 'folder' | 'file'` from the resolved kind (multi-select and
  single).
- ShareDialog: `apps/web/src/components/file-browser/ShareDialog.tsx:27` takes a
  real `kind: 'file' | 'folder'` prop; folder-only slash suffix gated at
  `:378` (`kind === 'folder' ? '${item.name}/' : item.name`).
- MoveDialog cycle guard: `MoveDialog.tsx:61-64` restricts the
  cannot-move-into-own-subtree set to items where
  `!isFileRefResolved(i, resolvedByIpnsName)` (folder-kind only).
- SharedMoveDialog cycle guard: `SharedMoveDialog.tsx:107-108` filters the
  moved-folder subtree-exclusion set the same way.
- FileBrowser threads resolved kind into rename/delete/share:
  `FileBrowser.tsx:119` (rename kind), `:123` (delete kind), `:126`
  (shareKind), and passes `resolvedByIpnsName` into MoveDialog at `:313,392`.

`isFileRefResolved` (`apps/web/src/utils/fileTypes.ts:167`) reads `kind`
inline off a `ResolvedChild`, else looks it up by `ipnsName`; a miss stays
folder-safe `false`.

### SC2 — real Created date from the Node envelope — MET

- `createdAt` is mandatory (non-optional) on `ResolvedChild`:
  `packages/sdk/src/folder-listing.ts:42` (`createdAt: number`).
- Populated in `resolveChildren` from the unsealed Node envelope:
  `folder-listing.ts:116` (`createdAt: node.createdAt`).
- FileDetails renders it: `details/FileDetails.tsx:88-93` — `formatDate(item.createdAt)`
  guarded by `Number.isFinite`, falling back to `—` (not a phase-63 stub).
- FolderDetails renders it: `details/FolderDetails.tsx:121-125` — same pattern.

No `phase 63`/`phase 65` "unavailable" stub remains in the details panes
(grep across `details/` and `DetailsDialog.tsx` returns nothing).

### SC3 — four deferred suites revived or explicitly retired — MET

- load.test.ts `fetchAndDecryptMetadata` — REVIVED, un-skipped, 3 tests pass:
  `packages/sdk-core/src/folder/__tests__/load.test.ts:45`
  (`describe('fetchAndDecryptMetadata (current node/v3 contract)')`).
- useSharedWriteOps move + batch-move — REVIVED, un-skipped:
  `apps/web/src/hooks/__tests__/useSharedWriteOps.test.ts:424`
  (`moveItemHandler (REQ-2)`) and `:525` (`batchMoveItemsHandler (REQ-6)`);
  15 tests in the file pass.
- bin.test.ts `nodeRef` fixture — POPULATED, `restoreFromBin` un-skipped:
  `packages/sdk/src/__tests__/bin.test.ts:363` describe, fixture at `:366`,
  asserted at `:491,494`; suite passes (21 bin tests).
- file.test.ts `updateFileMetadata` CAS suite — RETIRED with rationale:
  `packages/sdk-core/src/__tests__/file.test.ts:1-28`. Rationale verified: the
  current `updateFileMetadata` (`file/index.ts:433`) republishes single-shot
  with no `expectedSequenceNumber`/CAS/409-retry, so the legacy CAS assertions
  cannot compile or test real behavior; equivalent coverage of the CURRENT
  contract exists at `packages/sdk-core/src/__tests__/file/file-node.test.ts:317`
  (`describe('updateFileMetadata')`). Rationale holds.

## Hard gates and invariants

### TODO markers — 0

`grep -rn "TODO(phase 63)\|TODO(phase 65)"` excluding `.planning`,
`node_modules`, `.git` returns ZERO hits in product code. (Remaining hits are
all historical references inside `.planning/`.)

### Folder identity stayed ipnsName-keyed — confirmed

The folder-delete cleanup added in 79-07 (`useFolderMutations.ts`) uses
`collectDescendantFolderIds` (`:83`), a BFS over the store's `parentId` links,
and never re-keys to `Node.id`. The purge doc-comment (`:74-82`) explicitly
states identity stays ipnsName-keyed; store entries are keyed by
`result.ipnsName` (`:163`). No re-key to `Node.id` — the known orphaned-store
bug is not reintroduced.

### integration.test.ts still skipped — confirmed

`packages/sdk/src/__tests__/integration.test.ts:36` still
`const describeIf = describe.skip;`. The sdk run reports it as
`3 skipped` — the live-API-gated suite was NOT un-skipped.

## Test and typecheck results

- `pnpm --filter @cipherbox/sdk-core test` — 33 files, 395 passed, 0 failed.
- `pnpm --filter @cipherbox/sdk test` — 51 passed + 1 skipped files;
  411 passed, 3 skipped (the intentional integration.test.ts skip), 0 failed.
- `pnpm --filter @cipherbox/web test` — 10 files, 67 passed, 0 failed
  (stderr ERROR lines are expected output from failure-path tests).
- `apps/web` `pnpm exec tsc -b` — GREEN (exit 0), after rebuilding
  sdk-core/sdk `dist/`. The mandatory-`createdAt` ripple typechecks clean.

## Summary

Every Phase 79 success criterion is delivered in code, not merely committed:
kind is discriminated from `ResolvedChild.kind` at all listing/dialog/drag
sites; the details panes source a real Created date from a now-mandatory
`createdAt`; three deferred suites are revived and passing and the fourth is
retired with a verified rationale. Zero phase-63/65 TODO markers remain,
folder identity stays ipnsName-keyed, and the live-API integration suite
remains skipped. Phase 79 verdict: PASS.
