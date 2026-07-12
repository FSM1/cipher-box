---
phase: 79
phase_name: "web-kind-discrimination-completion-and-deferred-test-revival"
project: "CipherBox"
generated: "2026-07-12"
counts:
  decisions: 4
  lessons: 3
  patterns: 3
  surprises: 2
missing_artifacts:
  - "79-UAT.md"
---

## Decisions

### Folder identity stays keyed by ipnsName — delete the re-key TODO, do not act on it

The `TODO(phase 63): use Node.id for the folder ID (not ipnsName)` in `useFolderNavigation.ts` (and the analogous recursion in `useFolderMutations.ts`) was deleted as a documentation-only NON-CHANGE, not implemented. Folder identity is intentionally keyed by `ipnsName` across route params, store lookups, and SDK mutation calls.

**Rationale:** A prior UUID/Node.id-keying attempt caused an orphaned-store-entry bug (68.1/68.2-09). This was the single highest-risk temptation in the phase — the codebase invites the "fix", so the guard is a comment at the site plus a recorded NON-CHANGE in the SUMMARY, so no later diff silently re-keys navigation. **Source:** 79-02-SUMMARY.md, 79-07-SUMMARY.md

---

### Retire the updateFileMetadata CAS suite, do not revive it verbatim

The quarantined `describe.skip` in `file.test.ts` mocked retired `@cipherbox/core` exports and exercised a CAS-retry/conflict-merge loop. The current `updateFileMetadata` is single-shot (rebuilds and republishes at `fileSequenceNumber+1n`, no `expectedSequenceNumber`, no 409 retry), so the legacy assertions cannot compile against the current contract.

**Rationale:** Reviving verbatim would test behavior that no longer exists. Equivalent CURRENT-contract coverage already lives in `file/file-node.test.ts:317` (Phase 68.1-07), so the suite was retired with a written rationale rather than force-fit. **Source:** 79-03-SUMMARY.md

---

### Drop a field with no data source rather than carry a hardcoded default

`InviteInfo.itemType` was removed entirely (not defaulted to `'folder'`): there is no `ResolvedChild`/parent listing in scope at `fetchInvitesForItem`, the API's `ShareInvite` response carries no kind, and the sole consumer never read it (grep-verified).

**Rationale:** A hardcoded best-effort default with no source of truth is a latent lie. Dropping the field is honest and removes the stale deferred marker. **Source:** 79-02-SUMMARY.md

---

### Kind map-miss defaults folder-safe at every site

Every listing/sort/drag/dialog/cycle-guard site reads kind through `isFileRefResolved(item, resolvedByIpnsName)`, whose miss (still-loading listing) returns `false` → treated as folder.

**Rationale:** For sort/label/cycle-guard, folder-treatment on a transient miss is the conservative choice (over-constrains destinations rather than mislabeling a folder as a file); the server still validates the actual move/drop. Kept the design uniform rather than introducing a third "unresolved" UI state. **Source:** 79-VERIFICATION.md

---

## Lessons

### A `0` sentinel defeats a `Number.isFinite` "unknown date" guard

The DetailsDialog listing-miss fallback set `createdAt: 0`; the Details Created row guards on `Number.isFinite`, and `Number.isFinite(0)` is `true`, so the miss branch rendered `formatDate(0)` = "January 1, 1970" instead of the intended dim "—". Fixed at ship time by using `Number.NaN` as the sentinel.

**Action:** For a numeric field whose "unknown" state is rendered via `Number.isFinite`, the missing sentinel must itself be non-finite (`NaN`), never `0`.

---

### Fixtures with `createdAt === modifiedAt` cannot catch a field-projection swap

The `folder-listing.test.ts` builder hardcoded `createdAt: opts.modifiedAt`, so every assertion had the two timestamps equal — a `modifiedAt → createdAt` swap in `resolveChildren` would have passed. Fixed at ship time by threading a distinct `createdAt` and asserting `createdAt !== modifiedAt`.

**Action:** When a projection copies two same-typed fields, give them distinct fixture values and assert the inequality, or the test proves nothing about which field landed where.

---

### A both-fields type invites a phantom "id-space mismatch" review flag

`SharedPickerNode` carries both `id` and `ipnsName`, but `enumerateSharedSubtree` populates both (and `parentId`) with the ipnsName. A reviewer read the separate fields as separate identifier spaces and flagged the cycle guard as broken. It is correct — the guard compares ipnsName to ipnsName throughout.

**Action:** When two fields intentionally hold the same value, say so at the type/definition, so the equality is not read as an accident.

---

## Patterns

### `isFileRefResolved(item, resolvedByIpnsName)` as the single kind primitive

One helper, threaded as a `Map<string, ResolvedChild>` prop (`resolvedByIpnsName`) to every consumer (FileList, FileListItem, MoveDialog, SharedFileBrowser, SharedMoveDialog, FileBrowser dialogs). Sort/drag/drop/cycle-guard/label all derive kind from it instead of a hardcoded stub. **Source:** 79-04/05/06-SUMMARY.md

---

### BFS over `parentId` links to purge a deleted folder's subtree

`collectDescendantFolderIds(folders, rootId)` walks the store's `parentId` graph to remove every already-loaded descendant FolderNode on folder delete, so no stale entry survives to be hit by `useFolderNavigation`'s `isLoaded` fast path. Batch delete snapshots the tree BEFORE the SDK delete so the walk sees the full loaded subtree. Identity stays ipnsName-keyed — parentId walk only. **Source:** 79-07-SUMMARY.md

---

### Mandatory display field sourced off the already-unsealed Node

`ResolvedChild.createdAt` was added as a non-optional field populated in `resolveChildren` from `node.createdAt` — the same already-decrypted, already-access-controlled Node object that supplies kind/size/modifiedAt. No new codec, seal, or resolve call, and the mandatory-ness forced every fixture/fallback literal to account for it (a compile-time ripple that surfaced the DetailsDialog and folder.store fixture gaps). **Source:** 79-01-SUMMARY.md

---

## Surprises

### The "coverage gap" the plan targeted already existed

The plan assumed the quarantined `updateFileMetadata` CAS suite was the only coverage of the write-side rollback class. On reading, live coverage of the CURRENT single-shot contract already existed in `file/file-node.test.ts` (Phase 68.1-07), turning a planned "revive" into a "retire with rationale". **Source:** 79-03-SUMMARY.md

---

### A sixth phase-63 marker beyond the five the plan named

`useFileBrowserActions.ts` carried a sixth `TODO(phase 63)` in the shift-select range-selection sort (alphabetical-only because `SealedChildRef` has no `.type`) beyond the five hardcoded-`itemType` stub sites the plan enumerated. The SC3 zero-marker gate forced resolving it too (folders-first-then-alpha via `isFileRefResolved`). **Source:** 79-02-SUMMARY.md
