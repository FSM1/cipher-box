# Phase 79: Web Kind-Discrimination Completion and Deferred Test Revival - Pattern Map

**Mapped:** 2026-07-11
**Files analyzed:** 21 (17 wiring files + `packages/sdk/src/folder-listing.ts` + 4 test files, with `invite.service.ts` counted once across the wiring set)
**Analogs found:** 21 / 21 (every file's analog is either itself, a sibling in the same file, or an already-shipped helper elsewhere in the same package — this is an edit-in-place phase, not a new-file phase)

This phase creates zero new files. "Analog" below means: the existing pattern each edit site
must imitate, verified live in this worktree.

## File Classification

| Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `packages/sdk/src/folder-listing.ts` (`ResolvedChild` type + `resolveChildren()`) | model/transform | CRUD (field addition) | Same file's existing `modifiedAt`/`kind`/`size` fields (same function, same unseal) | exact |
| `apps/web/src/components/file-browser/FileList.tsx` (`sortItems`) | component | transform | `apps/web/src/utils/fileTypes.ts` `isFileRefResolved` | exact |
| `apps/web/src/components/file-browser/FileList.tsx` (`onDrop`/`onExternalFileDrop`) | component | event-driven | Same file's already-shipped `resolvedByIpnsName` (line 150) + `toResolvedChildView` (line 250) | exact |
| `apps/web/src/components/file-browser/SharedFileBrowser.tsx` (`sortItems`) | component | transform | Same file's own `resolvedByIpnsName` (line 158) + `isFileRefResolved` usage already live at lines 770/833 | exact |
| `apps/web/src/components/file-browser/useFileBrowserActions.ts` (return object + `itemType` stubs) | hook | request-response | Same file's own `resolvedByIpnsName` (line 120) + `isFileRefResolved` usage already live at lines 416/480 | exact |
| `apps/web/src/components/file-browser/FileBrowser.tsx` (dialog `itemType`/title props) | component | request-response | `useFileBrowserActions.ts` return-object consumption pattern (once `resolvedByIpnsName` is exposed) | role-match |
| `apps/web/src/components/file-browser/details/FileDetails.tsx` (`createdAt` row) | component | request-response | Same file's own `Modified` row guard (lines 94-95) | exact |
| `apps/web/src/components/file-browser/details/FolderDetails.tsx` (`createdAt` row) | component | request-response | Same file's own `Modified` row guard (lines 125-126) | exact |
| `apps/web/src/hooks/useFolderMutations.ts` (`itemType`/recursion TODOs) | hook | CRUD | `useFileBrowserActions.ts`'s existing `itemType: 'file' \| 'folder'` param plumbing (already typed, just fed hardcoded 'folder') | exact |
| `apps/web/src/hooks/useFolderNavigation.ts` (stale `Node.id` TODO) | hook | CRUD | Same file's own matching logic at line 242 (`c.ipnsName === targetFolderId`) — proves ipnsName-keying is intentional | exact |
| `apps/web/src/components/file-browser/FileListItem.tsx` (multi-select drag payload) | component | event-driven | Same-package `FileList.tsx`'s `resolvedByIpnsName` prop-threading precedent | role-match |
| `apps/web/src/components/file-browser/MoveDialog.tsx` (`folderItemIds` cycle guard) | component | transform | `apps/web/src/utils/fileTypes.ts` `isFileRefResolved` | exact |
| `apps/web/src/components/file-browser/SharedMoveDialog.tsx` (`movedFolderIds` cycle guard) | component | transform | Same pattern as `MoveDialog.tsx` (sibling dialog, same fix) | exact |
| `apps/web/src/components/file-browser/ShareDialog.tsx` (`itemDisplayName` `/` suffix, upgrade/downgrade comment) | component | request-response | `FileBrowser.tsx` (only call site, line 308) once `resolvedByIpnsName` is exposed | role-match |
| `apps/web/src/services/invite.service.ts:284` (`itemType: 'folder'`) | service | request-response | **No analog — Unresolved**, see below | none |
| `packages/sdk-core/src/folder/__tests__/load.test.ts` | test | request-response | Its own currently-passing (non-skipped) test blocks in the same file, once rewritten against current `fetchAndDecryptMetadata` | partial (needs a fresh read of `load.ts`'s current signature first) |
| `packages/sdk-core/src/__tests__/file.test.ts` | test | CRUD | `packages/sdk-core/src/file/index.ts:433`'s current single-shot `updateFileMetadata` contract (no passing sibling test exists yet — this is a coverage gap) | none (design decision required) |
| `packages/core/src/__tests__/bin.test.ts` | test | file-I/O | Same file's `BinEntry` fixture, populate `nodeRef` per the `Node` shape in `packages/core/src/bin/types.ts` | exact |
| `apps/web/src/hooks/__tests__/useSharedWriteOps.test.ts` | test | event-driven | Its own already-correct mock assertions against live `client.moveInSharedFolder` — un-skip only | exact |

## Pattern Assignments

### `packages/sdk/src/folder-listing.ts` (model, CRUD field addition)

**Analog:** same file, same function (`resolveChildren()`), extending the existing `modifiedAt`/`kind`/`size` pattern.

**Current shape (verified, lines ~36-43):**
```typescript
export type ResolvedChild = {
  ipnsName: string;
  name: string;
  kind: NodeKind;
  size?: number;
  modifiedAt: number;
  sequence: number;
};
```

**Pattern to copy:** add `createdAt: number;` (no `?`, mandatory — mirrors `modifiedAt`'s mandatory-ness, NOT `size`'s optionality) right after `size?`. In `resolveChildren()`'s push (RESEARCH lines 234-244), add `createdAt: node.createdAt,` alongside the existing `modifiedAt: node.modifiedAt,` line — same unseal, same object literal, zero new codec/seal call. Do NOT add this field to `SealedChildRef` (frozen per `packages/core/src/node/types.ts:76-83` doc comment, reverted precedent `ba3e0229a`).

**Fallback-default sites to update in lockstep** (every synthetic `ResolvedChild` constructor): `FileList.tsx`'s `toResolvedChildView`, and the equivalent in `SharedFileBrowser.tsx`/`SharedFolderRow.tsx` — add `createdAt: 0` next to the existing `modifiedAt: 0` sentinel.

---

### `apps/web/src/components/file-browser/FileList.tsx` — `sortItems` (component, transform)

**Analog:** `apps/web/src/utils/fileTypes.ts` `isFileRefResolved` (lines 155-172, verified live) — the canonical kind lookup already used elsewhere in this same file.

**Current broken state (verified):**
```
Line 96-100:
 * TODO(phase 63): restore folders-first sort once Node.kind discrimination is available.
function sortItems(items: SealedChildRef[]): SealedChildRef[] {
    // TODO(phase 63): SealedChildRef has no .type; sort alphabetically only until phase 63
```

**Core pattern to copy** (RESEARCH-provided, matches the already-shipped `resolvedByIpnsName` at line 150):
```typescript
function sortItems(
  items: SealedChildRef[],
  resolvedByIpnsName: Map<string, ResolvedChild>
): SealedChildRef[] {
  return [...items].sort((a, b) => {
    const aIsFolder = '_uploading' in a ? false : !isFileRefResolved(a, resolvedByIpnsName);
    const bIsFolder = '_uploading' in b ? false : !isFileRefResolved(b, resolvedByIpnsName);
    if (aIsFolder !== bIsFolder) return aIsFolder ? -1 : 1;
    return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
  });
}
```
Edge case (verified in RESEARCH Edge Coverage, must not be dropped): `UploadVirtualEntry` rows have empty `ipnsName`, so a bare map-miss would fall back to the folder-safe default and mis-sort in-progress uploads as folders. The `'_uploading' in item` check must short-circuit to `kind: 'file'` (i.e. `aIsFolder = false`) BEFORE the `isFileRefResolved` lookup.

**Call site update:** line 202, `sortItems(allItems as SealedChildRef[])` → `sortItems(allItems as SealedChildRef[], resolvedByIpnsName)`.

---

### `apps/web/src/components/file-browser/FileList.tsx` — `onDrop`/`onExternalFileDrop` (component, event-driven)

**Analog:** same file's own `resolvedByIpnsName` map (line 150) and `toResolvedChildView` usage (line 250) — already threaded per-row, just not consumed by the drop handlers yet.

**Current broken state (verified, lines 260-268):**
```
onDrop={
  // TODO(phase 63): SealedChildRef has no .type; drop targets disabled until phase 63
  undefined
}
onExternalFileDrop={
  // TODO(phase 63): SealedChildRef has no .type; external drop disabled until phase 63
  undefined
}
```

**Pattern to copy:**
```typescript
onDrop={
  isFileRefResolved(item, resolvedByIpnsName) ? undefined : onDropOnFolder && ((items, sourceParentId) =>
    onDropOnFolder(items, sourceParentId, item.ipnsName))
}
onExternalFileDrop={
  isFileRefResolved(item, resolvedByIpnsName) ? undefined : onExternalFileDrop && ((files) =>
    onExternalFileDrop(files, item.ipnsName))
}
```
Also unstub `_onDropOnFolder`/`_onExternalFileDrop` param names back to `onDropOnFolder`/`onExternalFileDrop` (lines 144-145).

---

### `apps/web/src/components/file-browser/SharedFileBrowser.tsx` — `sortItems` (component, transform)

**Analog:** identical shape to `FileList.tsx`'s fix above — same file already has `resolvedByIpnsName` at line 158 and already calls `isFileRefResolved(item, resolvedByIpnsName)` correctly at lines 770 and 833 (proves the pattern is already established elsewhere in this exact file).

**Current broken state (verified, lines 49-53):** same `TODO(phase 63)` alphabetical-only stub as `FileList.tsx`. Apply the identical comparator, threading `resolvedByIpnsName` (already in scope at the `sortedChildren = sortItems(folderChildren)` call site, line 583) as a second argument. `SharedFileBrowser` has no upload-in-progress virtual rows, so the `'_uploading'` special case is not needed here — verify before copying it in in case it's dead code for this file.

---

### `apps/web/src/components/file-browser/useFileBrowserActions.ts` — return object + `itemType` stubs (hook, request-response)

**Analog:** same file's own `resolvedByIpnsName` (built at line 120) and its established consumption pattern already live at lines 416, 480 (`isFileRefResolved(item, resolvedByIpnsName)`).

**Current broken state (verified):** `resolvedByIpnsName` is computed internally but never returned (`return {` at line 604 does not include it). Five call sites at lines 497/514/542/556/569 carry `// TODO(phase 63): SealedChildRef uses ipnsName as id; stub type as 'folder'` and hardcode `itemType: 'folder'`.

**Pattern to copy:**
1. Add `resolvedByIpnsName` to the returned object (line ~604) so `FileBrowser.tsx` can consume it — mirrors how every other computed value in this hook (e.g. `resolvedByIpnsName` itself, computed the same way `SharedFileBrowser.tsx` does at its own line 158) is already exposed for consumption.
2. At each of the 5 stub sites, replace `itemType: 'folder'` with a real lookup: `itemType: isFileRefResolved(item, resolvedByIpnsName) ? 'file' : 'folder'` (or equivalent `.kind` read off `resolvedByIpnsName.get(item.ipnsName)`), matching the exact same `isFileRefResolved` call shape already used at lines 416/480 in this file.
3. Delete the five `TODO(phase 63)` comments once resolved.

**Downstream consumer:** `useFolderMutations.ts`'s `moveItem`/`deleteItem`/`renameItem` already accept `itemType: 'file' | 'folder'` as a typed real parameter (lines 59/65/74 of `useFileBrowserActions.ts`'s own interface) — no signature change needed there, only the caller-side value fed into it.

---

### `apps/web/src/components/file-browser/details/FileDetails.tsx` / `FolderDetails.tsx` — `createdAt` row (component, request-response)

**Analog:** each file's own existing `Modified` row — this is a direct copy-with-field-swap, not a new pattern.

**Existing `Modified` guard (verified, `FileDetails.tsx:94-95`):**
```typescript
{typeof item.modifiedAt === 'number' && Number.isFinite(item.modifiedAt) ? (
  <span className="details-value">{formatDate(item.modifiedAt)}</span>
```
(identical shape at `FolderDetails.tsx:125-126`)

**Current broken `Created` row (verified, `FileDetails.tsx:89-90`, `FolderDetails.tsx:120-121`):**
```typescript
{/* TODO(phase 63): SealedChildRef has no createdAt; resolve from Node envelope */}
<span className="details-value details-value--dim">unavailable (phase 63)</span>
```

**Pattern to copy — apply verbatim, swap `modifiedAt` → `createdAt`:**
```typescript
{typeof item.createdAt === 'number' && Number.isFinite(item.createdAt) ? (
  <span className="details-value">{formatDate(item.createdAt)}</span>
) : (
  <span className="details-value details-value--dim">unavailable</span>
)}
```
Delete the `TODO(phase 63)` comment. `item.createdAt` will resolve once `ResolvedChild.createdAt` lands per the `folder-listing.ts` change above — no local type change needed in either Details component beyond this.

---

### `apps/web/src/hooks/useFolderNavigation.ts` — stale `Node.id` TODO (hook, CRUD)

**Analog:** same file's own matching logic at line 242 (`fNode.children.find((c) => c.ipnsName === targetFolderId)`) — this line proves the current ipnsName-keyed convention is intentional and load-bearing, not a bug.

**Do NOT** follow the TODO's literal text ("use Node.id for the folder ID"). **Fix pattern:** delete the stale comment; replace with a one-line rationale comment citing the 68.1/68.2-09 ipnsName-keying precedent (`useFolderMutations.ts` lines 127-135's documented war story about an orphaned store entry from UUID-keying). This is a documentation-only fix — zero code-behavior change at this site.

---

### `apps/web/src/components/file-browser/MoveDialog.tsx` / `SharedMoveDialog.tsx` — cycle-guard folder filtering (component, transform)

**Analog:** `apps/web/src/utils/fileTypes.ts` `isFileRefResolved` — same helper as the sort/drop fixes above.

**Pattern:** both `buildFolderList`'s `folderItemIds` (MoveDialog) and `SharedMoveDialog`'s `movedFolderIds` currently treat every moved item as a folder unconditionally for the "cannot move into own subtree" guard. Both dialogs need a new `resolvedByIpnsName: Map<string, ResolvedChild>` prop threaded in (neither currently receives one — verify at each dialog's prop interface). Filter the moved-items set to actual folder-kind items before building the disabled-destination set:
```typescript
const folderItemIds = movedItems
  .filter((item) => !isFileRefResolved(item, resolvedByIpnsName))
  .map((item) => item.ipnsName);
```

---

### `apps/web/src/components/file-browser/FileListItem.tsx` — multi-select drag payload (component, event-driven)

**Analog:** `FileList.tsx`'s established `resolvedByIpnsName` prop-threading precedent (already threaded into `FileListItem` for the single-item `resolved` prop per `SharedFileBrowser.tsx:754-755`, which passes both `resolved` AND `resolvedByIpnsName`).

**Pattern:** `FileListItem` currently receives its own `resolved: ResolvedChild` but not the full map, needed only for the multi-select branch (`allItems: SealedChildRef[]`, lines 164-170). Thread `resolvedByIpnsName` down as a new prop (mirroring how `SharedFileBrowser.tsx` already passes it at line 755), then use `isFileRefResolved(item, resolvedByIpnsName)` per item in the drag-payload `type` field instead of a hardcoded value.

---

### `apps/web/src/components/file-browser/ShareDialog.tsx` — `itemDisplayName` `/` suffix + upgrade/downgrade comment (component, request-response)

**Analog:** `FileBrowser.tsx` (line 308, only call site of `ShareDialog`) — once `resolvedByIpnsName` is exposed per the `useFileBrowserActions.ts` fix above, `FileBrowser.tsx` already has everything needed to pass a resolved-kind prop down, matching the same threading pattern used for `RenameDialog`/`ConfirmDialog`.

**Pattern:** add a `kind: 'file' | 'folder'` (or `isFolder: boolean`) prop to `ShareDialog`, computed at the `FileBrowser.tsx:308` call site via `isFileRefResolved(item, resolvedByIpnsName) ? 'file' : 'folder'`, and gate the trailing `/` suffix on it (`itemDisplayName = kind === 'folder' ? `${item.name}/` : item.name`).

**Upgrade/downgrade comment (line 548):** per RESEARCH Edge Coverage, this is likely a stray comment misfiled during the bulk TODO sweep (permission-level UI, unrelated to file/folder kind) — verify no actual kind-conditional logic exists before touching; if none, just delete the comment.

---

### `apps/web/src/services/invite.service.ts:284` — `itemType: 'folder'` (service, request-response)

**No analog found — flagged Unresolved, not a mechanical pattern.**

`fetchInvitesForItem` builds `InviteInfo[]` directly from the API's `ShareInvite` response; there is no parent folder listing / `ResolvedChild` in scope at this call site. Per RESEARCH Common Pitfall 5, this is the one site where "read `.kind` instead" has no data source. First step (Open Question 2): `grep -rn "itemType" apps/web/src` scoped to `InviteInfo` consumers to determine whether any UI actually branches on the value. Three options for the plan to choose among (not a copy-paste fix):
- (a) leave `itemType: 'folder'` as an explicit documented best-effort default with a permanent rationale comment (replaces the stale `TODO(phase 63)`)
- (b) add a resolve call keyed by `invite.shareRootIpnsName` if cheap/cached
- (c) drop `itemType` from `InviteInfo` entirely if no consumer branches on it

---

### Test files (test, various)

**`apps/web/src/hooks/__tests__/useSharedWriteOps.test.ts`** — Analog: its own already-correct mock assertions (verified in RESEARCH to match `client.moveInSharedFolder`'s live signature exactly). Pattern: remove `.skip` only, no rewrite needed. Near-zero risk.

**`packages/core/src/__tests__/bin.test.ts`** — Analog: same file's `BinEntry` fixture construction at lines 38-45 for the `contentCid`/`contentSize` branch; extend with a populated `nodeRef` per `packages/core/src/bin/types.ts` (`BinEntry.nodeRef?: Node`). Concrete fixture shape (from RESEARCH, verified against `packages/core/src/node/types.ts`):
```typescript
nodeRef: {
  schema: 'node/v3' as const,
  kind: 'file' as const,
  id: crypto.randomUUID(),
  generation: 0,
  createdAt: now - i * 60_000,
  modifiedAt: now - i * 60_000,
  content: {
    cid: `bafybeicontent${i}${'a'.repeat(40)}`,
    fileIv: 'AAAAAAAAAAAAAAAA',
    size: (i + 1) * 512,
    mimeType: 'text/plain',
    encryptionMode: 'GCM' as const,
    fileKey: new Uint8Array(32),
    versions: [],
  },
},
```

**`packages/sdk-core/src/folder/__tests__/load.test.ts`** — No passing analog for the current `fetchAndDecryptMetadata` contract exists yet in this file. Per RESEARCH Pitfall 3/Open Question 1, the mandatory first step is reading `packages/sdk-core/src/folder/load.ts`'s CURRENT `fetchAndDecryptMetadata` signature/body before deciding rewrite vs retire — do not assume the `(cid, key, ctx)` shape still holds. This is a design decision, not a mechanical pattern.

**`packages/sdk-core/src/__tests__/file.test.ts`** — No passing analog exists for `updateFileMetadata`'s current single-shot contract (zero live test coverage today, per RESEARCH). Per Pitfall 2, do not un-skip verbatim (mocks retired exports, tests CAS/conflict behavior the function no longer has). The file's own header (lines 1-8) already documents two valid options: rewrite against `packages/sdk-core/src/file/index.ts:433`'s current signature (`fileReadKey`/`fileWriteKey`/`nodeId`/`nodeGeneration`/`originalCreatedAt`/`currentMetadata: NodeContent`/`updates: UpdateFileContentParams`), or delete with written rationale + a logged todo for future CAS-retry coverage.

## Shared Patterns

### Kind discrimination lookup (apply to every sort/drag/dialog/details site)
**Source:** `apps/web/src/utils/fileTypes.ts` `isFileRefResolved` (lines 155-172, verified)
```typescript
export function isFileRefResolved(
  ref: SealedChildRef | ResolvedChild,
  resolvedByIpnsName: Map<string, ResolvedChild>
): boolean {
  if ('kind' in ref) return ref.kind === 'file';
  return resolvedByIpnsName.get(ref.ipnsName)?.kind === 'file';
}
```
**Apply to:** `FileList.tsx` (sort, drop targets), `SharedFileBrowser.tsx` (sort), `useFileBrowserActions.ts` (itemType stubs), `MoveDialog.tsx`/`SharedMoveDialog.tsx` (cycle guard), `FileListItem.tsx` (multi-select drag), `ShareDialog.tsx` (via a new prop). Do NOT reimplement a local `isFolder(item)` helper anywhere — this is the single canonical source, already imported in most touched files.

### `resolvedByIpnsName: Map<string, ResolvedChild>` construction
**Source:** `apps/web/src/components/file-browser/FileList.tsx` lines 150-153 (verified) / `SharedFileBrowser.tsx` line 158 (verified) / `useFileBrowserActions.ts` line 120 (verified) — three independent, already-shipped instances of the identical `useMemo` pattern.
```typescript
const resolvedByIpnsName = useMemo(
  () => new Map(resolvedChildren.map((r) => [r.ipnsName, r])),
  [resolvedChildren]
);
```
**Apply to:** any new prop-threading site (`MoveDialog`, `SharedMoveDialog`, `FileListItem`, `ShareDialog`) should receive this map from its parent (`FileList.tsx`/`FileBrowser.tsx`/`SharedFileBrowser.tsx`), never recompute it locally.

### `typeof x === 'number' && Number.isFinite(x)` display guard
**Source:** `FileDetails.tsx:94`, `FolderDetails.tsx:125` (verified) — the existing `Modified` row guard.
**Apply to:** the new `createdAt` row in both files, verbatim field swap, same dim-placeholder fallback.

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `apps/web/src/services/invite.service.ts:284` | service | request-response | No `ResolvedChild`/parent listing in scope at this call site — genuine design decision required (3 options above), not a mechanical fix. See RESEARCH Common Pitfall 5. |
| `packages/sdk-core/src/folder/__tests__/load.test.ts` (`fetchAndDecryptMetadata` suite) | test | request-response | Current `load.ts` implementation not fully read in RESEARCH pass (flagged A1/Open Question 1) — plan must read it first, no passing sibling to copy. |
| `packages/sdk-core/src/__tests__/file.test.ts` (`updateFileMetadata CAS + conflict` suite) | test | CRUD | Zero existing test coverage for the current single-shot contract — this is a coverage gap, not a pattern-copy job; requires an explicit rewrite-or-retire decision with written rationale (SC3). |

## Metadata

**Analog search scope:** `apps/web/src/components/file-browser`, `apps/web/src/hooks`, `apps/web/src/services`, `apps/web/src/utils/fileTypes.ts`, `packages/sdk/src/folder-listing.ts`, `packages/core/src/node/types.ts`, `packages/core/src/bin/types.ts`, `packages/sdk-core/src/file/index.ts`, `packages/sdk-core/src/folder/load.ts`, all 4 deferred test files — matches the 17-file phase-scope inventory plus the SDK type extension and test files enumerated in RESEARCH.md.
**Files scanned:** 21 target files + 3 supporting reference files (`fileTypes.ts`, `folder-listing.ts` current shape, `Node`/`BinEntry` types), all read live from this worktree (verified, not inferred).
**Pattern extraction date:** 2026-07-11
