# Phase 79: Web Kind-Discrimination Completion and Deferred Test Revival - Research

**Researched:** 2026-07-11
**Domain:** React/TypeScript web app wiring against an existing SDK type (`ResolvedChild`); Vitest test revival against a cut-over `node/v3` API surface
**Confidence:** HIGH

## Summary

This phase is **pure completion work**, not new design. Every capability it needs already
exists in `packages/sdk`/`packages/core` — Phase 68.2 shipped `ResolvedChild` with a `kind:
NodeKind` field (`'file' | 'folder' | 'root'`, string-literal union already, no enum), and the
unified `Node` type (`packages/core/src/node/types.ts`) already carries `id: string` (UUID) and
`createdAt: number`. The 43 `TODO(phase 63)`/`TODO(phase 65)` markers are stale stubs written
*before* 68.2 landed `ResolvedChild` — they describe a `SealedChildRef`-only world that no
longer exists. The fix pattern at nearly every site is: read `resolved.kind` (already computed
and sitting in scope, usually as `resolvedByIpnsName` or `resolvedChildren`) instead of
hardcoding `'folder'`.

`createdAt` requires one real code change: `ResolvedChild` (packages/sdk/src/folder-listing.ts)
does not currently carry `createdAt`, but the `Node` it unseals during `resolveChildren()`
already has it (`node.createdAt`) — this is a one-line addition to the type + the object literal
in `resolveChildren()`, not a new codec field, not a schema migration, and not optional (every
`Node` has always had `createdAt`; SC2's "or intentionally dropped" escape hatch does NOT apply
here — the data already exists and is nearly free to surface).

The four deferred test suites split into three very different situations the planner must not
conflate: (1) `useSharedWriteOps.test.ts`'s two skipped blocks (`moveItemHandler`,
`batchMoveItemsHandler`) are **already written against the current API** — the mock call-site
assertions match `client.moveInSharedFolder`'s live signature exactly (confirmed by direct
comparison below); this is a near-zero-risk un-skip. (2) `load.test.ts`'s
`fetchAndDecryptMetadata` suite mocks a retired `@cipherbox/core` export
(`decryptFolderMetadata`) that no longer exists — this suite must be rewritten against the
current node/v3 `fetchAndDecryptMetadata` contract, or explicitly retired. (3) `file.test.ts`'s
`updateFileMetadata CAS + conflict` suite is the highest-risk item: the function's current
contract is architecturally different (single-shot republish, no CAS-retry/conflict-merge loop
— the file's own header already says as much and offers "revive... or delete" as the two
options) — the *test title itself* describes behavior the function no longer has. `bin.test.ts`
is not a describe.skip at all — it's a one-line fixture gap (`nodeRef` left undefined) trivially
fixed by populating a `Node` fixture, now that `BinEntry.nodeRef?: Node` exists.

**Primary recommendation:** Treat this phase as six mechanical "read `resolved.kind` instead of
hardcoding" sites, one two-line SDK type extension (`ResolvedChild.createdAt`), one trivial test
fixture fix, one near-zero-risk test un-skip, and two test suites that need genuine rewrite-or-retire
decisions (with the file.test.ts one requiring explicit written rationale either way, and flagged
as a coverage gap for updateFileMetadata's current single-shot contract if retired without replacement).

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Folder-vs-file kind discrimination (sort, dialogs, drag) | Browser/Client (`apps/web/src`) | API/Backend (`packages/sdk`, `ResolvedChild.kind`) | Web renders from a pre-resolved SDK projection (SDK-READ-02); the web makes no independent classification decision, only reads `.kind` |
| `createdAt` surfacing | API/Backend (`packages/sdk` `folder-listing.ts` — extends `ResolvedChild`) | Browser/Client (renders via `formatDate`) | The value already exists inside the SDK's unsealed `Node`; the SDK is the only tier that can read it (web never unseals Node directly, D-07 boundary) |
| Folder/file mutation identity (rename/move/delete `itemId`) | API/Backend (`packages/sdk` `client.ts`, keyed by `ipnsName` per read-plane convention) | Browser/Client (passes through, does not reinterpret) | `client.moveItem`/`renameItem`/`deleteItem`/`moveInSharedFolder` are all `ipnsName`-keyed today; web must NOT switch to `Node.id` — that is a landmine, not a fix (see Common Pitfalls) |
| Deferred SDK-core test suites (`file.test.ts`, `load.test.ts`, `bin.test.ts`) | API/Backend (`packages/sdk-core`, `packages/core` — Vitest, CI-gated) | — | Pure unit-test revival against already-shipped sdk-core/core contracts, zero web involvement |
| Deferred web hook test suite (`useSharedWriteOps.test.ts`) | Browser/Client (`apps/web/src/hooks`, Vitest, NOT CI-gated) | API/Backend (asserts against `client.moveInSharedFolder` mock) | Web-side hook logic test; per project convention this is one of the rare `apps/web` unit tests that legitimately exists (a hook, not a UI component) |

## User Constraints

No CONTEXT.md exists for this phase. Planning proceeds from ROADMAP scope + this research. No
locked decisions to honor beyond the ROADMAP's three Success Criteria and the CLAUDE.md/project
conventions below.

## Phase Requirements

No REQ-IDs are mapped to Phase 79 in REQUIREMENTS.md (`phase_req_ids` is null in the roadmap
entry — do not fabricate IDs). This phase closes a marker-inventory gap identified independently
of the v2.0 REQUIREMENTS traceability table (which already shows WEB-01/02/03, SDK-READ-01..04
as Complete). Phase 79 is TODO-marker cleanup, not new-requirement work.

## Project Constraints (from CLAUDE.md)

- **String literals over TS enums** (user global CLAUDE.md): already honored throughout —
  `NodeKind = 'folder' | 'file' | 'root'`, `EncryptionMode = 'GCM' | 'CTR'`, `itemType: 'file' |
  'folder'` are all string-literal unions. No enum should be introduced by this phase's changes.
- **Terminology**: use `ipnsName`, `folderKey`, `fileKey`, `keyEpoch` exactly as defined —
  already the convention in every file touched by this phase.
- **`apps/web` is not unit-tested for UI** (apps/web/CLAUDE.md + project MEMORY): work areas 1-5
  (sort/drag/dialogs/created-date/folder-identity) touch only `.tsx`/`.ts` files under
  `apps/web/src/components` and `apps/web/src/hooks` that are **not** `*.test.ts` — do not add
  new `apps/web` unit tests for them. Verification is source-assertion (grep) + web-e2e +
  Puppeteer MCP manual check, never a new Vitest UI test. The one exception already in the
  codebase (`useSharedWriteOps.test.ts`, a hook test, `*.test.ts`, included by
  `apps/web/vitest.config.ts`'s `include: ['src/**/*.test.ts']`) is in scope for revival because
  it already exists — do not use this phase to create a second one.
- **Puppeteer MCP verification required** for UI-facing changes (folders-first sort, drag-drop
  re-enable, dialog labels, created-date display) — plan a verification task using
  `mcp__puppeteer__*` against the local dev server, or document manual steps if unavailable.
- **API regeneration**: this phase touches zero `apps/api` DTOs/controllers/endpoints — no
  `pnpm api:generate` step needed.
- **Commit message format**: Conventional Commits, no parenthesized text in the subject line.

## Standard Stack

No new libraries. This phase is 100% internal-code completion against already-installed
dependencies (`@cipherbox/core`, `@cipherbox/sdk`, `vitest`, `react`). No `npm install` step.

### Alternatives Considered

Not applicable — no library selection decisions in this phase.

## Package Legitimacy Audit

**N/A — this phase installs no external packages.** No `npm view`/registry checks required. Skip
the Package Legitimacy Gate.

## Architecture Patterns

### System Architecture Diagram

```
                    ┌─────────────────────────────────────────┐
                    │   packages/sdk (folder-listing.ts)       │
                    │                                           │
  SealedChildRef[]  │   resolveChildren(children, readKey,     │  ResolvedChild[]
  (parent read-body)├──▶  gatedResolve)                        ├──▶ { ipnsName, name,
                    │     for each child:                      │      kind, size?,
                    │       1. gatedResolve(childRef)  ─────┐   │      modifiedAt,
                    │          (ROT-07 anti-rollback gate)  │   │      sequence,
                    │       2. unsealChildReadKey(...)      │   │      createdAt ◀── NEW
                    │       3. unsealNode(published, key)   │   │        (Node.createdAt,
                    │          ── node.kind, node.createdAt,│   │         already decrypted
                    │             node.modifiedAt,          │   │         in step 3, just
                    │             node.content?.size        │   │         not yet copied
                    │                                        │   │         into the object
                    └────────────────────────────────────────┘   │         literal)
                                                                   └───────────────┐
                                                                                    │
                    ┌───────────────────────────────────────────────────────────────▼──┐
                    │  apps/web/src/{components/file-browser, hooks}                    │
                    │                                                                    │
                    │  FileList.tsx / SharedFileBrowser.tsx                              │
                    │    resolvedByIpnsName = Map(resolvedChildren by ipnsName)          │
                    │    sortItems(items, resolvedByIpnsName)  ◀── folders-first NEW     │
                    │    drop targets gated on resolved.kind === 'folder'  ◀── NEW       │
                    │                                                                    │
                    │  useFileBrowserActions.ts                                          │
                    │    resolvedByIpnsName (already built, line ~120) ─────┐            │
                    │    handleRenameConfirm/handleDeleteConfirm/            │            │
                    │      handleMoveConfirm: itemType = resolved.kind      │            │
                    │      (was hardcoded 'folder')            ◀── FIX      │            │
                    │    ── needs to EXPOSE resolvedByIpnsName in its        │            │
                    │       return object so FileBrowser.tsx can pass       │            │
                    │       real itemType/title into Rename/Confirm/        │            │
                    │       Move/Share dialogs                              │            │
                    │                                                        │            │
                    │  FileBrowser.tsx: passes itemType={resolved kind}      │            │
                    │    to RenameDialog/ConfirmDialog; deleteMessage/       │            │
                    │    title text branches on kind                        │            │
                    │                                                        │            │
                    │  FileDetails.tsx / FolderDetails.tsx                   │            │
                    │    item.createdAt (was: "unavailable (phase 63)")     ◀── uses NEW  │
                    │                                                        SDK field    │
                    └────────────────────────────────────────────────────────────────────┘
```

### Recommended Approach Per Work Area

**1. Folders-first sort (`FileList.tsx:96/100`, `SharedFileBrowser.tsx:50/54`,
`useFileBrowserActions.ts:333`)**

`sortItems` currently takes only `SealedChildRef[]`. Change its signature to accept the
`resolvedByIpnsName: Map<string, ResolvedChild>` (already built in `FileList.tsx` at
lines 150-153, and in `SharedFileBrowser.tsx`/`useFileBrowserActions.ts` — verify each site
builds or receives one) as a second parameter, and sort:

```typescript
// Source: existing pattern from isFileRefResolved (apps/web/src/utils/fileTypes.ts)
function sortItems(
  items: SealedChildRef[],
  resolvedByIpnsName: Map<string, ResolvedChild>
): SealedChildRef[] {
  return [...items].sort((a, b) => {
    const aIsFolder = !isFileRefResolved(a, resolvedByIpnsName);
    const bIsFolder = !isFileRefResolved(b, resolvedByIpnsName);
    if (aIsFolder !== bIsFolder) return aIsFolder ? -1 : 1;
    return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
  });
}
```

`FileList.tsx`'s `sortItems` call also sorts `UploadVirtualEntry` rows (uploads-in-progress,
which are always files being uploaded) — these have no `ResolvedChild` entry
(`resolvedByIpnsName.get('')` misses), so `isFileRefResolved` falls back to its documented
"miss → folder-safe `false`" default, which would sort in-progress uploads as folders (wrong
side of the folders-first sort). See Edge Coverage — treat `UploadVirtualEntry` as a known
`kind: 'file'` in the comparator rather than relying on the resolved-lookup miss default.

**2. Drag-and-drop re-enable (`FileList.tsx:144/145/264/268`)**

`onDrop`/`onExternalFileDrop` are wired `undefined` unconditionally. Re-enable per-row using the
same `resolvedByIpnsName` lookup already built in `FileList.tsx`:

```typescript
// Source: existing pattern (resolvedByIpnsName already exists at FileList.tsx:150-153)
onDrop={
  isFileRefResolved(item, resolvedByIpnsName) ? undefined : onDropOnFolder && (...)
}
onExternalFileDrop={
  isFileRefResolved(item, resolvedByIpnsName) ? undefined : onExternalFileDrop && (...)
}
```

Only folder rows should be valid drop targets (files are not containers). The prop names
(`onDropOnFolder`) already assume folder-only semantics — currently they are just never
attached to any row.

**3. Kind-aware dialogs/labels** — the single blocking gap is that `useFileBrowserActions.ts`
computes `resolvedByIpnsName` internally (line ~120-123) but **does not return it**, so
`FileBrowser.tsx` — which owns the `RenameDialog`/`ConfirmDialog`/`MoveDialog`/`ShareDialog`
JSX and needs the kind for `itemType`/title/delete-message text — cannot see it. The fix is to
add `resolvedByIpnsName` (or a small helper `getItemKind(ipnsName): 'file' | 'folder'`) to the
hook's return object, then replace every `'folder' as const` / `'folder'` literal listed in the
phase scope with a lookup. `moveItem`/`deleteItem`/`renameItem` in `useFolderMutations.ts`
already accept `itemType: 'file' | 'folder'` as a real parameter (used to decide whether to run
folder-store bookkeeping — `updateFolderName`, `removeFolder`, parentId patch — see Common
Pitfalls for why this currently silently "worked" for folders and needs verifying for files
post-fix). `invite.service.ts:284` and `ShareDialog.tsx`'s upgrade/downgrade comment are special
cases — see Common Pitfalls and Edge Coverage.

**4. Created-date wiring** — extend `ResolvedChild` and `resolveChildren()`:

```typescript
// Source: packages/sdk/src/folder-listing.ts (current shape, lines 36-43)
export type ResolvedChild = {
  ipnsName: string;
  name: string;
  kind: NodeKind;
  size?: number;
  modifiedAt: number;
  createdAt: number; // NEW — sourced from node.createdAt, same unseal as modifiedAt/kind
  sequence: number;
};

// in resolveChildren()'s push (line ~109-116):
resolved.push({
  ipnsName: childRef.ipnsName,
  name: childRef.name,
  kind: node.kind,
  size: node.kind === 'file' ? node.content?.size : undefined,
  modifiedAt: node.modifiedAt,
  createdAt: node.createdAt, // NEW — Node.createdAt already exists (packages/core/src/node/types.ts:166)
  sequence: Number(sequenceNumber),
});
```

`createdAt` is mandatory on `Node` (not optional — `packages/core/src/node/types.ts:166`), so
it is safe to make it mandatory on `ResolvedChild` too (no `?`). Update every fallback default
that constructs a synthetic `ResolvedChild` (`FileList.tsx`'s `toResolvedChildView`, and the
equivalent in `SharedFileBrowser.tsx`/`SharedFolderRow.tsx`) to include `createdAt: 0` as the
"still loading / miss" sentinel, mirroring the existing `modifiedAt: 0` sentinel pattern. Then
in `FileDetails.tsx:89` / `FolderDetails.tsx:120`, replace the `"unavailable (phase 63)"` stub
with the same `typeof item.modifiedAt === 'number' && Number.isFinite(...)` guard pattern
already used for the `Modified` row, applied to `item.createdAt`.

**5. Folder identity** — see Common Pitfalls; this is a landmine, not a straightforward fix.
`useFolderMutations.ts:366/397`'s TODO ("recurse into sub-folders using Node.kind
discrimination") is a real, actionable gap: `handleDelete`/`handleDeleteItems` only remove the
top-level deleted folder's OWN store entry (`store.removeFolder(itemId)`), never its
already-loaded descendant `FolderNode`s in `useFolderStore`. If a loaded subfolder's parent is
deleted, the child `FolderNode` entries become orphaned/stale in the store (not a crash, but a
staleness bug — a stale entry could be looked up by a race with `useFolderNavigation`'s `?.isLoaded`
fast path). Recursing requires walking `useFolderStore.getState().folders` for any node whose
`parentId` chain includes the deleted id (a small BFS/recursive collector), then calling
`removeFolder` for each. This does NOT require SDK/Node.kind changes — the store already has
the tree via `parentId`; "using Node.kind discrimination" in the TODO text is a slight
misnomer, since `items[i].type === 'folder'` (already resolved by area #3's fix) is what gates
whether recursion runs at all, and the recursion itself only needs `parentId` walking, not kind.

### Recommended Project Structure

No new files/directories — every change is a mechanical edit to the 17 files enumerated in the
phase scope, plus `packages/sdk/src/folder-listing.ts` (ResolvedChild extension) and the four
test files.

### Anti-Patterns to Avoid

- **Re-keying folder identity by `Node.id`:** see Common Pitfalls — this is the single highest-risk
  temptation in this phase and must be explicitly rejected.
- **Adding a new `apps/web` UI unit test:** per project convention, UI behavior (sort order,
  drag targets, dialog labels) is verified by source assertion + web-e2e, not new Vitest specs.
- **Silently dropping the `updateFileMetadata CAS + conflict` test without a written rationale:**
  SC3 explicitly requires "revived and passing (or explicitly retired with rationale)" — a bare
  deletion with no comment/PLAN note fails this criterion even if it makes the marker count hit
  zero.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| File-vs-folder classification | A new local `isFolder(item)` helper per component | `isFileRef` / `isFileRefResolved` (`apps/web/src/utils/fileTypes.ts`) — already exist and are already imported in most of the 17 touched files | Centralizes the fallback-to-folder-safe-default semantics; duplicating this logic risks divergent edge-case behavior across components |
| Folders-first comparator | A new sort utility module | Inline comparator using `isFileRefResolved`, colocated with each existing `sortItems` (2 call sites: `FileList.tsx`, `SharedFileBrowser.tsx`) plus the `useFileBrowserActions.ts:333` shift-select range comparator | Three call sites, small function — a shared module is one more file to keep in sync for zero reuse benefit at this scale; project convention already inlines `sortItems` per-component |
| Created-date display gating | New date-formatting logic in `FileDetails`/`FolderDetails` | Reuse the exact `typeof x === 'number' && Number.isFinite(x)` guard already used for `Modified` in both files, plus existing `formatDate` from `apps/web/src/utils/format.ts` | Consistency; `createdAt` and `modifiedAt` have identical shape/validity concerns |

**Key insight:** every piece of infrastructure this phase needs (kind classification, resolved-child
lookup, date formatting/guards) was already built in Phase 68.1/68.2. This phase is exclusively
about *wiring already-built pieces into sites that predate them* — resist the urge to design
anything new.

## Common Pitfalls

### Pitfall 1: "Fixing" folder identity by switching to `Node.id`

**What goes wrong:** `useFolderNavigation.ts:321`'s TODO literally says "use Node.id for the
folder ID (not ipnsName)." Following it verbatim breaks navigation.

**Why it happens:** The TODO predates the 68.1/68.2 convention (confirmed live in the current
codebase) that `FolderNode.id` IS `ipnsName` everywhere — `useFolderNavigation.ts` inserts
placeholders with `id: targetFolderId` where `targetFolderId` is always an ipnsName (route param
`/files/:folderId` is documented as "always an ipnsName" in `useFolderMutations.ts`'s
`handleCreate` comment, confirmed independently by `useFolderNavigation.ts`'s own matching logic
at line 242: `fNode.children.find((c) => c.ipnsName === targetFolderId)`). `useFolderMutations.ts`
lines 127-135 contain an explicit war story: an earlier attempt to key a new `FolderNode` by the
write-body UUID (`result.id`) instead of `ipnsName` created "a second, orphaned store entry,"
which was fixed by reverting to ipnsName-keying. SDK client mutation methods
(`renameItem`/`moveItem`/`deleteItem`/`moveInSharedFolder`) all take an `itemId`/`childId`
parameter that — per `packages/sdk-core/src/folder/metadata-ops.ts` — is matched against
`SealedChildRef.ipnsName`, confirming the read-plane (and route/store) identity really is
`ipnsName`, matching MEMORY's "Write plane keyed by UUID, read plane by ipnsName."

**How to avoid:** Do NOT resolve this TODO by switching to `Node.id`. The correct resolution is
to **delete the stale TODO comment** (with a one-line note explaining ipnsName is intentional,
citing the 68.1/68.2-09 precedent) — this is a documentation-only fix, not a code-behavior fix,
for this specific site. If the phase wants `Node.id` available for some other future purpose
(e.g. a future stable-identity feature), that is out of scope for Phase 79's stated goal
(finish kind wiring + revive tests) — do not introduce it speculatively.

**Warning signs:** Any diff that changes `id: targetFolderId` to `id: node.id` /
`id: resolvedChild.id` in `useFolderNavigation.ts`, `useFolderMutations.ts`, or
`folder.store.ts`, or that adds `id: string` (UUID) to `ResolvedChild` and starts consuming it
for navigation/store keys, should be treated as a regression risk requiring explicit
justification and a re-check of every `folders[id]` lookup site.

### Pitfall 2: Reviving `updateFileMetadata CAS + conflict` as a literal un-skip

**What goes wrong:** The skipped test in `file.test.ts:186` mocks `@cipherbox/core`'s
`encryptFileMetadata`/`decryptFileMetadata` (retired exports — confirmed absent from current
`@cipherbox/core`, only accessible via `as any` casts the file's own header already flags) and
exercises a `currentMetadata`/`updates` object shape (`fileKeyEncrypted: string`, top-level
`cid`/`fileIv`/`size`) that is structurally incompatible with the current `updateFileMetadata`
signature in `packages/sdk-core/src/file/index.ts:433` (`fileReadKey`/`fileWriteKey`/`nodeId`/
`nodeGeneration`/`originalCreatedAt`/`currentMetadata: NodeContent`/`updates:
UpdateFileContentParams`). Worse: the current function's own docstring says it is "single-shot
— mirrors ... updateSharedFile; no CAS retry/merge" — the CAS-retry-and-conflict-merge behavior
the skipped test exercises (`preserves local loser cid as VersionEntry when remote is newer on
409`) **does not exist in the current implementation at all**. Simply removing `.skip` produces
compile errors, not a passing suite.

**Why it happens:** `file.test.ts`'s own header (lines 1-8) already documents this exact
situation and offers two explicit options: "revive as a real spec for the current
`updateFileMetadata` contract, or delete."

**How to avoid:** Treat this as a genuine design decision the PLAN must record, not a mechanical
un-skip. Two valid paths: (a) delete the whole `describe.skip` block and write a new, minimal
suite against the CURRENT single-shot contract (asserting `expectedSequenceNumber`,
`nodeId`/`generation`/`createdAt` preservation, version-capping via `capVersions`) — noting there
is currently ZERO test coverage for `updateFileMetadata`'s live behavior, so this closes a real
gap; or (b) delete the block outright with a commit-message/PR rationale citing the architecture
change, and log a todo for future CAS-retry test coverage if that behavior is ever reintroduced.
Either way, SC3's "explicitly retired with rationale" bar requires the rationale to be written
down, not just the marker removed.

**Warning signs:** A diff that only deletes `.skip` and adds `@ts-expect-error`/`as any` casts to
force the old assertions to compile is NOT an acceptable resolution — it would pass CI while
testing behavior the function no longer has.

### Pitfall 3: `load.test.ts`'s `fetchAndDecryptMetadata` suite mocks a retired export

**What goes wrong:** Same category as Pitfall 2 — `describe.skip` at `load.test.ts:44` mocks
`decryptFolderMetadata` from `@cipherbox/core` via `vi.mock` + `(core as any)` cast (line 34: "is
retired from `@cipherbox/core` in phase 62"). The CURRENT `fetchAndDecryptMetadata`
(`packages/sdk-core/src/folder/load.ts:29`) almost certainly calls into node/v3 unseal
primitives (`unsealNode`/`decodeReadBody`, per the codec introduced in Phase 62/63), not
`decryptFolderMetadata`. Read the current `load.ts` implementation before writing the plan task
— do not assume the three test cases (malformed-JSON, wrong-key, happy-path) map 1:1 onto the
current function without checking its actual current signature/dependencies (it likely no longer
takes `(cid, key, ctx)` with a bare `Uint8Array` key given readKey/generation/childId AAD
binding requirements elsewhere in the node/v3 codec).

**How to avoid:** Read `packages/sdk-core/src/folder/load.ts`'s current `fetchAndDecryptMetadata`
signature and implementation in the PLAN step before deciding whether to rewrite or retire this
suite — do not assume research's characterization of "mocks a retired export" is sufficient; it
identifies the problem, not the current-contract replacement shape.

### Pitfall 4: `handleDelete`/`handleMove`'s `itemType` bookkeeping — a silent behavior change once fixed

**What goes wrong:** In `useFolderMutations.ts`, `itemType` is currently ALWAYS `'folder'`
(passed hardcoded from every web call site). This means `if (itemType === 'folder') { ... }`
branches (store bookkeeping: `updateFolderName`, `removeFolder`, parentId patch) currently run
on every delete/move/rename, including ones for files. Since `store.removeFolder(fileIpnsName)`
and `useFolderStore.getState().folders[fileIpnsName]` on a file's ipnsName currently just misses
(files are never inserted into `folders` by ipnsName) this has been a harmless no-op — but it
means the `itemType === 'folder'` branches have NEVER been exercised with `itemType === 'file'`
in production. Once area #3's fix makes `itemType` correctly resolve to `'file'` for file
operations, these branches will, for the first time, actually skip for files — verify this is
the INTENDED behavior (it is — files were never meant to hit folder-store bookkeeping) but treat
it as a real behavior change requiring a targeted manual/web-e2e check (delete a file, delete a
folder, confirm both remove correctly from the visible list), not just a "TODO comment removed,
ship it" diff.

**How to avoid:** Add an explicit verification step (Puppeteer MCP or manual) that deletes/moves/
renames BOTH a file and a folder after the fix, checking the store update is correct for both —
this is the one area-#3 sub-case that is not purely cosmetic.

### Pitfall 5: `invite.service.ts:284` has no `ResolvedChild` available at all

**What goes wrong:** `fetchInvitesForItem` builds `InviteInfo[]` directly from the API's
`ShareInvite` response (`invitesControllerListInvites`/`shareInvitesControllerListInvites`) — there
is no parent folder listing in scope at this call site, so there is no `ResolvedChild` to read
`.kind` from. Unlike every other site in this phase's scope, fixing this one for real requires
either an extra per-invite SDK resolve call (network cost, N+1 for a list endpoint) or an API
response field that doesn't currently exist.

**How to avoid:** Do not treat this identically to the other 16 files. Options for the PLAN to
choose from: (a) leave `itemType: 'folder'` as an explicit, documented best-effort default for
this one call site only (with a code comment explaining why, replacing the stale `TODO(phase
63)` with a permanent rationale comment — this keeps the marker-zero goal met without a design
change); (b) resolve the item's own kind via a single `client.listFolder`-adjacent call keyed by
`invite.shareRootIpnsName` if such a lookup is cheap/already-cached; (c) drop the `itemType`
field from `InviteInfo` entirely if no UI actually branches on it (check `InviteInfo` consumers
first). Do not silently guess — this is genuinely the one site in scope where "just read
`.kind`" does not apply, and it should be called out explicitly in the PLAN with a decision
recorded.

## Code Examples

### Existing kind-discrimination helper (reuse, do not reimplement)

```typescript
// Source: apps/web/src/utils/fileTypes.ts (already in the codebase, lines 150-173)
export function isFileRef(item: SealedChildRef | ResolvedChild): boolean {
  if ('kind' in item) return item.kind === 'file';
  return false;
}

export function isFileRefResolved(
  ref: SealedChildRef | ResolvedChild,
  resolvedByIpnsName: Map<string, ResolvedChild>
): boolean {
  if ('kind' in ref) return ref.kind === 'file';
  return resolvedByIpnsName.get(ref.ipnsName)?.kind === 'file';
}
```

### Existing resolved-listing lookup pattern (reuse in every dialog fix)

```typescript
// Source: apps/web/src/components/file-browser/FileList.tsx:150-153 (already shipped)
const resolvedByIpnsName = useMemo(
  () => new Map(resolvedChildren.map((r) => [r.ipnsName, r])),
  [resolvedChildren]
);
```

### `BinEntry.nodeRef` fixture fix for `bin.test.ts:43`

```typescript
// Source: packages/core/src/bin/types.ts (BinEntry.nodeRef?: Node, packages/core/src/node/types.ts)
// Replace the empty object-spread branch at bin.test.ts:38-45 with a populated Node fixture:
...(i % 2 === 0
  ? {
      contentCid: `bafybeicontent${i}${'a'.repeat(40)}`,
      contentSize: (i + 1) * 512,
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
    }
  : {}),
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| Per-ipnsName web-side kind-cache (`kind-cache.ts`) | `ResolvedChild.kind` pre-resolved by the SDK, cached in SDK by ipnsName+sequence | Phase 68.1-11 (removed cache) → 68.2-11/68.2-15 (wired render sites onto `ResolvedChild`) | The 43 TODO markers this phase closes are the LAST unmigrated render sites from that transition — every other site already converted |
| `SealedChildRef.size`/`modifiedAt` display mirror | Reverted; `ResolvedChild.size`/`modifiedAt` from a real per-child resolve | Commit `ba3e0229a` added, then reverted per D-08/68.2-12 (see `packages/core/src/node/types.ts:76-83` doc comment) | `SealedChildRef`'s field set is explicitly FROZEN — do not add `createdAt` there; it belongs on `ResolvedChild` only, matching the size/modifiedAt precedent |
| Legacy `FileMetadata`/`FolderMetadata` v1/v2 codec | Unified `Node`/`node/v3` schema, two sealed bodies (read/write) | Phase 62 (NODE-01..06) | `load.test.ts`/`file.test.ts`'s skipped suites test the PRE-Phase-62 codec via retired exports — this is why they cannot be un-skipped verbatim |

**Deprecated/outdated:**
- `decryptFolderMetadata`, `encryptFileMetadata`, `decryptFileMetadata` (as top-level
  `@cipherbox/core` exports usable the way the skipped tests mock them) — retired in Phase 62;
  only reachable via `as any` casts in the still-skipped test files.
- The `SealedChildRef` display-mirror pattern (`.size`/`.modifiedAt` on the read-chain link
  itself) — reverted; do not reintroduce for `createdAt`.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `load.test.ts`'s current `fetchAndDecryptMetadata` implementation signature/dependencies differ enough from the skipped test's mocks that a rewrite (not a trivial un-skip) is required | Common Pitfalls #3 | LOW — flagged explicitly as needing a fresh read of `load.ts`'s current body during planning; even if the delta turns out smaller than expected, re-reading before planning the task costs nothing and the recommendation (read current contract first) holds either way |
| A2 | No UI code currently reads `InviteInfo.itemType` for anything user-visible beyond a label, making option (a) (leave a documented best-effort default) viable | Common Pitfalls #5 | MEDIUM — if `itemType` actually drives conditional UI (e.g. an icon or a permission-relevant branch) in a consumer not inspected during this research, option (a) could ship a cosmetic-looking bug; the PLAN should grep `InviteInfo` consumers before choosing an option here |

## Open Questions

1. **Does the current `fetchAndDecryptMetadata` in `packages/sdk-core/src/folder/load.ts` still
   take a `(cid, key, ctx)`-shaped signature, or has it moved to Node/PublishedNode-typed
   parameters?**
   - What we know: the function exists and is exported (confirmed via grep); the skipped test
     calls it as `fetchAndDecryptMetadata(TEST_CID, DUMMY_KEY, DUMMY_CTX)`.
   - What's unclear: whether that call shape still compiles against the current implementation
     (not read in full during this research pass — flagged as A1).
   - Recommendation: the PLAN's first task for this test suite should be "read
     `packages/sdk-core/src/folder/load.ts` current `fetchAndDecryptMetadata` body/signature,
     THEN decide rewrite vs retire" — do not pre-commit to a rewrite approach in the plan before
     that read happens.

2. **Does any `InviteInfo` consumer branch on `itemType` in a way that matters visually?**
   - What we know: `fetchInvitesForItem` hardcodes `itemType: 'folder'`; `InviteInfo` type
     definition and its render consumers were not read in this research pass.
   - What's unclear: whether Pitfall 5's option (a) (leave documented default) is actually safe.
   - Recommendation: `grep -rn "itemType" apps/web/src` scoped to `InviteInfo`/invite-list render
     components as the first planning step for this specific site.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Vitest (sdk-core/core/sdk: CI-gated `Test` job; apps/web: local-only, `apps/web/vitest.config.ts` `include: ['src/**/*.test.ts']`, not in CI `Test` job — web-e2e-gated on main push instead) |
| Config file | `packages/sdk-core/vitest.config.ts`, `packages/core/vitest.config.ts`, `apps/web/vitest.config.ts` |
| Quick run command | `pnpm --filter @cipherbox/sdk-core test -- file.test.ts load.test.ts` / `pnpm --filter @cipherbox/core test -- bin.test.ts` / `pnpm --filter @cipherbox/web test -- useSharedWriteOps.test.ts` |
| Full suite command | `pnpm test` (root, runs all CI-gated packages) |

### Phase Success Criteria → Validation Map

| SC | Behavior | Validation Type | Concrete Observable |
|----|----------|-----------------|----------------------|
| SC1 (kind discrimination at every listing/dialog/drag site) | Folders-first sort, drag-drop re-enabled, dialogs show real kind | **Source assertion** (primary) + **web-e2e/manual** (behavioral confirmation) | `grep -rn "TODO(phase 63)\|TODO(phase 65)" apps/web/src` returns zero for the 6 discrimination-related file groups; `grep -n "'folder' as const\|itemType={'folder'" apps/web/src/components/file-browser` returns zero hardcoded-kind literals at the 17 listed sites; Puppeteer MCP screenshot/interaction check confirms a mixed file+folder listing sorts folders first and only folder rows accept a drop |
| SC2 (Created date wired or intentionally dropped) | `ResolvedChild.createdAt` populated from `Node.createdAt`; details panes show it | **Source assertion** (primary) — `ResolvedChild` type has `createdAt: number` in `packages/sdk/src/folder-listing.ts`, `resolveChildren()` sets it from `node.createdAt` | `grep -n "createdAt" packages/sdk/src/folder-listing.ts` shows the new field + assignment; `FileDetails.tsx`/`FolderDetails.tsx` no longer contain the string `"unavailable (phase 63)"`; Puppeteer MCP check confirms the Details dialog "Created" row renders a real date, not a dim placeholder |
| SC3 (4 suites revived/retired, zero markers remain) | `describe.skip` → `describe` (or deleted with rationale) for 4 suites; `bin.test.ts` fixture populated | **Vitest unit test** (primary, for the 3 sdk-core/core suites — CI-gated) + **source assertion** (marker count) | `pnpm --filter @cipherbox/sdk-core test` and `pnpm --filter @cipherbox/core test` pass with the (rewritten or original) suites green, no `.skip`; `pnpm --filter @cipherbox/web test -- useSharedWriteOps.test.ts` passes locally (not CI-gated, but must pass); `grep -rln "TODO(phase 63)\|TODO(phase 65)" .` (excluding this RESEARCH.md and PLAN.md) returns zero files |

### Sampling Rate
- **Per task commit:** relevant package's quick test command (see table above) for any task
  touching `packages/sdk-core`, `packages/core`, or `apps/web/src/hooks/__tests__`.
- **Per wave merge:** full `pnpm test` (root) — this phase touches CI-gated packages
  (`sdk-core`, `core`), so the `Test` CI job must be green before merge.
- **Phase gate:** `pnpm test` green + zero `TODO(phase 63)`/`TODO(phase 65)` grep hits +
  Puppeteer MCP or documented-manual UI verification for SC1/SC2 before `/gsd-verify-work`.

### Wave 0 Gaps

None — all four target test files already exist with the scaffolding needed (mocks, fixtures,
imports); no new test file or shared fixture needs to be created. The only gap is content: two
of the four suites (`load.test.ts`, `file.test.ts`) need their body rewritten against current
contracts before they can pass, per Common Pitfalls #2/#3 — this is plan-task work, not
infrastructure work.

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-------------------|
| V2 Authentication | No | Phase touches no auth flow |
| V3 Session Management | No | Phase touches no session flow |
| V4 Access Control | No | Phase touches no permission/authorization logic — kind display and date display are read-only projections of already-decrypted data the user already has access to |
| V5 Input Validation | Marginal | The `createdAt`/`kind` fields being surfaced are already-decrypted, already-trusted `Node` fields (the same trust boundary as `modifiedAt`/`size`, already rendered) — no new untrusted input path is introduced |
| V6 Cryptography | No | No crypto primitive touched; `resolveChildren()` already unseals the child `Node` for `kind`/`modifiedAt`/`size` — this phase reads one more already-decrypted field (`createdAt`) off the same already-unsealed object, no new seal/unseal call |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|-----------------------|
| None specific to this phase's scope | — | This phase is display-layer wiring against already-decrypted, already-access-controlled data (`ResolvedChild`, `Node`); it introduces no new attacker-reachable surface. The one item worth a sanity check: confirm the `updateFileMetadata` test rewrite (if chosen) does not weaken the existing CAS/`expectedSequenceNumber` assertion coverage that guards against the write-side rollback class already covered elsewhere (TEE-04/TEE-07, ROT-07) — but that is a test-completeness concern, not a new vulnerability class |

## Edge Coverage

| Edge Case | Classification | Notes |
|-----------|-----------------|-------|
| `UploadVirtualEntry` rows mixed into `sortItems`/drag logic in `FileList.tsx` | **Covered** (with an explicit fix required) | These synthetic rows have no `ResolvedChild` entry (empty `ipnsName` during upload); `isFileRefResolved` would default them to folder-safe `false` via the map-miss path, sorting them as folders — WRONG (uploads are always files). The comparator must special-case `'_uploading' in item` as `kind: 'file'` before falling back to `isFileRefResolved`, not rely on the miss-default. Flagged explicitly in Architecture Patterns #1. |
| A folder/file whose `ResolvedChild` entry is momentarily unresolved (still-loading listing, `resolvedByIpnsName.get(ipnsName)` miss for a REAL item, not an upload) | **Backstop** | `isFileRefResolved`'s documented miss-default is `false` (folder-safe) — this is intentional existing behavior (68.2-15 doc comment) and should NOT be changed by this phase; it means a still-resolving item sorts/behaves as a folder until its `ResolvedChild` arrives, then re-renders correctly on the next store update. Acceptable as-is; do not "fix" this into a loading spinner as part of this phase (out of scope). |
| A folder or file with `createdAt` that fails the `Number.isFinite` guard (e.g. `0` sentinel from a fallback `toResolvedChildView`) | **Covered** | Mirrors the exact existing `modifiedAt` guard pattern in `FileDetails.tsx`/`FolderDetails.tsx` — reuse verbatim, same dim-placeholder fallback, no new logic needed. |
| Shared vs owned folders in move dialogs (`MoveDialog.tsx` vs `SharedMoveDialog.tsx`) cycle-guard treating ALL moved items as folders | **Covered** (fix required, both dialogs) | Both `buildFolderList`'s `folderItemIds` (private) and `SharedMoveDialog`'s `movedFolderIds` conservatively treat every moved item as a folder for the "cannot move into own subtree" cycle guard. Post-fix, this should filter to only actual folder-kind items before building the disabled-destination set — a file cannot create a folder cycle. Both dialogs need the resolved-kind map threaded in as a new prop (neither currently receives one). |
| `invite.service.ts:284`'s `itemType: 'folder'` — no `ResolvedChild` available at this call site at all | **Unresolved** (flagged, needs a PLAN decision) | See Common Pitfalls #5 and Open Question #2. This is the one site where "read `.kind` instead" has no direct data source; requires an explicit decision (leave documented default / add a resolve call / drop the field) recorded in the plan, not silently patched. |
| Multi-select drag (`FileListItem.tsx:164-170`, `allItems: SealedChildRef[]` with no per-item resolved-kind map) | **Covered** (fix required) | `FileListItem` receives its OWN `resolved: ResolvedChild` but not a map for `allItems` (used only in the multi-select branch). `FileList.tsx` already has `resolvedByIpnsName` built — thread it down as a new prop to `FileListItem` for the multi-select drag-payload `type` field. |
| `ShareDialog.tsx`'s "upgrade/downgrade always shown" TODO comment (line 548) | **Backstop / likely no-op** | This TODO's own text conflates permission-upgrade UI visibility with kind discrimination — read-vs-write permission upgrade/downgrade is unrelated to file-vs-folder kind. Likely just a stale comment from the bulk marker sweep; the PLAN should verify no actual kind-conditional logic is needed here (probably just delete the stray comment) rather than assume real behavior change is required. |
| `ShareDialog.tsx:374`'s `itemDisplayName` trailing-`/` suffix (folder-only convention) | **Covered** (fix required) | `ShareDialog` receives `item: SealedChildRef` with no kind; `FileBrowser.tsx` (the only call site, line 308) has `resolvedByIpnsName` available (once exposed per area #3) and should pass the resolved kind in as a new prop so the `/`suffix only appears for actual folders. |

## Sources

### Primary (HIGH confidence — read directly from this worktree, static analysis)
- `packages/core/src/node/types.ts` — canonical `Node`/`SealedChildRef`/`WriteChildRef`/`NodeContent` shapes, confirms `Node.id`/`Node.createdAt` exist today
- `packages/sdk/src/folder-listing.ts` — `ResolvedChild` current shape + `resolveChildren()` implementation
- `packages/sdk/src/client.ts` — `moveItem`/`renameItem`/`deleteItem`/`deleteToBin`/`moveInSharedFolder`/`listFolder`/`ensureFolderLoaded` signatures
- `packages/sdk-core/src/folder/metadata-ops.ts` — confirms mutation `childId` params match against `SealedChildRef.ipnsName` (read-plane identity)
- `packages/sdk-core/src/file/index.ts` — current `updateFileMetadata` signature/contract (single-shot, no CAS-retry)
- `packages/core/src/bin/types.ts` — `BinEntry.nodeRef?: Node`
- `apps/web/src/utils/fileTypes.ts` — `isFileRef`/`isFileRefResolved` (existing kind-discrimination helpers to reuse)
- All 17 files in the phase-scope TODO marker inventory, read directly (`FileList.tsx`,
  `SharedFileBrowser.tsx`, `useFileBrowserActions.ts`, `useFolderMutations.ts`,
  `useFolderNavigation.ts`, `FileListItem.tsx`, `MoveDialog.tsx`, `SharedMoveDialog.tsx`,
  `ShareDialog.tsx`, `FileBrowser.tsx`, `FileDetails.tsx`, `FolderDetails.tsx`,
  `invite.service.ts`)
- `packages/sdk-core/src/folder/__tests__/load.test.ts`,
  `packages/sdk-core/src/__tests__/file.test.ts`,
  `packages/core/src/__tests__/bin.test.ts`,
  `apps/web/src/hooks/__tests__/useSharedWriteOps.test.ts` — the four deferred suites
- `apps/web/vitest.config.ts` — confirms `include: ['src/**/*.test.ts']`
- `.planning/REQUIREMENTS.md`, `.planning/STATE.md` — project decision history, WEB-01..04/SDK-READ-01..04 traceability

### Secondary (MEDIUM confidence)
- None — this phase required no external documentation lookup; it is entirely internal-codebase
  archaeology against already-shipped Phase 62/63/68.1/68.2 code.

### Tertiary (LOW confidence)
- None.

## Metadata

**Confidence breakdown:**
- Standard stack: N/A — no new libraries
- Architecture: HIGH — every pattern verified by direct file reads against the current worktree, not inferred from documentation or training data
- Pitfalls: HIGH — each pitfall traced to specific line-level evidence (docstrings, comments, signature diffs) in the actual current codebase
- Test-revival risk assessment: HIGH for `useSharedWriteOps.test.ts` (signature comparison done directly against live `client.ts`) and `bin.test.ts` (type comparison done directly); MEDIUM for `load.test.ts` (current `fetchAndDecryptMetadata` body not fully read — flagged as Open Question 1/Assumption A1); HIGH for `file.test.ts` (current `updateFileMetadata` full signature and docstring read directly, confirming the architecture mismatch)

**Research date:** 2026-07-11
**Valid until:** No expiry concern — this research is a point-in-time snapshot of the current worktree's own code, not of an external fast-moving dependency; it remains valid as long as no other phase touches these same files first. Re-verify TODO marker inventory (`grep -rn "TODO(phase 63)\|TODO(phase 65)"`) immediately before planning if significant time has passed or other phases have landed.
