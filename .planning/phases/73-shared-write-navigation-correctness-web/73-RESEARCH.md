# Phase 73: Shared Write/Navigation Correctness (Web) - Research

**Researched:** 2026-07-10
**Domain:** Web app shared-folder navigation/write correctness (existing code, React hooks + SDK facades) — pure correctness/refactor, no new architecture
**Confidence:** HIGH (every finding below is grounded in a specific file:line read this session; no library/framework research was needed since this phase touches zero new dependencies)

## Summary

This phase is a bug-fix/refactor pass over one already-shipped subsystem: `apps/web/src/hooks/useSharedNavigationActions.ts` (SC1/SC2/SC6/SC7), `apps/web/src/hooks/useSharedWriteOps.ts` + `packages/sdk/src/client.ts` (SC4), and `apps/web/src/components/file-browser/SharedFolderRow.tsx` (SC5). All 7 success criteria map to concrete, already-identified fix points — the source todos ARE the spec, and this research confirms/deepens each one against the current code rather than proposing new architecture.

The most important finding is for SC4: it is **not just** "wire a supplier" — `apps/web/src/hooks/useSharedWriteOps.ts` does not call `runWithFailureUx` **at all** today (confirmed by exhaustive grep of all `runWithFailureUx(` call sites in the repo). The classifier (`useMutationFailureUx.ts`) is fully correct and `CannotWriteUntilRefetchError` is fully wired inside `packages/sdk/src/share/shared-write.ts`, but two independent gaps stack on top of each other: (1) `publishNodeFn` (client.ts `buildWriteTransportSeams`) never produces `{tombstoned: true}` — it only returns `{tombstoned:false, ...}` or throws a generic `Error`, and a real API 410 (`IPNS_TOMBSTONED`) would surface as a raw uncaught `AxiosError`, not a classified error; and (2) even if it did throw `CannotWriteUntilRefetchError`, no shared-write handler in `useSharedWriteOps.ts` runs its mutation through `runWithFailureUx`, so the classifier is unreachable from any production code path. Both must be fixed for SC4's "at least one live production supplier" bar.

For SC1/SC2/SC6/SC7, all four success criteria touch the exact same ~400-line block of `useSharedNavigationActions.ts` (`navigateToSubfolder`, `navigateUp`, `navigateToBreadcrumb`), so this research treats them as one coordinated refactor rather than four independent patches — see "Recommended SC6/SC7-vs-SC1/SC2 sequencing" below.

**Primary recommendation:** Do the SC7 dead-code removal FIRST (deletes `resolveFolderIpnsPrivateKey` + the `getShareKeys` param, shrinking the diff surface), then the SC6 consolidation (extract `restoreToBreadcrumbIndex`/equivalent as the single restore path), landing SC1 (writeKey-in-navStack) and SC2 (re-resolve-on-restore) as the two behavior changes made INSIDE that now-single restore helper — not as three separate passes over the same lines.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Nav-stack writeKey/children state | Frontend (React hook, `useSharedNavigationActions.ts`) | API/Backend (SDK `client.ts` derives the writeKey via `resolveSharedSubfolderWriteKey`) | The stack itself is UI navigation memory; the crypto derivation it caches is SDK-owned (D-07 boundary already enforced) |
| ROT-07 floor gating of read facades | API/Backend (`packages/sdk/src/client.ts`, `RotationHighWater`) | — | Gating logic already lives entirely in the SDK; this phase only re-routes 3 facades to the existing gate, no new gate logic |
| WRITE-03 tombstone signal | API/Backend (apps/api `ipns.service.ts` emits 410) → SDK (`sdk-core`/`sdk` interprets it) → Frontend (`useMutationFailureUx.ts` renders the toast) | — | The signal already exists server-side (WRITE-04, Phase 66); this phase only completes the client-side relay, it does not touch the API |
| Drag-payload kind classification | Frontend (`SharedFolderRow.tsx`) | — | Purely a display/DnD-payload concern; the resolved listing it should read from is already computed one level up in `SharedFileBrowser.tsx` |

## Standard Stack

No new external packages are introduced by this phase. Every fix point below reuses an existing project dependency (`@cipherbox/sdk`, `@cipherbox/sdk-core`, `@cipherbox/core`, `axios` — already a `packages/sdk-core` dependency) or an existing in-repo helper (`isFileRefResolved` in `apps/web/src/utils/fileTypes.ts`, the `error as Error & { status?: number; response?: { status?: number } }` axios-status idiom already used in `packages/sdk-core/src/ipns/index.ts:317-325`).

## Package Legitimacy Audit

Not applicable — this phase installs no new packages (`npm install` step is empty). Skipping the audit per protocol.

## Per-SC Current-State Map

### SC1 — nested write-key retention (navStack carries `writeKey`)

**File:** `apps/web/src/hooks/useSharedNavigationActions.ts`

**Current state:**
- `NavStackEntry` (lines 32-39) has NO `writeKey` field — only `folderId`, `folderName`, `children`, `folderKey`, `ipnsName`, `sequenceNumber`.
- `navigateToSubfolder` (line 373-396) DOES correctly derive `childWriteKey` via `getSdkClient().resolveSharedSubfolderWriteKey(currentShareId, {...})` before seeding the child depth, but that derived buffer is **zeroed in the `finally` at line 395** (`childWriteKey?.fill(0)`) right after `seedActiveSharedFolder` clones it internally — it is never captured into the stack entry pushed at lines 344-354 (which is pushed BEFORE the write-key derivation even runs, at the START of the function, holding only the level being LEFT, not the level being ENTERED — note the parent's own writeKey was never derived at push time either, since it belongs to whatever depth was active before this descent).
- `navigateUp` (line 450-528) and `navigateToBreadcrumb` (line 537-610) each independently re-derive a writeKey ONLY when `isRootDepth` (`parent.ipnsName === share.ipnsName` / `target.ipnsName === share.ipnsName`, lines 493 / 575) via `resolveSharedRootWriteKey(share.encryptedWriteKey, ...)`. For any depth below the root, `rootWriteKey` stays `null`, and `seedActiveSharedFolder` is called with `writeKey: undefined`, which falls back to `new Uint8Array(32)` inside `shared-folder-projection.ts`'s `seedSharedFolder` (line 102: `writeKey: args.writeKey ?? new Uint8Array(32)`). This is the exact bug: a zero-buffer writeKey silently seeded for every non-root restore depth, causing the next write's GCM auth to fail.

**What's wrong:** The ONLY code path that correctly derives a subfolder writeKey (`resolveSharedSubfolderWriteKey`) runs on DESCENT, and its result is discarded instead of cached for later restore.

**Concrete change:**
1. Add `writeKey: Uint8Array | null` to `NavStackEntry`.
2. In `navigateToSubfolder`, capture a CLONE of `childWriteKey` (before the `finally` zeroes the original) into the entry that will represent THIS depth once the user descends further — i.e., when pushing the CURRENT level onto the stack, that current level's own writeKey must already have been resolved (either at share-root-entry time via `shareRootWriteKey`, or at a PRIOR `navigateToSubfolder` call for this same depth) and cloned in. Concretely: `navigateToShare` must also stash the resolved `shareRootWriteKey` (currently zeroed at line 268 with nothing but the SDK's internal clone) into a "current depth's writeKey" ref/variable that `navigateToSubfolder` reads when constructing the pushed stack entry, and `navigateToSubfolder` must clone its own newly-derived `childWriteKey` before its own zeroing so IT is available to store when the user descends past ITpast.
3. `navigateUp`/`navigateToBreadcrumb` restore: use the stack entry's stored `writeKey` directly (clone before passing to `seedActiveSharedFolder`, since seeding clones internally per D-09) instead of the `isRootDepth ? resolveSharedRootWriteKey(...) : null` branch. This makes the root-depth special case ALSO just read from the stack (push a root entry with its writeKey too, or special-case root only for the very first entry) — see SC6 sequencing note below for how this folds into the single restore helper.
4. Zero every stack entry's `writeKey` everywhere its `folderKey` is currently zeroed: `navigateToRoot`'s loop (line 427-429), `navigateToBreadcrumb`'s discard loop (line 545-547), and after a restored entry's writeKey is consumed by `seedActiveSharedFolder` (mirrors the existing `rootWriteKey?.fill(0)` / `childWriteKey?.fill(0)` finally pattern).

**Required new web-e2e case (per the source todo):** extend `tests/web-e2e/tests/writable-shares.spec.ts` — test 8.4 ("Bob navigates back to root and re-enters subfolder with write access") covers DESCEND-then-write, not the missing case. Add: descend two levels (depth 2), `navigateUp()` ONE level (not to root), then rename/upload from the restored depth-1 level and assert success. This is the exact gap Greptile flagged.

### SC2 — stale-child-snapshot invalidation

**Files:** `apps/web/src/hooks/useSharedNavigationActions.ts` (push site), `apps/web/src/hooks/useSharedNavigation.ts` (subscription), `apps/web/src/hooks/shared-folder-projection.ts` (projection apply)

**Current state:**
- `navigateToSubfolder` pushes `children: p.folderChildren` **by reference** (line 349) into the stack entry for the level being left.
- `subscribeSharedFolderProjection` (`shared-folder-projection.ts:142-154`) only updates `folderChildrenRef`/`setFolderChildren` for the CURRENTLY ACTIVE depth (`client.getSharedFolderState(activeShareId)` always returns the SDK's currently-seeded state, keyed by `shareId` only — there is exactly ONE live depth per share in the SDK's `sharedFolderTree`). It has **no knowledge of the navStack** at all — a `sharedFolder:updated` event for a depth the user has navigated away from (now sitting in `navStackRef.current`) is silently dropped from the stack's point of view; only the live depth's ref/state gets the fresh children.
- Confirmed via `packages/sdk/src/client.ts`'s `adoptSharedFolderResult` (line 5179-5216) and `refreshSharedFolder` (line 5609-5650): both operate on `this.sharedFolderTree.get(shareId)` — the ONE currently-seeded state — so there is no SDK-side memory of "this ipnsName used to be seeded and might now be stale" either.
- Net effect: navigating up/to a breadcrumb restores `NavStackEntry.children` frozen at descent time, even if a `sharedFolder:updated` fired for that exact depth while the user was deeper in the tree.

**Concrete change:** The cleanest fix reuses existing plumbing rather than inventing new invalidation tracking: after `seedActiveSharedFolder` re-seeds the target depth on `navigateUp`/`navigateToBreadcrumb` restore (this already happens today), immediately call `getSdkClient().refreshSharedFolder(currentShareId)` (public method, already used by the 30s poll in `useSharedNavigation.ts:448`). `refreshSharedFolder` re-resolves the just-seeded depth's IPNS record and, if its sequence is fresher than the just-seeded snapshot, calls `adoptSharedFolderResult` which emits `sharedFolder:updated` — the projection subscription (already wired) then overwrites `folderChildren`/`currentSequenceNumber` with the fresh listing. This means the stack's cached `children` becomes purely an OPTIMISTIC first paint (already true today for the folderKey/writeKey path), corrected within one round trip, instead of a permanently-stale value. No new invalidation-tracking data structure needed.
- Note the `refreshSharedFolder` fresh-vs-stale guard at client.ts:5624 (`if (state.sequenceNumber >= result.sequenceNumber) { ... re-emit existing snapshot ... }`) already no-ops correctly when nothing changed — calling it unconditionally on every restore is safe and cheap (one IPNS resolve).
- **Adjacent backlog item folded in (per 73-CONTEXT.md canonical_refs, item 4 of the coderabbit-hardening-backlog todo):** `refreshSharedFolder`'s "fresh" branch (client.ts:5645-5648) calls `adoptSharedFolderResult` WITHOUT `publishedParent`, so the write-body's cached `publishedNode` for that depth goes stale after this fix starts calling `refreshSharedFolder` more often (on every restore, not just every 30s poll). `sdkCore.loadFolderMetadata` (the function `refreshSharedFolder` calls) returns only the decrypted `Node` metadata, NOT the raw `PublishedNode` envelope — so fixing this properly requires an additional `resolvePublishedNode(state.ipnsName)` call inside `refreshSharedFolder` (extra IPFS+IPNS round trip) OR changing `loadFolderMetadata`'s return shape to also carry the envelope. Flag this as a real but bounded cost of choosing the `refreshSharedFolder`-based fix — it's the same code path the source todo #4 already called out as needing repair, so fixing SC2 via this route is the natural place to also close #4, not a new problem introduced by this phase.

**Required new web-e2e case:** a shared-folder-mutated-from-second-client-while-navigated-deeper-then-navigate-up test. `tests/web-e2e/tests/shared-folder-desync.spec.ts` already has the two-client harness (owner + grantee accounts, test 2.1/3.1 pattern) — extend it with a navigate-deeper-then-mutate-then-navigate-up assertion rather than writing a new spec file from scratch.

### SC3 — floor-gate the non-listing read facades

**File:** `packages/sdk/src/client.ts`

**Current state (all three confirmed to bypass the gate):**
- `resolveNodeIdentity(ipnsName: string)` (line 1315-1321) calls `this.resolvePublishedNode(ipnsName)` directly — no `signatureVerified`/`rotationHighWater` check.
- `resolveFileMetadata(fileRef: SealedChildRef, folderKey: Uint8Array)` (line 4207-4233) calls `this.resolvePublishedNode(fileRef.ipnsName)` directly at line 4212.
- `downloadFromIpns(fileRef: SealedChildRef, folderKey: Uint8Array, onProgress?)` (line 4260-...) calls `this.resolvePublishedNode(fileRef.ipnsName)` directly at line 4268.
- The gate itself already exists and is proven correct: `gatedResolveChild(childRef: SealedChildRef)` (line 860-889) wraps `resolvePublishedNode` with the exact ROT-07 checks (`signatureVerified` fail-closed, `Number.MAX_SAFE_INTEGER` overflow guard, `rotationHighWater.enforceResolved(...)`) and is already used by `resolveChildIdentity` (line 913-944), `resolveListingChildren` (line 953-978), and the shared-folder descend path.

**Concrete change:**
- `resolveFileMetadata` / `downloadFromIpns`: BOTH already receive a full `SealedChildRef` (`fileRef`) as a parameter — trivial fix, swap `this.resolvePublishedNode(fileRef.ipnsName)` → `await this.gatedResolveChild(fileRef)`, adjust the null-check message, and use the returned `{published}` exactly as `resolvedNode.published` was used before. No signature change to either public method.
- `resolveNodeIdentity(ipnsName: string)`: CANNOT call `gatedResolveChild` as-is because it takes only a bare `ipnsName` (no `generation`/`versionFloor` to gate on). Its ONE production caller is `apps/web/src/hooks/useSharedWriteOps.ts`'s `resolveChildNodeId(ipnsName)` (line 30-36), called from `deleteItemHandler` (line 187-198) as `resolveChildNodeId(item.ipnsName)` where `item: SealedChildRef` is already fully in scope. **Confirmed via repo-wide grep this is the only call site.** Fix: change `resolveNodeIdentity`'s signature to accept a `childRef: SealedChildRef` (mirroring `resolveChildIdentity`), route it through `gatedResolveChild(childRef)`, and update the one call site to pass `item` instead of `item.ipnsName`. This IS a public SDK API signature change — the existing test `packages/sdk/src/__tests__/resolve-node-identity.test.ts` (77 lines, both cases call `client.resolveNodeIdentity(NODE_IPNS)` with a bare string) must be updated to construct and pass a `SealedChildRef` fixture (mirror the fixture pattern in `resolve-child-identity.test.ts`).

**Required tests (CodeRabbit explicitly requested these, per the source todo):** add a `signatureVerified: false` fail-closed case to `resolve-child-identity.test.ts`-style suites for all three facades. `resolve-node-identity.test.ts` and a new/extended suite covering `resolveFileMetadata`/`downloadFromIpns` (no existing dedicated test file for these two — `folder-metadata-facade.test.ts` tests `getFolderMetadata`, a different method; a new `file-metadata-facade.test.ts` or extension of an existing file is the natural home). Mirror the exact fixture-building pattern already in `resolve-child-identity.test.ts` (`sealNode` + `sealChildReadKey` + `vi.mocked(sdkCore.resolveIpnsRecord).mockResolvedValue({..., signatureVerified: false})` + `expect(...).rejects.toThrow(...)`).

### SC4 — WRITE-03 refresh-access live production trigger (LOCKED: wire end-to-end)

**Files:** `packages/sdk-core/src/ipns/index.ts` (recommended fix point, see below), `packages/sdk/src/client.ts` (`buildWriteTransportSeams`/`publishNodeFn`), `packages/sdk/src/share/shared-write.ts` (already correct, no change needed), `apps/web/src/hooks/useSharedWriteOps.ts` (missing `runWithFailureUx` wiring — bigger gap than the todo states), `apps/web/src/hooks/useMutationFailureUx.ts` (already correct, no change needed).

**Current state — three independent, stacked gaps (confirmed, not assumed):**

1. **`CannotWriteUntilRefetchError`'s throw site is already correctly wired and does NOT need a change.** `packages/sdk/src/share/shared-write.ts` throws `CannotWriteUntilRefetchError` at three call sites (lines 238, 362, 505) whenever `publishNodeFn`'s result has `.tombstoned === true`. This logic is complete and correct.
2. **`publishNodeFn` never produces `{tombstoned: true}`.** `packages/sdk/src/client.ts`'s `buildWriteTransportSeams` (line 5140-5172) implements `publishNodeFn` as: call `sdkCore.createAndPublishIpnsRecord(...)`, and `if (!pubResult.success) throw new Error(...)`, else `return { tombstoned: false, newSequenceNumber: ... }`. There is no code path that returns `{tombstoned: true}` — confirmed by grepping the entire file for `tombstoned: true`, which returns zero matches outside the type signature itself (line 5147).
3. **A real API 410 would not even reach step 2's `if (!pubResult.success)` check — it would throw a raw, unclassified `AxiosError` first.** `packages/api/src/ipns/ipns.service.ts:252-254` throws `HttpException({error: 'IPNS_TOMBSTONED', ipnsName}, HttpStatus.GONE)` (410) when a publish targets a tombstoned name (confirmed server-side implementation for WRITE-04). `packages/api-client/src/instance.ts`'s `customInstance` (used by the generated `ipnsControllerPublishRecord`) does NOT intercept or transform non-2xx responses into a typed result — it lets axios throw the raw `AxiosError` on any non-2xx. `packages/sdk-core/src/ipns/index.ts`'s `createAndPublishIpnsRecord` (line 40-114) has NO try/catch around its `ipnsControllerPublishRecord` call (line 95) — so a 410 propagates as an uncaught `AxiosError`, never reaching the `pubResult.success` check at all.
4. **`useSharedWriteOps.ts` never calls `runWithFailureUx`.** Confirmed by grepping every `runWithFailureUx(` call site in the repo: only `useFolderMutations.ts`, `useFileOperations.ts`, `TextEditorDialog.tsx`, and `useFileBrowserActions.ts` call it — all OWNED-vault paths. `useSharedWriteOps.ts`'s `runWrite`/`withRevocationGuard`/`updateSharedFileHandler`/`moveItemHandler`/`batchMoveItemsHandler` wrap every SDK call with `withRevocationGuard` (403 detection) ONLY — never with `runWithFailureUx`. Even after gap 2 and 3 above are fixed, a thrown `CannotWriteUntilRefetchError` from a shared-write mutation would propagate straight to `runWrite`'s generic `catch (err) { ...setError(message)... }` (line 97-103), never reaching the classifier that dispatches the "Refresh access" toast.

**Concrete change (all four gaps must be closed for the LOCKED acceptance bar):**
1. Push the 410-detection into `sdk-core`'s `createAndPublishIpnsRecord` rather than adding an `axios` dependency to `packages/sdk` (which does not currently depend on axios directly — `sdk-core` and `api-client` do). Wrap the `ipnsControllerPublishRecord` call in a try/catch mirroring the EXISTING idiom already used in the same file's `resolveIpnsRecord` (line 317-325: `const anyError = error as Error & { status?: number; response?: { status?: number } }; const status = anyError.status ?? anyError.response?.status;`), check `status === 410`, and return a `{ success: false, sequenceNumber: 0n, tombstoned: true }`-shaped result (extend the function's return type) instead of rethrowing.
2. `client.ts`'s `publishNodeFn`: read the new `tombstoned` field off `sdkCore.createAndPublishIpnsRecord`'s result and map it straight to `{ tombstoned: true }` (no change needed to the `CannotWriteUntilRefetchError` throw site — that logic already lives correctly in `shared-write.ts`).
3. `useSharedWriteOps.ts`: wrap every write op's inner call in `runWithFailureUx`, threading a `refreshWriteAccess` supplier. The natural implementation of that supplier re-derives the writeKey for the CURRENT depth and re-seeds it (i.e., replay whatever the SC1/SC6 consolidated restore-helper does for "re-derive writeKey for depth X and reseed") — **this creates a real dependency of SC4 on the SC1/SC6 refactor landing first** (see sequencing section). Decide nesting order relative to the existing `withRevocationGuard` (403 detection) — `withRevocationGuard(() => runWithFailureUx(() => op(shareId), { refreshWriteAccess }))` is the natural composition (403 revocation is a harder failure than a stale write-key that a refresh might fix).
4. Upgrade `tests/web-e2e/tests/rotation-ux.spec.ts`'s test at line 278-333 ("a stale co-writer write surfaces Refresh access...") from its current direct `useNotificationStore.getState().addNotification(...)` injection to a genuine flow: perform a real shared write that triggers the classifier (e.g., have a second/owner client tombstone the writer's IPNS name via a real rotation, or via a direct API/DB tombstone in the test fixture, then have the co-writer attempt a write and assert the SAME toast appears through the real classifier path). The test's own `SCOPE NOTE` comment (lines 279-290) already documents exactly why it currently can't do this and cites the precise seams that need to land — this phase is what makes that upgrade possible.

### SC5 — `SharedFolderRow` drag-payload kind from resolved listing

**File:** `apps/web/src/components/file-browser/SharedFolderRow.tsx` (fix), `apps/web/src/components/file-browser/SharedFileBrowser.tsx` (caller, already has what's needed)

**Current state:**
- `SharedFolderRow.tsx:107-118` (`handleDragStart`) calls `isFileRef(i)` (line 111, multi-select payload) and `isFileRef(item)` (line 116, single-item payload) on bare `SealedChildRef`s. Per `apps/web/src/utils/fileTypes.ts:150-153`'s own doc comment, `isFileRef` on a bare `SealedChildRef` (no `.kind` field) ALWAYS returns `false` post-kind-cache-removal (68.2-11) — every shared drag item is mistyped `'folder'`.
- `isFileRefResolved(ref, resolvedByIpnsName)` (fileTypes.ts:167-173) already exists and is the correct replacement — it reads `.kind` directly for a `ResolvedChild`, or looks up `resolvedByIpnsName.get(ref.ipnsName)?.kind` for a bare ref.
- `SharedFileBrowser.tsx` ALREADY computes `resolvedByIpnsName` (a `Map<string, ResolvedChild>`, referenced at lines 160, 762, 777, 841) and ALREADY passes a per-item `resolved` prop to `<SharedFolderRow>` (line 762: `resolved={resolvedByIpnsName.get(item.ipnsName)}`) and already uses `isFileRefResolved(item, resolvedByIpnsName)` itself at lines 777 and 841 for its own double-click/context-menu logic — the map is right there, just not threaded into the drag handler.

**Concrete change:** Add a `resolvedByIpnsName: Map<string, ResolvedChild>` prop to `SharedFolderRowProps`, pass `resolvedByIpnsName={resolvedByIpnsName}` at the `<SharedFolderRow>` call site (line 759-805), and replace the two `isFileRef(...)` calls (lines 111, 116) with `isFileRefResolved(i, resolvedByIpnsName)` / `isFileRefResolved(item, resolvedByIpnsName)`. Purely additive prop-threading — no behavior change to anything currently observable (the todo confirms the shared drop handler never reads `DragItem.type` today), so this needs no new web-e2e assertion beyond "drag still works" (already covered by the existing writable-shares move tests).

### SC6 (folded-in) — consolidate duplicated shared-navigation logic

**File:** `apps/web/src/hooks/useSharedNavigationActions.ts`

**Current state:** `navigateUp` (line 450-528) and `navigateToBreadcrumb` (line 537-610) are ~55-line near-verbatim blocks: both discard current level's folderKey, slice the stack, restore `children`/`folderKey`/`ipnsName`/`sequenceNumber`/breadcrumbs, then independently resolve `ipnsPrivateKey` (via the doomed `resolveFolderIpnsPrivateKey`, SC7), independently branch on `isRootDepth` for the writeKey, and independently call `seedActiveSharedFolder`. `navigateUp` ≡ `navigateToBreadcrumb(stack.length - 1)` conceptually.

**Concrete change:** Extract a single `restoreToBreadcrumbIndex(crumbIndex: number)` (or equivalent) helper that both `navigateUp` (calling it with `stack.length - 1`) and `navigateToBreadcrumb` delegate to. This is the natural landing spot for the SC1 (writeKey source) and SC2 (`refreshSharedFolder` re-resolve) fixes — implement them ONCE inside this helper rather than twice. Per 73-CONTEXT.md, exact decomposition is Claude's discretion.

**Dependency note beyond what the todo states:** because SC4's `refreshWriteAccess` supplier (see SC4 above) most naturally reuses "re-derive writeKey + reseed for the CURRENT depth" logic, extracting that as a callable unit inside this same consolidation (not just inline in the restore path) gives SC4 a clean supplier to call. Consider naming/shaping the extracted helper so it is callable both from a restore (`crumbIndex` known) and from "refresh the CURRENT depth in place" (no navigation, just re-derive) — the latter is exactly what SC4 needs.

### SC7 (folded-in) — remove dead getShareKeys/folder-IPNS write-share key path

**Files:** `apps/web/src/hooks/useSharedNavigationActions.ts` (removal), `apps/web/src/hooks/useSharedNavigation.ts` (param/ref cleanup), `apps/web/src/services/share.service.ts` (NOT to be touched — see landmine below)

**Current state confirmed dead:** `fetchShareKeys(_shareId)` in `share.service.ts:193-201` is a stub that **always returns `[]`** (by design, per the DATA-01 `share_keys` table deletion — the doc comment above it explicitly says so). `resolveFolderIpnsPrivateKey` (useSharedNavigationActions.ts:96-113) therefore ALWAYS falls through to `return new Uint8Array(32)` for every write share, every time, at all 4 call sites (`navigateToShare` line 214, `navigateToSubfolder` line 334, `navigateUp` line 479, `navigateToBreadcrumb` line 563). Confirmed genuinely vestigial (not a live bug): `packages/sdk/src/client.ts`'s actual shared-write signing key recovery reads `parentNode.writeBody.ipnsPrivateKey` (confirmed via grep: `shared-write.ts:214`, `client.ts:1585-1586,3745,5396,5539,5741,5798`) — i.e., from the unsealed write-body, NEVER from `SharedFolderState.ipnsPrivateKey` (the web-seeded zero-buffer field). The web's `ipnsPrivateKeyRef` is write-path-inert.

**Concrete change:**
- Delete `resolveFolderIpnsPrivateKey` (lines 83-113) entirely.
- Remove the `getShareKeys` param from `SharedNavigationActionsParams` (line 74-76) and its 4 call sites; replace with a direct `p.ipnsPrivateKeyRef.current = new Uint8Array(32)` (byte-identical resulting behavior — this preserves the SDK's `SeedSharedFolderArgs.ipnsPrivateKey` contract untouched, which is the smaller, safer diff versus also trying to drop that field from the SDK's `SharedFolderState` shape).
- In `useSharedNavigation.ts`: `getShareKeys` (line 200-207, wraps `fetchShareKeys` with `shareKeysCacheRef`) and `shareKeysCacheRef` (`ShareKeyCache` instance, line 161) become entirely unused once the above lands (confirmed via grep: these two symbols appear ONLY in `useSharedNavigationActions.ts` and `useSharedNavigation.ts`, nowhere else in the web app) — remove the prop threading, the ref, its cleanup call (`shareKeysCacheRef.current.clear()` in the unmount effect, line 308), and the `getShareKeys` callback + its `useCallback` import if it becomes the last use.

**Landmine — do NOT delete `fetchShareKeys` itself or its `folder-ipns` keyType.** `fetchShareKeys` is called from THREE OTHER live sites not touched by this phase: `useSharedWriteOps.ts`'s `resolveFileIpnsKey` (line 45-57, the `file-ipns` keyType fallback for `updateSharedFileHandler`), and referenced by name in `share.service.ts`'s own doc comment as used by `SharedMoveDialog.tsx` and `TextEditorDialog.tsx`. The source todo says removing `fetchShareKeys` itself "may be" possible as a stretch goal — it is NOT, without also auditing and changing those three other call sites, which is out of this phase's declared scope (SC7 is scoped to `useSharedNavigationActions.ts` only per both the todo and the ROADMAP wording "no remaining references" — referring to `resolveFolderIpnsPrivateKey`'s references, not `fetchShareKeys`'s).

## Validation Architecture

Per repo convention (`docs/DEVELOPMENT.md` / `CLAUDE.md` project rules), `apps/web` has zero unit tests — all UI/nav behavior is validated via `tests/web-e2e` Playwright specs (main-push gated); testable logic is hoisted into `packages/sdk`, validated via Vitest (`packages/sdk` `pnpm test` → `vitest run`, config at `packages/sdk/vitest.config.ts`).

### Test Framework

| Property | Value |
|----------|-------|
| SDK framework | Vitest (`packages/sdk/vitest.config.ts`) |
| Web-e2e framework | Playwright (`tests/web-e2e/`, `playwright test`) |
| Quick run command (SDK) | `pnpm --filter @cipherbox/sdk test -- <file>.test.ts` |
| Full suite command (SDK) | `pnpm --filter @cipherbox/sdk test` |
| Web-e2e quick run | `pnpm --filter web-e2e test -- writable-shares.spec.ts` (requires local stack up) |
| Web-e2e full suite | `pnpm --filter web-e2e test` (main-push gated in CI; run locally per `project-web-e2e-local-full-suite-recipe` memory) |

### Phase Requirements → Test Map

| SC | Behavior | Test Type | Automated Command | File Exists? |
|----|----------|-----------|-------------------|-------------|
| SC1 | Write into a deep shared subfolder succeeds after navigate-up | web-e2e | `playwright test writable-shares.spec.ts -g "8.4"` (extend existing test or add new numbered case) | ✅ extend `tests/web-e2e/tests/writable-shares.spec.ts` |
| SC2 | Nav-stack restore reflects fresh children after a remote mutation | web-e2e | `playwright test shared-folder-desync.spec.ts` (extend) | ✅ extend `tests/web-e2e/tests/shared-folder-desync.spec.ts` |
| SC3 | `resolveFileMetadata`/`downloadFromIpns`/`resolveNodeIdentity` reject on `signatureVerified: false` | SDK Vitest | `vitest run resolve-node-identity.test.ts resolve-child-identity.test.ts` + new file-metadata facade test | ✅ (2 existing) / ❌ new file-metadata-facade fail-closed test — Wave 0 gap |
| SC4 | `publishNodeFn` surfaces `{tombstoned:true}` on a real 410; classifier reachable from a real shared write | SDK Vitest (publishNodeFn/createAndPublishIpnsRecord unit) + web-e2e (rotation-ux.spec.ts upgrade) | `vitest run` (sdk-core ipns tests) + `playwright test rotation-ux.spec.ts -g "D-01/WRITE-03"` | ❌ new sdk-core unit test for the 410→tombstoned mapping — Wave 0 gap; ✅ existing e2e test to upgrade |
| SC5 | Drag payload kind matches resolved listing | web-e2e (implicit — no new assertion needed; existing move tests continue passing) | `playwright test writable-shares.spec.ts` | ✅ no new file needed |
| SC6 | Consolidated restore helper behaves identically to the pre-refactor dual paths | web-e2e (regression, existing suites) | `playwright test writable-shares.spec.ts shared-folder-desync.spec.ts` | ✅ existing suites are the regression gate — UI-behavior-neutral refactor per the source todo |
| SC7 | No remaining references to the removed dead path; write behavior unchanged | SDK Vitest (none needed — pure web deletion) + web-e2e regression | `playwright test writable-shares.spec.ts shared-folder-desync.spec.ts` | ✅ existing suites (already documented as the gate in the source todo) |

### Sampling Rate
- **Per task commit:** targeted `vitest run <file>` for SDK changes; no per-commit web-e2e run (too slow — local stack required).
- **Per wave merge:** full `packages/sdk` Vitest suite; a targeted local `playwright test` run against the shared-nav/writable-shares/desync specs (not the full web-e2e suite, which is main-push gated per `project-ci-excludes-web-unit-tests`/`project-web-e2e-only-on-main-push` memory).
- **Phase gate:** full `packages/sdk` Vitest suite green; the four touched web-e2e spec files (`writable-shares.spec.ts`, `shared-folder-desync.spec.ts`, `rotation-ux.spec.ts`, plus a smoke pass of `sharing-workflow.spec.ts`) run locally before `/gsd-verify-work` — full CI web-e2e only runs on merge to main.

### Wave 0 Gaps
- [ ] New/extended SDK Vitest file covering `resolveFileMetadata`/`downloadFromIpns` fail-closed (`signatureVerified: false`) — no existing dedicated test file for these two facades (SC3).
- [ ] New SDK Vitest test for `createAndPublishIpnsRecord`'s 410→`{tombstoned:true}` mapping in `packages/sdk-core/src/ipns/index.ts` (SC4) — mock the axios error shape (`{ response: { status: 410 } }`) the same way `resolveIpnsRecord`'s existing 404 test (if any) does; check `packages/sdk-core/src/__tests__/ipns.test.ts` for the existing pattern to extend.
- [ ] New writable-shares.spec.ts case: descend 2 levels, navigate up 1, write from restored depth (SC1).
- [ ] New/extended shared-folder-desync.spec.ts case: mutate from second client while navigated deeper, then navigate up, assert fresh children (SC2).
- [ ] Rewritten rotation-ux.spec.ts D-01/WRITE-03 test: real classifier-driven flow instead of direct toast injection (SC4).

## Common Pitfalls

### Pitfall 1: Treating SC4 as "just add the `tombstoned:true` branch"
**What goes wrong:** A plan that only touches `publishNodeFn`'s return-mapping will still fail the LOCKED acceptance bar ("at least one live production supplier exists; the classifier path is reachable from real shared-write publish failures") because `useSharedWriteOps.ts` never calls `runWithFailureUx` at all today.
**Why it happens:** The source todo's wording ("no production call site passes a `refreshWriteAccess` supplier") reads as if `runWithFailureUx` IS called (just missing one option) — it is not called at all for shared writes.
**How to avoid:** Verify with `grep -rn "runWithFailureUx(" apps/web/src` before/after — the shared-write hooks must appear in that list post-fix.
**Warning signs:** If `useSharedWriteOps.ts`'s diff doesn't import `runWithFailureUx`, SC4 is incomplete.

### Pitfall 2: Fixing the 410-detection in the wrong package
**What goes wrong:** Adding a raw `axios` import to `packages/sdk/src/client.ts` to detect the 410 there. `packages/sdk` does not declare `axios` as a dependency (only `packages/sdk-core` and `packages/api-client` do) — this would add a new cross-package dependency for no benefit.
**Why it happens:** `publishNodeFn` (the natural-looking fix point) lives in `client.ts`, but the actual axios call happens two layers down inside `sdk-core`'s `createAndPublishIpnsRecord`.
**How to avoid:** Push the try/catch + status check into `packages/sdk-core/src/ipns/index.ts`, mirroring the EXISTING `error as Error & { status?: number; response?: { status?: number } }` idiom already used in the same file's `resolveIpnsRecord` (line 317-325) for 404 detection. `publishNodeFn` then just reads a new field off the already-typed result.
**Warning signs:** A diff that adds `"axios"` to `packages/sdk/package.json`.

### Pitfall 3: Re-deriving SC1's writeKey logic from scratch instead of reusing `resolveSharedSubfolderWriteKey`/`resolveSharedRootWriteKey`
**What goes wrong:** These two SDK-facing helpers (already correct, already tested in production for the descent path per the writable-shares 8.x tests) are the ONLY correct sources of a shared subfolder's writeKey. The fix is capture-and-reuse of their OUTPUT across navigation, not re-implementing key derivation.
**How to avoid:** The diff should not touch `resolveSharedSubfolderWriteKey`/`resolveSharedRootWriteKey`'s implementations at all — only where their results are stored/discarded.

### Pitfall 4: Breaking `resolveNodeIdentity`'s public signature without updating its one test file
**What goes wrong:** `resolveNodeIdentity(ipnsName: string)` → `resolveNodeIdentity(childRef: SealedChildRef)` is a breaking change to an exported `CipherBoxClient` method. `packages/sdk/src/__tests__/resolve-node-identity.test.ts` calls it with a bare string in both its cases and will fail to compile, not just fail assertions.
**How to avoid:** Update the test file in the SAME commit/task as the signature change — build a `SealedChildRef` fixture (mirror `resolve-child-identity.test.ts`'s `buildChildFixture` pattern) instead of a bare string.

### Pitfall 5: SC2's fix silently reintroducing the exact staleness Regression B fixed
**What goes wrong:** The 68.2 CodeRabbit hardening backlog (item 8, NOT in this phase's scope but touching the SAME `forceResolve`/re-resolve machinery) explicitly warns: "Do NOT just drop `forceResolve` on the second leg — that reintroduces the stale `rawChildren`/`sequence` staleness Regression B fixed." SC2's `refreshSharedFolder`-after-restore fix must not accidentally skip or race with this existing freshness machinery.
**How to avoid:** Call `refreshSharedFolder` as an ADDITIONAL step after the existing seed/restore, not as a replacement for anything currently guarding freshness elsewhere (`useSyncPolling.ts`, `useFolderNavigation.ts`'s D-03 belt-and-suspenders leg — those are the OWNED-tree equivalents and are untouched by this phase).

## Landmines / Gotchas (prior-phase seams the planner must respect)

1. **Phase 66 mock tombstone seam.** `packages/sdk/src/share/shared-write.ts`'s `PublishNodeResult` type and its three throw sites are a Phase-66 placeholder that has been sitting correct-but-unreachable since Phase 66. Do not "fix" `shared-write.ts` itself — it is already correct; the gap is entirely upstream (`publishNodeFn`) and downstream (`useSharedWriteOps.ts` wiring).
2. **`isFileRef(bareSealedChildRef)` is unconditionally `false` since the 68.2-11 kind-cache removal.** This is BY DESIGN per `fileTypes.ts`'s own doc comment (preserves the pre-regression always-miss behavior) — do not "fix" `isFileRef` itself; every render site that needs correct kind classification on a bare ref must use `isFileRefResolved` against a `resolvedByIpnsName`/`resolvedChildren` map instead (SC5 is one instance of this pattern; there are OTHER `isFileRef(bareRef)` call sites elsewhere in the codebase not in scope for this phase — do not sweep them).
3. **IPNS `sequenceNumber` is the clock, not wall-clock time.** Any new re-resolve logic (SC2's `refreshSharedFolder` call) must respect the existing `state.sequenceNumber >= result.sequenceNumber` monotonicity guard already in `refreshSharedFolder` (client.ts:5624) — never bypass it with a "just re-fetch and overwrite" shortcut.
4. **`folderTree`-vs-Zustand desync bug class (project memory).** This phase's SC1/SC2 changes touch `navStackRef` (a raw `MutableRefObject`, not Zustand) which is a THIRD state container alongside the SDK's `sharedFolderTree` and the web's `folderChildren`/`currentSequenceNumber` React state — a three-way sync, not two-way. Any new field added to `NavStackEntry` (the `writeKey`) must be kept in lockstep with what `seedActiveSharedFolder`/`sharedFolderTree` expects, or the same desync bug class recurs one level deeper.
5. **D-09 terminal-owner zeroing discipline.** Every new buffer this phase introduces long-lived storage for (the `NavStackEntry.writeKey`) needs a genuinely-audited zero-on-every-exit-path story — this phase is INCREASING the number of live key buffers the web owns (previously the writeKey was zeroed almost immediately after seeding; after SC1 it persists in `navStackRef` for the lifetime of the stack entry). Get this wrong and it's a new key-material-in-memory-longer-than-necessary regression, not just a functional bug.
6. **Item 9 (shared-nav seed race, in scope per 73-CONTEXT.md canonical_refs).** `useSharedNavigation.ts:355-375`'s resolved-listing projection effect can fire `listSharedFolder(currentShareId, [])` BEFORE `seedActiveSharedFolder` completes seeding `sharedFolderTree`, hitting a "Shared folder not loaded" path transiently (masked today by the effect's own dependency array re-firing on seed completion). SC1/SC2's changes to the seed timing (especially SC2's added `refreshSharedFolder` call) touch this exact sequencing — re-verify this race doesn't widen after the changes land; do not "fix" it beyond what's needed (it's explicitly a separate, already-masked, lower-priority item).
7. **Item 4 (refreshSharedFolder stale write envelope, in scope).** Covered under SC2 above — `adoptSharedFolderResult`'s `publishedParent` is not populated by `refreshSharedFolder`'s "fresh" branch. If SC2's fix increases how often `refreshSharedFolder` runs (every restore, not just every 30s poll), consider whether to close this gap in the same task, since the new call frequency makes the write-body staleness window occur more often.
8. **68.2-15's `isFileRefResolved` "unresolved = folder-safe default" convention.** `resolvedByIpnsName.get(ref.ipnsName)?.kind === 'file'` returns `false` (folder) for anything not-yet-resolved, not `undefined`/unknown. SC5's fix inherits this same "loading window defaults to folder" behavior — acceptable per existing convention, do not add new "unresolved" handling beyond what `isFileRefResolved` already does (that's backlog item 2, explicitly out of scope).

## Recommended SC6/SC7-vs-SC1/SC2 Sequencing

All four (SC1, SC2, SC6, SC7) touch the SAME function bodies in `useSharedNavigationActions.ts` (`navigateToSubfolder`, `navigateUp`, `navigateToBreadcrumb`). Sequencing recommendation, in order:

1. **SC7 first (dead-code removal).** Delete `resolveFolderIpnsPrivateKey` + the `getShareKeys`/`shareKeysCacheRef` plumbing. This is a pure subtraction with a well-understood blast radius (confirmed via grep: zero other consumers) and shrinks the file before the next two waves touch it — doing it last would mean re-diffing lines that SC6's consolidation just rewrote.
2. **SC6 second (consolidation).** Extract the single `restoreToBreadcrumbIndex`-style helper from the now-shorter `navigateUp`/`navigateToBreadcrumb` bodies (SC7 already removed the `resolveFolderIpnsPrivateKey` calls inside them, so there's less to carry into the extraction). This produces ONE place where restore logic lives.
3. **SC1 + SC2 third, as edits INSIDE the SC6-extracted helper**, not as a fourth separate pass: add the `writeKey` field to `NavStackEntry` and change the restore helper to (a) use the stack entry's own `writeKey` instead of the `isRootDepth` branch, and (b) call `refreshSharedFolder` after re-seeding. Because both land in the same already-consolidated function, there is no risk of fixing SC1 in `navigateUp` but forgetting the identical fix in `navigateToBreadcrumb` (the exact copy-paste risk SC6 exists to eliminate).
4. **SC4 depends on step 3's output**, not just on steps 1-2: its `refreshWriteAccess` supplier most naturally calls the same "re-derive writeKey + reseed for the current depth" logic that step 3 produces. Sequence SC4's web-side wiring (`useSharedWriteOps.ts`) AFTER SC1/SC6 land, even though SC4's SDK-side fix (`createAndPublishIpnsRecord`/`publishNodeFn`) is independent and can be built in parallel.
5. **SC5 (SharedFolderRow) and the SC3 (facade gating) are fully independent of the above** — different files, no shared state — and can be done in any wave, including in parallel with 1-4.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `refreshSharedFolder` is safe to call more frequently (on every restore, not just every 30s poll) without meaningful performance/rate concern | SC2 | If IPNS resolve is expensive/rate-limited, frequent restore-triggered resolves could add latency to every up/breadcrumb navigation — worth a quick manual check of resolve latency before committing to this approach over a lighter-weight invalidation flag |
| A2 | Extending existing web-e2e spec files (rather than new files) is preferred per repo convention | Validation Architecture | Low risk — matches the explicit "extend, don't duplicate" pattern already visible in the source todos' own "Solution" sections |
| A3 | Pushing the 410 detection into `sdk-core` (not `sdk`) is the right layer | SC4, Pitfall 2 | Low risk — mirrors an identical, already-shipped idiom in the same file; only risk is if a future refactor wants axios-awareness to live only in api-client, which would be a larger separate change |

**Risk note:** all three assumptions above are engineering-judgment calls about WHERE to put a fix, not claims about external facts — no package names, security requirements, or compliance claims are assumed anywhere in this document; every specific claim about current code behavior was verified by reading the cited file:line this session.

## Open Questions

1. **Should SC1's writeKey also be captured for the SHARE-ROOT depth uniformly, or keep the existing `isRootDepth` special case as a fallback?**
   - What we know: today only the root depth has a `resolveSharedRootWriteKey`-based re-derivation path (from `share.encryptedWriteKey`); subfolder depths rely entirely on `resolveSharedSubfolderWriteKey` at descent time.
   - What's unclear: whether the consolidated restore helper should treat the root as "just another stack entry with a writeKey" (requiring a synthetic root entry to exist in the conceptual stack) or keep root as a distinct branch.
   - Recommendation: treat root uniformly if the refactor makes it easy (simpler mental model — one restore path, no branch); keep the branch if it turns out root's write-key source (`share.encryptedWriteKey`, a grant field) is meaningfully different in shape from a subfolder's (`WriteChildRef` walk) such that unifying adds more complexity than it removes. Leave as a task-level decision during planning, not a phase-blocking question.

2. **How expensive is an extra `resolvePublishedNode` call inside `refreshSharedFolder` for the item-4 `publishedParent` fix?**
   - What we know: `loadFolderMetadata` doesn't return the raw envelope; getting `publishedParent` right requires either a second resolve or a `loadFolderMetadata` return-shape change.
   - What's unclear: whether this extra cost is acceptable given SC2 will call `refreshSharedFolder` more often (every restore).
   - Recommendation: decide during planning based on whether item 4 is treated as REQUIRED for this phase or left as a follow-up todo (it's explicitly listed as in-scope per 73-CONTEXT.md, but the ROADMAP's SC2 wording doesn't strictly require the write-body to be fresh, only the READ listing) — a reasonable phase-scoping call is to fix SC2's read-listing staleness now and leave the write-body envelope staleness (item 4) as `checkpoint:human-verify` or explicit follow-up if the extra round-trip proves costly.

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | Unaffected — no auth flow changes |
| V3 Session Management | No | Unaffected |
| V4 Access Control | Yes | SC3's floor-gating IS an access-control-adjacent fix (anti-rollback on shared-item metadata reads) — reuses the EXISTING `RotationHighWater.enforceResolved` gate, no new control introduced |
| V5 Input Validation | No | No new input surface — all changes are internal SDK/hook wiring |
| V6 Cryptography | No | No new crypto primitives; SC1 reuses existing `resolveSharedSubfolderWriteKey`/`resolveSharedRootWriteKey` derivation unchanged |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Anti-rollback bypass via un-gated read facade (SC3's exact bug) | Tampering | Route through `gatedResolveChild`/`RotationHighWater.enforceResolved` (already the project's standard control — this phase closes the last 3 gaps, introduces nothing new) |
| Key material lifetime extension (SC1 storing `writeKey` longer-lived in `navStackRef`) | Information Disclosure (memory-residency window) | D-09 terminal-owner zeroing discipline — every new storage site must have an audited zero-on-exit path (see Landmine 5) |

## Sources

### Primary (HIGH confidence — direct code reads this session)
- `apps/web/src/hooks/useSharedNavigationActions.ts` (full file, 803 lines) — SC1/SC2/SC6/SC7 current-state
- `packages/sdk/src/client.ts` (targeted reads: lines 820-980, 1300-1340, 4180-4300, 5050-5220) — SC3/SC4 current-state
- `apps/web/src/hooks/useMutationFailureUx.ts` (full file) — SC4 classifier correctness confirmed
- `apps/web/src/hooks/useSharedWriteOps.ts` (full file) — SC4 missing wiring confirmed
- `apps/web/src/hooks/useSharedNavigation.ts` (full file) — SC2/SC7 subscription + cleanup current-state
- `apps/web/src/hooks/shared-folder-projection.ts` (full file) — SC2 projection mechanics
- `apps/web/src/components/file-browser/SharedFolderRow.tsx` (full file) — SC5 current-state
- `apps/web/src/components/file-browser/SharedFileBrowser.tsx` (lines 745-841) — SC5 caller-side confirmation
- `apps/web/src/utils/fileTypes.ts` (full file) — `isFileRef`/`isFileRefResolved` exact contracts
- `apps/web/src/services/share.service.ts` (lines 185-225) — `fetchShareKeys` stub confirmation
- `apps/api/src/ipns/ipns.service.ts` (lines 180-270) — server-side tombstone (410) emission confirmed
- `packages/sdk-core/src/ipns/index.ts` (lines 40-114, 190-330) — `createAndPublishIpnsRecord`/`resolveIpnsRecord` implementation + existing 404-detection idiom
- `packages/api-client/src/instance.ts` (full file) — confirmed raw `AxiosError` propagation, no error-transforming interceptor
- `packages/sdk/src/share/shared-write.ts` (grep + targeted context) — `CannotWriteUntilRefetchError` throw sites confirmed correct
- `tests/web-e2e/tests/rotation-ux.spec.ts` (full file) — exact SC4 e2e test to upgrade, with its own scope-note confirming the gap
- `tests/web-e2e/tests/writable-shares.spec.ts`, `shared-folder-desync.spec.ts` (test-name listing) — existing coverage gaps for SC1/SC2
- `packages/sdk/src/__tests__/resolve-child-identity.test.ts`, `resolve-node-identity.test.ts`, `folder-metadata-facade.test.ts` — existing SC3 test patterns and gaps
- `.planning/todos/pending/*.md` (all 8 source todos referenced in 73-CONTEXT.md) — problem/solution specs, treated as authoritative per phase instructions
- `.planning/config.json` — confirmed `nyquist_validation: true` (Validation Architecture required), no `security_enforcement: false` (Security Domain required)

### Secondary (MEDIUM confidence)
- None — no web search or external documentation was needed for this phase; it is entirely internal-codebase research.

### Tertiary (LOW confidence)
- None.

## Metadata

**Confidence breakdown:**
- Per-SC current-state map: HIGH — every claim traced to a specific file:line read this session, cross-checked with grep for exhaustiveness (e.g., "only call site" claims verified via repo-wide grep, not assumed)
- Validation Architecture: HIGH for what test files exist / repo convention; MEDIUM for exact new-test-file naming (left as planner discretion, consistent with 73-CONTEXT.md's "Claude's Discretion" note on task decomposition)
- Sequencing recommendation: HIGH — grounded in the fact that all 4 SCs touch identical line ranges (confirmed by direct read), not a general refactoring heuristic

**Research date:** 2026-07-10
**Valid until:** Should be re-validated if Phase 72 (write-plane durability, in-flight per STATE.md at research time) lands changes to `buildWriteTransportSeams`/`publishNodeFn`/`createAndPublishIpnsRecord` before this phase is planned — check `git log` on `packages/sdk/src/client.ts` and `packages/sdk-core/src/ipns/index.ts` for post-2026-07-10 commits before planning.
