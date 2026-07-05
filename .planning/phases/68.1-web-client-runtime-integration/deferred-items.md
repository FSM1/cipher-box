# Deferred Items — Phase 68.1

Out-of-scope discoveries logged during plan execution (not fixed; scope boundary rule).

## From 68.1-11 (share/invite creation)

- **`apps/web/src/services/share.service.ts`** still throws
  `'deferred to Phase 68 — descriptor-ref rotation/grant path not yet wired'` in
  `createShare`, `updateSharePermission`, `fetchShareKeys`, and `fetchPendingRotations`.
  This file is marked `@deprecated: Use @cipherbox/sdk instead` and was explicitly
  out of 68.1-11's `files_modified` scope (only `key-wrapping.ts`, `ShareDialog.tsx`,
  `invite.service.ts` were touched).
  - `ShareDialog.tsx`'s `handleDowngradeConfirm` (pre-existing, not part of 68.1-11's
    task list) still calls `share.service.ts`'s `updateSharePermission` and will still
    throw at runtime when a user tries to downgrade a write share back to read-only.
    This is a **pre-existing bug**, not a regression introduced by 68.1-11 — the
    upgrade path (`handleUpgrade`, in scope for 68.1-11) now fails gracefully with a
    user-facing error instead of an unconditional throw; downgrade should get the
    same treatment (and ideally a real implementation) in a follow-up.
  - `checkPendingRotation`/`fetchPendingRotations` are unused by any current call
    site found during this plan's grep sweep — left as-is.

- **Write-permission share/invite creation** (SHARE-WRITE-KEY web-wiring gap): see
  the `68.1-11-SUMMARY.md` "Known Gaps" section — a full architecture note, not a
  simple out-of-scope item, so it is documented there rather than duplicated here.

## From 68.1-24 (GAP-6 backfill removal)

- **`apps/api/src/shares/shares.controller.spec.ts` `updateGrant` test** — pre-existing
  failure at HEAD (confirmed via `git show HEAD:...`, unrelated to this plan's changes).
  `SharesController.updateGrant` calls `sharesService.updateGrant(shareId, userId,
  readDescriptorRef, rootGeneration, writeDescriptorRef, clearWriteDescriptor)` (6 args,
  added in 68.1-19), but the test's `toHaveBeenCalledWith` assertion only lists the first
  4 args, so it now fails with two unexpected trailing `undefined`s. Not touched — outside
  this plan's `files_modified` (`updateGrant` describe block, not `updateShareItemName`).
  Needs a follow-up to update the assertion to include `dto.writeDescriptorRef` and
  `dto.clearWriteDescriptor`.

- **`apps/api/src/ipns/ipns-verify-cache.spec.ts` and
  `apps/api/src/metrics/http-metrics.interceptor.spec.ts`** — pre-existing `tsc --noEmit`
  errors on `apps/api`'s own tsconfig (TS2352 unsafe cast, TS2724 missing `HttpArgumentsHost`
  export from `@nestjs/common`). Unrelated to the shares module; not in this plan's file
  scope. `apps/api` typecheck is not part of the root `pnpm typecheck` chain (which only
  covers crypto/core/api-client/sdk-core/sdk/web), so this did not block the plan's
  `pnpm typecheck` acceptance criterion.

- **`pnpm lint:fix` (repo-root)** — fails on pre-existing errors in `landing/.astro/*.d.ts`
  (generated Astro content types: triple-slash-reference, empty-object-type) and warnings
  in `apps/api/src/ipfs/pending-unpin/unpin-helpers.spec.ts` (`no-explicit-any`). None of
  these files were touched by this plan; `pnpm api:generate`'s `openapi:generate` + `orval
  generate` + `api-client build` steps all succeeded before the trailing `lint:fix` step hit
  these unrelated errors. Scoped `eslint --fix` on this plan's touched files passed clean.

- **`packages/api-client` orval `clean` gap** — `orval.config.ts` has no `output.clean: true`,
  so regenerating after deleting the `UpdateItemNameDto` schema left an orphaned
  `src/models/updateItemNameDto.ts` file and a stale `export * from './updateItemNameDto'`
  barrel line in `src/models/index.ts` that `pnpm api:generate` did not remove on its own.
  Manually deleted both as part of this plan (in scope: `packages/api-client/src/models` is
  in `files_modified`). A future plan could add `output.clean: true` to
  `packages/api-client/orval.config.ts` to make future removals self-cleaning — architectural
  tooling change, not done here.

## From 68.1-30 (deep shared-write seeding, WEB-03 gap closure)

- **`apps/web/src/components/file-browser/SharedFileBrowser.tsx:417-447`** —
  `writable-shares.spec.ts` test 10.3 ("Bob opens the write-shared file and can
  edit it") fails deterministically (confirmed on two consecutive full-file live
  runs, not a flake): the text editor opens but the loaded content is empty
  string instead of the file's real content, so `expect(content).toBe(...)`
  fails at line 859 of the spec.
  - **Root cause:** for a DIRECT single-file share (root `kind: 'file'`), the
    auto-open-editor effect synthesizes a `SealedChildRef` with
    `readKeySealed: ''` — a pre-existing `// TODO(phase 63): populated when
    read-chain is available` stub, predating this plan. `navigateToShare` also
    sets `folderKey: null` for a single-file share root (by design — the root
    IS the leaf, and `downloadSharedFile` is meant to independently re-derive
    the chain via `navigateReadChain`). `TextEditorDialog`'s shared-file load
    path (`downloadFileFromIpns({ fileRef: item, folderKey })`) receives both
    an empty `readKeySealed` and a `null` `folderKey`, so it cannot recover the
    file's content — this is a distinct, unwired code path from the shared-FOLDER
    text-preview fix 68.1-29 already landed (`a6db25594`, which only fixed
    `TextEditorDialog` reads for a file living inside an already-loaded shared
    folder, not a directly-shared file root).
  - **Why not fixed here:** `SharedFileBrowser.tsx` is NOT in this plan's
    `files_modified` (`client.ts`, the new resolver test, and
    `useSharedNavigationActions.ts` only); Task 3 is explicitly a no-source-edit
    live-verification task. This is unrelated to the WEB-03 deep-shared-write
    write-chain this plan targets (subfolder writeKey recovery) — it is a
    read-chain wiring gap for the single-file-share editor route, never
    reachable in any prior full-suite run because `writable-shares.spec.ts`
    always cascade-stopped at 8.2 (the gap this plan closes) before reaching
    Phase 10 of the spec. A future plan should wire a real read-chain recovery
    (mirroring `downloadSharedFile`'s `navigateReadChain` approach) into the
    auto-open-editor effect for single-file shares.
  - **State:** `writable-shares.spec.ts` 1.1-10.2 green, 10.3 fails
    deterministically, 10.4 did-not-run (cascade). This plan's own gating tests
    (8.2/8.3/8.4/8.5, the deep-shared-write acceptance surface) are all green.

## From 68.1-32 (single-file-share text-editor path, closes writable-shares 10.3)

- **`apps/web/src/stores/folder.store.ts:239-256` (owner-side kind cache,
  `apps/web/src/lib/kind-cache.ts`)** — `writable-shares.spec.ts` test 10.4
  ("Alice can read the file edited by Bob") fails deterministically on two
  consecutive full-file live runs (both runs: `Target page, context or browser
  has been closed` / timeout waiting for `.context-menu-item` matching
  `/edit\|view/i`), even though this plan's own target (10.3, "Bob opens the
  write-shared file and can edit it") is GREEN on both runs.
  - **Root cause (confirmed via failure screenshots):** at the moment of
    failure, Alice's OWNED file browser row renders the file as
    `[DIR] file-share-<runId>.txt` instead of `[FILE]` — a `kind`-cache MISS.
    `SealedChildRef` carries no `kind` field (NODE-03); `isFileRef` reads a
    memoized cache (`kind-cache.ts`) populated by a **fire-and-forget**
    `resolveKinds(event.children)` call in `folder.store.ts` (documented D-02:
    "this is a synchronous setter — the initial render reads a cache miss
    (folder-safe default) ... once it settles, re-invoke updateFolderChildren").
    Because the cache miss defaults to folder-safe, the `ContextMenu`'s
    `isFile && onEdit` guard hides the "Edit" menu item, so no
    `.context-menu-item` matches `/edit\|view/i` and the click times out.
    Test 10.4 does `page.reload({ waitUntil: 'networkidle' })` →
    `waitForItemToAppear` → immediately right-click + click "Edit" **within
    the same test function**, with no wait for the async kind-cache resolve
    to settle. Sibling tests 4.1/4.2 exercise the identical reload-then-open
    sequence but SPLIT across two separate `test()` blocks (natural
    inter-test delay absorbs the async resolve), which is why this race was
    never observed there.
  - **Why not fixed here:** `folder.store.ts` and `kind-cache.ts` are NOT in
    this plan's `files_modified` (`client.ts`, its unit test,
    `useSharedNavigationActions.ts`, `useSharedNavigation.ts`,
    `TextEditorDialog.tsx`, `SharedFileBrowser.tsx` only) and are entirely
    unrelated to the single-file-share write seam this plan adds — 10.4
    exercises Alice's OWNER file browser (`FileBrowser.tsx`/`ContextMenu.tsx`),
    not `SharedFileBrowser.tsx`. Per this plan's constraints, Task 3 is
    explicitly a no-source-edit verification task and must not weaken the
    spec assertion. This is a documented, intentional D-02 async-settle
    design (best-effort kind resolution, folder-safe default) whose UI
    re-render race was never exercised before because `writable-shares.spec.ts`
    Phase 10 never ran to completion in any prior full-suite run (10.3 always
    failed first — see the 68.1-30 entry above — so 10.4 was unreached code
    until this plan's Task 1+2 fixes made 10.3 pass for the first time).
  - **Evidence the underlying write is correct, independent of the UI race:**
    10.3 is green on both runs (Bob's edit round-trips through
    `updateSharedSingleFile` and the dialog closes on save); the failure
    screenshot shows Alice's file list correctly displaying the shared item
    by its real name post-reload (data layer intact) — only the kind-derived
    "Edit" menu entry is transiently missing.
  - **State:** `writable-shares.spec.ts` 1.1-10.3 green (including this
    plan's own target, 10.3) on both live runs; 10.4 fails deterministically
    for the reason above. A future plan should either await kind-cache
    settlement before the owner "Edit" affordance renders (e.g. a loading
    state instead of a silent folder-safe default) or have test 10.4 wait for
    kind resolution (e.g. poll for the row to lose its `[DIR]` tag) before
    right-clicking.
