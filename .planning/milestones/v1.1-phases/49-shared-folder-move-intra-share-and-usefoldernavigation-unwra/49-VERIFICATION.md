---
phase: 49-shared-folder-move-intra-share-and-usefoldernavigation-unwra
verified: 2026-06-18T00:00:00Z
status: passed
score: 17/17
uat_signoff: "2026-06-18 — UAT gates signed off green by maintainer. Decrypt-survival (tests 4.3 + 5.1) proven by green CI E2E run 27766162738: shared-folder-move.spec.ts passed end-to-end (Bob and Alice both decrypt after sync). Move-UX functional routing covered by useSharedWriteOps + e2e; visual gestures accepted."
overrides_applied: 0
human_verification:
  - test: "Run the shared-folder-move e2e suite against a local docker stack (docker compose -f docker/docker-compose.yml up -d) with a two-account Playwright session"
    expected: "All 5 serial tests in shared-folder-move.spec.ts pass — Bob's TextEditor decrypt assertion (test 4.3, bobDecrypted === fileContent) and Alice's owner decrypt assertion (test 5.1, aliceDecrypted === fileContent) both succeed after cross-client sync (alice.page.reload networkidle)"
    why_human: "Decrypt-survival is the phase's load-bearing behavioral claim; it can only be proven by a live two-account session against real IPNS/IPFS + ECIES. CI gates web-e2e to main-push only and the verifier is forbidden from running the suite (RAM starvation under concurrent verifiers). Static analysis confirms the move op re-keys FileMetadata src->dest folderKey, but actual decryptability after the publish round-trip needs runtime."
  - test: "Manually drag a multi-selection of files onto a writable shared subfolder row in the shared view, and separately right-click a single file -> Move into a subfolder"
    expected: "Multi-select drag routes through batchMoveItems (selection clears on success); single context-menu move routes through moveItem; read-only destination folders are disabled in the picker; the source list refreshes via sharedFolder:updated without a manual reload"
    why_human: "Drag-and-drop gesture, picker disabled-state UX, and projection-driven refresh are runtime/visual behaviors that static wiring verification cannot exercise end to end."
---

# Phase 49: Shared-Folder Intra-Share Move + useFolderNavigation Consolidation — Verification Report

**Phase Goal:** Let a write-permission share recipient move a file between subfolders within a single shared folder, re-encrypting the file's FileMetadata IPNS record from the source subfolder's folderKey to the destination subfolder's folderKey (mirroring owner moveItem and the #507 decrypt-fail-after-move fix) so the file stays decryptable for owner AND recipient; consolidate the duplicated web-side ECIES key-unwrap in useFolderNavigation onto the SDK; AND bring the shared-view move UX to parity with the private vault (batch + drag move, REQ-6). Scope locked: intra-share moves only.
**Verified:** 2026-06-18
**Status:** passed (UAT signed off 2026-06-18 — see frontmatter `uat_signoff`)
**Re-verification:** No — fresh verification against the post-PR-509 merged working tree.

## Goal Achievement

### Observable Truths

| # | Truth (source plan) | Status | Evidence |
|---|---------------------|--------|----------|
| 1 | A write-permission recipient can move a file between two subfolders within one shared folder and it stays decryptable for owner and recipient (49-01) | VERIFIED (static); decrypt-survival needs live e2e | `shared-write.ts:558-591` publishes DEST first -> re-keys FileMetadata via `reencryptFileMetadataForFolderChange` with `srcCtx.folderKey`/`destCtx.folderKey` (`:572-578`) -> publishes SOURCE. `client.ts:2352-2364` resolves file-ipns key from `share_keys keyType:'file-ipns'` (NOT FilePointer). `client.ts:2386` adopts SOURCE result only. Runtime decryptability after publish round-trip -> human (e2e 4.3/5.1). |
| 2 | The destination picker lists folders anywhere in the shared subtree, each flagged writable or read-only (49-01) | VERIFIED | `client.ts:enumerateSharedSubtree` (`:2409-2500`): DFS from root state, `keyType:'folder'` for read access (`:2457-2458` skips nodes without it), `writable = some(keyType:'folder-ipns')` (`:2466-2468`), `visited` Set prevents cycles (`:2453`). |
| 3 | Moving into a folder the recipient lacks a write key for is rejected before any publish (49-01) | VERIFIED | `client.ts:2318-2326` checks `keyType:'folder'` then `keyType:'folder-ipns'` and throws "No write key for destination folder" BEFORE any `unwrapKey`/`loadFolderMetadata`/publish. Test `move-in-shared-folder.test.ts:339`. |
| 4 | A name collision in the destination is rejected (throws) (49-01) | VERIFIED | Collision enforced by `moveItem` inside the op (`shared-write.ts:552-556`). Test `move-in-shared-folder.test.ts:375` "propagates name collision error from moveItem without publishing". |
| 5 | Navigating into a folder loads children/folderKey/ipnsPrivateKey via the SDK's single unwrap path, not a duplicate web-side unwrap (49-02) | VERIFIED | `useFolderNavigation.ts:240` `getSdkClient().ensureFolderLoaded(folderEntry.ipnsName)`. No `unwrapKey`/`hexToBytes`/`resolveIpnsRecord`/`fetchAndDecryptMetadata` in navigateTo (grep returned none). |
| 6 | Navigating into a just-created folder still succeeds (IPNS-propagation retry preserved) (49-02) | VERIFIED | `useFolderNavigation.ts:234-244` MAX_RETRIES=3 / RETRY_DELAY_MS=2000 loop guarded by `latestNavTarget.current` (`:239,248`). |
| 7 | Folder key material in React state survives client.destroy() (cloned, not aliased) (49-02) | VERIFIED | `useFolderNavigation.ts:272-273` `new Uint8Array(state.folderKey)` and `new Uint8Array(state.ipnsKeypair.privateKey)` — fresh-buffer clones. |
| 8 | A write-permission recipient can right-click a file, pick a destination anywhere in the subtree, and move it (49-03) | VERIFIED | `SharedFileBrowser.tsx:823-828` folder-view ContextMenu `onMove` (gated `permission==='write'`) -> `handleMoveClick` -> `setMoveDialogItem`; dialog `:834-846` calls `moveItem`. |
| 9 | The picker lists the whole subtree, disabling folders the recipient cannot write to (49-03) | VERIFIED | `SharedMoveDialog.tsx:85` calls `enumerateSharedSubtree`; `:132` disables `!node.writable \|\| node.id === currentFolderId \|\| disabledDestIds`. 268 lines, no `useFolderStore` import. |
| 10 | After a move the source list refreshes via the sharedFolder:updated projection (write path reads nothing back) (49-03) | VERIFIED (static) | Op adopts SOURCE via `adoptSharedFolderResult` (`client.ts:2386`); web handler `useSharedWriteOps.ts:198-206` calls only `moveInSharedFolder` (no read-back). Test `useSharedWriteOps.test.ts:131`. Visual refresh -> human. |
| 11 | The Move option is absent from the synthetic top-level shares list-view menu (49-03) | VERIFIED | `SharedFileBrowser.tsx:546-560` read-only top-level ContextMenu has `readOnly` and NO `onMove`; folder-view menu (`:823`) is the only one with `onMove`. |
| 12 | A recipient can multi-select files and batch-move them in a single action (49-04) | VERIFIED | `SharedFileBrowser.tsx:143` `selectedIds` Set, `:649-653` `SelectionActionBar` `onMove={handleBatchMoveClick}`, batch dialog `:849-860` -> `batchMoveItems`. Handler `useSharedWriteOps.ts:232-241` loops `moveInSharedFolder` inside one `runWrite`. |
| 13 | A recipient can drag a file (or multi-selection) onto a shared subfolder row to move it (49-04) | VERIFIED | `SharedFolderRow.tsx:73-151,:197-201` `handleDragStart`/`handleDrop` with `application/json {items,parentId}` payload -> `onMoveItemTo`. `SharedFileBrowser.tsx:756-775` routes multi->`batchMoveItems`, single->`moveItem`. |
| 14 | Per-item collision and write-cap are validated during batch move; a failed item does not silently corrupt others (49-04) | VERIFIED | Each iteration calls `moveInSharedFolder` enforcing write-cap (`client.ts:2318-2326`) + collision (`shared-write.ts:552`); a per-item throw stops the loop, `runWrite` returns `false` (`useSharedWriteOps.ts:62-68`), selection is KEPT on failure (`:246` clears only on `ok`). |
| 15 | Selection clears after a successful batch move (49-04) | VERIFIED | `runWrite` returns `Promise<boolean>` (`useSharedWriteOps.ts:51,61,68`); `:246` `if (ok) clearSelection()`. Test `useSharedWriteOps.test.ts:516`. (Resolves the prior planning-time WARNING — current merged code gates on `ok`, does NOT clear on failure.) |
| 16 | An e2e test proves the recipient's intra-share move keeps content decryptable for recipient AND owner after cross-client sync (49-05) | VERIFIED (authored, unexecuted) | `shared-folder-move.spec.ts` `test.describe.serial`, two-account Alice/Bob, test 4.3 `expect(bobDecrypted).toBe(fileContent)` (`:286`), test 5.1 `expect(aliceDecrypted).toBe(fileContent)` (`:325`) after `alice.page.reload({waitUntil:'networkidle'})` (`:298`). Live execution -> human. |
| 17 | The decrypt-survival assertion goes through the TextEditor decrypt-on-read path, not mere list visibility (49-05) | VERIFIED | `shared-folder-move.spec.ts:76-88` `readContentViaEditor` drives right-click -> Edit -> `waitForContentLoaded({timeout:30_000})` -> `getContent()` via `TextEditorDialogPage`. |

**Score:** 17/17 truths verified (static + structural). Truths 1 and 16 carry a runtime decrypt-survival component authored as e2e but unexecuted -> human verification.

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `packages/sdk/src/share/shared-write.ts` | `moveInSharedFolder` stateless op | VERIFIED | `:529`; DEST-first publish, re-key, SOURCE publish; caller owns zeroing. |
| `packages/sdk/src/client.ts` | `moveInSharedFolder` + `enumerateSharedSubtree` | VERIFIED | `:2292` and `:2409`; `withOperation`; `finally` zeroes fileIpnsPrivateKey/destIpnsPrivateKey/destFolderKey (`:2387-2392`). |
| `packages/sdk/src/__tests__/move-in-shared-folder.test.ts` | SDK unit test | VERIFIED | 13 tests / 30 expects / 7 toThrow; no skips. |
| `packages/sdk/src/__tests__/enumerate-shared-subtree.test.ts` | SDK unit test | VERIFIED | 8 tests / 20 expects; writable flag, read-key skip, cycle guard, key-zeroing. |
| `apps/web/src/hooks/useFolderNavigation.ts` | ensureFolderLoaded delegation + retry + cloned buffers | VERIFIED | `:240`, `:234-244`, `:272-273`. |
| `apps/web/src/hooks/shared-folder-projection.ts` | Pick allowlist adds move + enumerate | VERIFIED | verifier passed; substantive. |
| `apps/web/src/hooks/useSharedWriteOps.ts` | `moveItemHandler` + `batchMoveItemsHandler` | VERIFIED | `:191` and `:218`; exports `moveItem`/`batchMoveItems` (`:257-258`). |
| `apps/web/src/hooks/__tests__/useSharedWriteOps.test.ts` | move + batch unit cases | VERIFIED | `moveItemHandler (REQ-2)` `:387`, `batchMoveItemsHandler (REQ-6)` `:483`. |
| `apps/web/src/components/file-browser/SharedMoveDialog.tsx` | subtree picker, enumerate, batch `items` prop | VERIFIED | 268 lines; `:85` enumerate, `:28/:57` `items?`/`isBatchMode`, no `useFolderStore`. |
| `apps/web/src/components/file-browser/SharedFileBrowser.tsx` | selectedIds + SelectionActionBar + drag routing + dialogs + list-view menu lacks onMove | VERIFIED | `:143,:649,:756-775,:834,:849`; list-view menu `:546-560` lacks `onMove`. |
| `apps/web/src/components/file-browser/SharedFolderRow.tsx` | handleDragStart/handleDrop + application/json | VERIFIED | `:73-151,:197-201`; defensive JSON parse; routes to `onMoveItemTo`. |
| `tests/web-e2e/tests/shared-folder-move.spec.ts` | two-account move + decrypt-survival | VERIFIED (authored) | serial, getContent assertions for Bob and Alice, networkidle reload. |
| `tests/web-e2e/page-objects/file-browser/shared-move-dialog.page.ts` | `SharedMoveDialogPage` page object | VERIFIED | verifier passed; used by the spec. |

Note: the artifact verifier flagged `shared-folder-move.spec.ts` with "Missing pattern: shared-folder move" — this is a literal-substring expectation in the plan's pattern, not a defect; the file exists, is substantive, and contains the asserted decrypt-survival logic (confirmed by direct read).

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `client.moveInSharedFolder` | `shareOps.moveInSharedFolder` | pre-resolved src/dest contexts + fileIpnsPrivateKey | WIRED | `client.ts:2366-2384` |
| `shareOps.moveInSharedFolder` (file branch) | `reencryptFileMetadataForFolderChange` | source/dest folderKey + file-ipns key | WIRED | `shared-write.ts:570-579` |
| `client.moveInSharedFolder` | `adoptSharedFolderResult` | SOURCE result only | WIRED | `client.ts:2386` (`destResult` never adopted) |
| `useFolderNavigation.navigateTo` | `client.ensureFolderLoaded` | 3x/2s retry guarded by latestNavTarget | WIRED | `useFolderNavigation.ts:238-244` |
| `FolderState.folderKey / ipnsKeypair.privateKey` | `FolderNode.folderKey / ipnsPrivateKey` | `new Uint8Array(...)` clone | WIRED | `useFolderNavigation.ts:272-273` |
| `SharedFileBrowser folder-view ContextMenu` | `SharedMoveDialog` | `onMove -> handleMoveClick -> setMoveDialogItem` | WIRED | `SharedFileBrowser.tsx:823-828,:137,:834` |
| `moveItemHandler` | `client.moveInSharedFolder` | `runWrite(shareId => ...)` | WIRED | `useSharedWriteOps.ts:198-206` |
| `SharedMoveDialog` | `client.enumerateSharedSubtree` | useEffect on open | WIRED | `SharedMoveDialog.tsx:68-94` |
| `SelectionActionBar batch-move button` | `SharedMoveDialog (items prop)` | `handleBatchMoveClick` | WIRED | `SharedFileBrowser.tsx:653,:197,:849-852` |
| `batchMoveItemsHandler` | `client.moveInSharedFolder` (loop) | per-item loop, clearSelection on success | WIRED | `useSharedWriteOps.ts:232-246` |
| `SharedFolderRow handleDrop` | `onMoveItemTo` (handleDropOnFolder-equiv) | `application/json {items,parentId}` parse | WIRED | `SharedFolderRow.tsx:114-151` -> `SharedFileBrowser.tsx:756-775` |
| `shared-folder-move.spec.ts` | `TextEditorDialogPage.getContent` | `readContentViaEditor` after `waitForContentLoaded` | WIRED | spec `:76-88,:280-286,:319-325` |
| `shared-folder-move.spec.ts` | `alice.page.reload({waitUntil:'networkidle'})` | cross-client sync before owner re-read | WIRED | spec `:298` |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|-------------------|--------|
| `SharedMoveDialog.tsx` | picker nodes | `enumerateSharedSubtree` DFS resolving real `share_keys` + `loadFolderMetadata` | Yes | FLOWING |
| `useSharedWriteOps.batchMoveItemsHandler` | per-item move | loops real SDK crypto (unwrap -> publish -> re-key); no mock/static fallback | Yes | FLOWING |
| `useFolderNavigation.navigateTo` | `FolderNode` | `client.ensureFolderLoaded` -> real IPNS resolve + ECIES decrypt | Yes | FLOWING |

### Behavioral Spot-Checks

Skipped per the execution constraint (live crypto/IPNS/browser require a running docker stack; verifier forbidden from running suites under concurrent verifiers). Static structural verification performed instead; runtime decrypt-survival routed to human verification.

### Probe Execution

N/A — no `scripts/*/tests/probe-*.sh` declared or implied for this phase.

### Requirements Coverage

| Requirement | Source | Status | Evidence |
|-------------|--------|--------|----------|
| REQ-1 SDK shared-subtree enumeration | 49-01 | SATISFIED | truth 2 |
| REQ-2 SDK move op + client method (re-key) | 49-01 | SATISFIED | truths 1,3,4 |
| REQ-3 web hook + context-menu move + dialog | 49-03 | SATISFIED | truths 8-11 |
| REQ-4 useFolderNavigation consolidation | 49-02 | SATISFIED | truths 5-7 |
| REQ-5 e2e decrypt-survival | 49-05 | SATISFIED (authored) / human (execution) | truths 16-17 |
| REQ-6 shared batch + drag move | 49-04 | SATISFIED | truths 12-15 |

No orphaned requirements: all 6 REQs map to executed plans.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `SharedFileBrowser.tsx` | 554-555, 821-822 | `() => {}` no-op rename/delete | Info | Intentional no-ops on the read-only synthetic-shares menu and the `isWritable`-gated path; not part of the move feature, not stubs. |

No TBD / FIXME / XXX / TODO / HACK / placeholder markers in any phase file. No empty-data stubs feeding rendered output.

The prior planning-time verification flagged a WARNING that `batchMoveItemsHandler.clearSelection()` fires unconditionally on failure. This is STALE against the merged tree: `runWrite` returns `Promise<boolean>` (`useSharedWriteOps.ts:51,61,68`) and the handler gates `if (ok) clearSelection()` (`:246`), so selection is preserved on failure. Warning withdrawn.

### Test-Quality Audit (static)

- No `.skip` / `.only` / `xit` / `xdescribe` / `test.todo` in any phase test file.
- `move-in-shared-folder.test.ts`: 13 tests / 30 expects / 7 toThrow — publish ordering, key args, finally-zeroing.
- `enumerate-shared-subtree.test.ts`: 8 tests / 20 expects — writable flag, read-key skip, cycle guard, key-zeroing.
- `useSharedWriteOps.test.ts`: 15 tests / 39 expects — move routing + error surfacing; batch early-return + clearSelection.
- No circular fixtures or trivially-true assertions observed. Assertion strength: strong.

### Human Verification Required

See frontmatter. Two items:

1. Execute `shared-folder-move.spec.ts` against a live two-account docker stack — proves decrypt-survival for recipient (test 4.3) and owner (test 5.1) at runtime.
2. Manual drag/batch/single move UX + picker disabled-state + projection-driven refresh in the running shared view.

**✅ Signed off 2026-06-18 (maintainer).** Item 1 is satisfied by green CI E2E run `27766162738`, in which `shared-folder-move.spec.ts` passed end-to-end (decrypt-survival tests 4.3 + 5.1 — Bob and Alice both decrypt after sync). Item 2's functional routing is covered by `useSharedWriteOps`/e2e; the visual gesture behavior is accepted by the maintainer. Status set to `passed`.

### Gaps Summary

No gaps. All 17 truths are structurally verified against the merged post-PR-509 tree with concrete file:line evidence; all artifacts exist, are substantive, and are wired with real data flow; all key links are WIRED. The only outstanding items are runtime/visual behaviors (decrypt-survival e2e execution and move-UX gestures) that cannot be exercised statically and are routed to human verification — which forces overall status `human_needed` rather than `passed`.

---

_Verified: 2026-06-18_
_Verifier: Claude (gsd-verifier)_
