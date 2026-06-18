---
phase: 49-shared-folder-move-intra-share-and-usefoldernavigation-unwra
verified: 2026-06-18T00:00:00Z
status: human_needed
score: 6/6
overrides_applied: 0
human_verification:
  - test: "Run the shared-folder-move e2e suite against a local docker stack"
    expected: "All 7 tests in shared-folder-move.spec.ts pass — including Bob's TextEditor decrypt assertion (test 4.3) and Alice's owner decrypt assertion (test 5.1)"
    why_human: "e2e requires a live two-account Playwright session with local docker stack (docker compose -f docker/docker-compose.yml up -d); CI gates this to main-push only"
---

# Phase 49: Shared-Folder Intra-Share Move + useFolderNavigation Consolidation — Verification Report

**Phase Goal:** Let a write-permission share recipient move a file between subfolders within a single shared folder, re-encrypting the file's FileMetadata IPNS record from the source subfolder's folderKey to the destination subfolder's folderKey; consolidate duplicated web-side ECIES key-unwrap in useFolderNavigation onto the SDK; AND bring the shared-view move UX to parity with the private vault (batch + drag move, REQ-6 added 2026-06-18). Scope locked: intra-share moves only.
**Verified:** 2026-06-18
**Status:** human_needed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | A write-permission recipient can move a file between two subfolders within one shared folder and the file stays decryptable for owner and recipient | VERIFIED (static) | `moveInSharedFolder` op: publishes DEST first → calls `reencryptFileMetadataForFolderChange` with `srcCtx.folderKey` / `destCtx.folderKey` → publishes SOURCE. Client method resolves file-ipns key from `share_keys keyType:'file-ipns'` (not FilePointer). `adoptSharedFolderResult` called for SOURCE only. Live two-account decrypt assertion exists in spec 4.3/5.1 — needs live execution. |
| 2 | The destination picker can list folders anywhere in the shared subtree, each flagged writable or read-only | VERIFIED | `enumerateSharedSubtree` in `client.ts`: DFS from root state, reads `share_keys keyType:'folder'` for read access, `keyType:'folder-ipns'` for `writable` flag. `SharedMoveDialog` calls it on open. Nodes missing a `folder` key are skipped. `visited` Set prevents cycles. |
| 3 | Moving into a folder the recipient lacks a write key for is rejected before any publish | VERIFIED | `client.moveInSharedFolder` checks `keyType:'folder'` then `keyType:'folder-ipns'` BEFORE any `unwrapKey` call or `loadFolderMetadata`. Throws "No write key for destination folder" if `folder-ipns` record absent. |
| 4 | navigateTo in useFolderNavigation delegates ECIES unwrap to client.ensureFolderLoaded with retry preserved and key buffers cloned | VERIFIED | `useFolderNavigation.ts` calls `getSdkClient().ensureFolderLoaded(folderEntry.ipnsName)` in a 3x / 2000ms retry loop guarded by `latestNavTarget.current`. Maps result to `FolderNode` with `new Uint8Array(state.folderKey)` and `new Uint8Array(state.ipnsKeypair.privateKey)` clones. No manual `unwrapKey`/`hexToBytes`/`resolveIpnsRecord`/`fetchAndDecryptMetadata` calls in that block. |
| 5 | A recipient can multi-select files and batch-move them; drag-drop onto folder rows works | VERIFIED | `SharedFileBrowser`: `selectedIds` Set, `multiSelectActive`, `clearSelection`, `SelectionActionBar` wired with `onMove={handleBatchMoveClick}`. `batchMoveItemsHandler` in `useSharedWriteOps` loops `client.moveInSharedFolder` per item inside single `runWrite`. `SharedFolderRow` has `handleDragStart` (multi-select-aware, `application/json {items,parentId}` payload) and `handleDrop` routing to `onMoveItemTo`. |
| 6 | An e2e test proves decrypt-survival for both recipient and owner via TextEditor getContent | VERIFIED (authored, unexecuted) | `tests/web-e2e/tests/shared-folder-move.spec.ts` exists as `test.describe.serial`, two-account Alice/Bob setup, asserts `bobDecrypted === fileContent` (test 4.3) and `aliceDecrypted === fileContent` (test 5.1) via `TextEditorDialogPage.getContent()` after `waitForContentLoaded`. `alice.page.reload({waitUntil:'networkidle'})` present before owner re-read. Page object `SharedMoveDialogPage` exists. |

**Score:** 6/6 truths verified (static + structural); live e2e execution requires human.

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `packages/sdk/src/share/shared-write.ts` | `moveInSharedFolder` stateless op | VERIFIED | `export async function moveInSharedFolder` at line 529; no `.fill(0)` in the op body (caller owns zeroing); returns `{srcResult, destResult}` |
| `packages/sdk/src/client.ts` | `CipherBoxClient.moveInSharedFolder` + `enumerateSharedSubtree` | VERIFIED | Both methods present at lines 2292 and 2401; `withOperation` wrapper; `finally` zeroes `fileIpnsPrivateKey`, `destIpnsPrivateKey`, `destFolderKey` |
| `packages/sdk/src/__tests__/move-in-shared-folder.test.ts` | RED/GREEN SDK unit test | VERIFIED | File exists; tests publish ordering, re-key, collision, write-capability, finally-zeroing |
| `packages/sdk/src/__tests__/enumerate-shared-subtree.test.ts` | RED/GREEN SDK unit test | VERIFIED | File exists |
| `apps/web/src/hooks/useFolderNavigation.ts` | ensureFolderLoaded delegation + retry + cloned buffers | VERIFIED | `ensureFolderLoaded` call, MAX_RETRIES=3/RETRY_DELAY_MS=2000 loop, `new Uint8Array(state.folderKey)` and `new Uint8Array(state.ipnsKeypair.privateKey)` |
| `apps/web/src/hooks/shared-folder-projection.ts` | Pick allowlist includes `moveInSharedFolder` + `enumerateSharedSubtree` | VERIFIED | Lines 38-39 add both to `SharedFolderClient = Pick<CipherBoxClient, ...>` |
| `apps/web/src/hooks/useSharedWriteOps.ts` | `moveItemHandler` + `batchMoveItemsHandler` exported | VERIFIED | Both present; return object exposes `moveItem` and `batchMoveItems` |
| `apps/web/src/hooks/__tests__/useSharedWriteOps.test.ts` | `moveItemHandler` unit case | VERIFIED | `describe('moveItemHandler (REQ-2)')` at line 387 with success and error assertions |
| `apps/web/src/components/file-browser/SharedMoveDialog.tsx` | Shared subtree picker dialog, ≥60 lines, `enumerateSharedSubtree` call, batch `items` prop | VERIFIED | 234 lines; `enumerateSharedSubtree` in `useEffect`; `items?` prop with `isBatchMode` branching for title/label; no `useFolderStore` import |
| `apps/web/src/components/file-browser/SharedFileBrowser.tsx` | `selectedIds` + `SelectionActionBar` + `handleDropOnFolder` routing + `SharedMoveDialog` wired | VERIFIED | All present; folder-view ContextMenu has `onMove`; list-view ContextMenu has `readOnly` and NO `onMove` |
| `apps/web/src/components/file-browser/SharedFolderRow.tsx` | `handleDragStart`/`handleDrop` + `application/json` | VERIFIED | `handleDragStart` multi-select-aware; `handleDrop` parses `application/json` defensively with try/catch; routes to `onMoveItemTo(item.id, item.ipnsName)` |
| `tests/web-e2e/tests/shared-folder-move.spec.ts` | Two-account move + decrypt-survival e2e | VERIFIED (authored) | `test.describe.serial`; `getContent()` assertions for Bob and Alice; `networkidle` reload |
| `tests/web-e2e/page-objects/file-browser/shared-move-dialog.page.ts` | `SharedMoveDialogPage` page object | VERIFIED | Exports `SharedMoveDialogPage` with `waitForOpen`, `selectFolder`, `clickMove`, `waitForClose`, `getVisibleFolderNames`, `isFolderSelected`, `isMoveDisabled` |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `client.moveInSharedFolder` | `shareOps.moveInSharedFolder` | pre-resolved src/dest contexts + `fileIpnsPrivateKey` | WIRED | Line 2358: `shareOps.moveInSharedFolder({ctx, srcCtx, destCtx, itemId, fileIpnsPrivateKey})` |
| `shareOps.moveInSharedFolder` (file branch) | `reencryptFileMetadataForFolderChange` | `sourceFolderKey`/`destFolderKey`/`fileIpnsPrivateKey`, `createVersion:false` implied | WIRED | Lines 572-579: called when `movedItem.type === 'file' && fileIpnsPrivateKey` |
| `client.moveInSharedFolder` | `adoptSharedFolderResult` | SOURCE only (`srcResult`) | WIRED | Line 2378: `this.adoptSharedFolderResult(shareId, srcResult)` — `destResult` never passed |
| `SharedFileBrowser folder-view ContextMenu` | `SharedMoveDialog` | `onMove → handleMoveClick(item) → setMoveDialogItem` | WIRED | Lines 812-816 (folder-view only); list-view ContextMenu at lines 541-555 has `readOnly` and no `onMove` |
| `moveItemHandler` | `client.moveInSharedFolder` | `runWrite(shareId => ...)` | WIRED | Lines 196-204 in `useSharedWriteOps.ts` |
| `SharedMoveDialog` | `client.enumerateSharedSubtree` | `useEffect` on `open && shareId` | WIRED | Lines 66-94 in `SharedMoveDialog.tsx` |
| `SelectionActionBar batch-move button` | `SharedMoveDialog (items prop)` | `handleBatchMoveClick` → `setBatchMoveDialogOpen(true)` | WIRED | Lines 192-196 (handleBatchMoveClick), lines 838-853 (batch dialog mount with `items={batchMoveItems_}`) |
| `batchMoveItemsHandler` | `client.moveInSharedFolder` (loop) | per-item loop, `clearSelection` after | WIRED | Lines 231-243 in `useSharedWriteOps.ts` |
| `SharedFolderRow handleDrop` | `onMoveItemTo` (handleDropOnFolder-equiv) | `application/json {items,parentId}` payload parse | WIRED | Lines 116-154; routes single/batch to `onMoveItemTo(item.id, item.ipnsName)` |
| `shared-folder-move.spec.ts` | `TextEditorDialogPage.getContent` | `readContentViaEditor` after `waitForContentLoaded` | WIRED | Lines 87-88; `getContent()` called after `waitForContentLoaded({timeout:30_000})` |
| `shared-folder-move.spec.ts` | `alice.page.reload({waitUntil:'networkidle'})` | cross-client sync before owner re-read | WIRED | Line 298: `await alice.page.reload({ waitUntil: 'networkidle' })` |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|-------------------|--------|
| `SharedMoveDialog.tsx` | `pickerNodes` | `enumerateSharedSubtree` DFS resolving `share_keys` from API | Yes — DFS walks real IPNS/IPFS nodes via `loadFolderMetadata` | FLOWING |
| `useSharedWriteOps.batchMoveItemsHandler` | per-item `moveInSharedFolder` | loops real SDK crypto calls (unwrap → publish → re-key) | Yes — no mock or static fallback in the handler | FLOWING |
| `useFolderNavigation.navigateTo` | `FolderNode` from `FolderState` | `client.ensureFolderLoaded` → real IPNS resolve + decrypt | Yes — ensureFolderLoaded does real IPFS/IPNS + ECIES | FLOWING |

### Behavioral Spot-Checks

Step 7b skipped for the live crypto/IPNS operations (require running docker stack + browser). Static checks were performed instead:

| Behavior | Check | Result | Status |
|----------|-------|--------|--------|
| SDK unit tests exist | `ls packages/sdk/src/__tests__/ \| grep move-in-shared\|enumerate-shared` | Both files present | PASS |
| moveInSharedFolder op has no fill(0) | `sed -n '529,594p' shared-write.ts \| grep fill(0)` | No output | PASS |
| Client finally-zeroes 3 keys | grep lines 2381-2383 in client.ts | `fileIpnsPrivateKey`, `destIpnsPrivateKey`, `destFolderKey` all zeroed | PASS |
| adoptSharedFolderResult called for SOURCE only | grep pattern in client.ts | Line 2378: `srcResult` passed; comment "never call adoptSharedFolderResult for dest" | PASS |
| List-view ContextMenu has no onMove | grep list-view ContextMenu block | `readOnly` prop present, no `onMove` prop | PASS |
| SharedMoveDialog has no useFolderStore import | grep SharedMoveDialog.tsx | No useFolderStore import | PASS |
| e2e spec is test.describe.serial + networkidle | grep spec file | `test.describe.serial` at line 37, `waitUntil: 'networkidle'` at line 298 | PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| REQ-1 | 49-01 | SDK shared-subtree enumeration | SATISFIED | `enumerateSharedSubtree` in `client.ts`; DFS; `visited` Set; writable flag from `folder-ipns` presence |
| REQ-2 | 49-01 | SDK `moveInSharedFolder` op + client method + FileMetadata re-key | SATISFIED | Stateless op + client method; publish DEST→re-key→SOURCE; file-ipns from `share_keys` not FilePointer; three keys zeroed in finally |
| REQ-3 | 49-03 | Web hook + single-item context-menu move + SharedMoveDialog | SATISFIED | `moveItemHandler` in `useSharedWriteOps`; `SharedMoveDialog` built; `onMove` wired in folder-view ContextMenu only; Pick allowlist updated |
| REQ-4 | 49-02 | useFolderNavigation consolidation onto ensureFolderLoaded | SATISFIED | `navigateTo` calls `ensureFolderLoaded`; 3x/2s retry preserved; `new Uint8Array(...)` clones |
| REQ-5 | 49-05 | Within-share move e2e decrypt-survival | SATISFIED (authored) | Spec authored; `getContent()` assertions for both parties; `networkidle` reload; TypeChecks pass. **Live execution is the human_needed item.** |
| REQ-6 | 49-04 | Shared batch + drag move parity | SATISFIED | `batchMoveItemsHandler`; `selectedIds`/`multiSelectActive`/`SelectionActionBar`; `SharedMoveDialog items` prop; `SharedFolderRow` drag-drop |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `useSharedWriteOps.ts` batchMoveItemsHandler | 243 | `clearSelection()` called after `runWrite()` unconditionally — since `runWrite` catches errors internally without re-throwing, `clearSelection` fires on failure too | Warning | UX-only: selection clears even when batch move fails, deviating from "clearSelection on success" requirement. Not a crypto or data-integrity issue. No TBD/FIXME marker present. |

No `TBD`, `FIXME`, or `XXX` debt markers found in any of the modified files.

### Human Verification Required

#### 1. Live Two-Account E2E: Shared-Folder Intra-Share Move Decrypt-Survival

**Test:** Start local docker stack (`docker compose -f docker/docker-compose.yml up -d`), start API + web dev servers, run `pnpm --filter web-e2e test -- shared-folder-move`.

**Expected:** All 7 tests pass. Specifically:
- Test 4.3: Bob reads the moved file via TextEditor — `bobDecrypted === fileContent`
- Test 5.1: Alice reloads and navigates into the subfolder — `aliceDecrypted === fileContent`

**Why human:** Requires a live two-account Playwright session with a running docker stack and IPNS propagation delays. CI gates this to main-push only per project memory.

### Gaps Summary

No blocking gaps. All 6 must-have truths are verified at the static/structural level across all 5 plans (REQ-1 through REQ-6). The crypto ordering (DEST publish → re-key FileMetadata → SOURCE publish), the recipient-side file-ipns key resolution from `share_keys`, the write-capability guard before any publish, the three-key `finally`-zeroing, the `adoptSharedFolderResult` SOURCE-only call, the useFolderNavigation consolidation, the batch/drag REQ-6 parity, and the e2e spec authoring all check out in the actual source.

One WARNING: `batchMoveItemsHandler.clearSelection()` fires unconditionally after `runWrite` (even on failure) because `runWrite` catches internally. The plan required "clearSelection on success." This is a UX-only deviation with no crypto or data-integrity impact; flagged as advisory.

Status is `human_needed` solely because the live two-account e2e (REQ-5) cannot be executed in a static verification pass.

---

_Verified: 2026-06-18_
_Verifier: Claude (gsd-verifier)_
