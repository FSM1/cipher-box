# Phase 49: Shared-folder move (intra-share) and useFolderNavigation unwrap consolidation - Pattern Map

**Mapped:** 2026-06-18
**Files analyzed:** 10 new/modified files
**Analogs found:** 10 / 10

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
| --- | --- | --- | --- | --- |
| `packages/sdk/src/share/shared-write.ts` (ADD `moveInSharedFolder`) | service | CRUD + file-I/O | `shared-write.ts` `renameInSharedFolder` (:345) + `deleteFromSharedFolder` (:378) + `updateSharedFile` (:413) | exact |
| `packages/sdk/src/client.ts` (ADD `enumerateSharedSubtree` + `moveInSharedFolder`) | service | CRUD + event-driven | `client.ts` `renameInSharedFolder` (:2141) / `deleteFromSharedFolder` (:2158) + `ensureFolderLoaded` (:444) | exact |
| `apps/web/src/hooks/shared-folder-projection.ts` (MODIFY Pick allowlist) | utility | — | Same file (:28-38) | exact |
| `apps/web/src/hooks/useSharedWriteOps.ts` (ADD `moveItemHandler`) | hook | request-response | `deleteItemHandler` (:173) / `updateSharedFileHandler` (:123) | exact |
| `apps/web/src/components/file-browser/SharedMoveDialog.tsx` (NEW) | component | request-response | `MoveDialog.tsx` (structure); `useSharedNavigationActions.ts` `navigateToSubfolder` (data source) | role-match |
| `apps/web/src/components/file-browser/SharedFileBrowser.tsx` (MODIFY `onMove` wire) | component | request-response | Same file folder-view ContextMenu (:687) | exact |
| `apps/web/src/hooks/useFolderNavigation.ts` (MODIFY unwrap block :241-302) | hook | request-response | `client.ts` `ensureFolderLoaded` (:444-514) | role-match |
| `packages/sdk/src/__tests__/enumerate-shared-subtree.test.ts` (NEW) | test | — | Existing SDK shared-write unit tests | role-match |
| `packages/sdk/src/__tests__/move-in-shared-folder.test.ts` (NEW) | test | — | Existing SDK shared-write unit tests | role-match |
| `tests/web-e2e/tests/shared-folder-move.spec.ts` (NEW) | test | — | `move-restore-content.spec.ts` + `writable-shares.spec.ts` | exact |

## Pattern Assignments

### `packages/sdk/src/share/shared-write.ts` — ADD `moveInSharedFolder` (stateless op)

**Analog:** `shared-write.ts` `renameInSharedFolder` (:345) + `updateSharedFile` (:413)

**Imports pattern** (lines 1-49 — everything already imported; add `moveItem` from sdk-core if not present):

```typescript
import { updateFolderMetadataAndPublish } from '@cipherbox/sdk-core';
import type { SdkContext } from '@cipherbox/sdk-core';
// reencryptFileMetadataForFolderChange is in ../reencrypt.ts (sibling)
import { reencryptFileMetadataForFolderChange } from '../reencrypt';
// sdkCore.moveItem from @cipherbox/sdk-core folder/index
import { moveItem } from '@cipherbox/sdk-core';
```

**Core op pattern** — two explicit contexts, publish DEST first (copy from `renameInSharedFolder` (:356-366) for the `updateFolderMetadataAndPublish` call shape):

```typescript
// packages/sdk/src/share/shared-write.ts:345-367 (renameInSharedFolder shape to mirror)
export async function renameInSharedFolder(
  swCtx: SharedWriteContext,
  params: { itemId: string; newName: string }
): Promise<{ publishedChildren: FolderChild[]; newSequenceNumber: bigint }> {
  const updatedChildren = swCtx.children.map((child) =>
    child.id === params.itemId ? { ...child, name: params.newName, modifiedAt: Date.now() } : child
  );
  const { newSequenceNumber, publishedChildren } = await updateFolderMetadataAndPublish({
    children: updatedChildren,
    baseChildren: swCtx.children,
    folderKey: swCtx.folderKey,
    ipnsPrivateKey: swCtx.ipnsPrivateKey,
    ipnsName: swCtx.ipnsName,
    sequenceNumber: swCtx.sequenceNumber,
    ctx: swCtx.ctx,
  });
  return { publishedChildren, newSequenceNumber };
}
```

**New op signature** (dual context, pre-resolved keys — no callbacks in stateless op):

```typescript
// packages/sdk/src/share/shared-write.ts — NEW moveInSharedFolder
export async function moveInSharedFolder(params: {
  ctx: SdkContext;
  srcCtx: {
    folderKey: Uint8Array;
    ipnsPrivateKey: Uint8Array;
    ipnsName: string;
    sequenceNumber: bigint;
    children: FolderChild[];
  };
  destCtx: {
    folderKey: Uint8Array;
    ipnsPrivateKey: Uint8Array;
    ipnsName: string;
    sequenceNumber: bigint;
    children: FolderChild[];
  };
  itemId: string;
  /** Pre-resolved file IPNS private key (from share_keys keyType:'file-ipns'); null for folder items */
  fileIpnsPrivateKey: Uint8Array | null;
}): Promise<{
  srcResult: { publishedChildren: FolderChild[]; newSequenceNumber: bigint };
  destResult: { publishedChildren: FolderChild[]; newSequenceNumber: bigint };
}> {
  // 1. Pure source/dest children mutation (throws on name collision)
  const { updatedSourceChildren, updatedDestChildren, movedItem } = moveItem({
    sourceChildren: params.srcCtx.children,
    destChildren: params.destCtx.children,
    childId: params.itemId,
  });

  // 2. Publish DEST first (add-before-remove crash safety)
  const destResult = await updateFolderMetadataAndPublish({
    children: updatedDestChildren,
    baseChildren: params.destCtx.children,
    folderKey: params.destCtx.folderKey,
    ipnsPrivateKey: params.destCtx.ipnsPrivateKey,
    ipnsName: params.destCtx.ipnsName,
    sequenceNumber: params.destCtx.sequenceNumber,
    ctx: params.ctx,
  });

  // 3. If file: re-seal FileMetadata under dest folderKey
  if (movedItem.type === 'file' && params.fileIpnsPrivateKey) {
    const fp = movedItem as FilePointer;
    await reencryptFileMetadataForFolderChange({
      fileMetaIpnsName: fp.fileMetaIpnsName,
      fileIpnsPrivateKey: params.fileIpnsPrivateKey,
      sourceFolderKey: params.srcCtx.folderKey,
      destFolderKey: params.destCtx.folderKey,
      ctx: params.ctx,
    });
    // Caller owns zeroing fileIpnsPrivateKey in finally — NOT this function.
  }

  // 4. Publish SOURCE (removal)
  const srcResult = await updateFolderMetadataAndPublish({
    children: updatedSourceChildren,
    baseChildren: params.srcCtx.children,
    folderKey: params.srcCtx.folderKey,
    ipnsPrivateKey: params.srcCtx.ipnsPrivateKey,
    ipnsName: params.srcCtx.ipnsName,
    sequenceNumber: params.srcCtx.sequenceNumber,
    ctx: params.ctx,
  });

  return { srcResult, destResult };
}
```

---

### `packages/sdk/src/client.ts` — ADD `enumerateSharedSubtree` + `moveInSharedFolder`

**Analog:** `client.ts` `renameInSharedFolder` (:2141-2153) + `deleteFromSharedFolder` (:2158-2167) + `ensureFolderLoaded` (:444-514)

**Client method shape** (copy from `renameInSharedFolder` / `deleteFromSharedFolder` (:2141-2167)):

```typescript
// client.ts:2141-2153 — shape to copy for ALL shared write methods
async renameInSharedFolder(
  shareId: string,
  args: { itemId: string; newName: string }
): Promise<void> {
  return this.withOperation('renameInSharedFolder', async () => {
    const state = this.requireSharedFolder(shareId);
    const result = await shareOps.renameInSharedFolder(
      this.buildSharedWriteContextFromState(state),
      args
    );
    this.adoptSharedFolderResult(shareId, result);
  });
}
```

**Private plumbing** (copy from :2045-2100 verbatim — do not reinvent):

```typescript
// client.ts:2045 — requireSharedFolder
private requireSharedFolder(shareId: string): SharedFolderState {
  const state = this.sharedFolderTree.get(shareId);
  if (!state) throw new Error('Shared folder not loaded');
  return state;
}

// client.ts:2078 — adoptSharedFolderResult (SOURCE ONLY — never call for dest)
private adoptSharedFolderResult(
  shareId: string,
  result: { publishedChildren: FolderChild[]; newSequenceNumber: bigint }
): void {
  const live = this.sharedFolderTree.get(shareId);
  if (!live) return;
  const next: SharedFolderState = { ...live, children: result.publishedChildren, sequenceNumber: result.newSequenceNumber };
  this.sharedFolderTree.set(shareId, next);
  this.emitter.emit({ type: 'sharedFolder:updated', shareId, ipnsName: live.ipnsName, children: result.publishedChildren, sequenceNumber: result.newSequenceNumber });
}
```

**`enumerateSharedSubtree` DFS pattern** (mirrors `ensureFolderLoaded` (:464-513) but reading from `share_keys` not vault-wrapped `FolderEntry.folderKeyEncrypted`):

```typescript
// client.ts:444-514 — DFS skeleton to mirror for enumerateSharedSubtree
// Differences: use share_keys keyType:'folder' for folderKey unwrap;
//              use share_keys keyType:'folder-ipns' for write-capability flag;
//              call loadFolderMetadata (not loadFolder) to get children without storing in folderTree;
//              return flat [{id, name, ipnsName, writable}] list instead of a single FolderState
const visited = new Set<string>([rootIpnsName]);
const stack: Array<{ ipnsName: string; children: FolderChild[] }> = [{ ipnsName: rootIpnsName, children: rootChildren }];
while (stack.length > 0) {
  const current = stack.pop()!;
  for (const child of current.children) {
    if (child.type !== 'folder') continue;
    if (visited.has(child.ipnsName)) continue;
    visited.add(child.ipnsName);
    const keyRecord = shareKeys.find((k) => k.keyType === 'folder' && k.itemId === child.id);
    if (!keyRecord) continue;
    const folderKey = await unwrapKey(hexToBytes(keyRecord.encryptedKey), vaultPrivateKey);
    const writable = shareKeys.some((k) => k.keyType === 'folder-ipns' && k.itemId === child.id);
    result.push({ id: child.id, name: child.name, ipnsName: child.ipnsName, writable });
    const meta = await loadFolderMetadata({ ipnsName: child.ipnsName, folderKey, ctx: this.ctx });
    if (meta) stack.push({ ipnsName: child.ipnsName, children: meta.children });
  }
}
```

**`moveInSharedFolder` client method** — dest context resolved fresh, source from `sharedFolderTree`, `adoptSharedFolderResult` called for SOURCE ONLY:

```typescript
async moveInSharedFolder(
  shareId: string,
  args: {
    itemId: string;
    destFolderId: string;
    destIpnsName: string;
    vaultPrivateKey: Uint8Array;
    getShareKeysFn: (shareId: string) => Promise<ShareKeyEntry[]>;
  }
): Promise<void> {
  return this.withOperation('moveInSharedFolder', async () => {
    const srcState = this.requireSharedFolder(shareId);
    const shareKeys = await args.getShareKeysFn(shareId);

    // Resolve dest folderKey + ipnsPrivateKey from share_keys (recipient-wrapped)
    const destFolderKeyRecord = shareKeys.find(
      (k) => k.keyType === 'folder' && k.itemId === args.destFolderId
    );
    if (!destFolderKeyRecord) throw new Error('No read key for destination folder');
    const destFolderIpnsRecord = shareKeys.find(
      (k) => k.keyType === 'folder-ipns' && k.itemId === args.destFolderId
    );
    if (!destFolderIpnsRecord) throw new Error('No write key for destination folder');

    const destFolderKey = await unwrapKey(hexToBytes(destFolderKeyRecord.encryptedKey), args.vaultPrivateKey);
    const destIpnsPrivateKey = await unwrapKey(hexToBytes(destFolderIpnsRecord.encryptedKey), args.vaultPrivateKey);

    // Load dest children fresh (NEVER use a cached/stale ref — A1 assumption)
    const destMeta = await loadFolderMetadata({ ipnsName: args.destIpnsName, folderKey: destFolderKey, ctx: this.ctx });
    const destChildren = destMeta?.children ?? [];
    const destSequenceNumber = destMeta?.sequenceNumber ?? 0n;

    // Resolve file IPNS key if item is a file (from share_keys keyType:'file-ipns' — recipient-wrapped)
    const movedItem = srcState.children.find((c) => c.id === args.itemId);
    let fileIpnsPrivateKey: Uint8Array | null = null;
    if (movedItem?.type === 'file') {
      const fileIpnsRecord = shareKeys.find((k) => k.keyType === 'file-ipns' && k.itemId === args.itemId);
      if (fileIpnsRecord) {
        fileIpnsPrivateKey = await unwrapKey(hexToBytes(fileIpnsRecord.encryptedKey), args.vaultPrivateKey);
      }
    }

    try {
      const { srcResult } = await shareOps.moveInSharedFolder({
        ctx: this.ctx,
        srcCtx: {
          folderKey: srcState.folderKey,
          ipnsPrivateKey: srcState.ipnsPrivateKey,
          ipnsName: srcState.ipnsName,
          sequenceNumber: srcState.sequenceNumber,
          children: srcState.children,
        },
        destCtx: { folderKey: destFolderKey, ipnsPrivateKey: destIpnsPrivateKey, ipnsName: args.destIpnsName, sequenceNumber: destSequenceNumber, children: destChildren },
        itemId: args.itemId,
        fileIpnsPrivateKey,
      });
      // Adopt SOURCE only (see Pitfall 1 in RESEARCH.md — never adopt dest)
      this.adoptSharedFolderResult(shareId, srcResult);
    } finally {
      if (fileIpnsPrivateKey) fileIpnsPrivateKey.fill(0);
      destIpnsPrivateKey.fill(0);
      destFolderKey.fill(0);
    }
  });
}
```

---

### `apps/web/src/hooks/shared-folder-projection.ts` — MODIFY Pick allowlist

**Analog:** Same file (:28-38)

**Current allowlist** (lines 28-38):

```typescript
export type SharedFolderClient = Pick<
  CipherBoxClient,
  | 'on'
  | 'loadSharedFolder'
  | 'unloadSharedFolder'
  | 'uploadToSharedFolder'
  | 'createSharedSubfolder'
  | 'renameInSharedFolder'
  | 'deleteFromSharedFolder'
  | 'updateSharedFile'
>;
```

**After modification** — add two new methods:

```typescript
export type SharedFolderClient = Pick<
  CipherBoxClient,
  | 'on'
  | 'loadSharedFolder'
  | 'unloadSharedFolder'
  | 'uploadToSharedFolder'
  | 'createSharedSubfolder'
  | 'renameInSharedFolder'
  | 'deleteFromSharedFolder'
  | 'updateSharedFile'
  | 'moveInSharedFolder'       // REQ-2
  | 'enumerateSharedSubtree'   // REQ-1
>;
```

---

### `apps/web/src/hooks/useSharedWriteOps.ts` — ADD `moveItemHandler`

**Analog:** `deleteItemHandler` (:173-180) for simple `runWrite` dispatch; `updateSharedFileHandler` (:123-167) for the share_keys resolution pattern

**Simple handler pattern** (copy `deleteItemHandler` (:173-180)):

```typescript
// useSharedWriteOps.ts:173-180 — deleteItemHandler (simplest runWrite shape)
const deleteItemHandler = useCallback(
  async (item: FolderChild) => {
    await runWrite(async (shareId) => {
      await getSdkClient().deleteFromSharedFolder(shareId, { itemId: item.id });
    }, 'Shared folder delete failed');
  },
  [runWrite]
);
```

**File IPNS key resolution pattern** (copy from `updateSharedFileHandler` (:138-163)):

```typescript
// useSharedWriteOps.ts:138-163 — getFileIpnsKeyFn pattern (re-use for move)
const keys = await fetchShareKeys(shareId);
const exactMatch = keys.find((k) => k.keyType === 'file-ipns' && k.itemId === itemId);
// For move: always use exactMatch (file-ipns entry keyed by itemId);
// never fall back to FilePointer.ipnsPrivateKeyEncrypted (owner-wrapped, cannot unwrap with recipient key)
```

**`moveItemHandler` imports needed:**

```typescript
// useSharedWriteOps.ts:14-21 (existing imports — moveItemHandler also needs)
import { useAuthStore } from '../stores/auth.store';
import { fetchShareKeys } from '../services/share.service';
import { unwrapKey, hexToBytes } from '@cipherbox/crypto';
import { getSdkClient } from '../lib/sdk-provider';
```

**`moveItemHandler` shape:**

```typescript
const moveItemHandler = useCallback(
  async (item: FolderChild, destFolderId: string, destIpnsName: string) => {
    const auth = useAuthStore.getState();
    if (!auth.vaultKeypair) { p.setError('No keypair available'); return; }
    await runWrite(async (shareId) => {
      await getSdkClient().moveInSharedFolder(shareId, {
        itemId: item.id,
        destFolderId,
        destIpnsName,
        vaultPrivateKey: auth.vaultKeypair!.privateKey,
        getShareKeysFn: fetchShareKeys,
      });
    }, 'Shared folder move failed');
  },
  [runWrite, p.setError]
);
```

---

### `apps/web/src/components/file-browser/SharedMoveDialog.tsx` (NEW)

**Analog:** `MoveDialog.tsx` (:1-60) for modal structure + props shape; `useSharedNavigationActions.ts` `navigateToSubfolder` (:222+) for data source pattern

**Do NOT import `useFolderStore`** — that is the private vault tree (confirmed: `MoveDialog.tsx:4`).

**Dialog props shape** (mirror `MoveDialogProps` from `MoveDialog.tsx:11-26` minus vault-store fields):

```typescript
// MoveDialog.tsx:11-26 — props shape to mirror (replace FolderNode tree with shared picker nodes)
type MoveDialogProps = {
  open: boolean;
  onClose: () => void;
  onConfirm: (destinationFolderId: string) => void;
  item: FolderChild | null;
  currentFolderId: string;
  isLoading?: boolean;
};
```

**Imports pattern** (from `MoveDialog.tsx:1-6`):

```typescript
import { useState, useEffect, useCallback } from 'react';
import type { FolderChild } from '@cipherbox/core';
import { Modal } from '../ui/Modal';
import '../../styles/dialogs.css';
// SharedMoveDialog also needs:
import { getSdkClient } from '../../lib/sdk-provider';
import { useAuthStore } from '../../stores/auth.store';
import { fetchShareKeys } from '../../services/share.service';
```

**Picker node type** (writable flag drives disabled state):

```typescript
type SharedPickerNode = {
  id: string;
  name: string;
  ipnsName: string;
  writable: boolean;
};
```

**Data loading pattern** — call `enumerateSharedSubtree` on open:

```typescript
useEffect(() => {
  if (!open || !shareId) return;
  const auth = useAuthStore.getState();
  if (!auth.vaultKeypair) return;
  getSdkClient()
    .enumerateSharedSubtree(shareId, {
      getShareKeysFn: fetchShareKeys,
      vaultPrivateKey: auth.vaultKeypair.privateKey,
    })
    .then(setPickerNodes)
    .catch(() => setError('Failed to load folder tree'));
}, [open, shareId]);
```

**a11y rule** (apps/web CLAUDE.md): interactive folder rows need `role="button"` + `onKeyDown` for Enter/Space; `:focus-visible` style required.

---

### `apps/web/src/components/file-browser/SharedFileBrowser.tsx` — MODIFY `onMove` wire

**Analog:** Same file folder-view ContextMenu (:686-709) — currently no `onMove` prop

**Wire pattern** — add `onMove` to folder-view ContextMenu only (NOT list-view at :466):

```typescript
// SharedFileBrowser.tsx:686-709 (folder-view ContextMenu) — add onMove prop:
<ContextMenu
  // ... existing props ...
  onMove={!readOnly && writeOps ? () => handleMoveClick(item) : undefined}
/>
// List-view ContextMenu at :466 — keep as-is (no onMove)
```

**Handler to add** (opens SharedMoveDialog):

```typescript
const [moveDialogItem, setMoveDialogItem] = useState<FolderChild | null>(null);
const handleMoveClick = useCallback((item: FolderChild) => setMoveDialogItem(item), []);
```

---

### `apps/web/src/hooks/useFolderNavigation.ts` — MODIFY unwrap block (:241-302)

**Analog:** `client.ts` `ensureFolderLoaded` (:444-514) for what the new call does

**Current block to replace** (lines 241-302 — hand-rolled unwrap + resolve + decrypt + retry):

```typescript
// useFolderNavigation.ts:241-302 — REPLACE this entire block
const folderKey = await unwrapKey(hexToBytes(folderEntry.folderKeyEncrypted), vaultKeypair.privateKey);
const ipnsPrivateKey = await unwrapKey(hexToBytes(folderEntry.ipnsPrivateKeyEncrypted), vaultKeypair.privateKey);
// ... manual resolveIpnsRecord + fetchAndDecryptMetadata + retry loop ...
```

**Replacement pattern** (from RESEARCH.md Pattern 3 — verified against `FolderState` shape):

```typescript
// AFTER — thin retry wrapper over ensureFolderLoaded
const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 2000;
let state: FolderState | null = null;
for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
  if (latestNavTarget.current !== targetFolderId) return;  // MUST preserve guard
  state = await getSdkClient().ensureFolderLoaded(folderEntry.ipnsName);
  if (state) break;
  if (attempt === MAX_RETRIES) break;
  await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
}
// Map FolderState -> FolderNode — clone SDK-owned buffers (zeroed on client.destroy())
const folderNode: FolderNode = {
  id: targetFolderId,
  name: folderEntry.name,
  ipnsName: folderEntry.ipnsName,
  parentId,
  children: state?.children ?? [],
  isLoaded: !!state,
  isLoading: false,
  sequenceNumber: state?.sequenceNumber ?? 0n,
  folderKey: state ? new Uint8Array(state.folderKey) : new Uint8Array(0),
  ipnsPrivateKey: state ? new Uint8Array(state.ipnsKeypair.privateKey) : new Uint8Array(0),
  // Do NOT use state.ipnsKeypair.publicKey — it is new Uint8Array(0) for tree-walked folders
};
```

---

### `packages/sdk/src/__tests__/enumerate-shared-subtree.test.ts` (NEW)

**Analog:** Existing SDK unit test structure for shared-write ops

**Test structure pattern:**

```typescript
// Mirror existing SDK shared tests: mock SdkContext, stub loadFolderMetadata,
// stub unwrapKey. Test: DFS returns all reachable subfolders; writable flag
// set only when keyType:'folder-ipns' present; missing keyType:'folder' entry
// skips that node; cycles (repeated ipnsName) do not loop.
```

---

### `packages/sdk/src/__tests__/move-in-shared-folder.test.ts` (NEW)

**Analog:** Existing SDK unit test structure; `move-restore-content.spec.ts` for scenario coverage

**Scenarios to cover:**

- Publish ordering: DEST published before SOURCE (mock captures call order)
- Name collision: `moveItem` throws; error propagates
- Missing `folder-ipns` key on dest: client method throws before any publish
- File re-key: `reencryptFileMetadataForFolderChange` called with correct src/dest folderKey
- Idempotent re-key: source `DECRYPTION_FAILED` handled by `reencryptFileMetadataForFolderChange` internally (no test needed — `reencrypt.ts` already covers this)
- `fileIpnsPrivateKey.fill(0)` called in `finally` even on error

---

### `tests/web-e2e/tests/shared-folder-move.spec.ts` (NEW)

**Analog:** `move-restore-content.spec.ts` (single-account, content-survival assertion via TextEditor) + `writable-shares.spec.ts` (two-account Alice/Bob setup)

**Imports pattern** (from `writable-shares.spec.ts:1-16`):

```typescript
import { test, expect, Browser } from '@playwright/test';
import {
  createWalletTestAccount,
  closeWalletTestAccounts,
  navigateToShared,
  navigateToFiles,
  type WalletTestAccount,
} from '../utils/multi-account-wallet';
import { SharedFileBrowserPage } from '../page-objects/file-browser/shared-file-browser.page';
import { ContextMenuPage } from '../page-objects/file-browser/context-menu.page';
import { TextEditorDialogPage } from '../page-objects/dialogs/text-editor-dialog.page';
// Also need: SharedMoveDialogPage (new page object — mirror MoveDialogPage shape)
```

**Two-account setup pattern** (from `writable-shares.spec.ts:28-54`):

```typescript
test.describe.serial('Shared-folder move (intra-share)', () => {
  let browser: Browser;
  let alice: WalletTestAccount;
  let bob: WalletTestAccount;
  // ... init as in writable-shares.spec.ts
});
```

**Content-survival assertion pattern** (from `move-restore-content.spec.ts:67-77`):

```typescript
// Exercises the real decrypt-on-read path — must go through TextEditor, not just list visibility
async function readContentViaEditor(page, name: string): Promise<string> {
  await fileList.rightClickItem(name);
  await contextMenu.waitForOpen();
  await contextMenu.clickEdit();
  await textEditor.waitForOpen({ timeout: 10_000 });
  await textEditor.waitForContentLoaded({ timeout: 30_000 });
  const content = await textEditor.getContent();
  await textEditor.clickCancel();
  await textEditor.waitForClose();
  return content;
}
```

**Cross-client sync pattern** (from `writable-shares.spec.ts:280` pattern):

```typescript
// After Bob's move, Alice must see the result:
await alice.page.reload({ waitUntil: 'networkidle' });
// Then navigate into the destination subfolder and assert decrypted content
```

**Scenario:**

1. Alice creates a parent folder with one file and one subfolder; shares read-write with Bob.
2. Bob navigates to the shared folder via `navigateToShared`.
3. Bob right-clicks the file → Move → selects subfolder → confirm.
4. Assert file disappears from source (Bob's view).
5. Bob navigates into subfolder → assert file appears → `readContentViaEditor` → assert content matches.
6. `alice.page.reload({waitUntil:'networkidle'})` → Alice navigates into the subfolder → `readContentViaEditor` → assert same content.

## Shared Patterns

### `withOperation` / `requireSharedFolder` / `adoptSharedFolderResult`

**Source:** `packages/sdk/src/client.ts:2045-2100`

**Apply to:** `moveInSharedFolder` + `enumerateSharedSubtree` client methods

```typescript
// All shared write methods follow this shell:
return this.withOperation('<methodName>', async () => {
  const state = this.requireSharedFolder(shareId);
  // ... op ...
  this.adoptSharedFolderResult(shareId, srcResult);  // SOURCE ONLY for move
});
```

### `runWrite` + revocation guard

**Source:** `apps/web/src/hooks/useSharedWriteOps.ts:50-72`

**Apply to:** `moveItemHandler` in `useSharedWriteOps`

```typescript
// Every write handler routes through runWrite — never call SDK directly outside it
await runWrite(async (shareId) => {
  await getSdkClient().<method>(shareId, args);
}, '<Human-readable fail message>');
```

### Buffer clone on FolderState mapping

**Source:** `packages/sdk/src/state/shared-folder-tree.ts` `set()` method (confirmed clones buffers)

**Apply to:** `useFolderNavigation.ts` FolderNode construction after `ensureFolderLoaded`

```typescript
// Always clone SDK-owned Uint8Arrays before storing in React/Zustand state
folderKey: state ? new Uint8Array(state.folderKey) : new Uint8Array(0),
ipnsPrivateKey: state ? new Uint8Array(state.ipnsKeypair.privateKey) : new Uint8Array(0),
```

### `finally` key zeroing

**Source:** `packages/sdk/src/client.ts` `moveItem` (private owner) + `reencrypt.ts:47` contract

**Apply to:** `CipherBoxClient.moveInSharedFolder` client method

```typescript
// Caller (client method) owns zeroing of all temporarily-resolved key material
try {
  // ... op ...
} finally {
  if (fileIpnsPrivateKey) fileIpnsPrivateKey.fill(0);
  destIpnsPrivateKey.fill(0);
  destFolderKey.fill(0);
}
```

### a11y interactive element rules

**Source:** `apps/web/CLAUDE.md`

**Apply to:** `SharedMoveDialog.tsx` folder picker rows

```typescript
// role="button" requires onKeyDown for Enter + Space; :focus-visible styles required
<div
  role="button"
  tabIndex={0}
  onClick={() => setSelected(node.id)}
  onKeyDown={(e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelected(node.id); }
  }}
/>
```

## No Analog Found

All files have close analogs in the codebase. No entries in this section.

## Metadata

**Analog search scope:** `packages/sdk/src/`, `packages/sdk/src/share/`, `apps/web/src/hooks/`, `apps/web/src/components/file-browser/`, `tests/web-e2e/tests/`

**Files scanned:** 12 source files read directly

**Pattern extraction date:** 2026-06-18
