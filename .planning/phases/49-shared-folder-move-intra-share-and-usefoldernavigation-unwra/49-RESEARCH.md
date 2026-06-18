# Phase 49: Shared-folder move (intra-share) and useFolderNavigation unwrap consolidation - Research

**Researched:** 2026-06-18
**Domain:** SDK shared-folder write layer, ECIES key unwrap, IPNS CAS publish, React web hooks
**Confidence:** HIGH

## Summary

Phase 49 adds intra-share file move capability for write-permission share recipients and collapses
the duplicated ECIES unwrap in `useFolderNavigation` onto the SDK. The cross-layer discovery in
CONTEXT.md has been verified against live code. All four open questions are now resolved with
concrete evidence. No new external packages are needed — every primitive (reencrypt, CAS publish,
pure moveItem, loadFolderMetadata) already exists and is reusable verbatim.

The central design challenge is that `sharedFolderTree` holds ONE depth per `shareId`. A
cross-subfolder move needs both source and destination contexts simultaneously. The solution: add
a `CipherBoxClient.moveInSharedFolder` method that accepts explicit source and destination
`SharedWriteContext`-equivalent parameters (resolved by the client from `share_keys` on demand),
mirrors the `moveItem` publish ordering, and emits `sharedFolder:updated` for the SOURCE folder
(which the projection renders), plus a silent in-memory update for the destination (which will be
seeded on next navigation).

**Primary recommendation:** Add `moveInSharedFolder` as a stateless op in `shared-write.ts` and a
client method in `client.ts`, add SDK shared-subtree enumeration, wire a new `SharedMoveDialog`
into the folder-view `ContextMenu`, replace the `useFolderNavigation` unwrap block with
`ensureFolderLoaded`, and add an e2e test mirroring `move-restore-content.spec.ts` with a
two-account setup.

## User Constraints (from CONTEXT.md)

### Locked Decisions

- Intra-share only — move a file between two subfolders within ONE shared folder.
  No cross-share, no share↔private-vault.
- Destination picker spans the ENTIRE shared subtree (not just direct children).
  Forces a new SDK shared-subtree enumeration capability.
- Recipient-side capability — the write-permission recipient performs the move.

### Claude's Discretion

- Op signature for `moveInSharedFolder` (two contexts)
- Collision policy (throw vs auto-rename)
- Whether to drop `@internal` from `ensureFolderLoaded` or expose a dedicated public method

### Deferred Ideas (OUT OF SCOPE)

- Cross-share moves
- Share↔private-vault moves
- Batch/drag move in the shared view (single-item context-menu move only for v1)
- `ensureFolderLoaded` negative-cache / re-walk mitigation

## Phase Requirements

| ID   | Description | Research Support |
| ---- | ----------- | ---------------- |
| REQ-1 | SDK shared-subtree enumeration: lazy DFS from share root, resolving `folderKey` from `share_keys keyType:'folder'` and write-capability from `keyType:'folder-ipns'`, returning `{id,name,ipnsName,writable}` picker nodes | `loadFolderMetadata` (sdk-core) + `share_keys` resolution pattern from `navigateToSubfolder` — both exist and are reusable |
| REQ-2 | SDK `moveInSharedFolder` op + `CipherBoxClient.moveInSharedFolder` client method (explicit source+dest contexts, mirror owner `moveItem` ordering) | `reencryptFileMetadataForFolderChange` confirmed key-agnostic; `moveItem` pure op + `publishWithCas` both verified; `SharedWriteContext` shape confirmed; `adoptSharedFolderResult` dual-emit design resolved |
| REQ-3 | Web hook + UI: `moveItemHandler` in `useSharedWriteOps`, new `SharedMoveDialog` (cannot reuse private MoveDialog which reads `useFolderStore`), wire `onMove` into folder-view `ContextMenu` | `runWrite` pattern and `deleteItemHandler` confirmed; `ContextMenu.onMove` prop at line 34 confirmed; private MoveDialog reads `useFolderStore` line 184 confirmed; folder-view ContextMenu at line 687 confirmed |
| REQ-4 | `useFolderNavigation` consolidation: replace ECIES unwrap+IPNS-resolve+decrypt (lines 241-302) with `ensureFolderLoaded`, preserve 3×/2s retry, clone buffers | `FolderState` fields confirmed (`folderKey`, `ipnsKeypair.privateKey`, `children`, `sequenceNumber`); `FolderNode` fields confirmed; buffer-clone requirement confirmed (SharedFolderTree.set clones for shared, same needed here) |
| REQ-5 | e2e: within-share move mirroring `move-restore-content.spec.ts` + two-account setup from `writable-shares.spec.ts` | Alice/Bob setup pattern confirmed; `TextEditorDialogPage.getContent()` assertion pattern confirmed; `page.reload({waitUntil:'networkidle'})` sync pattern confirmed |

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
| ---------- | ------------ | -------------- | --------- |
| Shared-subtree enumeration (DFS, key unwrap) | SDK (`client.ts`) | — | Key material stays in SDK; avoids re-exposing ECIES primitives to web |
| FileMetadata re-encryption on move | SDK (`reencrypt.ts` + `shared-write.ts`) | — | Crypto boundary; identical to owner `moveItem` path |
| IPNS CAS publish (source + dest) | sdk-core (`publishWithCas` via `updateFolderMetadataAndPublish`) | — | CAS is already the single engine; no second retry loop |
| Write-context resolution from `share_keys` | SDK (`client.ts moveInSharedFolder`) | — | Private key material; same pattern as `navigateToSubfolder` |
| Move state projection (UI refresh) | Web (`sharedFolder:updated` event) | — | Projection already subscribes to this event; no new web state |
| Shared subtree picker UI | Web (`SharedMoveDialog`) | — | New React component; reads from SDK enumeration result |
| Move handler wiring | Web (`useSharedWriteOps` + `SharedFileBrowser`) | — | `runWrite` pattern; wire `onMove` prop in folder-view |
| ECIES unwrap consolidation | SDK (`ensureFolderLoaded`) | Web (retry wrapper) | SDK owns unwrap; web keeps 3×/2s IPNS-propagation retry |
| e2e two-account move assertion | Test (`web-e2e`) | — | Mirrors `move-restore-content.spec.ts` structure |

## Standard Stack

### Core

All primitives are already in the monorepo. No new external packages.

| Primitive | Location | Purpose |
| --------- | -------- | ------- |
| `reencryptFileMetadataForFolderChange` | `packages/sdk/src/reencrypt.ts:49` | Re-seal FileMetadata under dest folderKey — key-agnostic, idempotent |
| `sdkCore.moveItem` | `packages/sdk-core/src/folder/index.ts:328` | Pure source/dest children mutation + name-collision guard |
| `sdkCore.updateFolderMetadataAndPublish` | `packages/sdk-core/src/folder/index.ts` | CAS publish via `publishWithCas` |
| `sdkCore.loadFolderMetadata` | `packages/sdk-core/src/folder/index.ts:73` | IPNS resolve + decrypt for DFS enumeration |
| `adoptSharedFolderResult` | `packages/sdk/src/client.ts:2078` | Write-back + emit pattern (private method) |
| `requireSharedFolder` / `buildSharedWriteContextFromState` | `packages/sdk/src/client.ts:2045/2056` | Standard client write-method plumbing |
| `client.ensureFolderLoaded` | `packages/sdk/src/client.ts:444` | DFS-from-root folder load for `useFolderNavigation` consolidation |

### Package Legitimacy Audit

No external packages are added in this phase.

## Architecture Patterns

### System Architecture Diagram

```
[Bob selects "Move" in SharedFileBrowser ContextMenu (folder-view)]
        |
        v
[SharedMoveDialog opens]
        |
        v (REQ-1)
[client.enumerateSharedSubtree(shareId)]
  --> share_keys API: fetch folder + folder-ipns entries
  --> DFS: loadFolderMetadata for each subfolder reachable from share root
  --> returns [{id, name, ipnsName, writable}] picker nodes
        |
[Bob selects destination folder, clicks "Move"]
        |
        v (REQ-2)
[useSharedWriteOps.moveItemHandler(item, destNode)]
  --> runWrite() --> withRevocationGuard()
  --> client.moveInSharedFolder(shareId, {itemId, srcFolderId, destFolderId})
        |
        v (SDK client)
[client.moveInSharedFolder]
  --> share_keys: resolve src folderKey + ipnsPrivateKey (from sharedFolderTree[shareId])
  --> share_keys: resolve dest folderKey + ipnsPrivateKey (fresh fetch -- not the active depth)
  --> verify folder-ipns key exists on BOTH (write-capability check)
  --> sdkCore.moveItem({sourceChildren, destChildren, childId})
        |
        v (publish DEST first -- crash safety)
  --> sdkCore.updateFolderMetadataAndPublish({dest context})
        |
        v (if file: re-key FileMetadata)
  --> reencryptFileMetadataForFolderChange({fileIpnsPrivateKey from share_keys 'file-ipns', srcFolderKey, destFolderKey})
        |
        v (publish SOURCE -- removal)
  --> sdkCore.updateFolderMetadataAndPublish({source context})
        |
        v (adopt + emit)
  --> adoptSharedFolderResult(shareId, sourceResult)  [active depth -- projection renders]
  --> emit sharedFolder:updated (shareId, sourceIpnsName, sourcePublishedChildren)
  --> in-memory update for dest (future navigation will re-seed from this)
        |
[subscribeSharedFolderProjection applies event -> folderChildrenRef updated -> UI re-renders]
```

### Recommended Project Structure

```
packages/sdk/src/share/
  shared-write.ts          # ADD: moveInSharedFolder stateless op
packages/sdk/src/
  client.ts                # ADD: enumerateSharedSubtree + moveInSharedFolder methods
apps/web/src/hooks/
  useSharedWriteOps.ts     # ADD: moveItemHandler
  useFolderNavigation.ts   # EDIT: replace unwrap block with ensureFolderLoaded + retry wrapper
  shared-folder-projection.ts  # ADD moveInSharedFolder to SharedFolderClient Pick allowlist
apps/web/src/components/file-browser/
  SharedMoveDialog.tsx     # NEW: shared subtree picker dialog
  SharedFileBrowser.tsx    # EDIT: wire onMove into folder-view ContextMenu
tests/web-e2e/tests/
  shared-folder-move.spec.ts   # NEW: two-account move + decrypt-survival e2e
```

### Pattern 1: moveInSharedFolder with dual contexts

The key insight: `sharedFolderTree` holds the SOURCE context (the active depth). The DEST context
must be resolved on demand from `share_keys` inside the client method. The two publish calls
each carry their own `ipnsName`/`ipnsPrivateKey`/`folderKey`/`sequenceNumber`.

```typescript
// packages/sdk/src/share/shared-write.ts (new stateless op)
export async function moveInSharedFolder(params: {
  ctx: SdkContext;
  srcCtx: Pick<SharedWriteContext, 'folderKey' | 'ipnsPrivateKey' | 'ipnsName' | 'sequenceNumber' | 'children'>;
  destCtx: Pick<SharedWriteContext, 'folderKey' | 'ipnsPrivateKey' | 'ipnsName' | 'sequenceNumber' | 'children'>;
  itemId: string;
}): Promise<{
  srcResult: { publishedChildren: FolderChild[]; newSequenceNumber: bigint };
  destResult: { publishedChildren: FolderChild[]; newSequenceNumber: bigint };
}> { ... }
```

```typescript
// packages/sdk/src/client.ts (client method)
async moveInSharedFolder(
  shareId: string,
  args: { itemId: string; srcFolderIpnsName: string; destFolderIpnsName: string; getShareKeysFn: ... }
): Promise<void> {
  return this.withOperation('moveInSharedFolder', async () => {
    // 1. Source context from sharedFolderTree (already loaded -- the active depth)
    const srcState = this.requireSharedFolder(shareId);
    // 2. Dest context: resolve folderKey + ipnsPrivateKey from share_keys
    const destCtx = await resolveDestContext(args);  // fetch+unwrap from share_keys
    // 3. moveInSharedFolder stateless op
    const { srcResult, destResult } = await shareOps.moveInSharedFolder({...});
    // 4. Adopt source (the active depth) -- triggers projection
    this.adoptSharedFolderResult(shareId, srcResult);
    // 5. Update dest in-memory without emitting (not the rendered depth)
    const liveAfter = this.sharedFolderTree.get(shareId);
    if (liveAfter) {
      // dest is NOT the active depth; just persist result for future navigation
      // No emit needed -- the web will re-seed on navigateToSubfolder
    }
  });
}
```

### Pattern 2: Shared-subtree DFS enumeration

```typescript
// packages/sdk/src/client.ts
async enumerateSharedSubtree(
  shareId: string,
  args: { getShareKeysFn: (shareId: string) => Promise<ShareKeyEntry[]>; vaultPrivateKey: Uint8Array }
): Promise<Array<{ id: string; name: string; ipnsName: string; writable: boolean }>> {
  // Start from the loaded share root (sharedFolderTree[shareId])
  // DFS: for each FolderEntry child, check share_keys for keyType:'folder' (read) and 'folder-ipns' (write)
  // Unwrap folderKey, loadFolderMetadata to get that level's children, recurse
  // Return flat list of {id, name, ipnsName, writable}
}
```

### Pattern 3: useFolderNavigation consolidation

```typescript
// BEFORE (lines 241-302 in useFolderNavigation.ts)
const folderKey = await unwrapKey(hexToBytes(folderEntry.folderKeyEncrypted), vaultKeypair.privateKey);
const ipnsPrivateKey = await unwrapKey(hexToBytes(folderEntry.ipnsPrivateKeyEncrypted), vaultKeypair.privateKey);
// ... manual IPNS resolve + retry loop + decrypt

// AFTER
const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 2000;
let state: FolderState | null = null;
for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
  if (latestNavTarget.current !== targetFolderId) return;
  state = await getSdkClient().ensureFolderLoaded(folderEntry.ipnsName);
  if (state) break;
  if (attempt === MAX_RETRIES) break;
  await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
}
// Map FolderState -> FolderNode (clone buffers)
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
};
```

### Anti-Patterns to Avoid

- **Do NOT call `adoptSharedFolderResult` for the destination folder.** It emits `sharedFolder:updated`
  with the destination's `ipnsName`, but the projection only filters by `shareId` — it would overwrite
  the source's rendered children with the destination's children. Only emit for the source (active depth).
- **Do NOT zero `ipnsPrivateKey` inside `moveInSharedFolder` stateless op.** The contract follows
  `reencryptFileMetadataForFolderChange`: the CALLER owns zeroing in a `finally` block.
- **Do NOT rely on `state.ipnsKeypair.publicKey` after `ensureFolderLoaded`** — it is
  `new Uint8Array(0)` for tree-walked folders (verified: client.ts line 495).
- **Do NOT pass `.buffer` on Uint8Array for Blob construction** (apps/web CLAUDE.md rule).
- **Do NOT use TypeScript enums** — use string literals (global CLAUDE.md rule).
- **Do NOT reuse the private `MoveDialog`** — it reads `useFolderStore` (private vault tree, line 4 and 184).

## Resolved Open Questions

### 1. Op signature: TWO contexts

`moveInSharedFolder` takes explicit source and destination context parameters, not a single
`swCtx`. The source context comes from `sharedFolderTree.get(shareId)` (the active depth). The
destination context is resolved by the client method on demand: fetch `share_keys` for the share,
find `keyType:'folder'` entry where `itemId === destFolderId` to unwrap `destFolderKey`, find
`keyType:'folder-ipns'` entry where `itemId === destFolderId` to unwrap `destIpnsPrivateKey`, then
call `loadFolderMetadata({ipnsName: destIpnsName, folderKey: destFolderKey, ctx})` to get the
current `destChildren` and `destSequenceNumber`. [VERIFIED: live code read]

### 2. Does moved file need fresh share_keys entry under dest?

**No.** The file's `share_keys` entries (`keyType:'file'` and `keyType:'file-ipns'`) are keyed by
`itemId` (the file's UUID), not by parent folder. The download path (line 524 of
`useSharedNavigationActions.ts`) resolves the file key by `k.keyType === 'file' && k.itemId === item.id`
— independent of which folder the file is currently listed in. The move only changes the folder
that lists the `FilePointer` and re-seals the `FileMetadata` IPNS record. Existing `share_keys`
remain valid. No re-registration needed. [VERIFIED: live code read]

### 3. Dest folder not the active depth — how to adopt/emit

`adoptSharedFolderResult` is designed for the ACTIVE depth (the single `sharedFolderTree` entry).
The projection filters `sharedFolder:updated` by `shareId` only — not `ipnsName`. If we call
`adoptSharedFolderResult` for the dest, it emits with `live.ipnsName` which is the ACTIVE
depth's `ipnsName` (source), but with the dest's `publishedChildren` — corrupting the rendered
view.

Correct design: call `adoptSharedFolderResult(shareId, srcResult)` only (updates active depth,
triggers correct projection). For the destination: the `sharedFolderTree` stores ONE entry per
`shareId` — the dest result is not persisted there (it will be re-resolved when the user navigates
into the dest). This is acceptable: the dest folder will be re-seeded on `navigateToSubfolder`.
Emit ONE `sharedFolder:updated` event (for the source/active depth). [VERIFIED: live code read]

### 4. Collision policy for shared move

`sdkCore.moveItem` throws `Error('An item with this name already exists in destination')` on a
name collision (verified: `packages/sdk-core/src/folder/index.ts:346`). Use **throw** (same as
private `moveItem`). The error propagates through `runWrite` which calls `p.setError(message)`.
The web will display the error message to the user. Auto-rename is not needed and adds complexity.
[VERIFIED: live code read]

### 5. @internal decision for ensureFolderLoaded

`ensureFolderLoaded` is tagged `@internal` (line 442) but the whole `CipherBoxClient` class is
exported from `packages/sdk/src/index.ts`. The `@internal` tag is documentation convention only —
calling it from `apps/web` is already possible. **Recommendation:** Keep `@internal` and call it
directly. A dedicated `loadFolderForDisplay` public alias adds boilerplate with no functional
difference. The `@internal` tag signals "may change" — acceptable for an intra-monorepo consumer
(web). [VERIFIED: live code read]

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
| ------- | ----------- | ----------- | --- |
| IPNS publish with 409 retry | Custom retry loop | `updateFolderMetadataAndPublish` (routes through `publishWithCas`) | 3-way merge, exponential backoff, 4-attempt cap already implemented |
| FileMetadata re-key | Custom encrypt/publish | `reencryptFileMetadataForFolderChange` | Idempotent; handles partial-retry; already covers both move and restore paths |
| Name collision check | Custom name scan | `sdkCore.moveItem` | Already guards; throws on collision |
| Folder tree walk from DFS | Custom BFS/DFS | `loadFolderMetadata` per node | Handles IPNS resolve + decrypt; no need to re-implement |
| ECIES unwrap in `useFolderNavigation` | Keep hand-rolled version | `client.ensureFolderLoaded` | SDK already does identical unwrap+resolve+decrypt internally |

## Common Pitfalls

### Pitfall 1: Emitting sharedFolder:updated for the wrong ipnsName

**What goes wrong:** If `adoptSharedFolderResult` is called after updating the destination folder
in-memory, the event carries `live.ipnsName` (the active/source depth), but the `publishedChildren`
would be the DESTINATION's children — the web renders the destination's children while still at
the source URL.

**Why it happens:** `adoptSharedFolderResult` reads `live = sharedFolderTree.get(shareId)` which
is always the active depth (source). The projection subscription only filters by `shareId`.

**How to avoid:** Only call `adoptSharedFolderResult(shareId, srcResult)` — the source removal.
The dest result is not adopted into `sharedFolderTree` (will be re-loaded on next navigation).

### Pitfall 2: Zeroing buffers prematurely in the stateless op

**What goes wrong:** If the stateless `moveInSharedFolder` zeroes `destIpnsPrivateKey` in a
`finally`, the caller's key tracking is corrupted.

**Why it happens:** Shared-write convention: callers own zeroing. `reencryptFileMetadataForFolderChange`
explicitly does NOT own the `fileIpnsPrivateKey` (comment at line 47 of reencrypt.ts).

**How to avoid:** The client method owns a `finally` that zeroes dest IPNS key after the op. The
stateless op must NOT zero keys — same contract as all other stateless ops.

### Pitfall 3: Destination sequence out of date after loadFolderMetadata

**What goes wrong:** Between loading the destination's metadata and the actual publish, a 409 can
occur if another writer modified the destination. The CAS engine handles this, but only if the
`sequenceNumber` passed to `updateFolderMetadataAndPublish` was the freshly resolved one.

**Why it happens:** If the sequence is stale (e.g., cached from an earlier navigation), the CAS
detects it via 409 and re-merges. This is fine — `publishWithCas` handles it. Just make sure the
sequence comes from the freshly-resolved `loadFolderMetadata` result, not from a stale web ref.

**How to avoid:** Always derive `destSequenceNumber` from `loadFolderMetadata` result inside the
client method, not from `sharedFolderTree` or any web-side ref.

### Pitfall 4: file-ipns key lookup for re-encryption

**What goes wrong:** `moveInSharedFolder` needs the moved file's `ipnsPrivateKey` to call
`reencryptFileMetadataForFolderChange`. The key is in `share_keys keyType:'file-ipns' itemId=fileId`
(wrapped for recipient), not in `FilePointer.ipnsPrivateKeyEncrypted` (wrapped for owner).

**Why it happens:** Dual-wrapping convention: `FilePointer` keys are owner-wrapped; `share_keys`
are recipient-wrapped. Recipient's vault private key cannot unwrap owner-wrapped keys.

**How to avoid:** The client method must receive a `getFileIpnsKeyFn` callback (same pattern as
`updateSharedFile`) OR resolve the `share_keys file-ipns` entry internally. The web passes the
result of `fetchShareKeys` + ECIES unwrap — mirroring `updateSharedFileHandler` in `useSharedWriteOps.ts`.

### Pitfall 5: SharedFolderClient Pick allowlist not updated

**What goes wrong:** `SharedFolderClient` in `shared-folder-projection.ts` is a `Pick<CipherBoxClient, ...>`
(line 28-38). If `moveInSharedFolder` and `enumerateSharedSubtree` are not added to the pick list,
TypeScript accepts the call but mock-based projection unit tests will fail to typecheck.

**How to avoid:** Add both new methods to the `SharedFolderClient` Pick list in
`apps/web/src/hooks/shared-folder-projection.ts`.

### Pitfall 6: ensureFolderLoaded re-walk negative cache

**What goes wrong:** If a subfolder was just created and its IPNS hasn't propagated, the DFS will
fail to find it (returns null), but will also cache nothing — the next call does the full re-walk.
On the hot nav path this adds latency.

**Why it happens:** `ensureFolderLoaded` has no negative cache. Known issue — deliberately deferred
per CONTEXT.md.

**How to avoid:** DEFER per scope lock. The 3×/2s retry wrapper in web handles the most common
case (just-created folder).

## Runtime State Inventory

Not applicable — this is a greenfield feature phase, not a rename/refactor.

## Code Examples

### Verified: reencryptFileMetadataForFolderChange signature (key-agnostic)

```typescript
// Source: packages/sdk/src/reencrypt.ts:49 [VERIFIED: live code read]
export async function reencryptFileMetadataForFolderChange(params: {
  fileMetaIpnsName: string;
  fileIpnsPrivateKey: Uint8Array;
  sourceFolderKey: Uint8Array;
  destFolderKey: Uint8Array;
  ctx: SdkContext;
}): Promise<void>
// Idempotent: on source-key DECRYPTION_FAILED, probes dest key to detect already-rekeyed partial retry.
// createVersion: false (re-key is not a content change).
// Caller owns zeroing fileIpnsPrivateKey in finally.
```

### Verified: pure moveItem (throws on name collision)

```typescript
// Source: packages/sdk-core/src/folder/index.ts:328 [VERIFIED: live code read]
export function moveItem(params: {
  sourceChildren: FolderChild[];
  destChildren: FolderChild[];
  childId: string;
}): {
  updatedSourceChildren: FolderChild[];
  updatedDestChildren: FolderChild[];
  movedItem: FolderChild;
}
// throws Error('An item with this name already exists in destination') on collision
// throws Error('Item not found') if childId not in sourceChildren
```

### Verified: SharedFolderState shape

```typescript
// Source: packages/sdk/src/types.ts:138 [VERIFIED: live code read]
type SharedFolderState = {
  shareId: string;
  ipnsName: string;
  folderKey: Uint8Array;
  ipnsPrivateKey: Uint8Array;
  sequenceNumber: bigint;
  children: FolderChild[];
  ownerPublicKey: Uint8Array;
  recipientPublicKey: Uint8Array;
  addShareKeysFn: (...) => Promise<void>;
}
```

### Verified: adoptSharedFolderResult (reads live state post-await)

```typescript
// Source: packages/sdk/src/client.ts:2078 [VERIFIED: live code read]
private adoptSharedFolderResult(
  shareId: string,
  result: { publishedChildren: FolderChild[]; newSequenceNumber: bigint }
): void
// Re-reads live state after await; no-ops if share was unloaded mid-flight; emits sharedFolder:updated
```

### Verified: share_keys folder key resolution pattern

```typescript
// Source: apps/web/src/hooks/useSharedNavigationActions.ts:232-238 [VERIFIED: live code read]
const keys = await p.getShareKeys(p.currentShareId);
const keyRecord = keys.find((k) => k.keyType === 'folder' && k.itemId === folderId);
if (!keyRecord) throw new Error('No key available for this subfolder');
const subfolderKey = await unwrapKey(hexToBytes(keyRecord.encryptedKey), auth.vaultKeypair.privateKey);
// folder-ipns:
const ipnsKeyRecord = subKeys.find((k) => k.keyType === 'folder-ipns' && k.itemId === folderId);
// Absence of 'folder-ipns' entry means read-only on that subfolder.
```

### Verified: file key resolution by itemId (independent of parent folder)

```typescript
// Source: apps/web/src/hooks/useSharedNavigationActions.ts:524 [VERIFIED: live code read]
const fileKeyRecord = keys.find((k) => k.keyType === 'file' && k.itemId === item.id);
// Keyed by itemId only -- parent folder is irrelevant. Move does not invalidate this.
```

### Verified: FolderState fields (for ensureFolderLoaded mapping)

```typescript
// Source: packages/sdk/src/types.ts:110 [VERIFIED: live code read]
type FolderState = {
  ipnsName: string;
  folderKey: Uint8Array;
  ipnsKeypair: { publicKey: Uint8Array; privateKey: Uint8Array };
  // NOTE: ipnsKeypair.publicKey === new Uint8Array(0) for tree-walked folders (client.ts:495)
  sequenceNumber: bigint;
  children: FolderChild[];
  metadata: FolderMetadata | null;
  lastLoadedAt: number;
}
```

### Verified: useFolderNavigation current unwrap block (lines to replace)

```typescript
// Source: apps/web/src/hooks/useFolderNavigation.ts:241-302 [VERIFIED: live code read]
// Lines 241-302: manual unwrapKey x2 + resolveIpnsRecord + fetchAndDecryptMetadata
// + 3x/2s retry loop. Replace with ensureFolderLoaded + thin retry wrapper.
// MUST preserve latestNavTarget.current guard on each retry iteration.
```

### Verified: ContextMenu onMove prop and render location

```typescript
// Source: apps/web/src/components/file-browser/ContextMenu.tsx:33-34 [VERIFIED: live code read]
onMove?: () => void;  // optional prop
// Rendered at line 336: {!readOnly && onMove && (...)}
// Folder-view ContextMenu is at SharedFileBrowser.tsx:686-709 -- no onMove prop currently
// List-view ContextMenu is at line 466-479 -- keep readOnly, no onMove
```

### Verified: e2e content assertion pattern

```typescript
// Source: tests/web-e2e/tests/move-restore-content.spec.ts [VERIFIED: live code read]
// uses TextEditorDialogPage.getContent() after textEditor.waitForContentLoaded({timeout:30_000})
// This exercises the real decrypt-on-read path (not list visibility).
// Cross-client sync: alice.page.reload({waitUntil:'networkidle'}) [writable-shares.spec.ts:280]
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
| ------------ | ---------------- | ------------ | ------- |
| Web-side ECIES unwrap in `useFolderNavigation` | SDK `ensureFolderLoaded` | Phase 49 (this phase) | Single source of truth for unwrap; web keeps retry wrapper only |
| No shared-folder move capability | `moveInSharedFolder` with FileMetadata re-key | Phase 49 (this phase) | Recipients with write permission can reorganize files within a share |
| `sharedFolderTree` holds one depth (active only) | Enumeration resolves all depths on demand | Phase 49 (this phase) | Enables anywhere-in-subtree destination picker without pre-loading the whole tree |

## Environment Availability

Step 2.6: SKIPPED — this phase is code/SDK changes with no new external CLI tools or services.
All infrastructure (IPFS, IPNS, postgres, redis) is already required by existing phases.

## Validation Architecture

### Test Framework

| Property | Value |
| -------- | ----- |
| Framework | Vitest (SDK unit), Playwright (web e2e) |
| Config file | `packages/sdk/vitest.config.ts` (SDK), `tests/web-e2e/playwright.config.ts` (e2e) |
| Quick run command | `pnpm --filter @cipherbox/sdk test --run` |
| Full suite command | `pnpm --filter @cipherbox/sdk test --run && pnpm --filter @cipherbox/web test --run` |

### Phase Requirements to Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
| ------ | -------- | --------- | ----------------- | ------------ |
| REQ-1 | SDK enumerates shared subtree DFS, returns writable/read-only nodes | unit | `pnpm --filter @cipherbox/sdk test --run -- enumerate-shared-subtree` | No — Wave 0 |
| REQ-2 | `moveInSharedFolder` publishes DEST first, re-keys FileMetadata, publishes SOURCE | unit | `pnpm --filter @cipherbox/sdk test --run -- move-in-shared-folder` | No — Wave 0 |
| REQ-2 | Name collision throws; missing write key throws | unit | same suite | No — Wave 0 |
| REQ-2 | Re-key is idempotent (source DECRYPTION_FAILED → probes dest) | unit | same suite (reencrypt module already tested but shared path new) | Partial |
| REQ-4 | `ensureFolderLoaded` replaces unwrap block; FolderNode mapping correct | unit | `pnpm --filter @cipherbox/sdk test --run -- ensure-folder-loaded` | Yes (existing) |
| REQ-5 | Bob moves file into subfolder; content decrypts for Bob AND Alice | e2e | `pnpm --filter web-e2e test -- shared-folder-move` (local docker stack) | No — Wave 0 |

### Sampling Rate

- **Per task commit:** `pnpm --filter @cipherbox/sdk test --run`
- **Per wave merge:** `pnpm --filter @cipherbox/sdk test --run && pnpm --filter @cipherbox/web test --run`
- **Phase gate:** Full SDK + web unit suites green before `/gsd-verify-work`. E2E runs only on push to `main` (per memory: `web-e2e` gates main push, not PRs).

### Wave 0 Gaps

- [ ] `packages/sdk/src/__tests__/enumerate-shared-subtree.test.ts` — covers REQ-1 DFS + writable flag
- [ ] `packages/sdk/src/__tests__/move-in-shared-folder.test.ts` — covers REQ-2 publish ordering, re-key, collision, write-capability check
- [ ] `tests/web-e2e/tests/shared-folder-move.spec.ts` — covers REQ-5 two-account move + decrypt-survival

Existing `ensure-folder-loaded.test.ts` covers the `ensureFolderLoaded` SDK behavior; REQ-4 consolidation is tested via the web unit layer (no new SDK test needed for the mapping).

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
| ------------- | ------- | ---------------- |
| V2 Authentication | no | — |
| V3 Session Management | no | — |
| V4 Access Control | yes | Write-capability check on BOTH source and dest via `share_keys keyType:'folder-ipns'` existence |
| V5 Input Validation | yes | `sdkCore.moveItem` guards name collision; `requireSharedFolder` guards load contract |
| V6 Cryptography | yes | ECIES (unwrapKey) for key unwrap; AES-256-GCM via `reencryptFileMetadataForFolderChange` |

### Known Threat Patterns for this Stack

| Pattern | STRIDE | Standard Mitigation |
| ------- | ------ | ------------------- |
| Recipient moves file to folder they lack write access on | Elevation of Privilege | Check `share_keys keyType:'folder-ipns'` exists for dest before publish; throw if absent |
| Orphaned FileMetadata under wrong folderKey after partial failure | Tampering | `reencryptFileMetadataForFolderChange` idempotency — detects partial retry via dest-key probe |
| Stale dest sequence causes spurious 409 cascade | Denial of Service | CAS (`publishWithCas`) handles 409 with 4-attempt exponential backoff; use fresh `loadFolderMetadata` result for sequence |
| Use-after-zero on `client.destroy()` (buffer aliasing) | Information Disclosure | Clone SDK-owned buffers into FolderNode (`new Uint8Array(state.folderKey)`) — same pattern as SharedFolderTree.set() |
| Owner-wrapped `FilePointer.ipnsPrivateKeyEncrypted` used by recipient | Cryptographic Failure | Always resolve file IPNS key from `share_keys keyType:'file-ipns'` (recipient-wrapped), never from `FilePointer` |

## Project Constraints (from CLAUDE.md)

- TypeScript string literals over enums (global + project rule)
- `Uint8Array` for binary data, not strings
- ECIES for key wrapping; AES-256-GCM for content encryption
- Server NEVER has access to plaintext or unencrypted keys
- `clearBytes`/`.fill(0)` sensitive key material in `finally` blocks
- Run `pnpm api:generate` after any API endpoint changes (none expected this phase)
- Commit regenerated API client alongside API changes (none expected)
- No push to `main` — feature branch + PR required
- Conventional commits: `feat(sdk):`, `feat(web):`, etc.
- markdownlint enforced on commit: proper `###` headings, blank lines around code blocks and lists
- Never use `.buffer` on Uint8Array for Blob construction (apps/web CLAUDE.md)
- ARIA roles require matching keyboard handlers; `:focus-visible` styles for interactive elements

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
| - | ----- | ------- | ------------- |
| A1 | The destination folder's current children must be fetched fresh via `loadFolderMetadata` inside the client method (not cached anywhere) | Architecture Patterns | If stale children are used for the dest publish, a name that was just added by another writer would not be caught, causing data loss on the 3-way merge |
| A2 | `enumerateSharedSubtree` lives in `client.ts` (not `shared-write.ts`) because it requires ECIES key unwrap (vault private key), which is SDK-internal | Standard Stack | If placed in stateless `shared-write.ts`, the web would need to pass the vault private key, violating the SDK-owns-crypto boundary |

## Open Questions

1. **Does `getShareKeysFn` need to be passed through to the stateless `moveInSharedFolder` op or resolved in the client method?**
   - What we know: `updateSharedFile` passes `getFileIpnsKeyFn` as a callback to the stateless op. `moveInSharedFolder` also needs the file's IPNS key (for re-encryption) and the dest folder's keys.
   - What's unclear: whether the stateless op should receive pre-resolved keys (simpler, avoids callback threading) or callbacks.
   - Recommendation: Pass pre-resolved raw key bytes to the stateless op. The client method resolves all keys before calling the stateless function, mirroring how `moveItem` in client.ts pre-resolves `source` and `dest` FolderState before calling `sdkCore.moveItem`.

2. **Should `enumerateSharedSubtree` use the recipient's vault private key directly (requires passing it in) or should it accept per-folder folderKey callbacks?**
   - What we know: The DFS must unwrap each subfolder's `folderKey` from `share_keys`, ECIES-unwrapped with the recipient's vault private key.
   - What's unclear: whether the client method holds the vault private key or requires the web to pass it.
   - Recommendation: The client does NOT hold the vault private key — the web must pass it (same pattern as `navigateToSubfolder` which receives `auth.vaultKeypair.privateKey`). Accept `vaultPrivateKey: Uint8Array` as an argument. Zero it never (caller owns).

## Sources

### Primary (HIGH confidence)

- `packages/sdk/src/reencrypt.ts` — signature and idempotency contract verified [VERIFIED: live code read]
- `packages/sdk-core/src/folder/index.ts` — `moveItem` and `loadFolderMetadata` signatures verified [VERIFIED: live code read]
- `packages/sdk-core/src/cas.ts` — `publishWithCas` signature and retry semantics verified [VERIFIED: live code read]
- `packages/sdk/src/share/shared-write.ts` — all 5 existing ops and `SharedWriteContext` shape verified [VERIFIED: live code read]
- `packages/sdk/src/client.ts` — `moveItem`, `requireSharedFolder`, `buildSharedWriteContextFromState`, `adoptSharedFolderResult`, `renameInSharedFolder`, `deleteFromSharedFolder`, `ensureFolderLoaded` all verified [VERIFIED: live code read]
- `packages/sdk/src/state/shared-folder-tree.ts` — `set()` clones key buffers confirmed [VERIFIED: live code read]
- `packages/sdk/src/types.ts` — `FolderState` and `SharedFolderState` shapes verified [VERIFIED: live code read]
- `apps/web/src/hooks/useSharedWriteOps.ts` — `runWrite` + `deleteItemHandler` pattern verified [VERIFIED: live code read]
- `apps/web/src/hooks/useSharedNavigationActions.ts` — `navigateToSubfolder` share_keys resolution + file key lookup by `itemId` verified [VERIFIED: live code read]
- `apps/web/src/hooks/useFolderNavigation.ts` — unwrap block lines 241-302 verified [VERIFIED: live code read]
- `apps/web/src/hooks/shared-folder-projection.ts` — `SharedFolderClient` Pick allowlist and projection subscription pattern verified [VERIFIED: live code read]
- `apps/web/src/components/file-browser/ContextMenu.tsx` — `onMove` prop at line 34 verified [VERIFIED: live code read]
- `apps/web/src/components/file-browser/SharedFileBrowser.tsx` — folder-view ContextMenu at line 687 (no `onMove`) and list-view at line 466 (keep readOnly) verified [VERIFIED: live code read]
- `apps/web/src/components/file-browser/MoveDialog.tsx` — reads `useFolderStore` (cannot be reused for shared) verified [VERIFIED: live code read]

### Secondary (MEDIUM confidence)

- `tests/web-e2e/tests/move-restore-content.spec.ts` — `TextEditorDialogPage.getContent()` assertion pattern [VERIFIED: live code read]
- `tests/web-e2e/tests/writable-shares.spec.ts` — Alice/Bob two-account setup and `page.reload({waitUntil:'networkidle'})` sync pattern [VERIFIED: live code read]

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — all primitives confirmed in live code with exact signatures
- Architecture: HIGH — design decisions derived from verified code behavior (adoption/emit semantics, key resolution paths)
- Pitfalls: HIGH — each pitfall traced to a specific verified code path

**Research date:** 2026-06-18
**Valid until:** 2026-07-18 (stable SDK, no fast-moving deps)
