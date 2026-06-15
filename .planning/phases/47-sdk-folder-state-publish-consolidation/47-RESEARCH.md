# Phase 47: SDK Folder-State and Publish-Path Consolidation - Research

**Researched:** 2026-06-15
**Domain:** TypeScript SDK refactor — sdk-core, sdk, apps/web (no API changes)
**Confidence:** HIGH

---

## Summary

Phase 47 closes four interrelated design debts surfaced by `/simplify` (2026-06-14) and the PR #489 post-mortem. All four are pure TypeScript refactors with no new external dependencies and no API schema changes.

**Req 1 (folder-state ownership):** The web Zustand `useFolderStore` and the SDK client `folderTree` hold duplicate authoritative state. Two web hooks (`useFileOperations.handleUpdateFile` "6b" block and both paths in `useFileVersions`) publish folder metadata directly via sdk-core and write back only to Zustand, leaving `folderTree` stale. `reconcileFolderState` (shipped in PR #489) papers over the race but cannot close it — a sub-second window survives between the fire-and-forget publish landing and the `.then` updating the store sequence. The fix is to route these two hooks through new `CipherBoxClient` methods that own the full publish+bookkeeping+`folder:updated` cycle, making `useFolderStore` a pure projection of `folder:updated` events for `children`/`sequenceNumber`.

**Req 2 (publishWithCas):** `updateFolderMetadataAndPublish` (folder/index.ts) and `updateFileMetadata` (file/index.ts) each contain a bespoke 409-retry skeleton. The folder path runs 4 attempts with exponential backoff+jitter; the file path runs 2 attempts with no backoff. They have already drifted. Extracting a single `publishWithCas` helper in sdk-core unifies retry/backoff logic.

**Req 3 (baseChildren encapsulation):** Every `updateFolderMetadataAndPublish` caller must manually snapshot `const baseChildren = [...folder.children]` before mutation and adopt `folder.children = publishedChildren` after. ~14 call sites do this by hand; `useFileVersions.ts` calls it without `baseChildren` (union-fallback warning path fires today). A stateful wrapper encapsulating the snapshot ceremony eliminates the foot-gun by construction.

**Req 4 (prunedCids unpin):** `updateSharedFile` (shared-write.ts:464) calls `updateFileMetadata` with `await` but discards the return entirely, dropping `prunedCids` with a comment "pre-existing Phase-42 deferred leak". The owner path (`useFileOperations.handleUpdateFile`) already unpins via `apps/web/src/lib/api/ipfs.ts:unpinFromIpfs`. The fix is mirroring that unpin call in `updateSharedFile`, after confirming the unpin authority model.

**Primary recommendation:** Tackle in dependency order: Req 2 (publishWithCas in sdk-core) → Req 3 (baseChildren wrapper using publishWithCas) → Req 4 (unpin in updateSharedFile) → Req 1 (new client methods + folder:updated projection). Each step is independently testable.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|---|---|---|---|
| CAS publish + retry | sdk-core | — | Stateless; no store access; consumed by both sdk and web |
| Folder children bookkeeping | sdk (CipherBoxClient) | — | FolderTree is stateful, lives in sdk |
| folder:updated emission | sdk (CipherBoxClient) | — | Client owns the authoritative sequence post-publish |
| UI projection (children render) | apps/web (useFolderStore) | — | Zustand is the React rendering layer |
| Unpin pruned CIDs | sdk-core (unpinFromIpfs ctx) / apps/web (unpinFromIpfs relay) | — | Two different unpin authorities — see Req 4 |
| File IPNS private key resolution | apps/web services | — | Lazy HKDF migration logic stays in web |

---

## Standard Stack

No new external packages. This phase modifies existing code only.

| Package | Role | Notes |
|---|---|---|
| `@cipherbox/sdk-core` | New `publishWithCas` helper + `updateFolderChildren` wrapper | Pure TypeScript, vitest tests |
| `@cipherbox/sdk` | New client methods: `replaceFile`, `restoreFileVersion`, `deleteFileVersion` | Extends CipherBoxClient |
| `apps/web` | Remove bypass publish calls; subscribe to folder:updated | Thin hooks only |

**Build order (cross-package dist staleness):** sdk-core → sdk → web. After any sdk-core public-API change, run `pnpm --filter @cipherbox/sdk-core build` and `pnpm --filter @cipherbox/sdk build` before web typechecks, or tsc will fail against stale dist files.

---

## Package Legitimacy Audit

No new external packages. Section not applicable.

---

## Architecture Patterns

### System Architecture Diagram

```
useFileOperations.handleUpdateFile
  └─ [NEW] client.replaceFile(parentId, fileData)
       ├─ updateFileMetadata() (file IPNS publish, CAS)
       ├─ [NEW] updateFolderChildren({ folder, nextChildren, ctx })
       │    └─ publishWithCas({ ..., merge: mergeChildren })
       └─ emits folder:updated
            └─ useFolderStore.subscribeToSdk handler
                 └─ updateFolderChildren + updateFolderSequence

useFileVersions.handleRestoreVersion / handleDeleteVersion
  └─ [NEW] client.restoreFileVersion() / client.deleteFileVersion()
       ├─ restoreVersion() / deleteVersion() service fns
       ├─ replaceFileInFolder() (file IPNS publish only)
       ├─ [conditional] updateFolderChildren() for lazy IPNS key migration
       └─ emits folder:updated
```

```
publishWithCas (new, sdk-core)
  for attempt in 0..maxAttempts:
    encrypt + upload → CID
    createAndPublishIpnsRecord(CAS)
    if success → return { cid, newSeq, publishedData }
    if 409:
      re-resolve IPNS
      fetch + decrypt remote
      mergeCallback(base, local, remote) → merged
      backoff
  throw ConflictError
```

### Recommended Project Structure

The phase does not restructure packages. Files added or modified:

```
packages/sdk-core/src/
  folder/index.ts          # updateFolderMetadataAndPublish delegates to publishWithCas
  file/index.ts            # updateFileMetadata delegates to publishWithCas
  cas.ts                   # NEW: publishWithCas<T> generic helper
  __tests__/cas.test.ts    # NEW: publishWithCas unit tests

packages/sdk/src/
  client.ts                # NEW: replaceFile(), restoreFileVersion(), deleteFileVersion()
  __tests__/client-extended.test.ts  # extend existing tests or add client-file-ops.test.ts

apps/web/src/
  hooks/useFileOperations.ts    # handleUpdateFile "6b" block → client.replaceFile()
  hooks/useFileVersions.ts      # → client.restoreFileVersion(), client.deleteFileVersion()
  lib/sdk-provider.ts           # reconcileFolderState call in ensureFolderRegistered removed
```

### Pattern 1: publishWithCas Generic Helper

**What:** A generic function in sdk-core that owns the resolve→encrypt→upload→CAS→409→merge→retry→ConflictError skeleton. The domain-specific merge logic is injected as a callback.

**Proposed signature (for planner):**
```typescript
// packages/sdk-core/src/cas.ts
export async function publishWithCas<TData>(params: {
  ipnsName: string;
  ipnsPrivateKey: Uint8Array;
  ipnsPublicKey?: Uint8Array;
  sequenceNumber: bigint;
  ctx: SdkContext;
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
  maxAttempts: number;       // folder: 4, file: 2 (intentional, not accidental)
  backoff: boolean;          // folder: true, file: false — confirm deliberately
  /** Encode local state → IPFS bytes and return CID */
  encodeAndUpload: (local: TData) => Promise<string>;
  /** Decode remote IPFS bytes → domain state */
  decodeRemote: (cid: string) => Promise<TData>;
  /** Three-way merge: (base, local, remote) → merged */
  merge: (base: TData, local: TData, remote: TData) => { merged: TData; prunedCids?: string[] };
  /** Initial local data (pre-first-attempt) */
  localData: TData;
  /** Base snapshot for three-way merge (undefined triggers union fallback in folder path) */
  baseData?: TData;
}): Promise<{ cid: string; newSequenceNumber: bigint; publishedData: TData; prunedCids: string[] }>
```

**Open question on backoff:** The 4 vs 2 attempt difference and backoff vs no-backoff were noted as "accidental" in the todo. The planner should decide the correct unified values before coding. The research suggests 4 attempts + backoff is correct for both paths (file conflicts are equally deserving of retry), but this is a discretionary choice.

### Pattern 2: updateFolderChildren Stateful Wrapper

**What:** A `CipherBoxClient` private method (or thin sdk-core function) that captures the base snapshot, mutates, publishes, and adopts `publishedChildren`.

**Current ceremony at each call site (14 times):**
```typescript
// Step 1: snapshot before mutation
const baseChildren = [...folder.children];
// Step 2: mutate
const updatedChildren = [...folder.children, newItem];
// Step 3: publish
const { newSequenceNumber, publishedChildren } = await sdkCore.updateFolderMetadataAndPublish({
  children: updatedChildren,
  baseChildren,
  ...
});
// Step 4: adopt
folder.children = publishedChildren;
folder.sequenceNumber = newSequenceNumber;
```

**After encapsulation (caller supplies only the mutation):**
```typescript
// sdk-core helper OR client method
await updateFolderChildren({
  folder,          // FolderState — base is captured internally
  nextChildren,    // caller provides post-mutation array
  ctx,
  // ... keys passed from folder
});
// folder.children and folder.sequenceNumber already updated
```

### Anti-Patterns to Avoid

- **Updating Zustand directly from mutation code after Req 1:** `store.updateFolderChildren(...)` and `store.updateFolderSequence(...)` must NOT be called from `useFileOperations` or `useFileVersions` for folder state — only the `folder:updated` event handler in `subscribeToSdk` should write these fields.
- **Calling reconcileFolderState after Req 1:** Once the bypass paths are removed, `reconcileFolderState` is dead code and calling it is a logic error. DELETE the call in `ensureFolderRegistered` and the method itself.
- **Returning `updatedChildren` alongside `publishedChildren` from shared-write:** Callers that use `updatedChildren` instead of `publishedChildren` get the stale pre-merge set. After Req 3, drop `updatedChildren` from all 4 shared-write function return types.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---|---|---|---|
| 409 detection | Custom HTTP error inspector | `is409()` from `sdk-core/errors.ts` | Already exists, covers both `.status` and `.response.status` |
| ConflictError throw | Custom throw | `ConflictError` from `sdk-core/errors.ts` | Already exists with `ipnsName`, `attempts`, `lastRemoteSeq` fields |
| Exponential backoff | Custom timer | `retryDelayMs(attempt)` already in `folder/index.ts` | Move into `publishWithCas`; don't duplicate |
| Key zeroing | Custom buffer zero | `clearBytes` from `@cipherbox/crypto` or `.fill(0)` on Uint8Array | Consistent pattern throughout codebase |
| Unpin API call | Direct axios | `unpinFromIpfs(ctx, cid)` from `@cipherbox/sdk-core` OR `unpinFromIpfs(cid)` from `apps/web/src/lib/api/ipfs.ts` | Two different authorities — see Req 4 analysis |

---

## Domain A: sdk-core CAS Retry Loops (Req 2)

### updateFolderMetadataAndPublish — Current State

**File:** `packages/sdk-core/src/folder/index.ts:186`

**Signature:**
```typescript
export async function updateFolderMetadataAndPublish(params: {
  children: FolderChild[];
  baseChildren?: FolderChild[];       // optional — triggers union-fallback if absent
  folderKey: Uint8Array;
  ipnsPrivateKey: Uint8Array;
  ipnsPublicKey?: Uint8Array;
  ipnsName: string;
  sequenceNumber: bigint;
  ctx: SdkContext;
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
}): Promise<{ cid: string; newSequenceNumber: bigint; publishedChildren: FolderChild[] }>
```

**Loop skeleton (lines 205–274):**
- 4 attempts (`for (let attempt = 0; attempt < 4; attempt++)`)
- Per attempt: encrypt metadata → `addToIpfs` → `createAndPublishIpnsRecord` with `expectedSequenceNumber: currentSeq.toString()`
- On 409 (`is409(err)`): re-resolve via `resolveIpnsRecord`, re-fetch + decrypt via `fetchAndDecryptMetadata`
- Three-way merge via `mergeChildren(baseChildren, currentLocalChildren, remote.children)` (line 248)
- Union fallback + `console.warn` when `baseChildren` is `undefined` (line 254–260)
- After final attempt: `throw new ConflictError(params.ipnsName, 4, lastRemoteSeq)` (line 264)
- Between attempts: `await new Promise(r => setTimeout(r, retryDelayMs(attempt)))` — exponential backoff with ±50% jitter, base 100ms, cap 1500ms (lines 41–43, 269)
- **Returns:** `{ cid, newSequenceNumber: newSeq, publishedChildren: currentLocalChildren }`

### updateFileMetadata — Current State

**File:** `packages/sdk-core/src/file/index.ts:225`

**Signature:**
```typescript
export async function updateFileMetadata(params: {
  fileIpnsPrivateKey: Uint8Array;
  fileMetaIpnsName: string;
  folderKey: Uint8Array;
  currentMetadata: FileMetadata;
  updates: Partial<Pick<FileMetadata, 'cid' | 'fileKeyEncrypted' | 'fileIv' | 'size' | 'encryptionMode'>>;
  createVersion: boolean;
  maxVersionsPerFile?: number;
  ctx: SdkContext;
}): Promise<{
  ipnsName: string;
  metadataCid: string;
  newSequenceNumber: bigint;
  prunedCids: string[];
}>
```

**Structure (lines 276–400):**
- Concurrent pre-resolve + upload (line 276): `Promise.all([resolveIpnsRecord, encryptAndUpload])`
- 2 attempts — hand-unrolled nested try/catch (not a loop)
- Attempt 1 (line 291): `createAndPublishIpnsRecord` with `expectedSequenceNumber: currentSeq.toString()`
- On 409: re-resolve, `fetchAndDecryptFileMetadata`, latest-wins by `modifiedAt` (`>=` prefers local on tie)
- Loser's content → `VersionEntry` (loser-as-version pattern, line 334)
- `mergeVersions(winner.versions ++ loserAsVersion, loser.versions, maxVersions)` (line 347)
- CR-02 reference-filter: CIDs resurrected into `mergedMetadata.versions` are removed from `prunedCids` (lines 364–368)
- Re-upload merged metadata, Attempt 2 (line 374)
- If Attempt 2 → 409: `throw new ConflictError(fileMetaIpnsName, 2, currentSeq)` (line 391)
- **`finally` block:** `params.fileIpnsPrivateKey.fill(0)` on all exit paths (line 398)
- **Returns:** `{ ipnsName, metadataCid, newSequenceNumber, prunedCids }`

### Common Skeleton vs Divergences

| Aspect | updateFolderMetadataAndPublish | updateFileMetadata |
|---|---|---|
| Attempts | 4 (loop) | 2 (unrolled) |
| Backoff | Yes (exponential + jitter) | No |
| Re-resolve on 409 | `resolveIpnsRecord` | `resolveIpnsRecord` |
| Remote fetch | `fetchAndDecryptMetadata` | `fetchAndDecryptFileMetadata` |
| Merge callback | `mergeChildren(base, local, remote)` | `mergeVersions(winner.v ++ loserAsVersion, loser.v, max)` |
| prunedCids output | None | Yes — CR-02 filtered |
| Key zeroing | None (caller's keys) | `fileIpnsPrivateKey.fill(0)` in finally |
| Pre-attempt optimization | None | Concurrent resolve + upload |

---

## Domain B: Folder Child-Bookkeeping Call Sites (Req 3)

### All updateFolderMetadataAndPublish Call Sites (Production Code Only)

**packages/sdk/src/client.ts:**
| Line | Method | Snapshots baseChildren? | Adopts publishedChildren? |
|---|---|---|---|
| 451 | `createFolder` (parent publish) | Yes — `const baseChildren = [...parent.children]` (line 447) | Yes — `parent.children = publishedChildren` (line 464) |
| 470 | `createFolder` (new subfolder empty publish) | Yes — `baseChildren: []` hardcoded | N/A (children always []) |
| 539 | `renameItem` | Yes — `const baseChildren = [...folder.children]` (line 532) | Yes — `folder.children = publishedChildren` (line 552) |
| 595 | `moveItem` (dest) | Yes — `const baseDestChildren = [...dest.children]` (line 586) | Yes — `dest.children = destResult.publishedChildren` (line 620) |
| 606 | `moveItem` (source) | Yes — `const baseSourceChildren = [...source.children]` (line 587) | Yes — `source.children = sourceResult.publishedChildren` (line 619) |
| 665 | `deleteItem` | Yes — `const baseChildren = [...folder.children]` (line 659) | Yes — `folder.children = publishedChildren` (line 680) |
| 778 | `uploadFile` | Yes — `const baseChildren = [...folder.children]` (line 764) | Yes — `folder.children = publishedChildren` (line 831) |
| 1045 | `uploadFiles` | Yes — `const baseChildren = [...initialChildren]` (line 1006) | Yes — `folder.children = publishedChildren` (line 1093) |

**packages/sdk/src/bin/index.ts:**
| Line | Function | Snapshots baseChildren? | Adopts publishedChildren? |
|---|---|---|---|
| 243 | `addToBin` | Yes — `const baseChildren = [...folder.children]` (line 236) | Yes — `folder.children = publishedChildren` (line 253) |
| 342 | `restoreFromBin` | Yes — `const baseChildren = [...targetFolder.children]` (line 338) | Yes — `targetFolder.children = publishedChildren` (line 353) |

**packages/sdk/src/share/shared-write.ts:**
| Line | Function | Snapshots baseChildren? | Adopts publishedChildren? | Returns updatedChildren? |
|---|---|---|---|---|
| 202 | `uploadToSharedFolder` | Yes — `baseChildren: swCtx.children` | No (stateless, returns result) | Yes — `updatedChildren` in return + `publishedChildren` |
| 299 | `createSharedSubfolder` | Yes — `baseChildren: swCtx.children` | No (stateless) | Yes — `updatedChildren` + `publishedChildren` |
| 358 | `renameInSharedFolder` | Yes — `baseChildren: swCtx.children` | No (stateless) | Yes — `updatedChildren` + `publishedChildren` |
| 390 | `deleteFromSharedFolder` | Yes — `baseChildren: swCtx.children` | No (stateless) | Yes — `updatedChildren` + `publishedChildren` |

**apps/web/src/hooks/useFileVersions.ts:**
| Line | Usage | Snapshots baseChildren? | Adopts publishedChildren? |
|---|---|---|---|
| 130 | `handleRestoreVersion` lazy migration | Yes — `baseChildren: parentFolder.children` | Yes — in `.then()` (line 140–141) |
| 264 | `handleDeleteVersion` lazy migration | Yes — `baseChildren: parentFolder.children` | Yes — in `.then()` (line 273–275) |

**apps/web/src/hooks/useFileOperations.ts:**
| Line | Usage | Snapshots baseChildren? | Adopts publishedChildren? |
|---|---|---|---|
| 458 | `handleUpdateFile` "6b" folder republish | Yes — `baseChildren: parentFolder.children` (line 460) | Yes — in `.then()` (lines 468–469) |

**Total production call sites: 14** (8 client.ts + 2 bin/index.ts + 4 shared-write.ts + 2 useFileVersions.ts + 1 useFileOperations.ts = 17 found; 3 are in web hooks being REPLACED by Req 1)

**Risk flags:**
- The `useFileVersions` lazy migration paths (lines 130, 264) have `baseChildren: parentFolder.children` — but `parentFolder.children` is stale (captured before any store subscription update). This is the exact bug described in the todo. The SDK client method will capture the base internally from `folderTree.get()` at the moment of call, which is always correct.
- `shared-write.ts` all 4 functions return both `updatedChildren` (pre-merge stale set) AND `publishedChildren` (correct). The calling web hook `useSharedWriteOps.ts` already correctly consumes `publishedChildren` (lines 144, 146, 191, 193, 238, 240, 348, 350). After Req 3, `updatedChildren` can be dropped from return shapes.

---

## Domain C: Folder-State Ownership Web/SDK Boundary (Req 1)

### CipherBoxClient — Relevant State and Methods

**File:** `packages/sdk/src/client.ts`

**`folderTree: FolderTree` (line 49):** In-memory map of `ipnsName → FolderState`. `FolderState` holds `folderKey`, `ipnsKeypair`, `children`, `sequenceNumber`, `lastLoadedAt`. Mutated by every client folder/file method.

**`registerFolder(...)` (line 282):** Bridge method — populates folderTree from externally-loaded data (navigation hook calls it). Comment: "bridge method for gradual SDK adoption — eventually all folder loading should go through client.loadFolder()."

**`reconcileFolderState(...)` (line 328):** Adopts newer children+sequenceNumber from the store if strictly higher seq. Added in PR #489 as band-aid. To be DELETED by Req 1.

**`folder:updated` emission:** Emitted in `createFolder` (line 487), `renameItem` (line 558), `moveItem` (lines 625, 634), `deleteItem` (line 686), `uploadFile` (line 843), `uploadFiles` (line 1108), `deleteToBin` (line 1271), `restoreFromBin` (line 1305). NOT emitted in any web hook bypass paths — this is the gap to close.

**Existing SDK-routed mutation pattern to mirror for new methods:**
1. `const folder = this.folderTree.get(ipnsName)` — throws if not loaded
2. Snapshot `baseChildren`
3. Call sdk-core pure op or updateFolderMetadataAndPublish
4. `folder.children = publishedChildren; folder.sequenceNumber = newSequenceNumber`
5. `this.folderTree.set(ipnsName, folder)`
6. `this.emitter.emit({ type: 'folder:updated', ... })`
7. Wrap in `withOperation(name, fn)` for telemetry

### ensureFolderRegistered (sdk-provider.ts)

**File:** `apps/web/src/lib/sdk-provider.ts:96`

Called before every SDK-routed mutation in `useFolderMutations` (lines 114, 171, 217, 218, 301, 302, 346, 396, 425) and `useDropUpload` (line 109). Currently:
1. If `hasFolder(ipnsName)`: call `client.reconcileFolderState(...)` — THIS CALL IS DELETED after Req 1
2. Else: call `client.registerFolder(...)` with folderNode data

After Req 1: just `if (!client.hasFolder(folder.ipnsName)) { client.registerFolder(...) }`. No reconcile.

### useFolderStore — Store Shape Analysis

**File:** `apps/web/src/stores/folder.store.ts`

**UI/navigation fields (safe to remain in Zustand, not affected by Req 1):**
- `currentFolderId: string | null`
- `breadcrumbs: Breadcrumb[]`
- `pendingPublishes: Set<string>`
- `isLoaded`, `isLoading` (on FolderNode)
- `parentId: string | null` (on FolderNode)
- `name: string` (on FolderNode)

**Duplicate authoritative state (must become projection-only after Req 1):**
- `folders[id].children: FolderChild[]`
- `folders[id].sequenceNumber: bigint`

**Actions that write children/sequenceNumber from web mutation code (to be REMOVED from call sites, not from store):**
- `updateFolderChildren(folderId, children)` — line 92 (store action itself stays for the subscription handler to call)
- `updateFolderSequence(folderId, sequenceNumber)` — line 105

**Remaining direct `updateFolderChildren`/`updateFolderSequence` call sites AFTER Req 1 (legitimate, not bypass):**
- `apps/web/src/components/file-browser/useFileBrowserActions.ts:126–127` — root folder re-sync on hard refresh (not a mutation)
- `apps/web/src/hooks/folder-helpers.ts:30–31` — `resyncFolder` helper (re-read from IPNS, not bypass publish)
- `apps/web/src/hooks/useFileOperations.ts:136–137` — handleAddFile (file upload, NOT folder publish; this path uses SDK client's `addFileToFolder` batch-publish — THIS IS NOT BYPASS, the SDK already emits folder:updated through uploadFile)

Wait — `handleAddFile` calls `addFileToFolder` from sdk-core directly (not `client.uploadFile`). This is ANOTHER bypass path. However, it does NOT trigger a folder metadata re-publish (it uses the batch-publish path that publishes file+folder in one atomic call). The store update at lines 136–137 is correct sequencing. This path does NOT go through the client and does NOT cause folderTree desync because there is no subsequent file-only IPNS publish that advances the store past the client. It is OUT OF SCOPE for Req 1 per the requirement text ("file replace" and "version edits" only).

### `subscribeToSdk` — Existing Projection Handler

**File:** `apps/web/src/stores/folder.store.ts:200`

Already implemented. Handles `folder:loaded` and `folder:updated` events by reverse-looking up the store `id` from `event.ipnsName` and calling `updateFolderChildren` + `updateFolderSequence`. This subscription is already wired — the missing piece is that the two web bypass paths don't emit `folder:updated`, so the handler never fires for them. No new subscription infrastructure needed for Req 1.

### New Client Methods Needed (Req 1)

Three new methods on `CipherBoxClient`:

1. **`replaceFile(parentIpnsName: string, fileId: string, fileData: { ... }): Promise<{ prunedCids: string[] }>`**
   - Mirrors `handleUpdateFile` (useFileOperations.ts) steps 2–6b
   - Calls `updateFileMetadata` (sdk-core), then `updateFolderMetadataAndPublish` (for the "6b" folder touch with modifiedAt bump on FilePointer)
   - Emits `folder:updated`
   - Returns `prunedCids` so caller can unpin

2. **`restoreFileVersion(parentIpnsName: string, fileId: string, versionIndex: number): Promise<{ prunedCids: string[] }>`**
   - Mirrors `handleRestoreVersion`
   - Calls `restoreVersion` service, `replaceFileInFolder`, optional lazy-migration `updateFolderMetadataAndPublish`
   - Emits `folder:updated`

3. **`deleteFileVersion(parentIpnsName: string, fileId: string, versionIndex: number): Promise<{ deletedCid: string }>`**
   - Mirrors `handleDeleteVersion`
   - Calls `deleteVersion` service, `replaceFileInFolder`, optional lazy-migration `updateFolderMetadataAndPublish`
   - Emits `folder:updated`

**Problem:** `restoreVersion` and `deleteVersion` service functions live in `apps/web/src/services/file-metadata.service.ts` and import web-tier auth state. The client cannot import from apps/web. Options:
- Move `restoreVersion`/`deleteVersion` to sdk-core (they are stateless — they take `fileIpnsPrivateKey`, `currentMetadata`, `versionIndex` and return an IPNS record)
- OR accept explicit `fileIpnsPrivateKey` and `currentMetadata` as params on the client methods, with the web hooks responsible for key resolution before calling the client

The second option is safer (avoids moving web service logic into sdk-core): client methods accept pre-resolved keys and metadata; web hooks do `getFileIpnsPrivateKey(...)` then call `client.restoreFileVersion(parentIpnsName, fileId, versionIndex, { fileIpnsPrivateKey, currentMetadata })`. This matches the existing pattern where `client.uploadFile` accepts raw data and the web layer calls the client.

---

## Domain D: prunedCids Pin Leak (Req 4)

### updateSharedFile — The Leak

**File:** `packages/sdk/src/share/shared-write.ts:416`

At line 464:
```typescript
await updateFileMetadata({
  fileIpnsPrivateKey: ipnsPrivKey,
  fileMetaIpnsName: params.filePointer.fileMetaIpnsName,
  // ...
  createVersion: false,
  ctx: params.ctx,
});
// Note: batchPublishIpnsRecords for the file record was here pre-Plan-03.
// updateFileMetadata now publishes internally with CAS; the separate publish
// has been removed to avoid double-publish. prunedCids from version overflow
// are dropped here (pre-existing Phase-42 deferred leak — not regressed).
```

The `await` discards the `Promise<{ ipnsName, metadataCid, newSequenceNumber, prunedCids }>` return. `prunedCids` is never consumed.

### The Owner Path to Mirror

**File:** `apps/web/src/hooks/useFileOperations.ts:506–511`
```typescript
// 9. Only unpin CIDs of pruned versions (excess beyond max 10)
for (const prunedCid of prunedCids) {
  unpinFromIpfs(prunedCid).catch((err) =>
    logger.warn('[FileOps] Unpin pruned CID failed:', err)
  );
}
```

`unpinFromIpfs` here is `apps/web/src/lib/api/ipfs.ts:unpinFromIpfs(cid: string)` — a thin wrapper around `ipfsControllerUnpin({ cid })` using the generated API client. This calls `DELETE /api/ipfs/:cid`.

The SDK-core equivalent is `sdkCore.unpinFromIpfs(ctx, cid)` (`packages/sdk-core/src/ipfs/index.ts:57`) which also calls the same backend endpoint. `updateSharedFile` already has `params.ctx: SdkContext`, so `sdkCore.unpinFromIpfs(params.ctx, cid)` is directly usable.

### Unpin Authority Check (Phase 42 Context)

Phase 42 added ownership check + cross-user refcount on the API `DELETE /api/ipfs/:cid` endpoint. The server-side guard verifies that the calling user owns the CID (recorded in `pinned_cids` table) before decrementing the refcount and unpinning. A share RECIPIENT wrote the new file version content to IPFS (via `addToIpfs` in `updateSharedFile` — line 443). The CID of the new content was pinned by the recipient's request. The `prunedCids` are old version CIDs previously pinned by the recipient (or possibly the owner). [ASSUMED] — The pinned_cids table records which user made the pin request; if the original content was pinned by the owner and the shared file was later updated by the recipient, the recipient does NOT own the old owner-pinned CID. Calling unpin would fail with a server 403. The correct fix is:
- Destructure `prunedCids` from `updateFileMetadata` return
- Attempt `unpinFromIpfs` fire-and-forget for each, catching errors silently (same pattern as owner path)
- A 403 from the server is caught and logged, not propagated — safe to attempt

This is the same pattern as the owner path: fire-and-forget with catch. The server guards prevent actual cross-user unpins from succeeding. So the fix is safe: add `const { prunedCids } = await updateFileMetadata(...)` and loop over them with fire-and-forget `unpinFromIpfs`.

Note: `updateSharedFile` has `params.ctx: SdkContext`, so use `sdkCore.unpinFromIpfs(params.ctx, cid)` — NOT `apps/web/src/lib/api/ipfs.ts:unpinFromIpfs`, since shared-write.ts is in `packages/sdk` (no browser/web dep).

---

## Common Pitfalls

### Pitfall 1: Fire-and-Forget Race in "6b" Folder Republish

**What goes wrong:** `handleUpdateFile` publishes the folder with a fire-and-forget `.then`. The store's `sequenceNumber` is updated synchronously (line 452: `store.updateFolderChildren`), but the SDK `folderTree` is NOT updated. If a `deleteToBin` fires before the `.then` completes, `ensureFolderRegistered` runs `reconcileFolderState` — but the store sequence hasn't advanced yet (the `.then` hasn't run), so folderTree is still stale. Residual window survives even with `reconcileFolderState`.

**How to avoid:** Routing through `client.replaceFile()` eliminates this: the client updates folderTree synchronously after the awaited publish, emits `folder:updated`, and the store handler updates Zustand. No race.

### Pitfall 2: useFileVersions Lazy Migration Sequence Number Is Stale

**What goes wrong:** `handleRestoreVersion` and `handleDeleteVersion` call `updateFolderMetadataAndPublish` with `sequenceNumber: parentFolder.sequenceNumber`. But `parentFolder` was read at the start of the hook invocation — it may be stale if another operation advanced the sequence concurrently. The lazy migration write uses `parentFolder.children` as both the base and the new children (it only changes one FilePointer's `ipnsPrivateKeyEncrypted`). The 409 CAS handles this, but the base snapshot is wrong if the store was not refreshed.

**How to avoid:** New client method reads sequence from `folderTree.get()` (SDK's authoritative state) at publish time, not from a stale hook-scope capture.

### Pitfall 3: Dropping updatedChildren Instead of publishedChildren in Shared Context

**What goes wrong:** `shared-write.ts` returns `{ updatedChildren, publishedChildren }`. `updatedChildren` is the local-intent set BEFORE CAS merge. `publishedChildren` is the actual published state. The `useSharedWriteOps.ts` hook correctly uses `publishedChildren` today, but any new call site that uses `updatedChildren` will silently drop remote concurrent changes.

**How to avoid:** Drop `updatedChildren` from shared-write return types after Req 3 so no call site can accidentally use it.

### Pitfall 4: subscribeToSdk ipnsName Reverse Lookup Fails for Root

**What goes wrong:** `subscribeToSdk` does `Object.values(folders).find(f => f.ipnsName === event.ipnsName)`. The root folder has `id = 'root'` and its own IPNS name. If `folder:updated` emits with the root folder's IPNS name, the lookup works — but only if the root folder is in `folders`. Root is loaded differently via `useVaultStore` and keyed as 'root' in the store. Verify the root folder is registered in `folders` before the subscription handler can match it.

**How to avoid:** Confirm root folder registration flow in `useFileBrowserActions.ts` (line 126–127 already writes root, so it should be in `folders`) — this is likely already fine but must be tested.

### Pitfall 5: Mocking updateFolderMetadataAndPublish After publishWithCas Refactor

**What goes wrong:** Existing sdk tests mock `sdkCore.updateFolderMetadataAndPublish` directly. After Req 2 makes it a thin wrapper around `publishWithCas`, tests that mock only `updateFolderMetadataAndPublish` still work IF the wrapper is not inlined. But if the test structure changes, all ~50 mock sites in `packages/sdk/src/__tests__/` need updating.

**How to avoid:** Keep `updateFolderMetadataAndPublish` and `updateFileMetadata` as public functions that delegate to `publishWithCas` internally. Public signature unchanged. Test mock surface unchanged.

---

## Code Examples

### Existing folder:updated event subscription (folder.store.ts:206–229)

```typescript
// Source: apps/web/src/stores/folder.store.ts:206
_folderSdkUnsubscribe = client.on((event) => {
  switch (event.type) {
    case 'folder:loaded':
    case 'folder:updated': {
      const folders = get().folders;
      const matchingFolder = Object.values(folders).find((f) => f.ipnsName === event.ipnsName);
      if (matchingFolder) {
        get().updateFolderChildren(matchingFolder.id, event.children);
        get().updateFolderSequence(matchingFolder.id, event.sequenceNumber);
      }
      break;
    }
  }
});
```

### Current CAS retry loop structure (folder/index.ts:205)

```typescript
// Source: packages/sdk-core/src/folder/index.ts:205-274
for (let attempt = 0; attempt < 4; attempt++) {
  const { cid } = await addToIpfs(params.ctx, encryptedBytes);
  const newSeq = currentSeq + 1n;
  try {
    await createAndPublishIpnsRecord({ ..., expectedSequenceNumber: currentSeq.toString() });
    return { cid, newSequenceNumber: newSeq, publishedChildren: currentLocalChildren };
  } catch (err) {
    if (!is409(err)) throw err;
    const resolved = await resolveIpnsRecord(params.ipnsName, params.ctx);
    currentSeq = resolved.sequenceNumber;
    const remote = await fetchAndDecryptMetadata(resolved.cid, params.folderKey, params.ctx);
    currentLocalChildren = mergeChildren(params.baseChildren, currentLocalChildren, remote.children);
    if (attempt === 3) throw new ConflictError(params.ipnsName, 4, lastRemoteSeq);
    await new Promise(r => setTimeout(r, retryDelayMs(attempt)));
  }
}
```

### File-side hand-unrolled 2-attempt structure (file/index.ts:289)

```typescript
// Source: packages/sdk-core/src/file/index.ts:289-394
try {
  // Attempt 1
  const result = await createAndPublishIpnsRecord({ ..., expectedSequenceNumber: currentSeq.toString() });
  return { ..., prunedCids };
} catch (err) {
  if (!is409(err)) throw err;
  // merge ...
  currentCid = await encryptAndUpload(mergedMetadata, ...);
  // Attempt 2
  try {
    const retryResult = await createAndPublishIpnsRecord({ ..., expectedSequenceNumber: currentSeq.toString() });
    return { ..., prunedCids };
  } catch (retryErr) {
    if (is409(retryErr)) throw new ConflictError(fileMetaIpnsName, 2, currentSeq);
    throw retryErr;
  }
}
```

### unpinFromIpfs in sdk-core context (for updateSharedFile fix)

```typescript
// Source: packages/sdk-core/src/ipfs/index.ts:57
export async function unpinFromIpfs(ctx: SdkContext, cid: string): Promise<void> {
  await ipfsControllerUnpin({ cid });  // generated API client
}

// Pattern to add in updateSharedFile after destructuring prunedCids:
const { prunedCids } = await updateFileMetadata({ ... });
for (const cid of prunedCids) {
  sdkCore.unpinFromIpfs(params.ctx, cid).catch((err) =>
    console.warn('[shared-write] Unpin pruned CID failed:', err)
  );
}
```

---

## Build/Test Infrastructure

### Build Order

```bash
# After sdk-core public API change:
pnpm --filter @cipherbox/sdk-core build
pnpm --filter @cipherbox/sdk build
# Then web typechecks pass
```

Each package: `tsup` → `dist/index.js` + `dist/index.d.ts`. Consumers typecheck against built dist, not source.

### Existing Test Files (Relevant to This Phase)

| Package | File | Coverage |
|---|---|---|
| sdk-core | `src/__tests__/folder.test.ts` | `updateFolderMetadataAndPublish` (retry loop, union-fallback, ConflictError) |
| sdk-core | `src/__tests__/file.test.ts` | `updateFileMetadata` (2-attempt retry, mergeVersions, prunedCids CR-02) |
| sdk-core | `src/__tests__/folder-merge.test.ts` | `mergeChildren` |
| sdk | `src/__tests__/client.test.ts` | Basic client operations |
| sdk | `src/__tests__/client-extended.test.ts` | createFolder, renameItem, moveItem, deleteItem, deleteToBin, restoreFromBin, emptyBin, purgeExpired |
| sdk | `src/__tests__/shared-write.test.ts` | All 6 shared-write functions including `updateSharedFile` (no prunedCids assertion today) |
| sdk | `src/__tests__/bin.test.ts` | addToBin, restoreFromBin, permanentDelete, emptyBin, purgeExpired |
| sdk | `src/__tests__/client-upload-concurrency.test.ts` | uploadFile concurrent publish |
| sdk | `src/__tests__/upload-batch.test.ts` | uploadFiles batch |
| apps/web | `src/stores/__tests__/` | logout-security, sync-store, upload-error-recovery (NO hook tests) |

**No existing tests for:** `useFileOperations`, `useFileVersions`, `folder.store subscribeToSdk`, `ensureFolderRegistered`/`reconcileFolderState`.

**Web vitest include:** `src/**/*.test.ts` only (confirmed in `apps/web/vitest.config.ts`). Files ending in `.spec.ts` are silently skipped.

### Event-Emitter Test Pattern (from client.test.ts)

```typescript
// How existing tests verify folder:updated emission:
const events: SdkEvent[] = [];
client.on((e) => events.push(e));
await client.renameItem(rootIpnsName, 'child-id', 'new-name');
const folderUpdated = events.find(e => e.type === 'folder:updated');
expect(folderUpdated?.children).toEqual(expectedChildren);
```

---

## Validation Architecture

### Test Map by Requirement

| Req | Behavior | Test Type | Location | Automated Command |
|---|---|---|---|---|
| REQ-2 | `publishWithCas` retries 4x with backoff, throws ConflictError on exhaustion | unit | `packages/sdk-core/src/__tests__/cas.test.ts` (new) | `pnpm --filter @cipherbox/sdk-core test` |
| REQ-2 | `publishWithCas` merges on 409 using injected callback | unit | `cas.test.ts` | same |
| REQ-2 | `publishWithCas` passes `prunedCids` from merge callback through | unit | `cas.test.ts` | same |
| REQ-2 | `updateFolderMetadataAndPublish` (now delegating) still passes existing tests | regression | `folder.test.ts` | same |
| REQ-2 | `updateFileMetadata` (now delegating) still passes existing tests | regression | `file.test.ts` | same |
| REQ-3 | Calling wrapper without explicit base captures correct base from folder | unit | `client-extended.test.ts` or new | `pnpm --filter @cipherbox/sdk test` |
| REQ-3 | `publishedChildren` (not `updatedChildren`) adopted after wrapper | unit | same | same |
| REQ-3 | shared-write functions no longer return `updatedChildren` | TypeScript compile | n/a | `pnpm --filter @cipherbox/sdk build` |
| REQ-4 | `updateSharedFile` calls `unpinFromIpfs` for each `prunedCid` | unit | `shared-write.test.ts` (extend) | `pnpm --filter @cipherbox/sdk test` |
| REQ-4 | `updateSharedFile` handles unpin failure without throwing | unit | same | same |
| REQ-1 | `client.replaceFile()` emits `folder:updated` with correct children+seq | unit | new `client-file-ops.test.ts` | `pnpm --filter @cipherbox/sdk test` |
| REQ-1 | `useFolderStore.subscribeToSdk` updates children+seq on `folder:updated` | unit | new `folder.store.test.ts` in `apps/web` | `pnpm --filter @cipherbox/web test` |
| REQ-1 | `reconcileFolderState` is DELETED — call site removed | compile | n/a | `pnpm --filter @cipherbox/sdk build` |
| REQ-1 | `client.restoreFileVersion()` / `deleteFileVersion()` emit `folder:updated` | unit | `client-file-ops.test.ts` | same as above |

### Wave 0 Gaps (Test Files to Create)

- [ ] `packages/sdk-core/src/__tests__/cas.test.ts` — publishWithCas unit tests (retry, merge callback, ConflictError)
- [ ] `packages/sdk/src/__tests__/client-file-ops.test.ts` — replaceFile, restoreFileVersion, deleteFileVersion
- [ ] `apps/web/src/stores/__tests__/folder.store.test.ts` — subscribeToSdk folder:updated projection

### Sampling Rate

- Per task commit: `pnpm --filter @cipherbox/sdk-core test && pnpm --filter @cipherbox/sdk test`
- Per wave merge: full suite above + `pnpm --filter @cipherbox/web test`
- Phase gate: all suites green

---

## Runtime State Inventory

Not applicable — this is a pure code refactor with no rename/rebrand/migration. No stored data, live service config, OS-registered state, secrets, or build artifacts contain strings being changed.

---

## Environment Availability

No external dependencies. This phase is purely TypeScript source edits with existing toolchain (pnpm, vitest, tsup). No environment probe needed.

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---|---|---|
| V2 Authentication | no | n/a |
| V3 Session Management | no | n/a |
| V4 Access Control | partial | Unpin authority guard on server (Phase 42) — respected by fire-and-forget catch |
| V5 Input Validation | no | All inputs already validated at existing call sites |
| V6 Cryptography | no | No new crypto; existing `fileIpnsPrivateKey.fill(0)` pattern preserved |

**Security invariant to preserve:** `fileIpnsPrivateKey.fill(0)` in `updateFileMetadata`'s `finally` block (line 398) must remain after any `publishWithCas` refactor. The new client methods that accept `fileIpnsPrivateKey` as a parameter must document and enforce that the caller is responsible for zeroing (same contract as today, since the key comes from `getFileIpnsPrivateKey` in the web hook).

**Key insight:** No new crypto surfaces, no new key handling. The security risk is limited to the unpin authority question in Req 4, which is mitigated by the server-side guard (Phase 42) and the fire-and-forget catch pattern.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|---|---|---|
| A1 | Phase 42 server-side unpin guard returns 403 for cross-user unpins (not 200 or silent drop) | Domain D | If guard is not enforced, `updateSharedFile` unpin could succeed for owner-pinned CIDs, causing storage corruption |
| A2 | Root folder is present in `useFolderStore.folders` under key 'root' before `folder:updated` events arrive | Domain C / Pitfall 4 | If root is not in `folders`, subscribeToSdk handler will not match and root children won't update |
| A3 | The attempt count divergence (4 folder vs 2 file) was accidental, not intentional | Domain A | If intentional (e.g., file conflicts are cheaper to abort), unifying at 4+backoff changes behavior |

---

## Open Questions (RESOLVED)

All three open questions were resolved at planning time and baked into the plans.

1. **publishWithCas: unified attempt count?**
   - RESOLVED: 4 attempts + exponential backoff (base 100ms, cap 1500ms, ±50% jitter) for BOTH file and folder paths. The 2-attempt/no-backoff file divergence was accidental; the todo says "reconcile the divergence intentionally" — reconcile UP to the more robust folder values. Baked into Plan 47-01 (locked decision 1).

2. **New client methods: where does restoreVersion/deleteVersion logic live?**
   - RESOLVED: Keep restore/delete service logic in the web tier. The new client methods (`replaceFile` / `restoreFileVersion` / `deleteFileVersion`) accept PRE-RESOLVED params (`fileIpnsPrivateKey`, `currentMetadata`) from the web hook and own ONLY publish + sequence bookkeeping + `folder:updated` emission. The caller owns key zeroing. Baked into Plan 47-03 (locked decision 2).

3. **Drop updatedChildren from shared-write returns: breaking change for callers?**
   - RESOLVED: Safe to drop. `useSharedWriteOps.ts` already consumes `publishedChildren`; `updatedChildren` is unused. Verified by sdk + web TypeScript compile after removal. Baked into Plan 47-02 (locked decision 3).

---

## Sources

### Primary (HIGH confidence)

- Direct source code read of all relevant files in this session (authoritative)

### Secondary (MEDIUM confidence)

- Todo files (`.planning/todos/pending/`) — problem descriptions verified against source code

### Metadata

**Confidence breakdown:**

- Current code state (signatures, line numbers, call sites): HIGH — read directly from source
- Security/unpin authority model: MEDIUM — Phase 42 behavior inferred from guards and comments, not directly read
- Correct unified attempt count: LOW — explicitly marked as open question

**Research date:** 2026-06-15
**Valid until:** 2026-07-15 (stable internal codebase, no external library churn)
