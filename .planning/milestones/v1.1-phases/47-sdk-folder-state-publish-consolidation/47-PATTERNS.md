# Phase 47: SDK Folder-State and Publish-Path Consolidation - Pattern Map

**Mapped:** 2026-06-15
**Files analyzed:** 11 new/modified files
**Analogs found:** 11 / 11

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `packages/sdk-core/src/cas.ts` (NEW) | utility | request-response (CAS retry) | `packages/sdk-core/src/folder/index.ts:205-275` | exact |
| `packages/sdk-core/src/__tests__/cas.test.ts` (NEW) | test | — | `packages/sdk-core/src/__tests__/folder.test.ts` | role-match |
| `packages/sdk-core/src/folder/index.ts` | service | request-response | self (delegates to cas.ts) | self-refactor |
| `packages/sdk-core/src/file/index.ts` | service | request-response | self (delegates to cas.ts) | self-refactor |
| `packages/sdk/src/client.ts` | service | request-response | `packages/sdk/src/client.ts:652-696` (deleteItem) | exact |
| `packages/sdk/src/__tests__/client-file-ops.test.ts` (NEW) | test | — | `packages/sdk/src/__tests__/client-extended.test.ts:67-109` | exact |
| `packages/sdk/src/share/shared-write.ts` | service | request-response | `apps/web/src/hooks/useFileOperations.ts:506-511` | partial |
| `apps/web/src/lib/sdk-provider.ts` | utility | request-response | self (delete one call) | self-edit |
| `apps/web/src/hooks/useFileOperations.ts` | hook | request-response | `packages/sdk/src/client.ts:652-696` (deleteItem) | role-match |
| `apps/web/src/hooks/useFileVersions.ts` | hook | request-response | `packages/sdk/src/client.ts:652-696` (deleteItem) | role-match |
| `apps/web/src/stores/__tests__/folder.store.test.ts` (NEW) | test | — | `apps/web/src/stores/__tests__/logout-security.test.ts` | role-match |

---

## Pattern Assignments

### `packages/sdk-core/src/cas.ts` (NEW — publishWithCas generic helper)

**Analog:** `packages/sdk-core/src/folder/index.ts:186-275`

The entire CAS retry loop in `updateFolderMetadataAndPublish` is the template. Extract the loop body, parameterise `encodeAndUpload`, `decodeRemote`, and `merge` as callbacks. Key behaviors to preserve exactly:

**Loop structure to generify** (`folder/index.ts:205-275`):
```typescript
let currentSeq = params.sequenceNumber;
let lastRemoteSeq = params.sequenceNumber;

for (let attempt = 0; attempt < params.maxAttempts; attempt++) {
  // 1. Encode + upload (domain-specific, injected)
  const { cid } = await params.encodeAndUpload(localData);
  const newSeq = currentSeq + 1n;

  try {
    // 2. CAS publish
    await createAndPublishIpnsRecord({
      ipnsPrivateKey: params.ipnsPrivateKey,
      ipnsPublicKey: params.ipnsPublicKey,
      ipnsName: params.ipnsName,
      metadataCid: cid,
      sequenceNumber: newSeq,
      encryptedIpnsPrivateKey: params.encryptedIpnsPrivateKey,
      keyEpoch: params.keyEpoch,
      expectedSequenceNumber: currentSeq.toString(),
      ctx: params.ctx,
    });
    return { cid, newSequenceNumber: newSeq, publishedData: localData, prunedCids };
  } catch (err) {
    if (!is409(err)) throw err;

    // 3. Re-resolve authoritatively
    const resolved = await resolveIpnsRecord(params.ipnsName, params.ctx);
    if (!resolved) throw new ConflictError(params.ipnsName, attempt + 1, lastRemoteSeq);
    currentSeq = resolved.sequenceNumber;
    lastRemoteSeq = resolved.sequenceNumber;

    // 4. Fetch + decode remote
    const remoteData = await params.decodeRemote(resolved.cid);

    // 5. Three-way merge (domain-specific, injected)
    const { merged, prunedCids: extraPruned } = params.merge(baseData, localData, remoteData);
    localData = merged;
    prunedCids = [...new Set([...prunedCids, ...(extraPruned ?? [])])];

    // 6. After final attempt, throw ConflictError
    if (attempt === params.maxAttempts - 1) {
      throw new ConflictError(params.ipnsName, params.maxAttempts, lastRemoteSeq);
    }

    // 7. Backoff + jitter (move retryDelayMs from folder/index.ts here)
    if (params.backoff) {
      await new Promise<void>((r) => setTimeout(r, retryDelayMs(attempt)));
    }
  }
}
throw new ConflictError(params.ipnsName, params.maxAttempts, lastRemoteSeq);
```

**retryDelayMs to move into cas.ts** (`folder/index.ts:41-43`):
```typescript
// Exponential backoff with ±50% jitter, base 100ms, cap 1500ms
function retryDelayMs(attempt: number): number {
  const base = Math.min(100 * 2 ** attempt, 1500);
  return base * (0.5 + Math.random());
}
```

**Imports needed** (`folder/index.ts:1-15` area):
```typescript
import { createAndPublishIpnsRecord, resolveIpnsRecord } from '../ipns';
import { is409, ConflictError } from '../errors';
```

**SECURITY:** The `fileIpnsPrivateKey.fill(0)` in `file/index.ts:399` MUST remain in `updateFileMetadata`'s own `finally` block after delegating — the caller of `publishWithCas` is responsible for zeroing, NOT `publishWithCas` itself.

---

### `packages/sdk-core/src/folder/index.ts` (MODIFIED — delegate to publishWithCas)

**After refactor:** `updateFolderMetadataAndPublish` becomes a thin wrapper. The public signature is UNCHANGED (mock surface preserved). The wrapper supplies:
- `encodeAndUpload`: encrypt folder metadata then `addToIpfs`
- `decodeRemote`: `fetchAndDecryptMetadata(resolved.cid, params.folderKey, params.ctx)`
- `merge`: `(base, local, remote) => ({ merged: mergeChildren(base ?? [], local, remote) })`
- `maxAttempts: 4`, `backoff: true`

The union-fallback warning for missing `baseChildren` (currently `folder/index.ts:254-261`) stays in the wrapper before constructing `baseData`:
```typescript
if (params.baseChildren === undefined) {
  console.warn('[sdk-core] updateFolderMetadataAndPublish: baseChildren not provided for ' +
    params.ipnsName + ' — using union fallback (deletes may resurrect). Caller should pass baseChildren.');
}
const baseData = params.baseChildren ?? [];
```

---

### `packages/sdk-core/src/file/index.ts` (MODIFIED — delegate to publishWithCas)

**After refactor:** `updateFileMetadata` becomes a thin wrapper. The hand-unrolled 2-attempt structure (`file/index.ts:289-394`) is replaced by a `publishWithCas` call with:
- `maxAttempts: 4` (unified with folder — planner decision: 4+backoff for both)
- `backoff: true`
- `encodeAndUpload`: `encryptAndUpload(local, params.folderKey, params.ctx)`
- `decodeRemote`: `fetchAndDecryptFileMetadata(cid, params.folderKey, params.ctx)`
- `merge`: the loser-as-version logic, returns `{ merged: mergedMetadata, prunedCids }`

The `finally` block zeroing `params.fileIpnsPrivateKey.fill(0)` MUST stay in `updateFileMetadata`, wrapping the `publishWithCas` call:
```typescript
// file/index.ts:396-400 — PRESERVE THIS
} finally {
  params.fileIpnsPrivateKey.fill(0);
}
```

The concurrent pre-resolve+upload optimization (`file/index.ts:276-279`) can be dropped since `publishWithCas` performs resolve inside the loop. This is intentional — the optimization depended on the hand-unrolled structure.

---

### `packages/sdk-core/src/__tests__/cas.test.ts` (NEW)

**Analog:** `packages/sdk-core/src/__tests__/folder.test.ts:1-54` (mock setup pattern)

**Mock setup pattern** (`folder.test.ts:19-54`):
```typescript
const mockFns = vi.hoisted(() => ({
  createAndPublishIpnsRecord: vi.fn(),
  resolveIpnsRecord: vi.fn(),
  addToIpfs: vi.fn(),
  fetchFromIpfs: vi.fn(),
}));

vi.mock('../ipns', () => ({
  createAndPublishIpnsRecord: mockFns.createAndPublishIpnsRecord,
  resolveIpnsRecord: mockFns.resolveIpnsRecord,
}));
```

**Test cases to implement:**
1. Success on first attempt — `encodeAndUpload` called once, returns `{ cid, newSequenceNumber, publishedData, prunedCids: [] }`
2. 409 → merge → success on retry — `resolveIpnsRecord` called, `merge` called with `(base, local, remote)`, second `createAndPublishIpnsRecord` called
3. All attempts exhausted → `ConflictError` thrown with `attempts === maxAttempts`
4. `prunedCids` from merge callback propagated through return
5. Non-409 error is rethrown immediately without retry
6. `backoff: false` skips `setTimeout` (mock `setTimeout` and assert not called)

**createMockContext pattern** (from `folder.test.ts`, uses `packages/sdk-core/src/__tests__/helpers.ts`):
```typescript
import { createMockContext } from './helpers';
const ctx = createMockContext();
```

---

### `packages/sdk/src/client.ts` (MODIFIED — new replaceFile/restoreFileVersion/deleteFileVersion)

**Analog:** `packages/sdk/src/client.ts:652-696` (deleteItem — exact 5-step pattern)

**The canonical 5-step SDK client method pattern** (`client.ts:652-696`):
```typescript
async deleteItem(folderIpnsName: string, childId: string): Promise<{ removedItem: FolderChild }> {
  return this.withOperation('deleteItem', async () => {
    // Step 1: Get folder from folderTree (throws if not loaded)
    const folder = this.folderTree.get(folderIpnsName);
    if (!folder) throw new Error('Folder not loaded');

    // Step 2: Snapshot baseChildren + compute next children
    const baseChildren = [...folder.children];
    const { updatedChildren, removedItem } = sdkCore.deleteFromFolder({ children: folder.children, childId });

    // Step 3: Publish via sdk-core (CAS, handles 409 internally)
    const { newSequenceNumber, publishedChildren } = await sdkCore.updateFolderMetadataAndPublish({
      children: updatedChildren,
      baseChildren,
      folderKey: folder.folderKey,
      ipnsPrivateKey: folder.ipnsKeypair.privateKey,
      ipnsName: folderIpnsName,
      sequenceNumber: folder.sequenceNumber,
      ctx: this.ctx,
    });

    // Step 4: Adopt published state (CR-01 — use publishedChildren, NOT updatedChildren)
    folder.children = publishedChildren;
    folder.sequenceNumber = newSequenceNumber;
    folder.lastLoadedAt = Date.now();
    this.folderTree.set(folderIpnsName, folder);

    // Step 5: Emit folder:updated
    this.emitter.emit({
      type: 'folder:updated',
      folderId: folderIpnsName,
      ipnsName: folderIpnsName,
      children: publishedChildren,
      sequenceNumber: newSequenceNumber,
    });

    return { removedItem };
  });
}
```

**For replaceFile** — step 3 is split: first `sdkCore.updateFileMetadata(...)` (file IPNS publish), then `sdkCore.updateFolderMetadataAndPublish(...)` (folder touch for modifiedAt bump on FilePointer). The `prunedCids` from `updateFileMetadata` are returned so the caller can unpin. The method accepts pre-resolved `fileIpnsPrivateKey` and `currentMetadata` as params (web hook resolves keys before calling).

**For restoreFileVersion / deleteFileVersion** — same 5-step shape. Step 3 calls the service logic (move from `apps/web/src/services/file-metadata.service.ts`-equivalent logic or accept pre-resolved keys). The optional lazy IPNS key migration (`updateFolderMetadataAndPublish` for key epoch update on FilePointer) happens before step 4 if `needsKeyMigration`.

**deleteToBin pattern for emit without direct publish** (`client.ts:1253-1281`) — used as analog for restoreFileVersion/deleteFileVersion where the service function mutates `folderTree` internally via bin ops:
```typescript
// After op, read back from folderTree rather than from publish return
const folderState = this.folderTree.get(folderIpnsName);
this.emitter.emit({
  type: 'folder:updated',
  folderId: folderIpnsName,
  ipnsName: folderIpnsName,
  children: folderState?.children ?? [],
  sequenceNumber: folderState?.sequenceNumber ?? 0n,
});
```

---

### `packages/sdk/src/__tests__/client-file-ops.test.ts` (NEW)

**Analog:** `packages/sdk/src/__tests__/client-extended.test.ts:1-109`

**Complete test file structure to mirror** (`client-extended.test.ts:1-109`):
```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import type { SdkEvent } from '../events';
import { createTestConfig, setupFolder } from './helpers';

vi.mock('@cipherbox/crypto', () => ({
  clearBytes: vi.fn((arr: Uint8Array) => arr.fill(0)),
}));

vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    updateFolderMetadataAndPublish: vi.fn(),
    updateFileMetadata: vi.fn(),
    // ... other fns used by new methods
  };
});

import * as sdkCore from '@cipherbox/sdk-core';

describe('CipherBoxClient - file ops', () => {
  let client: CipherBoxClient;
  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
  });

  describe('replaceFile', () => {
    it('updates file metadata, publishes folder, and emits folder:updated', async () => {
      const events: SdkEvent[] = [];
      client.on((e) => events.push(e));
      setupFolder(client);

      vi.mocked(sdkCore.updateFileMetadata).mockResolvedValue({
        ipnsName: 'k51file',
        metadataCid: 'bafyfile',
        newSequenceNumber: 2n,
        prunedCids: [],
      });
      vi.mocked(sdkCore.updateFolderMetadataAndPublish).mockResolvedValue({
        cid: 'bafyfolder',
        newSequenceNumber: 2n,
        publishedChildren: [],
      });

      const result = await client.replaceFile('folder-ipns', 'file1', { /* fileData */ });

      expect(sdkCore.updateFileMetadata).toHaveBeenCalled();
      expect(sdkCore.updateFolderMetadataAndPublish).toHaveBeenCalled();
      expect(events.some((e) => e.type === 'folder:updated')).toBe(true);
      expect(result.prunedCids).toEqual([]);
    });
  });
});
```

**Event assertion pattern** (from `client-extended.test.ts:108`):
```typescript
expect(events.some((e) => e.type === 'folder:updated')).toBe(true);
// Or with children assertion:
const evt = events.find((e) => e.type === 'folder:updated');
expect(evt?.sequenceNumber).toBe(2n);
```

---

### `packages/sdk/src/share/shared-write.ts` (MODIFIED — prunedCids unpin)

**Analog for unpin call:** `apps/web/src/hooks/useFileOperations.ts:506-511`

**Exact owner-path unpin pattern to mirror** (`useFileOperations.ts:506-511`):
```typescript
for (const prunedCid of prunedCids) {
  unpinFromIpfs(prunedCid).catch((err) =>
    logger.warn('[FileOps] Unpin pruned CID failed:', err)
  );
}
```

**SDK-tier equivalent in updateSharedFile** (uses `sdkCore.unpinFromIpfs(ctx, cid)` — NOT the web-tier wrapper):
```typescript
// shared-write.ts:464 — change from:
await updateFileMetadata({ ... });

// To (destructure prunedCids, fire-and-forget unpin):
const { prunedCids } = await updateFileMetadata({ ... });
for (const cid of prunedCids) {
  unpinFromIpfs(params.ctx, cid).catch((err) =>
    console.warn('[shared-write] Unpin pruned CID failed:', err)
  );
}
```

**`unpinFromIpfs` in sdk-core context** (`packages/sdk-core/src/ipfs/index.ts:57`):
```typescript
export async function unpinFromIpfs(ctx: SdkContext, cid: string): Promise<void> {
  await ipfsControllerUnpin({ cid });
}
```

Import: `import { unpinFromIpfs } from '@cipherbox/sdk-core'` (already imported in shared-write.ts via `sdkCore` namespace — use `sdkCore.unpinFromIpfs` or destructure).

---

### `apps/web/src/lib/sdk-provider.ts` (MODIFIED — remove reconcileFolderState)

**Current call to delete** (`sdk-provider.ts:107-110`):
```typescript
if (client.hasFolder(folder.ipnsName)) {
  client.reconcileFolderState(folder.ipnsName, folder.children, folder.sequenceNumber);
  return;
}
```

**After Req 1** — replace with simple guard:
```typescript
if (client.hasFolder(folder.ipnsName)) {
  return;
}
```

The `client.reconcileFolderState` method itself is DELETED from `client.ts`. This file just removes the call.

---

### `apps/web/src/hooks/useFileOperations.ts` (MODIFIED — route through client.replaceFile)

**Current bypass pattern to REMOVE** (`useFileOperations.ts:458-469` area) — the `handleUpdateFile` "6b" block that calls `sdkCore.updateFolderMetadataAndPublish` directly and writes Zustand store directly.

**Pattern after Req 1:** Call `client.replaceFile(parentIpnsName, fileId, { ... })` then unpin returned `prunedCids` (owner path unpin stays here in web tier, using `apps/web/src/lib/api/ipfs.ts:unpinFromIpfs`). DO NOT call `store.updateFolderChildren` or `store.updateFolderSequence` — those are now driven by the `folder:updated` event handler in `subscribeToSdk`.

---

### `apps/web/src/hooks/useFileVersions.ts` (MODIFIED — route through client methods)

Same pattern as `useFileOperations.ts`. Replace direct `sdkCore.updateFolderMetadataAndPublish` calls at lines 130 and 264 with `client.restoreFileVersion(...)` and `client.deleteFileVersion(...)`. Web hook resolves `fileIpnsPrivateKey` via `getFileIpnsPrivateKey` before calling the client method. Remove direct Zustand `updateFolderChildren`/`updateFolderSequence` calls from `.then()` handlers at lines 140-141 and 273-275.

---

### `apps/web/src/stores/folder.store.ts` (MODIFIED — children/sequenceNumber as projection-only)

**No new code needed** — `subscribeToSdk` at `folder.store.ts:200` already correctly handles `folder:updated` events. The change is at CALL SITES: removing direct `updateFolderChildren`/`updateFolderSequence` calls from `useFileOperations` and `useFileVersions`.

**Existing subscription handler pattern** (`folder.store.ts:206-231`):
```typescript
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

---

### `apps/web/src/stores/__tests__/folder.store.test.ts` (NEW)

**Analog:** `apps/web/src/stores/__tests__/logout-security.test.ts:1-29`

**Web store test harness pattern** (`logout-security.test.ts:1-29`):
```typescript
import { describe, it, expect, beforeEach } from 'vitest';
import { useFolderStore, type FolderNode } from '../folder.store';

describe('useFolderStore', () => {
  beforeEach(() => {
    useFolderStore.setState({
      folders: {},
      currentFolderId: null,
      breadcrumbs: [],
      pendingPublishes: new Set<string>(),
    });
  });
```

**For subscribeToSdk tests:** Mock `getSdkClient()` to return a fake client that captures the `on()` subscriber, then trigger events manually:
```typescript
import { vi } from 'vitest';
// mock sdk-provider
vi.mock('../../lib/sdk-provider', () => ({
  getSdkClient: vi.fn(() => mockClient),
}));

// In test: trigger the event handler and assert Zustand state updated
const handler = capturedOnCallback;
handler({ type: 'folder:updated', ipnsName: 'k51test', children: [...], sequenceNumber: 2n });
expect(useFolderStore.getState().folders['some-id'].sequenceNumber).toBe(2n);
```

---

## Shared Patterns

### CAS 409 Detection

**Source:** `packages/sdk-core/src/errors.ts` (is409 / ConflictError)
**Apply to:** `cas.ts`
```typescript
import { is409, ConflictError } from '../errors';
// is409(err) checks err.status === 409 || err.response?.status === 409
// new ConflictError(ipnsName, attempts, lastRemoteSeq)
```

### Key Zeroing

**Source:** `packages/sdk-core/src/file/index.ts:396-400`
**Apply to:** Any function that receives `fileIpnsPrivateKey: Uint8Array` as a param

```typescript
} finally {
  params.fileIpnsPrivateKey.fill(0);
}
```

`publishWithCas` itself does NOT zero keys — it is the wrapper's responsibility.

### folderTree Adoption (CR-01)

**Source:** `packages/sdk/src/client.ts:677-681`
**Apply to:** All new client methods that call `updateFolderMetadataAndPublish`

```typescript
// ALWAYS use publishedChildren, never updatedChildren
folder.children = publishedChildren;
folder.sequenceNumber = newSequenceNumber;
folder.lastLoadedAt = Date.now();
this.folderTree.set(ipnsName, folder);
```

### folder:updated Emission

**Source:** `packages/sdk/src/client.ts:683-690`
**Apply to:** All three new client methods (replaceFile, restoreFileVersion, deleteFileVersion)

```typescript
this.emitter.emit({
  type: 'folder:updated',
  folderId: folderIpnsName,
  ipnsName: folderIpnsName,
  children: publishedChildren,
  sequenceNumber: newSequenceNumber,
});
```

### withOperation Wrapper

**Source:** `packages/sdk/src/client.ts:652-653`
**Apply to:** All new client methods

```typescript
return this.withOperation('replaceFile', async () => {
  // ...
});
```

### vi.hoisted + vi.mock Pattern (sdk-core tests)

**Source:** `packages/sdk-core/src/__tests__/folder.test.ts:19-54`
**Apply to:** `cas.test.ts`

Use `vi.hoisted()` to define mock function refs before `vi.mock()` factories:
```typescript
const mockFns = vi.hoisted(() => ({
  createAndPublishIpnsRecord: vi.fn(),
  resolveIpnsRecord: vi.fn(),
}));
vi.mock('../ipns', () => ({
  createAndPublishIpnsRecord: mockFns.createAndPublishIpnsRecord,
  resolveIpnsRecord: mockFns.resolveIpnsRecord,
}));
```

---

## No Analog Found

None — all files have direct analogs in the codebase.

---

## Critical Constraints

- String literals over TypeScript enums (project-wide rule)
- `Uint8Array` for binary data — never `string` for key material
- `camelCase` for all TypeScript fields
- Build order after sdk-core API change: `pnpm --filter @cipherbox/sdk-core build` then `pnpm --filter @cipherbox/sdk build` before web typechecks
- Test files must end `.test.ts` (not `.spec.ts`) — web vitest `include` only matches `src/**/*.test.ts`
- `apps/api` is OUT OF SCOPE — do not touch

---

## Metadata

**Analog search scope:** `packages/sdk-core/src/`, `packages/sdk/src/`, `apps/web/src/stores/`, `apps/web/src/lib/`, `apps/web/src/hooks/`
**Files scanned:** 11 source files + 4 test files
**Pattern extraction date:** 2026-06-15
