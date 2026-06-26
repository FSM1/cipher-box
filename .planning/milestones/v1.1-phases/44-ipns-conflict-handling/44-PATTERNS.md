# Phase 44: IPNS conflict handling - Pattern Map

**Mapped:** 2026-06-13
**Files analyzed:** 7 new/modified files
**Analogs found:** 7 / 7

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
| --- | --- | --- | --- | --- |
| `packages/sdk-core/src/errors.ts` (new) | utility | — | `packages/sdk/src/client.ts` (`BinNotLoadedError`) | role-match |
| `packages/sdk-core/src/folder/merge.ts` (new) | utility | transform | `packages/sdk-core/src/folder/index.ts` (pure helpers: `renameInFolder`, `deleteFromFolder`) | exact |
| `packages/sdk-core/src/__tests__/folder-merge.test.ts` (new) | test | transform | `packages/sdk-core/src/__tests__/folder.test.ts` | exact |
| `packages/sdk-core/src/folder/index.ts` (modified) | service | request-response | self (existing `updateFolderMetadataAndPublish` loop, lines 174-238) | exact |
| `packages/sdk-core/src/file/index.ts` (modified) | service | request-response | `packages/sdk-core/src/folder/index.ts` (CAS pattern) | role-match |
| `packages/sdk/src/share/shared-write.ts` (modified) | service | request-response | self (existing `updateFolderMetadataAndPublish` call sites at lines ~201, 296, 350, 377) | exact |
| `packages/sdk/src/client.ts` (modified) | service | request-response | self (8 existing `updateFolderMetadataAndPublish` call sites) | exact |

---

## Pattern Assignments

### `packages/sdk-core/src/errors.ts` (new — utility)

**Analog:** `packages/sdk/src/client.ts` lines 38-43 (`BinNotLoadedError`)

**Typed error class pattern** (lines 38-43):

```typescript
export class BinNotLoadedError extends Error {
  constructor() {
    super('Bin not loaded');
    this.name = 'BinNotLoadedError';
  }
}
```

**Apply for `ConflictError`:** Extend `Error`, set `this.name`, carry typed fields. Class lives in `sdk-core` (not `sdk`) so `updateFolderMetadataAndPublish` can throw it without a circular import.

**Also note:** The 409 detection helper pattern already exists in `packages/sdk/src/error.ts` (lines 29-37). The new `isConflictExhausted` type-guard for `ConflictError` should follow the same shape as `isConflictError` there:

```typescript
// packages/sdk/src/error.ts lines 29-37
export function isConflictError(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  const e = error as Record<string, unknown>;
  if (e.status === 409) return true;
  if (typeof e.response === 'object' && e.response !== null) {
    return (e.response as Record<string, unknown>).status === 409;
  }
  return false;
}
```

---

### `packages/sdk-core/src/folder/merge.ts` (new — pure utility)

**Analog:** `packages/sdk-core/src/folder/index.ts` pure helpers, e.g. `renameInFolder` (lines 244-266), `deleteFromFolder` (lines 272-284).

**Imports pattern** (lines 1-6 of `folder/index.ts`):

```typescript
import {
  type FolderChild,
  type FolderEntry,
  type FilePointer,
} from '@cipherbox/core';
```

**Pure function shape** (copy from `deleteFromFolder` lines 272-284 — same pattern: no async, no side effects, takes typed arrays, returns typed value):

```typescript
export function deleteFromFolder(params: { children: FolderChild[]; childId: string }): {
  updatedChildren: FolderChild[];
  removedItem: FolderChild;
} {
  const index = params.children.findIndex((c) => c.id === params.childId);
  if (index === -1) throw new Error('Item not found');
  const removedItem = params.children[index];
  const updatedChildren = params.children.filter((c) => c.id !== params.childId);
  return { updatedChildren, removedItem };
}
```

**Key identity in merge:** Use `child.id` (UUID) as the map key — the same stable identity field used by `renameInFolder` (`children.findIndex((c) => c.id === params.childId)`) and `deleteFromFolder`. Do NOT use `child.name` or `fileMetaIpnsName`.

---

### `packages/sdk-core/src/__tests__/folder-merge.test.ts` (new — unit test)

**Analog:** `packages/sdk-core/src/__tests__/folder.test.ts` (exact pattern)

**Test file structure** (lines 1-28 of `folder.test.ts`):

```typescript
import { describe, it, expect } from 'vitest';
import type { FolderChild, FolderEntry, FilePointer } from '@cipherbox/core';
import { renameInFolder, deleteFromFolder, addFilePointerToFolder, moveItem } from '../folder';

// These tests cover the pure (synchronous) folder metadata operations.

const makeFolder = (id: string, name: string): FolderEntry => ({
  type: 'folder',
  id,
  name,
  ipnsName: `k51-${id}`,
  ipnsPrivateKeyEncrypted: 'encrypted-key',
  folderKeyEncrypted: 'encrypted-folder-key',
  createdAt: 1000,
  modifiedAt: 1000,
});

const makeFile = (id: string, name: string): FilePointer => ({
  type: 'file',
  id,
  name,
  fileMetaIpnsName: `k51-file-${id}`,
  ipnsPrivateKeyEncrypted: 'encrypted-key',
  createdAt: 1000,
  modifiedAt: 1000,
});
```

**Test assertion style** (lines 32-46 of `folder.test.ts`):

```typescript
describe('Folder operations', () => {
  describe('renameInFolder', () => {
    it('renames a child and updates modifiedAt', () => {
      const children: FolderChild[] = [makeFolder('f1', 'Documents'), makeFile('f2', 'photo.jpg')];
      const result = renameInFolder({ children, childId: 'f1', newName: 'My Documents' });
      expect(result.updatedChildren).toHaveLength(2);
      expect(result.renamedChild.name).toBe('My Documents');
      // Original array not mutated
      expect(children[0].name).toBe('Documents');
    });
```

**For `folder-merge.test.ts`:** Import `mergeChildren` from `'../folder/merge'`. Fixture factory functions (`makeFolder`, `makeFile`) should be copy-pasted from `folder.test.ts` (or imported from a shared helper if one is created). Each permutation (local-add, remote-add, local-delete, remote-delete, modified-both, edit-beats-delete) gets its own `it` block.

No mocking needed — pure function, no async, no IPFS/IPNS calls.

---

### `packages/sdk-core/src/folder/index.ts` (modified — retry loop)

**Analog:** Self — existing `updateFolderMetadataAndPublish` body (lines 174-238).

**Existing loop being replaced** (lines 200-233):

```typescript
let currentSeq = params.sequenceNumber;

for (let attempt = 0; attempt < 2; attempt++) {
  const newSeq = currentSeq + 1n;
  try {
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
    return { cid, newSequenceNumber: newSeq };
  } catch (err) {
    const is409 =
      (err as Error & { status?: number }).status === 409 ||
      (err as Error & { response?: { status?: number } }).response?.status === 409;
    if (!is409 || attempt > 0) throw err;

    // Re-sync: resolve current seq from IPNS
    const resolved = await resolveIpnsRecord(params.ipnsName, params.ctx);
    if (resolved) {
      currentSeq = resolved.sequenceNumber;
    } else {
      throw err;
    }
  }
}
```

**Existing CAS params pattern** (lines 207-217): The `expectedSequenceNumber: currentSeq.toString()` field is already wired to `createAndPublishIpnsRecord`. The new loop keeps this — changes are: expand to 4 attempts, add `baseChildren`/`fetchAndDecryptMetadata`/`mergeChildren` in the 409 branch, re-encrypt and re-upload before republishing, throw `ConflictError` on exhaustion.

**`withPerf` wrapper pattern** (lines 185-238): All new code stays inside `withPerf('folder:update-publish', async () => { ... })`.

**Re-fetch building blocks already imported** (line 31 of `folder/index.ts`):

```typescript
import { createAndPublishIpnsRecord, batchPublishIpnsRecords, resolveIpnsRecord } from '../ipns';
```

`fetchAndDecryptMetadata` is defined in the same file (lines 46-60) — call directly, no new import.

---

### `packages/sdk-core/src/file/index.ts` (modified — CAS + conflict)

**Analog:** `packages/sdk-core/src/folder/index.ts` CAS pattern (lines 200-233) and version-cap logic already in `file/index.ts` (lines 196-211).

**Existing TOCTOU resolve pattern** (lines 224-231 of `file/index.ts`):

```typescript
// 3. Resolve current IPNS to get sequence number
const resolved = await resolveIpnsRecord(params.fileMetaIpnsName, params.ctx);
if (!resolved) {
  throw new Error(
    `Cannot update file metadata: existing IPNS record not found for ${params.fileMetaIpnsName}`
  );
}
const newSeq = resolved.sequenceNumber + 1n;
```

**Existing version-cap pattern** (lines 196-211 of `file/index.ts`):

```typescript
if (params.createVersion) {
  const versionEntry: VersionEntry = {
    cid: params.currentMetadata.cid,
    fileKeyEncrypted: params.currentMetadata.fileKeyEncrypted,
    fileIv: params.currentMetadata.fileIv,
    size: params.currentMetadata.size,
    timestamp: Date.now(),
    encryptionMode: params.currentMetadata.encryptionMode ?? 'GCM',
  };
  const allVersions = [versionEntry, ...(params.currentMetadata.versions ?? [])];
  versions = allVersions.slice(0, MAX_VERSIONS_PER_FILE);
  prunedCids = allVersions.slice(MAX_VERSIONS_PER_FILE).map((v) => v.cid);
}
```

**Key change:** After resolving seq, pass `expectedSequenceNumber: resolved.sequenceNumber.toString()` to `createAndPublishIpnsRecord` (same as the folder CAS pattern at `folder/index.ts:215`). On 409, re-resolve, re-fetch remote `FileMetadata`, apply latest-wins by `modifiedAt`, union `versions[]` (dedup by `cid`, sort by `timestamp`, cap by `maxVersionsPerFile`), re-encrypt, re-upload, retry. Throw `ConflictError` after 2 total attempts.

**New import needed** (align with `folder/index.ts` line 31):

```typescript
import { createAndPublishIpnsRecord, resolveIpnsRecord } from '../ipns';
```

`createAndPublishIpnsRecord` is not currently imported by `file/index.ts` — add it.

**`uint8ToBase64` helper:** Already defined at `file/index.ts` lines 31-37. Do not duplicate.

**Add optional `maxVersionsPerFile` param** to `updateFileMetadata` params object, defaulting to `MAX_VERSIONS_PER_FILE` (line 28). Replace direct use of constant with `params.maxVersionsPerFile ?? MAX_VERSIONS_PER_FILE` in both the main version-cap path and the conflict merge path.

---

### `packages/sdk/src/share/shared-write.ts` (modified — baseChildren sweep)

**Analog:** Self — existing `updateFolderMetadataAndPublish` call at line 201.

**Current call shape** (lines 200-208 of `shared-write.ts`):

```typescript
const { newSequenceNumber } = await updateFolderMetadataAndPublish({
  children: updatedChildren,
  folderKey: swCtx.folderKey,
  ipnsPrivateKey: swCtx.ipnsPrivateKey,
  ipnsName: swCtx.ipnsName,
  sequenceNumber: swCtx.sequenceNumber,
  ctx: swCtx.ctx,
});
```

**Pattern to add:** Each call site must snapshot `swCtx.children` (before mutation) as `baseChildren` and pass it:

```typescript
const { newSequenceNumber } = await updateFolderMetadataAndPublish({
  children: updatedChildren,
  baseChildren: swCtx.children,   // <-- add: snapshot before mutation
  folderKey: swCtx.folderKey,
  ipnsPrivateKey: swCtx.ipnsPrivateKey,
  ipnsName: swCtx.ipnsName,
  sequenceNumber: swCtx.sequenceNumber,
  ctx: swCtx.ctx,
});
```

All 4 call sites (lines ~201, 296, 350, 377) follow this same pattern — `swCtx.children` is the correct base for all of them.

**`ConflictError` handling in `shared-write.ts`:** The shared-write functions already propagate thrown errors to callers (no internal catch). `ConflictError` will naturally surface to the web hook callers where the conflict UI routing lives (`apps/web/src/hooks/folder-helpers.ts` `withConflictRetry`). No additional catch block needed in `shared-write.ts` itself.

---

### `packages/sdk/src/client.ts` (modified — baseChildren sweep)

**Analog:** Self — 8 existing `updateFolderMetadataAndPublish` call sites. Refer to the Research.md caller sweep table (lines 274-291) for the source of `baseChildren` per call site.

**Representative current call** (around line 414 — `createFolder`):

```typescript
await updateFolderMetadataAndPublish({
  children: updatedChildren,
  folderKey: parentFolderKey,
  ipnsPrivateKey: parentIpnsPrivateKey,
  ipnsPublicKey: parentIpnsPublicKey,
  ipnsName: parentFolder.ipnsName,
  sequenceNumber: parentFolder.sequenceNumber,
  ctx: this.ctx,
});
```

**Pattern to add:** Capture `parent.children` before mutation as `const baseChildren = [...folder.children]` (or inline), then pass `baseChildren` to the call. The `FolderTree` state object holds `children` per folder — that is the correct snapshot source.

**`ConflictError` import** needed in `client.ts`:

```typescript
import { ConflictError } from '@cipherbox/sdk-core';
```

Then re-throw or surface via the event emitter's error event (match existing error event emission pattern in `withOperation()`).

---

## Shared Patterns

### 409 detection

**Source:** `packages/sdk-core/src/folder/index.ts` lines 220-223

**Apply to:** `updateFolderMetadataAndPublish` retry loop and `updateFileMetadata` conflict path

```typescript
const is409 =
  (err as Error & { status?: number }).status === 409 ||
  (err as Error & { response?: { status?: number } }).response?.status === 409;
```

### Key zeroization on error

**Source:** `packages/sdk-core/src/file/index.ts` lines 138-142 and `packages/sdk-core/src/folder/index.ts` lines 158-163

**Apply to:** Any new code that holds decrypted IPNS private keys in the conflict path

```typescript
} finally {
  ipnsKeypair.privateKey.fill(0);
}
```

### `withPerf` instrumentation

**Source:** `packages/sdk-core/src/folder/index.ts` lines 185-238

**Apply to:** New retry loop code inside `updateFolderMetadataAndPublish` — keep the existing `withPerf('folder:update-publish', ...)` wrapper; do not add a nested wrapper.

### Mock context in tests

**Source:** `packages/sdk-core/src/__tests__/helpers.ts`

**Apply to:** `folder-merge.test.ts` — not needed for the pure merge function (no I/O), but if `folder.test.ts` is expanded for the retry loop, import `createMockContext` from `'./helpers'`.

```typescript
import { createMockContext } from './helpers';
```

### API client mocking pattern in tests

**Source:** `packages/sdk-core/src/__tests__/ipns.test.ts` lines 5-8

**Apply to:** Any test that exercises the retry loop (needs mock `createAndPublishIpnsRecord`)

```typescript
vi.mock('@cipherbox/api-client', () => ({
  ipnsControllerPublishRecord: vi.fn(),
  ipnsControllerPublishBatch: vi.fn(),
  ipnsControllerResolveRecord: vi.fn(),
}));
```

---

## No Analog Found

All files have close analogs. No entries in this section.

---

## Metadata

**Analog search scope:** `packages/sdk-core/src/`, `packages/sdk/src/`, `apps/web/src/hooks/`
**Files scanned:** 9 source files read directly
**Pattern extraction date:** 2026-06-13
