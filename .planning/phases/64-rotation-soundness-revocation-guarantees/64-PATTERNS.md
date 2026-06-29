# Phase 64: Rotation Soundness — Revocation Guarantees - Pattern Map

**Mapped:** 2026-06-29
**Files analyzed:** 8 files to modify + 2 new files
**Analogs found:** 9 / 10 (rotation-crash-safety.test.ts is new — scaffold is read-chain-navigation.test.ts)

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `packages/sdk-core/src/rotation/engine.ts` | service | event-driven (CAS-retry BFS walk) | Self (Phase-63 scaffold — filling stubs in-place) | exact |
| `packages/sdk-core/src/folder/merge.ts` | utility | transform | `cas.ts` merge callback pattern | role-match |
| `packages/sdk-core/src/folder/registration.ts` | service | CRUD | Self (fix `?? crypto.randomUUID()` at L174-175) | exact |
| `packages/sdk/src/client.ts` | service | CRUD | Self (6 call sites at L493/L558/L581/L629/L747/L1006) | exact |
| `packages/sdk-core/src/folder/metadata-ops.ts` | utility | transform | Self (moveItem L132-143 — re-seal added in caller) | exact |
| `packages/sdk-core/src/__tests__/rotation/engine.test.ts` | test | — | Self (extend) + `cas.test.ts` vi.hoisted mock pattern | exact |
| `packages/sdk-core/src/__tests__/rotation/grant-remint.test.ts` | test | — | `engine.test.ts` vi.hoisted + callback mock pattern | role-match |
| `tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts` | test | request-response (live IPNS) | `tests/sdk-e2e/src/suites/read-chain-navigation.test.ts` | role-match |

---

## Pattern Assignments

### `packages/sdk-core/src/rotation/engine.ts` — Fill four seams + D-01/D-02/D-07 fixes

**Analog:** Self (the Phase-63 scaffold is the file being modified)

**Existing throwing stub bodies** (`engine.ts` L200-257):

```typescript
// L200-202
export async function mintFileKeyOnRotate(_node: Node, _job: RotationJobRecord): Promise<void> {
  throw new Error('not implemented — phase 64 (ROT-03/CRIT-1 content-key rotation)');
}

// L215-223
export async function reMintGrantsRootedAt(
  _nodeId: string,
  _key: Uint8Array,
  _gen: number,
  _job: RotationJobRecord,
  _ctx: SdkContext
): Promise<void> {
  throw new Error('not implemented — phase 64 (ROT-04/HIGH-3 inner-grant re-mint)');
}

// L235-241
export async function mergeConcurrentChildren(
  _node: Node,
  _resolved: unknown,
  _ctx: SdkContext
): Promise<void> {
  throw new Error('not implemented — phase 64 (ROT-05/HIGH-4 concurrent-add merge)');
}

// L255-257
export async function verifySubtreeClean(_rootNodeId: string, _ctx: SdkContext): Promise<boolean> {
  throw new Error('not implemented — phase 64 (ROT-06 crash-resume + verifySubtreeClean)');
}
```

**D-01: Placeholder publish fallback to DELETE** (`engine.ts` L355-357, inside `publishWithCas` call):

```typescript
// CURRENT — DELETE THIS LINE:
ipnsPrivateKey: nodeIpnsPrivateKey ?? PLACEHOLDER_WRITE_KEY,

// REPLACEMENT — fail closed:
if (!nodeIpnsPrivateKey) throw new Error(`rotateOne: no IPNS private key for ${nodeIpnsName} — Phase 65 wires write-body keys`);
// then:
ipnsPrivateKey: nodeIpnsPrivateKey,
```

**D-02: Re-seal bug — wrong key in `rotateOne`** (`engine.ts` L344-350):

```typescript
// CURRENT (BUGGY — seals under child's own pre-rotation key, never written to parent):
const newReadKeySealed = await sealChildReadKey(
  readKeyPrime,
  parentReadKey,   // misnomer: this is the child's OWN pre-rotation key
  nodeId,
  node.kind,
  generationPrime
);
```

The parent-link re-seal MUST happen out-of-band in `rotateReadFromNode` (the BFS caller) under the parent's NEW `readKey'` — not inside `rotateOne`. After each child's `rotateOne` returns, the caller does:

```typescript
// In rotateReadFromNode, after child rotateOne returns (D-02):
const updatedReadKeySealed = await sealChildReadKey(
  childResult.childReadKey,   // child's freshly minted readKey'
  parentNewReadKey,            // parent's NEW readKey' (from parent's rotateOne result)
  childPub.id,                 // PublishedNode.id — plaintext in envelope
  childPub.kind,               // PublishedNode.kind — plaintext in envelope
  childResult.newGeneration    // child's new generation
);
// Write back to parent's in-memory SealedChildRef, then publish parent ONCE (D-09)
```

**D-07: Job-record ordering bug** (`engine.ts` L386 and L458-462):

```typescript
// CURRENT (BUG — completedNodeIds.add before reMintGrantsRootedAt, L386 then L391):
jobRecord.completedNodeIds.add(nodeId);   // L386: too early
if (innerGrants && innerGrants.length > 0) {
  await reMintGrantsRootedAt(...);         // L391: if throws, node is skipped on resume
}

// FIXED (Phase 64):
if (innerGrants && innerGrants.length > 0) {
  await reMintGrantsRootedAt(...);         // re-mint FIRST
}
jobRecord.completedNodeIds.add(nodeId);   // mark done only after ALL work succeeds

// CURRENT resume guard (BUG — L458-462, bypasses verifySubtreeClean):
if (rootResult.skipped) {
  jobRecord.status = 'complete';           // WRONG: skips verifySubtreeClean
  if (jobRecord.persistCallback) await jobRecord.persistCallback(jobRecord);
  return;
}
// FIXED: call verifySubtreeClean to rebuild dirty-edge frontier, continue BFS from it
```

**CAS merge callback shape in `rotateOne`** (`engine.ts` L371-382 — the `merge` callback Phase 64 fills):

```typescript
// Current placeholder in publishWithCas call (engine.ts L371-382):
merge: (_base, local, _remote) => {
  throw new Error(
    'not implemented — phase 64 (ROT-05/HIGH-4 concurrent-add merge): CAS-409 on rotation publish'
  );
  return { merged: local };
},
```

Phase 64 replaces this throw with a call to `mergeConcurrentChildren` and then `mergeChildren` from `folder/merge.ts`.

---

### `packages/sdk-core/src/folder/merge.ts` — Fill `mergeChildren` stub

**Analog:** `publishWithCas` merge callback pattern (`cas.ts` L59-63) + `registration.ts` merge callback (L195-202)

**Existing stub** (`merge.ts`):

```typescript
export function mergeChildren(
  base: SealedChildRef[], local: SealedChildRef[], remote: SealedChildRef[]
): never {
  throw new Error('not implemented — phase 64 (CAS merge on sealed child refs)');
}
```

**Caller pattern** — how the merge callback is wired in `registration.ts` (L195-202):

```typescript
merge: (
  base: SealedChildRef[] | undefined,
  local: SealedChildRef[],
  remote: SealedChildRef[]
) => ({
  merged: mergeChildren(base ?? [], local, remote),
}),
```

**Fill shape** (three-way merge: union by `ipnsName`, remote wins on conflicts, base detects intentional deletes):

```typescript
// Phase 64 body: union local + remote by ipnsName; remote wins on conflict;
// items in base but absent from BOTH local and remote were deleted — do not resurrect.
export function mergeChildren(
  base: SealedChildRef[],
  local: SealedChildRef[],
  remote: SealedChildRef[]
): SealedChildRef[] {
  const baseNames = new Set(base.map((c) => c.ipnsName));
  const byName = new Map<string, SealedChildRef>();
  for (const c of local) byName.set(c.ipnsName, c);
  for (const c of remote) byName.set(c.ipnsName, c); // remote wins on conflict
  // Drop entries deleted in BOTH local and remote relative to base
  for (const name of baseNames) {
    const inLocal = local.some((c) => c.ipnsName === name);
    const inRemote = remote.some((c) => c.ipnsName === name);
    if (!inLocal && !inRemote) byName.delete(name);
  }
  return Array.from(byName.values());
}
```

---

### `packages/sdk-core/src/folder/registration.ts` — Node-identity/generation preservation (D-06)

**Analog:** Self — fix at `registration.ts` L174-175

**Current buggy code** (`registration.ts` L171-179):

```typescript
const node: Node = {
  schema: 'node/v3',
  kind: 'folder',
  id: params.nodeId ?? crypto.randomUUID(),   // BUG: fresh UUID on every call without nodeId
  generation: params.nodeGeneration ?? 0,      // BUG: resets generation to 0
  createdAt: Date.now(),
  modifiedAt: Date.now(),
  children: localChildren,
};
```

**Fix:** Remove both `??` fallbacks; make `nodeId: string` and `nodeGeneration: number` required in the params type. Both fields are already present as optional — just remove the `?` and the fallback expressions.

---

### `packages/sdk/src/client.ts` — Six call sites needing `nodeId`/`nodeGeneration` (D-06)

**Analog:** Self — the six call sites are already in the file; each needs two new fields added.

**Call site pattern** — current form (L493-503, `renameItem`):

```typescript
await sdkCore.updateFolderMetadataAndPublish({
  children: updatedChildren,
  baseChildren,
  folderKey: folder.folderKey,
  ipnsPrivateKey: folder.ipnsKeypair.privateKey,
  ipnsName: folderIpnsName,
  sequenceNumber: folder.sequenceNumber,
  ctx: this.ctx,
  // MISSING: nodeId, nodeGeneration
});
```

**Fixed form** — add from `folder.metadata` (or dedicated `FolderState` fields, per open question in RESEARCH.md):

```typescript
await sdkCore.updateFolderMetadataAndPublish({
  children: updatedChildren,
  baseChildren,
  folderKey: folder.folderKey,
  ipnsPrivateKey: folder.ipnsKeypair.privateKey,
  ipnsName: folderIpnsName,
  sequenceNumber: folder.sequenceNumber,
  nodeId: folder.nodeId,             // from FolderState (required field)
  nodeGeneration: folder.nodeGeneration, // from FolderState (required field)
  ctx: this.ctx,
});
```

All six call sites follow this same shape. The `moveItem` re-seal (FLAG-63-U2) is also in `client.ts` — insert it between `sdkCore.moveItem()` and the dest `updateFolderMetadataAndPublish` call (L579-589):

```typescript
// After sdkCore.moveItem returns movedRef:
const childPub = await resolveAndFetch(movedRef.ipnsName); // re-use resolveAndFetch helper
const childReadKey = await unsealChildReadKey(
  movedRef.readKeySealed, sourceFolder.folderKey,
  childPub.id, childPub.kind, movedRef.generation
);
const newReadKeySealed = await sealChildReadKey(
  childReadKey, destFolder.folderKey,
  childPub.id, childPub.kind, movedRef.generation
);
movedRef = { ...movedRef, readKeySealed: newReadKeySealed };
// then proceed to updateFolderMetadataAndPublish for dest
```

---

### `packages/sdk-core/src/folder/metadata-ops.ts` — `moveItem` (D-06, no change here)

**Status:** No change needed in `metadata-ops.ts`. The pure sync `moveItem` (L132-143) carries `movedRef` unchanged — this is correct. The re-seal is the caller's responsibility (in `client.ts`).

**Current `moveItem`** (`metadata-ops.ts` L132-143) for reference:

```typescript
export function moveItem(params: {
  sourceChildren: SealedChildRef[];
  destChildren: SealedChildRef[];
  childId: string;
}): { updatedSource: SealedChildRef[]; updatedDest: SealedChildRef[]; movedRef: SealedChildRef } {
  const idx = params.sourceChildren.findIndex((c) => c.ipnsName === params.childId);
  if (idx === -1) throw new Error('Item not found');
  const movedRef = params.sourceChildren[idx];
  const updatedSource = params.sourceChildren.filter((c) => c.ipnsName !== params.childId);
  const updatedDest = [...params.destChildren, movedRef];
  return { updatedSource, updatedDest, movedRef };
}
```

---

### `packages/sdk-core/src/__tests__/rotation/engine.test.ts` — Extend existing tests

**Analog:** Self (existing test file) — use the same vi.hoisted + vi.mock pattern

**Existing mock setup pattern** (`engine.test.ts` L29-72) — copy for any new describe block:

```typescript
const mockFns = vi.hoisted(() => ({
  resolveIpnsRecord: vi.fn(),
  fetchFromIpfs: vi.fn(),
  publishWithCas: vi.fn(),
  unsealNode: vi.fn(),
  sealNode: vi.fn(),
  sealChildReadKey: vi.fn(),
  unsealChildReadKey: vi.fn(),
}));

vi.mock('../../ipns', () => ({
  resolveIpnsRecord: mockFns.resolveIpnsRecord,
  createAndPublishIpnsRecord: vi.fn(),
  batchPublishIpnsRecords: vi.fn(),
}));
vi.mock('../../ipfs', () => ({
  fetchFromIpfs: mockFns.fetchFromIpfs,
  addToIpfs: vi.fn(),
  unpinFromIpfs: vi.fn(),
  registerCid: vi.fn(),
}));
vi.mock('../../cas', () => ({ publishWithCas: mockFns.publishWithCas }));
vi.mock('@cipherbox/core', () => ({
  unsealNode: mockFns.unsealNode,
  sealNode: mockFns.sealNode,
  sealChildReadKey: mockFns.sealChildReadKey,
  unsealChildReadKey: mockFns.unsealChildReadKey,
  CryptoError: class CryptoError extends Error { ... },
}));
```

**Existing fixture helpers** (`engine.test.ts` L87-133) — reuse for new tests:

```typescript
function makeFolderNode(overrides?: Partial<Node>): Node { ... }
function makePublishedNode(nodeId, generation, kind): PublishedNode { ... }
function makeJobRecord(overrides?: Partial<RotationJobRecord>): RotationJobRecord { ... }
```

**Phase 64 additions to assert:**
- `mockFns.sealChildReadKey` called with parent's NEW `readKey'` (not old key) for D-02
- `mockFns.publishWithCas` called on parent AFTER all children processed (D-09 batched)
- `completedNodeIds` does NOT contain nodeId when `reMintGrantsRootedAt` throws (D-07 ordering)
- Resume path calls `verifySubtreeClean` and continues BFS (D-07 guard fix)
- `readKeyPrime` is zeroed on failure, `parentReadKey` is NOT zeroed (zeroization invariant)

---

### `packages/sdk-core/src/__tests__/rotation/grant-remint.test.ts` — New unit test (ROT-04/D-04)

**Analog:** `engine.test.ts` vi.hoisted mock pattern (same file) + the "Share module accepts callback functions for API calls" seam from STATE.md

**Pattern to copy:** Same vi.hoisted + vi.mock setup as `engine.test.ts`. The transport-decoupled callbacks are the test seam — mock them directly:

```typescript
// Pattern: inject mock callbacks and assert they are called correctly
const mockQueryGrants = vi.fn();
const mockUpdateGrant = vi.fn();
const mockDeleteGrant = vi.fn();

// Phase-64 D-04 callback shape:
await reMintGrantsRootedAt(
  nodeId,
  newReadKey,
  newGeneration,
  jobRecord,
  ctx,
  {
    queryGrantsFn: mockQueryGrants,
    updateGrantFn: mockUpdateGrant,
    deleteGrantFn: mockDeleteGrant,
  }
);

// Assert: revoked grantee's deleteGrantFn called, not updateGrantFn
expect(mockDeleteGrant).toHaveBeenCalledWith(revokedShareId);
expect(mockUpdateGrant).not.toHaveBeenCalledWith(revokedShareId, expect.anything(), expect.anything());

// Assert: non-revoked grantee's updateGrantFn called with new readDescriptorRef + generation
expect(mockUpdateGrant).toHaveBeenCalledWith(
  validShareId,
  expect.any(String), // ECIES-wrapped readDescriptorRef
  newGeneration
);
```

Also mock `@cipherbox/crypto`'s `wrapKey` to assert ECIES wrapping is called per non-revoked grantee.

---

### `tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts` — New (TEST-01/D-03)

**Analog:** `tests/sdk-e2e/src/suites/read-chain-navigation.test.ts` (Phase-63 scaffold)

**Imports pattern** (copy from `read-chain-navigation.test.ts` L30-50):

```typescript
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import {
  createSubfolder,
  addFilePointerToFolder,
  updateFolderMetadataAndPublish,
  addToIpfs,
  createAndPublishIpnsRecord,
  rotateReadFromNode,
  type RotationJobRecord,
} from '@cipherbox/sdk-core';
import { sealNode } from '@cipherbox/core';
import type { Node } from '@cipherbox/core';
import {
  generateEd25519Keypair,
  deriveEd25519PublicKey,
  deriveIpnsName,
  generateRandomBytes,
} from '@cipherbox/crypto';
import { createMultiAccountFixture, type MultiAccountFixture } from '../fixtures/multi-account';
```

**Manual-node tree build pattern** (Phase-63 analog, `read-chain-navigation.test.ts` L76-186):

Step 1 — create root folder via `createSubfolder` (provides known keypair, publishes seq 1n):
```typescript
const folderResult = await createSubfolder({ name: 'crash-test-root', ctx: aliceCtx });
const folderIpnsPublicKey = deriveEd25519PublicKey(folderResult.ipnsPrivateKey);
const folderIpnsName = await deriveIpnsName(folderIpnsPublicKey);
```

Step 2 — create subfolder (depth ≥ 2 for D-03 — extend beyond Phase-63's single level):
```typescript
const subfolderResult = await createSubfolder({ name: 'sub', ctx: aliceCtx });
// derive subfolderIpnsName, store keypair in keyMap
```

Step 3 — manually create file node (same pattern as `read-chain-navigation.test.ts` L111-158):
```typescript
const fileIpnsKeypair = generateEd25519Keypair();
const fileIpnsName = await deriveIpnsName(fileIpnsKeypair.publicKey);
const fileReadKey = generateRandomBytes(32);
const fileNode: Node = {
  schema: 'node/v3', kind: 'file', id: crypto.randomUUID(), generation: 0,
  createdAt: Date.now(), modifiedAt: Date.now(),
  content: { cid: PLACEHOLDER_CID, fileKey: generateRandomBytes(32), ... },
};
const publishedFileNode = await sealNode(fileNode, fileReadKey, new Uint8Array(32));
const { cid: fileNodeIpfsCid } = await addToIpfs(aliceCtx, new TextEncoder().encode(JSON.stringify(publishedFileNode)));
await createAndPublishIpnsRecord({
  ipnsPrivateKey: fileIpnsKeypair.privateKey,
  ipnsPublicKey: fileIpnsKeypair.publicKey,
  ipnsName: fileIpnsName,
  metadataCid: fileNodeIpfsCid,
  sequenceNumber: 1n,   // CRITICAL: first publish must be 1n
  ctx: aliceCtx,
});
```

Step 4 — `updateFolderMetadataAndPublish` with `nodeId` + `nodeGeneration` (Phase-64 required fields):
```typescript
await updateFolderMetadataAndPublish({
  children: updatedChildren,
  readKey: folderResult.rootReadKey,
  ipnsPrivateKey: folderResult.ipnsPrivateKey,
  ipnsPublicKey: folderIpnsPublicKey,
  ipnsName: folderIpnsName,
  sequenceNumber: 1n,
  nodeId: folderResult.node.id,       // required in Phase 64
  nodeGeneration: folderResult.node.generation,  // required in Phase 64
  ctx: aliceCtx,
});
```

**Per-node keymap for D-01 fail-closed engine:**
```typescript
const keyMap = new Map<string, { privateKey: Uint8Array; publicKey: Uint8Array }>();
keyMap.set(folderIpnsName, { privateKey: folderResult.ipnsPrivateKey, publicKey: folderIpnsPublicKey });
keyMap.set(subfolderIpnsName, { privateKey: subfolderKeypair.privateKey, publicKey: subfolderKeypair.publicKey });
keyMap.set(fileIpnsName, { privateKey: fileIpnsKeypair.privateKey, publicKey: fileIpnsKeypair.publicKey });
// Thread keyMap into rotationParams via a test-provided key source (Claude's discretion on exact shape)
```

**Fault injection pattern** (throw-after-N per D-03 — test-only, not production code):
```typescript
let committed = 0;
const originalPersistCallback = (job: RotationJobRecord) => {
  committed++;
  if (committed >= N) throw new Error('simulated-crash');
};
// First run: catch the throw
let crashed = false;
try {
  await rotateReadFromNode({ ..., jobRecord: { ...jobRecord, persistCallback: originalPersistCallback } });
} catch { crashed = true; }
expect(crashed).toBe(true);

// Resume: fresh jobRecord, verifySubtreeClean rebuilds frontier
const freshJob: RotationJobRecord = {
  rootNodeId: folderNodeId, status: 'pending', completedNodeIds: new Set(), frontier: [],
};
await rotateReadFromNode({ ..., jobRecord: freshJob }); // must converge
// Assert: no double-bump — every node's generation == baseline + 1
```

**Test timeout** (copy from `read-chain-navigation.test.ts` L310):
```typescript
}, 120_000); // 2-minute timeout: live IPNS round-trips involve multiple publish/resolve cycles
```

---

## Shared Patterns

### CAS Publish / `publishWithCas` Merge Callback
**Source:** `packages/sdk-core/src/cas.ts` L38-135
**Apply to:** `engine.ts` (fill `merge` callback in `rotateOne`'s `publishWithCas` call); `registration.ts` (already uses this pattern)

The `merge` callback shape (`cas.ts` L59-63):
```typescript
merge: (
  base: TData | undefined,
  local: TData,
  remote: TData
) => { merged: TData; prunedCids?: string[] };
```

On CAS-409, `publishWithCas` calls `merge(baseData, localData, remoteData)` — the rotation engine fills this with `mergeConcurrentChildren` + `mergeChildren`.

### `createAndPublishIpnsRecord` — First-Publish Sequence Convention
**Source:** `packages/sdk-core/src/ipns/index.ts` L39-49
**Apply to:** `tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts` (all new-node IPNS publishes)

```typescript
// First publish: sequenceNumber MUST be 1n (Phase-60 strict gate rejects 0 or other values)
await createAndPublishIpnsRecord({
  ipnsPrivateKey, ipnsPublicKey, ipnsName, metadataCid,
  sequenceNumber: 1n,   // embeds the arg verbatim
  ctx,
});
// Subsequent publishes via publishWithCas: pass sequenceNumber: 0n as base (publishWithCas embeds base+1)
```

### Zeroization — Terminal-Owner Rule
**Source:** `engine.ts` L401-405 (existing pattern in `rotateOne`)
**Apply to:** All new engine helpers in Phase 64

```typescript
// rotateOne zeros readKeyPrime on failure — it minted it (terminal owner):
} catch (err) {
  readKeyPrime.fill(0);  // engine minted this; engine zeros it on failure
  throw err;             // DO NOT zero parentReadKey — caller is terminal owner (D-09)
}
// Never zero: parentReadKey, rootReadKey, or any caller-supplied buffer
// Zero BFS queue-derived child readKeys AFTER their children are enqueued (terminal-owner)
```

### Vi.hoisted Mock Pattern
**Source:** `engine.test.ts` L29-72
**Apply to:** `grant-remint.test.ts` (new unit test for D-04)

Use `vi.hoisted` + `vi.mock` with factory pattern. Module mocks must be declared at the top level, before any describe block.

---

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `verifySubtreeClean` implementation (within engine.ts) | utility | CRUD (BFS IPNS resolve walk) | No existing BFS IPNS read-only pass exists; design §4.5 is the spec; `resolveIpnsRecord` + `fetchPublishedNode` helpers in `engine.ts` are the building blocks |

---

## Metadata

**Analog search scope:** `packages/sdk-core/src/rotation/`, `packages/sdk-core/src/folder/`, `packages/sdk/src/`, `packages/sdk-core/src/__tests__/rotation/`, `tests/sdk-e2e/src/suites/`
**Files scanned:** 9 source files read in full
**Pattern extraction date:** 2026-06-29

---

## PATTERN MAPPING COMPLETE

**Phase:** 64 - rotation-soundness-revocation-guarantees
**Files classified:** 10
**Analogs found:** 9 / 10

### Coverage

- Files with exact analog (self-modification): 5 (`engine.ts`, `registration.ts`, `client.ts`, `metadata-ops.ts`, `engine.test.ts`)
- Files with role-match analog: 4 (`merge.ts` via cas pattern, `grant-remint.test.ts` via engine.test.ts, `rotation-crash-safety.test.ts` via read-chain-navigation.test.ts, `registration.ts` call-site pattern)
- Files with no analog: 1 (`verifySubtreeClean` internals — spec-driven)

### Key Patterns Identified

- All seam fills replace a single `throw` line; signatures are frozen — copy the stub param name (strip leading underscore), fill the body
- `publishWithCas` `merge` callback is the entry point for HIGH-4 concurrent-add merge; `mergeChildren` in `folder/merge.ts` is the three-way merge domain logic it calls
- sdk-e2e crash-safety suite extends the Phase-63 `read-chain-navigation.test.ts` scaffold exactly: same imports, same `sealNode + addToIpfs + createAndPublishIpnsRecord(seq: 1n)` tree-build, same 120s timeout — only extends to depth ≥ 2 and adds fault-injection + resume assertions
- `updateFolderMetadataAndPublish` node-identity fix is a two-field addition (`nodeId`, `nodeGeneration`) at one source site (`registration.ts` L174-175) and six call sites in `client.ts` — all call sites follow identical shape, add the same two fields from `FolderState`
- Zeroization rule is already encoded in `engine.ts` L401-405 (catch block); every new helper copies this pattern verbatim

### File Created

`/Users/myankelev/Code/random/cipher-box/.planning/phases/64-rotation-soundness-revocation-guarantees/64-PATTERNS.md`

### Ready for Planning

Pattern mapping complete. Planner can now reference analog patterns in PLAN.md files.
