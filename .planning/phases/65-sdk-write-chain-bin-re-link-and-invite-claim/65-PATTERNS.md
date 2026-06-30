# Phase 65: SDK Write-Chain, Bin Re-link, and Invite Claim - Pattern Map

**Mapped:** 2026-06-30
**Files analyzed:** 7 new/modified files
**Analogs found:** 7 / 7

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `packages/core/src/node/seal.ts` (add `sealChildWriteKey`/`unsealChildWriteKey`) | utility | transform | Same file — `sealChildReadKey`/`unsealChildReadKey` at lines 187–224 | exact |
| `packages/sdk-core/src/rotation/engine.ts` (wire writeKey + add `rotateWriteFromNode`) | service | event-driven | Same file — `rotateReadFromNode` / `rotateOne` | exact |
| `packages/sdk/src/share/shared-write.ts` (rewrite all 6 stubs) | service | request-response | `packages/sdk-core/src/share/grant.ts` (`issueReadGrant`/`claimInviteReadKey`) | role-match |
| `packages/sdk/src/bin/index.ts` (implement `addToBin`/`restoreFromBin`) | service | CRUD | Same file — `permanentDeleteFromBin` (lines 324–354) | exact |
| Invite-claim wiring in `packages/sdk-core`/`packages/sdk` | service | request-response | `packages/sdk-core/src/share/grant.ts` — `claimInviteReadKey` (lines 184–224) | exact |
| `tests/sdk-e2e/src/suites/write-chain-rotation.test.ts` (new) | test | event-driven | `tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts` | exact |
| `packages/sdk-core/src/__tests__/rotation/write-revocation.test.ts` (new) | test | event-driven | Existing rotation unit tests in `packages/sdk-core/src/__tests__/` | role-match |

---

## Pattern Assignments

### `packages/core/src/node/seal.ts` — add `sealChildWriteKey` / `unsealChildWriteKey`

**Analog:** Same file, lines 187–224 (`sealChildReadKey` / `unsealChildReadKey`, role 0x02).

**Copy-from pattern** (seal.ts lines 187–224):

```typescript
// Role 0x02 — child-readkey — the DIRECT copy template for role 0x04 child-writekey.
export async function sealChildReadKey(
  childReadKey: Uint8Array,
  parentReadKey: Uint8Array,
  childId: string,
  childKind: NodeKind,
  childGeneration: number
): Promise<string> {
  const kb = kindByte(childKind);
  const aad = buildNodeAad(childId, kb, childGeneration, 0x02 /* child-readkey */);
  const sealed = await sealAesGcmAad(childReadKey, parentReadKey, aad);
  // Do NOT zero childReadKey: caller is terminal owner (D-09)
  return uint8ArrayToBase64(sealed);
}

export async function unsealChildReadKey(
  sealedBase64: string,
  parentReadKey: Uint8Array,
  childId: string,
  childKind: NodeKind,
  childGeneration: number
): Promise<Uint8Array> {
  const kb = kindByte(childKind);
  const aad = buildNodeAad(childId, kb, childGeneration, 0x02 /* child-readkey */);
  const sealedBytes = base64ToUint8Array(sealedBase64);
  return unsealAesGcmAad(sealedBytes, parentReadKey, aad);
}
```

**What changes for role 0x04:**

- Rename `sealChildReadKey` → `sealChildWriteKey`; `unsealChildReadKey` → `unsealChildWriteKey`
- Parameters: `childReadKey`/`parentReadKey` → `childWriteKey`/`parentWriteKey`
- Role byte: `0x02` → `0x04` in both `buildNodeAad` calls
- Comment: `child-readkey` → `child-writekey`
- Everything else is identical — same `kindByte`, `uint8ArrayToBase64`, `base64ToUint8Array`, `sealAesGcmAad`, `unsealAesGcmAad`

**Imports pattern** (seal.ts lines 27–31) — no new imports needed; all primitives already present:

```typescript
import { sealAesGcmAad, unsealAesGcmAad, buildNodeAad, CryptoError } from '@cipherbox/crypto';
// uint8ArrayToBase64 / base64ToUint8Array are file-local helpers (lines 41–59)
// kindByte is a file-local helper (lines 65–71)
```

**Security invariants to copy verbatim** (seal.ts lines 18–19):

```typescript
// - Never zero a caller-supplied or returned key buffer (D-09: caller is terminal owner).
// - Never reimplement AES/AAD — always compose the Phase-61 primitive.
```

---

### `packages/sdk-core/src/rotation/engine.ts` — wire real writeKey + add `rotateWriteFromNode`

**Analog:** Same file — `rotateOne` (lines 473–652) and `rotateReadFromNode` (lines 675–end).

#### PLACEHOLDER_WRITE_KEY removal pattern

**Current code at lines 547–550** (the PLACEHOLDER_WRITE_KEY to remove):

```typescript
// Step 6: Re-seal the read-body under readKey' with the new generation'.
const updatedNode: Node = { ...node, generation: generationPrime };
// Placeholder writeKey: unused because updatedNode.writeBody is absent (D-09 safe).
const PLACEHOLDER_WRITE_KEY = new Uint8Array(32);
const resealedPublished = await sealNode(updatedNode, readKeyPrime, PLACEHOLDER_WRITE_KEY);
```

**Also at lines 594–604** (the CAS merge path — same placeholder):

```typescript
const mergedPublished = await mergeConcurrentChildren(
  base, remote, parentReadKey,
  node.children ?? [],
  readKeyPrime,
  node, generationPrime,
  PLACEHOLDER_WRITE_KEY  // ← remove this; pass real nodeWriteKey
);
```

**Replacement pattern:** `rotateOne` receives a `nodeWriteKey?: Uint8Array` parameter. When unsealing a node that has a write-body, call `unsealNode(published, parentReadKey, nodeWriteKey)` instead of `unsealNode(published, parentReadKey)`. Re-seal with the real `nodeWriteKey` instead of the placeholder. The fail-closed guard (lines 514–524) is the pattern for the analogous writeKey guard:

```typescript
// D-01 fail-closed guard (lines 514–524) — copy this pattern for writeKey when writeBody present
if (
  !(nodeIpnsPrivateKey instanceof Uint8Array) ||
  nodeIpnsPrivateKey.length !== 32 ||
  nodeIpnsPrivateKey.every((byte) => byte === 0)
) {
  throw new Error(
    `rotateOne: no valid IPNS private key for ${nodeIpnsName} — ` +
      'provide via nodeKeySource (Phase 64) or write-body wiring (Phase 65)'
  );
}
```

#### GrantRemintCallbacks type pattern (lines 53–65) — copy for WriteRevocationCallbacks

```typescript
// Source: engine.ts lines 53–65 — GrantRemintCallbacks type shape
export type GrantRemintCallbacks = {
  queryGrantsFn: (
    nodeId: string
  ) => Promise<
    ReadonlyArray<{ shareId: string; recipientPublicKey: Uint8Array; isRevoked: boolean }>
  >;
  updateGrantFn: (shareId: string, readDescriptorRef: string, newGeneration: number) => Promise<void>;
  deleteGrantFn: (shareId: string) => Promise<void>;
};
// → WriteRevocationCallbacks follows the same shape with:
//   queryWriteGrantsFn, writeDescriptorRefPersistFn, teeUnenrollFn
```

#### RotationJobRecord pattern (lines 78–105) — reference for write-revocation job shape

The write-revocation driver (`rotateWriteFromNode`) should define its own job record type following the same pattern: `status`, `completedNodeIds: Set<string>`, `frontier`, optional `persistCallback`.

#### rotateReadFromNode BFS pattern (lines 675–820) — structural template for `rotateWriteFromNode`

Key differences: write-revocation is child-first (bottom-up, not root-first); mints new Ed25519 keypair + new k51 name per node (via `generateEd25519Keypair()` + `deriveIpnsName()`); first-publishes to the new name via `createAndPublishIpnsRecord({..., sequenceNumber: 1n})`; fires `teeUnenrollFn(oldIpnsName)` after each new-name publish; updates parent's `SealedChildRef.ipnsName` pointing to the new k51.

**Import pattern** (engine.ts lines 27–35) — add `sealChildWriteKey`/`unsealChildWriteKey` and crypto helpers:

```typescript
import { sealNode, unsealNode, sealChildReadKey, unsealChildReadKey } from '@cipherbox/core';
// Phase 65 additions:
// import { sealChildWriteKey, unsealChildWriteKey } from '@cipherbox/core';
import { generateRandomBytes, wrapKey } from '@cipherbox/crypto';
// Phase 65 additions:
// import { generateEd25519Keypair, deriveIpnsName } from '@cipherbox/crypto';
import { publishWithCas } from '../cas';
import { resolveIpnsRecord } from '../ipns';
import { fetchFromIpfs, addToIpfs } from '../ipfs';
import type { SdkContext } from '../types';
```

**Zeroization pattern** (engine.ts lines 641–651) — copy for `rotateWriteFromNode`:

```typescript
// Zero minted keys on failure — NEVER zero caller-supplied keys (D-09)
} catch (err) {
  readKeyPrime.fill(0);         // rotateOne MINTED this — it owns it on failure
  // DO NOT zero parentReadKey — caller is terminal owner (D-09)
  if (fileKeyMinted && node.content?.fileKey) {
    node.content.fileKey.fill(0);
  }
  throw err;
}
// In rotateWriteFromNode: zero newWriteKey and newIpnsPrivKey on failure paths only.
```

---

### `packages/sdk/src/share/shared-write.ts` — rewrite all 6 stubs

**Analog:** `packages/sdk-core/src/share/grant.ts` — specifically the transport-decoupled callback injection pattern (lines 100–145).

**SharedWriteContext reshape pattern** — the existing type at lines 28–59 carries raw `folderKey: Uint8Array` and `ipnsPrivateKey: Uint8Array` as top-level parameters. In the write-body model, `ipnsPrivateKey` comes from unsealing the write-body (not from a raw parameter). The type should be reshaped to carry `writeKey: Uint8Array` (the node's write-body decryption key) from which `writeBody.ipnsPrivateKey` is derived after unsealing. `addShareKeysFn` stays as a typed field (Phase 68 removes it) but is never called.

**Callback injection pattern** (grant.ts lines 100–107) — mirror for write operations:

```typescript
// grant.ts: insertShareFn is injected so tests pass vi.fn() without API coupling.
export async function issueReadGrant(params: {
  // ...
  insertShareFn: (payload: ReadGrantPayload) => Promise<{ shareId: string }>;
}): Promise<{ shareId: string; readDescriptorRef: string }> {
  // crypto work first; callback last (never called on crypto failure)
  const result = await params.insertShareFn({ ... });
  return { shareId: result.shareId, readDescriptorRef };
}
// In shared-write.ts: each write op takes a publishFn / persistFn callback
// so Phase 65 is mock-testable without live apps/api (D-02).
```

**Input validation pattern** (grant.ts lines 109–123) — copy for write-key inputs:

```typescript
if (params.shareRootReadKey.length !== 32) {
  throw new Error(`issueReadGrant: shareRootReadKey must be 32 bytes, got ${params.shareRootReadKey.length}`);
}
if (params.recipientPublicKey.length !== 65) {
  throw new Error(`issueReadGrant: recipientPublicKey must be 65 bytes ...`);
}
// → In shared-write.ts: guard writeKey.length === 32, ipnsPrivateKey.length === 32
```

**Error handling pattern** (grant.ts lines 128–133):

```typescript
let wrapped: Uint8Array;
try {
  wrapped = await wrapKey(params.shareRootReadKey, params.recipientPublicKey);
} catch (err) {
  throw new Error('issueReadGrant: key wrapping failed', { cause: err });
}
// → shared-write.ts: wrap crypto failures with { cause: err }; re-throw; zero minted keys.
```

---

### `packages/sdk/src/bin/index.ts` — implement `addToBin` and `restoreFromBin`

**Analog:** Same file — `permanentDeleteFromBin` (lines 324–354) for the bin metadata save/update pattern.

**Bin metadata load/save pattern** (bin/index.ts lines 60–100):

```typescript
// Load
async function loadBinMetadataInternal(params: { userPrivateKey: Uint8Array; ctx: SdkContext }) {
  const binIpns = await deriveBinIpnsKeypair(params.userPrivateKey);
  const resolved = await sdkCore.resolveIpnsRecord(binIpns.ipnsName, params.ctx);
  if (!resolved) return null;
  const encryptedBytes = await sdkCore.fetchFromIpfs(params.ctx, resolved.cid);
  const metadata = await decryptBinMetadata(encryptedBytes, params.userPrivateKey);
  return { metadata, ipnsName: binIpns.ipnsName, sequenceNumber: resolved.sequenceNumber };
}

// Save
async function saveBinMetadata(params: { metadata: RecycleBinMetadata; binCtx: BinOperationContext }) {
  const binIpns = await deriveBinIpnsKeypair(params.binCtx.userPrivateKey);
  const encryptedBytes = await encryptBinMetadata(params.metadata, params.binCtx.userPublicKey);
  const { cid } = await sdkCore.addToIpfs(params.binCtx.ctx, encryptedBytes);
  // ... TEE enrollment + publishWithCas
}
```

**permanentDeleteFromBin pattern** (lines 324–354) — the exact template for how `addToBin` and `restoreFromBin` should update bin metadata and call `saveBinMetadata`:

```typescript
export async function permanentDeleteFromBin(params: { entryId: string; binState: BinState; binCtx: BinOperationContext }) {
  const entry = params.binState.entries.find((e) => e.id === params.entryId);
  if (!entry) throw new Error('Bin entry not found');
  // mutate entries array, increment sequenceNumber
  const remainingEntries = params.binState.entries.filter((e) => e.id !== params.entryId);
  const newBinSeq = params.binState.sequenceNumber + 1;
  const metadata: RecycleBinMetadata = { version: BIN_METADATA_VERSION, sequenceNumber: newBinSeq, entries: remainingEntries };
  await saveBinMetadata({ metadata, binCtx: params.binCtx });
  return { updatedBinState: { entries: remainingEntries, sequenceNumber: newBinSeq, ipnsName: params.binState.ipnsName } };
}
```

**Bin restore re-link pattern:** `restoreFromBin` retrieves the `BinEntry`, uses `sealChildReadKey` (from `@cipherbox/core`) to re-seal the node's `readKey` under the destination parent's `readKey`, inserts the new `SealedChildRef` into the parent folder, and removes the entry from bin metadata. The `addFilePointerToFolder` helper in `sdk-core/src/folder/metadata-ops.ts` is the downstream analog for inserting a child ref.

**Imports pattern** (bin/index.ts lines 17–28) — already correct; `sealChildReadKey` needs adding from `@cipherbox/core`:

```typescript
import type { SdkContext, TeeKeys } from '@cipherbox/sdk-core';
import * as sdkCore from '@cipherbox/sdk-core';
import {
  encryptBinMetadata, decryptBinMetadata, deriveBinIpnsKeypair,
  type BinEntry, type RecycleBinMetadata,
} from '@cipherbox/core';
import type { SealedChildRef } from '@cipherbox/core';
// Phase 65: import { sealChildReadKey } from '@cipherbox/core';
```

---

### Invite-claim wiring — `packages/sdk-core`/`packages/sdk`

**Analog:** `packages/sdk-core/src/share/grant.ts` — `claimInviteReadKey` (lines 184–224, already implemented).

**claimInviteReadKey pattern** (lines 184–224) — the crypto primitive is complete; Phase 65 adds the service flow wiring around it:

```typescript
// Already implemented — Phase 65 wires the full flow:
// 1. GET /invites/{token}/data → invite.readDescriptorRef
// 2. claimInviteReadKey({ readDescriptorRef, ephemeralPrivateKey, claimerPublicKey })
// 3. insertShareFn persists standard grant row (mocked behind D-02 seam)
//
// Delete any sdk-layer code that reads encryptedChildKeys from invite data.
export async function claimInviteReadKey(params: {
  readDescriptorRef: string;
  ephemeralPrivateKey: Uint8Array;  // 32-byte secp256k1 private key from URL fragment
  claimerPublicKey: Uint8Array;     // 65-byte uncompressed secp256k1
}): Promise<string> {
  // reWrapKey: unwrap with ephemeralPrivateKey, re-wrap to claimerPublicKey.
  // Intermediate readKey is zeroed inside reWrapKey (terminal ownership delegated).
  const claimerWrapped = await reWrapKey(inviteWrapped, params.ephemeralPrivateKey, params.claimerPublicKey);
  return bytesToBase64(claimerWrapped);
}
```

**Service flow callback injection pattern** (grant.ts lines 136–145) — the `insertShareFn` shape is the model for wiring `claimInviteReadKey` into a full service function with a mocked persist callback (D-02):

```typescript
const result = await params.insertShareFn({
  recipientPublicKey: params.recipientPublicKey,
  rootNodeId: params.rootNodeId,
  rootIpnsName: params.rootIpnsName,
  rootGeneration: params.rootGeneration,
  readDescriptorRef,
});
return { shareId: result.shareId, readDescriptorRef };
```

---

### `tests/sdk-e2e/src/suites/write-chain-rotation.test.ts` (new)

**Analog:** `tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts` — the Phase-63/64 manual-node-build + IPNS publish + assertion pattern. Copy the full file structure.

**Suite setup pattern** (rotation-crash-safety.test.ts lines 31–103):

```typescript
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  addToIpfs, createAndPublishIpnsRecord, resolveIpnsRecord,
  type SdkContext,
} from '@cipherbox/sdk-core';
import { sealNode, unsealNode } from '@cipherbox/core';  // + sealChildWriteKey, unsealChildWriteKey
import type { Node, PublishedNode } from '@cipherbox/core';
import { deriveEd25519PublicKey, deriveIpnsName, generateEd25519Keypair, generateRandomBytes } from '@cipherbox/crypto';
import { type MultiAccountFixture, createMultiAccountFixture } from '../fixtures/multi-account';

let fixture: MultiAccountFixture;
beforeAll(async () => { fixture = await createMultiAccountFixture(['alice', 'bob']); });
afterAll(async () => { if (fixture) await fixture.cleanupAll(); vi.restoreAllMocks(); });
```

**Manual node build pattern with real write-body** (extends rotation-crash-safety.test.ts lines 144–164):

```typescript
// rotation-crash-safety.test.ts lines 144–164 (publishFileNode helper):
async function publishFileNode(node, readKey, ctx) {
  const keypair = generateEd25519Keypair();  // synchronous
  const ipnsName = await deriveIpnsName(keypair.publicKey);
  const dummyWriteKey = new Uint8Array(32);
  const pub = await sealNode(node, readKey, dummyWriteKey);
  const { cid } = await addToIpfs(ctx, new TextEncoder().encode(JSON.stringify(pub)));
  await createAndPublishIpnsRecord({
    ipnsPrivateKey: keypair.privateKey, ipnsPublicKey: keypair.publicKey,
    ipnsName, metadataCid: cid,
    sequenceNumber: 1n,  // MUST be 1n for first publish (strict gate)
    ctx,
  });
  return { ipnsName, keypair };
}

// Phase 65 extension — a write-capable node:
async function publishWriteCapableNode(node: Node, readKey: Uint8Array, writeKey: Uint8Array, ctx: SdkContext) {
  const keypair = generateEd25519Keypair();
  const ipnsName = await deriveIpnsName(keypair.publicKey);
  const nodeWithWriteBody: Node = { ...node, writeBody: { ipnsPrivateKey: keypair.privateKey, writeChildren: [] } };
  const pub = await sealNode(nodeWithWriteBody, readKey, writeKey);
  const { cid } = await addToIpfs(ctx, new TextEncoder().encode(JSON.stringify(pub)));
  await createAndPublishIpnsRecord({ ipnsPrivateKey: keypair.privateKey, ipnsPublicKey: keypair.publicKey, ipnsName, metadataCid: cid, sequenceNumber: 1n, ctx });
  return { ipnsName, keypair };
}
```

**fetchPublishedEnvelope helper** (rotation-crash-safety.test.ts lines 112–117) — copy verbatim:

```typescript
async function fetchPublishedEnvelope(ipnsName: string, ctx: SdkContext): Promise<PublishedNode> {
  const resolved = await resolveIpnsRecord(ipnsName, ctx);
  if (!resolved) throw new Error(`fetchPublishedEnvelope: IPNS not found: ${ipnsName}`);
  const raw = await fetchFromIpfs(ctx, resolved.cid);
  return JSON.parse(new TextDecoder().decode(raw)) as PublishedNode;
}
```

**Key map / nodeKeySource injection pattern** (rotation-crash-safety.test.ts lines 243–248):

```typescript
const keyMap = new Map([
  [rootIpnsName, { privateKey: rootResult.ipnsPrivateKey, publicKey: rootIpnsPublicKey }],
  [subIpnsName, { privateKey: subResult.ipnsPrivateKey, publicKey: subIpnsPublicKey }],
]);
const nodeKeySource = (name: string) => keyMap.get(name);
// Phase 65: for rotateWriteFromNode, inject a writeKeyMap analogously.
```

**Mock callback injection pattern** — the write-revocation test should inject `vi.fn()` mocks for `teeUnenrollFn`, `queryWriteGrantsFn`, `writeDescriptorRefPersistFn` and assert they were called with the correct old IPNS names / share IDs after `rotateWriteFromNode` completes. Copy the `vi.spyOn` + capture pattern from rotation-crash-safety.test.ts lines 86–97.

---

## Shared Patterns

### Zeroization — terminal owner only

**Source:** `packages/sdk-core/src/rotation/engine.ts` lines 641–651; `packages/core/src/node/seal.ts` lines 17–19.
**Apply to:** ALL new functions in seal.ts, engine.ts, shared-write.ts.

```typescript
// Zero keys the CURRENT function MINTED on failure paths only — never on success.
// NEVER zero caller-supplied buffers (parentReadKey, parentWriteKey, nodeWriteKey, etc.)
} catch (err) {
  mintedKey.fill(0);  // only keys THIS function generated via generateRandomBytes / generateEd25519Keypair
  throw err;
}
```

### Transport-decoupled callback injection (D-02 / Phase-64 discipline)

**Source:** `packages/sdk-core/src/share/grant.ts` lines 100–145; `packages/sdk-core/src/rotation/engine.ts` lines 53–65.
**Apply to:** `rotateWriteFromNode`, shared-write.ts write ops, invite-claim service function.

All apps/api persistence calls are injected as typed callback parameters (`insertShareFn`, `queryWriteGrantsFn`, `writeDescriptorRefPersistFn`, `teeUnenrollFn`). Tests pass `vi.fn()`. Production callers (Phase 66) supply real API calls.

### Error wrapping with cause

**Source:** `packages/sdk-core/src/share/grant.ts` lines 128–133.
**Apply to:** All new crypto operations in shared-write.ts, invite-claim wiring, rotateWriteFromNode.

```typescript
try {
  result = await cryptoOp(...);
} catch (err) {
  throw new Error('descriptive: operation failed', { cause: err });
}
```

### Input validation — fail-closed before crypto

**Source:** `packages/sdk-core/src/share/grant.ts` lines 109–123; `packages/sdk-core/src/rotation/engine.ts` lines 514–524.
**Apply to:** `sealChildWriteKey`, `unsealChildWriteKey`, `rotateWriteFromNode`, `shared-write.ts` write ops.

Validate lengths and reject all-zero keys before any `sealAesGcmAad`, `wrapKey`, or IPNS publish. The engine.ts guard at lines 514–524 is the pattern for the writeKey analog in `rotateOne`.

### First-publish sequence number

**Source:** `tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts` line 160.
**Apply to:** Every `createAndPublishIpnsRecord` call for a NEW k51 name in write-revocation.

```typescript
await createAndPublishIpnsRecord({
  ipnsPrivateKey, ipnsPublicKey, ipnsName, metadataCid: cid,
  sequenceNumber: 1n,  // MUST be 1n — strict gate rejects any other value for new names
  ctx,
});
```

### String literals over enums

**Source:** `packages/sdk-core/src/rotation/engine.ts` lines 40–68 (`RotationStatus`, `GrantRemintCallbacks` use string-literal unions, not enums).
**Apply to:** All new types in this phase (`WriteRevocationCallbacks`, job status, error codes).

---

## No Analog Found

None. All files have exact or role-match analogs in the codebase.

---

## Metadata

**Analog search scope:** `packages/core/src/node/`, `packages/sdk-core/src/rotation/`, `packages/sdk-core/src/share/`, `packages/sdk/src/share/`, `packages/sdk/src/bin/`, `tests/sdk-e2e/src/suites/`
**Files scanned:** 7 primary source files read in full
**Pattern extraction date:** 2026-06-30
