# Phase 63: Read-Chain Navigation and Rotation Core — Pattern Map

**Mapped:** 2026-06-29
**Files analyzed:** 10
**Analogs found:** 10 / 10

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `packages/sdk-core/src/folder/load.ts` | service | request-response (IPNS resolve + IPFS fetch + unseal) | `packages/sdk-core/src/ipns/index.ts` (resolveIpnsRecord) + `packages/core/src/node/seal.ts` (unsealNode) | role-match |
| `packages/sdk-core/src/folder/metadata-ops.ts` | utility | transform (SealedChildRef mutation) | `packages/core/src/node/seal.ts` (sealChildReadKey/unsealChildReadKey) | role-match |
| `packages/sdk-core/src/folder/registration.ts` | service | CRUD + publish | `packages/sdk-core/src/cas.ts` (publishWithCas) + `packages/sdk-core/src/ipns/index.ts` (createAndPublishIpnsRecord) | role-match |
| `packages/sdk-core/src/rotation/engine.ts` (NEW) | service | event-driven BFS walk + CAS publish | `packages/sdk-core/src/cas.ts` (publishWithCas retry loop) | partial-match |
| `packages/sdk-core/src/share/grant.ts` (NEW) | utility | request-response (ECIES wrap/unwrap) | `packages/sdk/src/share/index.ts` (createShareKey, transport-decoupled callback seam) | role-match |
| `packages/sdk/src/share/index.ts` (DELETE reWrapForRecipients L88) | utility | — (deletion) | `packages/sdk/src/share/index.ts` itself | exact |
| `packages/sdk/src/client.ts` (rewire L164, L1602) | service | CRUD | `packages/sdk/src/client.ts` L164 pattern | exact |
| `packages/sdk-core/src/__tests__/rotation/engine.test.ts` (NEW) | test | — | `packages/sdk-core/src/__tests__/cas.test.ts` | exact |
| `packages/sdk-core/src/__tests__/folder.test.ts` (revive TODO blocks) | test | — | existing file (quarantine markers at L105, L248, L445, L491, L515, L563) | exact |
| `packages/sdk/src/__tests__/client-extended.test.ts` (revive L133) | test | — | existing file | exact |

---

## Pattern Assignments

### `packages/sdk-core/src/folder/load.ts` (service, request-response)

**Stubs to un-stub:** `fetchAndDecryptMetadata` (L23), `loadFolderMetadata` (L43).

**Analog 1:** `packages/sdk-core/src/ipns/index.ts` — `resolveIpnsRecord` (L193)

**Imports pattern** (lines 1-23 of ipns/index.ts):
```typescript
import { createIpnsRecord, marshalIpnsRecord, IPNS_SIGNATURE_PREFIX } from '@cipherbox/core';
import {
  verifyEd25519,
  concatBytes,
  deriveEd25519PublicKey,
  deriveIpnsName,
} from '@cipherbox/crypto';
import { ipnsControllerResolveRecord } from '@cipherbox/api-client';
import type { SdkContext } from '../types';
import { withPerf } from '../perf';
```

**withPerf wrapper pattern** (lines 50-53 of ipns/index.ts):
```typescript
return withPerf('ipns:publish', async () => {
  // ... body
});
```

**resolve + null-on-404 pattern** (lines 193-327 of ipns/index.ts):
```typescript
export async function resolveIpnsRecord(
  ipnsName: string,
  ctx?: SdkContext
): Promise<{ cid: string; sequenceNumber: bigint; signatureVerified: boolean } | null> {
  return withPerf('ipns:resolve', async () => {
    try {
      const response = await ipnsControllerResolveRecord({ ipnsName }, apiOptions);
      if (!response.success) return null;
      // ...
      return { cid: response.cid, sequenceNumber: BigInt(response.sequenceNumber), signatureVerified };
    } catch (error) {
      const status = (error as any).status ?? (error as any).response?.status;
      if (status === 404) return null;
      throw error;
    }
  });
}
```

**Analog 2:** `packages/core/src/node/seal.ts` — `unsealNode` (L139)

**unsealNode call shape** (lines 139-169 of seal.ts):
```typescript
export async function unsealNode(
  published: PublishedNode,
  readKey: Uint8Array,
  writeKey?: Uint8Array
): Promise<Node> {
  if (published.schema !== 'node/v3' || published.aeadVersion !== 1) {
    throw new CryptoError('Unsupported PublishedNode envelope', 'INVALID_AAD_INPUT');
  }
  // unseal readSealed (role 0x01), then optionally writeSealed
  return node;
}
```

**Implementation notes for load.ts:**
- `fetchAndDecryptMetadata(cid, folderKey, ctx)`: fetch CID from IPFS via `fetchFromIpfs(cid, ctx)` → JSON parse as `PublishedNode` → `unsealNode(published, folderKey)`.
- `loadFolderMetadata({ ipnsName, folderKey, ctx })`: call `resolveIpnsRecord(ipnsName, ctx)` → if null return null → `fetchAndDecryptMetadata(resolved.cid, folderKey, ctx)` → return `{ metadata, sequenceNumber: resolved.sequenceNumber, cid: resolved.cid }`.
- Keep `withPerf` wrappers (existing stub already has them).
- Rename `folderKey → readKey` parameter internally or accept the stub param name — either is fine; align with `unsealNode(published, readKey)`.

---

### `packages/sdk-core/src/folder/metadata-ops.ts` (utility, transform)

**Stubs to un-stub:** `renameInFolder` (L21), `deleteFromFolder` (L35), `addFilePointerToFolder` (L46), `moveItem` (L62).

**Analog:** `packages/core/src/node/seal.ts` — `sealChildReadKey` / `unsealChildReadKey` (L187, L213)

**sealChildReadKey call shape** (lines 187-199 of seal.ts):
```typescript
export async function sealChildReadKey(
  childReadKey: Uint8Array,
  parentReadKey: Uint8Array,
  childId: string,
  childKind: NodeKind,
  childGeneration: number
): Promise<string>  // returns base64 sealed blob for SealedChildRef.readKeySealed
```

**Implementation notes for metadata-ops.ts:**
- `renameInFolder`: pure array transform — map `children`, find by `childId`, return new array with `name` updated. No re-encryption (name lives in the read-body, not in `SealedChildRef` — the parent re-seal happens in `updateFolderMetadataAndPublish`).
- `deleteFromFolder`: `children.filter(c => c.childId !== params.childId)` — pure array transform.
- `addFilePointerToFolder`: build new `SealedChildRef` entry and append — the `readKeySealed` field is populated by `sealChildReadKey` at the call site in `registration.ts`/`client.ts`, not in this utility.
- `moveItem`: remove child from `sourceChildren`, append to `destChildren` — pure array transform; no key re-encryption (move within scope is link rewrites only, READ-04/D-02).
- All four functions become **synchronous** (`never` → concrete return type). Remove the `void params` stubs.

---

### `packages/sdk-core/src/folder/registration.ts` (service, CRUD + publish)

**Stubs to un-stub:** `createSubfolder` (L24), `updateFolderMetadataAndPublish` (L46).

**Analog:** `packages/sdk-core/src/cas.ts` — `publishWithCas` (L38)

**publishWithCas call shape** (lines 38-135 of cas.ts):
```typescript
await publishWithCas<SealedChildRef[]>({
  ipnsName: params.ipnsName,
  ipnsPrivateKey: params.ipnsPrivateKey,
  ipnsPublicKey: params.ipnsPublicKey,
  sequenceNumber: params.sequenceNumber,
  ctx: params.ctx,
  encryptedIpnsPrivateKey: params.encryptedIpnsPrivateKey,
  keyEpoch: params.keyEpoch,
  maxAttempts: 3,
  backoff: true,
  encodeAndUpload: async (data) => {
    // seal node read-body + upload to IPFS, return CID
    const published = await sealNode(node, params.folderKey, writeKey);
    return addToIpfs(JSON.stringify(published), params.ctx);
  },
  decodeRemote: async (cid) => {
    const raw = await fetchFromIpfs(cid, params.ctx);
    const published = JSON.parse(raw) as PublishedNode;
    const unsealed = await unsealNode(published, params.folderKey);
    return unsealed.readBody?.children ?? [];
  },
  merge: (base, local, remote) => ({ merged: mergeChildren(base, local, remote) }),
  localData: params.children,
  baseData: params.baseChildren,
});
```

**createAndPublishIpnsRecord for first publish** (lines 86-110 of ipns/index.ts):
```typescript
// First-publish convention (post-Phase-60 strict gate):
await createAndPublishIpnsRecord({
  ipnsPrivateKey: newNodeIpnsPrivateKey,
  ipnsName: derivedIpnsName,
  metadataCid: cid,
  sequenceNumber: 1n,   // embedded verbatim — must be 1n for first publish
  // no expectedSequenceNumber for first publish
  ctx: params.ctx,
});
```

**Implementation notes for registration.ts:**
- `createSubfolder`: generate Ed25519 keypair (`generateEd25519Keypair`), `deriveIpnsName`, generate `readKey`/`writeKey` (32 random bytes each), build the `Node` struct, call `sealNode(node, readKey, writeKey)`, `addToIpfs`, then `createAndPublishIpnsRecord` with `sequenceNumber: 1n`.
- `updateFolderMetadataAndPublish`: delegate to `publishWithCas` — inject `encodeAndUpload` (seal + upload), `decodeRemote` (fetch + unseal), `merge` (three-way children merge from `folder-merge.ts`). Return `{ cid, newSequenceNumber, publishedChildren }`.
- Rename `folderKey → readKey` in the params (open question Q2 from RESEARCH.md).

---

### `packages/sdk-core/src/rotation/engine.ts` (NEW — service, event-driven BFS walk)

**No direct analog in the codebase.** Closest structural analog is `publishWithCas` (retry loop with injected callbacks) for the CAS step, and the `withPerf` wrapper pattern from `ipns/index.ts`.

**Key imports to copy from** (`packages/sdk-core/src/ipns/index.ts` lines 1-22, `packages/sdk-core/src/cas.ts` lines 1-15, `packages/core/src/node/seal.ts` lines 27-30):
```typescript
import { sealNode, unsealNode, sealChildReadKey, unsealChildReadKey } from '@cipherbox/core';
import type { Node, SealedChildRef, PublishedNode, NodeContent } from '@cipherbox/core';
import { publishWithCas } from '../cas';
import { resolveIpnsRecord } from '../ipns';
import { addToIpfs, fetchFromIpfs } from '../ipfs';
import type { SdkContext } from '../types';
```

**Named seam pattern** (from RESEARCH.md Pattern 2 + Phase-62 D-01 discipline):
```typescript
// Each seam is individually exported so Phase 64 can vi.mock() it in unit tests.
// Throw message names the owning phase — same convention used in load.ts/metadata-ops.ts stubs.
export async function mintFileKeyOnRotate(_node: Node, _job: RotationJobRecord): Promise<void> {
  throw new Error('not implemented — phase 64 (ROT-03/CRIT-1 content-key rotation)');
}
export async function mergeConcurrentChildren(
  _node: Node, _resolved: unknown, _ctx: SdkContext
): Promise<void> {
  throw new Error('not implemented — phase 64 (ROT-05/HIGH-4 concurrent-add merge)');
}
export async function reMintGrantsRootedAt(
  _nodeId: string, _key: Uint8Array, _gen: number,
  _job: RotationJobRecord, _ctx: SdkContext
): Promise<void> {
  throw new Error('not implemented — phase 64 (ROT-04/HIGH-3 inner-grant re-mint)');
}
export async function verifySubtreeClean(_rootNodeId: string, _ctx: SdkContext): Promise<boolean> {
  throw new Error('not implemented — phase 64 (ROT-06 crash-resume + verifySubtreeClean)');
}
```

**zeroization ownership comment pattern** (from `packages/sdk-core/src/ipns/index.ts` lines 51-63):
```typescript
// T-47-01 / D-09: caller-owns-key convention. This is a CALLEE that receives
// caller-owned `parentReadKey` — it MUST NOT zero it. Only zero locally-minted
// keys (`readKeyPrime`, `fileKeyPrime`) on failure paths. Never zero params.
```

**CAS publish pattern** (from `cas.ts` L84-97 — the inner createAndPublishIpnsRecord call within publishWithCas):
```typescript
await createAndPublishIpnsRecord({
  ipnsPrivateKey: params.ipnsPrivateKey,
  ipnsName: params.ipnsName,
  metadataCid: cid,
  sequenceNumber: newSeq,                      // currentSeq + 1n (publishWithCas does +1n internally)
  expectedSequenceNumber: currentSeq.toString(), // pre-increment CAS guard
  ctx: params.ctx,
});
```

**String-literal discriminated result type** (project convention — no enums):
```typescript
export type NavigateResult =
  | { status: 'ok'; content: NodeContent; nodeId: string }
  | { status: 'behind-retry' }
  | { status: 'revoked' };
```

**Job record type** (no enum — string literals):
```typescript
export type RotationJobRecord = {
  rootNodeId: string;
  status: 'pending' | 'in-progress' | 'complete' | 'failed';
  completedNodeIds: Set<string>;
  frontier: Array<{ nodeId: string; ipnsName: string; parentReadKey: Uint8Array }>;
  persistCallback?: (job: RotationJobRecord) => void | Promise<void>;
};
```

**CRITICAL:** File MUST be `src/rotation/engine.ts`, not `src/rotation/index.ts`. The vitest config excludes `src/**/index.ts` from coverage (verified in `packages/sdk-core/vitest.config.ts`).

---

### `packages/sdk-core/src/share/grant.ts` (NEW — utility, ECIES wrap/unwrap)

**Analog:** `packages/sdk/src/share/index.ts` — `createShareKey` (L64) and the transport-decoupled callback seam pattern used throughout.

**ECIES wrapKey call shape** (lines 64-73 of packages/sdk/src/share/index.ts):
```typescript
export async function createShareKey(params: {
  folderKey: Uint8Array;
  recipientPublicKey: Uint8Array;
  folderIpnsName: string;
  shareCtx: ShareOperationContext;
}): Promise<{ encryptedKey: string }> {
  const wrappedKey = await wrapKey(params.folderKey, params.recipientPublicKey);
  return { encryptedKey: bytesToHex(wrappedKey) };
}
```

**Transport-decoupled callback seam pattern** (lines 88-134 of packages/sdk/src/share/index.ts):
```typescript
// Inject the API call as a callback so the unit test can mock it
export async function reWrapForRecipients(params: {
  // ...
  addShareKeysFn: (shareId: string, keys: ...) => Promise<void>;
}): Promise<{ failedRecipients: string[] }> {
```

**Imports for grant.ts:**
```typescript
import { wrapKey, unwrapKey } from '@cipherbox/crypto';
import type { SdkContext } from '../types';
```

**Implementation notes:**
- `issueReadGrant(params: { shareRootReadKey, recipientPublicKey, rootNodeId, rootIpnsName, rootGeneration, insertShareFn })`: `wrapKey(shareRootReadKey, recipientPublicKey)` → base64 → call `insertShareFn`. Zero-node-touches, zero-publishes (READ-01).
- `claimInviteReadKey(params: { readDescriptorRef, ephemeralPrivKey, claimerPublicKey })`: `unwrapKey(fromBase64(readDescriptorRef), ephemeralPrivKey)` → `wrapKey(shareRootReadKey, claimerPublicKey)` → base64. Zero `shareRootReadKey` after use (this function mints the intermediate; it is the terminal owner).
- Base64 encoding: use same chunk-based pattern from `seal.ts` or use the project's existing `bytesToHex`/`hexToBytes` if the grant payload is hex. Check existing grant API contract when wiring.

---

### `packages/sdk/src/share/index.ts` — DELETE `reWrapForRecipients` (L88–L134)

**Deletion scope (D-03):**
- Remove function `reWrapForRecipients` at lines 88–134.
- Leave all other exports (`createShareKey`, `revokeShare`, `revokeSharesForItems`, re-exports) intact.
- `packages/sdk/src/types.ts:32` (`addShareKeys` callback type) — **DO NOT TOUCH** (Phase 68).

---

### `packages/sdk/src/client.ts` — rewire L164 and L1602

**Current pattern at L164** (add-item fan-out — to be replaced):
```typescript
const { failedRecipients } = await shareOps.reWrapForRecipients({
  // ...
  addShareKeysFn: callbacks.addShareKeys,
});
```

**Replacement pattern** (READ-03 — seal child readKey under parent readKey):
```typescript
// Seal the new child readKey under the parent readKey (no per-recipient fan-out).
// sealChildReadKey returns the base64 SealedChildRef.readKeySealed value.
const readKeySealed = await sealChildReadKey(
  childReadKey, parentReadKey, childId, childKind, 0 /* generation 0 for new node */
);
```

**L1602** — the exposed `reWrapForRecipients` method on the client class: remove the method body, keep the method signature commented with `// Phase 68: addShareKeys web wiring` or delete the method entirely if no external callers remain after L164 rewire.

---

### `packages/sdk-core/src/__tests__/rotation/engine.test.ts` (NEW — test)

**Analog:** `packages/sdk-core/src/__tests__/cas.test.ts` (exact pattern)

**Mock hoisting pattern** (lines 1-21 of cas.test.ts):
```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { publishWithCas } from '../cas';
import { ConflictError } from '../errors';
import { createMockContext } from './helpers';

const mockFns = vi.hoisted(() => ({
  createAndPublishIpnsRecord: vi.fn(),
  resolveIpnsRecord: vi.fn(),
}));

vi.mock('../ipns', () => ({
  createAndPublishIpnsRecord: mockFns.createAndPublishIpnsRecord,
  resolveIpnsRecord: mockFns.resolveIpnsRecord,
  batchPublishIpnsRecords: vi.fn(),
}));
```

**Publish-call spy pattern for zero-rotation invariant (ROT-02):**
```typescript
// The zero-rotation invariant test uses vi.spyOn or vi.fn() as the injected
// encodeAndUpload callback — assert it was called zero times for a private delete.
it('ROT-02: private delete (no covering grant) triggers zero rotations', async () => {
  const publishSpy = vi.fn();
  // set up: hasCoveringGrant returns false
  // call deleteFromFolder path
  // assert publishSpy.mock.calls.length === 0
  expect(publishSpy).not.toHaveBeenCalled();
});
```

**Mock codec pattern** (align with folder.test.ts lines 52-66):
```typescript
vi.mock('@cipherbox/core', () => ({
  sealNode: vi.fn().mockResolvedValue({ schema: 'node/v3', kind: 'folder', id: 'node-1', generation: 0, aeadVersion: 1, readSealed: 'base64==' }),
  unsealNode: vi.fn().mockResolvedValue({ id: 'node-1', kind: 'folder', generation: 0, readBody: { name: 'root', children: [] } }),
  sealChildReadKey: vi.fn().mockResolvedValue('childsealed=='),
  unsealChildReadKey: vi.fn().mockResolvedValue(new Uint8Array(32).fill(0x42)),
}));
```

**createMockContext usage** (from `packages/sdk-core/src/__tests__/helpers.ts`):
```typescript
export function createMockContext(): SdkContext {
  return {
    apiUrl: 'http://localhost:3000',
    getAccessToken: vi.fn().mockResolvedValue('test-token'),
  };
}
```

**Test file location:** `packages/sdk-core/src/__tests__/rotation/engine.test.ts` — create the `rotation/` subdirectory under `__tests__/`. The engine.test.ts path mirrors the source path `src/rotation/engine.ts`.

---

### `packages/sdk-core/src/__tests__/folder.test.ts` (revive quarantine blocks)

**Quarantine markers to remove:**
- L105, L248, L445, L491, L515, L563 — `describe.skip` / `it.skip` / `TODO(phase 63)` comments.
- Update mock factories: the retired `encryptFolderMetadata`/`decryptFolderMetadata` mocks (L62-66) must be replaced with the new codec mocks (`sealNode`, `unsealNode`, `sealChildReadKey`, `unsealChildReadKey`).
- Remove `@ts-nocheck` (L2) once the `FolderEntry`/`FilePointer` retired-type references are replaced with `Node`/`SealedChildRef`.

**Pattern for mock replacement** (lines 62-66 of folder.test.ts — the retired mock):
```typescript
// BEFORE (retired):
vi.mock('@cipherbox/core', () => ({
  encryptFolderMetadata: mockFns.encryptFolderMetadata,
  decryptFolderMetadata: mockFns.decryptFolderMetadata,
  // ...
}));

// AFTER (Phase-62 codec):
vi.mock('@cipherbox/core', () => ({
  sealNode: mockFns.sealNode,
  unsealNode: mockFns.unsealNode,
  sealChildReadKey: mockFns.sealChildReadKey,
  unsealChildReadKey: mockFns.unsealChildReadKey,
  // keep createIpnsRecord, marshalIpnsRecord if still used
}));
```

---

### `packages/sdk/src/__tests__/client-extended.test.ts` (revive L133)

**Quarantine marker:** `describe.skip` or `it.skip` at L133 for `moveItem`. Remove the `.skip`. The mock setup at lines 1-56 already mocks `moveItem` from `@cipherbox/sdk-core`, so the test should pass once `moveItem` is un-stubbed.

---

## Shared Patterns

### withPerf wrapper
**Source:** `packages/sdk-core/src/ipns/index.ts` lines 50-53
**Apply to:** All functions in `folder/load.ts`, `rotation/engine.ts` public functions
```typescript
return withPerf('folder:load', async () => {
  // implementation
});
```

### Zeroization ownership (T-47-01 / D-09)
**Source:** `packages/sdk-core/src/ipns/index.ts` lines 51-63 (comment block), `packages/sdk-core/src/cas.ts` line 9
**Apply to:** `rotation/engine.ts` (rotateOne, rotateReadFromNode), `share/grant.ts` (claimInviteReadKey)

Rule: zero only locally-minted keys (`readKeyPrime`, `fileKeyPrime`, intermediate unwrapped share-root readKey in claimInviteReadKey). Never zero a `Uint8Array` parameter. Add a JSDoc `@security` note on every function that touches key material.

### Transport-decoupled callback seam
**Source:** `packages/sdk/src/share/index.ts` lines 88-134 (`reWrapForRecipients` with injected `addShareKeysFn`)
**Apply to:** `share/grant.ts` (`issueReadGrant` with injected `insertShareFn`; `claimInviteReadKey` with injected `persistGrantFn`)

Pattern: inject the API call as a `Fn` callback parameter so unit tests pass a `vi.fn()` mock without importing the API client.

### String-literal unions (never enums)
**Source:** `packages/sdk-core/src/ipns/index.ts` return types throughout
**Apply to:** `rotation/engine.ts` (NavigateResult, RotationJobRecord.status, RotationStatus)

### vi.hoisted mock pattern
**Source:** `packages/sdk-core/src/__tests__/cas.test.ts` lines 12-21
**Apply to:** `__tests__/rotation/engine.test.ts`, revived `folder.test.ts` mock section

### First-publish sequence convention
**Source:** `packages/sdk-core/src/cas.ts` L86-96; `packages/sdk-core/src/ipns/index.ts` L39-111
**Apply to:** `registration.ts` (`createSubfolder` first publish)

For new nodes: pass `sequenceNumber: 1n` to `createAndPublishIpnsRecord` (embedded verbatim). For CAS updates: pass `sequenceNumber: currentSeq` to `publishWithCas` (it does `+1n` internally and sets `expectedSequenceNumber: currentSeq.toString()`).

---

## No Analog Found

All files have analogs in the codebase. The rotation engine is a structural novelty but composes existing patterns (publishWithCas retry loop + resolveIpnsRecord + unsealNode). RESEARCH.md Pattern 2 (`rotateOne` skeleton) is the design-level analog when no codebase analog exists.

---

## Metadata

**Analog search scope:** `packages/sdk-core/src/`, `packages/sdk/src/`, `packages/core/src/node/`, `packages/crypto/src/ecies/`
**Files read:** 13 (load.ts, metadata-ops.ts, registration.ts, cas.ts, ipns/index.ts, core/node/seal.ts, sdk/share/index.ts, sdk/client.ts (header), sdk/reencrypt.ts, __tests__/folder.test.ts (header), __tests__/helpers.ts, __tests__/cas.test.ts, sdk/__tests__/client-extended.test.ts (header))
**Pattern extraction date:** 2026-06-29
