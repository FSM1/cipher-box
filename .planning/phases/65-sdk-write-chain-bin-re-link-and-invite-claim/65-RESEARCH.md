# Phase 65: SDK Write-Chain, Bin Re-link, and Invite Claim - Research

**Researched:** 2026-06-30
**Domain:** Ed25519 write-chain, write-revocation, bin restore, invite claim re-wrap (sdk-core / sdk)
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Reconcile on owner sync; the exposure window for write-recipient destructive ops on owner sub-shares is a documented residual. C unlinks immediately, no cross-principal revoke attempt, no new schema. Owner's reconcile pass re-derives dangling grants via the existing `shares WHERE rootNodeId IN (destroyed subtree)` enumeration (HIGH-3 seam, inverted) — wired live in Phase 66/68.
- **D-02:** Hold the Phase-64 D-04 line: Phase 65 is sdk-core/sdk crypto + behavior only. Tombstone enforcement, `writeDescriptorRef` co-writer persistence, all apps/api schema — mock-tested behind injected callbacks, cut over in Phase 66. `reWrapForRecipients` is already gone from sdk (Phase 63); `addShareKeys` and `encryptedChildKeys` live in apps/api → Phase 66. Phase 65 rewires sdk-layer fan-out logic so it no longer depends on the old fan-out.
- **D-03:** Explicit SDK error only — co-writer offline during write-key rotation gets `"cannot write until re-fetch"`. No grace period / notification / pending-rekey marker (Phase 68 web UX).
- **D-04:** Real `tests/sdk-e2e` write-chain rotation round-trip is the phase gate. Live round-trip: node with `writeBody`, write-revocation minting new k51 per node, parent re-point cascade to share root, surviving co-writer re-wrap, tombstone-intent on rotated-out names. Reuse Phase-63/64 manual-node build pattern with real write-bodies.
- **D-05:** Phase-62 write-body codec is complete — Phase 65 CALLS it, never reimplements it. Seam: `sealNode`/`unsealNode` (with writeKey param), `encodeWriteBody`/`decodeWriteBody`, role `0x04 child-writekey`.
- **D-06:** Bin restore = pure re-link. Delete `originalFolderKeyEncrypted` + re-encrypt-on-restore path from `packages/sdk/src/bin/index.ts`. Invite claim = unwrap share-root `readKey` with URL-fragment ephemeral key, re-wrap to claimer → standard grant. Delete `encryptedChildKeys[]` fan-out logic.

### Claude's Discretion

- Write-revocation driver shape — distinct `rotateWriteFromNode` vs extension of `rotateReadFromNode`.
- Whether Phase 65 un-stubs `createFileMetadata`/`createSubfolder` to emit real write-bodies, or continues the manual-node-build pattern for e2e.
- Exact co-writer "cannot write until re-fetch" error type/shape.
- Internal factoring of `shared-write.ts`, the write-chain walk, and how the mocked callbacks are structured.
- How the e2e injects/verifies the parent re-point cascade and tombstone-intent.

### Deferred Ideas (OUT OF SCOPE)

- Q3 option (c) — owner-signed revocation-request queue.
- Co-writer offline grace/notification UX → Phase 68.
- Live apps/api cutover — tombstone state machine, publish-gate rejection, resolve-410, atomic publish CAS, `share_keys`/`addShareKeys` deletion, `encryptedChildKeys` column drop, `shares` slim, `folder_ipns` → `ipns_records` → Phase 66.
- Live apps/web cutover — `reWrapForRecipients` deletion, `addShareKeysFn` type removal → Phase 68.
- TEE lease-renewer contract + `createSubfolder` TEE republish wiring → Phase 67.
- `crates/fuse` write plane → Phase 69.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| WRITE-01 | Write-body holds Ed25519 signing material under `writeKey` as structured recursive write chain; role `0x04`; read-only holder can never reach signing material | `sealNode`/`unsealNode`/`encodeWriteBody`/`decodeWriteBody` complete in Phase 62. Missing: `sealChildWriteKey`/`unsealChildWriteKey` (role 0x04) — must add to seal.ts. `SharedWriteContext` must be reshaped to write-body model. |
| WRITE-02 | Write-revocation: new Ed25519 keypair + k51 name per node, cascade upward to share root, re-point co-grants and owner devices | Requires a new `rotateWriteFromNode` driver — structurally heavier than `rotateReadFromNode`; mints new names, cascades UPWARD, re-enrolls TEE, re-wraps co-grants. |
| WRITE-03 | Surviving co-writers receive rotated Ed25519 key re-wrapped into `writeDescriptorRef`; offline co-writer gets explicit error | Mock-tested via injected `queryWriteGrantsFn`/`writeDescriptorRefPersistFn` callbacks (Phase-64 D-04 discipline). Error type is Claude's discretion. |
| WRITE-04 | Tombstone rotated-out IPNS name: publish-gate rejects, resolve 410, removed from TEE republish batch (EOL renewal also rejected) | Mock-tested via injected `teeUnenrollFn(oldIpnsName)` callback. Live enforcement in Phase 66. Phase 65 produces intent + removes from batch. |
</phase_requirements>

---

## Summary

Phase 65 is a wiring + driver phase, not a primitive-build phase. The Phase-62 codec (`sealNode`, `unsealNode`, `encodeWriteBody`, `decodeWriteBody`, `NodeWriteBody`, `WriteChildRef`) is complete and callable. The Phase-63/64 rotation engine's `nodeKeySource` seam is the primary extension point. Four delivery areas:

**WRITE-01/02/03/04 (shared-write.ts + rotation engine):** Implement the stubbed `packages/sdk/src/share/shared-write.ts` using the write-body codec. Thread the real `writeKey` into the rotation engine's `PLACEHOLDER_WRITE_KEY` seam. Add a new write-revocation driver that mints new Ed25519 keypairs and cascades parent re-points upward. Mock-test co-writer re-wrap and tombstone-intent behind Phase-64-discipline injected callbacks.

**WRITE-01 gap in core:** `sealChildWriteKey` / `unsealChildWriteKey` (role `0x04`) do NOT exist in `packages/core/src/node/seal.ts`. Only `sealChildReadKey`/`unsealChildReadKey` (role `0x02`) exist. Phase 65 must add these two functions — they follow the identical pattern as `sealChildReadKey` but with role byte `0x04`.

**Bin re-link (D-06):** `addToBin` and `restoreFromBin` in `packages/sdk/src/bin/index.ts` are stubbed. `BinEntry.nodeRef?: Node` exists (Phase 62). Restore = re-seal node's `readKey` under destination parent `readKey` via `sealChildReadKey`. Delete `originalFolderKeyEncrypted` from bin test fixtures.

**Invite claim (D-06/D-07):** `claimInviteReadKey` is ALREADY IMPLEMENTED in `packages/sdk-core/src/share/grant.ts` and has no `encryptedChildKeys` fan-out. Phase 65 wires the full invite claim service flow using this primitive and ensures `encryptedChildKeys` consumption is dead from the sdk-layer. The `api-client` types still reference `encryptedChildKeys` but the sdk-layer must not consume them (apps/api column drop is Phase 66).

**Phase gate (D-04):** Real `tests/sdk-e2e` write-chain rotation round-trip. Copy the Phase-64 `rotation-crash-safety.test.ts` pattern: manual `sealNode` with real `writeBody`, `addToIpfs`, `createAndPublishIpnsRecord`, supply per-node key maps. Assert: new k51 per node, parent `SealedChildRef.ipnsName` updated, co-writer re-wrap, tombstone-intent callbacks fired.

**Primary recommendation:** Start with `sealChildWriteKey`/`unsealChildWriteKey` in core (unblocks everything), then implement `shared-write.ts` write-chain (WRITE-01), then the write-revocation driver (WRITE-02/03/04), then bin restore, then invite claim wiring.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Write-body sealing (Ed25519 material) | packages/core | — | Phase-62 codec (`sealNode`/`encodeWriteBody`); NEVER in sdk or sdk-core |
| Write-chain link sealing (child writeKey under parent writeKey) | packages/core | — | Analogous to `sealChildReadKey`; role 0x04; lives in seal.ts |
| Write-chain walk (add-item, create subfolder in shared folder) | packages/sdk | packages/sdk-core | `shared-write.ts` calls core codec; sdk-core for IPNS/CAS helpers |
| Write-revocation driver (rotateWriteFromNode) | packages/sdk-core | — | Rotation engine lives in sdk-core/src/rotation/engine.ts |
| Tombstone-intent / TEE unenroll | packages/sdk-core | — | Injected callback seam (mock in Phase 65, live in Phase 66/67) |
| Co-writer re-wrap (writeDescriptorRef) | packages/sdk-core | — | Injected callback seam; ECIES via `wrapKey` from @cipherbox/crypto |
| Bin restore (pure re-link) | packages/sdk | packages/core | `restoreFromBin` in bin/index.ts; uses `sealChildReadKey` from core |
| Invite claim re-wrap | packages/sdk-core | — | `claimInviteReadKey` already in grant.ts; wire service flow |
| All apps/api persistence | DEFERRED Phase 66 | — | Mock-tested only in Phase 65 |

---

## Standard Stack

### Core (Phase-62-complete — call, never reimplement)

| Function / Type | Location | Role |
|----------------|----------|------|
| `sealNode(node, readKey, writeKey)` | `packages/core/src/node/seal.ts:96` | Seals read-body + write-body (write-body sealed only when `node.writeBody` is set); always takes `writeKey` even when no writeBody |
| `unsealNode(published, readKey, writeKey?)` | `packages/core/src/node/seal.ts:139` | Unseals read-body always; unseals write-body only when `writeKey` supplied AND `published.writeSealed` is set |
| `sealChildReadKey(childReadKey, parentReadKey, childId, childKind, childGeneration)` | `packages/core/src/node/seal.ts:187` | Role 0x02; produces `SealedChildRef.readKeySealed` |
| `unsealChildReadKey(sealedBase64, parentReadKey, childId, childKind, childGeneration)` | `packages/core/src/node/seal.ts:213` | Inverse of above |
| `encodeWriteBody(node)` | `packages/core/src/node/encode.ts:159` | JSON-encodes the write-body; throws if `node.writeBody` absent |
| `decodeWriteBody(bytes)` | `packages/core/src/node/decode.ts:318` | Restores `ipnsPrivateKey` as `Uint8Array`, `writeChildren` as `WriteChildRef[]` |
| `Node`, `NodeWriteBody`, `WriteChildRef`, `SealedChildRef`, `PublishedNode` | `packages/core/src/node/types.ts` | `NodeWriteBody.ipnsPrivateKey: Uint8Array`; `NodeWriteBody.writeChildren: WriteChildRef[]`; `WriteChildRef.writeKeySealed: string` |

### Missing — Must Add to core in Phase 65

| Function | Location | Role | Priority |
|----------|----------|------|----------|
| `sealChildWriteKey(childWriteKey, parentWriteKey, childId, childKind, childGeneration)` | Add to `packages/core/src/node/seal.ts` | Role 0x04; produces `WriteChildRef.writeKeySealed` | BLOCKER — everything downstream needs this |
| `unsealChildWriteKey(sealedBase64, parentWriteKey, childId, childKind, childGeneration)` | Add to `packages/core/src/node/seal.ts` | Inverse of above; needed to walk the write chain | BLOCKER |

These follow exactly the same pattern as `sealChildReadKey`/`unsealChildReadKey` at lines 187–224 of seal.ts, substituting role byte `0x04` for `0x02`.

### Phase-63/64-complete — Extend in Phase 65

| API | Location | Phase 65 extension |
|-----|----------|--------------------|
| `rotateReadFromNode(params: RotationParams)` | `packages/sdk-core/src/rotation/engine.ts:675` | Wire real `writeKey` through BFS; remove `PLACEHOLDER_WRITE_KEY` |
| `rotateOne(params: RotateOneParams)` | `packages/sdk-core/src/rotation/engine.ts:473` | Pass real `writeKey` to `sealNode` instead of zeros at L550/L594 |
| `RotationParams.nodeKeySource` | `engine.ts:229` | Provides IPNS signing keys — Phase 65 derives them FROM `writeBody.ipnsPrivateKey` after unsealing |
| `publishWithCas`, `resolveIpnsRecord`, `createAndPublishIpnsRecord` | `packages/sdk-core/src/cas.ts`, `packages/sdk-core/src/ipns/index.ts` | Used for new k51 first-publishes (seq `1n`) and parent re-point CAS |

### Supporting

| Library | Purpose |
|---------|---------|
| `wrapKey(key, recipientPublicKey)` from `@cipherbox/crypto` | ECIES-wrap `writeKey` into `writeDescriptorRef` for co-writers |
| `reWrapKey` from `@cipherbox/crypto` | Invite-claim re-wrap (already used in `claimInviteReadKey`) |
| `generateEd25519Keypair()`, `deriveIpnsName(pubKey)` from `@cipherbox/crypto` | New Ed25519 keypairs for write-revocation — one per node |
| `generateRandomBytes(32)` from `@cipherbox/crypto` | New `writeKey'` for each node in write-revocation |

---

## Package Legitimacy Audit

No new external packages are introduced. All dependencies already exist in the monorepo.

---

## Architecture Patterns

### Write-Body Build Pattern (for new nodes in shared-write.ts)

```typescript
// Source: packages/core/src/node/seal.ts (Phase-62-complete)
// To build a node with a write-body for a child folder:
const writeKey = generateRandomBytes(32);          // child's writeKey
const { privateKey: ipnsPrivateKey, publicKey: ipnsPublicKey } = await generateEd25519Keypair();
const ipnsName = await deriveIpnsName(ipnsPublicKey);

const node: Node = {
  schema: 'node/v3',
  kind: 'folder',
  id: crypto.randomUUID(),
  generation: 0,
  createdAt: Date.now(),
  modifiedAt: Date.now(),
  children: [],
  writeBody: {
    ipnsPrivateKey,           // raw Ed25519 seed — inside sealed write-body
    writeChildren: [],        // parent seals child writeKey in ITS own write-body
  },
};

// Seal both bodies
const published = await sealNode(node, readKey, writeKey);

// Parent write-body carries the child writeKey link (role 0x04):
// writeKeySealed = sealChildWriteKey(childWriteKey, parentWriteKey, childId, childKind, childGeneration)
// This is inserted into parent.writeBody.writeChildren[] before sealNode(parent, ...)
```

### sealChildWriteKey Pattern to Add to seal.ts

```typescript
// Add to packages/core/src/node/seal.ts — identical to sealChildReadKey at L187 but role 0x04
export async function sealChildWriteKey(
  childWriteKey: Uint8Array,
  parentWriteKey: Uint8Array,
  childId: string,
  childKind: NodeKind,
  childGeneration: number
): Promise<string> {
  const kb = kindByte(childKind);
  const aad = buildNodeAad(childId, kb, childGeneration, 0x04 /* child-writekey */);
  const sealed = await sealAesGcmAad(childWriteKey, parentWriteKey, aad);
  return uint8ArrayToBase64(sealed);
  // Do NOT zero childWriteKey — caller is terminal owner (D-09)
}

export async function unsealChildWriteKey(
  sealedBase64: string,
  parentWriteKey: Uint8Array,
  childId: string,
  childKind: NodeKind,
  childGeneration: number
): Promise<Uint8Array> {
  const kb = kindByte(childKind);
  const aad = buildNodeAad(childId, kb, childGeneration, 0x04 /* child-writekey */);
  const sealedBytes = base64ToUint8Array(sealedBase64);
  return unsealAesGcmAad(sealedBytes, parentWriteKey, aad);
}
```

### rotateOne writeKey Wiring Pattern

```typescript
// In rotateOne (engine.ts ~L547-551):
// BEFORE (Phase 63/64):
const PLACEHOLDER_WRITE_KEY = new Uint8Array(32);
const resealedPublished = await sealNode(updatedNode, readKeyPrime, PLACEHOLDER_WRITE_KEY);

// AFTER (Phase 65 — real writeKey from unsealNode):
// 1. rotateOne receives nodeWriteKey (threaded by rotateReadFromNode's BFS)
// 2. unsealNode is called WITH the writeKey to recover writeBody.ipnsPrivateKey
// 3. Re-seal under SAME writeKey (read rotation does NOT rotate write plane):
const nodeWithBody = await unsealNode(published, parentReadKey, nodeWriteKey);
// nodeIpnsPrivateKey comes FROM nodeWithBody.writeBody.ipnsPrivateKey
// (eliminates the nodeKeySource seam for write-capable nodes)
const updatedNode: Node = { ...nodeWithBody, generation: generationPrime };
const resealedPublished = await sealNode(updatedNode, readKeyPrime, nodeWriteKey);
```

### Write-Revocation Driver Pattern (rotateWriteFromNode)

```typescript
// New function in packages/sdk-core/src/rotation/engine.ts
// Structurally heavier than rotateReadFromNode (design §5.3):
//   1. Per-node: mint new Ed25519 keypair + k51 name + new writeKey'
//   2. Re-seal write-body under new writeKey' with new ipnsPrivateKey
//   3. First-publish at seq 1n to new k51 name (createAndPublishIpnsRecord)
//   4. Tombstone-intent old name: teeUnenrollFn(oldIpnsName) callback
//   5. Update PARENT's SealedChildRef.ipnsName → new k51 name (cascade upward)
//   6. At share root: re-wrap surviving co-writer writeKey' into writeDescriptorRef
//
// Mock-seam callbacks:
type WriteRevocationCallbacks = {
  queryWriteGrantsFn: (nodeId: string) => Promise<Array<{
    shareId: string; recipientPublicKey: Uint8Array; isRevoked: boolean;
  }>>;
  writeDescriptorRefPersistFn: (shareId: string, writeDescriptorRef: string) => Promise<void>;
  teeUnenrollFn: (oldIpnsName: string) => Promise<void>;
};
```

### Bin Restore Pattern (pure re-link)

```typescript
// restoreFromBin — packages/sdk/src/bin/index.ts
// BinEntry.nodeRef is a Node (Phase-62 [62-05]); its readKey is the node's own readKey.
// To restore: re-seal the node's readKey under the destination parent's readKey.
// This is exactly the same as addFilePointerToFolder.
//
// Phase 65 DELETES originalFolderKeyEncrypted + re-encrypt-on-restore from:
//   - packages/sdk/src/bin/index.ts (the function body)
//   - packages/sdk/src/__tests__/bin.test.ts (fixtures at L724, L1063)
//   - packages/core/src/bin/types.ts: confirm it's already absent (it is — types.ts has nodeRef only)
//
// NOTE: BinEntry.nodeRef has type `Node` which carries readKey inside its sealed bodies.
// The restore operation needs the node's readKey (unsealed from the destination parent's chain).
// The bin entry stores the SealedChildRef-equivalent so the restore can re-link without re-encrypt.
```

### Invite Claim Wiring Pattern

```typescript
// claimInviteReadKey is ALREADY IMPLEMENTED in packages/sdk-core/src/share/grant.ts:184
// Phase 65 wires the full claim flow:
//
// 1. Client receives invite link with URL fragment = ephemeral private key
// 2. API call to GET /invites/{token}/data → returns invite.readDescriptorRef (the ECIES-wrapped readKey)
// 3. claimInviteReadKey({ readDescriptorRef, ephemeralPrivateKey, claimerPublicKey })
//    → claimerReadDescriptorRef (re-wrapped to claimer)
// 4. insertShareFn persists standard grant row (mocked in Phase 65; live in Phase 66)
//
// Phase 65 DELETES any sdk-layer code that:
//   - Reads encryptedChildKeys from invite data
//   - Builds or consumes encryptedChildKeys[] fan-out arrays
// The api-client models (createInviteDto.ts:23, inviteDataResponseDto.ts:21) still reference
// encryptedChildKeys but sdk-core/sdk MUST NOT consume them.
```

### E2E Test Pattern (from rotation-crash-safety.test.ts)

```typescript
// Extend with real write-body:
const writeKey = generateRandomBytes(32);
const { privateKey: ipnsPrivateKey } = await generateEd25519Keypair();
const ipnsName = await deriveIpnsName(deriveEd25519PublicKey(ipnsPrivateKey));

const node: Node = {
  schema: 'node/v3', kind: 'folder', id: crypto.randomUUID(), generation: 0,
  createdAt: Date.now(), modifiedAt: Date.now(), children: [],
  writeBody: { ipnsPrivateKey, writeChildren: [] }
};
const pub = await sealNode(node, readKey, writeKey);
const { cid } = await addToIpfs(ctx, new TextEncoder().encode(JSON.stringify(pub)));
await createAndPublishIpnsRecord({
  ipnsPrivateKey, ipnsName, metadataCid: cid, sequenceNumber: 1n, ctx
});

// For write-revocation test: assert old k51 names change,
// tombstone callback fired, co-writer re-wrap callback called.
```

### Recommended Project Structure for Phase 65 Changes

```
packages/core/src/node/
├── seal.ts               # ADD: sealChildWriteKey, unsealChildWriteKey (role 0x04)
├── types.ts              # Read-only (NodeWriteBody, WriteChildRef already complete)
├── encode.ts             # Read-only (encodeWriteBody already complete)
└── decode.ts             # Read-only (decodeWriteBody already complete)

packages/sdk-core/src/rotation/
├── engine.ts             # MODIFY: wire real writeKey into rotateOne; ADD rotateWriteFromNode
└── index.ts              # EXPORT: rotateWriteFromNode

packages/sdk/src/share/
└── shared-write.ts       # REWRITE: all 6 stubs + SharedWriteContext reshape

packages/sdk/src/bin/
└── index.ts              # IMPLEMENT: addToBin + restoreFromBin (pure re-link)

tests/sdk-e2e/src/suites/
└── write-chain-rotation.test.ts  # NEW: D-04 round-trip test
```

### Anti-Patterns to Avoid

- **Reimplementing AES-GCM or ECIES**: Always use `sealAesGcmAad`/`unsealAesGcmAad` from `@cipherbox/crypto` and `wrapKey`/`reWrapKey`. Never hand-roll.
- **Zeroing caller-supplied keys**: Only zero keys the current function MINTS. Never zero `parentReadKey`, `parentWriteKey`, or any key passed in from the caller (D-09 / T-63-10).
- **Zeroing on the success path**: Only zero minted keys on FAILURE paths before re-throw. The frontier walk still needs them.
- **Placing write chain logic in SealedChildRef**: `SealedChildRef` is read-only. Write links live ONLY in `parent.writeBody.writeChildren[]`.
- **Using index.ts barrels**: `engine.ts` and `shared-write.ts` must remain named files (coverage excludes `src/**/index.ts` barrels in sdk-core).
- **Publishing with all-zero writeKey**: The D-01 fail-closed guard in `rotateOne` (L514-524) catches all-zero/malformed IPNS keys. The analogous guard for writeKey should be fail-closed too.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Child writeKey link sealing | Custom AES-GCM | `sealChildWriteKey` (add to seal.ts) + `sealAesGcmAad` | AAD binding is frozen; any deviation = silent total decryption failure |
| ECIES key wrapping for co-writer descriptors | Custom ECDH | `wrapKey` from `@cipherbox/crypto` | HKDF + AES-GCM; test vectors locked |
| Invite re-wrap | Custom unwrap/re-wrap | `claimInviteReadKey` (already exists in grant.ts) | Already implemented and tested |
| IPNS name derivation | Hash the key yourself | `deriveIpnsName(pubKey)` from `@cipherbox/crypto` | Strict verification in API uses same function |
| CAS-retry publish | Retry loop | `publishWithCas` from `packages/sdk-core/src/cas.ts` | Handles 409, backoff, merge callback |
| New Ed25519 keypair generation | Use existing private key | `generateEd25519Keypair()` from `@cipherbox/crypto` | Write-revocation REQUIRES a NEW keypair per node |

**Key insight:** The write chain is a thin wiring layer on top of Phase-62 primitives. The rotation driver is the heaviest new code, and it mirrors the read-rotation engine structure.

---

## Common Pitfalls

### Pitfall 1: Missing sealChildWriteKey causes silent no-write-link bug

**What goes wrong:** `WriteChildRef.writeKeySealed` contains an incorrectly sealed blob (wrong role byte) that `unsealChildWriteKey` silently rejects at runtime with a GCM auth tag failure.

**Why it happens:** If someone uses `sealChildReadKey` (role 0x02) instead of the new `sealChildWriteKey` (role 0x04), the AAD mismatch causes auth tag failure when the child later tries to unseal its write link.

**How to avoid:** Add `sealChildWriteKey`/`unsealChildWriteKey` with role 0x04 as the FIRST task. Add KAT coverage asserting the role byte is 0x04 in the AAD.

**Warning signs:** `CryptoError` with "decryption failed" or "auth tag invalid" when trying to walk the write chain.

### Pitfall 2: PLACEHOLDER_WRITE_KEY regression if write-body node enters rotateOne

**What goes wrong:** If `rotateOne` processes a node with a `writeBody`, the placeholder `new Uint8Array(32)` re-seals the write-body under all-zeros, silently corrupting the write plane.

**Why it happens:** The placeholder is safe in Phase 63/64 (no nodes had writeBody). Once Phase 65 adds real write-bodies, ANY rotation of a write-capable node via `rotateReadFromNode` will corrupt it if the placeholder isn't replaced.

**How to avoid:** Wire the real `writeKey` into the BFS alongside the IPNS private key BEFORE adding write-body nodes to any rotation scenario. Remove `PLACEHOLDER_WRITE_KEY` from both L550 and L594 in engine.ts.

**Warning signs:** `unsealNode(pub, readKey, writeKey)` succeeds for read-body but returns no `writeBody` where one was expected, OR `unsealNode` throws when writeKey is supplied to a post-rotation node.

### Pitfall 3: AAD byte drift breaks write-chain seal

**What goes wrong:** `sealChildWriteKey` uses `buildNodeAad(childId, kb, childGeneration, 0x04)` — the `childGeneration` in the AAD MUST match the generation value used when the sealed link was created. If the parent re-seals with a stale generation, `unsealChildWriteKey` throws.

**Why it happens:** In the write-revocation cascade, the parent's write-body is re-sealed with `child.generation` (the NEW generation after write rotation mints a new k51 name + generation = 0). Using the PRE-rotation generation in the AAD breaks the unseal.

**How to avoid:** When building `WriteChildRef.writeKeySealed` during write-revocation, use the child's NEW generation (0 for freshly minted nodes) as the AAD `generation`.

**Warning signs:** Write chain walk fails with auth tag error at the first child after a write-rotation.

### Pitfall 4: Zeroization — never zero caller-supplied keys

**What goes wrong:** A callee zeros a Uint8Array buffer that belongs to the caller, corrupting a still-needed key. This caused 48/89 sdk-e2e failures in a previous phase.

**Why it happens:** Callee mistakenly assumes ownership of a passed-in key buffer.

**How to avoid:** Only zero keys that the CURRENT function MINTED (e.g., a freshly generated `writeKeyPrime` on the failure path). NEVER zero `parentWriteKey`, `nodeWriteKey`, or any key received as a parameter. Zero only on failure paths before re-throw — never on the success path.

**Warning signs:** Intermittent "auth tag invalid" errors on subsequent operations that reuse a key buffer; 100% failure rate if the buffer is zeroed on the success path.

### Pitfall 5: First IPNS publish for new k51 names must use seq 1n

**What goes wrong:** Write-revocation mints a NEW k51 name per node. The first publish for a new name must use `sequenceNumber: 1n` — not 0n. The API's strict gate rejects first publishes with seq ≠ 1 with HTTP 400.

**Why it happens:** The strict CAS gate at `ipns.service.ts` enforces this for all first publishes. (Confirmed in project memory and Phase-60 implementation.)

**How to avoid:** Always call `createAndPublishIpnsRecord({ ..., sequenceNumber: 1n })` for new names. Subsequent publishes via `publishWithCas` pass `resolved.sequenceNumber`.

**Warning signs:** HTTP 400 errors on the first publish of a rotated node's new k51 name.

### Pitfall 6: coverage drops below 80% gate if shared-write.ts or engine.ts moved to index barrel

**What goes wrong:** Coverage drops silently; CI fails at the gate.

**Why it happens:** `packages/sdk-core/vitest.config.ts` excludes `src/**/index.ts` from coverage metrics.

**How to avoid:** `shared-write.ts` stays as `packages/sdk/src/share/shared-write.ts`; `engine.ts` stays as `packages/sdk-core/src/rotation/engine.ts`. Never rename to `index.ts`.

---

## Code Examples

### Read-chain navigation (existing — to reuse in e2e)

```typescript
// Source: packages/sdk-core/src/share/navigate.ts (Phase-63-complete)
// navigateReadChain({ readDescriptorRef, recipientPrivKey, rootIpnsName,
//   rootExpectedGeneration, path, ctx }) → { status, content? }
// status: 'ok' | 'behind-retry' | 'revoked'
```

### Write-chain walk pattern (new — shared-write.ts)

```typescript
// To unseal the write chain at a node and recover its writeKey:
// 1. Resolve IPNS → fetch PublishedNode → unsealNode(pub, readKey, writeKey)
//    Note: caller supplies writeKey (from parent's write chain)
// 2. node.writeBody.ipnsPrivateKey = Ed25519 seed for this node
// 3. To walk to a child:
//    childWriteKey = await unsealChildWriteKey(
//      childRef.writeKeySealed,  // from parent.writeBody.writeChildren[i]
//      parentWriteKey,
//      childId, childKind, childGeneration
//    )
// 4. Fetch child node, unsealNode(childPub, childReadKey, childWriteKey)
```

### Write-revocation cascade (WRITE-02)

```typescript
// Per node in the subtree (child-first, then cascade parent pointers upward):
const { privateKey: newIpnsPrivKey, publicKey: newIpnsPublicKey } =
  await generateEd25519Keypair();
const newIpnsName = await deriveIpnsName(newIpnsPublicKey);
const newWriteKey = generateRandomBytes(32);

// Re-seal node under new keys, first-publish to new k51
const nodeWithNewBody: Node = {
  ...node,
  generation: 0,  // new name = generation 0
  writeBody: {
    ipnsPrivateKey: newIpnsPrivKey,
    writeChildren: node.writeBody?.writeChildren ?? [],
  },
};
const newPub = await sealNode(nodeWithNewBody, node_readKey, newWriteKey);
const { cid } = await addToIpfs(ctx, new TextEncoder().encode(JSON.stringify(newPub)));
await createAndPublishIpnsRecord({
  ipnsPrivateKey: newIpnsPrivKey, ipnsName: newIpnsName,
  metadataCid: cid, sequenceNumber: 1n, ctx
});

// Tombstone-intent: unenroll old name from TEE republish batch
await callbacks.teeUnenrollFn(oldIpnsName);

// Update parent's SealedChildRef to point at new k51 name, publish parent
```

### Bin restore (pure re-link)

```typescript
// restoreFromBin — conceptually identical to addFilePointerToFolder
// Source pattern: packages/sdk-core/src/folder/metadata-ops.ts:89
//
// BinEntry.nodeRef carries the node's current state (SealedChildRef-equivalent).
// The restore:
//   1. Get destination parent's readKey (from write chain or from parameters)
//   2. Re-seal node's readKey under destination parent's readKey via sealChildReadKey
//   3. Add new SealedChildRef to destination parent's read-body
//   4. Remove entry from bin metadata
//   5. Publish both: parent + bin
```

---

## State of the Art

| Old Approach | Current Approach | Phase | Impact |
|--------------|------------------|-------|--------|
| ECIES-wrap the raw Ed25519 key to write recipient | Ed25519 signing material sealed in write-body under separate `writeKey` | Phase 62 (codec), Phase 65 (wiring) | Revocation is now cryptographically enforceable |
| `originalFolderKeyEncrypted` + re-encrypt-on-restore | `BinEntry.nodeRef` pure re-link under destination `readKey` | Phase 62 (types), Phase 65 (impl) | O(1) restore, no content re-encryption |
| `encryptedChildKeys[]` fan-out on invite | Single-root `readKey` ECIES-wrapped to claimer | Phase 63 (primitive), Phase 65 (wiring) | O(recipients) grant rows, no O(items) fan-out |
| `addShareKeys` per-child fan-out | Parent write-body seals child writeKey (no per-recipient DB rows) | Phase 62 (design), Phase 65 (impl) | O(subtree) DB rows eliminated |

**Deprecated (delete in Phase 65 at sdk layer):**

- `SharedWriteContext.addShareKeysFn` — the callback type stays in types.ts for Phase 68 removal; Phase 65 rewires logic so it's never called.
- `originalFolderKeyEncrypted` field in bin tests (L724, L1063 of bin.test.ts) — delete from fixtures.
- Any sdk-core/sdk code that consumes `encryptedChildKeys` from invite data.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `sealChildWriteKey`/`unsealChildWriteKey` do not exist and must be added to seal.ts | Standard Stack, Missing section | If they exist elsewhere (e.g., in a branch), duplication waste; found by grep, HIGH confidence this is correct |
| A2 | `rotateWriteFromNode` is the correct name for the write-revocation driver | Architecture Patterns | Planner may choose different factoring; discretion per CONTEXT D-02 |
| A3 | `BinEntry.nodeRef` carries enough information to restore without re-encryption | Bin restore | If `nodeRef` lacks the sealed readKey blob (it's a `Node` type without `readKeySealed`), a different mechanism is needed — but design §3.10 confirms restore = pure re-link |
| A4 | The invite claim wiring requires a server round-trip to GET invite data | Invite claim pattern | API shape may differ; sdk-e2e invite-link.test.ts is quarantined so the current API shape must be confirmed against live API |

**If this table is short:** The primary uncertainty is A3 (BinEntry.nodeRef shape). The `BinEntry.nodeRef?: Node` field stores the full in-memory `Node` (decrypted), but the bin metadata is encrypted with the user's ECIES public key. Restore must recover the node's readKey from within — which comes from the node itself having been re-sealed in the bin entry. The planner should verify whether BinEntry needs a separate `nodeReadKey` field or whether the node's sealed structure is sufficient.

---

## Open Questions

1. **BinEntry.nodeRef and readKey recovery for restore**
   - What we know: `BinEntry.nodeRef?: Node` is the `Node` type (decrypted in-memory struct). The bin metadata is ECIES-encrypted to the user's public key. At restore time, the owner unseals the bin metadata to get the `Node`.
   - What's unclear: Does the `Node` stored in `nodeRef` include enough to re-derive the node's `readKey` (it doesn't — `readKey` is not stored in the plaintext `Node`)? The re-link needs the node's `readKey` to `sealChildReadKey` under the destination parent.
   - Recommendation: Planner must decide whether to add a `nodeReadKey` field to `BinEntry` or store the `SealedChildRef` (which has `readKeySealed` but not the raw key). The most natural approach is to store the `SealedChildRef` as the bin entry's link — then restore re-seals `child.readKey` (unsealed from the bin entry's sealed ref under the bin's own readKey) under the destination parent readKey. This is what design §3.10 "BinEntry is a `SealedChildRef`-shaped link sealed under the bin's own readKey" implies.

2. **Write-revocation cascade direction: upward vs. subtree**
   - What we know: Design §5.3 says "cascades parent re-points upward to the share root" — but the Ed25519 key rotation also changes each node's k51 name, which means CHILDREN need new names too (not just parents). The cascade goes BOTH ways: child nodes get new k51 names (bottom-up generation of new keypairs), and PARENT pointers must be updated to point at new child k51 names.
   - What's unclear: Is the cascade child-first (bottom-up) or root-first? The read-rotation is root-first (for immediate revocation cut). Write-rotation should be child-first (generate new k51 names for leaves first, then update parent pointers pointing at them, cascading up).
   - Recommendation: Child-first (bottom-up). Planner should document this ordering decision explicitly.

3. **SharedWriteContext reshape scope**
   - What we know: The current `SharedWriteContext` type in shared-write.ts has `folderKey: Uint8Array` and `ipnsPrivateKey: Uint8Array` (raw, exposed), plus `addShareKeysFn` (old fan-out callback). All six operations throw.
   - What's unclear: How much of `SharedWriteContext` survives? In the write-body model, `ipnsPrivateKey` comes from unsealing the write-body, not from a raw param. The `addShareKeysFn` callback stays as a type (Phase 68 removes it from types.ts) but Phase 65 rewires so the callback is never called.
   - Recommendation: Planner should decide whether to reshape the type or add a parallel `WriteChainContext` that replaces it. The safest approach is to reshape in place and keep the type name.

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Docker (docker-compose) | sdk-e2e test stack | Verify locally | — | No fallback — required for D-04 gate |
| Redis on port 6380 | sdk-e2e test stack | Verify locally | — | No fallback |
| `pnpm --filter @cipherbox/api dev` | sdk-e2e test stack | Verify locally | — | No fallback |
| `packages/core/dist` rebuild | sdk-core/sdk typecheck | Must rebuild after seal.ts changes | — | `pnpm --filter @cipherbox/core build` |

**Cross-package dist staleness:** After adding `sealChildWriteKey`/`unsealChildWriteKey` to `packages/core/src/node/seal.ts`, run `pnpm --filter @cipherbox/core build` before sdk-core or sdk typecheck. Skipping this produces phantom TS2345/TS2339 errors in downstream packages.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Vitest (sdk-core unit), Vitest (sdk unit), Vitest (sdk-e2e integration) |
| Config file | `packages/sdk-core/vitest.config.ts`, `packages/sdk/vitest.config.ts`, `tests/sdk-e2e/vitest.config.ts` |
| Quick run command (unit) | `pnpm --filter @cipherbox/sdk-core test run` |
| Quick run command (sdk-e2e) | Requires docker stack up + API dev server |
| Full suite command | `pnpm test` (CI) |

### Phase Requirements to Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| WRITE-01 | Write-body held by write-capable node; read-only holder cannot reach signing material | Unit | `pnpm --filter @cipherbox/sdk test run -- shared-write` | ❌ Wave 0 — rewrite existing stub test |
| WRITE-01 | sealChildWriteKey / unsealChildWriteKey round-trip with correct role 0x04 | Unit | `pnpm --filter @cipherbox/core test run -- seal` | ❌ Wave 0 |
| WRITE-02 | Write-revocation: new k51 per node, parent re-point cascade | E2E | sdk-e2e write-chain-rotation suite | ❌ Wave 0 |
| WRITE-03 | Surviving co-writer receives re-wrapped writeDescriptorRef; offline gets explicit error | Unit | sdk-core rotation test | ❌ Wave 0 |
| WRITE-04 | Tombstone-intent: unenrollFn called with old IPNS name | Unit | sdk-core rotation test (mock callback assertion) | ❌ Wave 0 |
| WRITE-01 | Read-only holder unseal of write-body with only readKey returns no writeBody | Unit | `pnpm --filter @cipherbox/core test run` | ❌ Wave 0 |
| Bin | Restore is pure re-link; no re-encryption | Unit | `pnpm --filter @cipherbox/sdk test run -- bin` | ✅ exists (skip block needs un-skip) |
| Invite | claimInviteReadKey re-wraps single readKey; no encryptedChildKeys | Unit | `pnpm --filter @cipherbox/sdk-core test run -- grant` | ✅ exists and passing |

### Wave 0 Gaps

- [ ] `packages/core/src/__tests__/node/seal.test.ts` — add `sealChildWriteKey`/`unsealChildWriteKey` test cases (role 0x04 KAT)
- [ ] `packages/sdk/src/__tests__/shared-write.test.ts` — rewrite for write-body model (currently tests old pre-v3 mocked API)
- [ ] `packages/sdk-core/src/__tests__/rotation/write-revocation.test.ts` — unit tests for `rotateWriteFromNode` with mocked callbacks
- [ ] `tests/sdk-e2e/src/suites/write-chain-rotation.test.ts` — new D-04 gate test
- [ ] Un-skip `describe.skip('addToBin — TODO(phase 65)')` and `describe.skip('restoreFromBin — TODO(phase 65)')` in `packages/sdk/src/__tests__/bin.test.ts` + update fixtures

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | — |
| V3 Session Management | No | — |
| V4 Access Control | Yes | Write-body sealed under separate `writeKey`; read grant never conveys `writeKey`; WRITE-01 |
| V5 Input Validation | Yes | Fail-closed guards: `nodeIpnsPrivateKey` length/all-zeros check (engine.ts L514-524); analogous guard needed for writeKey |
| V6 Cryptography | Yes | `sealAesGcmAad`/`wrapKey` only; never hand-roll; zeroization D-09 |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Read-only holder accessing Ed25519 signing material | Elevation of Privilege | `writeSealed` under independent `writeKey`; `unsealNode` without `writeKey` returns no `writeBody` (design §2.2 / WRITE-01) |
| Revoked writer publishing to old k51 name | Tampering | Tombstone-intent (WRITE-04); publish gate rejects (Phase 66 enforcement); old name removed from TEE batch (mock in Phase 65) |
| Stale write-body re-published under all-zeros writeKey | Tampering, Information Disclosure | Remove PLACEHOLDER_WRITE_KEY; fail-closed guard for writeKey analogous to existing IPNS private key guard |
| Callee zeroing reused session key buffer | Denial of Service | Zeroization rule D-09: only zero minted keys on failure paths; never zero caller-supplied keys |
| AAD transplant (write link from one node used for another) | Tampering | `buildNodeAad(childId, kb, childGeneration, 0x04)` binds to exact child identity |

---

## Sources

### Primary (HIGH confidence)

- `packages/core/src/node/seal.ts` — confirmed complete Phase-62 codec: `sealNode`, `unsealNode`, `sealChildReadKey`, `unsealChildReadKey`; confirmed `sealChildWriteKey`/`unsealChildWriteKey` ABSENT.
- `packages/sdk-core/src/rotation/engine.ts` — confirmed PLACEHOLDER_WRITE_KEY at L550, L594; `nodeKeySource` seam at L891, L1041; Phase-65 comments at L157, L213.
- `packages/sdk/src/share/shared-write.ts` — confirmed all 6 exports throw `'not implemented — phase 65 (write-chain)'`; `SharedWriteContext` type confirmed.
- `packages/sdk/src/bin/index.ts` — confirmed `addToBin` (L293) and `restoreFromBin` (L316) throw; `originalFolderKeyEncrypted` appears only in test fixtures, not in `BinEntry` type.
- `packages/core/src/bin/types.ts` — confirmed `BinEntry.nodeRef?: Node`; confirmed `originalFolderKeyEncrypted` is ABSENT from the type (already removed in Phase 62).
- `packages/sdk-core/src/share/grant.ts` — confirmed `claimInviteReadKey` is FULLY IMPLEMENTED; no `encryptedChildKeys` fan-out.
- `tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts` — confirmed Phase-64 manual-node-build pattern; `nodeKeySource` Map injection; `vi.spyOn` for capturing generated keys.
- `.planning/design/2026-06-26-sharing-read-keychaining-design.md` §2.2, §3.10, §3.11, §5.3, §5.5, §7.2, §7.3 — design source of truth.
- `docs/adr/0001-write-revocation-full-ed25519-rotation.md` — ratified (c) full Ed25519 rotation.

### Secondary (MEDIUM confidence)

- `packages/sdk/src/__tests__/bin.test.ts` — confirmed `describe.skip` blocks at L164, L473; `originalFolderKeyEncrypted` in fixture at L724, L1063.
- `packages/sdk-core/src/__tests__/share/grant.test.ts` — confirmed `encryptedChildKeys` is only tested to be ABSENT.
- `.planning/todos/pending/2026-06-29-rotateone-placeholder-writekey-phase65.md` — confirmed FLAG-63-U1 todo scope.

---

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — all function signatures verified by direct source read
- Architecture: HIGH — design §5.3 explicit; engine.ts seams confirmed at line-level
- Pitfalls: HIGH — PLACEHOLDER_WRITE_KEY and sealChildWriteKey gap confirmed by grep/read
- Bin re-link: HIGH — BinEntry type confirmed; stubs confirmed in index.ts
- Invite claim: HIGH — claimInviteReadKey confirmed fully implemented

**Research date:** 2026-06-30
**Valid until:** 2026-07-30 (30 days; codebase under active development — recheck engine.ts seams if Phase 64 has any follow-ups before Phase 65 execution)
