# Phase 64: Rotation Soundness — Revocation Guarantees - Research

**Researched:** 2026-06-29
**Domain:** Cryptographic read-key rotation — seam fill, crash-safety, concurrent-add merge, inner-grant re-mint, node-identity preservation
**Confidence:** HIGH (sourced from live codebase reads + project design docs + ADRs)

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Delete the `PLACEHOLDER_WRITE_KEY` publish fallback in `rotateOne`. Require real `ipnsPrivateKey` per frontier node; throw if absent. Test-supplied keymap threads keys via a test-provided source. Phase 65 owns write-body→key wiring.
- **D-02:** Out-of-band re-seal in the BFS caller (`rotateReadFromNode`). After each child's `rotateOne`, re-seal `childReadKey'` under the parent's NEW `readKey'` via `sealChildReadKey`, write back to the parent's `SealedChildRef[child]`, and publish the parent ONCE after all its children rotate (batched per §4.7). `rotateOne` stays focused on "rotate this node." Rename the `parentReadKey` misnomer at planner's discretion.
- **D-03:** Crash-safety E2E: throw-after-N + fresh-resume via `verifySubtreeClean`. Depth ≥ 2 tree (root → folder → file) with known keypairs. No durable job-record persistence (Phase 68). Re-running `rotateReadFromNode` with a fresh job record proves convergence.
- **D-04:** `reMintGrantsRootedAt` transport-decoupled via injected callbacks; unit-tested against mocked `shares` query + persist callback. Live `shares` persistence is Phase 66.
- **D-05:** `mintFileKeyOnRotate` fills per §4.1 / ADR 0002: mint `fileKey' = random32`, set `contentRekeyPending`, lazy re-key on next content write. Keep `fileKey` rotation coupled to `readKey` rotation coupled to `generation` bump.
- **D-06 IN:** `moveItem` dest-parent re-seal (FLAG-63-U2) and `updateFolderMetadataAndPublish` node-identity/generation preservation (drop `?? crypto.randomUUID()` / `?? 0`, make `nodeId`/`nodeGeneration` required), threaded through all six `client.ts` call sites.
- **D-06 OUT:** `client.ts` move dest-before-source publish-ordering durability → Phase 68.
- **D-07:** Job-record ordering hardening: move `completedNodeIds.add(nodeId)` to AFTER `reMintGrantsRootedAt`; fix resume guard (already-complete rootNodeId must NOT bypass `verifySubtreeClean`); persist terminal `jobRecord.status`; zero engine-derived child readKeys in BFS queue once children derived (terminal-owner only — never zero caller-supplied keys).
- **D-09 (adopted):** Batched parent-link publish. Publish each parent ONCE after all its children rotate.
- **D-10 (adopted):** Published IPNS records are the source of truth. Advisory job record. Resume rebuilds from IPNS truth via `verifySubtreeClean`.
- **Convergence test:** N is done iff `parent.SealedChildRef[N].generation == N.envelope.generation` and that generation exceeds the baseline when N was enqueued.

### Claude's Discretion

- Seam-function internal factoring and signatures (four seams keep their names, filled not re-architected).
- Whether to rename the `parentReadKey` misnomer.
- Helper extraction for the batched parent-publish.
- Exact `verifySubtreeClean` return shape and how the resume frontier is rebuilt.
- How the mocked-API unit tests and the test key source are structured.
- How fault injection is wired into the engine (injected hook vs test-only seam — keep test-only, not production code).

### Deferred Ideas (OUT OF SCOPE)

- M1 durable client floor (`{nodeId → highestGeneration}` IndexedDB persistence, `executeLazyRotation` deletion, `folderTree` reconcile-before-rotate) → Phase 68.
- Server-side `generation` gate → Phase 66.
- Full write-body signing material (per-node Ed25519 from write-body, write-revocation) → Phase 65.
- Live `shares` schema (`readDescriptorRef`/`writeDescriptorRef` columns, `share_keys` drop) → Phase 66.
- `client.ts` move dest-before-source ordering + unreadable-descendant enumeration → Phase 68.
- Web/FUSE host integration, Rust `Node` enum, TEE lease-renewer → Phases 67–69.

</user_constraints>

<phase_requirements>

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| ROT-03 | Rotating a file node mints a new `fileKey` (lazy `contentRekeyPending`); old readKey/fileKey cannot decrypt next published version | `mintFileKeyOnRotate` seam fill (L200–202 engine.ts); ADR 0002 |
| ROT-04 | Rotation re-mints `readDescriptorRef` for every non-revoked grant whose `rootNodeId` is in the rotated set | `reMintGrantsRootedAt` seam fill (L215–223); transport-decoupled via D-04 callbacks |
| ROT-05 | On CAS-409 the walk re-fetches and re-merges `SealedChildRef`s — a concurrent add is never silently dropped | `mergeConcurrentChildren` seam fill (L235–241) + `mergeChildren` fill in `folder/merge.ts` |
| ROT-06 | Crash mid-walk is recoverable via `verifySubtreeClean`; re-run converges, no incorrect double-bump, revoked recipient cut from root after root step | `verifySubtreeClean` seam fill (L255–257); D-07 job-record hardening |
| TEST-01 | Rotation crash-safety/resume suite in `tests/sdk-e2e` gates the phase | New `rotation-crash-safety.test.ts`; live stack prereqs |

</phase_requirements>

## Summary

Phase 64 fills the four named throwing stubs in `packages/sdk-core/src/rotation/engine.ts` (the Phase-63 scaffold) and hardens the multi-node BFS walk with crash-safety, concurrent-add merge, inner-grant re-mint, and content-key rotation. It is a seam-fill phase, not a re-architecture.

The Phase-63 CRITICAL deferred bug is confirmed in live code: `rotateOne` seals `newReadKeySealed` under `parentReadKey` (the child's own pre-rotation key — a legacy misnomer) and returns it, but `rotateReadFromNode` never writes it back to any parent's `SealedChildRef`. The D-02 fix lives in the BFS caller, not in `rotateOne`. After each child's `rotateOne` returns, `rotateReadFromNode` re-seals the child's fresh `readKey'` under the parent's NEW `readKey'` and publishes the parent once after all its children complete.

Two folded correctness bugs (D-06) complete the binding-stability surface: (1) `registration.ts` silently mints fresh UUIDs and resets generation to 0 on every `updateFolderMetadataAndPublish` call that omits `nodeId`/`nodeGeneration`, breaking AAD stability and the convergence test; (2) `moveItem` carries `readKeySealed` sealed under the source parent's readKey, making dest-path navigation AEAD-fail.

Phase 64 closes with a new `tests/sdk-e2e/rotation-crash-safety.test.ts` that exercises the full abort-and-resume cycle against the live local API stack, which is the only real client→API IPNS publish/resolve round-trip.

**Primary recommendation:** Fill the four seams in `engine.ts` in this order — D-06 first (unblocks stable test infrastructure), then D-02 re-seal fix, then D-01 fail-closed, then the four seam bodies, then D-07 hardening, then TEST-01.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Content-key rotation (ROT-03) | `sdk-core` engine | — | Pure crypto mutation on Node state; no API surface |
| Inner-grant re-mint (ROT-04) | `sdk-core` engine | API (Phase 66) | Crypto re-mint is sdk-core; transport-decoupled callbacks let Phase 66 wire live shares persistence |
| Concurrent-add merge (ROT-05) | `sdk-core` engine + `sdk-core/folder/merge.ts` | — | CAS-409 re-merge in the `publishWithCas` merge callback; `mergeChildren` is the domain logic |
| Crash-resume convergence (ROT-06) | `sdk-core` engine | — | `verifySubtreeClean` is a pure IPNS-resolve walk in sdk-core |
| Node-identity preservation (D-06) | `sdk-core/folder/registration.ts` + `sdk/client.ts` | — | `nodeId`/`nodeGeneration` required at seal site; caller threads them |
| Move re-seal (D-06) | `sdk/client.ts` | `sdk-core/folder/metadata-ops.ts` | Re-seal is async (IPNS resolve needed); client.ts is the right place |
| E2E crash-safety test (TEST-01) | `tests/sdk-e2e/` | — | Only real client→API IPNS round-trip; unit mocks hide CAS/zeroization regressions |

## Standard Stack

### Core (no new packages — all present in the monorepo)

| Module | Location | Purpose | Phase 64 Use |
|--------|----------|---------|--------------|
| `sealNode` / `unsealNode` | `@cipherbox/core` | Seal/unseal the full Node read-body | Re-seal rotated nodes under `readKey'`; fill `mintFileKeyOnRotate` |
| `sealChildReadKey` / `unsealChildReadKey` | `@cipherbox/core` | Seal/unseal `SealedChildRef.readKeySealed` (role 0x02) | D-02 re-seal fix; D-06 move re-seal |
| `sealContent` / `unsealContent` | `@cipherbox/core` | Seal file `content` under node's own readKey (role 0x03) | `mintFileKeyOnRotate` must seal new `content` under new readKey' |
| `buildNodeAad` | `@cipherbox/crypto` (via `@cipherbox/core`) | Build AAD for AES-GCM-AAD ops | Called transitively by `sealChildReadKey` — do not call directly |
| `publishWithCas` | `sdk-core/src/cas.ts:38` | CAS-retry publish helper | HIGH-4 re-merge plugs into the `merge` callback; already in use |
| `createAndPublishIpnsRecord` | `sdk-core/src/ipns/index.ts:39` | Create + publish IPNS record with CAS guard | Used by crash-safety suite for manual tree building |
| `resolveIpnsRecord` | `sdk-core/src/ipns/` | Resolve IPNS name → CID + sequenceNumber | `verifySubtreeClean` BFS walk |
| `generateRandomBytes` | `@cipherbox/crypto` | Generate 32 cryptographically random bytes | `mintFileKeyOnRotate` → `fileKey'`; `readKey'` (already in `rotateOne`) |
| `wrapKey` / `unwrapKey` (ECIES) | `@cipherbox/crypto` | ECIES key wrap/unwrap | `reMintGrantsRootedAt` re-wraps `readDescriptorRef` for remaining grantees |

**No new npm packages are required. All required primitives are already in the monorepo.**

### Package Legitimacy Audit

No external packages are installed in this phase. All dependencies are internal monorepo packages already present. **Packages removed due to SLOP verdict:** none. **Packages flagged SUS:** none.

## Architecture Patterns

### System Architecture Diagram

```
rotateReadFromNode (entry point)
  │
  ├─ [resume path] verifySubtreeClean(rootNodeId)
  │    └── BFS IPNS resolve → check parent.SealedChildRef[N].generation
  │         vs N.envelope.generation → rebuild dirty-edge frontier
  │
  ├─ rotateOne(root, rootReadKey)  ← §4.2 "root first" cut
  │    ├── resolveIpnsRecord → fetchPublishedNode
  │    ├── unsealNode(parentReadKey=rootReadKey) → Node
  │    ├── [file] mintFileKeyOnRotate → fileKey', contentRekeyPending
  │    ├── sealNode(node{generation+1}, readKeyPrime, PLACEHOLDER_WRITE_KEY)
  │    ├── sealChildReadKey(readKeyPrime, parentReadKey, ...) → newReadKeySealed [NOTE: seals under CHILD's own old key — legacy misnomer; D-02 fixes this in the CALLER]
  │    ├── publishWithCas → { cid, newSeq }
  │    │     └── merge callback: [409] mergeConcurrentChildren → re-fetch + re-merge SealedChildRefs
  │    ├── completedNodeIds.add(nodeId)  [AFTER reMintGrantsRootedAt — D-07]
  │    └── [if innerGrants] reMintGrantsRootedAt → re-mint readDescriptorRef via callbacks
  │         └── revoked recipient row deleted
  │
  ├─ [D-02 out-of-band, in rotateReadFromNode]
  │    For each child of root:
  │    re-sealChildReadKey(childReadKey', rootNewReadKey', childPub.id, kind, newGen)
  │    → update root's SealedChildRef[child]
  │
  ├─ [D-09 batched] publish root node with updated SealedChildRefs (once)
  │
  └─ BFS frontier loop:
       rotateOne(child, childOldReadKey) → childReadKeyPrime
       [D-02] re-seal grandchild refs under childReadKeyPrime
       [D-09] publish child with updated SealedChildRefs
       → enqueue grandchildren with grandchildOldReadKey
       [D-07] zero childOldReadKey after grandchildren enqueued (terminal-owner)
```

### Recommended Project Structure

No new directories. All changes are within existing files:

```
packages/sdk-core/src/rotation/
├── engine.ts          # Fill 4 seams + D-02/D-01/D-07 fixes (NAMED FILE — not a barrel, SC#5)
└── scope.ts           # Unchanged (hasCoveringGrant present, gates moveItem)

packages/sdk-core/src/folder/
├── metadata-ops.ts    # moveItem: pure link rewrite (unchanged); re-seal lives in client.ts caller
├── merge.ts           # Fill mergeChildren stub (Phase-64 owner per file comment)
└── registration.ts    # Make nodeId/nodeGeneration required (L174-175 fix)

packages/sdk-core/src/__tests__/rotation/
└── engine.test.ts     # Add parent-ref-update assertion, resume test, zeroization test, reMintGrantsRootedAt mock-test

packages/sdk/src/
├── types.ts           # Add nodeId/nodeGeneration to FolderState
└── client.ts          # Thread nodeId/nodeGeneration into 6 call sites; add move re-seal

tests/sdk-e2e/src/suites/
└── rotation-crash-safety.test.ts  # NEW (TEST-01)
```

### Pattern 1: Filling a Phase-64 Seam

Each seam replaces a `throw new Error('not implemented — phase 64 ...')` with a real body. The signature is frozen; only the body changes.

```typescript
// Source: engine.ts — Phase-63 scaffold pattern
export async function mintFileKeyOnRotate(node: Node, job: RotationJobRecord): Promise<void> {
  // Phase 64 body replaces the throw:
  const fileKeyPrime = crypto.getRandomValues(new Uint8Array(32));
  // Set contentRekeyPending on the node's content (lazy — applied on next content write)
  if (node.content) {
    node.content.fileKey = fileKeyPrime; // rotateOne will re-seal node under readKeyPrime
    // Phase 65 wires the contentRekeyPending flag to the write path
  }
  // Do NOT zero fileKeyPrime here — rotateOne is the terminal owner via node.content
  void job; // job-record persistence is D-07 / Phase 68
}
```

### Pattern 2: D-02 Out-of-Band Re-Seal in BFS Caller

After each child's `rotateOne` returns, `rotateReadFromNode` re-seals the child's link under the parent's NEW readKey':

```typescript
// Source: D-02 decision + §4.5 step 6 design
// parentNewReadKey: the parent's own rotateOne returned `childReadKey` (its minted readKey')
// childResult.childReadKey: the child's newly minted readKey' (from rotateOne return)
const updatedReadKeySealed = await sealChildReadKey(
  childResult.childReadKey,  // child's new readKey'
  parentNewReadKey,           // parent's NEW readKey' (not the old one!)
  childPub.id,                // from PublishedNode.id (plaintext in envelope)
  childPub.kind,              // from PublishedNode.kind (plaintext in envelope)
  childResult.newGeneration   // child's new generation
);
// Update parent's SealedChildRef in-memory, publish parent once (D-09)
```

### Pattern 3: D-04 Transport-Decoupled reMintGrantsRootedAt

Callbacks injected via RotateOneParams (testability seam — D-04):

```typescript
// Source: Phase-63 D-05 / STATE.md "Share module accepts callback functions" pattern
export async function reMintGrantsRootedAt(
  nodeId: string,
  newReadKey: Uint8Array,
  newGeneration: number,
  job: RotationJobRecord,
  ctx: SdkContext,
  // Injectable transport seam (D-04):
  callbacks?: {
    queryGrantsFn: (nodeId: string) => Promise<ReadonlyArray<{ shareId: string; recipientPublicKey: Uint8Array; isRevoked: boolean }>>;
    updateGrantFn: (shareId: string, readDescriptorRef: string, newGeneration: number) => Promise<void>;
    deleteGrantFn: (shareId: string) => Promise<void>;
  }
): Promise<void> {
  if (!callbacks) return; // no grants to re-mint (invoked only when innerGrants non-empty)
  const grants = await callbacks.queryGrantsFn(nodeId);
  for (const grant of grants) {
    if (grant.isRevoked) {
      await callbacks.deleteGrantFn(grant.shareId);
    } else {
      const readDescriptorRef = await wrapKey(newReadKey, grant.recipientPublicKey); // ECIES
      await callbacks.updateGrantFn(grant.shareId, readDescriptorRef, newGeneration);
    }
  }
}
```

### Pattern 4: TEST-01 Manual-Node Tree Build (sdk-e2e)

Extending the Phase-63 pattern from `read-chain-navigation.test.ts`:

```typescript
// Source: tests/sdk-e2e/src/suites/read-chain-navigation.test.ts (Phase-63 scaffold)
// Phase 64 extends to depth ≥ 2 (root → subfolder → file) with known keypairs

// Per-node keypair map for fail-closed engine (D-01)
const keyMap = new Map<string, { privateKey: Uint8Array; publicKey: Uint8Array }>();

// Step 1: Create root folder (createSubfolder — provides known keypair)
const rootResult = await createSubfolder({ name: 'crash-test-root', ctx: aliceCtx });
const rootIpnsPublicKey = deriveEd25519PublicKey(rootResult.ipnsPrivateKey);
const rootIpnsName = await deriveIpnsName(rootIpnsPublicKey);
keyMap.set(rootIpnsName, { privateKey: rootResult.ipnsPrivateKey, publicKey: rootIpnsPublicKey });

// Step 2: createSubfolder for child folder → store keypair
// Step 3: sealNode + addToIpfs + createAndPublishIpnsRecord (seq 1n) for file node → store keypair
// Step 4: Build tree (updateFolderMetadataAndPublish with nodeId + nodeGeneration)
// Step 5: Fault injection via hook after N committed nodes
// Step 6: Resume via fresh RotationJobRecord → rotateReadFromNode → verifySubtreeClean rebuilds
// Step 7: Assert no double-bump (generation == baseline+1), revoked gets 'behind-retry'
```

### Pattern 5: D-07 Job-Record Hardening

Move `completedNodeIds.add` to AFTER `reMintGrantsRootedAt`:

```typescript
// CURRENT (Phase 63, bug):
jobRecord.completedNodeIds.add(nodeId);  // L386 — too early
if (innerGrants && innerGrants.length > 0) {
  await reMintGrantsRootedAt(...);       // L391 — if this throws, node is skipped on resume
}

// FIXED (Phase 64):
if (innerGrants && innerGrants.length > 0) {
  await reMintGrantsRootedAt(...);       // re-mint first
}
jobRecord.completedNodeIds.add(nodeId);  // mark done only after ALL work succeeds
```

### Anti-Patterns to Avoid

- **Zeroing caller-supplied keys:** Never `parentReadKey.fill(0)` or `rootReadKey.fill(0)` in engine or helpers. Only zero keys minted by rotateOne (`readKeyPrime`, `fileKeyPrime`) on failure paths. Zero queue-derived child keys after children are enqueued (terminal-owner rule). This is Pitfall 16.
- **Barrel placement:** Do NOT move `engine.ts` into `rotation/index.ts`. Coverage excludes `src/**/index.ts`. This is Pitfall 14 / SC#5.
- **Sealing newReadKeySealed under the child's own key:** The current `sealChildReadKey(readKeyPrime, parentReadKey, ...)` in `rotateOne` is wrong because `parentReadKey` is the child's own key (legacy misnomer). The parent-link re-seal MUST happen in `rotateReadFromNode` under the parent's NEW `readKey'`.
- **crypto.randomUUID() in encodeAndUpload:** The `updateFolderMetadataAndPublish` call must pass `nodeId` and `nodeGeneration`; every omission silently mints a new UUID and resets generation to 0 (D-06 CRITICAL).
- **Stale child list in merge:** On CAS-409, ALWAYS re-fetch the remote and re-merge `SealedChildRef`s. Never re-seal from the in-memory child list captured before the 409. This is Pitfall 4.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| AEAD with AAD | Custom AES-GCM | `sealAesGcmAad` / `unsealAesGcmAad` + `buildNodeAad` from `@cipherbox/core` | AAD encoding is frozen in ADR 0003; role bytes 0x01-0x04 KAT-tested |
| Child-readKey seal/unseal | Custom AES-GCM | `sealChildReadKey` / `unsealChildReadKey` from `@cipherbox/core` | Correct AAD (role 0x02), UUID byte encoding, generation encoding all handled |
| ECIES key wrap | Custom ECDH/KEM | `wrapKey` / `unwrapKey` from `@cipherbox/crypto` | readDescriptorRef re-mint for D-04 reMintGrantsRootedAt |
| CAS-retry loop | Custom retry | `publishWithCas` from `sdk-core/src/cas.ts` | Exponential backoff, 409 detection, merge callback pattern already in use |
| IPNS resolve | Custom HTTP | `resolveIpnsRecord` from `sdk-core/src/ipns` | Already wired in engine.ts |
| Node seal/unseal | Custom JSON+crypto | `sealNode` / `unsealNode` from `@cipherbox/core` | Handles write-body absence (Phase 63 read-chain only); PLACEHOLDER_WRITE_KEY pattern already in rotateOne |

**Key insight:** Every Phase-62 codec primitive is complete and callable. Phase 64 calls them — never reimplements them. The AAD encoding is frozen (ADR 0003) and cross-language KAT-tested. Even a single byte divergence from `buildNodeAad` is a silent total decryption failure.

## Engine State: Verified Phase-63 Scaffold

### Four Named Throwing Seams (VERIFIED: live code read)

```typescript
// engine.ts L200-202
export async function mintFileKeyOnRotate(_node: Node, _job: RotationJobRecord): Promise<void> {
  throw new Error('not implemented — phase 64 (ROT-03/CRIT-1 content-key rotation)');
}

// engine.ts L215-223
export async function reMintGrantsRootedAt(
  _nodeId: string, _key: Uint8Array, _gen: number, _job: RotationJobRecord, _ctx: SdkContext
): Promise<void> {
  throw new Error('not implemented — phase 64 (ROT-04/HIGH-3 inner-grant re-mint)');
}

// engine.ts L235-241
export async function mergeConcurrentChildren(
  _node: Node, _resolved: unknown, _ctx: SdkContext
): Promise<void> {
  throw new Error('not implemented — phase 64 (ROT-05/HIGH-4 concurrent-add merge)');
}

// engine.ts L255-257
export async function verifySubtreeClean(_rootNodeId: string, _ctx: SdkContext): Promise<boolean> {
  throw new Error('not implemented — phase 64 (ROT-06 crash-resume + verifySubtreeClean)');
}
```

### `RotateOneParams` Signature (VERIFIED: live code read)

```typescript
type RotateOneParams = {
  nodeId?: string;
  nodeIpnsName: string;
  nodeIpnsPrivateKey?: Uint8Array;  // D-01: must throw if absent after Phase 64 fix
  nodeIpnsPublicKey?: Uint8Array;
  parentReadKey: Uint8Array;        // LEGACY MISNOMER: carries this node's OWN pre-rotation key
  parentIpnsName: string;
  parentCurrentSeq: bigint;
  jobRecord: RotationJobRecord;
  ctx: SdkContext;
  innerGrants?: ReadonlyArray<unknown>;
}
```

### `RotateOneDone` Return (VERIFIED: live code read)

```typescript
type RotateOneDone = {
  skipped: false;
  childReadKey: Uint8Array;  // The freshly minted readKey' for THIS node (not a child of it)
  newGeneration: number;
  newReadKeySealed: string;  // WRONG: sealed under parentReadKey (child's own old key) — D-02 fix
  children: SealedChildRef[];
}
```

### Phase-63 CRITICAL Re-Seal Bug (VERIFIED: live code read)

**Location:** `engine.ts` L344-350

```typescript
// Phase 63 current (BUGGY):
const newReadKeySealed = await sealChildReadKey(
  readKeyPrime,   // child's new readKey'
  parentReadKey,  // child's OWN pre-rotation key (WRONG — should be parent's NEW readKey')
  nodeId,
  node.kind,
  generationPrime
);
```

**The bug:** `parentReadKey` is the **child's own** pre-rotation readKey (a legacy misnomer in the param name). The parent's `SealedChildRef[N].readKeySealed` must be sealed under the **parent's NEW** `readKey'` for `unsealChildReadKey(sealedRef, parentNewReadKey', childId, kind, gen)` to authenticate. Additionally, `newReadKeySealed` is returned in `RotateOneDone` but `rotateReadFromNode` never writes it back to any parent's `SealedChildRef`. Without the D-02 fix, `unsealChildReadKey` on any non-root node will fail with a decryption error.

### D-01 Placeholder Fallback (VERIFIED: live code read)

**Location:** `engine.ts` ~L357 (inside `publishWithCas` call)

```typescript
// Phase 63 current (MUST DELETE in Phase 64):
await publishWithCas<PublishedNode>({
  ipnsName: nodeIpnsName,
  ipnsPrivateKey: nodeIpnsPrivateKey ?? PLACEHOLDER_WRITE_KEY,  // ← DELETE THIS
  ...
});
```

Phase 64 replaces `nodeIpnsPrivateKey ?? PLACEHOLDER_WRITE_KEY` with:
```typescript
if (!nodeIpnsPrivateKey) throw new Error(`rotateOne: no IPNS private key for ${nodeIpnsName} — Phase 65 wires write-body keys`);
ipnsPrivateKey: nodeIpnsPrivateKey,
```

### D-07 Job-Record Ordering Bug (VERIFIED: live code read)

**Location 1:** `engine.ts` L386 — `completedNodeIds.add(nodeId)` placed BEFORE `reMintGrantsRootedAt` call at L391. A failed re-mint at L391 leaves the node in `completedNodeIds` and it would be skipped on resume, silently omitting the grant re-mint. Fix: swap the order.

**Location 2:** `rotateReadFromNode` L458-462 — resume guard:
```typescript
if (rootResult.skipped) {
  jobRecord.status = 'complete';  // WRONG: bypasses verifySubtreeClean
  if (jobRecord.persistCallback) await jobRecord.persistCallback(jobRecord);
  return;
}
```
Fix: when root is already committed, call `verifySubtreeClean` to rebuild the frontier and continue the walk rather than marking complete immediately.

### D-06 Node-Identity Bug (VERIFIED: live code read)

**Location:** `registration.ts` L174-175

```typescript
// Phase 63 current (BUGGY):
const node: Node = {
  schema: 'node/v3',
  kind: 'folder',
  id: params.nodeId ?? crypto.randomUUID(),   // ← BUG: fresh UUID on every call without nodeId
  generation: params.nodeGeneration ?? 0,      // ← BUG: resets generation to 0
  ...
};
```

**Why critical:** `buildNodeAad(id, kind, generation, role)` uses `id` (UUID) as the AAD. A fresh UUID per call means every re-seal produces a ciphertext that cannot be decrypted with the original AAD (the old UUID). `generation = 0` after any rotation means the `parent.SealedChildRef[N].generation == N.envelope.generation` convergence test is permanently broken.

**Fix:** Remove `?? crypto.randomUUID()` and `?? 0`. Make `nodeId: string` and `nodeGeneration: number` required fields. All 6 client.ts call sites must supply them from `folder.metadata.id` and `folder.metadata.generation` (FolderState.metadata is a `Node | null` already in scope — non-null after `loadFolder`).

### Six client.ts Call Sites Needing nodeId/nodeGeneration (VERIFIED: live code read)

| Line | Method | Current call | Missing fields |
|------|--------|-------------|----------------|
| L493 | `renameItem` | `folderKey`, no nodeId/nodeGeneration | `nodeId: folder.metadata!.id`, `nodeGeneration: folder.metadata!.generation` |
| L558 | `moveItem` (src) | `readKey`, no nodeId/nodeGeneration | same |
| L581 | `moveItem` (dst) | `readKey`, no nodeId/nodeGeneration | same |
| L629 | `deleteItem` | `folderKey`, no nodeId/nodeGeneration | same |
| L747 | `uploadFile` | `folderKey`, no nodeId/nodeGeneration | same |
| L1006 | `uploadFiles` | `folderKey`, no nodeId/nodeGeneration | same |

`FolderState.metadata: Node | null` — populated by `loadFolder` (sets `metadata: result.metadata`). For call sites where `metadata` may be null (registered via `registerFolder` without a full load), need to either: (a) require non-null metadata in the callers or (b) add `nodeId: string; nodeGeneration: number` as required fields to `FolderState` populated during both `registerFolder` and `loadFolder`. The D-06 fix must ensure both paths populate the identity fields.

### D-06 moveItem Re-Seal (VERIFIED: live code read)

`metadata-ops.ts` `moveItem` (L132-143) is a pure sync function that carries `movedRef` as-is, with `readKeySealed` sealed under the source parent's readKey. The D-06 re-seal lives in **`client.ts` moveItem**, between calling `sdkCore.moveItem` and the dest `updateFolderMetadataAndPublish` call:

```typescript
// In client.ts moveItem, after sdkCore.moveItem returns movedRef:
// 1. Resolve the child's IPNS → get PublishedNode.id and .kind (plaintext in envelope)
const childPub = await resolveAndFetchChild(movedRef.ipnsName, this.ctx);
// 2. Unseal from source parent
const childReadKey = await unsealChildReadKey(
  movedRef.readKeySealed, sourceFolder.folderKey,
  childPub.id, childPub.kind, movedRef.generation
);
// 3. Re-seal under dest parent
const newReadKeySealed = await sealChildReadKey(
  childReadKey, destFolder.folderKey,
  childPub.id, childPub.kind, movedRef.generation
);
movedRef.readKeySealed = newReadKeySealed;
// 4. Now publish dest with updated movedRef (existing updateFolderMetadataAndPublish call)
```

### merge.ts Phase-64 Stub (VERIFIED: live code read)

`packages/sdk-core/src/folder/merge.ts` has a Phase-64 stub:

```typescript
export function mergeChildren(
  base: SealedChildRef[], local: SealedChildRef[], remote: SealedChildRef[]
): never {
  throw new Error('not implemented — phase 64 (CAS merge on sealed child refs)');
}
```

Phase 64 fills this with a three-way merge: union of `local` and `remote` by `ipnsName`, with `remote` winning on conflicts (concurrent add wins). The `base` is used to detect deletions (if an entry is in base but not in both local and remote, it was intentionally deleted — don't resurrect it).

### verifySubtreeClean Implementation Shape

```typescript
// Source: §4.5 design — "O(items) read-only pass flagging parent.link.generation ≠ child.envelope.generation"
export async function verifySubtreeClean(rootNodeId: string, ctx: SdkContext): Promise<{
  isDirty: boolean;
  frontier: Array<{ ipnsName: string; nodeId: string }>;
}> {
  // BFS from root:
  // 1. Resolve each node → fetch PublishedNode (generation in plaintext)
  // 2. For each SealedChildRef: compare ref.generation vs child envelope.generation
  // 3. Mismatch → child is in-flight → add to frontier
  // 4. All match → subtree is clean
  // Return isDirty + frontier for resume
}
```

The resume path in `rotateReadFromNode`: call `verifySubtreeClean` when `completedNodeIds` is non-empty at walk start (instead of the current short-circuit that marks complete). Feed the returned frontier into the BFS queue.

## Common Pitfalls

### Pitfall 1: Re-Seal Under Child's Own Key (CRIT — confirmed in Phase 63 code)

**What goes wrong:** `sealChildReadKey(readKeyPrime, parentReadKey, ...)` in the current `rotateOne` uses `parentReadKey` (which is the child's OWN pre-rotation key, despite the name). The parent's `SealedChildRef.readKeySealed` then fails `unsealChildReadKey(sealedRef, parentNewReadKey', ...)` because it was sealed under a different key.

**How to avoid:** The D-02 re-seal MUST happen in `rotateReadFromNode` (the walk caller), not in `rotateOne`. `rotateOne` continues to seal `newReadKeySealed` under `parentReadKey` (child's own key) for local reference — the caller overwrites this with the correct re-seal.

**Warning sign:** Any non-root node in the BFS queue fails `unsealChildReadKey` with a decryption error.

### Pitfall 2: Content-Key Rotation Omitted from mintFileKeyOnRotate (Pitfall 2 from PITFALLS.md)

**What goes wrong:** Re-sealing the read-body under `readKey'` is not sufficient. The revoked reader already holds `content.fileKey`. If the next file write uses the same `fileKey`, the revoked reader can decrypt it.

**How to avoid:** `mintFileKeyOnRotate` MUST mint `fileKey' = random32` AND set `contentRekeyPending`. Both are required. Test: §7.3 test 2 — old `readKey`/`fileKey` cannot decrypt the next published version.

### Pitfall 3: Stale Child List on CAS-409 Retry (Pitfall 4 from PITFALLS.md)

**What goes wrong:** `mergeConcurrentChildren` receives `(node, resolved, ctx)` where `node` is the in-memory unsealed node from BEFORE the 409. A concurrent add visible in `resolved` would be silently dropped if the merge re-seals from `node.children`.

**How to avoid:** On 409, unseal the REMOTE `PublishedNode` under the OLD `parentReadKey` (the current node's pre-rotation key). Extract remote children. Merge: take union of pre-rotation children + remote children by `ipnsName`, with remote entries winning. Then re-seal under `readKeyPrime`.

**Warning sign:** After a concurrent add, the added child is absent from the rotated parent. Test: §7.3 test 4.

### Pitfall 4: Zeroization of Caller-Supplied Keys (Pitfall 16 from PITFALLS.md)

**What goes wrong:** Zeroing `parentReadKey` (or `rootReadKey`) inside `rotateOne` or a helper destroys the caller's live buffer, breaking subsequent operations (400 "publicKey does not correspond" pattern).

**Rules (D-09):**
- `rotateOne` mints `readKeyPrime` → zeros it on failure paths before re-throw (terminal owner).
- Queue-derived child readKeys: zero after the child's grandchildren are enqueued (terminal owner, not caller-supplied).
- NEVER zero `parentReadKey`, `rootReadKey`, or any caller-supplied buffer.

### Pitfall 5: Convergence Test Missing When resuming via verifySubtreeClean

**What goes wrong:** The resume guard at engine.ts L458 marks the whole walk complete if root is in `completedNodeIds`, bypassing `verifySubtreeClean`. An aborted walk where the root committed but children did not would never finish.

**How to avoid:** When root is already committed (skipped), call `verifySubtreeClean(rootNodeId, ctx)` to rebuild the dirty-edge frontier. Continue BFS from that frontier. Only mark `jobRecord.status = 'complete'` when `verifySubtreeClean` returns zero dirty edges.

### Pitfall 6: FolderState.metadata null at Call Sites

**What goes wrong:** `registerFolder` in client.ts does not populate `metadata`. If one of the 6 call sites uses `folder.metadata!.id` and `metadata` is null, it throws.

**How to avoid:** Either (a) require `metadata` to be non-null at all 6 call sites (ensure `loadFolder` is always called before mutations), or (b) add `nodeId: string; nodeGeneration: number` as separate required fields to `FolderState` populated by both `registerFolder` and `loadFolder`.

## State of the Art

| Phase-63 State | Phase-64 Target | Impact |
|----------------|-----------------|--------|
| 4 seams throw Phase-64 errors | 4 seams filled with real bodies | Completes the rotation engine for all 3 revocation gaps |
| `rotateOne` seals `newReadKeySealed` under child's own key (never written to parent) | D-02: re-seal in BFS caller under parent's NEW readKey'; batched parent-publish | Fixes CRITICAL: non-root nodes no longer AEAD-fail on `unsealChildReadKey` |
| `nodeIpnsPrivateKey ?? PLACEHOLDER_WRITE_KEY` fallback | Throw if absent; test-supplied keymap threads real keys | Closes the "never publish with a placeholder key" finding |
| `registration.ts` `?? crypto.randomUUID()` / `?? 0` fallbacks | Required `nodeId` + `nodeGeneration` fields | Fixes AAD stability and convergence-test witness |
| `moveItem` carries source-sealed `readKeySealed` to dest | Re-seal in client.ts before dest publish | Fixes AEAD-fail on dest-path navigation |
| `completedNodeIds.add()` before `reMintGrantsRootedAt` | After | Failed re-mint no longer silently skipped on resume |
| Resume guard marks complete without `verifySubtreeClean` | Call `verifySubtreeClean`, continue from dirty frontier | Crash-resume convergence (ROT-06) |
| Phase-63 sdk-e2e: single root-step, expects Phase-64 throw | New crash-safety suite: depth ≥ 2, abort-and-resume | TEST-01 gate |

**Deprecated/outdated:**
- `PLACEHOLDER_WRITE_KEY` publish fallback in `rotateOne`: deleted entirely (D-01).
- `nodeId ?? crypto.randomUUID()` and `nodeGeneration ?? 0` in `registration.ts`: deleted (D-06).
- Phase-63 resume guard (L458-462 that bypasses `verifySubtreeClean`): replaced with frontier-rebuilding resume path.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `folder.metadata` is non-null at all 6 `updateFolderMetadataAndPublish` call sites after `loadFolder` | D-06 call sites | If metadata is null at a call site, `folder.metadata!.id` throws — mitigation: add explicit `nodeId`/`nodeGeneration` to `FolderState` | [ASSUMED]
| A2 | `PublishedNode.id` and `.kind` are always available in plaintext (no additional fetch beyond IPNS resolve) for the moveItem re-seal | D-06 FLAG-63-U2 | If the child's IPNS record returns a CID that is not yet available via IPFS, the re-seal fails — same risk as existing `rotateReadFromNode` child resolution | [ASSUMED]
| A3 | The `innerGrants` injection pattern for `reMintGrantsRootedAt` will accept callbacks in its signature (Phase 64 extends the signature beyond the current stub) | D-04 | If existing tests hard-import the exact stub signature, they need updating | [ASSUMED — low risk, seam fill pattern] |
| A4 | `mergeChildren` in `folder/merge.ts` is ONLY called from `updateFolderMetadataAndPublish`'s merge callback (no other call sites) | D-06 / merge.ts fill | If other callers exist, filling it changes their behavior | [ASSUMED — verified no other imports in sdk-core/sdk by grep expectation] |

**If this table is empty:** Not empty — four low-risk assumptions logged above.

## Open Questions (RESOLVED)

1. **FolderState identity fields vs metadata access** — **RESOLVED** (planned in 64-01)
   - What we know: `FolderState.metadata: Node | null`; `registerFolder` sets `metadata: null`; `loadFolder` sets `metadata: result.metadata`.
   - What's unclear: Which of the 6 call sites may have `metadata: null` at invocation time? The `createSubfolder` path (used in sdk-e2e) registers a folder without loading it.
   - **Resolution:** Plan 64-01 adds `nodeId: string; nodeGeneration: number` as explicit required fields to `FolderState`, populated in both `registerFolder` (from the caller-supplied node) and `loadFolder` (from `result.metadata.id`/`.generation`), and threads them through all 6 `client.ts` call sites. This is safer than relying on `metadata` being non-null (closes assumption A1).

2. **BFS parent-grouping for batched parent-publish (D-09)** — **RESOLVED** (planned in 64-04)
   - What we know: D-02 requires publishing each parent ONCE after all its children rotate.
   - What's unclear: The flat BFS queue doesn't inherently know when all children of a parent are done. Need a parent-tracking structure or a simpler per-child publish (less efficient but correct).
   - **Resolution:** Plan 64-04 Task 2 uses a `Map<parentIpnsName, parentState>` accumulator in `rotateReadFromNode` to collect each parent's re-sealed `SealedChildRef`s and publish the parent once after all its children rotate (Claude's discretion per D-02 exercised toward the Map approach).

## Environment Availability

| Dependency | Required By | Available | Fallback |
|------------|------------|-----------|----------|
| Docker + docker compose | TEST-01 sdk-e2e (live API stack) | Assumed ✓ (used in Phase-63 sdk-e2e) | None — required for TEST-01 |
| `pnpm --filter @cipherbox/api dev` | TEST-01 sdk-e2e live API | Assumed ✓ | None — required |
| Redis on port 6380 | TEST-01 sdk-e2e (api uses redis) | Assumed ✓ (docker compose) | None — required |
| `@cipherbox/core` dist rebuilt | sdk-core typecheck after any core changes | Manual: `pnpm --filter @cipherbox/core build` | None — required before typecheck |

**Missing dependencies with no fallback:**
- Live local stack for TEST-01. Standard setup: `docker compose -f docker/docker-compose.yml up -d && pnpm --filter @cipherbox/api dev`.

## Validation Architecture

> Nyquist validation is enabled (config key absent = enabled).

### Test Framework

| Property | Value |
|----------|-------|
| Unit framework | vitest (sdk-core: `packages/sdk-core/vitest.config.ts`) |
| E2E framework | vitest (tests/sdk-e2e: `tests/sdk-e2e/vitest.config.ts`) |
| Unit config file | `packages/sdk-core/vitest.config.ts` |
| Unit quick run | `pnpm --filter @cipherbox/sdk-core test --run` |
| Unit full run | `pnpm --filter @cipherbox/sdk-core test --run --coverage` |
| E2E run | `pnpm -C tests/sdk-e2e test --run` (requires live stack) |
| Coverage gate | 80% (sdk-core); engine.ts MUST appear in coverage (not a barrel) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| ROT-03 | Old readKey/fileKey cannot decrypt next published file version after rotation | unit | `pnpm --filter @cipherbox/sdk-core test --run src/__tests__/rotation/engine.test.ts` | ✅ (add test) |
| ROT-04 | Non-revoked grantee's readDescriptorRef is re-minted; revoked recipient's row deleted | unit | same engine.test.ts + new grant-remint.test.ts | ❌ Wave 0 |
| ROT-05 | Concurrent add during rotation is present in the completed parent (no drop) | unit + E2E | unit: engine.test.ts merge test; E2E: rotation-crash-safety.test.ts §7.3 test 4 | ❌ Wave 0 |
| ROT-06 | Crash + resume converges; no double-bump; verifySubtreeClean rebuilds frontier | unit + E2E | unit: engine.test.ts resume test; E2E: rotation-crash-safety.test.ts abort+resume | ❌ Wave 0 |
| TEST-01 | sdk-e2e crash-safety suite passes against live stack | E2E (live) | `pnpm -C tests/sdk-e2e test --run` (live stack required) | ❌ Wave 0 |
| D-06 nodeId | updateFolderMetadataAndPublish called without nodeId throws (required field) | unit | `pnpm --filter @cipherbox/sdk-core test --run src/__tests__/folder/registration.test.ts` | needs update |
| D-06 moveItem | dest-path navigation succeeds after moveItem (AEAD round-trip) | unit | new test in metadata-ops.test.ts or client.test.ts | ❌ Wave 0 |
| D-07 ordering | Failed reMintGrantsRootedAt does not advance completedNodeIds | unit | engine.test.ts | needs new test |
| D-02 re-seal | Parent's SealedChildRef[N].readKeySealed updated with child's new readKey'; parent published | unit | engine.test.ts (existing test at L247 verifies sealChildReadKey called once — Phase 64 strengthens to assert parent ref is updated AND republished) | extend existing test |

### Sampling Rate

- **Per-task commit:** `pnpm --filter @cipherbox/sdk-core test --run` (unit, no live stack)
- **Per-wave merge:** `pnpm --filter @cipherbox/sdk-core test --run --coverage` + `pnpm typecheck` (all packages)
- **Phase gate:** Full suite including `pnpm -C tests/sdk-e2e test --run` (live stack) must be green before `/gsd-verify-work`.

### Wave 0 Gaps (new files required before implementation)

- [ ] `packages/sdk-core/src/__tests__/rotation/grant-remint.test.ts` — ROT-04 mock-tested unit tests for `reMintGrantsRootedAt` with mocked callbacks
- [ ] `tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts` — TEST-01; extends Phase-63 read-chain-navigation pattern to depth ≥ 2 + abort/resume
- [ ] Extend `engine.test.ts` — add parent-ref-update + republish assertion (D-02), resume test (ROT-06), ordered-completedNodeIds test (D-07), failure-path zeroization test
- [ ] Extend `metadata-ops.test.ts` (or add `move-reseal.test.ts`) — dest-path navigation round-trip after moveItem (D-06)

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | — |
| V3 Session Management | no | — |
| V4 Access Control | yes | `hasCoveringGrant` predicate (scope.ts — present); `reMintGrantsRootedAt` deletes revoked recipient row |
| V5 Input Validation | yes | `nodeId` UUID validation in `buildNodeAad` (present in core); generation bounds check (u32-safe in `sealNode`) |
| V6 Cryptography | yes | AES-256-GCM via `sealAesGcmAad`; role bytes per ADR 0003; ECIES via `wrapKey`/`unwrapKey`; fresh random IV per seal; NEVER hand-roll |

### Known Threat Patterns for Rotation Engine

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Revoked reader re-derives child readKey from cached parent readKey | Information Disclosure | D-02 re-seal ensures `SealedChildRef[N].readKeySealed` is sealed under parent's NEW readKey'; `unsealChildReadKey` fails closed on stale parent key |
| Replay of pre-rotation `SealedChildRef.readKeySealed` under new parent readKey | Tampering | AAD includes `childId + childGeneration + role=0x02`; generation bump changes AAD → AEAD tag mismatch |
| Crash + resume double-bumps a node's generation | Repudiation / Integrity | D-07 convergence test: N is done iff `parent.SealedChildRef[N].generation == N.envelope.generation` AND exceeds baseline; double-rotation only strengthens revocation |
| Concurrent add during rotation drops uploaded file | Data Loss | `mergeConcurrentChildren` on CAS-409: re-fetch remote, union children by `ipnsName`, remote wins on conflict |
| Inner grant orphaned (grantee at subtree leaf locked out permanently) | Denial of Service | `reMintGrantsRootedAt` scans `shares WHERE rootNodeId IN (rotated set)` per node |
| Caller-supplied key buffer zeroed by engine callee | Data Loss / Integrity | Zeroization rule (D-09): engine only zeros keys it minted (`readKeyPrime`/`fileKeyPrime`); never caller-supplied buffers. Flag every new helper in security review. |
| `updateFolderMetadataAndPublish` with fresh UUID breaks AAD | Tampering | D-06: required `nodeId` field; remove `?? crypto.randomUUID()` fallback |

## Project Constraints (from CLAUDE.md)

- **TypeScript string literals, not enums** — `RotationStatus`, `ScopeExitResult` already use string literals. No new enums in Phase 64.
- **`pnpm api:generate` after API changes** — Phase 64 has no API surface changes (rotation is entirely client-side). `pnpm api:generate` not required.
- **Critical Security Rules** — Never log `readKeyPrime`, `fileKeyPrime`, or any key material. Never pass unencrypted keys to the server. Server never has access to plaintext.
- **Commit messages** — Conventional commits: `feat(sdk-core):`, `test(sdk-e2e):`. No parenthesized text in subject line.
- **Markdownlint** — `.planning/` excluded from markdownlint lint-staged. Phase files are safe.
- **Zeroization — callee-must-not-zero-reused-buffer** — documented in project memory; engine.ts already flagged in comments (L16-20). Every new helper added in Phase 64 must follow D-09.
- **sdk-e2e as only real publish/resolve gate** — documented in project memory. TEST-01 must run against live stack before sign-off.
- **Cross-package dist staleness** — rebuild `@cipherbox/core dist/` before sdk-core typecheck if `packages/core/src/` is touched. Phase 64 does not touch core, but verify if any type changes are needed.
- **engine.ts must stay a named file** — SC#5 / Pitfall 14. Coverage excludes `src/**/index.ts` barrels.
- **First IPNS publish must embed sequence 1n** — `createAndPublishIpnsRecord(..., sequenceNumber: 1n)` for new nodes in the sdk-e2e crash-safety suite. `publishWithCas` embeds base+1 (pass `0n` as base).
- **`gsd commit` helper false negative** — verify with `git log`, never retry blindly.

## Sources

### Primary (HIGH confidence — verified from live codebase)

- `packages/sdk-core/src/rotation/engine.ts` — full read; confirmed seam signatures, Phase-63 CRITICAL bug at L344-350, D-01 placeholder at L357, D-07 ordering bug at L386, resume guard bug at L458-462
- `packages/sdk-core/src/folder/registration.ts` — confirmed D-06 bug at L174-175 (`?? crypto.randomUUID()` / `?? 0`)
- `packages/sdk/src/client.ts` L480-600, L600-1050 — confirmed all 6 `updateFolderMetadataAndPublish` call sites missing `nodeId`/`nodeGeneration`; confirmed `moveItem` source/dest publish without re-seal
- `packages/sdk-core/src/folder/metadata-ops.ts` — confirmed `moveItem` carries `readKeySealed` unchanged
- `packages/sdk-core/src/folder/merge.ts` — confirmed Phase-64 stub `mergeChildren`
- `packages/sdk-core/src/rotation/scope.ts` — `hasCoveringGrant` present and correct
- `packages/sdk-core/src/__tests__/rotation/engine.test.ts` — full read; confirmed Phase-63 test coverage; Phase-64 additions identified
- `packages/sdk-core/src/cas.ts` — confirmed `publishWithCas` signature and merge-callback shape
- `packages/sdk-core/src/ipns/index.ts` — confirmed `createAndPublishIpnsRecord` signature
- `packages/core/src/node/seal.ts` L187-224 — confirmed `sealChildReadKey`/`unsealChildReadKey` signatures (childId UUID + childKind + childGeneration)
- `packages/core/src/node/types.ts` — confirmed `PublishedNode` has plaintext `id`, `kind`, `generation`; `SealedChildRef` has `ipnsName` (not UUID)
- `packages/sdk/src/types.ts` — confirmed `FolderState.metadata: Node | null`
- `tests/sdk-e2e/src/suites/read-chain-navigation.test.ts` — confirmed Phase-63 manual-node tree pattern; Phase-64 crash-safety suite extends this
- `.planning/phases/64-rotation-soundness-revocation-guarantees/64-CONTEXT.md` — locked decisions D-01 through D-10
- `.planning/REQUIREMENTS.md` — ROT-03/04/05/06, TEST-01 requirement text
- `.planning/research/PITFALLS.md` — Pitfalls 2, 4, 14, 16 confirmed relevant

### Secondary (HIGH confidence — authoritative project design)

- `.planning/design/2026-06-26-sharing-read-keychaining-design.md` §4.1–4.8, §3.5–3.7, §7.3 — design source of truth; confirmed §4.5 9-step algorithm, convergence test, `verifySubtreeClean` spec, §4.7 batched parent-publish
- `docs/adr/0002-read-revocation-protects-future-content-only.md` — honest threat-model stance; lazy `contentRekeyPending` is correct; cold files keep old CID decryptable
- `docs/adr/0003-aad-bound-node-seal-encoding.md` — frozen AAD encoding, role bytes 0x01-0x04, KAT-tested

## Metadata

**Confidence breakdown:**
- Current engine state (seam locations, bugs): HIGH — directly read from live code
- D-02 re-seal fix shape: HIGH — design §4.5/§4.7 + confirmed bug in code
- D-06 call-site threading: HIGH — all 6 call sites read; FolderState type read
- TEST-01 sdk-e2e pattern: HIGH — Phase-63 scaffold read; extends established pattern
- D-04 reMintGrantsRootedAt callbacks shape: MEDIUM — pattern from STATE.md + design §4.4, exact callback signature is Claude's discretion
- `verifySubtreeClean` exact return shape: MEDIUM — design §4.5 spec is clear; implementation shape is Claude's discretion

**Research date:** 2026-06-29
**Valid until:** 2026-07-14 (30 days — stable codebase; changes invalidated immediately by any Phase-63 re-work)

---

## RESEARCH COMPLETE
