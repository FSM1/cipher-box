# Phase 63: Read-Chain Navigation and Rotation Core — Research

**Researched:** 2026-06-29
**Domain:** SDK-Core read key-chain navigation, grant issuance, add-item sealing, scope-exit predicate, rotation engine skeleton
**Confidence:** HIGH (all findings sourced from codebase canonical refs and design document)

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** `rotateOne` ships the structural walk skeleton (resolve → unseal → mint key' + generation' → re-seal → rewrite parent SealedChildRef → publish CAS → advance frontier). Four named, individually-testable seam functions deferred to Phase 64: `mintFileKeyOnRotate`, `reMintGrantsRootedAt`, `mergeConcurrentChildren`, `verifySubtreeClean`.
- **D-02:** Web is a first-class but best-effort rotation host. Rotation engine is host-agnostic pure logic (no FUSE/Tauri dependency). Durable resume-across-page-reload is Phase 68 (ROT-07). A web reload restarts the idempotent walk from `verifySubtreeClean` (Phase-64 logic).
- **D-03:** Phase 63 deletes `reWrapForRecipients` (`packages/sdk/src/share/index.ts:88`) and its sdk add-item fan-out callers (`packages/sdk/src/client.ts:164,1602`), and rewires the add-item path to seal the child readKey under the parent readKey. `addShareKeys` callback type (`packages/sdk/src/types.ts:32`) and web wiring removal land in Phase 68.
- **D-04:** Vitest unit bulk + ONE happy-path sdk-e2e round-trip (issue grant → navigate to file → root-step rotate → revoked grant can't navigate). Full fault-injection/crash-safety is Phase 64 (TEST-01).
- **D-05:** Transport-decoupled crypto, mock-tested. Grant issuance + `readDescriptorRef` ECIES crypto live behind the existing callback/transport-decoupled seam. Unit-test against a mocked API. The happy-path sdk-e2e exercises only node navigation + rotation over IPNS, NOT live `shares` persistence. Real `shares` persistence waits for Phase 66.
- **D-06:** Navigation surfaces a typed discriminated result: `'ok' | 'behind-retry' | 'revoked'`.
- **D-07:** Crypto primitive only in Phase 63. Implement claim re-wrap crypto in sdk-core/sdk: unwrap share-root readKey with ephemeral private key → re-wrap to claimer public key. Full invite service wiring is Phase 65; `encryptedChildKeys` JSONB column drop is Phase 66.
- **D-08:** `hasCoveringGrant` is a pure sdk-core function taking `(mutated-node ancestry chain, activeGrantRoots set, localGrantRecord) → coverage`. The host supplies the active grant-root set. sdk-core does NOT fetch grants or hold durable state. Gates every delete/move/rename (ROADMAP SC#4).
- **D-09:** Batched parent-link publish deferred to Phase 64. Phase 63's `rotateOne` does per-node parent-link publish (correct, simpler).
- **D-10:** Phase 63 defines the job-record type + resumable in-memory frontier loop, with optional host-injected persistence callback (no-op by default). `verifySubtreeClean` is Phase-64 seam per D-01.

### Claude's Discretion

- `sdk-core` module layout beyond the locked `src/rotation/engine.ts` (e.g., placement of navigation walk, grant/share helpers, `hasCoveringGrant` predicate, invite re-wrap primitive).
- Exact result/error type names and the `'ok' | 'behind-retry' | 'revoked'` representation (string-literal union per project convention).
- Seam-function signatures and helper factoring — provided each deferred seam is explicit and names its owning phase.
- How the mocked-API unit tests are structured.

### Deferred Ideas (OUT OF SCOPE)

- Rotation soundness: CRIT-1 content-key rotation (ROT-03), HIGH-3 inner-grant re-mint (ROT-04), HIGH-4 concurrent-add merge (ROT-05), crash-resume convergence + `verifySubtreeClean` (ROT-06), `tests/sdk-e2e` crash-safety suite (TEST-01), batched parent-link publish (D-09) → Phase 64.
- Write-chain, full Ed25519 write-revocation, bin re-link, full invite create/claim service wiring + `encryptedChildKeys` service removal → Phase 65.
- `shares`/`share_keys` schema cutover, `readDescriptorRef`/`writeDescriptedRef` columns, `encryptedChildKeys` JSONB drop, atomic CAS publish gate, tombstone, server-side `generation` gate → Phase 66.
- TEE lease-renewer contract → Phase 67.
- Web rotation UX, `executeLazyRotation` deletion, durable IndexedDB `{nodeId → generation}` + seq high-water (ROT-07/M1), `folderTree` reconcile-before-rotate, `addShareKeys` web-callback removal → Phase 68.
- FUSE/WinFsp symmetric unwrap, Rust `Node` enum, Rust grant-root awareness, durable client floors → Phase 69.
- Q3 (write-recipient deletions vs owner-held sub-shares) → Phase 65/68/69.
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| READ-01 | User can issue a read grant with one ECIES wrap of the share-root readKey + one shares row (0 node touches, 0 republishes); granting a single file is identical to granting a deep folder | Design §3.2; crypto `wrapKey`/`unwrapKey` (ECIES); transport-decoupled callback seam (D-05) |
| READ-02 | Grantee can navigate to a depth-d child via one ECIES unwrap then O(depth) symmetric AES, recovering content key/CID/mode at a file node; read path distinguishes "soft behind, retry" from "hard revoked" | Design §2.6 4-step unwrap walk; `unsealNode`/`unsealChildReadKey`/`unsealContent` from `packages/core/src/node/seal.ts`; D-06 discriminated result |
| READ-03 | Adding an item seals the child readKey under the parent readKey with no per-recipient fan-out; `reWrapForRecipients`/`addShareKeys` are deleted | Design §3.4; `sealChildReadKey` from core/node/seal.ts; D-03 deletion boundary |
| READ-04 | A move within a grantee's scope is link rewrites only (no re-encrypt), computing exact per-grant scope so benign within-scope moves do not over-rotate | Design §3.5; `hasCoveringGrant` predicate (D-08); `metadata-ops.ts` stubs to un-stub |
| READ-05 | An invite wraps the single share-root readKey to an ephemeral key (private half in URL fragment); claim re-wraps it to the claimer's key and stores a standard grant; `encryptedChildKeys[]` fan-out is deleted | Design §3.11; crypto `wrapKey`/`unwrapKey`; D-07 crypto-only boundary |
| ROT-01 | `rotateReadFromNode` is a resumable, per-node-commit, idempotent walk backing read-revoke and every scope-exit mutation; published IPNS records are the source of truth (job record advisory) | Design §4 (esp. §4.5 9-step rotateOne); `publishWithCas`/`createAndPublishIpnsRecord` in cas.ts/ipns; D-01 skeleton + named seams |
| ROT-02 | Rotation fires iff a node leaves a grantee's reachable scope; a node with no covering grant is a pure relink (zero rotations) — enforced as a hard test across delete/move/rename | Design §3.6/§3.8; `hasCoveringGrant` predicate (D-08); zero-rotation invariant test (SC#4) |
</phase_requirements>

---

## Summary

Phase 63 is the first behavioral consumer of the Phase-62 `node/v3` codec keystone. The Phase-62 stubs in `packages/sdk-core/src/folder/{load,metadata-ops,registration}.ts` and `packages/sdk/src/share/index.ts` get un-stubbed or deleted here. All work lives in `packages/sdk-core` and `packages/sdk`; no `apps/`, `crates/`, or schema changes are in scope.

The core insight driving the design: a read grant is a single ECIES-wrapped readKey. Navigation is one ECIES unwrap then O(depth) symmetric AES by composing `unsealNode` → `unsealChildReadKey` for each link in the chain → `unsealContent` at the file leaf. Sharing any subtree is structurally identical to sharing a single file — both are `readDescriptorRef = ECIES_wrap(node.readKey → recipientPubKey)`. Adding a child seals the child readKey under the parent readKey with zero per-recipient fan-out; every existing grant-holder already transitively holds the parent readKey. Rotation fires iff a node exits a grantee's reachable scope — a pure unshared delete/move is a parent-link rewrite with zero rotation.

The rotation engine (`src/rotation/engine.ts`) implements the happy-path clean walk (single-rooted, no concurrent-add, no file-key rotation) end-to-end in Phase 63, with four named seam functions deferred to Phase 64. This mirrors the Phase-62 "name the deferred behavior after its owning phase" discipline. The coverage-barrel pitfall demands the engine live in a named file, not an `index.ts`.

**Primary recommendation:** Un-stub the six stubs in `folder/` (`fetchAndDecryptMetadata`, `loadFolderMetadata`, `renameInFolder`, `deleteFromFolder`, `addFilePointerToFolder`, `moveItem`, `createSubfolder`, `updateFolderMetadataAndPublish`) by composing the Phase-62 codec primitives; create `src/rotation/engine.ts` with `rotateReadFromNode` / `rotateOne` + four named seams; implement `hasCoveringGrant` in a named file; delete `reWrapForRecipients` from `packages/sdk`; implement the grant-issuance and invite-claim re-wrap crypto behind the existing transport-decoupled callback seam; revive the quarantined test suites marked `TODO(phase 63)`.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Read-chain navigation walk | `packages/sdk-core` | `packages/core` (codec) | Navigation composes codec primitives; sdk-core owns the IPNS resolve + chain traversal |
| Read-grant issuance | `packages/sdk-core`/`sdk` | `packages/crypto` (ECIES) | ECIES wrap lives in crypto; issuance logic (callback seam) lives in sdk-core/sdk |
| Add-item child sealing | `packages/sdk-core` | `packages/core` (sealChildReadKey) | Core seals the key; sdk-core owns the parent read-body reseal + publish |
| Move-within-scope | `packages/sdk-core` | — | Pure SealedChildRef rewrite; no re-encryption |
| hasCoveringGrant predicate | `packages/sdk-core` | Host caller (web Ph68/FUSE Ph69) | Pure function; host supplies active grant-root set |
| Invite claim re-wrap primitive | `packages/sdk-core`/`sdk` | `packages/crypto` (ECIES) | Crypto layer does unwrap/re-wrap; sdk owns the claim flow primitive |
| Rotation engine (rotateReadFromNode/rotateOne) | `packages/sdk-core` | `cas.ts`/`ipns/index.ts` (CAS publish) | Engine is pure sdk-core; reuses existing CAS and IPNS publish infra |
| Job record / frontier tracking | `packages/sdk-core` | Host (optional persistence callback) | In-memory loop in sdk-core; host optionally persists for durability (Phase 68/69) |
| Named deferred seams (Phase-64 soundness) | `packages/sdk-core` | Phase 64 | Stubs declared in engine.ts; Phase 64 fills without re-architecting |

---

## Standard Stack

### Core (all internal — no new npm packages)

| Package | Source | Purpose | Why Standard |
|---------|--------|---------|--------------|
| `@cipherbox/core` | `packages/core/src/node/` | `sealNode`/`unsealNode`, `sealChildReadKey`/`unsealChildReadKey`, `sealContent`/`unsealContent`, `encodeReadBody`/`decodeReadBody`, types | Phase-62 keystone; CALL, never reimplement [VERIFIED: codebase] |
| `@cipherbox/crypto` | `packages/crypto/src/` | `sealAesGcmAad`/`unsealAesGcmAad`/`buildNodeAad`; `wrapKey`/`unwrapKey` (ECIES) | Frozen primitives per ADR 0003; ECIES for grant issuance [VERIFIED: codebase] |
| `packages/sdk-core` CAS infra | `src/cas.ts:38 publishWithCas`, `src/ipns/index.ts:39 createAndPublishIpnsRecord` | CAS-retry publish loop; IPNS record signing + relay call | Existing, functional, used by rotation rotateOne CAS step [VERIFIED: codebase] |

### No New External Packages

Phase 63 installs zero new npm packages. All required primitives exist:
- ECIES: `wrapKey`/`unwrapKey` in `@cipherbox/crypto`
- AES-256-GCM AAD: `sealAesGcmAad`/`unsealAesGcmAad`/`buildNodeAad` in `@cipherbox/crypto`
- Node codec: `sealNode`/`unsealNode`/`sealChildReadKey`/`unsealChildReadKey`/`sealContent`/`unsealContent` in `@cipherbox/core`
- CAS publish: `publishWithCas` in `sdk-core/src/cas.ts`
- IPNS publish/resolve: `createAndPublishIpnsRecord`/`resolveIpnsRecord` in `sdk-core/src/ipns/index.ts`

## Package Legitimacy Audit

No external packages to audit. Phase 63 is pure internal implementation.

---

## Architecture Patterns

### System Architecture Diagram

```
Grant issuance (READ-01):
  caller → [ECIES wrapKey(shareRootNode.readKey, recipientPubKey)]
          → readDescriptorRef (base64) + shares row INSERT (mocked in unit tests)

Navigation walk (READ-02):
  grant.readDescriptorRef
    → ECIES unwrapKey(recipientPrivKey)   ← 1 ECIES, once
    → shareRootNode.readKey
    → resolveIpnsRecord(shareRootNode.ipnsName)
    → unsealNode(publishedNode, readKey)
    → [for each hop: unsealChildReadKey(SealedChildRef.readKeySealed, parentReadKey, childId, childKind, childGeneration)]
    → resolveIpnsRecord(child.ipnsName) → unsealNode(child, childReadKey)
    → at file leaf: unsealContent(fileNode.content, fileNodeReadKey) → {cid, fileKey, encryptionMode}
  result: 'ok' | 'behind-retry' | 'revoked'

Add-item child sealing (READ-03):
  newChildNode (fresh readKey, generation=0)
    → sealChildReadKey(child.readKey, parent.readKey, childId, childKind, 0)
    → SealedChildRef added to parent.children[]
    → sealNode(updatedParent, parent.readKey, parent.writeKey)
    → publishWithCas(parentIpnsName, ...)

Scope-exit predicate (READ-04, ROT-02):
  delete/move/rename
    → hasCoveringGrant(nodeAncestorChain, activeGrantRoots, localGrant)
    → false → pure parent-link rewrite (zero rotations)
    → true  → rotateReadFromNode(nodeId, rootReadKey, grantSet)

Rotation engine (ROT-01):
  rotateReadFromNode(nodeId):
    [root step first per §4.2]
    → rotateOne(rootNode, parentReadKey) [see 9-step below]
    → BFS frontier walk: rotateOne(child, childReadKey') for each child

rotateOne(N, parentReadKey) — happy-path skeleton (D-01):
  1. resolve N → envelope {generation: gN}
  2. skip if done (idempotency check)
  3. unsealNode(N, keyChainedFromParent) → plaintext children[]
  4. readKey' = random32(); gN' = gN + 1
  5. [mintFileKeyOnRotate — SEAM, Phase 64, files only]
  6. [mergeConcurrentChildren — SEAM, Phase 64, re-fetch on 409]
     re-seal N read-body under readKey' (AAD gN')
  7. rewrite parent SealedChildRef[N].readKeySealed + .generation = gN'
  8. publishWithCas(N, seq: currentSeq) → CAS; on 409 re-resolve + retry from step 3
  9. [reMintGrantsRootedAt — SEAM, Phase 64]
     mark N done; push children with readKey'

[verifySubtreeClean — SEAM, Phase 64]

Invite claim re-wrap (READ-05):
  ECIES unwrapKey(readDescriptorRef, ephemeralPrivKey)  → shareRootReadKey
  ECIES wrapKey(shareRootReadKey, claimerPubKey)        → newReadDescriptorRef
  → produce standard grant row (mock-persisted in unit test)
```

### Recommended Project Structure

```
packages/sdk-core/src/
├── rotation/
│   └── engine.ts       # rotateReadFromNode, rotateOne, hasCoveringGrant,
│                       # job-record type, 4 named Phase-64 seams [NEW]
├── share/
│   └── grant.ts        # issueReadGrant (ECIES wrap), navigateReadChain,
│                       # claimInviteReadKey (re-wrap primitive) [NEW or new file]
├── folder/
│   ├── load.ts         # un-stub fetchAndDecryptMetadata, loadFolderMetadata
│   ├── metadata-ops.ts # un-stub renameInFolder, deleteFromFolder,
│   │                   # addFilePointerToFolder, moveItem
│   └── registration.ts # un-stub createSubfolder, updateFolderMetadataAndPublish
packages/sdk/src/
├── share/
│   └── index.ts        # DELETE reWrapForRecipients (L88); rewire add-item fan-out
└── client.ts           # rewire L164, L1602 (add-item) off reWrapForRecipients
```

Coverage note: `rotation/engine.ts` and `share/grant.ts` MUST be named files, not barrel `index.ts` files. The sdk-core vitest config excludes `src/**/index.ts` from coverage — rotation engine in a barrel = silent coverage miss (Pitfall 14). [VERIFIED: codebase — `packages/sdk-core/vitest.config.ts` exclude `src/**/index.ts`]

### Pattern 1: Navigation Walk (§2.6)

```typescript
// Source: design §2.6 + packages/core/src/node/seal.ts
// Generation source rule: reader's expected AAD generation comes from
// SealedChildRef.generation mirror (NOT the child envelope's plaintext generation)

export type NavigateResult =
  | { status: 'ok'; content: NodeContent; nodeId: string }
  | { status: 'behind-retry' }
  | { status: 'revoked' };

async function navigateReadChain(
  grantReadDescriptorRef: string,
  recipientPrivKey: Uint8Array,
  path: string[],  // ipnsNames from root to target
  rootGeneration: number,
  ctx: SdkContext
): Promise<NavigateResult> {
  // 1. ONE ECIES unwrap — the only asymmetric op
  const shareRootReadKey = await unwrapKey(fromBase64(grantReadDescriptorRef), recipientPrivKey);

  // 2. Resolve + unseal root
  const rootResolved = await resolveIpnsRecord(path[0], ctx);
  if (!rootResolved) return { status: 'revoked' };
  // D-06: envelope generation ahead of grant.rootGeneration → behind-retry
  // (check after unseal to confirm re-minted grant present)

  const rootPublished = await fetchPublishedNode(rootResolved.cid, ctx);
  const rootNode = await unsealNode(rootPublished, shareRootReadKey);

  // 3. O(depth) symmetric walk
  let currentReadKey = shareRootReadKey;
  let currentNode = rootNode;
  for (let i = 1; i < path.length; i++) {
    const childRef = currentNode.children?.find(c => c.ipnsName === path[i]);
    if (!childRef) return { status: 'revoked' };
    // AAD uses childRef.generation (parent mirror), NOT child envelope
    currentReadKey = await unsealChildReadKey(
      childRef.readKeySealed, currentReadKey,
      childRef.childId, childRef.kind, childRef.generation
    );
    const resolved = await resolveIpnsRecord(path[i], ctx);
    if (!resolved) return { status: 'revoked' };
    const published = await fetchPublishedNode(resolved.cid, ctx);
    currentNode = await unsealNode(published, currentReadKey);
  }

  // 4. At file leaf: unseal content
  if (currentNode.kind === 'file' && currentNode.content) {
    const content = await unsealContent(
      currentNode.content as unknown as string, // base64 sealed
      currentReadKey, currentNode.id, currentNode.generation
    );
    return { status: 'ok', content, nodeId: currentNode.id };
  }
  return { status: 'revoked' };
}
```

### Pattern 2: rotateOne Skeleton (§4.5 D-01)

```typescript
// Source: design §4.5
// Named seams use descriptive throw so Phase 64 fills without re-architecting

async function rotateOne(
  nodeId: string,
  parentReadKey: Uint8Array,
  parentIpnsName: string,
  parentSeq: bigint,
  jobRecord: RotationJobRecord,
  ctx: SdkContext
): Promise<{ childReadKey: Uint8Array; newGeneration: number }> {
  // Step 1: resolve
  const resolved = await resolveIpnsRecord(nodeId, ctx);
  if (!resolved) throw new Error(`rotateOne: node ${nodeId} not found`);

  // Step 2: idempotency check (parent mirror vs envelope)
  // done check handled by caller

  // Step 3: unseal
  const published = await fetchPublishedNode(resolved.cid, ctx);
  const node = await unsealNode(published, parentReadKey);

  // Step 4: mint new key + bump generation
  const readKeyPrime = crypto.getRandomValues(new Uint8Array(32));
  const generationPrime = node.generation + 1;

  // Step 5: SEAM — content rekey (Phase 64 — ROT-03/CRIT-1)
  await mintFileKeyOnRotate(node, jobRecord); // throws 'not implemented — phase 64 (ROT-03)'

  // Step 6: re-seal read-body under readKey' (happy path: no concurrent-add merge)
  // SEAM — merge concurrent children (Phase 64 — ROT-05/HIGH-4)
  await mergeConcurrentChildren(node, resolved, ctx); // throws 'not implemented — phase 64 (ROT-05)'
  const updatedNode: Node = { ...node, generation: generationPrime };
  const resealedPublished = await sealNode(updatedNode, readKeyPrime, writeKey /* from write-body */);

  // Step 7: rewrite parent SealedChildRef[N]
  const newReadKeySealed = await sealChildReadKey(
    readKeyPrime, parentReadKey, nodeId, node.kind, generationPrime
  );

  // Step 8: publish child (CAS), then parent
  await publishWithCas({ ipnsName: nodeId, sequenceNumber: resolved.sequenceNumber, ... });

  // Step 9: SEAM — re-mint inner grants (Phase 64 — ROT-04/HIGH-3)
  await reMintGrantsRootedAt(nodeId, readKeyPrime, generationPrime, jobRecord, ctx);
  // throws 'not implemented — phase 64 (ROT-04)'

  return { childReadKey: readKeyPrime, newGeneration: generationPrime };
}

// SEAM declarations (individually testable, Phase 64 fills):
async function mintFileKeyOnRotate(_node: Node, _job: RotationJobRecord): Promise<void> {
  throw new Error('not implemented — phase 64 (ROT-03/CRIT-1 content-key rotation)');
}
async function mergeConcurrentChildren(_node: Node, _resolved: unknown, _ctx: SdkContext): Promise<void> {
  throw new Error('not implemented — phase 64 (ROT-05/HIGH-4 concurrent-add merge)');
}
async function reMintGrantsRootedAt(_nodeId: string, _key: Uint8Array, _gen: number, _job: RotationJobRecord, _ctx: SdkContext): Promise<void> {
  throw new Error('not implemented — phase 64 (ROT-04/HIGH-3 inner-grant re-mint)');
}
// verifySubtreeClean is Phase 64 per D-01/D-10
async function verifySubtreeClean(_rootNodeId: string, _ctx: SdkContext): Promise<boolean> {
  throw new Error('not implemented — phase 64 (ROT-06 crash-resume + verifySubtreeClean)');
}
```

### Pattern 3: hasCoveringGrant (D-08)

```typescript
// Source: design §3.9 + D-08
// Pure function — no API calls, no Zustand, no durable state
// Host (web Phase 68, FUSE Phase 69) supplies activeGrantRoots from API shares query

export function hasCoveringGrant(params: {
  /** Ancestry chain of the mutated node (from root to parent), as ipnsNames */
  nodeAncestorIpnsNames: string[];
  /** Set of ipnsNames that are roots of active grants (from host's shares query) */
  activeGrantRootIpnsNames: Set<string>;
  /** Client's own local grant record for cross-check (anti-malicious-relay) */
  localGrantRecord?: { rootIpnsName: string } | null;
}): boolean {
  // At least one ancestor (or the node itself) must be a grant root
  const { nodeAncestorIpnsNames, activeGrantRootIpnsNames, localGrantRecord } = params;
  // Cross-check: relay set is completeness aid, not authority
  // If we have a local grant record whose root IS an ancestor, the grant covers this node
  if (localGrantRecord && nodeAncestorIpnsNames.includes(localGrantRecord.rootIpnsName)) {
    return true;
  }
  return nodeAncestorIpnsNames.some(name => activeGrantRootIpnsNames.has(name));
}
```

### Pattern 4: Grant Issuance (§3.2, READ-01)

```typescript
// Source: design §3.2 + D-05
// Transport-decoupled: insertShareFn is injected callback (mock in unit tests)

export async function issueReadGrant(params: {
  shareRootReadKey: Uint8Array;
  recipientPublicKey: Uint8Array;   // secp256k1 65B
  rootNodeId: string;
  rootIpnsName: string;
  rootGeneration: number;
  insertShareFn: (grant: ReadGrantPayload) => Promise<{ shareId: string }>;
}): Promise<{ shareId: string; readDescriptorRef: string }> {
  // ECIES wrap: 1 operation, 0 node touches, 0 republishes
  const wrapped = await wrapKey(params.shareRootReadKey, params.recipientPublicKey);
  const readDescriptorRef = toBase64(wrapped);
  const { shareId } = await params.insertShareFn({
    recipientPublicKey: toHex(params.recipientPublicKey),
    rootNodeId: params.rootNodeId,
    rootIpnsName: params.rootIpnsName,
    rootGeneration: params.rootGeneration,
    readDescriptorRef,
  });
  return { shareId, readDescriptorRef };
}
```

### Anti-Patterns to Avoid

- **Reimplement seal/encode/decode:** Phase-62 codec (`packages/core/src/node/`) is the only implementation. Never inline `buildNodeAad` or `sealAesGcmAad` logic in sdk-core. [VERIFIED: codebase]
- **Rotate on private deletes:** `rotateReadFromNode` must be guarded by `hasCoveringGrant`. Unconditional rotation on delete is an O(subtree) storm over 99% of unshared vaults. [VERIFIED: design §3.6, PITFALLS.md Pitfall 7]
- **Use `SealedChildRef.generation` as authoritative seal input source:** Generation for unseal AAD comes from the **parent mirror** (childRef.generation), never from the child's own envelope plaintext. The child envelope's generation is used only for the M1 high-water check. [VERIFIED: design §2.6]
- **Place rotation engine in `index.ts` barrel:** sdk-core vitest coverage excludes `src/**/index.ts`. Engine MUST be in `src/rotation/engine.ts`. [VERIFIED: packages/sdk-core/vitest.config.ts]
- **Zero caller-owned buffers:** Rotation helpers zero only buffers they allocate (`readKey'`, `fileKey'`). Never zero a `parentReadKey` or session key that was passed in — the caller reuses those across the walk. [VERIFIED: design D-09, PITFALLS.md Pitfall 16]
- **Use `expectedSequenceNumber` = new seq:** `publishWithCas` passes `sequenceNumber = currentSeq` (pre-increment); `createAndPublishIpnsRecord` is called with `sequenceNumber = currentSeq + 1n` and `expectedSequenceNumber = currentSeq.toString()`. For new nodes (first publish), pass `1n` as `sequenceNumber` (the post-Phase-60 strict gate rejects embedded seq ≠ 1). [VERIFIED: codebase — ipns/index.ts, project memory]

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| AES-256-GCM with AAD | Custom encrypt | `sealAesGcmAad` / `unsealAesGcmAad` from `@cipherbox/crypto` | Frozen per ADR 0003; TS↔Rust KAT; IV minting handled |
| AAD construction | Manual byte concatenation | `buildNodeAad(nodeId, kindByte, generation, role)` from `@cipherbox/crypto` | 45-byte layout frozen; fail-closed on invalid inputs |
| Node seal/unseal | Custom codec | `sealNode`/`unsealNode` from `@cipherbox/core` | Phase-62 keystone; handles both sealed bodies |
| Child readKey seal | Custom AES call | `sealChildReadKey`/`unsealChildReadKey` from `@cipherbox/core` | Correct role byte (0x02), correct AAD construction |
| File content seal | Custom AES call | `sealContent`/`unsealContent` from `@cipherbox/core` | Role 0x03 content, correct nodeId/generation binding |
| ECIES key wrapping | Custom EC crypto | `wrapKey`/`unwrapKey` from `@cipherbox/crypto` | secp256k1 ECIES, audited |
| CAS publish retry | Custom retry loop | `publishWithCas` from `sdk-core/src/cas.ts` | 409 → re-resolve → merge → retry; backoff; ConflictError |
| IPNS record create + publish | Raw API calls | `createAndPublishIpnsRecord` from `sdk-core/src/ipns/index.ts` | Handles Ed25519 sign + marshal + CAS guard |
| IPNS resolve + verify | Raw API calls | `resolveIpnsRecord` from `sdk-core/src/ipns/index.ts` | Signature verify, CBOR CID/seq binding, expiry check |

**Key insight:** Phase 63's value is the traversal algorithm and the scope-exit logic, not new crypto. Any implementation that re-creates a sealed blob or re-invents ECIES is an error — call into the established primitives.

---

## Common Pitfalls

### Pitfall 1: Generation AAD Source Confusion

**What goes wrong:** Using the child node's own envelope `generation` (plaintext on `PublishedNode`) as the AAD input for `unsealChildReadKey` instead of the parent mirror `SealedChildRef.generation`. The child envelope can be served stale by a relay; the parent mirror is integrity-anchored via the signed CID chain.

**Why it happens:** Both values are named `generation` and the child envelope's value is more "obviously present" when the developer has just resolved the child.

**How to avoid:** The AAD for `unsealChildReadKey(sealedBase64, parentReadKey, childId, childKind, childGeneration)` uses the **parent's `SealedChildRef.generation` mirror**. Only use the child's own envelope `generation` for post-unseal M1 high-water comparison (Phase 68/69 concern, not Phase 63).

**Warning signs:** Navigation test fails AAD transplant resistance check (unseal accepts wrong generation). [VERIFIED: design §2.6]

### Pitfall 2: Coverage-Barrel — rotateReadFromNode in index.ts

**What goes wrong:** `rotateReadFromNode` placed in `src/rotation/index.ts` or `src/index.ts` is excluded from coverage by the sdk-core vitest config (`exclude: ['src/**/index.ts']`). The 80% coverage gate passes with zero coverage on the rotation engine.

**How to avoid:** All rotation logic lives in `src/rotation/engine.ts`. ROADMAP SC#5 explicitly requires named-file coverage. [VERIFIED: packages/sdk-core/vitest.config.ts line `'src/**/index.ts'`]

### Pitfall 3: Over-Rotation on Private Deletes

**What goes wrong:** Calling `rotateReadFromNode` unconditionally on every delete/move/rename storms `O(subtree)` IPNS publishes over the unshared 99% of a vault.

**How to avoid:** Every delete/move/rename call site must check `hasCoveringGrant()` first. "No covering grant → pure relink, zero rotations" is ROADMAP SC#4 and must be a hard unit test (publish-call spy asserting zero `rotateReadFromNode` invocations and zero IPNS publishes beyond the parent relink for a private delete). [VERIFIED: design §3.6/§3.8, PITFALLS.md Pitfall 7]

### Pitfall 4: Zeroing Caller-Supplied Key Buffers

**What goes wrong:** Zeroing `parentReadKey` or any session key passed into a rotation helper corrupts the caller's buffer. The next SDK operation operates on all-zero bytes → 400 "publicKey does not correspond" from the API. This broke 48/89 sdk-e2e tests in a prior incident.

**How to avoid:** Zero only `readKey'` and `fileKey'` (freshly allocated). Never zero a `Uint8Array` parameter. Document in JSDoc. The SDK E2E suite is the only gate that catches this. [VERIFIED: PITFALLS.md Pitfall 16, project memory `project-zeroization-callee-must-not-zero-reused-buffer`]

### Pitfall 5: reWrapForRecipients Deletion Scope

**What goes wrong:** Deleting `reWrapForRecipients` (`packages/sdk/src/share/index.ts:88`) without updating its callers at `client.ts:164` (add-item fan-out) and `client.ts:1602` (exposed method) causes a compile error. The `addShareKeys` callback TYPE and its web wiring must NOT be deleted yet (Phase 68 boundary per D-03).

**How to avoid:** Delete only the function and the two call sites in `client.ts`. Leave `packages/sdk/src/types.ts:32` (`addShareKeys` callback type) intact. [VERIFIED: CONTEXT.md D-03, codebase grep]

### Pitfall 6: First-Publish Sequence

**What goes wrong:** Passing `1n` as `expectedSequenceNumber` to `createAndPublishIpnsRecord` for a new node's first publish. The post-Phase-60 strict gate rejects first publish where embedded seq ≠ 1 (400). The convention: `createAndPublishIpnsRecord` embeds the `sequenceNumber` arg verbatim (pass `1n`); `publishWithCas` embeds `base+1` (pass `0n` as initial seq so it sends `1n`).

**How to avoid:** For new-node creation in `createSubfolder` / `addFilePointerToFolder`: call `createAndPublishIpnsRecord` with `sequenceNumber: 1n`. For CAS updates via `publishWithCas`: pass `sequenceNumber: currentSeq` (the function does `+1n` internally). [VERIFIED: project memory `project-ipns-first-publish-embed-seq-1`, codebase ipns/index.ts]

### Pitfall 7: dist Staleness Before Consumer Typecheck

**What goes wrong:** sdk-core typechecks against `packages/core/dist/`, not source. After any `packages/core` change, the dist must be rebuilt before judging the typecheck gate.

**How to avoid:** Run `pnpm --filter @cipherbox/core build` before `pnpm typecheck` in sdk-core. Wave 0 of the plan should include a dist-rebuild task. [VERIFIED: project memory `project-cross-package-dist-staleness`]

---

## Code Examples

### Fetching and Decoding a PublishedNode from IPFS

The existing pattern in `sdk-core` fetches IPFS blobs via the CID and JSON-parses as `PublishedNode`. Navigation needs this at each hop:

```typescript
// Source: packages/sdk-core/src/folder/load.ts pattern (before un-stubbing)
// The actual IPFS fetch uses ctx.ipfsUrl or similar; check the ipfs/ module
import { unsealNode } from '@cipherbox/core';

async function fetchAndDecryptNode(cid: string, readKey: Uint8Array, ctx: SdkContext): Promise<Node> {
  const response = await fetch(`${ctx.ipfsGatewayUrl}/ipfs/${cid}`);
  const published = await response.json() as PublishedNode;
  return unsealNode(published, readKey);
}
```

### SealedChildRef update on move-within-scope

```typescript
// Source: design §3.5 — pure SealedChildRef rewrite, no re-encryption
// Re-seal the parent read-body: the child's readKey stays unchanged,
// only the parent child-list changes
import { sealNode } from '@cipherbox/core';

function removeChildRef(children: SealedChildRef[], childId: string): SealedChildRef[] {
  return children.filter(c => c.childId !== childId);  // keep all others
}
// Then call updateFolderMetadataAndPublish on both source and destination parents
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Per-recipient ECIES fan-out on add-item (`reWrapForRecipients` + `share_keys` table) | Seal child readKey under parent readKey once; existing grantees get it transitively | Phase 63 (this phase) | O(recipients) fan-out → O(1) per add-item |
| `executeLazyRotation` (rotate only share-root folderKey, no subtree walk) | `rotateReadFromNode` resumable BFS walk with per-node CAS commit | Phase 63 (skeleton), Phase 64 (soundness) | Correct revocation; no stale subtree keys |
| FolderMetadata/FileMetadata split codecs | Unified `Node` codec (`node/v3`) with `sealChildReadKey` chain | Phase 62 (complete) | Single code path for all node kinds |
| Per-child ECIES in FolderEntry (`folderKeyEncrypted`, `ipnsPrivateKeyEncrypted`) | Symmetric `unsealChildReadKey` O(depth) walk from grant root | Phase 63 (this phase) | O(recipients × depth) ECIES → O(depth) AES per navigate |

**Deprecated/outdated (Phase 63 deletes):**
- `reWrapForRecipients` (`packages/sdk/src/share/index.ts:88`): superseded by child-key sealing under parent readKey
- `addShareKeys` fan-out call in `client.ts:164,1602`: superseded by READ-03 add-item pattern
- `executeLazyRotation` stub in `packages/sdk/src/reencrypt.ts`: superseded by `rotateReadFromNode` (note: web wiring removal = Phase 68)

---

## Runtime State Inventory

Phase 63 is a greenfield sdk-core behavioral phase — no production data, no running services, no rename/rebrand. Runtime state inventory is **not applicable**.

**Nothing found in any category:** Confirmed — Phase 63 adds new named files and un-stubs existing stubs in packages that are not deployed to production mid-milestone.

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Node.js | pnpm build/test | ✓ | (project standard) | — |
| Docker compose stack | sdk-e2e happy-path (D-04) | ✓ (local dev) | — | Manual skip of sdk-e2e, unit-only |
| Redis on 6380 | sdk-e2e (API dependency) | ✓ (docker stack) | — | Skip sdk-e2e |
| `pnpm --filter @cipherbox/api dev` | sdk-e2e live API | ✓ (local) | — | Skip sdk-e2e |

**Missing dependencies with no fallback:** None for unit test execution.

**Missing dependencies with fallback:** sdk-e2e requires the docker stack + local API. If unavailable, unit tests can still pass; sdk-e2e is a separate explicit phase gate.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | vitest |
| Config file | `packages/sdk-core/vitest.config.ts`, `packages/sdk/vitest.config.ts` |
| Quick run command | `pnpm --filter @cipherbox/sdk-core test --run` |
| Full suite command | `pnpm --filter @cipherbox/sdk-core test --run --coverage && pnpm --filter @cipherbox/sdk test --run` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| READ-01 | Issue read grant: O(1) ECIES wrap, 0 node touches, 0 republishes | unit (mocked insertShareFn) | `pnpm --filter @cipherbox/sdk-core test --run src/__tests__/folder.test.ts` | ✅ (revive from TODO phase 63) |
| READ-02 | Navigation walk to depth-d: 1 ECIES, O(d) AES, typed result | unit | `pnpm --filter @cipherbox/sdk-core test --run src/__tests__/folder.test.ts` | ✅ (revive) |
| READ-02 | D-06 behind-retry vs revoked discrimination | unit | same | ✅ (revive) |
| READ-03 | Add-item seals child readKey under parent readKey; no fan-out | unit | `pnpm --filter @cipherbox/sdk-core test --run src/__tests__/folder.test.ts` | ✅ (revive) |
| READ-04 | Move-within-scope is link rewrites only; moveItem un-stub | unit | `pnpm --filter @cipherbox/sdk test --run src/__tests__/client-extended.test.ts` | ✅ (revive) |
| READ-05 | Invite claim re-wrap: unwrap ephemeral → re-wrap to claimer | unit | `pnpm --filter @cipherbox/sdk test --run` | ❌ Wave 0: new test |
| ROT-01 | `rotateReadFromNode` happy-path: navigate to depth-d post-rotate fails for revoked grantee | unit (publish-call spy) | `pnpm --filter @cipherbox/sdk-core test --run src/__tests__/` | ❌ Wave 0: new file `src/rotation/engine.test.ts` |
| ROT-01 | Coverage on `src/rotation/engine.ts` ≥ 80% | coverage | `pnpm --filter @cipherbox/sdk-core test --run --coverage` (SC#5) | ❌ Wave 0: engine.ts doesn't exist |
| ROT-02 | Scope-exit zero-rotation invariant: private delete → zero `rotateReadFromNode` invocations, zero IPNS publishes beyond parent relink | unit (publish spy) | same | ❌ Wave 0: new test in engine.test.ts |
| ALL | Happy-path sdk-e2e: issue grant → navigate → root-step rotate → revoked grant can't navigate | integration (live stack) | `pnpm --filter tests/sdk-e2e test --run` | ❌ Wave 0: new spec in `tests/sdk-e2e/src/suites/share-operations.test.ts` (or new file) |

**Existing quarantined suites to revive (remove `describe.skip` / `it.skip`, `TODO(phase 63)`):**
- `packages/sdk-core/src/__tests__/folder.test.ts` lines 105, 248, 445, 491, 515, 563
- `packages/sdk/src/__tests__/client-extended.test.ts` line 133 (moveItem)
- `packages/sdk/src/__tests__/enumerate-shared-subtree.test.ts` line 154

### Sampling Rate

- **Per task commit:** `pnpm --filter @cipherbox/sdk-core test --run`
- **Per wave merge:** `pnpm --filter @cipherbox/sdk-core test --run --coverage && pnpm --filter @cipherbox/sdk test --run`
- **Phase gate:** Full suite green + coverage ≥ 80% on `sdk-core` before `/gsd-verify-work`; sdk-e2e happy-path passes against live local stack

### Wave 0 Gaps

- [ ] `packages/sdk-core/src/rotation/engine.ts` — covers ROT-01, ROT-02 (the file itself; tests in engine.test.ts)
- [ ] `packages/sdk-core/src/__tests__/rotation/engine.test.ts` — covers ROT-01 rotateOne skeleton, ROT-02 zero-rotation invariant (publish spy)
- [ ] New grant/share test in `packages/sdk-core/src/__tests__/share/` or similar — covers READ-01 (grant issuance), READ-05 (invite claim re-wrap)
- [ ] sdk-e2e happy-path addition in `tests/sdk-e2e/src/suites/share-operations.test.ts` (or new `read-chain-navigation.test.ts`) — covers D-04 end-to-end round-trip
- [ ] Rebuild `packages/core` dist before first typecheck: `pnpm --filter @cipherbox/core build`

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | — |
| V3 Session Management | no | — |
| V4 Access Control | yes | `hasCoveringGrant` predicate; scope-exit iff covers; rotation on scope-exit |
| V5 Input Validation | yes | `buildNodeAad` fail-closed on invalid kind/role/generation; `unsealNode` rejects non-v3/non-aeadVersion-1 envelopes |
| V6 Cryptography | yes | AES-256-GCM AAD (ADR 0003); ECIES for grant/invite; never reimplement |

### Known Threat Patterns for This Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Stale-generation replay: relay serves pre-rotation CID | Spoofing | Parent-mirror AAD binding (§2.6); child unseal fails with old generation in AAD |
| AAD transplant: re-use sealed child-readKey blob under different childId/role/generation | Tampering | `buildNodeAad` binds childId + generation + role; transplant fails GCM auth tag |
| Scope predicate bypass: relay omits grant root from active-grant set | Elevation of privilege | Local grant record cross-check (D-08 anti-malicious-relay); defer rather than skip on reconcile failure |
| Caller-buffer zero: rotation helper zeros reused session key | Denial of Service | D-09 zeroization rule: zero only locally-minted keys; SDK E2E catches violations |
| Fan-out leakage: new add-item exposes key to revoked grantee | Information Disclosure | READ-03: seal under parent readKey once; no per-recipient fan-out; `reWrapForRecipients` deleted |
| Invite link replay: same ephemeral key claimed multiple times | Spoofing | Re-wrap produces a standard grant per claimer; each re-wrap uses the same root readKey (acceptable per design §3.11); revoke = rotate readKey |

**Zeroization ownership (D-09 carried from Phase 62):** `rotateOne` mints `readKey'` — zero it on its own failure paths, not on success (the frontier walk needs it for children). Never zero `parentReadKey` or any caller-supplied buffer. The SDK E2E is the only gate that catches zeroization bugs (unit tests don't share buffers). [VERIFIED: design D-09, PITFALLS.md Pitfall 16]

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | The Phase-62 codec dist is built and up-to-date at the start of Phase 63 | Standard Stack | sdk-core typecheck fails; Wave 0 must include `pnpm --filter @cipherbox/core build` |
| A2 | The `addFilePointerToFolder` stub signature in `metadata-ops.ts` (`ipnsPrivateKeyEncrypted` param) will need updating to align with the new `SealedChildRef` shape | Architecture Patterns | Minor refactor to the un-stub signature |
| A3 | `createSubfolder` in `registration.ts` must generate both a readKey and writeKey (the return type already has `rootReadKey`/`rootWriteKey`) | Architecture Patterns | If only readKey is generated, the write-body seal fails |

**If this table is empty for verified claims:** All primary implementation facts above were verified from codebase source files read in this session — no unverified external claims.

---

## Open Questions

1. **Write-body key source in rotateOne**
   - What we know: `rotateOne` re-seals the read-body under `readKey'`. The write-body reseal requires the node's `writeKey` — but Phase 63 is read-chain only and `writeBody` may be absent on read-only nodes.
   - What's unclear: Should `rotateOne` skip write-body re-seal entirely (read-chain only, Phase 65 owns write-chain)? Or pass `writeKey` as an optional parameter?
   - Recommendation: Skip write-body in Phase 63. `sealNode` only re-seals the write-body if `node.writeBody` is set AND `writeKey` is supplied. Read-only rotation (Phase 63) passes no writeKey; Phase 65 adds write-chain rotation.

2. **updateFolderMetadataAndPublish signature alignment**
   - What we know: The current stub signature has `children: SealedChildRef[]`, `folderKey: Uint8Array`, `ipnsPrivateKey`, etc. but the v3 path requires sealing a full `Node` (read-body + optional write-body).
   - What's unclear: Whether the stub's `folderKey` maps directly to `readKey` or whether the write-body key is a separate parameter.
   - Recommendation: Rename `folderKey → readKey`, add optional `writeKey` parameter — align with `sealNode(node, readKey, writeKey)`.

---

## Sources

### Primary (HIGH confidence)
- `packages/sdk-core/src/folder/load.ts`, `metadata-ops.ts`, `registration.ts` — stub signatures to un-stub [VERIFIED: codebase]
- `packages/core/src/node/seal.ts` — `sealNode`/`unsealNode`/`sealChildReadKey`/`unsealChildReadKey`/`sealContent`/`unsealContent` API [VERIFIED: codebase]
- `packages/core/src/node/types.ts` — `Node`, `SealedChildRef`, `PublishedNode` type definitions [VERIFIED: codebase]
- `packages/crypto/src/aes/seal.ts` — `buildNodeAad`/`sealAesGcmAad`/`unsealAesGcmAad` [VERIFIED: codebase]
- `packages/sdk-core/src/cas.ts` — `publishWithCas` API [VERIFIED: codebase]
- `packages/sdk-core/src/ipns/index.ts` — `createAndPublishIpnsRecord`/`resolveIpnsRecord` [VERIFIED: codebase]
- `packages/sdk/src/share/index.ts:88` — `reWrapForRecipients` to delete [VERIFIED: codebase]
- `packages/sdk-core/vitest.config.ts` — coverage exclusion of `src/**/index.ts` [VERIFIED: codebase]

### Secondary (MEDIUM confidence)
- `.planning/design/2026-06-26-sharing-read-keychaining-design.md` §2.6, §2.8, §2.9, §3.2–3.11, §4 — implementation-ready design [VERIFIED: codebase]
- `docs/adr/0002-read-revocation-protects-future-content-only.md` — threat-model stance [VERIFIED: codebase]
- `docs/adr/0003-aad-bound-node-seal-encoding.md` — frozen AAD byte layout [VERIFIED: codebase]
- `.planning/research/PITFALLS.md` — pitfall catalogue (all 20 pitfalls read) [VERIFIED: codebase]
- `.planning/phases/63-read-chain-navigation-and-rotation-core/63-CONTEXT.md` — all decisions D-01..D-10 [VERIFIED: codebase]

---

## Metadata

**Confidence breakdown:**
- Standard Stack: HIGH — all primitives verified in codebase source
- Architecture Patterns: HIGH — algorithms taken directly from design §2.6/§3.x/§4.5
- Pitfalls: HIGH — sourced from PITFALLS.md (itself sourced from design reviews and project memory)
- Validation Architecture: HIGH — test files inspected, quarantine markers confirmed

**Research date:** 2026-06-29
**Valid until:** 2026-07-29 (stable internal design — no external dependencies)
