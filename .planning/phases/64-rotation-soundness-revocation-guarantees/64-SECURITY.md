---
phase: 64-rotation-soundness-revocation-guarantees
asvs_level: 2
block_on: high
threats_open: 0
verdict: SECURED
audited: 2026-06-29
---

# Phase 64 Security Audit — Rotation Soundness / Revocation Guarantees

## Overall Verdict: SECURED

The cryptographic cut mechanism is sound. Every declared `mitigate` threat has code-level evidence at the correct boundary. Accepted threats are documented against authoritative references (ADR 0002; Package Legitimacy Audit). Two residual liveness risks are explicitly deferred per user decision and are tracked below — neither constitutes a confidentiality bypass.

**Threats closed:** 18/18 (mitigate) + 2 accepted (T-64-03b, T-64-SC)
**Threats open (blocking, severity >= high):** 0
**Unregistered flags:** 0

---

## Threat Verification

### Declared Mitigations

| Threat ID | Category | Severity | Disposition | Evidence (file:line) |
|-----------|----------|----------|-------------|----------------------|
| T-64-06a | Tampering | high | mitigate | `registration.ts` L144-185: `nodeId: string` and `nodeGeneration: number` are required (no `?`). Runtime guards L171-179 throw `'nodeId is required'` and `'nodeGeneration is required'` when absent. No `?? crypto.randomUUID()` or `?? 0` fallback present. |
| T-64-06b | Information Disclosure | high | mitigate | `client.ts` L598-610: `unsealChildReadKey(movedRef.readKeySealed, sourceFolder.folderKey, ...)` recovers the child key from the source binding; `sealChildReadKey(childReadKey, destFolder.folderKey, ...)` binds it to the destination. Source-key unseal proven to fail closed by `move-reseal.test.ts` Test 2. |
| T-64-05a | Tampering / Data Loss | high | mitigate | `merge.ts` L23-47: union-by-ipnsName via `Map` (local first, remote overwrites). Base entries absent from both local AND remote are pruned (intentional delete). A concurrent-only remote child survives. No crypto mutation — pure structural merge. |
| T-64-03a | Information Disclosure | critical | mitigate | `engine.ts` L288-295: `generateRandomBytes(32)` called unconditionally for file nodes; result assigned to `node.content.fileKey`. No hand-rolled randomness. `sealNode` at L531 re-seals the body carrying the new `fileKey'` under `readKeyPrime`. |
| T-64-01 | Tampering | high | mitigate | `engine.ts` L504-510: `if (!nodeIpnsPrivateKey) throw new Error('rotateOne: no IPNS private key ...')` placed before `readKeyPrime` is minted. `publishWithCas` at L548 receives `ipnsPrivateKey: nodeIpnsPrivateKey` directly — no `??` fallback present in that argument. |
| T-64-02 | Information Disclosure | critical | mitigate | `engine.ts` L933-941: `sealChildReadKey(result.childReadKey, parentState.parentNewReadKey, item.childPubId, item.childPubKind, result.newGeneration)` — uses the PARENT's NEW `readKey'` (from `ParentTrackingState.parentNewReadKey`, populated from the parent's own `rotateOne` result), not the child's own key. `PLACEHOLDER_WRITE_KEY` at L530-531/L575/L585 is used only in `sealNode` write-body calls, not in the IPNS publish path (confirmed: L550 `ipnsPrivateKey: nodeIpnsPrivateKey`). |
| T-64-02b | Repudiation / Integrity | high | mitigate | `engine.ts` L958-974: batched parent `updateFolderMetadataAndPublish` called with `nodeId: parentState.parentNodeId` and `nodeGeneration: parentState.parentNodeGeneration` — these are the parent's generation from ITS own `rotateOne`, never incremented again. Only the IPNS sequence counter advances. |
| T-64-04a | Denial of Service | high | mitigate | `engine.ts` L313-342: `reMintGrantsRootedAt` enumerates via `callbacks.queryGrantsFn(nodeId)` and calls `callbacks.updateGrantFn(shareId, readDescriptorRef, newGeneration)` for every non-revoked grant. No orphaned inner grantee on the in-scope (SDK-core + mock) path. Live persistence deferred to Phase 66 via D-04 transport seam — injection callbacks are the correct boundary. |
| T-64-04b | Elevation of Privilege | critical | mitigate | `engine.ts` L329-331: `if (grant.isRevoked) { await callbacks.deleteGrantFn(grant.shareId); }` — revoked recipient's row is deleted and the code path never calls `updateGrantFn` for that shareId. Confirmed by `grant-remint.test.ts` Test 2 (revoked → delete only). |
| T-64-04c | Cryptography | high | mitigate | `engine.ts` L337: `const wrappedBytes = await wrapKey(newReadKey, grant.recipientPublicKey)` — ECIES `wrapKey` from `@cipherbox/crypto`. No hand-rolled key wrapping. Import visible at L29: `import { generateRandomBytes, wrapKey } from '@cipherbox/crypto'`. |
| T-64-05b | Tampering / Data Loss | high | mitigate | `engine.ts` L564-591: the `merge` callback on CAS-409 calls `mergeConcurrentChildren(base, remote, parentReadKey, node.children ?? [], readKeyPrime, node, generationPrime, PLACEHOLDER_WRITE_KEY)`. `mergeConcurrentChildren` at L365-391 unseals both base and remote under `oldReadKey` (pre-rotation), delegates to `mergeChildren` (remote wins), re-seals merged result under `readKeyPrime`. The re-fetch (remote) is used, not the stale pre-409 local snapshot (Pitfall 3 avoided). |
| T-64-06c | Repudiation / Integrity | high | mitigate | `engine.ts` L877-909: convergence guard — `resolveAndFetch` called before `rotateOne`; if `currentPub.generation > item.enqueuedGeneration`, `rotateOne` is skipped and only the parent ref update runs. `verifySubtreeClean` at L405-438 detects dirty edges by comparing `childPub.generation > childRef.generation`. |
| T-64-06d | Tampering | high | mitigate | `engine.ts` L756-819: the `rootResult.skipped` branch calls `await verifySubtreeClean(rootNodeIpnsName, rootReadKey, ctx)` before marking any status. A clean subtree sets `status = 'complete'`; a dirty subtree seeds the BFS queue from the frontier and falls through to the BFS loop. The old bypass (marking complete on root-only commit) is absent. |
| T-64-06e | Denial of Service | high | mitigate | `engine.ts` L600-611: `await reMintGrantsRootedAt(...)` runs at L600; `jobRecord.completedNodeIds.add(nodeId)` runs at L611 (AFTER). The catch at L621-626 zeroes `readKeyPrime` and re-throws without ever executing L611, leaving the node retryable on resume. |
| T-64-06f | Data Loss / Integrity | high | mitigate | `engine.ts` L624: `readKeyPrime.fill(0)` in catch — only the engine-minted key is zeroed. L1023: `item.nodeReadKey.fill(0)` zeroes queue-derived keys AFTER the grandchild enqueue loop. `rootReadKey` is never zeroed (doc comment at L13-18 and inline at L513 and L848-849 confirm caller owns it). |
| T-64-06g | Integrity | high | mitigate | `tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts` Test 2: crash at final persist; resume with fresh job; all 3 nodes remain at gen=1; zero `getRandomValues` calls on resume (no re-rotation). Suite passed against live stack (64-08-SUMMARY). |
| T-64-05c | Data Loss | high | mitigate | `rotation-crash-safety.test.ts` Test 3: concurrent child added mid-rotation forces CAS-409; after walk `concurrentIpnsName` AND `sub3IpnsName` both present in rotated parent. Suite passed against live stack (64-08-SUMMARY). |
| T-64-01b | Tampering | high | mitigate | `rotation-crash-safety.test.ts` Test 1: `nodeKeySource` callback supplies real per-node keypairs; no fail-closed throw on the happy path; all 3 nodes rotated. Suite passed against live stack (64-08-SUMMARY). |

### Accepted Threats

| Threat ID | Category | Severity | Disposition | Accepted Risk Reference |
|-----------|----------|----------|-------------|------------------------|
| T-64-03b | Information Disclosure | medium | accept | ADR 0002 (`docs/adr/0002-read-revocation-protects-future-content-only.md`): cold CIDs pinned on IPFS remain decryptable by any prior holder; read-revocation protects future writes and navigation only. Lazy `contentRekeyPending` is architecturally correct for content-addressed storage. Disclosed in revoke UX per ADR consequences. |
| T-64-SC | Tampering | low | accept | No npm/pip/cargo package installs in any Phase-64 plan. Package Legitimacy Audit in 64-RESEARCH.md confirms "Packages removed due to SLOP verdict: none; Packages flagged SUS: none." All dependencies are existing monorepo packages. |

---

## Key Security Property Verification

### D-02 Genuine Cut (Phase-63 CRITICAL Bug Fixed)

The Phase-63 bug was: `rotateOne` sealed `newReadKeySealed` under `parentReadKey` (the child's OWN pre-rotation key — a legacy misnomer) and the caller never wrote it back.

Verified fixed: `engine.ts` L933-941 re-seals the child's new `readKey'` under `parentState.parentNewReadKey` (the parent's new readKey', from the parent's own rotateOne result), using `childPubId`/`childPubKind`/`result.newGeneration` for AAD binding. The update is written to the mutable `parentState.children` copy and published via `updateFolderMetadataAndPublish` once after all children complete (L956-974).

AAD integrity: `sealChildReadKey` calls `buildNodeAad(childId, kind, generation, 0x02)` (role `child-readkey` per ADR 0003). A stale `generation` or wrong `childId` causes AEAD tag mismatch on unseal — fail closed.

### D-01 Fail-Closed Publish

`engine.ts` L504-510: the guard fires BEFORE `readKeyPrime` is minted. `publishWithCas` at L548 unconditionally passes `ipnsPrivateKey: nodeIpnsPrivateKey` — no `??` fallback.

The `PLACEHOLDER_WRITE_KEY` (L530) is the `writeKey` argument to `sealNode` — it seals the write-body (role `0x04` per ADR 0003), which is legitimately absent until Phase 65. It does NOT appear in the publish path. Verified: L548 `ipnsPrivateKey: nodeIpnsPrivateKey` only.

### Zeroization Invariant (D-07/D-09)

Three zero sites, all correct:
- L624 (`readKeyPrime.fill(0)` in catch): engine minted it → engine zeroes on failure. No success-path zero.
- L1023 (`item.nodeReadKey.fill(0)`): engine derived via `unsealChildReadKey` → engine zeroes after grandchildren are enqueued. Not before.
- No zero on `rootReadKey`, `parentReadKey`, or any caller-supplied buffer — confirmed by absence in the grep output.

### D-06 Binding Stability

`registration.ts` L144-150: `nodeId: string` and `nodeGeneration: number` are required fields (no `?`). Runtime guards L171-179 throw before `sealNode` is called if either is absent.

`client.ts`: all 6 `updateFolderMetadataAndPublish` call sites pass `nodeId: folder.nodeId` and `nodeGeneration: folder.nodeGeneration` (confirmed by grep at L517-518, L629-630, L705-706, L824-825, L1085-1086). Both `registerFolder` and `loadFolder` populate `FolderState.nodeId`/`.nodeGeneration` (grep L392-393).

### ECIES + AES-GCM Primitives

- `readDescriptorRef` re-mint: `wrapKey` (ECIES) from `@cipherbox/crypto` — L337.
- Node seal/unseal: `sealNode`/`unsealNode` from `@cipherbox/core` — calls `sealAesGcmAad` internally per ADR 0003.
- Child readKey seal/unseal: `sealChildReadKey`/`unsealChildReadKey` from `@cipherbox/core` — role `0x02`, fresh random IV per ADR 0003.
- Random key generation: `generateRandomBytes(32)` from `@cipherbox/crypto` and `crypto.getRandomValues(new Uint8Array(32))` (both 32-byte, no hand-rolled entropy).
- No hand-rolled AEAD or ECDH anywhere in `engine.ts`.

---

## Residual Risks (Deferred, User-Accepted — NOT Blockers)

These risks are liveness/durability concerns, not confidentiality bypasses. Decided 2026-06-29 with captured todos.

### RR-01: Concurrent-Add Remote-Wins Downgrades Rotated Child readKeySealed

**Description:** During a CAS-409 on a parent's D-09 batched re-publish, `mergeChildren` applies remote-wins. If the remote snapshot pre-dates the D-02 re-seal (i.e., the remote was published before the child's `SealedChildRef.readKeySealed` was updated), the merged parent carries the stale pre-D-02 `readKeySealed` for that child. The moved child is NOT dropped (T-64-05c/T-64-05b is satisfied) but the child link is sealed under the parent's OLD `readKey` rather than the NEW `readKey'`, causing `unsealChildReadKey` to fail on next navigation.

**Security impact:** Liveness regression only. The merged parent body is sealed under `readKeyPrime` — a revoked reader cannot access it. Future content writes remain protected. This does NOT constitute a revocation bypass.

**Status:** Deferred — todo `rotation-concurrent-add-merge-downgrades-rotated-child-readkey`.

**Mitigation path:** A merge strategy that prefers the local D-02 re-sealed ref when both sides carry the same `ipnsName` (local-wins for known-rotated children). Phase 65 or 66 context.

### RR-02: Fresh-Record Crash-Resume Requires Persisted Completion State

**Description:** A genuine cold-restart resume (empty `completedNodeIds`, original `rootReadKey`) is not viable mid-walk. After the root rotates, its body is sealed under `readKeyPrime_root`; passing the original `rootReadKey` to `verifySubtreeClean` causes AEAD failure. The sdk-e2e crash-safety suite (Test 2) works around this by seeding `completedNodeIds` from crash-time state and passing `readKeyPrimeRoot2` as the resume `rootReadKey`, representing a real host checkpoint. Without durable persistence of both `completedNodeIds` AND `readKeyPrime`, a post-crash restart cannot self-heal.

**Security impact:** Durability gap only. A crash mid-walk leaves the subtree partially rotated — a revoked reader is cut at the root the moment the root step commits (§4.2 root-first ordering). Partial rotation does not re-admit the revoked reader. The gap is that a partially-rotated subtree requires manual operator recovery without Phase-68 durable persistence.

**Status:** Deferred — todo `rotation-fresh-record-resume-and-sc4-double-bump`. Phase-68 IndexedDB persistence resolves this.

---

## Unregistered Flags

None. All SUMMARY.md `## Threat Flags` sections for Plans 01-08 report "none" / "no new network endpoints, auth paths, or schema changes." The 64-08-SUMMARY deviation notes (concurrent-add remote-wins, seeded completedNodeIds) are captured as RR-01 and RR-02 above.

---

## ASVS Boundary Checks (Level 2)

| ASVS Category | Control | Boundary Check |
|---------------|---------|----------------|
| V4 Access Control | `hasCoveringGrant` scope predicate | `scope.ts` present and gates `moveItem` scope-exit (not modified this phase; confirmed stable). `reMintGrantsRootedAt` deletes revoked recipient row at the correct point (after successful `rotateOne`). |
| V5 Input Validation | `nodeId` UUID in `buildNodeAad`; generation bounds | `buildNodeAad` is fail-closed per ADR 0003: rejects invalid kind/role/UUID/generation. Runtime guards in `registration.ts` enforce non-empty `nodeId` and numeric `nodeGeneration` before `sealNode` is called. |
| V6 Cryptography | AES-256-GCM + ECIES; fresh random IV; no hand-roll | `sealAesGcmAad`/`unsealAesGcmAad` called via `@cipherbox/core` wrappers (not directly); `wrapKey`/`unwrapKey` ECIES for grant descriptors. IV is minted fresh per seal inside `sealAesGcmAad` — no caller-supplied IV accepted. No plaintext key material logged or sent to server. |

---

SECURITY.md generated: `.planning/phases/64-rotation-soundness-revocation-guarantees/64-SECURITY.md`
