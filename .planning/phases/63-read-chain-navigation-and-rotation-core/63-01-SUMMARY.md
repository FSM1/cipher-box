---
phase: 63-read-chain-navigation-and-rotation-core
plan: "01"
subsystem: sdk-core/share
tags: [read-chain, navigation, codec, tdd]
dependencies:
  requires: [62-unified-node-codec-core-keystone]
  provides: [fetchAndDecryptMetadata, loadFolderMetadata, navigateReadChain, NavigateResult]
  affects: [sdk-core/folder/load.ts, sdk-core/share/navigate.ts]
tech-stack:
  added: [share/navigate.ts]
  patterns: [TDD RED/GREEN, vi.hoisted mocks, string-literal discriminated union, Phase-62 codec composition]
key-files:
  created:
    - packages/sdk-core/src/share/navigate.ts
    - packages/sdk-core/src/__tests__/share/navigate.test.ts
  modified:
    - packages/sdk-core/src/folder/load.ts
    - packages/sdk-core/src/__tests__/folder.test.ts
decisions:
  - "fetchAndDecryptMetadata composes fetchFromIpfs + JSON.parse as PublishedNode + unsealNode (never reimplements AES)"
  - "loadFolderMetadata returns null on IPNS 404 without throwing"
  - "navigateReadChain uses fetchPublishedNode private helper to get plaintext id/kind before unsealChildReadKey"
  - "NavigateResult is a string-literal union (no TS enums): ok | behind-retry | revoked (D-06)"
  - "Parent mirror childRef.generation — not child envelope generation — is passed to unsealChildReadKey (§2.6 generation-source rule)"
  - "CryptoError from unsealChildReadKey propagates as throw (not silently mapped to revoked)"
  - "folder.test.ts L105/L248 blocks (Folder operations and updateFolderMetadataAndPublish) left skipped — those functions are stubs not implemented in this plan; only fetchAndDecryptMetadata and loadFolderMetadata blocks revived (see Deviations)"
metrics:
  duration: 17m
  completed: "2026-06-29T03:02:26Z"
  tasks_completed: 2
  files_changed: 4
status: complete
---

# Phase 63 Plan 01: Read-Chain Navigation Core Summary

Un-stubbed single-hop folder metadata loading and implemented depth-d multi-hop read-chain navigation using the Phase-62 `node/v3` codec as the first behavioral consumer.

## Tasks Completed

### Task 1: Un-stub folder/load.ts (TDD)

RED commit `ef190fd8b`: Revived `fetchAndDecryptMetadata` and `loadFolderMetadata` test blocks in `folder.test.ts`. Updated `vi.mock('@cipherbox/core')` factory to replace retired `encryptFolderMetadata`/`decryptFolderMetadata` mocks with Phase-62 codec mocks (`sealNode`, `unsealNode`, `sealChildReadKey`, `unsealChildReadKey`). Added those to `vi.hoisted` mockFns.

GREEN commit `e57da586c`: Implemented both functions in `packages/sdk-core/src/folder/load.ts`:

- `fetchAndDecryptMetadata(cid, folderKey, ctx)` — `fetchFromIpfs(ctx, cid)` + `JSON.parse` as `PublishedNode` + `unsealNode(published, folderKey)`.
- `loadFolderMetadata({ ipnsName, folderKey, ctx })` — `resolveIpnsRecord` + null guard + `fetchAndDecryptMetadata`. Returns `null` on IPNS 404.

Both functions keep the existing `withPerf` wrappers and do not zero the caller-supplied `folderKey` (D-09: caller is terminal owner).

### Task 2: Implement navigateReadChain (TDD)

RED commit `43f697de0`: Created `packages/sdk-core/src/__tests__/share/navigate.test.ts` with 7 test cases covering all behavior in the plan's `<behavior>` block.

GREEN commit `8e19c0e1f`: Created `packages/sdk-core/src/share/navigate.ts` exporting:

- `NavigateResult` — string-literal discriminated union `{ status: 'ok'; content: NodeContent; nodeId: string } | { status: 'behind-retry' } | { status: 'revoked' }` (no TS enum, D-06).
- `navigateReadChain(params)` — walks 1 ECIES + O(depth) symmetric hops:
  1. `unwrapKey(base64Decode(readDescriptorRef), recipientPrivKey)` — one ECIES op.
  2. `fetchPublishedNode(rootIpnsName)` — resolve + fetch raw envelope.
  3. Generation check: `published.generation > rootExpectedGeneration` → `behind-retry`.
  4. `unsealNode(rootPublished, shareRootReadKey)` → root node.
  5. For each `hopIpnsName` in `path`: find `SealedChildRef`, fetch child published node, `unsealChildReadKey(childRef.readKeySealed, currentReadKey, childPublished.id, childPublished.kind, childRef.generation)` using the parent mirror generation, `unsealNode`.
  6. Return `{ status: 'ok', content, nodeId }` from file leaf.

## Verification Results

```
pnpm --filter @cipherbox/sdk-core test --run src/__tests__/folder.test.ts src/__tests__/share/navigate.test.ts

Test Files  2 passed (2)
      Tests 10 passed | 29 skipped (39)
```

All acceptance criteria pass:

- `grep -c 'not implemented' load.ts` → 0
- `grep -c 'unsealNode' load.ts` → 3
- `grep -c 'export async function navigateReadChain' navigate.ts` → 1
- `grep -c "status: 'behind-retry'" navigate.ts` → 2 (type + implementation)
- No `enum ` in navigate.ts → 0
- No `sealAesGcmAad`/`buildNodeAad` reimplementation in either file → 0

## Deviations from Plan

### Deviation 1 — L105/L248 block revival

The plan action says to "revive ONLY the load/navigation quarantine blocks at L105 and L248". After reading the actual file, L105 is `describe.skip('Folder operations')` (renameInFolder, deleteFromFolder, addFilePointerToFolder, moveItem) and L248 is `describe.skip('updateFolderMetadataAndPublish conflict handling')`. Both test functions that are still stubs (`throw new Error('not implemented — phase 63')`) NOT being implemented in this plan. Reviving them would produce failing tests.

The blocks that match the plan's intent ("load/navigation") are the `fetchAndDecryptMetadata` block (L491 in the current file) and the `loadFolderMetadata` block (L515). Those ARE the blocks this plan implements.

**Action taken:** Revived the fetchAndDecryptMetadata and loadFolderMetadata blocks (the correct semantic match), updated their test bodies to use `unsealNode` instead of the retired `decryptFolderMetadata`. All 3 tests pass. Left L105, L248, L445, L563 blocks skipped — their functions are implemented in later plans.

**Impact:** Zero behavioral impact. The acceptance criteria ("test exits 0") is satisfied. The deviation is a line-number discrepancy in the plan, not a logic change.

### Deviation 2 — navigate.ts uses fetchPublishedNode private helper instead of fetchAndDecryptMetadata

The plan says to "Compose the Phase-62 codec + `unwrapKey` + `resolveIpnsRecord` + `fetchAndDecryptMetadata`" for navigate. However, `fetchAndDecryptMetadata` requires the readKey upfront (it calls `unsealNode` internally), but for each hop we need the plaintext `id` and `kind` from the `PublishedNode` BEFORE we can call `unsealChildReadKey` to derive the child readKey. Calling `fetchAndDecryptMetadata` would require fetching the node twice (once to get id/kind, once to unseal).

**Action taken:** Added a private `fetchPublishedNode(ipnsName, ctx): Promise<PublishedNode | null>` helper that resolves IPNS + fetches raw bytes + JSON.parses without unsealing. Navigate uses this to get the plaintext id/kind for AAD, then calls `unsealChildReadKey`, then calls `unsealNode` directly. This avoids double-fetch and correctly implements the 4-step walk from §2.6.

**Impact:** Zero behavioral impact. One ECIES op + O(depth) `unsealChildReadKey` + O(depth) `unsealNode` — identical algorithm to the plan's spec.

## Known Stubs

None — this plan's artifacts are fully implemented. The skipped test blocks reference functions in `metadata-ops.ts` and `registration.ts` that remain stubs for plans 63-02 through 63-04.

## Threat Flags

None — no new network endpoints, auth paths, or schema changes introduced. The threat model in the plan (T-63-01 through T-63-04) is correctly mitigated by the implementation (generation-source rule enforced, caller-owns-key, typed fail-closed union).

## Self-Check: PASSED

- `packages/sdk-core/src/folder/load.ts` — FOUND
- `packages/sdk-core/src/share/navigate.ts` — FOUND
- `packages/sdk-core/src/__tests__/share/navigate.test.ts` — FOUND
- Commits `ef190fd8b`, `e57da586c`, `43f697de0`, `8e19c0e1f` — all in git log
