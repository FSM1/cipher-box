---
phase: 63-read-chain-navigation-and-rotation-core
verified: 2026-06-29T00:00:00Z
status: passed
score: 5/5 must-haves verified
behavior_unverified: 0
overrides_applied: 2
overrides:
  - must_have: "reWrapForRecipients and addShareKeys are deleted from the codebase (SC#3 / READ-03)"
    reason: "Decision D-03 (locked in 63-CONTEXT.md before Phase 63 planning) explicitly defers addShareKeys callback TYPE removal to Phase 68 (apps/web layer). The SDK-layer fan-out function reWrapForRecipients IS deleted; only the TYPE in packages/sdk/src/types.ts:32 is preserved as a layering boundary. The PLAN must_haves correctly reflect D-03: 'The addShareKeys callback TYPE is left intact (Phase 68 owns its removal).' Functional behavior (no fan-out) is fully satisfied."
    accepted_by: "Phase 63 CONTEXT.md D-03 (locked before planning)"
    accepted_at: "2026-06-29T00:00:00Z"
  - must_have: "A single happy-path sdk-e2e round-trip passes against the live local API stack (D-04)"
    reason: "Infrastructure-limited: the live API stack (docker + pnpm api dev + redis 6380) is not running in the verifier environment. Per project convention (project memory: 'infra-limited items aren't human-verify — deliverable wired, data missing upstream → accepted override + status passed, not human_needed'): the test file exists, is not skipped, is substantively implemented (313 lines, full grant→navigate→rotate→revoked round-trip), is wired to the real SDK-core functions, and the executor documented the pass in 63-07-SUMMARY.md with commit e405ec6f9 and specific assertion evidence (jobRecord.completedNodeIds, behind-retry status)."
    accepted_by: "infra-limited convention + executor pass documented in 63-07-SUMMARY.md"
    accepted_at: "2026-06-29T00:00:00Z"
---

# Phase 63: Read-Chain Navigation and Rotation Core Verification Report

**Phase Goal:** The read key-chain navigation and rotation walk exist in `packages/sdk-core` as named implementation files; read grants require one ECIES unwrap then O(depth) symmetric AES; the scope-exit predicate gates every delete/move/rename.
**Verified:** 2026-06-29
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | A read grant is issued by ONE ECIES wrap of the share-root readKey into one readDescriptorRef with zero node touches and zero IPNS publishes; granting a single file is structurally identical to granting a deep folder (SC#1 / READ-01) | VERIFIED | `issueReadGrant` in `packages/sdk-core/src/share/grant.ts` L100–124: one `wrapKey` call, zero `resolveIpnsRecord`/`sealNode`/IPNS calls. `grant.test.ts` asserts `wrapKey` called exactly once and no IPNS mock invoked. |
| 2 | A grantee navigates to a depth-d child via ONE ECIES unwrap then d symmetric `unsealChildReadKey` hops, recovering content key + CID + encryptionMode at a file node; the read path distinguishes `'behind-retry'` from `'revoked'` without ambiguity (SC#2 / READ-02 / D-06) | VERIFIED | `navigateReadChain` in `packages/sdk-core/src/share/navigate.ts` L101–169: single `unwrapKey` call, O(depth) loop calling `unsealChildReadKey` with parent-mirror generation (childRef.generation, not childPublished.generation). `NavigateResult` string-literal union, no enum. `navigate.test.ts` asserts exactly 1 ECIES unwrap and d symmetric calls via spy. |
| 3 | Adding an item seals the child readKey under the parent readKey with no per-recipient fan-out; `reWrapForRecipients` is deleted from the SDK codebase; `addShareKeys` callback TYPE is preserved per D-03 (Phase 68 boundary — see override) (SC#3 / READ-03 / D-03) | VERIFIED (override) | `reWrapForRecipients`: 0 matches in `packages/sdk/src/share/index.ts` and `packages/sdk/src/client.ts`. `addFilePointerToFolder` in `packages/sdk-core/src/folder/metadata-ops.ts` L101–107: one `sealChildReadKey` call. Test asserts `sealChildReadKey` called exactly once. `addShareKeys` TYPE at `packages/sdk/src/types.ts:32` preserved per D-03 (override applied). |
| 4 | A move within a grantee's scope is link rewrites only with zero re-encryption; `hasCoveringGrant` is present and gates every delete/move/rename; a private delete with no active grants triggers zero `rotateReadFromNode` invocations and zero IPNS publishes beyond the parent relink (SC#4 / READ-04 / ROT-02) | VERIFIED | `moveItem` in `metadata-ops.ts` L132–143: pure link rewrite. Test asserts `sealChildReadKey` and `sealNode` NOT called. `hasCoveringGrant` in `packages/sdk-core/src/rotation/scope.ts` L98–113: pure function, no I/O (grep confirms zero fetch/axios/resolveIpnsRecord calls). `scope.test.ts` L134–146: zero-rotation invariant — injected `rotateSpy` called 0 times for private mutation, called exactly once for covered scope-exit. |
| 5 | `rotateReadFromNode` is implemented in a named file `src/rotation/engine.ts` (NOT an index.ts barrel) so vitest coverage counts it; `rotateOne` commits per-node atomically via CAS before advancing the walk frontier; four Phase-64 seams exist as named individually-testable functions that throw conditionally (SC#5 / ROT-01 / D-01) | VERIFIED | File at `packages/sdk-core/src/rotation/engine.ts` (558 lines, not index.ts). `rotateReadFromNode` L421 and `rotateOne` L274 are both exported. Four seams: `mintFileKeyOnRotate` L191, `reMintGrantsRootedAt` L206, `mergeConcurrentChildren` L225, `verifySubtreeClean` L246 — each throws "not implemented — phase 64 (...)". Seams invoked CONDITIONALLY: `mintFileKeyOnRotate` only on file nodes (L319), `mergeConcurrentChildren` only on CAS-409 (L363 merge callback), `reMintGrantsRootedAt` only when `innerGrants` supplied (L381), `verifySubtreeClean` only on resume. CAS commit via `publishWithCas` at L346. Host-agnostic: zero fuse/tauri/web imports. |

**Score:** 5/5 truths verified (2 overrides applied: addShareKeys type per D-03; sdk-e2e infra-limited per project convention)

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `packages/sdk-core/src/share/navigate.ts` | `navigateReadChain` + `NavigateResult` string-literal union | VERIFIED | 169 lines, substantive. Exports `navigateReadChain` and `NavigateResult`. No enum. |
| `packages/sdk-core/src/share/grant.ts` | `issueReadGrant` + `claimInviteReadKey` | VERIFIED | 179 lines, substantive. Exports both functions and `ReadGrantPayload`. No enum. |
| `packages/sdk-core/src/rotation/engine.ts` | `rotateReadFromNode`, `rotateOne`, 4 seams, `RotationJobRecord` | VERIFIED | 558 lines, substantive. Named file (not index.ts). All required exports present. |
| `packages/sdk-core/src/rotation/scope.ts` | `hasCoveringGrant` + `maybeRotateOnScopeExit` | VERIFIED | 159 lines, substantive. Both functions exported. Pure — no I/O. No enum. |
| `packages/sdk-core/src/folder/load.ts` | Un-stubbed `fetchAndDecryptMetadata` + `loadFolderMetadata` | VERIFIED | 69 lines. Zero "not implemented" strings. Both functions call `unsealNode`. |
| `packages/sdk-core/src/folder/metadata-ops.ts` | Un-stubbed add/move/rename/delete | VERIFIED | 143 lines. Zero "not implemented" strings. `sealChildReadKey` present (1 call in addFilePointerToFolder). |
| `packages/sdk-core/src/folder/registration.ts` | Un-stubbed `createSubfolder` + `updateFolderMetadataAndPublish`; Phase-65 stubs preserved | VERIFIED | 281 lines. Zero "phase 63" stubs. Three Phase-65 stubs intact (each throws "not implemented — phase 65"). `publishWithCas` present. |
| `packages/sdk/src/share/index.ts` | `reWrapForRecipients` removed | VERIFIED | 0 matches for `reWrapForRecipients` in file. |
| `packages/sdk/src/client.ts` | `reWrapForRecipients`/`reWrapNewItems` removed; add-item path wired to `addFilePointerToFolder` | VERIFIED | 0 matches for either deleted symbol. `addFilePointerToFolder` wired at L730 and L971. |
| `tests/sdk-e2e/src/suites/read-chain-navigation.test.ts` | Happy-path sdk-e2e round-trip; describe NOT skipped | VERIFIED (override) | 313 lines. `describe(...)` (no `.skip`). Calls `navigateReadChain`, `issueReadGrant`, `rotateReadFromNode`. Infra-limited override applied. |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `share/navigate.ts` | `@cipherbox/core` (seal.ts) | `unsealChildReadKey` using `childRef.generation` parent-mirror as AAD source | WIRED | Import at L26; used at L146 with `childRef.generation` (not `childPublished.generation`) |
| `folder/load.ts` | `../ipns` | `resolveIpnsRecord` then fetch CID then `unsealNode` | WIRED | Import at L16; used at L64 |
| `rotation/engine.ts` | `../cas` (cas.ts) | `rotateOne` per-node CAS commit via `publishWithCas` | WIRED | Import at L29; used at L346 inside `rotateOne` |
| `rotation/engine.ts` | `@cipherbox/core` (seal.ts) | Re-seal read-body under readKey' and rewrite parent `SealedChildRef.readKeySealed` | WIRED | `sealChildReadKey` imported at L27; used at L335 |
| `rotation/scope.ts` | `rotation/engine.ts` | `maybeRotateOnScopeExit` invokes `rotateReadFromNode` iff `hasCoveringGrant` true (injectable for spying) | WIRED | `deps.rotate` injection at L157; scope.test.ts spy asserts call count |
| `client.ts` | `@cipherbox/sdk-core` | add-item path delegates to `addFilePointerToFolder` + `updateFolderMetadataAndPublish` | WIRED | `addFilePointerToFolder` calls at L730 and L971 |
| `read-chain-navigation.test.ts` | `@cipherbox/sdk-core` | `issueReadGrant` → `navigateReadChain` → `rotateReadFromNode` against the live API | WIRED (infra override) | All three imports confirmed at L37–41; test not skipped |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| `navigateReadChain` exported from barrel | `grep -c 'navigateReadChain' packages/sdk-core/src/index.ts` | 1 | PASS |
| `rotateReadFromNode` exported from barrel | `grep -c 'rotateReadFromNode' packages/sdk-core/src/index.ts` | 1 | PASS |
| `hasCoveringGrant` exported from barrel | `grep -c 'hasCoveringGrant' packages/sdk-core/src/index.ts` | 1 | PASS |
| `reWrapForRecipients` absent from SDK client | `grep -c 'reWrapForRecipients\|reWrapNewItems' packages/sdk/src/client.ts` | 0 | PASS |
| `addShareKeys` TYPE preserved in types.ts | `grep -c 'addShareKeys' packages/sdk/src/types.ts` | 3 | PASS (D-03 override) |
| engine.ts is a named file, not index.ts | `ls packages/sdk-core/src/rotation/engine.ts` | exists | PASS |
| No enum declarations in any Phase-63 file | `grep 'enum ' navigate.ts grant.ts engine.ts scope.ts` | 0 matches | PASS |
| No TBD/FIXME/XXX debt markers in Phase-63 source files | `grep 'TBD\|FIXME\|XXX' <all 7 files>` | 0 matches | PASS |
| No FUSE/Tauri/web imports in engine.ts | `grep 'fuse\|tauri\|@cipherbox/web\|window\.' engine.ts` | 0 matches | PASS |
| Phase-65 stubs preserved in registration.ts | `grep -c 'not implemented.*phase 65' registration.ts` | 3 | PASS |
| load.ts fully implemented (no stubs) | `grep -c 'not implemented' load.ts` | 0 | PASS |
| metadata-ops.ts fully implemented (no stubs) | `grep -c 'not implemented' metadata-ops.ts` | 0 | PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| READ-01 | 63-02 | One ECIES wrap, zero node touches, file == deep folder | SATISFIED | `issueReadGrant` in `share/grant.ts`; `wrapKey` called once; no IPNS/seal ops |
| READ-02 | 63-01 | 1 ECIES unwrap + d symmetric hops; typed soft/hard result | SATISFIED | `navigateReadChain` in `share/navigate.ts`; parent-mirror generation rule; string-literal union |
| READ-03 | 63-04, 63-06 | One seal per add-item, no fan-out; `reWrapForRecipients` deleted | SATISFIED | `addFilePointerToFolder` — one `sealChildReadKey` call; fan-out function deleted from SDK |
| READ-04 | 63-04 | Move = link rewrites only, zero re-encryption | SATISFIED | `moveItem` — pure link rewrite; test confirms no sealChildReadKey/sealNode |
| READ-05 | 63-02 | Invite re-wrap primitive; no per-child fan-out | SATISFIED | `claimInviteReadKey` in `share/grant.ts`; `reWrapKey` used; zero `encryptedChildKeys` produced |
| ROT-01 | 63-03 | Resumable per-node-CAS-commit walk; IPNS records are source of truth | SATISFIED | `rotateReadFromNode` + `rotateOne` in `rotation/engine.ts`; `publishWithCas` CAS commit per node |
| ROT-02 | 63-05 | Rotation fires iff scope-exit; private delete = zero rotations | SATISFIED | `hasCoveringGrant` pure predicate; `maybeRotateOnScopeExit` gating; scope.test.ts zero-rotation spy invariant |

All 7 required IDs (READ-01, READ-02, READ-03, READ-04, READ-05, ROT-01, ROT-02) are satisfied. ROT-03..07 correctly remain unchecked in REQUIREMENTS.md (Phase 64/68 scope).

### Anti-Patterns Found

| File | Pattern | Severity | Impact |
|------|---------|----------|--------|
| `packages/sdk-core/src/__tests__/folder.test.ts` | 4 stale `describe.skip('...TODO(phase 63)')` blocks (L114, L257, L454, L878) | INFO | Dead code — tests the retired FolderChild/FolderEntry/FilePointer/encryptFolderMetadata API under `@ts-nocheck`. Not a failure. See finding below. |

No TBD/FIXME/XXX markers in any Phase-63 source file. No unresolved debt markers.

### folder.test.ts Stale Skip Blocks — Finding and Recommendation

**What exists:** Four `describe.skip` blocks marked `TODO(phase 63)` remain in `packages/sdk-core/src/__tests__/folder.test.ts`:

1. `L114 — 'Folder operations — TODO(phase 63)'` — tests `renameInFolder`, `deleteFromFolder`, `addFilePointerToFolder`, `moveItem` using the retired `FolderChild`/`FilePointer`/`FolderEntry` types.
2. `L257 — 'updateFolderMetadataAndPublish conflict handling — TODO(phase 63)'` — tests 409/CAS conflict handling using the retired `encryptFolderMetadata`/`decryptFolderMetadata` API.
3. `L454 — 'updateFolderMetadataAndPublish zeroization decision guard (S3/D-05) — TODO(phase 63)'` — tests that `ipnsPrivateKey`/`folderKey` are not zeroed.
4. `L878 — 'createSubfolder — TODO(phase 63)'` — tests subfolder creation using the retired `FolderEntry` return shape with `wrapKey`/`bytesToHex` encoding.

**What the executors did instead:** Created new active `describe` blocks (not skipped) for the Phase-63 implementation:

- L620–737: `renameInFolder (SealedChildRef)`, `deleteFromFolder (SealedChildRef)`, `addFilePointerToFolder (SealedChildRef — READ-03: one seal, no fan-out)`, `moveItem (SealedChildRef — READ-04: zero re-encryption)` — covers Block 1.
- L806–870: `updateFolderMetadataAndPublish (phase 63 — delegates to publishWithCas)` with CAS-increment and zeroization tests — covers Blocks 3 and partially Block 2.
- L743–799: `createSubfolder (phase 63 — first-publish seq 1n)` — covers Block 4.

**Coverage assessment:**

| Stale Block | New Active Coverage | Verdict |
|-------------|---------------------|---------|
| L114 Folder operations | L620–737: all four SealedChildRef mutations tested (rename/delete/add/move) | REDUNDANT DEAD CODE — safe to delete |
| L257 Conflict handling | L806 tests happy path + zeroization; 409 path in Phase 63 hits `mergeChildren` Phase-64 stub (by design — throws "not implemented — phase 64"). No test for the 409-propagation path, but this is intentionally untestable in Phase 63. `publishWithCas` CAS retry tested in `cas.test.ts`. | REDUNDANT DEAD CODE — the old tests use the retired `decryptFolderMetadata` API; the Phase-63 conflict behavior (stub throw) is correct and tested at the `cas.ts` level. |
| L454 Zeroization guard | L851: `updateFolderMetadataAndPublish` does NOT zero `readKey` or `ipnsPrivateKey` (caller retains ownership, D-09) | REDUNDANT DEAD CODE — identical scenario covered by new active test |
| L878 createSubfolder | L743: first-publish seq 1n, D-09 non-zeroing tested | REDUNDANT DEAD CODE — old block tests retired `FolderEntry` return shape |

**Recommendation:** All 4 stale skip blocks are **safe to delete**. They test a fully retired API (types and functions that no longer exist). The new active describe blocks cover the Phase-63 scenarios. No critical scenario is missing from active coverage.

This is housekeeping — cleanup can happen in any follow-up phase without behavioral impact.

---

_Verified: 2026-06-29_
_Verifier: Claude (gsd-verifier)_
