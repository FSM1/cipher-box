---
phase: 65-sdk-write-chain-bin-re-link-and-invite-claim
verified: 2026-06-30T00:00:00Z
status: passed
score: 4/4 must-haves verified
behavior_unverified: 0
overrides_applied: 0
deferred:
  - truth: "old names are tombstoned — publish gate rejects (403/410), resolve returns 410"
    addressed_in: "Phase 66"
    evidence: "Phase 66 SC: 'A tombstoned `ipns_records` row is rejected at the publish gate (403/410) and at the EOL-only renewal; resolve returns a 410 marker for tombstoned names'"
---

# Phase 65: SDK Write-Chain, Bin Re-link, and Invite Claim — Verification Report

**Phase Goal:** The write-body carries Ed25519 signing material sealed under a separate `writeKey`; write-revocation performs full Ed25519 rotation per ADR 0001; bin restore is a pure re-link; invite claim re-wraps a single root `readKey`.
**Verified:** 2026-06-30
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | The write-body holds Ed25519 signing material sealed under `writeKey` with role `0x04` (`child-writekey`); a read-only holder can never reach signing material | VERIFIED | `sealChildWriteKey`/`unsealChildWriteKey` in `packages/core/src/node/seal.ts` use `buildNodeAad(..., 0x04)`; `packages/sdk/src/__tests__/shared-write.test.ts` line 161: `expect(readOnlyNode.writeBody).toBeUndefined()` after `unsealNode(pub, readKey)` with no writeKey |
| 2 | Write-revocation generates a new Ed25519 keypair and k51 name per node, cascading parent re-points to the share root; old names are removed from the TEE republish batch | VERIFIED | `rotateWriteFromNode` in `engine.ts`: calls `generateEd25519Keypair()` + `deriveIpnsName()` per node, `createAndPublishIpnsRecord({sequenceNumber: 1n})`, `teeUnenrollFn(oldIpnsName)` per old name; write-revocation unit tests Test 3 (child-first cascade) and Test 8 (parent re-point); D-04 e2e gate PASSED (2/2) |
| 3 | Surviving co-writers receive the rotated Ed25519 key re-wrapped into their `writeDescriptorRef`; an offline co-writer receives a clear "cannot write until re-fetch" error | VERIFIED | `rotateWriteFromNode` calls `wrapKey(newWriteKey, recipientPublicKey)` for non-revoked grants + `writeDescriptorRefPersistFn`; `deleteWriteGrantFn` for revoked; `CannotWriteUntilRefetchError` class exported from `shared-write.ts` with tests for every write operation + tombstoned target |
| 4 | `bin` restore is a pure re-link; `originalFolderKeyEncrypted` and re-encrypt-on-restore path deleted from `packages/core/src/bin/types.ts` and `packages/sdk/src/bin/index.ts`; `encryptedChildKeys` JSONB fan-out deleted from invite claim | VERIFIED | `restoreFromBin` in `bin/index.ts` calls `sealChildReadKey(entry.nodeReadKey, destParentReadKey, ...)` with no content re-encrypt; `originalFolderKeyEncrypted` grep returns 0 in both files; `encryptedChildKeys` grep returns 0 in all non-test sdk-core/sdk source; `claimInvite` in `grant.ts` calls `claimInviteReadKey` and `insertShareFn` once with no fan-out |

**Score:** 4/4 truths verified (0 present, behavior-unverified)

### Deferred Items

Items not yet met but explicitly addressed in later milestone phases.

| # | Item | Addressed In | Evidence |
|---|------|-------------|----------|
| 1 | Live publish gate rejects (403/410) and resolve returns 410 for tombstoned names | Phase 66 | Phase 66 SC: "A tombstoned `ipns_records` row is rejected at the publish gate (403/410) and at the EOL-only renewal; resolve returns a 410 marker for tombstoned names." Phase 65 plans explicitly scope this to a mock seam (D-02); the TEE unenroll (teeUnenrollFn) is done. |

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `packages/core/src/node/seal.ts` | `sealChildWriteKey` / `unsealChildWriteKey` (role 0x04) | VERIFIED | Both functions present, compose `sealAesGcmAad`/`buildNodeAad` with role `0x04`, do not zero caller buffers |
| `packages/core/src/node/index.ts` | barrel re-export of `sealChildWriteKey` / `unsealChildWriteKey` | VERIFIED | Lines 26-27 re-export both symbols |
| `packages/core/src/index.ts` | top-level barrel re-export | VERIFIED | Lines 24-25 re-export both symbols |
| `packages/core/src/__tests__/seal-write-chain.test.ts` | round-trip + role-0x04 KAT + cross-role rejection + AAD-mismatch + terminal-owner | VERIFIED | All four assertion groups present and named |
| `packages/core/src/bin/types.ts` | `BinEntry.nodeReadKey?: Uint8Array` field | VERIFIED | Field at line 72 with doc comment |
| `packages/sdk/src/bin/index.ts` | `addToBin` / `restoreFromBin` implemented as pure re-link; no `originalFolderKeyEncrypted` | VERIFIED | `restoreFromBin` calls `sealChildReadKey(entry.nodeReadKey, ...)`, no content re-encrypt, grep for `originalFolderKeyEncrypted` returns 0 |
| `packages/sdk-core/src/share/grant.ts` | `claimInvite` service flow; no `encryptedChildKeys` | VERIFIED | `claimInvite` at line 271, calls `claimInviteReadKey` + `insertShareFn` once; non-test source grep for `encryptedChildKeys` returns 0 |
| `packages/sdk-core/src/share/index.ts` | barrel re-export of `claimInvite` | VERIFIED | Line 5 re-exports `claimInvite` |
| `packages/sdk/src/share/shared-write.ts` | `SharedWriteContext` carries `writeKey`; six operations implemented; `CannotWriteUntilRefetchError`; no `addShareKeysFn` invocations | VERIFIED | `writeKey: Uint8Array` at line 77; `CannotWriteUntilRefetchError` at line 136; `grep -c "addShareKeysFn("` returns 0; no stub bodies |
| `packages/sdk-core/src/rotation/engine.ts` | `PLACEHOLDER_WRITE_KEY` removed; `nodeWriteKey` threaded; fail-closed guard; `rotateWriteFromNode` + `WriteRevocationCallbacks` | VERIFIED | `grep -c "PLACEHOLDER_WRITE_KEY"` returns 0 (only comments in test file); `nodeWriteKey` at lines 543, 563, 592-600; fail-closed guard at lines 590-601; `rotateWriteFromNode` at line 1417; `WriteRevocationCallbacks` at line 97 |
| `packages/sdk-core/src/rotation/index.ts` | barrel re-exports `rotateWriteFromNode` + `WriteRevocationCallbacks` | VERIFIED | Lines 10 and 14 |
| `packages/sdk-core/src/__tests__/rotation/write-body-reseal.test.ts` | write plane preserved after read-rotation; fail-closed case | VERIFIED | Tests assert `ipnsPrivateKey`/`writeChildren` unchanged, generation bumped, fail-closed throw |
| `packages/sdk-core/src/__tests__/rotation/write-revocation.test.ts` | child-first cascade, tombstone-intent, co-writer re-wrap, read-plane invariance | VERIFIED | Test 3 (child-first), Test 7 (read-plane invariant), Test 8 (parent re-point) |
| `tests/sdk-e2e/src/suites/write-chain-rotation.test.ts` | D-04 gate; real round-trip WRITE-02/03/04 | VERIFIED | 431 lines, 43 assertions; PASSED 2/2 against live docker API per orchestrator evidence |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `shared-write.ts` | `packages/core/src/node/seal.ts` | `sealChildWriteKey` (role 0x04) imported at line 37 | WIRED | Used in `buildChildWriteLink` helper at line 167 |
| `packages/sdk-core/src/rotation/engine.ts` | `packages/core/src/node/seal.ts` | `sealChildWriteKey`/`unsealChildWriteKey` | WIRED | Imported (line 34-35); used in write revocation subtree re-point |
| `rotateWriteFromNode` | `generateEd25519Keypair` + `deriveIpnsName` | `@cipherbox/crypto` at lines 39-40 | WIRED | Called per node in `rotateWriteSubtree` at line 1298-1299 |
| `rotateWriteFromNode` | `wrapKey` | `@cipherbox/crypto` at line 38 | WIRED | Called for surviving co-writers at line 1449 |
| `claimInvite` | `claimInviteReadKey` | same file `grant.ts` | WIRED | Called at line 306 |
| `restoreFromBin` | `sealChildReadKey` | `@cipherbox/core` imported at line 23 | WIRED | Called at line 436 with `entry.nodeReadKey` |

### Data-Flow Trace (Level 4)

Not applicable — this phase delivers crypto primitives, rotation drivers, and SDK operations (not page/component rendering pipelines). Dynamic data flows are exercised by unit tests and the D-04 e2e gate.

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| `sealChildWriteKey`/`unsealChildWriteKey` exports on built dist | `grep -c "sealChildWriteKey" packages/core/src/node/index.ts packages/core/src/index.ts` | 1 each (confirmed) | PASS |
| `PLACEHOLDER_WRITE_KEY` absent from engine source | `grep -c "PLACEHOLDER_WRITE_KEY" engine.ts` | 0 (no code references; test file comments only) | PASS |
| `encryptedChildKeys` absent from non-test sdk-core/sdk source | `grep -rn "encryptedChildKeys" packages/sdk-core/src packages/sdk/src --include=*.ts \| grep -v __tests__` | 0 matches | PASS |
| `originalFolderKeyEncrypted` absent from both source files | `grep -rc "originalFolderKeyEncrypted" packages/sdk/src/bin/index.ts packages/core/src/bin/types.ts` | 0 both | PASS |
| `addShareKeysFn(` never invoked in `shared-write.ts` | `grep -c "addShareKeysFn(" shared-write.ts` | 0 | PASS |
| D-04 e2e gate | `pnpm --filter @cipherbox/sdk-e2e test run -- write-chain-rotation` | PASSED 2/2 against live docker API | PASS |
| Core unit tests | 197 crypto, 199 core, 318 sdk-core, 207 sdk (9 web shared-folder hook) | All green (orchestrator evidence) | PASS |
| Full typecheck chain | `pnpm typecheck` (crypto→core→api-client→sdk-core→sdk→web→scripts) | GREEN exit 0 | PASS |

### Probe Execution

No explicit probe scripts declared in phase plans. The D-04 e2e test (`write-chain-rotation.test.ts`) serves as the live verification gate and PASSED per orchestrator evidence.

### Requirements Coverage

| Requirement | Source Plan(s) | Description | Status | Evidence |
|-------------|---------------|-------------|--------|---------|
| WRITE-01 | 65-01, 65-02, 65-03, 65-04, 65-05 | Write-body holds Ed25519 material under separate `writeKey`; read-only holder cannot reach signing material | SATISFIED | `sealChildWriteKey` role 0x04; `unsealNode` without writeKey returns no writeBody (unit test line 161); `SharedWriteContext.writeKey`; `BinEntry.nodeReadKey`; `claimInvite` no fan-out |
| WRITE-02 | 65-06, 65-07 | Write-revocation: full Ed25519 rotation — new keypair + k51 name per node, cascading parent re-points | SATISFIED | `rotateWriteFromNode` mints new keypair/k51/writeKey per node child-first; D-04 e2e PASSED; parent re-point asserted |
| WRITE-03 | 65-04, 65-06, 65-07 | Surviving co-writers re-wrapped; offline co-writer gets explicit "cannot write until re-fetch" error | SATISFIED | `CannotWriteUntilRefetchError` in every write op; `wrapKey` for survivors, `deleteWriteGrantFn` for revoked; D-04 e2e asserts both |
| WRITE-04 | 65-06, 65-07 | Tombstoned name: publish gate rejects (403/410), resolve returns 410, name removed from TEE republish batch | PARTIALLY SATISFIED — deferred | TEE unenroll done (`teeUnenrollFn` per old name, asserted in e2e); publish gate reject + resolve-410 are mock-asserted per D-02 design; live enforcement is Phase 66 SC |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `packages/sdk/src/client.ts` | 205, 216, 1220, 1272, 1318, 1358, 1886 | "not implemented — phase 65 (...)" stub throws | Info | NOT a phase-65 regression — `client.ts` is not in any plan's `files_modified`; these are pre-existing carry-forward stubs. Per orchestrator: "OUT OF SCOPE". Tests tolerate them non-fatally. |
| `apps/web/src/hooks/shared-folder-projection.ts` | 48, 73-78, 102 | `PLACEHOLDER_PUBLISHED_NODE` | Info | Explicitly labeled Phase-68 placeholder; the web shared-write path was already non-functional pre-phase-65. Per orchestrator: "intentional and clearly marked for Phase 68 wiring". |

No TBD/FIXME/XXX debt markers found in any file listed in phase-65 plan `files_modified` entries.

### Human Verification Required

None. All success criteria are verifiable by static analysis + the orchestrator-provided D-04 live gate evidence. No visual/UX/real-time behaviors are in scope for this phase.

### Gaps Summary

No gaps. All four phase goal success criteria are verified by code evidence:

1. SC#1 (WRITE-01): `sealChildWriteKey`/`unsealChildWriteKey` role 0x04 in seal.ts; read-only holder cannot-reach assertion in unit test.
2. SC#2 (WRITE-02 + WRITE-04 partial): `rotateWriteFromNode` full child-first cascade; `teeUnenrollFn` per old name; live publish gate deferred to Phase 66 per D-02 design and matched by Phase 66 SC.
3. SC#3 (WRITE-03): `CannotWriteUntilRefetchError` + co-writer re-wrap/drop tested end-to-end.
4. SC#4 (WRITE-01 + DATA-04 partial): pure re-link restore; `originalFolderKeyEncrypted` deleted; `encryptedChildKeys` eliminated from sdk layer; `claimInvite` single-grant no fan-out.

The one partial item (WRITE-04 live publish gate) is an explicitly designed mock seam (D-02) with Phase 66 as the live cutover — not a gap.

---

_Verified: 2026-06-30_
_Verifier: Claude (gsd-verifier)_
