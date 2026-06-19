---
phase: 51-crypto-signature-secret-leak-hardening
plan: "04"
subsystem: sdk-core
tags: [zeroization, ipns, vault, folder, tdd, security, s3-d05]
dependency_graph:
  requires: []
  provides:
    - T-47-01 fill(0) on createAndPublishIpnsRecord ipnsPrivateKey
    - T-47-01 fill(0) on publishVaultKeyBlob vaultKeyKeypair.privateKey
    - Documented caller-owns-key skip for updateFolderMetadataAndPublish
    - S3 zeroization enforcement guard tests (A/B/C)
    - S2 resolveIpnsRecord regression guard (D)
  affects:
    - packages/sdk-core/src/ipns/index.ts
    - packages/sdk-core/src/vault/index.ts
    - packages/sdk-core/src/folder/index.ts
tech_stack:
  added: []
  patterns:
    - T-47-01 caller-owns-key try/finally fill(0) convention (sdk-core)
key_files:
  created: []
  modified:
    - packages/sdk-core/src/ipns/index.ts
    - packages/sdk-core/src/vault/index.ts
    - packages/sdk-core/src/folder/index.ts
    - packages/sdk-core/src/__tests__/ipns.test.ts
    - packages/sdk-core/src/__tests__/vault.test.ts
    - packages/sdk-core/src/__tests__/folder.test.ts
decisions:
  - updateFolderMetadataAndPublish SKIP zeroing: all client.ts call sites pass live session keys from folderTree state that persist and are reused across the full session lifetime
  - publishVaultKeyBlob owns its own try/finally even though createAndPublishIpnsRecord also zeroes the passed buffer; buffer-owning boundary is vault/index.ts
metrics:
  duration: 12min
  completed: "2026-06-19"
  tasks: 3
  files: 6
---

# Phase 51 Plan 04: SDK-Core Key Zeroization Summary

T-47-01 caller-owns-key convention (try/finally fill(0)) applied to createAndPublishIpnsRecord and publishVaultKeyBlob; updateFolderMetadataAndPublish documented as deliberate skip with matching guard test; S3 enforcement guard tests and S2 regression guard added to ipns/vault/folder test suites.

## What Was Built

### Task 1: RED - Failing zeroization guard tests

Added failing tests to `ipns.test.ts` and `vault.test.ts`:

- **Test A** (ipns success path): allocates `key.fill(5)`, passes to `createAndPublishIpnsRecord`, asserts all-zero after return
- **Test B** (ipns throw path): mocks publish to reject, asserts key still all-zero (finally path)
- **Test C** (vault): mocks `deriveVaultKeyIpnsKeypair` with a non-zero `privateKey` buffer, asserts all-zero after `publishVaultKeyBlob` returns
- **Test D** (S2 regression): `resolveIpnsRecord` with `verifyEd25519` mocked false → asserts throws "IPNS signature verification failed" — passes immediately (S2 already correct in sdk-core)

RED result: 3 failing (A/B/C), 1 passing (D).

### Task 2: GREEN - fill(0) implementation

`packages/sdk-core/src/ipns/index.ts`:

- Wrapped `createAndPublishIpnsRecord` body inside `try { ... } finally { params.ipnsPrivateKey.fill(0); }` within the `withPerf` callback
- Comment: "T-47-01 / D-05: caller-owns-key convention — zero the private key on all exit paths"

`packages/sdk-core/src/vault/index.ts`:

- Wrapped `publishVaultKeyBlob` publish logic (after `deriveVaultKeyIpnsKeypair`) in `try { ... } finally { vaultKeyKeypair.privateKey.fill(0); }`
- This function is the terminal owner of the derived keypair; the finally runs on both success and throw paths

All tests A/B/C turned GREEN; Test D continues passing.

### Task 3: Folder path audit + decision + guard test

**client.ts audit result:**

All 9 call sites of `updateFolderMetadataAndPublish` pass keys from live `folderTree` state:

- `folder.ipnsKeypair.privateKey` and `folder.folderKey` are stored in `folderTree` as session-lifetime keys
- The same folder object is reused across sequential operations (renameItem, deleteItem, uploadFile, moveItem, etc.)
- `moveItem` uses `dest.ipnsKeypair.privateKey` and `source.ipnsKeypair.privateKey` — distinct objects from distinct folders, but both are live session keys
- No call site zeros these keys after the call; all continue using them for subsequent operations
- `createFolder` (line 716) passes a freshly-created key but then returns it to the caller at line 752 — the caller retains ownership

**Decision: SKIP** — `updateFolderMetadataAndPublish` must NOT zero because callers retain ownership.

`packages/sdk-core/src/folder/index.ts`:

- Added 18-line documented comment block before `updateFolderMetadataAndPublish` explaining the SKIP decision, referencing the client.ts audit (A2) and contrasting with `updateFileMetadata` which DOES zero (per-use key, terminal consumer)

`packages/sdk-core/src/__tests__/folder.test.ts`:

- Added "SKIP guard" test: passes `ipnsKey.fill(0x77)` and `folderKey.fill(0x88)`, snapshots initial values, calls `updateFolderMetadataAndPublish`, asserts keys are UNCHANGED — documents deliberate non-zeroing and prevents accidental future fill(0)

## Test Results

Full `@cipherbox/sdk-core` suite: **209 tests, 18 test files, all passing**

TDD gate compliance:

- RED commit: `f242a08da` — `test(...)` — Tests A/B/C failing, Test D passing
- GREEN commit: `f6319af9f` — `feat(...)` — All tests passing
- No REFACTOR commit needed (code is clean)

## Deviations from Plan

None — plan executed exactly as written. The folder path audit (A2) resolved to SKIP as anticipated by the plan's open-question framing; the implementation followed the documented-skip branch.

## Known Stubs

None.

## Threat Flags

None — no new network endpoints, auth paths, file access patterns, or schema changes introduced. All changes are in-process memory safety (fill(0) in finally blocks) and test additions.

## Self-Check: PASSED

- `packages/sdk-core/src/ipns/index.ts` contains `params.ipnsPrivateKey.fill(0)` inside a `finally` block ✓
- `packages/sdk-core/src/vault/index.ts` contains `vaultKeyKeypair.privateKey.fill(0)` inside a `finally` block ✓
- `packages/sdk-core/src/folder/index.ts` contains documented caller-owns-key skip comment ✓
- `__tests__/ipns.test.ts` contains S3 zeroization guard tests A/B and S2 regression guard D ✓
- `__tests__/vault.test.ts` contains S3 zeroization guard test C ✓
- `__tests__/folder.test.ts` contains SKIP guard test asserting unchanged buffer ✓
- Commits: `f242a08da` (test/RED), `f6319af9f` (feat/GREEN), `df58bac56` (feat/folder) ✓
