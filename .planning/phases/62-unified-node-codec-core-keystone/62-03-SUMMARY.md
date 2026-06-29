---
phase: 62-unified-node-codec-core-keystone
plan: "03"
subsystem: vault
tags: [vault, blob-v3, ecies, two-key, hard-cut]
status: complete

dependency_graph:
  requires: []
  provides:
    - serializeVaultBlobV3
    - deserializeVaultBlobV3
    - BLOB_V3_VERSION
    - VaultInit.rootReadKey
    - VaultInit.rootWriteKey
    - EncryptedVaultKeys.encryptedRootReadKey
    - EncryptedVaultKeys.encryptedRootWriteKey
    - tests/vectors/vault-v3-blob.json
  affects:
    - packages/core/src/vault/blob.ts
    - packages/core/src/vault/types.ts
    - packages/core/src/vault/init.ts
    - packages/core/src/vault/index.ts
    - packages/core/src/index.ts

tech_stack:
  added: []
  patterns:
    - "v3 blob layout: 0x03 | u16_BE(readLen) | ECIES(rootReadKey) | u16_BE(writeLen) | ECIES(rootWriteKey)"
    - "Two independent generateFileKey() outputs for rootReadKey and rootWriteKey (T-62-08)"
    - "Cross-language fixture JSON loaded in test (not inline constant) for Phase-69 Rust portability"

key_files:
  created:
    - tests/vectors/vault-v3-blob.json
  modified:
    - packages/core/src/vault/blob.ts
    - packages/core/src/vault/types.ts
    - packages/core/src/vault/init.ts
    - packages/core/src/vault/index.ts
    - packages/core/src/index.ts
    - packages/core/src/__tests__/vault-blob-vectors.test.ts
    - packages/core/src/__tests__/vault.test.ts
  deleted:
    - packages/core/src/__tests__/vault-blob.test.ts

decisions:
  - "Deleted vault-blob.test.ts (v2-only) in Task 1 GREEN because vault-blob-vectors.test.ts fully covers v3 — no duplicate coverage needed"
  - "rootReadKey and rootWriteKey are independently generated via generateFileKey(); neither is derived from the other or from the Ed25519 keypair (RESEARCH Open Q2 / T-62-08)"
  - "vault-blob-vectors.test.ts loads expected_blob_hex from JSON fixture, not inline constant, so Phase-69 Rust cross_language.rs can assert the same bytes (D-04)"

metrics:
  duration: "~16 minutes"
  completed: "2026-06-28"
  tasks_completed: 3
  tasks_total: 3
  files_modified: 9
---

# Phase 62 Plan 03: Vault v3 Hard-Cut Summary

One-liner: v3-only vault blob carrying two ECIES-wrapped keys (rootReadKey + rootWriteKey) replacing the single-key v2 envelope, with cross-language frozen fixture.

## What Was Built

### Task 1: Vault blob v3 — RED/GREEN

**RED:** Rewrote `vault-blob-vectors.test.ts` to import `serializeVaultBlobV3`/`deserializeVaultBlobV3`/`BLOB_V3_VERSION` and load the two-key hex fixture from `tests/vectors/vault-v3-blob.json`. Tests failed (v3 functions did not exist).

**GREEN:** Replaced `vault/blob.ts` with v3-only implementation:

- `BLOB_V3_VERSION = 0x03`
- `serializeVaultBlobV3(encryptedRootReadKey, encryptedRootWriteKey)`: layout `0x03 | u16_BE(readLen) | read | u16_BE(writeLen) | write`; guards for empty keys and keys over 0xffff
- `deserializeVaultBlobV3(blob)`: validates version byte, minimum length (5), readLen > 0, write header and write body presence; returns subarray views
- Deleted `detectBlobVersion`, `serializeVaultBlobV2`, `deserializeVaultBlobV2`, `BLOB_V2_VERSION`, and the v1 JSON path

Committed `tests/vectors/vault-v3-blob.json`: frozen cross-language fixture with `read_key_hex` (0xaa + 0x00..0x7f, 129 bytes), `write_key_hex` (0xbb + 0x00..0x7f, 129 bytes), `expected_blob_hex` (deterministic 263-byte envelope).

### Task 2: Two-key vault types + init — RED/GREEN

**RED:** Updated `vault.test.ts` to use `rootReadKey`/`rootWriteKey` field names, asserts they differ (T-62-08), checks for absence of `rootFolderKey`/`encryptedRootFolderKey`. Tests failed (types/init still used old names).

**GREEN:** Updated `vault/types.ts` and `vault/init.ts`:

- `VaultInit`: `rootFolderKey` → `rootReadKey`; added `rootWriteKey: Uint8Array`
- `EncryptedVaultKeys`: `encryptedRootFolderKey` → `encryptedRootReadKey`; added `encryptedRootWriteKey: Uint8Array`
- `initializeVault`: generates two independent random keys via `generateFileKey()`
- `encryptVaultKeys`: wraps both root keys plus IPNS key
- `decryptVaultKeys`: unwraps both root keys; does not zero caller-owned buffers (D-09)

### Task 3: Barrel updates (execute)

- `vault/index.ts`: replaced v2 re-exports with `serializeVaultBlobV3`/`deserializeVaultBlobV3`/`BLOB_V3_VERSION`
- `packages/core/src/index.ts`: swapped vault block from v2 to v3 symbol names (only vault block touched; folder/file blocks unchanged per plan guardrail)
- TypeScript typecheck (`tsc --noEmit -p tsconfig.build.json`) clean
- Full core suite: 208 tests, all passing

## Deviations from Plan

### Auto-addressed Issues

**1. [Rule 3 - Blocking] vault-blob.test.ts deleted in Task 1 GREEN (not Task 3)**

- **Found during:** Task 1 GREEN — `pnpm test -- vault-blob` filter matched both `vault-blob-vectors.test.ts` and `vault-blob.test.ts`; the latter imported the deleted v2 functions and blocked the Task 1 acceptance criterion
- **Issue:** Task 1's acceptance criterion requires `pnpm --filter @cipherbox/core test -- vault-blob` to exit 0. `vault-blob.test.ts` importing deleted v2 functions caused 14 test failures in that filter scope
- **Fix:** Deleted `vault-blob.test.ts` during Task 1 GREEN (plan authorized deletion in Task 3 "if vault-blob-vectors.test.ts covers v3 fully" — it does). Task 3 verified the absence
- **Files modified:** `packages/core/src/__tests__/vault-blob.test.ts` (deleted)
- **Commits:** `1da5ce12b`

## Verification Results

```
pnpm --filter @cipherbox/core test -- vault-blob  → 10 files, 202 tests PASS
pnpm --filter @cipherbox/core test -- vault       → 10 files, 208 tests PASS
pnpm --filter @cipherbox/core test               → 10 files, 208 tests PASS
pnpm --filter @cipherbox/core exec tsc --noEmit -p tsconfig.build.json → clean

grep -c "BLOB_V2_VERSION|serializeVaultBlobV2|deserializeVaultBlobV2|detectBlobVersion" blob.ts → 0
grep -c "encryptedRootFolderKey|rootFolderKey" packages/core/src/vault/* → 0
grep -c "vault-v3-blob.json" vault-blob-vectors.test.ts → 2
grep -c "export function serializeVaultBlobV3|..." blob.ts → 3
```

## Known Stubs

None — all vault v3 functions are fully implemented with real byte-manipulation (no TODO/placeholder).

## Commits

| Hash | Message |
|------|---------|
| `182065bc9` | test(62-03): add failing v3 vault blob vector test and fixture |
| `1da5ce12b` | feat(62-03): v3-only vault blob serialize/deserialize (hard-cut D-05) |
| `3af684e7a` | test(62-03): add failing two-key vault type + init tests |
| `48508d2d9` | feat(62-03): two-key vault types and init (remove encryptedRootFolderKey) |
| `cd029e8d9` | feat(62-03): update vault barrel exports to v3 symbols |

## Self-Check: PASSED
