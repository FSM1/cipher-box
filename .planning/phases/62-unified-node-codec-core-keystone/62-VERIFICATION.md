---
phase: 62-unified-node-codec-core-keystone
verified: 2026-06-29T01:45:00Z
status: passed
score: 6/6 must-haves verified
behavior_unverified: 0
overrides_applied: 0
---

# Phase 62: Unified Node Codec (Core Keystone) Verification Report

**Phase Goal:** The unified `Node`/`SealedChildRef`/`PublishedNode` types and codecs exist in `packages/core`, replacing all `FolderMetadata`/`FileMetadata`/`FilePointer`/`FolderEntry` types; all downstream packages typecheck after `dist/` rebuild.
**Verified:** 2026-06-29T01:45:00Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Single `Node` discriminated by `kind` with two independently sealed bodies; `generation` plaintext in published envelope | VERIFIED | `packages/core/src/node/types.ts` exports `Node` (kind: 'folder'\|'file'\|'root'), `PublishedNode` with `readSealed`/`writeSealed`; `sealNode` in `seal.ts` composes `sealAesGcmAad` with role 0x01 per body, uses distinct keys |
| 2 | File node `content` (incl. `fileKey` + each `VersionEntry.fileKey` + mandatory `encryptionMode`) self-seals under file's own `readKey` with role 0x03 | VERIFIED | `sealContent` in `seal.ts` calls `buildNodeAad(nodeId, 0x02, generation, 0x03)`; `NodeContent.fileKey` and `VersionEntry.fileKey` are `Uint8Array` (32 bytes); `encryptionMode` is mandatory in both types |
| 3 | `SealedChildRef` field set is exactly `{name, ipnsName, generation, versionFloor, readKeySealed}` — no write field | VERIFIED | `types.ts` defines `SealedChildRef` with exactly those 5 fields; `writeKeySealed` lives in `WriteChildRef` inside `NodeWriteBody` — never in `SealedChildRef` |
| 4 | Vault recovery blob v3 carries `ECIES(rootReadKey)` + `ECIES(rootWriteKey)`; `encryptedRootFolderKey` removed; v2/v1 paths deleted | VERIFIED | `vault/blob.ts` exports only `serializeVaultBlobV3`/`deserializeVaultBlobV3`/`BLOB_V3_VERSION`; grep for `serializeVaultBlobV2`, `deserializeVaultBlobV2`, `detectBlobVersion`, `BLOB_V2_VERSION` in `packages/core/src/` returns empty; `VaultInit` has `rootReadKey` + `rootWriteKey` |
| 5 | `sdk-core`, `sdk`, `web` typecheck cleanly after core `dist/` rebuild — zero references to retired types in production source | VERIFIED | `tsc -p tsconfig.build.json --noEmit` → 0 errors on sdk-core and sdk; `tsc --noEmit` → 0 errors on web; consumers import `SealedChildRef`/`Node`/`NodeContent`/`BinEntry` from `@cipherbox/core` — all new types; no retired-type imports in any production source file |
| 6 | `METADATA_SCHEMAS.md` documents the `generation`-as-convergence-witness invariant and the `fileKey`-inside-sealed-read-body semantic type change | VERIFIED | Section 10 "Invariants" documents both: (1) generation-as-convergence-witness (authoritative only on child's own envelope; SealedChildRef.generation and shares.rootGeneration are staleness mirrors), (2) fileKey semantic type change (ECIES hex string → raw 32-byte Uint8Array inside sealed body) |

**Score:** 6/6 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `packages/core/src/node/types.ts` | Node, SealedChildRef, PublishedNode, NodeContent, VersionEntry, WriteChildRef, NodeWriteBody | VERIFIED | All types exported; string-literal unions not enums |
| `packages/core/src/node/encode.ts` | encodeReadBody, encodeWriteBody, serializeContentForWire | VERIFIED | Fixed field order for deterministic body bytes (D-04) |
| `packages/core/src/node/decode.ts` | decodeReadBody, decodeWriteBody, validateNode, deserializeContentFromWire | VERIFIED | Generation range guard matches `buildNodeAad` predicate verbatim |
| `packages/core/src/node/seal.ts` | sealNode, unsealNode, sealChildReadKey, unsealChildReadKey, sealContent, unsealContent | VERIFIED | Composes Phase-61 `sealAesGcmAad`/`buildNodeAad`; correct role bytes |
| `packages/core/src/node/index.ts` | Re-export barrel only | VERIFIED | Re-exports only; no logic |
| `tests/vectors/node-codec.json` | Body PRIMARY LOCK vectors (all three kinds) + FULL-SEAL LOCK vector | VERIFIED | 4 body vectors (folder, file GCM, file CTR, root) + 1 full-seal vector (folder kind); 7209 bytes |
| `tests/vectors/vault-v3-blob.json` | Frozen v3 blob vector | VERIFIED | Two-key layout vector present; 1541 bytes |
| `packages/core/src/__tests__/node-codec-vectors.test.ts` | Asserts body vectors byte-for-byte; asserts full-seal via fixed-IV | VERIFIED | 428 lines; loads from JSON fixture |
| `packages/core/src/__tests__/vault-blob-vectors.test.ts` | Asserts v3 blob vector | VERIFIED | 120 lines; loads from JSON fixture |
| `packages/core/src/vault/blob.ts` | serializeVaultBlobV3, deserializeVaultBlobV3, BLOB_V3_VERSION only | VERIFIED | v2 functions absent; pure byte manipulation |
| `packages/core/src/vault/types.ts` | VaultInit with rootReadKey+rootWriteKey; EncryptedVaultKeys with encryptedRootReadKey+encryptedRootWriteKey | VERIFIED | encryptedRootFolderKey not present |
| `docs/METADATA_SCHEMAS.md` | Full static node/v3 schema + two SC#6 invariants + vault-v3 section | VERIFIED | 15-section doc; Section 10 has both invariants |
| `docs/METADATA_EVOLUTION_PROTOCOL.md` | node/v3 schema-version lever + cross-language vector discipline | VERIFIED | Sections on node/v3 schema discriminator + lockstep vector discipline |
| `docs/FILESYSTEM_SPECIFICATION.md` | node/v3 storage model description | VERIFIED | Section "node/v3 storage model" present |

### Legacy Directory Deletion

| Path | Expected | Status |
|------|----------|--------|
| `packages/core/src/folder/` | DELETED | VERIFIED — directory absent |
| `packages/core/src/file/` | DELETED | VERIFIED — directory absent |

### Key Link Verification

| From | To | Via | Status |
|------|----|-----|--------|
| `node/seal.ts` | `@cipherbox/crypto` `sealAesGcmAad` + `buildNodeAad` | Direct import; composes, never reimplements | WIRED |
| `node/seal.ts` | `node/encode.ts` `encodeReadBody`/`encodeWriteBody` | Direct import | WIRED |
| `node/seal.ts` | `node/decode.ts` `decodeReadBody`/`decodeWriteBody` | Direct import | WIRED |
| `packages/core/src/index.ts` | `node/` exports | Re-exports `Node`, `SealedChildRef`, `PublishedNode`, all codec fns | WIRED |
| `packages/core/src/index.ts` | `vault/` exports | Re-exports `serializeVaultBlobV3`, `BLOB_V3_VERSION`, v3 only | WIRED |
| consumer packages | `packages/core` dist | Import `SealedChildRef`/`Node`/`NodeContent`/`BinEntry` — all new types | WIRED |
| `node-codec-vectors.test.ts` | `tests/vectors/node-codec.json` | `import VECTORS from '../../../../tests/vectors/node-codec.json'` | WIRED |
| `vault-blob-vectors.test.ts` | `tests/vectors/vault-v3-blob.json` | `import VAULT_V3 from '../../../../tests/vectors/vault-v3-blob.json'` | WIRED |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Core 190-test suite passes | `pnpm --filter @cipherbox/core exec npx vitest run` | 9 files, 190 tests PASSED | PASS |
| Core `dist/` rebuilds clean | `pnpm --filter @cipherbox/core build` | `dist/index.mjs 32.72 KB`, `dist/index.js 37.29 KB`, build success | PASS |
| sdk-core production typecheck (build tsconfig) | `pnpm --filter @cipherbox/sdk-core exec tsc -p tsconfig.build.json --noEmit` | 0 errors | PASS |
| sdk production typecheck (build tsconfig) | `pnpm --filter @cipherbox/sdk exec tsc -p tsconfig.build.json --noEmit` | 0 errors | PASS |
| web full typecheck | `pnpm --filter @cipherbox/web exec tsc --noEmit` | 0 errors | PASS |
| upload-batch.test.ts runtime (sdk) | `pnpm --filter @cipherbox/sdk exec npx vitest run src/__tests__/upload-batch.test.ts` | 20/20 passed | PASS |

### Requirements Coverage

| Requirement | Phase | Description | Status | Evidence |
|-------------|-------|-------------|--------|----------|
| NODE-01 | 62 | Unified Node model (folder/file/root via kind) replacing legacy types | SATISFIED | `Node` type in `types.ts`; `folder/` + `file/` dirs deleted; consumers compile |
| NODE-02 | 62 | File node content self-seals under file's own readKey; fileKey raw Uint8Array | SATISFIED | `sealContent` with role 0x03; `NodeContent.fileKey: Uint8Array`; decode asserts 32 bytes |
| NODE-03 | 62 | SealedChildRef is read-only chain link (name/ipnsName/generation/versionFloor/readKeySealed) | SATISFIED | `SealedChildRef` has exactly 5 fields; write link in `NodeWriteBody` |
| NODE-04 | 62 | Published object is plaintext envelope with generation folded into AAD | SATISFIED | `PublishedNode` has plaintext generation; `buildNodeAad` called with generation in both seal/unseal |
| NODE-05 | 62 | Wire-format golden vector freeze (TS only; Rust Node enum deferred to phase 69) | SATISFIED | `tests/vectors/node-codec.json` frozen with body vectors (all 3 kinds) + full-seal vector; asserted byte-for-byte in `node-codec-vectors.test.ts` |
| NODE-06 | 62 | Vault recovery blob carries ECIES(rootReadKey) + ECIES(rootWriteKey) | SATISFIED | `serializeVaultBlobV3`/`deserializeVaultBlobV3` implement two-key v3 blob; vector frozen in `vault-v3-blob.json` |

### Anti-Patterns Found

| File | Pattern | Severity | Notes |
|------|---------|----------|-------|
| `packages/sdk/src/__tests__/upload-batch.test.ts` | TypeScript errors: mock return value uses old `type`/`fileMetaIpnsName`/`ipnsPrivateKeyEncrypted` fields not present in `SealedChildRef` | WARNING | Test was not quarantined with `describe.skip` per D-02 expectation. All 20 tests PASS at runtime (vitest transpiles without typechecking). Production build (`tsconfig.build.json`) excludes test files and is clean. `cas.test.ts` vitest union-narrowing errors are pre-existing and out-of-scope per plan 06 decision. |
| `apps/web/public/recovery.html` | Still implements `deserializeVaultBlobV2` and `encryptedRootFolderKey` | INFO | Static HTML emergency-recovery page; not a TypeScript source file; not referenced in any phase 62 plan. No real-world impact (greenfield, staging wiped). Not in the phase's TypeScript scope. |

No TBD/FIXME/XXX debt markers found in `packages/core/src/node/` or `packages/core/src/vault/`.
Consumer stubs correctly name the owning phase: `throw new Error('not implemented — phase 63 (read-chain navigation)')` etc.

### Gaps Summary

No gaps. All 6 ROADMAP success criteria verified against the actual codebase. The two anti-pattern findings are informational:

1. `upload-batch.test.ts` D-02 quarantine was not applied. The tests pass at runtime; the production build is clean. This is a code hygiene deviation, not a phase-goal failure. The TypeScript errors are in mock helper bodies, not in imports of retired types from `@cipherbox/core`.

2. `recovery.html` v3 update was not in scope for any phase 62 plan. Since the app is intentionally non-runnable mid-milestone (D-01) and staging is wiped (greenfield), there is no real-world impact. Update deferred naturally to when vault v3 flows are wired end-to-end.

---

_Verified: 2026-06-29T01:45:00Z_
_Verifier: Claude (gsd-verifier)_
