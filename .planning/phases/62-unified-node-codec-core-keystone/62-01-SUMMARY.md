---
phase: 62-unified-node-codec-core-keystone
plan: "01"
subsystem: packages/core
tags: [node-codec, types, tdd, encode, decode, validation]
status: complete

dependency_graph:
  requires: []
  provides:
    - packages/core/src/node/types.ts (Node, SealedChildRef, PublishedNode, NodeContent, VersionEntry, WriteChildRef, NodeWriteBody)
    - packages/core/src/node/encode.ts (encodeReadBody, encodeWriteBody, serializeContentForWire)
    - packages/core/src/node/decode.ts (validateNode, decodeReadBody, decodeWriteBody, deserializeContentFromWire)
    - packages/core/src/__tests__/node-codec.test.ts (15 tests: NODE-01..NODE-04)
  affects:
    - packages/core/src/node/seal.ts (Plan 02 — seals the encoded bytes)
    - tests/vectors/node-codec.json (Plan 02 — body-byte golden vector)

tech_stack:
  added: []
  patterns:
    - JSON codec with fixed field order (encodeReadBody) for byte-level determinism (D-04)
    - uint8ArrayToBase64 chunked helper (SECURITY MEDIUM-08) for large Uint8Array safety
    - bigint versionFloor serialized as decimal string (JSON-safe round-trip)
    - fail-closed validateNode mirroring validateFolderMetadata CryptoError pattern
    - generation range guard verbatim copy from buildNodeAad (D-08 sync guarantee)

key_files:
  created:
    - packages/core/src/node/types.ts
    - packages/core/src/node/encode.ts
    - packages/core/src/node/decode.ts
    - packages/core/src/__tests__/node-codec.test.ts
  modified: []

decisions:
  - "versionFloor serialized as decimal string (not number) on wire — bigint is not JSON.stringify-safe; BigInt(String(raw.versionFloor)) is the inverse"
  - "generation guard uses verbatim predicate from buildNodeAad: Number.isInteger && >=0 && <=0xffffffff — ensures D-08 predicates stay in sync by construction"
  - "encodeReadBody field order is fixed (schema, kind, id, generation, kind-specific, createdAt, modifiedAt) to make Plan-02 body-byte golden vector deterministic (D-04)"
  - "writeKeySealed lives only in WriteChildRef/NodeWriteBody, never in SealedChildRef (NODE-03, design §2.2)"

metrics:
  duration: "10 minutes"
  completed: "2026-06-28"
  tasks_completed: 3
  files_created: 4
---

# Phase 62 Plan 01: Node Type Model and Body Codec Summary

Unified Node type model and JSON encode/decode codec in `packages/core/src/node/`. The codec is
pure in-memory JSON (no AEAD) — it produces the plaintext body bytes that Plan 02 seals with
AES-256-GCM + AAD binding.

## What Was Built

### Task 1: node/types.ts (types only)

Seven exported types:

- `NodeKind = 'folder' | 'file' | 'root'` and `EncryptionMode = 'GCM' | 'CTR'` — string-literal
  unions per project convention (no TS enums)
- `VersionEntry` — file version with `fileKey: Uint8Array` (raw 32B AES key inside sealed body,
  not an ECIES hex string — semantic type change from legacy model, D-07/NODE-02)
- `NodeContent` — file content descriptor with `fileKey: Uint8Array` and `encryptionMode: EncryptionMode`
- `SealedChildRef` — exactly `{name, ipnsName, generation, versionFloor, readKeySealed}`. No write
  field (NODE-03, design §2.2/§2.6). `versionFloor` is `bigint` (IPNS sequenceNumber convention)
- `WriteChildRef = { childId: string; writeKeySealed: string }` — write-chain link in write-body only
- `NodeWriteBody = { ipnsPrivateKey: Uint8Array; writeChildren: WriteChildRef[] }` — nested per §2.3
- `Node` — discriminated union on `kind`; `generation: number` in `[0, 2^32-1]` (D-08)
- `PublishedNode` — plaintext envelope with `readSealed`/`writeSealed` base64 fields (NODE-04)

### Task 2: node-codec.test.ts (RED)

Failing test suite (15 cases) for NODE-01..NODE-04:

- Tests 1-3 (NODE-01): folder/root/file round-trip via `encodeReadBody`/`decodeReadBody`
- Tests 4-8 (NODE-02): `fileKey instanceof Uint8Array && length 32`; GCM+CTR modes preserved;
  wire bytes expose fileKey as string (base64), not raw object map
- Test 9 (NODE-03): `Object.keys(child).sort()` exactly matches the 5-field read-only set
- Tests 10-15 (NODE-04): generation = `0x100000000`, `-1`, `1.5` throw; `0` and `0xffffffff` pass

### Task 3: node/encode.ts + node/decode.ts (GREEN)

`encode.ts`:

- `serializeContentForWire(content)`: `fileKey` and all `VersionEntry.fileKey` → base64 via chunked
  `uint8ArrayToBase64` helper (SECURITY MEDIUM-08); `versionFloor` unchanged (caller is types, not
  encode, for SealedChildRef serialization)
- `encodeReadBody(node)`: fixed field order `{ schema, kind, id, generation, children|content, createdAt, modifiedAt }` → `TextEncoder(JSON.stringify(...))`; `SealedChildRef.versionFloor` bigint → decimal string
- `encodeWriteBody(node)`: `ipnsPrivateKey` Uint8Array → base64; throws CryptoError if no writeBody

`decode.ts`:

- `deserializeContentFromWire(raw)`: validates and restores `fileKey`/version fileKeys from base64 →
  32-byte Uint8Array (asserts length)
- `validateNode(data)`: fail-closed CryptoError on schema/kind/id/generation; generation guard is
  verbatim copy of `buildNodeAad` predicate (D-08 sync guarantee)
- `decodeReadBody(bytes)`: `JSON.parse(TextDecoder(bytes))` → `validateNode` → reconstructed Node
- `decodeWriteBody(bytes)`: restores `ipnsPrivateKey` Uint8Array

## Verification Results

- `pnpm --filter @cipherbox/core test -- node-codec`: 15/15 GREEN
- `pnpm --filter @cipherbox/core test`: 211/211 GREEN (no regressions in folder/file/vault/bin/registry/ipns suites)
- `pnpm --filter @cipherbox/core exec tsc --noEmit -p tsconfig.build.json`: clean

## Deviations from Plan

None — plan executed exactly as written.

## Known Stubs

None — this plan adds net-new codec files only; no stubs or placeholders in the produced artifacts.

## Threat Flags

No new trust-boundary surface introduced. The encode/decode functions are pure in-memory transforms
with no network, storage, or auth paths. All STRIDE mitigations from the plan threat register are
implemented:

- T-62-04: `content.fileKey`/`VersionEntry.fileKey` typed `Uint8Array`; base64 on wire; tests
  assert `instanceof Uint8Array && length 32`
- T-62-02: `validateNode` rejects generation outside `[0, 2^32-1]` fail-closed (D-08)
- T-62-03: codec never logs or leaks raw key material; only base64 appears inside encoded body bytes
- T-62-SC: no new packages added

## Self-Check: PASSED

- `packages/core/src/node/types.ts` exists
- `packages/core/src/node/encode.ts` exists
- `packages/core/src/node/decode.ts` exists
- `packages/core/src/__tests__/node-codec.test.ts` exists
- Commits: `1985d015` (types), `e9ea0fd2` (RED tests), `f760e7f6` (GREEN encode/decode)
