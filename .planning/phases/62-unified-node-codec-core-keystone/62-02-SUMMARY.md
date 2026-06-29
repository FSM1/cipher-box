---
phase: 62-unified-node-codec-core-keystone
plan: "02"
subsystem: node-codec
tags: [node-seal, aes-gcm-aad, tdd, test-vectors, cross-language]
dependency_graph:
  requires: ["62-01"]
  provides: ["62-04", "62-05", "62-06", "62-07", "62-08"]
  affects: ["packages/core", "tests/vectors"]
tech_stack:
  added: []
  patterns:
    - "AAD-bound AES-256-GCM seal/unseal composing Phase-61 primitive (sealAesGcmAad)"
    - "TDD RED/GREEN: test-first with placeholder imports, then implement"
    - "Fixed-IV encryptAesGcmAad for frozen FULL-SEAL cross-language vectors"
    - "Chunked base64 encoding (CHUNK_SIZE=32768, SECURITY MEDIUM-08)"
key_files:
  created:
    - packages/core/src/node/seal.ts
    - packages/core/src/node/index.ts
    - packages/core/src/__tests__/node-codec-vectors.test.ts
    - tests/vectors/node-codec.json
  modified: []
decisions:
  - "Role byte 0x01 used for BOTH readSealed and writeSealed bodies (same role, different key — ADR 0003 §2.5)"
  - "writeSealed omitted from PublishedNode when node.writeBody is absent (read-only access paths)"
  - "Fixture stores file node fileKey as file_key_hex strings (JSON cannot carry Uint8Array); nodeFromFixture() helper converts hex to Uint8Array in tests"
  - "D-09 enforced: never zero caller-supplied readKey/writeKey/childReadKey in seal.ts — caller is terminal owner"
  - "T-62-03 enforced: no console.log of key material anywhere in seal.ts"
  - "node/index.ts is re-export barrel only — zero logic (vitest excludes src/**/index.ts from coverage)"
metrics:
  duration: "~75 minutes (across two sessions)"
  completed: "2026-06-28"
  tasks_completed: 2
  tasks_total: 2
  files_created: 4
  files_modified: 0
  tests_added: 20
  tests_total: 228
status: complete
---

# Phase 62 Plan 02: Node AAD-Bound Seal/Unseal Summary

AAD-bound AES-256-GCM node seal/unseal layer (`seal.ts`) composing Phase-61 primitives, with frozen PRIMARY LOCK body-byte and FULL-SEAL cross-language vectors.

## What Was Built

### Task 1 (TDD): node/seal.ts + frozen vectors

RED commit (`90b9bb2bc`): wrote 20 failing tests across 5 describe blocks in
`node-codec-vectors.test.ts`. Tests import `sealNode`, `unsealNode`, `sealChildReadKey`,
`unsealChildReadKey`, `sealContent`, `unsealContent` from the missing `../node/seal` module,
causing import failure (correct RED behavior).

GREEN commit (`ffc617c8e`): implemented `packages/core/src/node/seal.ts` and populated
`tests/vectors/node-codec.json` with real frozen values.

`seal.ts` exports:

- `sealNode(node, readKey, writeKey)` — seals readBody (role 0x01) under readKey; seals writeBody (role 0x01) under writeKey when writeBody is present; returns `PublishedNode`
- `unsealNode(published, readKey, writeKey?)` — rebuilds AADs identically; unseals read-body always, write-body if `writeSealed` + `writeKey` both present
- `sealChildReadKey(childReadKey, parentReadKey, childId, childKind, childGeneration)` — role 0x02; seals child readKey under parent readKey (read chain)
- `unsealChildReadKey(sealedBase64, parentReadKey, childId, childKind, childGeneration)` — inverse
- `sealContent(content, fileNodeReadKey, nodeId, generation)` — role 0x03; serializes NodeContent via `serializeContentForWire` then seals under the file node's own readKey
- `unsealContent(sealedBase64, fileNodeReadKey, nodeId, generation)` — inverse

Internal helpers: `kindByte(kind)` (folder→0x01, file→0x02, root→0x03, fail-closed D-03),
`uint8ArrayToBase64` (CHUNK_SIZE 32768, SECURITY MEDIUM-08), `base64ToUint8Array`.

`tests/vectors/node-codec.json` contains:

- 4 PRIMARY LOCK body vectors: folder, file/GCM, file/CTR, root — `expected_read_body_hex` is UTF-8 hex of `JSON.stringify(encodeReadBody(node))`, IV-independent
- 1 FULL-SEAL vector: folder with `read_key="01...01"`, `write_key="02...02"`, `fixed_iv="000102...0b"` — `expected_published_node.readSealed` and `.writeSealed` are base64 of `fixedIv ‖ encryptAesGcmAad(bodyBytes, key, fixedIv, aad)`, deterministic, Phase-69 Rust twin ready

Vector computation method: ran `encodeReadBody`/`encryptAesGcmAad` inside a temporary
vitest test (`compute-vectors.test.ts`, deleted after use) because tsx from repo root could
not resolve `@cipherbox/crypto` (bundler moduleResolution incompatible with Node.js runtime).

### Task 2 (execute): node/index.ts barrel

Commit `49cdcdbdb`: created `packages/core/src/node/index.ts` as a pure re-export barrel.
Zero logic (vitest excludes `src/**/index.ts` from coverage). Re-exports:

- `encodeReadBody, encodeWriteBody, serializeContentForWire` from `./encode`
- `decodeReadBody, decodeWriteBody, deserializeContentFromWire, validateNode` from `./decode`
- `sealNode, unsealNode, sealChildReadKey, unsealChildReadKey, sealContent, unsealContent` from `./seal`
- Types: `Node, NodeKind, EncryptionMode, SealedChildRef, WriteChildRef, NodeWriteBody, NodeContent, VersionEntry, PublishedNode` from `./types`

Noted: top-level `packages/core/src/index.ts` NOT wired — that is Plan 05's barrel cutover.

## Test Results

228/228 tests passing. 20 new tests across 5 describe blocks:

- PRIMARY LOCK (4): body-byte hex assertions — IV-independent, freeze `encodeReadBody` output
- FULL-SEAL LOCK (2): deterministic `encryptAesGcmAad(fixedIv)` assertions for cross-language Phase-69 Rust twin
- Round-Trip (5): `unsealNode(sealNode(node))` deep-equals node for folder/file-GCM/file-CTR/root/file-with-write-body
- AAD Transplant Rejection (4): wrong generation, wrong childId, wrong role — each fails with CryptoError
- Content Self-Seal (5): `unsealContent(sealContent(content))` round-trip, wrong-generation rejection, child-readkey/content role isolation

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] TS1160 backtick in JSDoc comment**

- Found during: Task 2
- Issue: `node/index.ts` JSDoc used backtick chars (`` `=>` ``, `` `src/**/index.ts` ``) inside a block comment; TypeScript compiler emitted TS1160 "Unterminated template literal" at EOF
- Fix: replaced backtick chars with plain text equivalents in the comment
- Files modified: `packages/core/src/node/index.ts`
- Commit: included in `49cdcdbdb`

**2. [Rule 3 - Blocking] tsx cannot resolve @cipherbox/crypto from repo root**

- Found during: Task 1 vector computation phase
- Issue: `tsx .tmp-gen-vectors.mts` from repo root fails — `Cannot find package '@cipherbox/crypto'` (bundler moduleResolution in tsconfig.base.json incompatible with Node.js runtime resolution)
- Fix: ran `encodeReadBody`/`encryptAesGcmAad` inside a temporary vitest test that uses the correct resolver; extracted hex via `console.log` output; deleted the temp test file after use
- Files modified: none (temp file created and deleted)

## TDD Gate Compliance

- RED gate: `test(62-02): add failing node-codec-vectors suite (RED)` — commit `90b9bb2bc`
- GREEN gate: `feat(62-02): implement node/seal.ts and freeze node-codec.json vectors (GREEN)` — commit `ffc617c8e`
- REFACTOR gate: not needed — implementation was clean on first pass

## Known Stubs

None — all vectors contain real computed values; all seal/unseal functions fully implemented.

## Threat Flags

| Flag | File | Description |
|------|------|-------------|
| threat_flag: key-material-in-memory | packages/core/src/node/seal.ts | sealNode/sealChildReadKey receive raw key Uint8Arrays — intentional, D-09 prohibits zeroing. Caller (SDK layer, Phase 63+) is the terminal owner and must zero after all seal operations complete |

No net-new attack surface: seal.ts is a pure crypto library (no I/O, no network, no DOM access). The AAD binding prevents cross-node transplant attacks. The IPNS private key inside writeBody is encrypted under writeKey before going to wire (encodeWriteBody → base64).

## Self-Check: PASSED

Files exist:

- FOUND: packages/core/src/node/seal.ts
- FOUND: packages/core/src/node/index.ts
- FOUND: tests/vectors/node-codec.json
- FOUND: packages/core/src/__tests__/node-codec-vectors.test.ts

Commits exist:

- FOUND: 90b9bb2bc (RED)
- FOUND: ffc617c8e (GREEN)
- FOUND: 49cdcdbdb (barrel)
