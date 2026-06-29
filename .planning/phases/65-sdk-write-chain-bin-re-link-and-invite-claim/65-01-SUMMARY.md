---
phase: 65-sdk-write-chain-bin-re-link-and-invite-claim
plan: "01"
subsystem: packages/core
tags: [crypto, node-codec, write-chain, role-0x04, tdd]
dependency_graph:
  requires: []
  provides: [sealChildWriteKey, unsealChildWriteKey]
  affects: [packages/core/src/node/seal.ts, packages/core/src/node/index.ts, packages/core/src/index.ts]
tech_stack:
  added: []
  patterns: [AES-256-GCM AAD-bound key seal, role-byte isolation, terminal-owner D-09]
key_files:
  created:
    - packages/core/src/__tests__/seal-write-chain.test.ts
  modified:
    - packages/core/src/node/seal.ts
    - packages/core/src/node/index.ts
    - packages/core/src/index.ts
decisions:
  - Role byte 0x04 frozen per ADR 0003 for child-writekey (verified by cross-role rejection tests)
  - Verbatim copy of sealChildReadKey/unsealChildReadKey per D-05 — no new primitives, no new imports
  - D-09 terminal-owner: neither sealChildWriteKey nor unsealChildWriteKey zeros caller buffers
metrics:
  duration: "~10 minutes"
  completed: "2026-06-30"
  tasks_completed: 2
  tasks_total: 2
  files_created: 1
  files_modified: 3
status: complete
---

# Phase 65 Plan 01: Role-0x04 Child Write-Key Seal Primitives Summary

AES-256-GCM key-wrap pair for the write chain — `sealChildWriteKey` and `unsealChildWriteKey` with frozen role byte `0x04` — added to `packages/core` and exported from both barrels, unblocking Plans 04, 05, 06.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | RED — role-0x04 write-chain seal KAT and round-trip test | b82c23748 | packages/core/src/__tests__/seal-write-chain.test.ts |
| 2 | GREEN — implement sealChildWriteKey / unsealChildWriteKey and export them | 6954798c7 | packages/core/src/node/seal.ts, packages/core/src/node/index.ts, packages/core/src/index.ts |

## What Was Built

Two new exported async functions in `packages/core/src/node/seal.ts`:

- `sealChildWriteKey(childWriteKey, parentWriteKey, childId, childKind, childGeneration)` — seals a child node's write key under the parent write key using AES-256-GCM with AAD role `0x04`; returns base64.
- `unsealChildWriteKey(sealedBase64, parentWriteKey, childId, childKind, childGeneration)` — inverse; reconstructs AAD identically and throws on any mismatch.

Both are re-exported from `packages/core/src/node/index.ts` and `packages/core/src/index.ts`. The dist was rebuilt to expose the symbols to downstream consumers.

## TDD Gate Compliance

- RED gate: `test(65-01)` commit `b82c23748` — 9 tests failing with `sealChildWriteKey is not a function`
- GREEN gate: `feat(65-01)` commit `6954798c7` — all 9 tests passing

## Verification Results

- `pnpm --filter @cipherbox/core exec vitest run seal-write-chain` — 9/9 passed (round-trip, cross-role rejection, AAD-mismatch ×4, terminal-owner ×2)
- `pnpm --filter @cipherbox/core build` — ESM + CJS dist built successfully
- `grep "sealChildWriteKey" packages/core/dist/index.js` — 6 occurrences; symbols present in CJS dist

## Deviations from Plan

None — plan executed exactly as written.

The `sealChildWriteKey` / `unsealChildWriteKey` functions are a verbatim copy of the role-`0x02` pair with exactly the three substitutions specified: parameter names, role byte (`0x02` → `0x04`), and inline comment. No new imports were added. D-09 terminal-owner rule preserved.

## Known Stubs

None — no stub values in the created or modified files.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced. The two new functions operate entirely in-memory, composing existing `@cipherbox/crypto` primitives. The threat model items T-65-01 through T-65-04 are all mitigated by the test suite.

## Self-Check: PASSED

- FOUND: packages/core/src/__tests__/seal-write-chain.test.ts
- FOUND: sealChildWriteKey in packages/core/src/node/seal.ts
- FOUND: sealChildWriteKey in packages/core/src/node/index.ts
- FOUND: sealChildWriteKey in packages/core/src/index.ts
- FOUND: RED commit b82c23748
- FOUND: GREEN commit 6954798c7
