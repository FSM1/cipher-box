---
phase: 77-crypto-hygiene-and-terminology-canonicalization
plan: 07
subsystem: core
tags: [base64-codec-dedup, node-codec, crypto-hygiene, typescript]

# Dependency graph
requires:
  - phase: 77
    plan: 01
    provides: hoisted bytesToBase64/base64ToBytes canonical codec in @cipherbox/crypto (packages/crypto/src/utils/encoding.ts)
provides:
  - packages/core/src/node/{encode,decode,seal}.ts consuming the single @cipherbox/crypto base64 codec instead of 3 copy-pasted implementations
affects: [core-node-codec, crypto-hygiene-sc2]

# Tech tracking
tech-stack:
  added: []
  patterns: [Thin local wrapper over a shared primitive to preserve a superset signature (decode.ts's expectedLength length-check) rather than duplicating the primitive's body]

key-files:
  created: []
  modified:
    - packages/core/src/node/encode.ts
    - packages/core/src/node/decode.ts
    - packages/core/src/node/seal.ts

key-decisions:
  - "decode.ts kept its local base64ToUint8Array(b64, expectedLength?) function name and superset signature exactly as the plan specified, but its body now delegates to the shared base64ToBytes(b64) from @cipherbox/crypto instead of re-implementing the atob loop, retaining only the decode-specific length assertion"
  - "seal.ts's existing @cipherbox/crypto import (sealAesGcmAad, unsealAesGcmAad, buildNodeAad, CryptoError) was extended in place with bytesToBase64 and base64ToBytes rather than adding a second import statement"

requirements-completed: [SC2]

coverage:
  - id: D1
    description: "The 3 base64 duplicates in packages/core/src/node/{encode,decode,seal}.ts are removed and consume the hoisted @cipherbox/crypto base64 codec"
    requirement: "SC2"
    verification:
      - kind: other
        ref: "grep -rn 'String.fromCharCode(...chunk)|const CHUNK_SIZE' packages/core/src/node/encode.ts packages/core/src/node/seal.ts -> 0 matches; grep -rc 'base64ToBytes|bytesToBase64' packages/core/src/node/encode.ts packages/core/src/node/seal.ts -> 4 and 12 respectively"
        status: pass
    human_judgment: false
  - id: D2
    description: "sealNode/unsealNode golden-vector round-trips still pass byte-for-byte (no behavior change)"
    requirement: "SC2"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/core test -> node-codec-vectors.test.ts (20 tests) + node-codec.test.ts (15 tests) both green; full suite 10 files / 200 tests passed"
        status: pass
    human_judgment: false
  - id: D3
    description: "decode.ts keeps its decode-specific expectedLength length-check as a thin local wrapper over the shared bytes-only helper"
    requirement: "SC2"
    verification:
      - kind: other
        ref: "grep -c 'expectedLength' packages/core/src/node/decode.ts -> 5 (function signature, JSDoc, param check, throw message, thrown-length reference)"
        status: pass
      - kind: unit
        ref: "pnpm --filter @cipherbox/core build && pnpm --filter @cipherbox/core typecheck -> both exit 0"
        status: pass
    human_judgment: false

# Metrics
duration: 10min
completed: 2026-07-11
status: complete
---

# Phase 77 Plan 07: Node-Codec Base64 Dedup Summary

**Consolidated the 3 copy-pasted `uint8ArrayToBase64`/`base64ToUint8Array` implementations in `packages/core/src/node/{encode,decode,seal}.ts` onto the single hoisted `bytesToBase64`/`base64ToBytes` codec in `@cipherbox/crypto` (Plan 77-01), preserving decode.ts's `expectedLength` length-check as a thin wrapper.**

## Performance

- **Duration:** ~10 min
- **Tasks:** 1 completed
- **Files modified:** 3

## Accomplishments

- `encode.ts`: deleted the local `uint8ArrayToBase64` chunk-encoder; added `bytesToBase64` to a new `@cipherbox/crypto` import and rewired all 4 call sites (`content.fileKey`, each version's `fileKey`, `wb.ipnsPrivateKey`)
- `seal.ts`: deleted both local `uint8ArrayToBase64`/`base64ToUint8Array` functions; extended the existing `@cipherbox/crypto` import (which already pulled in `sealAesGcmAad`, `unsealAesGcmAad`, `buildNodeAad`, `CryptoError`) with `bytesToBase64`/`base64ToBytes` and rewired all 10 call sites across `sealNode`/`unsealNode`/`sealChildReadKey`/`unsealChildReadKey`/`sealChildWriteKey`/`unsealChildWriteKey`/`sealContent`/`unsealContent`
- `decode.ts`: replaced the local `atob` loop inside `base64ToUint8Array(b64, expectedLength?)` with a call to the shared `base64ToBytes(b64)`, keeping the function's name, superset signature, and decode-specific length assertion intact (T-77-07b mitigation)
- Rebuilt `@cipherbox/core` and reran `node-codec-vectors.test.ts` + `node-codec.test.ts` — both green, proving byte-for-byte parity (T-77-07a mitigation: the shared codec is a verbatim copy of the original implementation)
- No `packages/core`-local shared base64 file was created — each file imports directly from `@cipherbox/crypto`, as specified

## Task Commits

Each task was committed atomically:

1. **Task 1: Replace the 3 node-codec base64 duplicates with the shared crypto import** - `cfc444a1c` (refactor)

## Files Created/Modified

- `packages/core/src/node/encode.ts` - Removed local `uint8ArrayToBase64`; imports and uses `bytesToBase64` from `@cipherbox/crypto`
- `packages/core/src/node/seal.ts` - Removed local `uint8ArrayToBase64`/`base64ToUint8Array`; imports and uses `bytesToBase64`/`base64ToBytes` from `@cipherbox/crypto` (joined the existing crypto import)
- `packages/core/src/node/decode.ts` - `base64ToUint8Array(b64, expectedLength?)` body now delegates to shared `base64ToBytes`, retaining only the `expectedLength` assertion

## Decisions Made

- decode.ts's wrapper name/signature (`base64ToUint8Array(b64, expectedLength?)`) preserved unchanged per plan instruction — only the internal `atob` loop was replaced by a call to the shared `base64ToBytes`
- seal.ts's base64 imports were added to its existing single `@cipherbox/crypto` import statement rather than introducing a second import line, matching the plan's `read_first` note that "base64 import joins that line"

## Deviations from Plan

None — plan executed exactly as written. No auto-fixes were needed; the refactor was mechanical and the golden-vector tests passed on the first build/test run.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `@cipherbox/core` builds clean (`tsup` + `tsc -p tsconfig.build.json`) and typechecks clean (`tsc --noEmit`)
- Full `@cipherbox/core` test suite green: 10 files / 200 tests, including the `node-codec-vectors.test.ts` golden-vector parity gate and `node-codec.test.ts`
- No local base64 codec body remains in `encode.ts`/`seal.ts`; `decode.ts` retains its `expectedLength` length-check wrapper
- Ready for the next phase-77 plan (77-08)

---
*Phase: 77-crypto-hygiene-and-terminology-canonicalization*
*Completed: 2026-07-11*

## Self-Check: PASSED

- FOUND: packages/core/src/node/encode.ts
- FOUND: packages/core/src/node/decode.ts
- FOUND: packages/core/src/node/seal.ts
- FOUND: .planning/phases/77-crypto-hygiene-and-terminology-canonicalization/77-07-SUMMARY.md
- FOUND commit: cfc444a1c (refactor(77-07): consolidate node-codec base64 onto shared crypto codec)
- FOUND commit: aee08cb7b (docs(77-07): add plan summary for node-codec base64 dedup)
