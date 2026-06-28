---
phase: 61-aad-bound-seal-primitive-and-cross-language-kat
plan: "01"
subsystem: crypto
tags: [crypto, aad, aes-gcm, kat, cross-language, typescript]
requires: []
provides: [buildNodeAad, uuidToBytes, INVALID_AAD_INPUT, node-aad.json aad_vectors]
affects: [packages/crypto, tests/vectors/crypto, scripts/check-vector-parity.sh]
tech-stack:
  added: []
  patterns: [TDD red-green, frozen domain constant, fail-closed validation, hex-field UUID parse]
key-files:
  created:
    - packages/crypto/src/__tests__/build-node-aad.test.ts
    - tests/vectors/crypto/node-aad.json
  modified:
    - packages/crypto/src/utils/encoding.ts
    - packages/crypto/src/aes/seal.ts
    - packages/crypto/src/types.ts
    - packages/crypto/src/aes/index.ts
    - packages/crypto/src/utils/index.ts
    - packages/crypto/src/index.ts
    - scripts/check-vector-parity.sh
decisions:
  - "uuidToBytes delegates to hexToBytes after stripping hyphens — never TextEncoder (D-04)"
  - "buildNodeAad domain constant computed once at module load via TextEncoder, not inside function"
  - "KAT guards aad_vectors.length === 4 and sorted role set === [1,2,3,4] before iterating (prevents vacuous pass)"
  - "node-aad.json expected_aad values derived from TS implementation output and committed as frozen ground truth"
metrics:
  duration: "~18 minutes"
  completed: "2026-06-28"
  tasks_completed: 2
  files_changed: 9
status: complete
---

# Phase 61 Plan 01: TS AAD Builder and Frozen KAT Vectors Summary

TypeScript AAD builder (`buildNodeAad`), UUID-to-bytes helper (`uuidToBytes`), and the frozen cross-language KAT vector file (`node-aad.json`) covering all four role bytes — first half of the C-01 merge gate.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| RED | Failing tests for buildNodeAad and uuidToBytes | 2b08bf70e | types.ts, build-node-aad.test.ts |
| GREEN | uuidToBytes + buildNodeAad implementation + barrels | 904a4fc7c | encoding.ts, seal.ts, aes/index.ts, utils/index.ts, index.ts |
| 2 | Freeze node-aad.json + KAT assertions + parity registration | 70a4d7599 | node-aad.json, build-node-aad.test.ts, check-vector-parity.sh |

## What Was Built

### `uuidToBytes` — `packages/crypto/src/utils/encoding.ts`

Strips hyphens from the input UUID string, validates the result is exactly 32 hex chars, then delegates to the existing `hexToBytes`. Produces 16 raw RFC-4122 field-order bytes. Never uses `TextEncoder` (D-04 — that would produce 36 UTF-8 bytes, the primary silent-mismatch landmine).

### `buildNodeAad` — `packages/crypto/src/aes/seal.ts`

Assembles the 45-byte AAD per the frozen D-00 encoding:

```
"cipherbox/node-seal/v1" (22 bytes, UTF-8) ‖ 0x00 (1) ‖ nodeId (16 raw UUID bytes) ‖ kind (1) ‖ generation BE u32 (4) ‖ role (1)
```

Domain prefix computed once at module load (`TextEncoder` on the literal string). Generation encoded via `DataView.setUint32(0, generation, false)` (big-endian). Fail-closed (D-03): throws `CryptoError('...', 'INVALID_AAD_INPUT')` for kind outside {0x01,0x02,0x03}, role outside {0x01–0x04}, non-integer or out-of-range generation, and malformed UUID.

### `'INVALID_AAD_INPUT'` error code — `packages/crypto/src/types.ts`

Added to the `CryptoErrorCode` union.

### `tests/vectors/crypto/node-aad.json`

Four `aad_vectors` entries sharing node ID `550e8400-e29b-41d4-a716-446655440000`, kind=folder, generation=42, covering roles 1–4. Values derived from TS implementation and committed as the frozen ground truth. Non-zero generation (42) ensures a little-endian regression in either language is caught.

Example (role=body):
```
expected_aad: 636970686572626f782f6e6f64652d7365616c2f763100550e8400e29b41d4a716446655440000010000002a01
```

### TS KAT — `packages/crypto/src/__tests__/build-node-aad.test.ts`

Two guards before iterating:
1. `expect(aad_vectors.length).toBe(4)` — prevents vacuous pass if vectors are dropped
2. `expect(sortedRoles).toEqual([1, 2, 3, 4])` — pins the four-role invariant

### Parity script — `scripts/check-vector-parity.sh`

`tests/vectors/crypto/node-aad.json` added to `EXPECTED_VECTORS`.

## Verification Results

- `pnpm --filter @cipherbox/crypto test`: **178 tests passed** (10 test files)
- `bash scripts/check-vector-parity.sh`: **exits 0**, prints OK for all 10 vector files including node-aad.json

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Incorrect expected_aad hex in initial node-aad.json**

- **Found during:** Task 2 test run
- **Issue:** Hand-computed generation encoding had an extra leading "0" ("00000002a" instead of "0000002a"), making expected strings 91 chars instead of 90
- **Fix:** Replaced all four expected_aad values with strings derived directly from the TS implementation (`bytesToHex(buildNodeAad(...))` output observed in test failure)
- **Files modified:** tests/vectors/crypto/node-aad.json
- **Commit:** 70a4d7599

**2. [Rule 1 - Bug] Premature KAT test in RED commit caused extra failure**

- **Found during:** Task 1 GREEN phase
- **Issue:** The KAT test referencing node-aad.json was included in the RED commit; it caused 1 extra failure in the GREEN phase since node-aad.json did not exist yet
- **Fix:** Removed the KAT test from the file for the Task 1 GREEN commit; re-added it in Task 2 alongside the vector file creation
- **Files modified:** build-node-aad.test.ts (two edits within same task flow)

## Known Stubs

None. All symbols are fully implemented and asserted by passing tests.

## Threat Flags

None. All threat mitigations from the plan threat model are implemented:

- T-61-01 (UUID UTF-8 vs raw): `uuidToBytes` uses hex-field parse; KAT pins exact bytes
- T-61-02 (wrong-length AAD): fail-closed validation; 45-byte assertion in tests
- T-61-03 (generation LE regression): non-zero generation=42 in KAT; DataView BE encoding
- T-61-04 (coverage exclusion): primitives in named files (seal.ts, encoding.ts); barrels only re-export

## Self-Check: PASSED

All created files confirmed present on disk. All three task commits confirmed in git log.
