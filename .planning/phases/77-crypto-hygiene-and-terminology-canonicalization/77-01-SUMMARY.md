---
phase: 77-crypto-hygiene-and-terminology-canonicalization
plan: 01
subsystem: crypto
tags: [base64, encoding, dedup, tdd]

# Dependency graph
requires: []
provides:
  - "bytesToBase64/base64ToBytes canonical base64 codec exported from @cipherbox/crypto"
  - "encoding.test.ts golden-vector parity oracle for downstream base64 dedup"
affects: [77-07, 77-08, 77-09]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Hoisted utility pattern: copy chunked-encode implementation verbatim into @cipherbox/crypto, re-export from utils/index.ts and top-level index.ts alongside existing hex helpers"

key-files:
  created:
    - packages/crypto/src/__tests__/encoding.test.ts
  modified:
    - packages/crypto/src/utils/encoding.ts
    - packages/crypto/src/utils/index.ts
    - packages/crypto/src/index.ts

key-decisions:
  - "Copied the CHUNK_SIZE = 32768 chunked-btoa loop verbatim from packages/core/src/node/encode.ts per RESEARCH Pitfall 2 / MEDIUM-08 — no rewrite, byte-identical output guaranteed"

patterns-established:
  - "Golden-vector known-vector pair ((bytes, base64String) hardcoded pair) as the canonical parity oracle for any future base64 dedup step"

requirements-completed: [SC2]

coverage:
  - id: D1
    description: "@cipherbox/crypto exports one canonical base64 codec pair (bytesToBase64 / base64ToBytes)"
    requirement: "SC2"
    verification:
      - kind: unit
        ref: "packages/crypto/src/__tests__/encoding.test.ts#Base64 Codec — Output Types"
        status: pass
      - kind: other
        ref: "grep -n \"base64ToBytes\" packages/crypto/src/index.ts"
        status: pass
    human_judgment: false
  - id: D2
    description: "The base64 codec round-trips arbitrary byte arrays (including >32768 bytes and empty) byte-for-byte"
    requirement: "SC2"
    verification:
      - kind: unit
        ref: "packages/crypto/src/__tests__/encoding.test.ts#Base64 Codec — Round-Trip"
        status: pass
      - kind: unit
        ref: "packages/crypto/src/__tests__/encoding.test.ts#Base64 Codec — Known Vector (canonical parity oracle)"
        status: pass
    human_judgment: false

duration: 15min
completed: 2026-07-11
status: complete
---

# Phase 77 Plan 01: Hoist Canonical Base64 Codec Summary

**Hoisted a single canonical base64 codec (`bytesToBase64`/`base64ToBytes`) into `@cipherbox/crypto`, copied verbatim from the chunked-`btoa` implementation in `packages/core/src/node/encode.ts`, backed by a golden-vector round-trip test suite.**

## Performance

- **Duration:** ~15 min
- **Completed:** 2026-07-11T08:08:39Z
- **Tasks:** 2 (TDD RED → GREEN)
- **Files modified:** 4 (1 created, 3 modified)

## Accomplishments
- Added `bytesToBase64`/`base64ToBytes` to `packages/crypto/src/utils/encoding.ts`, alongside the existing `hexToBytes`/`bytesToHex` helpers
- Copied the chunked-`btoa` encode loop (`CHUNK_SIZE = 32768`) verbatim from `packages/core/src/node/encode.ts` per RESEARCH Pitfall 2 / threat T-77-01a — no rewrite, output is byte-identical to every existing copy
- Re-exported both functions from `packages/crypto/src/utils/index.ts` and the top-level `packages/crypto/src/index.ts` in the same block as the hex helpers, so Wave 2 consumers (Plans 77-07/08/09) can import directly from `@cipherbox/crypto`
- New `packages/crypto/src/__tests__/encoding.test.ts` golden-vector suite: round-trip cases (empty, 1-byte, 40000-byte crossing the chunk boundary, fixed pattern) + a hardcoded known-vector `(bytes, base64String)` pair as the parity oracle for downstream dedup

## Task Commits

Each task was committed atomically:

1. **Task 1: Golden-vector test for base64 round-trip (RED)** - `466016dd7` (test)
2. **Task 2: Add + export base64 codec, make test green (GREEN)** - `799479b48` (feat)

**Plan metadata:** pending (docs: complete plan)

_TDD plan: RED (test) → GREEN (feat), no refactor needed._

## Files Created/Modified
- `packages/crypto/src/__tests__/encoding.test.ts` - New golden-vector round-trip + known-vector suite for the base64 codec
- `packages/crypto/src/utils/encoding.ts` - Added `bytesToBase64`/`base64ToBytes` next to existing hex helpers
- `packages/crypto/src/utils/index.ts` - Re-export barrel updated to include the new base64 helpers
- `packages/crypto/src/index.ts` - Top-level package re-export updated to include the new base64 helpers

## Decisions Made
- Copied the `CHUNK_SIZE = 32768` chunked-`btoa` loop verbatim from `packages/core/src/node/encode.ts` rather than rewriting it, per RESEARCH Pitfall 2 and threat T-77-01a — this guarantees byte-identical output vs. every existing duplicate before any consumer is switched over in Wave 2

## Deviations from Plan

None — plan executed exactly as written. RED confirmed with 8 failing tests ("is not a function" errors) before Task 2; GREEN confirmed with all 205 crypto package tests passing (8 new + 197 existing) after Task 2; build and typecheck both pass.

## Issues Encountered
None.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- `bytesToBase64`/`base64ToBytes` are now importable from `@cipherbox/crypto` root entry, unblocking Plans 77-07, 77-08, 77-09 (Wave 2 base64 dedup consumers in `packages/core` and `packages/sdk-core`)
- `encoding.test.ts` is the canonical parity oracle those plans should extend/reference when swapping their local base64 duplicates for this shared implementation
- No blockers

---
*Phase: 77-crypto-hygiene-and-terminology-canonicalization*
*Completed: 2026-07-11*

## Self-Check: PASSED

All created/modified files and all task commit hashes verified present on disk and in git log.
