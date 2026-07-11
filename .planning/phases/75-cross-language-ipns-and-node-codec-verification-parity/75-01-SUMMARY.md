---
phase: 75-cross-language-ipns-and-node-codec-verification-parity
plan: 01
subsystem: testing
tags: [ipns, cbor, ed25519, cross-language-vectors, rfc3339, validity-type]

# Dependency graph
requires: []
provides:
  - "12-case tests/vectors/ipns/verify.json shared cross-language IPNS verify oracle (was 8 cases)"
  - "scripts/gen-ipns-verify-vectors.ts extended with parameterized Validity/ValidityType support in buildCborData"
affects: [75-02, 75-03]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Extend the committed generator script and re-run it to add cases to a shared crypto-signed JSON vector fixture — never hand-edit data/signature_v2 bytes"

key-files:
  created: []
  modified:
    - scripts/gen-ipns-verify-vectors.ts
    - tests/vectors/ipns/verify.json

key-decisions:
  - "buildCborData parameterized with validity/validityType defaults matching prior hardcoded values, preserving byte-identical output for the 8 pre-existing cases"
  - "New case count fixed at 4 (expired-valid-sig, wrong-validity-type, malformed-rfc3339-trailing-component, malformed-rfc3339-impossible-date) per RESOLVED Open Question 2 in 75-RESEARCH.md"

patterns-established:
  - "Shared JSON vector as parity oracle: generator is sole producer of cryptographic vector bytes; consumers (Plans 02 Rust, 03 TS) assert accept/reject agreement against the same file"

requirements-completed:
  - "SC1 (RFC3339 + ValidityType lockstep) — shared-oracle half"
  - "todo:2026-06-24-harden-validity-type-and-vector-expiry-lockstep"
  - "todo:2026-06-24-ts-resolve-strict-rfc3339-validity-parity"

coverage:
  - id: D1
    description: "tests/vectors/ipns/verify.json regenerated to 12 cases; the 4 new cases (expired-valid-sig, wrong-validity-type, malformed-rfc3339-trailing-component, malformed-rfc3339-impossible-date) are real Ed25519-signed and expected_result invalid"
    requirement: "SC1 (RFC3339 + ValidityType lockstep) — shared-oracle half"
    verification:
      - kind: unit
        ref: "npx tsx scripts/gen-ipns-verify-vectors.ts && node -e assertion script from PLAN Task 1 <verify> block"
        status: pass
    human_judgment: false
  - id: D2
    description: "Regenerating a second time reproduces byte-identical data/signature_v2 for the pre-existing 8 cases (idempotency / no-hand-edit guarantee)"
    verification:
      - kind: unit
        ref: "diff of two consecutive generator runs (verified this session, zero diff)"
        status: pass
    human_judgment: false
  - id: D3
    description: "wrong-validity-type case's decoded CBOR embeds ValidityType as integer 1 (not 0); expired case embeds ValidityType 0 with a past Validity"
    verification:
      - kind: unit
        ref: "manual cborg decode check performed this session confirming ValidityType=1 for wrong-validity-type and ValidityType=0/Validity=2020-01-01... for expired-valid-sig"
        status: pass
    human_judgment: false

duration: 3min
completed: 2026-07-11
status: complete
---

# Phase 75 Plan 01: Extend IPNS Verify-Vector Generator Summary

**Extended `scripts/gen-ipns-verify-vectors.ts` with a parameterized `buildCborData` and regenerated `tests/vectors/ipns/verify.json` from 8 to 12 real Ed25519-signed cases, adding the expired/wrong-ValidityType/malformed-RFC3339 oracle both Plan 02 (Rust) and Plan 03 (TS) must reject identically.**

## Performance

- **Duration:** 3 min
- **Started:** 2026-07-11T05:49:00Z
- **Completed:** 2026-07-11T05:52:24Z
- **Tasks:** 1
- **Files modified:** 2

## Accomplishments
- `buildCborData(cid, sequenceNumber, validity?, validityType?)` now accepts optional Validity string and ValidityType overrides (defaults preserve the exact prior behavior for all 8 pre-existing cases)
- Added 4 new real-signed vector cases to `tests/vectors/ipns/verify.json`: `expired-valid-sig` (past Validity, ValidityType 0), `wrong-validity-type` (canonical future Validity, ValidityType 1), `malformed-rfc3339-trailing-component` (extra dash-number date component), `malformed-rfc3339-impossible-date` (Feb 30)
- Verified idempotency: two consecutive generator runs produce byte-identical output across all 12 cases
- Verified the wrong-validity-type case's CBOR decodes to `ValidityType: 1` and the expired case decodes to `ValidityType: 0` with `Validity: 2020-01-01T00:00:00.000000000Z` (acceptance criteria confirmed by direct cborg decode, not inferred)

## Task Commits

Each task was committed atomically:

1. **Task 1: Extend gen-ipns-verify-vectors.ts to emit four new failing cases** - `21b6f00d5` (feat)

## Files Created/Modified
- `scripts/gen-ipns-verify-vectors.ts` - Parameterized `buildCborData` with `validity`/`validityType` args; added 4 new case builders (9-12) with real Ed25519 signing; updated sanity-check vector count/description/result arrays from 8 to 12
- `tests/vectors/ipns/verify.json` - Regenerated from the extended generator; 12 cases total, original 8 byte-identical, 4 new cases real-signed and `expected_result: invalid`

## Decisions Made
- Kept `buildCborData`'s new parameters as trailing optional args with defaults equal to the prior hardcoded values (`2099-01-01T00:00:00.000000000Z`, `ValidityType: 0`) so no existing call site needed changes and byte-identity of the 8 pre-existing cases was guaranteed by construction, not just verified after the fact
- Followed 75-RESEARCH.md's RESOLVED Open Question 2 exactly: 4 new cases, bringing total to 12

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

`tests/vectors/ipns/verify.json` is now the 12-case shared oracle that Plan 02 (`crates/fuse/tests/ipns_verify_vectors.rs`) and Plan 03 (`packages/sdk-core/src/__tests__/ipns.test.ts`) both depend on. Their hard-coded vector-count guards (currently 8) will need updating to 12 as part of those plans — this is the expected, anticipated checkpoint per 75-RESEARCH.md Pitfall 2, not a regression.

---
*Phase: 75-cross-language-ipns-and-node-codec-verification-parity*
*Completed: 2026-07-11*

## Self-Check: PASSED

- FOUND: scripts/gen-ipns-verify-vectors.ts
- FOUND: tests/vectors/ipns/verify.json
- FOUND: .planning/phases/75-cross-language-ipns-and-node-codec-verification-parity/75-01-SUMMARY.md
- FOUND: commit 21b6f00d5
