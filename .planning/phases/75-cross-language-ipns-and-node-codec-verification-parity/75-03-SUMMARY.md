---
phase: 75-cross-language-ipns-and-node-codec-verification-parity
plan: 03
subsystem: crypto
tags: [ipns, rfc3339, cbor, sdk-core, ed25519, verification]

# Dependency graph
requires:
  - phase: 75-cross-language-ipns-and-node-codec-verification-parity (Plan 01)
    provides: tests/vectors/ipns/verify.json shared 12-case oracle (4 new invalid cases)
  - phase: 75-cross-language-ipns-and-node-codec-verification-parity (Plan 02)
    provides: Rust bind_verified ValidityType==0 gate + parse_rfc3339_to_unix_secs (source of truth)
provides:
  - "parseRfc3339ToUnixSecs in packages/sdk-core/src/ipns/index.ts — strict RFC3339 parser ported branch-for-branch from Rust"
  - "ValidityType == 0 fail-closed gate in resolveIpnsRecord"
  - "TS-side SC1 closure: resolveIpnsRecord now rejects the same 12-case verify.json fixture as the Rust verifier"
affects: [phase-76, ipns-verification, cross-language-parity]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Manual branch-for-branch port of a Rust security-critical parser to TS instead of adding a date-library dependency"
    - "Fail-closed CBOR field gate (ValidityType) applied before treating an adjacent field (Validity) as authoritative"

key-files:
  created: []
  modified:
    - packages/sdk-core/src/ipns/index.ts
    - packages/sdk-core/src/__tests__/ipns.test.ts

key-decisions:
  - "Ported the Rust parser manually (no date-library dependency) to guarantee byte-for-byte branch parity with crates/api-client/src/ipns.rs, matching the plan's explicit no-new-dependency constraint"
  - "Exported parseRfc3339ToUnixSecs from ipns/index.ts so it can be unit-tested directly (mirroring the Rust module's own #[cfg(test)] parser tests), in addition to driving the malformed cases through resolveIpnsRecord's public verdict"

patterns-established:
  - "When porting a Rust security parser to TS, mirror the branch structure 1:1 (same rejection order, same leap-year/day-in-month logic, same Hinnant civil_from_days days-since-epoch computation) rather than reimplementing with a different algorithm — makes future divergence audits a line-by-line diff instead of a behavioral re-derivation"

requirements-completed:
  - "SC1 (strict RFC3339 Validity parse + ValidityType==0 binding, TS side)"
  - "todo:2026-06-24-ts-resolve-strict-rfc3339-validity-parity"
  - "todo:2026-06-24-harden-validity-type-and-vector-expiry-lockstep"

coverage:
  - id: D1
    description: "parseRfc3339ToUnixSecs rejects every malformed-timestamp case the Rust parser rejects (trailing date/time components, impossible calendar dates including leap-year edge cases, non-digit fractional seconds, missing Z) and accepts canonical timestamps"
    requirement: "SC1 (strict RFC3339 Validity parse + ValidityType==0 binding, TS side)"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/ipns.test.ts#parseRfc3339ToUnixSecs (Phase 75 SC1)"
        status: pass
    human_judgment: false
  - id: D2
    description: "resolveIpnsRecord fail-closes when cborFields['ValidityType'] is absent or non-zero, even with a canonical future Validity timestamp"
    requirement: "SC1 (strict RFC3339 Validity parse + ValidityType==0 binding, TS side)"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/ipns.test.ts#D-05/D-07: strict throw-path (Plan 60-03) D-07-f, D-07-g"
        status: pass
    human_judgment: false
  - id: D3
    description: "resolveIpnsRecord rejects the same 4 new invalid vectors (expired-valid-sig, wrong-validity-type, malformed-rfc3339-trailing-component, malformed-rfc3339-impossible-date) that the Rust verifier rejects, driven against the shared 12-case tests/vectors/ipns/verify.json fixture"
    requirement: "SC1 (strict RFC3339 Validity parse + ValidityType==0 binding, TS side)"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/ipns.test.ts#D-11/D-12 cross-language IPNS verify vectors (12-case count guard + 4 new per-vector tests)"
        status: pass
    human_judgment: false

duration: 15min
completed: 2026-07-11
status: complete
---

# Phase 75 Plan 03: TS RFC3339 Strict Parser + ValidityType Gate Summary

**Ported the Rust strict RFC3339 parser to TypeScript and added a ValidityType==0 fail-closed gate to resolveIpnsRecord, closing the TS half of cross-language IPNS verification parity (SC1).**

## Performance

- **Duration:** 15 min
- **Started:** 2026-07-11T08:39:41+02:00 (previous plan's completion commit)
- **Completed:** 2026-07-11T08:46:47+02:00
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- `parseRfc3339ToUnixSecs(s: string): number | null` in `packages/sdk-core/src/ipns/index.ts` — a manual, strict RFC3339 parser ported branch-for-branch from `crates/api-client/src/ipns.rs::parse_rfc3339_to_unix_secs`, including the Hinnant `civil_from_days` days-since-epoch computation, leap-year-aware day-of-month validation, and rejection of trailing date/time components, non-digit fractional seconds, and missing-`Z` timestamps
- Replaced `new Date(validityStr).getTime()` in `resolveIpnsRecord` with `parseRfc3339ToUnixSecs`, preserving the existing 5-minute clock-skew buffer and expiry comparison
- Added a fail-closed `cborFields['ValidityType'] === 0` gate in `resolveIpnsRecord`, applied before the Validity timestamp is treated as an expiry — mirrors Rust's `bind_verified` gate exactly
- Bumped the shared-vector count guard in `ipns.test.ts` from 8 to 12 and added per-vector tests for the 4 new invalid fixture cases (`expired-valid-sig`, `wrong-validity-type`, `malformed-rfc3339-trailing-component`, `malformed-rfc3339-impossible-date`)
- `pnpm --filter @cipherbox/sdk-core test -- ipns` is green (382/394 tests pass, 12 pre-existing skips) and `tsc --noEmit` is clean

## Task Commits

Each task was committed atomically (RED → GREEN TDD):

1. **Task 1: Add strict RFC3339 + ValidityType unit and vector cases (RED)** - `8748a2dd2` (test)
2. **Task 2: Implement parseRfc3339ToUnixSecs + ValidityType==0 gate (GREEN)** - `58924f548` (feat)

**Plan metadata:** (this commit, following)

## Files Created/Modified
- `packages/sdk-core/src/ipns/index.ts` - Added `parseRfc3339ToUnixSecs` (exported) and the `ValidityType == 0` fail-closed gate in `resolveIpnsRecord`; removed `new Date(validityStr).getTime()`
- `packages/sdk-core/src/__tests__/ipns.test.ts` - Bumped `toHaveLength(8)` → `toHaveLength(12)`; added 4 new per-vector tests, a `parseRfc3339ToUnixSecs` unit-test describe block, and 2 ValidityType absent/non-zero throw-path tests

## Decisions Made
- Ported the parser manually rather than adding a date library, per the plan's explicit constraint ("Do not add a date-library dependency") and to guarantee exact branch parity with the audited Rust implementation.
- Exported `parseRfc3339ToUnixSecs` from `ipns/index.ts` so the malformed-timestamp cases could be unit-tested directly (mirroring the Rust module's own `#[cfg(test)]` parser tests), in addition to driving them end-to-end through `resolveIpnsRecord`'s public verdict against the real fixture CBOR bytes.

## Deviations from Plan

None - plan executed exactly as written. One incidental note: the `malformed-rfc3339-trailing-component` vector test happened to already pass against the pre-Task-2 loose `new Date()` parser (JS's native `Date` constructor rejects that particular malformed string too), so it was not RED at Task 1 — the other 3 new vector tests, all 7 `parseRfc3339ToUnixSecs` unit tests, and both new ValidityType throw-path tests were RED as expected. This does not affect coverage: the assertion is correct and continues to hold post-Task-2.

## Issues Encountered
None.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- SC1 is now fully met cross-language: Rust (Plan 02) and TS (this plan) reject the identical set of fixture cases in `tests/vectors/ipns/verify.json`.
- No blockers for subsequent plans in Phase 75.

---
*Phase: 75-cross-language-ipns-and-node-codec-verification-parity*
*Completed: 2026-07-11*

## Self-Check: PASSED

- FOUND: commit 8748a2dd2 (test RED)
- FOUND: commit 58924f548 (feat GREEN)
- FOUND: packages/sdk-core/src/ipns/index.ts
- FOUND: packages/sdk-core/src/__tests__/ipns.test.ts
