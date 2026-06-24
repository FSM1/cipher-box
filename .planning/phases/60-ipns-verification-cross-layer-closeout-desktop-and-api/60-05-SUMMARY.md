---
phase: 60-ipns-verification-cross-layer-closeout-desktop-and-api
plan: 05
subsystem: api
tags: [ipns, nestjs, jest, tdd, security]

requires:
  - phase: 60-03
    provides: strict TS SDK resolve path (fail-closed, strict equality, D-05/D-07) that the API must match

provides:
  - D-03 strict first-publish gate in ipns.service.ts (embeddedSeq !== 1n; rejects 0n)
  - D-06 parseCachedRecord returns null for null-signedRecord rows
  - D-06 CID-mismatch discard (inconsistent cached row returns null instead of warn+override)
  - D-06 resolve enrich removal (withCachedPublicKey call + equal-seq signatureV2 enrich removed)

affects:
  - 60-06 (verify-cache around publish-side anchor)
  - any future API resolve/publish consumers

tech-stack:
  added: []
  patterns:
    - 'Fail-closed cached record: null signedRecord or CID mismatch → parseCachedRecord returns null → 404'
    - 'D-03 strict first-publish: only embedded sequence 1n accepted, 0n now rejected'

key-files:
  created: []
  modified:
    - apps/api/src/ipns/ipns-record.codec.ts
    - apps/api/src/ipns/ipns.service.ts
    - apps/api/src/ipns/ipns.service.spec.ts

key-decisions:
  - '[Phase 60-05]: D-03 first-publish gate changed from {0n,1n} to strict {1n} only; embedded-0 now returns 400'
  - '[Phase 60-05]: D-06 parseCachedRecord null-signedRecord path returns null (not cid-only 200); CID mismatch discards cached result'
  - '[Phase 60-05]: D-06 withCachedPublicKey enrich and equal-seq signatureV2 enrich removed from resolveRecord'
  - '[Phase 60-05]: api:generate NOT required — changes are internal service/codec logic with no DTO/controller/OpenAPI surface change'
  - '[Phase 60-05]: withCachedPublicKey export deleted from codec (no remaining callers after enrich removal)'

patterns-established:
  - 'Test CIDs in IPNS spec mocks must use [a-zA-Z0-9] only — underscores cause CID regex mismatch in parseIpnsRecordBytes, triggering D-06 discard'

requirements-completed: [HARD-11]

duration: 16min
completed: 2026-06-24
---

# Phase 60 Plan 05: IPNS Verification Cross-Layer Closeout — API strict gate and null-signed-record 404

**API strict first-publish gate (D-03: only embedded sequence 1 accepted) and null-signed-record returns 404 via parseCachedRecord (D-06), with legacy resolve enrich branches removed**

## Performance

- **Duration:** 16 min
- **Started:** 2026-06-24T00:59:00Z
- **Completed:** 2026-06-24T01:15:00Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- D-03: Changed first-publish gate from `embeddedSeq !== 0n && embeddedSeq !== 1n` to `embeddedSeq !== 1n`; first publish with embedded 0 now returns 400
- D-06: `parseCachedRecord` returns null when `signedRecord` is null (no more cid-only 200 from legacy rows); also discards on CID mismatch instead of warn+override
- D-06: Removed `withCachedPublicKey(result, cached.publicKey)` call and equal-seq `signatureV2` enrich block from `resolveRecord`; deleted unused `withCachedPublicKey` export
- Publish-side `verifyIpnsRecordSignature` anchor at ipns.service.ts:87-89 confirmed unchanged
- 96 jest tests pass (159 across all 4 IPNS spec files); no OpenAPI surface change

## Task Commits

TDD RED/GREEN/REFACTOR cycle:

1. **RED: D-03 + D-06 failing tests** - `fd371a87c` (test)
2. **GREEN: D-03 gate + D-06 codec/service changes** - `90471b9d9` (feat)
3. **REFACTOR: Remove unused withCachedPublicKey export** - `9de26f122` (refactor)

## Files Created/Modified

- `apps/api/src/ipns/ipns-record.codec.ts` — null-signedRecord → return null; CID mismatch → discard; withCachedPublicKey deleted
- `apps/api/src/ipns/ipns.service.ts` — D-03 gate strict (only 1n); removed withCachedPublicKey enrich call; removed equal-seq signatureV2 enrich block
- `apps/api/src/ipns/ipns.service.spec.ts` — RED tests added; updated existing tests for D-03/D-06 new behavior; 96 total tests

## Decisions Made

- D-03: strict equality `embeddedSeq !== 1n` (not `{0n, 1n}` tolerance); message updated to "embedded sequence must be 1, got ${embeddedSeq}"
- D-06: parseCachedRecord null-signedRecord → return null (fail-closed; caller 404s)
- D-06: CID mismatch between signedRecord bytes and DB latestCid → return null (inconsistent row discarded)
- `api:generate` NOT required — all changes internal to service/codec; no DTO/controller/endpoint signature modified
- `withCachedPublicKey` removed from codec export (no callers remain after enrich removal)
- Test CID convention: use `[a-zA-Z0-9]` only in mock CIDs — underscores trigger CID regex mismatch in `parseIpnsRecordBytes` which cascades to D-06 discard

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Existing spec tests testing old embedded-0 tolerance needed updating**

- **Found during:** Task 1 (D-03 GREEN implementation)
- **Issue:** Two existing tests (`should accept embedded sequence 0n on first publish` and `allows first publish with embedded sequence 0n`) asserted the OLD behavior (embedded-0 accepted). They now correctly fail after D-03 tightening.
- **Fix:** Updated both tests to assert BadRequestException with the new strict message; updated the global `mockParseIpnsRecord` default from `sequence: 0n` to `sequence: 1n`.
- **Files modified:** apps/api/src/ipns/ipns.service.spec.ts
- **Committed in:** 90471b9d9 (part of GREEN commit)

**2. [Rule 1 - Bug] Existing spec tests for resolve enrich behavior needed updating**

- **Found during:** Task 2 (D-06 GREEN implementation)
- **Issue:** Tests for `withCachedPublicKey` enrich, equal-seq signatureV2 enrich, and null-signedRecord DB fallback all tested the removed behavior. Additionally, metrics tests used entities with `signedRecord: null` which now returns null from parseCachedRecord.
- **Fix:** Updated 8 existing tests and added 2 new tests to reflect D-06 behavior:
  - `should enrich network signature data with cached publicKey...` → asserts pubKey is undefined (no enrich)
  - `should enrich network result with cached signature fields...` → asserts no signature field borrowing
  - `should use DB sequenceNumber and CID when signed record contains stale values` → split into mismatch-discards test + consistent-CID test
  - `should fall back to DB on parse errors (BAD_GATEWAY)` → updated to reflect null-signedRecord → null behavior
  - Metrics tests: added `signedRecord` to DB entities so parseCachedRecord returns non-null
- **Files modified:** apps/api/src/ipns/ipns.service.spec.ts
- **Committed in:** 90471b9d9 (part of GREEN commit)

**3. [Rule 1 - Bug] Test CID strings with underscores caused false CID mismatch in parseCachedRecord**

- **Found during:** Task 2 (debugging failing DB fallback tests)
- **Issue:** Mock CIDs like `bafyCACHED_PARSE` and `bafyCACHED_NULL_NET` contain underscores. The `parseIpnsRecordBytes` CID regex `/\/ipfs\/([a-zA-Z0-9]+)/` extracts only the prefix before `_`. The extracted CID then mismatched `cached.latestCid`, triggering D-06's mismatch discard and returning null. Tests saw null instead of the expected result.
- **Fix:** Replaced underscore-containing test CIDs with alphanumeric-only strings (e.g., `bafyCAcHeDPaRsE7777...`, `bafyCAcHeDnULLNeT7777...`). Documented in `patterns-established`.
- **Files modified:** apps/api/src/ipns/ipns.service.spec.ts
- **Committed in:** 90471b9d9 (part of GREEN commit)

---

**Total deviations:** 3 auto-fixed (all Rule 1 — existing tests testing removed behavior, plus underscore-CID regex interaction)
**Impact on plan:** All fixes required to bring the spec in line with the new strict behavior. No scope creep.

## Issues Encountered

None beyond the above auto-fixed spec updates.

## Next Phase Readiness

- Plan 60-06: verify-cache around publish-side anchor (short-circuit for idempotent TEE republish path)
- The strict server contract now matches the strict client from Plan 60-03
- T-60-16, T-60-17, T-60-18, T-60-19 mitigations all implemented and verified

## Self-Check

Files exist:

- `apps/api/src/ipns/ipns-record.codec.ts` — FOUND
- `apps/api/src/ipns/ipns.service.ts` — FOUND
- `apps/api/src/ipns/ipns.service.spec.ts` — FOUND

---

_Phase: 60-ipns-verification-cross-layer-closeout-desktop-and-api_
_Completed: 2026-06-24_
