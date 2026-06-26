---
phase: 35-phala-testnet-tee-migration
plan: 02
subsystem: testing
tags: [vitest, tee, ecies, epoch-fallback, auth-middleware, ipns-republish]

# Dependency graph
requires:
  - phase: 35-phala-testnet-tee-migration (plan 01)
    provides: shared package integration for tee-worker (crypto, core, sdk-core)
provides:
  - Unit test suite for TEE-specific business logic (36 new tests)
  - Vitest configuration for tee-worker package
  - Test coverage for key derivation, epoch fallback, auth, and republish route
affects: [35-phala-testnet-tee-migration]

# Tech tracking
tech-stack:
  added: [vitest]
  patterns: [real-crypto-testing (no ECIES mocking), http-request-helper for route testing]

key-files:
  created:
    - apps/tee-worker/vitest.config.ts
    - apps/tee-worker/src/__tests__/tee-keys.test.ts
    - apps/tee-worker/src/__tests__/key-manager.test.ts
    - apps/tee-worker/src/__tests__/auth.test.ts
    - apps/tee-worker/src/__tests__/republish.test.ts
  modified:
    - apps/tee-worker/package.json

key-decisions:
  - 'Used real HKDF-derived keys and real @cipherbox/crypto wrapKey/unwrapKey instead of mocking ECIES'
  - 'Mocked only ipns-signer in republish tests (IPNS record creation tested in @cipherbox/core)'
  - 'Used raw node:http for route testing instead of adding supertest dependency'

patterns-established:
  - 'Real crypto in TEE tests: use simulator-mode HKDF keys + real ECIES to test orchestration without mocking primitives'
  - 'Mock only cross-boundary dependencies (ipns-signer) that are tested in their own package'

requirements-completed: []

# Metrics
duration: 5min
completed: 2026-03-29
---

# Phase 35 Plan 02: TEE Worker Unit Tests Summary

**Vitest test suite for TEE-specific business logic: key derivation, epoch fallback, auth middleware, and batch republish route**

## Performance

- **Duration:** 5 min
- **Started:** 2026-03-29T11:05:53Z
- **Completed:** 2026-03-29T11:11:34Z
- **Tasks:** 4
- **Files modified:** 6

## Accomplishments

- Configured Vitest test runner for tee-worker with node environment
- 10 tests for TEE key derivation (determinism, epoch isolation, key format, caching, production guard)
- 11 tests for epoch fallback orchestration (single-epoch, fallback, both-fail, null-previous, re-encrypt round-trip)
- 8 tests for auth middleware (valid token, missing/wrong/malformed headers, unconfigured secret)
- 7 tests for republish route (single entry, batch independence, epoch upgrade, validation, base64)
- All 36 new tests use real ECIES crypto (no mocking of primitives)

## Task Commits

Each task was committed atomically:

1. **Task 1: Set up Vitest and add test dev dependencies** - `a677b349a` (chore)
2. **Task 2: Unit tests for TEE key derivation** - `3a0fe6f5c` (test)
3. **Task 3: Unit tests for epoch fallback orchestration** - `a7adc6e10` (test)
4. **Task 4: Unit tests for auth middleware and republish route** - `3ff2b9ee9` (test)

## Files Created/Modified

- `apps/tee-worker/vitest.config.ts` - Vitest configuration with node environment
- `apps/tee-worker/package.json` - Added vitest devDependency, test/test:watch scripts
- `apps/tee-worker/src/__tests__/tee-keys.test.ts` - TEE key derivation tests (10 tests)
- `apps/tee-worker/src/__tests__/key-manager.test.ts` - Epoch fallback orchestration tests (11 tests)
- `apps/tee-worker/src/__tests__/auth.test.ts` - Auth middleware tests (8 tests)
- `apps/tee-worker/src/__tests__/republish.test.ts` - Republish route batch processing tests (7 tests)

## Decisions Made

- **Real crypto over mocks:** Used simulator-mode HKDF-derived keys and real @cipherbox/crypto wrapKey/unwrapKey to create test ciphertexts. This tests the full orchestration path without duplicating primitive tests.
- **Mock only ipns-signer:** The republish route tests mock only the signIpnsRecord function (which delegates to @cipherbox/core). IPNS record creation and marshaling are tested in that package's own test suite.
- **No supertest dependency:** Used raw node:http requests for route testing to avoid adding another dev dependency. The helper is simple and sufficient for the test cases.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- TEE-specific business logic has test coverage for all key orchestration paths
- Ready for 35-03 (Phala CVM Docker build) and subsequent deployment plans
- Existing ssrf-validation tests (20 passing + 8 todo) were not modified

## Self-Check: PASSED

All 6 files verified present. All 4 task commits verified in git log.

---

_Phase: 35-phala-testnet-tee-migration_
_Completed: 2026-03-29_
