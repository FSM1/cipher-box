---
phase: 71-share-invite-security-and-ipns-data-integrity-api
plan: 05
subsystem: testing
tags: [sdk-e2e, vitest, ipns, postgres, concurrency, typescript]

# Dependency graph
requires:
  - phase: 71-share-invite-security-and-ipns-data-integrity-api
    provides: 71-04 first-publish 23505→409 translation in upsertIpnsRecord (the API-side behavior this proves), and 71-02 renamed sdk-e2e share vocabulary (so the package typechecks)
provides:
  - Test 21 (D-06) — a genuine concurrent first-publish race against live Postgres proving the ipns_records(ipnsName) unique constraint yields exactly one 200 + one 409 (never 500)
  - The real-concurrency backstop the mocked apps/api unit suite cannot provide
affects: [ipns-service, sc4-data-integrity, sdk-e2e]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "First-publish concurrent-race pattern: two Promise.allSettled first-publishes of one brand-new ipnsName (sequenceNumber 1n, no expectedSequenceNumber), assert exactly one fulfilled 200 + one rejected statusOf===409"

key-files:
  created: []
  modified:
    - tests/sdk-e2e/src/suites/ipns-publish-gate.test.ts

key-decisions:
  - "Mirrored Test 16's Promise.allSettled + statusOf helper structure but WITHOUT a baseline publish, so both requests race the INSERT rather than an UPDATE"
  - "Proven against a live stack (fresh Postgres + real API on :3000) — the only way to exercise DB-level unique-constraint concurrency; the apps/api Jest suite mocks the DataSource"

patterns-established:
  - "Live-stack D-06 backstop: reset DB → migration:run → api dev (:3000) → sdk-e2e ipns-publish-gate; SDK_E2E_SECRET must equal the API's TEST_LOGIN_SECRET"

requirements-completed: [D-06, SC#4]

coverage:
  - id: D1
    description: "Test 21 authored: concurrent first-publish of the same new ipnsName asserts exactly one 200 + one 409 (never 500); sdk-e2e typechecks under the 71-02 renamed vocabulary"
    requirement: "D-06"
    verification:
      - kind: e2e
        ref: "tests/sdk-e2e/src/suites/ipns-publish-gate.test.ts#Test 21 (D-06)"
        status: pass
    human_judgment: false
  - id: D2
    description: "D-06 real-race backstop proven against live Postgres: exactly one 200 + one 409, no 500"
    requirement: "SC#4"
    verification:
      - kind: e2e
        ref: "pnpm --filter sdk-e2e exec vitest run src/suites/ipns-publish-gate.test.ts -t 'Test 21' (against fresh DB + API :3000)"
        status: pass
    human_judgment: false
---

## Accomplishments

- **Task 1 — Test 21 authored (D-06).** Added `it('Test 21 (D-06): concurrent first-publish of the same new ipnsName → exactly one 200 + one 409', ...)` to `tests/sdk-e2e/src/suites/ipns-publish-gate.test.ts`, mirroring Test 16's `Promise.allSettled` + `statusOf` structure but with **no baseline publish**: one brand-new Ed25519 keypair/ipnsName, a signed first-publish record embedding sequence 1, two concurrent first-publish requests, asserting exactly one fulfilled (200) + one rejected with `statusOf(reason) === 409` (never 500), followed by a resolve confirming a single row at `sequenceNumber === 1n`. Suite header comment extended to list Test 21 alongside 16/17/20. Tests 16/17/20 and fixtures untouched. `pnpm --filter sdk-e2e exec tsc --noEmit -p tsconfig.json` clean for the file. Committed in `a42634802`.

- **Task 2 — Live-stack verification PASSED (checkpoint resolved).** Ran the D-06 real concurrent race against a live stack: local Postgres reset to clear stale data, `pnpm --filter @cipherbox/api migration:run` applied the greenfield cutover (including `UQ_ipns_records_ipns_name UNIQUE (ipns_name)`), API rebuilt+restarted from current branch code on `:3000` (carries 71-04's first-publish 23505→409 translation), then `pnpm --filter sdk-e2e exec vitest run src/suites/ipns-publish-gate.test.ts -t "Test 21"` (with `SDK_E2E_SECRET` aligned to the API's `TEST_LOGIN_SECRET`). **Result: Test 21 passed — exactly one 200 + one 409, never a 500.** The genuine DB-level unique-constraint race is proven to produce a clean 409.

## Verification results

- Test 21 typecheck: clean (`tsc --noEmit -p tsconfig.json`).
- Live run: `✓ src/suites/ipns-publish-gate.test.ts (Test 21) 1 passed`, exit 0 — one success (200) + one conflict (409), no 500.
- SC#4 backstop satisfied: the concurrent first-publish race yields exactly one success and one 409 against real Postgres, closing the gap the mocked unit test cannot cover.

## Notes / deviations

- vitest does not auto-load `.env`; the run required `SDK_E2E_SECRET=<API TEST_LOGIN_SECRET>` passed inline so the sdk-e2e test-login matched the API. Environment-only; no code change.
- Fresh worktree required a one-time `pnpm install` + `@cipherbox/{crypto,core,api-client,sdk-core,sdk}` dist rebuild to resolve workspace types (logged as environment setup, not code).
- Pre-existing unrelated `TS18048` errors in `bin-operations.test.ts` (last modified well before Phase 71, untouched by this plan) recorded in `deferred-items.md`; out of scope.
