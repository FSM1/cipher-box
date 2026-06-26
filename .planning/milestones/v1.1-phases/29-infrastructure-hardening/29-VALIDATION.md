---
phase: 29
slug: infrastructure-hardening
status: draft
nyquist_compliant: false
wave_0_complete: true
created: 2026-06-19
---

# Phase 29 — Validation Strategy

> Retroactive per-phase validation contract. Phase 29 shipped 2026-03-28; this
> document reconstructs the ACTUAL current test coverage (State A) for each
> success criterion via static enumeration — no suites were executed.

---

## Test Infrastructure

| Property               | Value                                       |
| ---------------------- | ------------------------------------------- |
| **API framework**      | Jest 29.x + ts-jest                         |
| **API config**         | `apps/api/jest.config.js`                   |
| **API run command**    | `cd apps/api && pnpm test`                  |
| **SDK framework**      | Vitest                                      |
| **SDK config**         | `packages/sdk/vitest.config.ts`            |
| **SDK run command**    | `pnpm --filter @cipherbox/sdk test`         |
| **Config artifacts**   | Grafana alert JSON, docker-compose (static) |
| **Estimated runtime**  | ~30s (API) · ~20s (SDK)                     |

---

## Per-Success-Criterion Verification Map

| SC  | Plan(s) | Requirement                                                    | Test Type   | Automated Command                                                          | Coverage | Status      |
| --- | ------- | -------------------------------------------------------------- | ----------- | ------------------------------------------------------------------------- | -------- | ----------- |
| SC1 | 29-01   | `unenrollBatch` delegates per-name to `RepublishService`       | unit        | `cd apps/api && npx jest src/ipns/ipns.service.spec.ts -t unenrollBatch`  | COVERED  | green       |
| SC1 | 29-01   | `POST /ipns/unenroll` endpoint (JWT scope, 200-name cap, DTO)  | integration | _none_                                                                    | MISSING  | manual      |
| SC1 | 29-02   | SDK `fireAndForgetUnenroll` fires on the 4 delete paths        | unit        | _none_                                                                     | MISSING  | manual      |
| SC2 | 29-02   | `collectSubtreeIpnsNames` recursively walks folderTree subtree | unit        | _none_                                                                     | MISSING  | manual      |
| SC3 | 29-03   | `test-login` throws `ForbiddenException` when `NODE_ENV=prod`  | unit        | `cd apps/api && npx jest src/auth/services/test-auth.service.spec.ts -x`  | COVERED  | green       |
| SC3 | 29-03   | `TEST_LOGIN_SECRET` absence + `timingSafeEqual` mismatch guard | unit        | `cd apps/api && npx jest src/auth/services/test-auth.service.spec.ts -x`  | COVERED  | green       |
| SC3 | 29-03   | Grafana alert fires >100 test-logins/hr on staging            | manual      | `jq . docker/grafana/alerts/test-login-rate.json`                         | MANUAL   | green       |
| SC4 | 29-03   | Kubo API port 5001 bound to `127.0.0.1` in staging            | manual      | `grep "127.0.0.1:5001" docker/docker-compose.staging.yml`                 | MANUAL   | green       |

_Status legend: green · red · flaky · manual_

---

## Detailed Coverage Findings

### SC1 — IPNS unenrollment on file/folder deletion

**Status: PARTIAL** — API service layer is tested; the endpoint and the SDK
delete-path wiring that actually triggers it are not.

- **COVERED (green):** `apps/api/src/ipns/ipns.service.spec.ts` has a real
  `describe('unenrollBatch', ...)` block (line 1500) with 4 behavioral tests:
  unenrolls all provided names (asserts `unenrollIpns` called per-name), continues
  on individual failure, returns zero when all fail, and handles the empty array.
  This proves `IpnsService.unenrollBatch` delegates correctly to
  `RepublishService.unenrollIpns()`.
- **MISSING (manual only):** There is **no** `apps/api/src/ipns/ipns.controller.spec.ts`.
  The `POST /ipns/unenroll` endpoint contract — JWT auth scoping to `req.user.id`,
  the 200-name `@ArrayMaxSize` cap, the IPNS-name `@Matches` regex validation in
  `BatchUnenrollIpnsDto`, and the throttle — is verified only by the plan's static
  greps, not by an executed test. No DTO-validation spec exists either.
- **MISSING (manual only):** The SDK `fireAndForgetUnenroll()` method
  (`packages/sdk/src/client.ts`, 9 references = definition + 4 call sites + helper
  refs) has **zero** automated coverage. A repo-wide search of
  `packages/sdk/src/__tests__/` for `unenroll` returns 0 matches. The behavioral
  claim "deleting a file/folder triggers unenrollment of its IPNS name(s)" is
  unverified by any test that can fail. The existing `bin.test.ts` /
  `client-file-ops.test.ts` exercise the deletion paths but assert nothing about
  the unenroll call.

### SC2 — Batch unenrollment for folder deletes with nested files

**Status: MISSING (manual only).** `collectSubtreeIpnsNames()`
(`packages/sdk/src/client.ts`) performs the recursive in-memory folderTree walk
that gathers the folder name plus every nested `fileMetaIpnsName`. No test
references this symbol (0 matches in `packages/sdk/src/__tests__/`). The recursion,
the "unloaded subtree returns folder name only" edge, and the batching into a
single API call are all unproven by automated tests. This is the highest-value
untested behavior in the phase.

### SC3 — Test login unreachable in production + monitoring alert

**Status: COVERED + MANUAL.**

- **COVERED (green):** `apps/api/src/auth/services/test-auth.service.spec.ts`
  contains 3 directly relevant behavioral tests (8 `it()` total in the file):
  "should throw ForbiddenException in production environment" (line 80, mocks
  `NODE_ENV=production` and asserts the message), "should throw ForbiddenException
  if TEST_LOGIN_SECRET not set" (line 94), and "should throw UnauthorizedException
  if secret does not match" (line 102, exercising the `timingSafeEqual` path).
  These are real, executable, can-fail tests covering the production guard.
- **MANUAL:** The Grafana alert is a config artifact, not code.
  `docker/grafana/alerts/test-login-rate.json` is valid JSON (verified via `jq`),
  titled "Test Login Rate High", queries
  `increase(cipherbox_auth_logins_total{method="test"}[1h])` with a `gt 100`
  threshold. Alert firing behavior is verifiable only against a live Grafana/
  Prometheus instance.

### SC4 — Kubo API port 5001 restricted in staging/production

**Status: MANUAL.** `docker/docker-compose.staging.yml` line 73 binds Kubo to
`127.0.0.1:5001:5001`, confirmed by static grep. This is deployment configuration
with no code path to unit-test; verification is inspection-only (and ideally a
runtime smoke test against staging confirming 5001 is not externally reachable).

---

## Manual-Only Verifications

| Behavior                          | SC  | Why Manual                          | Test Instructions                                                                                        |
| --------------------------------- | --- | ----------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Grafana test-login rate alert     | SC3 | Grafana alert JSON, no code path    | `jq . docker/grafana/alerts/test-login-rate.json`; confirm title, `cipherbox_auth_logins_total`, `gt 100` |
| Kubo 5001 not externally exposed  | SC4 | Deployment config, no code path     | `grep "127.0.0.1:5001" docker/docker-compose.staging.yml`; on staging confirm `curl <public>:5001` fails |
| `POST /ipns/unenroll` HTTP contract | SC1 | No controller/e2e spec authored     | Manual: authenticated POST with >200 names → 400; unauth → 401; valid batch → `totalUnenrolled` count    |

---

## Gaps (uncovered behaviors lacking a can-fail test)

1. **SDK `fireAndForgetUnenroll` is never tested** — the actual delete-to-unenroll
   wiring (SC1, the headline phase goal) has no automated coverage in `packages/sdk`.
2. **SDK `collectSubtreeIpnsNames` recursion is never tested** — SC2's entire
   behavior (nested-file collection, unloaded-subtree skip) is unverified.
3. **No `ipns.controller.spec.ts`** — the `/ipns/unenroll` endpoint's auth scoping,
   array-size cap, and DTO regex validation are static-grep-verified only.

Recommended fills (deferred; not authored in this retroactive pass):

- `packages/sdk/src/__tests__/unenroll-on-delete.test.ts` — mock
  `ipnsControllerUnenrollBatch`, call `deleteItem`/`deleteToBin`/`permanentDelete`/
  `emptyBin`, assert the collected IPNS names; assert a rejected unenroll never
  throws to the caller (fire-and-forget contract).
- A `collectSubtreeIpnsNames` unit test seeding a multi-level folderTree and
  asserting the flattened name list, plus the unloaded-subtree edge.
- `apps/api/src/ipns/ipns.controller.spec.ts` — endpoint auth scoping + DTO
  validation (or an e2e POST test).

---

## Validation Audit 2026-06-19

This is a **retroactive documentation pass** on a docs branch — no tests or source
files were created or modified, and no suites were executed (static enumeration
only, per parallel-auditor RAM constraints).

| Metric             | Count |
| ------------------ | ----- |
| Success criteria   | 4     |
| COVERED (green)    | 1 (SC3 production guard, 3 tests)        |
| PARTIAL            | 1 (SC1 — service tested, SDK + endpoint untested) |
| MISSING            | 1 (SC2 — `collectSubtreeIpnsNames` untested)       |
| MANUAL-ONLY        | 2 (SC3 alert JSON, SC4 Kubo binding)     |
| Test-backed checks | `unenrollBatch` (4) + `test-login` guard (3) = 7 executable tests |

**Compliance decision:** `nyquist_compliant: false`, `status: draft`. The phase's
headline behavior — deleting a file or folder actually triggers IPNS unenrollment
(SC1 SDK layer) and folder deletes recursively collect nested IPNS names (SC2) —
ships with **no automated test that can fail**. Only the API service helper
(`unenrollBatch`) and the unrelated test-login guard carry real coverage. Marking
this `validated`/`true` would claim coverage that does not exist. SC3 (guard) and
SC4 (config) are honestly satisfied via unit tests + justified manual inspection,
but they are not the core deliverable. The phase functioned and was grep-verified
at execution time; closing the three gaps above would justify promotion to
`validated`.
