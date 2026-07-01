---
phase: 67-tee-lease-renewer-contract-rewrite
plan: "08"
subsystem: tests/sdk-e2e
tags: [tee, ipns, e2e, round-trip, migration, blocking-gate]
dependency_graph:
  requires: [67-01, 67-05, 67-06, 67-07]
  provides: [tee-republish-e2e, live-schedule-collapse-migration]
  affects:
    - tests/sdk-e2e/src/suites/tee-republish.test.ts
    - apps/api/src/republish/republish.service.ts
tech_stack:
  added: []
  patterns: [deterministic BullMQ trigger, direct-pg make-due, live-migration gate]
key_files:
  created:
    - tests/sdk-e2e/src/suites/tee-republish.test.ts
  modified:
    - apps/api/src/republish/republish.service.ts
    - apps/api/src/republish/republish.service.spec.ts
decisions:
  - "Live gate run by the orchestrator (not a checker subagent) per plan Task 3 — the migration + round-trip ran against the local cipherbox DB"
  - "getDueEntries reverted from 67-07's query-builder innerJoin to the find-options API: the QB innerJoin + raw-column orderBy + take path threw a TypeORM 'databaseName' metadata error at runtime that the mocked unit test could not catch"
  - "Tombstone/key filter (defense layer 1) moved from the JOIN to the ipns_records find + record-map null-drop — same guarantee, robust query"
  - "readTeeKeys reads current_public_key (bytea) and returns hex — tee_key_state has no public_key column"
metrics:
  completed: "2026-07-01T01:36:00Z"
  tasks_completed: 3
  tasks_total: 3
  files_modified: 3
status: complete
---

# Phase 67 Plan 08: TEE Lease-Renewer Round-Trip — Live Gate Summary

Proved the new verify-in-enclave lease-renewer contract end-to-end (D-04 / success
criterion 4): ran the schedule-collapse migration against the live local Postgres, then a
new `tests/sdk-e2e` suite published a TEE-enrolled record, forced one deterministic
republish, and asserted equal sequence, equal CID, later EOL — plus tombstoned-name never
re-signed. Both tests pass against the migrated schema and the freshly-built simulator
`tee-worker`.

## Tasks Completed

### Task 1 [BLOCKING]: Live schedule-collapse migration

- Rebuilt + restarted the docker `tee-worker` service (the running container was ~2 weeks
  old, pre-67-06). Container `cipherbox-tee-worker` healthy, simulator mode, host `:3002`.
- Ran `migration:run` against the live `cipherbox` DB (the local database; `cipherbox_test`
  is a CI-only DB name). `ScheduleCollapse1751000000000` applied successfully; the 4 signing
  columns (`encrypted_ipns_key`, `key_epoch`, `latest_cid`, `sequence_number`) confirmed
  dropped via `information_schema.columns`.

### Task 2: sdk-e2e round-trip suite

- `tests/sdk-e2e/src/suites/tee-republish.test.ts` (authored by the executor, one correction
  applied — see Deviations): reads TEE keys from `tee_key_state`, enrolls a record via
  `createSubfolder` with `teeKeys`, makes the schedule row due via a direct pg
  `next_republish_at` write, enqueues exactly ONE `republish-batch` job on the real BullMQ
  `republish` queue (redis `:6380`), polls until `signed_record` changes.
- Test A asserts `renewed.sequence === original.sequence` (no increment), `renewed.value ===
  original.value` (same CID), and renewed bytes differ (later EOL). Test B tombstones the
  name via `POST /ipns/tombstone` and asserts the schedule row is gone and `signed_record`
  is unchanged. No cron/timer waits.

### Task 3 [GATE]: Live round-trip verified

- `pnpm --filter @cipherbox/sdk-e2e ... tee-republish` → **2 passed**.
- API + tee-worker logs: `processed=1, succeeded=1, failed=0`; tombstone batch `processed=0`;
  **no key material** (no long hex) in the worker logs.

## Deviations from Plan

### Bug found by the live gate (fixed)

**1. [BLOCKING-class] `getDueEntries` TypeORM metadata error (67-07 impl)**

- **Found during:** first live round-trip — `RepublishProcessor` threw `Cannot read
  properties of undefined (reading 'databaseName')`, so the batch never reached the TEE.
- **Root cause:** 67-07 implemented `getDueEntries` with a query-builder `innerJoin(IpnsRecord,
  'r', ...)` + raw snake_case `orderBy('s.next_republish_at')` + `take(2000)`. TypeORM's
  take-pagination path fails to resolve the raw column into entity metadata. The unit spec
  mocked `createQueryBuilder`, so it passed while the real query crashed. The QB form was
  chosen to satisfy a `grep innerJoin` acceptance criterion in the 67-07 plan.
- **Fix:** restored the pre-67-07 `find`-options query (property names) + a second
  tombstone/key-filtered `ipns_records.find` paired via the record map (defense layer 1
  preserved). Realigned `republish.service.spec.ts` to the `find` shape.
- **Commit:** `afcaefd1c` (`fix(67-07): ...`).

**2. [Rule 1 - Bug] `readTeeKeys` wrong column in the e2e suite**

- The suite queried `public_key` from `tee_key_state`, but the column is `current_public_key`
  (bytea). Fixed to select `current_public_key` and return it as hex for `createSubfolder`.
- **Commit:** `fix(67-08): ...`.

### Environment wiring (operational, not code)

- Local DB is `cipherbox` (not the `.env`'s stray `DB_DATABASE=cipherbox_test`); forced
  `DB_DATABASE=cipherbox` for the migration, API, and e2e.
- API restarted from current source wired to `TEE_WORKER_URL=http://localhost:3002`,
  `TEE_WORKER_SECRET=dev-secret` (matching the rebuilt worker), and
  `TEST_LOGIN_SECRET=e2e-test-secret-do-not-use-in-production` (matching the e2e harness).
- The simulator TEE key is deterministic (HKDF from a fixed seed), so the rebuilt worker
  matched `tee_key_state` and `initializeFromTee()` re-populated it on startup.

## Self-Check: PASSED

- FOUND: `tests/sdk-e2e/src/suites/tee-republish.test.ts` (queue.add republish-batch, make-due, no cron)
- CONFIRMED: live migration applied to `cipherbox`; 4 signing columns dropped
- CONFIRMED: round-trip 2/2 passing — equal seq + equal CID + later EOL; tombstone not re-signed
- CONFIRMED: batch `succeeded=1`, no key material in worker logs
- CONFIRMED: `republish.service.spec` 39/39 green after the find-options realignment
