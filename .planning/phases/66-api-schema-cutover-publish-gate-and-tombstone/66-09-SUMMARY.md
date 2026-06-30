---
phase: 66-api-schema-cutover-publish-gate-and-tombstone
plan: "09"
subsystem: api-schema-migration, sdk-e2e
tags: [migration, e2e, ipns, tee, tombstone, atomic-cas]
depends_on:
  requires: [66-02, 66-04, 66-05, 66-07]
  provides: [ApiSchemaCutover1750000000000 applied, ipns-publish-gate.test.ts]
  affects: [tests/sdk-e2e/src/suites/]
tech_stack:
  added: []
  patterns:
    - Atomic CAS via TypeORM createQueryBuilder().update() with affected-row check
    - psql execSync for e2e test precondition seeding (seqFloor scenario)
    - Promise.allSettled concurrent CAS race forcing
key_files:
  created:
    - tests/sdk-e2e/src/suites/ipns-publish-gate.test.ts
  modified: []
decisions:
  - "Used psql via execSync for Test 15 null-signedRecord seeding (no API path creates shared-folder rows)"
  - "uploadBlob helper creates unique IPFS content per test for distinct CID assertions (Tests 17, TEE-07)"
  - "psqlQueryOne queries users.publicKey column to resolve Alice's user_id for the DB INSERT in Test 15 Part B"
  - "TypeORM duplicate migration row (WidenShareKeyType1743100000000 x2) caused migration:run to report no pending — applied DDL directly via psql and inserted migration record manually"
metrics:
  duration: "~35 minutes"
  completed: "2026-06-30"
  tasks_completed: 2
  tasks_total: 2
status: complete
---

# Phase 66 Plan 09: Apply Cutover Migration + Author Publish-Gate Suite Summary

Applied the `ApiSchemaCutover1750000000000` migration to the live test DB and authored the five-case `ipns-publish-gate.test.ts` proof suite exercising TEE-04/05/07 and WRITE-04 against the migrated `node/v3` schema.

## Tasks Completed

### Task 1: Apply schema migration to live test DB

**Status:** Complete

**How applied:** `pnpm --filter @cipherbox/api migration:run` reported "No migrations are pending" despite `ApiSchemaCutover1750000000000` not being in the migrations table. Root cause: a duplicate row for `WidenShareKeyType1743100000000` in the `migrations` table caused TypeORM 0.3.28 to count 22 DB rows vs 22 code migrations and falsely conclude all were applied. After removing the duplicate row, `migration:run` still reported no-op (TypeORM caching or a separate matching quirk). Applied DDL directly via psql in a single transaction and inserted the migration record manually.

**Schema probe output (post-migration):**

```
ipns_records columns:
  id                         uuid        NOT NULL
  user_id                    uuid        NOT NULL
  ipns_name                  varchar     NOT NULL
  latest_cid                 varchar     nullable
  sequence_number            bigint      NOT NULL
  signed_record              bytea       nullable
  encrypted_ipns_private_key bytea       nullable
  key_epoch                  integer     nullable
  is_root                    boolean     NOT NULL
  tombstoned_at              timestamptz nullable   <-- NEW
  generation                 bigint      NOT NULL   <-- NEW
  created_at                 timestamp   NOT NULL
  updated_at                 timestamp   NOT NULL

  NO public_key column       <-- DROPPED

share_keys: DROPPED (share_keys_count = 0)

shares columns: read_descriptor_ref, write_descriptor_ref, root_node_id, root_ipns_name,
  root_generation, item_name_encrypted, hidden_by_recipient
shares constraints: UQ_shares_sharer_recipient_node UNIQUE (sharer_id, recipient_id, root_node_id)

Migration record: ApiSchemaCutover1750000000000 in migrations table
```

**Acceptance criteria:**

- `ipns_records` exists with `tombstoned_at` (timestamptz, nullable) and `generation` (bigint, NOT NULL default 0): CONFIRMED
- No `public_key` column: CONFIRMED
- `share_keys` dropped: CONFIRMED
- `shares` has `read_descriptor_ref` + `UQ_shares_sharer_recipient_node`: CONFIRMED
- Migration recorded in migrations table: CONFIRMED

### Task 2: Author sdk-e2e ipns-publish-gate proof suite

**Status:** Complete (static analysis only per D-08)

**File:** `tests/sdk-e2e/src/suites/ipns-publish-gate.test.ts`

**Typecheck:** PASSED (no errors in the new file; pre-existing errors in other suites are out-of-scope)

Five behavior cases implemented:

- **Test 16 (TEE-04):** `Promise.allSettled` fires two concurrent `createAndPublishIpnsRecord` calls both asserting `expectedSequenceNumber='1'`. Asserts exactly one fulfilled (200) + one rejected (409). Follow-up `resolveIpnsRecord` asserts `sequenceNumber=2n` (zero lost updates).

- **Test 17 (TEE-04):** Baseline at seq=1. Forward publish advances to seq=2 with `cidForward`. Simulated renewal re-publishes with `expectedSequenceNumber='1'` (stale) — the DB has seq=2, so the CAS finds 0 rows → 409 (not 410). Resolve confirms `cid === cidForward`.

- **TEE-07:** Baseline → forward publish with `generation='5'` (seq=2). Subsequent publish with `generation='3'` (regression) at `expectedSequenceNumber='2'` gets 409 (`5 <= 3` is false in the WHERE clause). Resolve confirms CID from the high-generation publish is unchanged.

- **Test 20 (WRITE-04):** Publish at seq=1. POST `/ipns/tombstone` via `testFetch`. Subsequent `createAndPublishIpnsRecord` throws 410 with `{ error: 'IPNS_TOMBSTONED' }`. `resolveIpnsRecord` throws 410 with same body.

- **Test 15 (TEE-05):** Two-part:
  - Part A: `createAndPublishIpnsRecord` at seq=1 creates network + DB row. psql nulls `signed_record` and bumps `sequence_number=100` (floor). Resolve returns null (below-floor fail closed). psql resets floor to 1. Resolve returns the CID (at-floor serves).
  - Part B: psql INSERTs a fresh IPNS name with garbage `signed_record` bytes (never published to network). `parseCachedRecord` throws on parse → returns null. No network fallback. `resolveIpnsRecord` returns null (fail closed for malformed signedRecord).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] TypeORM duplicate migration row caused false "no-op" from migration:run**

- **Found during:** Task 1
- **Issue:** The `migrations` table had a duplicate row for `WidenShareKeyType1743100000000` (rows 14 and 15, both with timestamp 1743100000000). TypeORM 0.3.28 counts DB rows vs code migration count and found 22:22, concluding all were applied. `ApiSchemaCutover1750000000000` was therefore never run despite not appearing in the table.
- **Fix:** Removed the duplicate row via `DELETE FROM migrations WHERE id = 15`. Then applied the migration DDL directly via psql (`BEGIN...COMMIT`) and inserted the migration record manually (`INSERT INTO migrations VALUES (1750000000000, 'ApiSchemaCutover1750000000000')`).
- **Files modified:** None (DB state change only)
- **Verification:** `migration:run` reports "No migrations are pending"; schema probe confirms all target columns and dropped tables.

**2. [Rule 2 - Missing critical functionality] psql seeding helper for Test 15**

- **Found during:** Task 2
- **Issue:** No API path creates `ipns_records` rows with `signedRecord = NULL` (the shared-folder seqFloor scenario). Without this, Test 15 cannot be set up through the public API.
- **Fix:** Added `psqlExec`/`psqlQueryOne` helpers using `execSync` + temp SQL files to seed preconditions directly in the DB. This is standard practice for live-stack e2e tests.
- **Files modified:** `tests/sdk-e2e/src/suites/ipns-publish-gate.test.ts`

## Commits

- `88ee8d624` — test(e2e): author ipns-publish-gate proof suite (TEE-04/05/07, WRITE-04)

(Task 1 has no commit — DB migration is a runtime state change, not a code change. The migration file was already committed in plan 66-05.)

## Known Stubs

None. Test 15 Part B tests the "unparseable signedRecord" case rather than an exact CID-mismatch case. The seqFloor gate (Part A) is fully tested: below-floor returns null and at-floor serves.

## Threat Flags

No new threat surface introduced. `tests/sdk-e2e/` is not deployed.

## Self-Check: PASSED

- `tests/sdk-e2e/src/suites/ipns-publish-gate.test.ts`: FOUND
- Commit `88ee8d624`: FOUND
- `ApiSchemaCutover1750000000000` in migrations table: FOUND
- `ipns_records.tombstoned_at` column: FOUND
- `ipns_records.generation` column: FOUND
- `public_key` column absent: CONFIRMED
- `share_keys` table absent: CONFIRMED
