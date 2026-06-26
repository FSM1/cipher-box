---
phase: 50-ipfs-ipns-data-integrity-fixes
plan: "01"
subsystem: api/vault
tags: [tdd, advisory-lock, postgresql, data-integrity, overflow-fix]
dependency_graph:
  requires: []
  provides: [guardedUnpin-advisory-lock-safe-bigint]
  affects: [apps/api/src/vault/vault.service.ts]
tech_stack:
  added: []
  patterns: [RED-GREEN TDD, manager.query SQL capture pattern]
key_files:
  created: []
  modified:
    - apps/api/src/vault/vault.service.ts
    - apps/api/src/vault/vault.service.spec.ts
decisions:
  - Drop abs(int4) from pg_advisory_xact_lock hash; int4→bigint sign-extends safely (D-01/WR-01)
  - SQL capture pattern via mockManager.query.mockImplementation for regression assertions
metrics:
  duration: 2min
  completed: "2026-06-19"
  tasks: 2
  files: 2
---

# Phase 50 Plan 01: Advisory-Lock abs(int4) Overflow Fix Summary

Drop `abs()` from `guardedUnpin`'s `pg_advisory_xact_lock` advisory-lock SQL, eliminating the INT_MIN int4 overflow that made one specific CID permanently undeletable (D-01 / WR-01).

## What Was Built

Eliminated the integer-overflow defect in `guardedUnpin`'s advisory-lock hash computation.
The prior `pg_advisory_xact_lock(abs(hashtext($1))::bigint)` applied `abs()` to the `int4`
result of `hashtext()` before casting to `bigint`. For the CID whose `hashtext` equals
`INT_MIN` (-2147483648), `abs(int4)` raises `ERROR: integer out of range` in PostgreSQL,
making that file permanently undeletable via the API and permanently sticking its quota row.

The fix drops `abs()`: `pg_advisory_xact_lock(hashtext($1)::bigint)` sign-extends the `int4`
result safely to `bigint`, which `pg_advisory_xact_lock` accepts as a signed value.

## RED / GREEN / REFACTOR

### RED (Task 1)

Added `it('WR-01: advisory lock query must not use abs(int4) form (INT_MIN CID stays deletable)')`
inside `describe('guardedUnpin')` in `vault.service.spec.ts`. The test captures the SQL string
passed to `mockManager.query` via `mockImplementation` and asserts:

- `expect(capturedSql).toMatch(/pg_advisory_xact_lock/)` — lock call present
- `expect(capturedSql).not.toMatch(/abs\(hashtext/)` — no abs(int4) form

Ran RED against production code; test FAILED on the `.not.toMatch` assertion as expected.

**Commit:** `ac15122f4` — `test(50-01): add failing regression for WR-01 abs(int4) advisory-lock overflow`

### GREEN (Task 2)

Changed line 262 in `vault.service.ts` from:

```sql
SELECT pg_advisory_xact_lock(abs(hashtext($1))::bigint)
```

to:

```sql
SELECT pg_advisory_xact_lock(hashtext($1)::bigint)
```

Updated the preceding comment to document the int4 overflow root cause and cite D-01/WR-01.
Full `vault.service.spec` suite ran: **60/60 tests pass**, including the new WR-01 test and
the existing advisory-lock ordering test.

**Commit:** `f3c07cd24` — `feat(50-01): drop abs() from guardedUnpin advisory-lock to fix INT_MIN overflow`

### REFACTOR

No refactor needed — the change is a one-line SQL edit with a comment update.

## Commits

| Commit | Type | Description |
| --- | --- | --- |
| `ac15122f4` | test | Add failing WR-01 regression (RED) |
| `f3c07cd24` | feat | Drop abs() from advisory-lock hash (GREEN) |

## Deviations from Plan

None — plan executed exactly as written.

## Threat Surface Scan

No new network endpoints, auth paths, or schema changes introduced. This plan is a pure
SQL text correction inside an existing transactional method. No new threat surface.

## TDD Gate Compliance

- RED gate (`test(50-01)` commit): `ac15122f4` — present
- GREEN gate (`feat(50-01)` commit): `f3c07cd24` — present, after RED

## Self-Check: PASSED

- `apps/api/src/vault/vault.service.ts` — FOUND
- `apps/api/src/vault/vault.service.spec.ts` — FOUND
- Commit `ac15122f4` (RED) — FOUND
- Commit `f3c07cd24` (GREEN) — FOUND
