---
phase: 67-tee-lease-renewer-contract-rewrite
plan: "01"
subsystem: api/republish
tags: [migration, entity, tee, ipns, schema]
dependency_graph:
  requires: []
  provides: [slimmed-republish-schedule-entity, schedule-collapse-migration]
  affects: [apps/api/src/republish/republish-schedule.entity.ts, apps/api/src/migrations/1751000000000-ScheduleCollapse.ts]
tech_stack:
  added: []
  patterns: [greenfield-migration-pattern, drop-column-if-exists]
key_files:
  modified:
    - apps/api/src/republish/republish-schedule.entity.ts
  created:
    - apps/api/src/migrations/1751000000000-ScheduleCollapse.ts
decisions:
  - "D-02: signing inputs sourced from ipns_records via JOIN; schedule table is pure scheduling metadata"
  - "D-01 greenfield waiver applied: down() throws, no rollback target"
  - "IDX_ipns_republish_schedule_ipns_name added for efficient getDueEntries JOIN"
metrics:
  duration: "~5 minutes"
  completed: "2026-06-30"
  tasks_completed: 2
  tasks_total: 2
status: complete
---

# Phase 67 Plan 01: Schedule Collapse Entity and Migration Summary

Slimmed `IpnsRepublishSchedule` to pure scheduling metadata by removing four signing-input columns and created forward migration `1751000000000-ScheduleCollapse.ts`.

## Tasks

| Task | Name | Commit | Files |
| ---- | ---- | ------ | ----- |
| 1 | Drop 4 signing-input columns from entity | a365d5504 | apps/api/src/republish/republish-schedule.entity.ts |
| 2 | Forward migration to drop columns and add JOIN index | 63545bf88 | apps/api/src/migrations/1751000000000-ScheduleCollapse.ts |

## What Was Built

The `IpnsRepublishSchedule` TypeORM entity no longer carries `encryptedIpnsKey`, `keyEpoch`, `latestCid`, or `sequenceNumber`. The entity retains exactly 7 `@Column` fields: `userId`, `ipnsName`, `nextRepublishAt`, `lastRepublishAt`, `consecutiveFailures`, `status`, `lastError`.

The migration `ScheduleCollapse1751000000000` drops the four columns from the live schema using `DROP COLUMN IF EXISTS` in a single `ALTER TABLE` statement, then creates `IDX_ipns_republish_schedule_ipns_name` for the `getDueEntries` JOIN to `ipns_records`. The `down()` throws per the D-01 greenfield waiver, matching the Phase-66 analog.

## Deviations from Plan

None — plan executed exactly as written.

The intentional breakage noted in the phase context is in effect: `republish.service.ts` references the removed fields and will not typecheck until plan 67-07. This is expected and was not treated as a failure.

## Known Stubs

None.

## Threat Surface Scan

No new network endpoints, auth paths, or trust-boundary changes introduced. The dropped columns (`encrypted_ipns_key` in particular) reduce the crypto-bearing surface on the schedule table, directly mitigating T-67-01-I (Information Disclosure).

## Self-Check: PASSED

- [x] `apps/api/src/republish/republish-schedule.entity.ts` exists and contains 7 `@Column` decorators
- [x] `apps/api/src/migrations/1751000000000-ScheduleCollapse.ts` exists with `ScheduleCollapse1751000000000` class
- [x] Commit a365d5504 present in git log
- [x] Commit 63545bf88 present in git log
