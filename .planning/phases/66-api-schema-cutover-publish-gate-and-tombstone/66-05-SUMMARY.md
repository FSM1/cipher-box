---
phase: 66-api-schema-cutover-publish-gate-and-tombstone
plan: "05"
subsystem: api/migrations
tags: [migration, schema, typeorm, postgres, ipns, shares]
status: complete

dependency_graph:
  requires: ["66-01", "66-03"]
  provides: ["66-08", "66-09"]
  affects: []

tech_stack:
  added: []
  patterns:
    - TypeORM MigrationInterface with raw queryRunner.query DDL
    - Drop-recreate strategy with greenfield waiver (D-01)
    - Separate FK and index statements after CREATE TABLE

key_files:
  created:
    - apps/api/src/migrations/1750000000000-ApiSchemaCutover.ts
  modified: []

decisions:
  - "drop-recreate used for shares and share_invites (not alter-column) for schema consistency and simplicity"
  - "down() throws per D-01 greenfield waiver — staging DB wiped on each deploy"
  - "public_key column omitted from ipns_records — recoverable via publicKeyFromIpnsName"
  - "plain UNIQUE constraint on shares (sharer_id, recipient_id, root_node_id) per D-11 hard-delete revoke"

metrics:
  duration: "~8 minutes"
  completed: "2026-06-30"
  tasks_completed: 1
  tasks_total: 1
  files_created: 1
  files_modified: 0
---

# Phase 66 Plan 05: Schema Cutover Migration Summary

**One-liner:** Forward-only TypeORM migration drop-recreates shares/share_invites/folder_ipns and creates ipns_records with tombstoned_at and generation, matching the node/v3 entity shapes from 66-01/66-03.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Author drop-recreate forward migration | 602f2671b | apps/api/src/migrations/1750000000000-ApiSchemaCutover.ts |

## What Was Built

A single TypeORM migration `ApiSchemaCutover1750000000000` that transitions the Postgres schema from the legacy node model to node/v3 in five ordered steps:

1. `DROP TABLE share_keys CASCADE` — removes the per-key-type share table and its FK to shares
2. `DROP TABLE shares CASCADE` + `CREATE TABLE shares` — descriptor-ref schema with `read_descriptor_ref`, `write_descriptor_ref`, `root_node_id`, `root_ipns_name`, `root_generation`; plain `UNIQUE (sharer_id, recipient_id, root_node_id)`; two FKs to users(id) ON DELETE CASCADE
3. `DROP TABLE share_invites CASCADE` + `CREATE TABLE share_invites` — drops `encrypted_child_keys`; adds `root_ipns_name`, `root_node_id`, `root_generation`, `write_descriptor_ref`; single ephemeral-wrapped `encrypted_key` readKey only
4. `DROP TABLE folder_ipns CASCADE` — no external SQL FKs confirmed by FK-map research; ipns_republish_schedule/vaults/shares reference ipns_name as plain varchar
5. `CREATE TABLE ipns_records` — matches ipns-record.entity.ts exactly: drops `public_key`, adds `tombstoned_at timestamptz` and `generation bigint NOT NULL DEFAULT 0`; UNIQUE on ipns_name; FK user_id → users(id)

`down()` throws with a descriptive message per D-01 greenfield waiver.

## Acceptance Criteria Verification

| Check | Result |
|-------|--------|
| `grep -c 'class ApiSchemaCutover1750000000000'` | 1 |
| `grep -c 'CREATE TABLE "ipns_records"'` | 1 |
| `grep -c 'tombstoned_at'` | 3 (column def + 2 comments) |
| `grep -c '"generation"'` | 1 |
| `grep -c 'DROP TABLE IF EXISTS "share_keys"'` | 1 |
| `grep -c 'CREATE TABLE "shares"'` | 1 |
| `grep -c '"read_descriptor_ref"'` | 1 |
| `grep -c 'UQ_shares_sharer_recipient_node'` | 1 |
| `grep -c 'throw new Error'` | 1 (down throws) |
| `public_key` as created column | 0 (appears only in comments) |

Build verification note: `pnpm --filter @cipherbox/api build` has ~97 pre-existing errors in shares service/controller files (66-04 logic layer, sibling plan, out of scope). The migration file itself has no TypeScript complexity beyond standard TypeORM interface types.

## Deviations from Plan

None. Plan executed exactly as written.

## Known Stubs

None. The migration is a pure DDL file with no stub patterns.

## Threat Flags

None. No new network endpoints, auth paths, or trust boundaries introduced. The migration only modifies the Postgres schema.

## Self-Check: PASSED

- File exists: `apps/api/src/migrations/1750000000000-ApiSchemaCutover.ts` — FOUND
- Commit 602f2671b exists — FOUND (verified via git rev-parse)
- All grep acceptance criteria — PASSED (see table above)
