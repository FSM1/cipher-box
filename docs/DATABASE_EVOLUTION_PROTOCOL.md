# CipherBox Database Schema Evolution Protocol

**Version:** 1.0
**Last Updated:** 2026-02-22
**Status:** Active

## Table of Contents

1. [Purpose](#1-purpose)
2. [Guiding Principles](#2-guiding-principles)
3. [Change Classification](#3-change-classification)
4. [Evolution Checklist](#4-evolution-checklist)
5. [Naming & Timestamp Conventions](#5-naming--timestamp-conventions)
6. [Current Schema Reference](#6-current-schema-reference)
7. [Environment Behavior Matrix](#7-environment-behavior-matrix)
8. [Dangerous Patterns](#8-dangerous-patterns)
9. [Historical Incidents](#9-historical-incidents)
10. [References](#10-references)

---

## 1. Purpose

CipherBox uses TypeORM with PostgreSQL. In development and test environments, `synchronize: true` auto-creates and alters tables from entity decorators. In staging and production, `synchronize` is **off** -- the schema is managed exclusively by explicit migration files.

This creates a dangerous gap: a developer can add a new `@Entity()`, run the dev server, interact with the new table, write tests that pass, and ship a PR -- all without writing a migration. The missing `CREATE TABLE` only surfaces when the staging deploy fails.

This protocol establishes formal rules for database schema evolution to prevent this class of error. It mirrors the structure of the [Metadata Evolution Protocol](METADATA_EVOLUTION_PROTOCOL.md) for consistency.

---

## 2. Guiding Principles

1. **Every `@Entity()` must have a `CREATE TABLE` migration.** `synchronize: true` is a development convenience, not a deployment strategy. If a table exists in an entity file, it must exist in a migration file.

2. **Migrations must be idempotent.** Use `IF NOT EXISTS` for `CREATE TABLE` / `CREATE INDEX`, `IF EXISTS` for `DROP`, and column-existence checks for `ALTER TABLE ADD COLUMN`. This allows migrations to run safely on databases where `synchronize: true` already created the structure.

3. **Timestamp ordering matters.** A migration that creates a table must have an earlier timestamp than any migration that modifies that table. TypeORM runs migrations in timestamp order.

4. **The FullSchema baseline does not need updating for new tables.** `1700000000000-FullSchema.ts` captures the schema at a point in time. Fresh database deployments run FullSchema first, then all incremental migrations in timestamp order. New tables created by incremental migrations (with `IF NOT EXISTS`) do not need to be duplicated into FullSchema -- the incremental migration handles creation on both fresh and existing databases.

5. **`down()` must document ownership.** When both FullSchema and an incremental migration create the same table, the `down()` method must note which migration "owns" the table in which context (fresh DB vs existing DB).

6. **No data loss in migrations.** Column type changes, renames, and drops must preserve or migrate existing data. Destructive changes require explicit data migration steps.

---

## 3. Change Classification

### 3.1 Additive (Non-Breaking) Changes

Changes that extend the schema without altering existing structures. These are safe to apply to running databases.

**Examples:**

- Creating a new table (`CREATE TABLE IF NOT EXISTS`)
- Adding a new nullable column (`ALTER TABLE ADD COLUMN IF NOT EXISTS`)
- Adding a new index (`CREATE INDEX IF NOT EXISTS`)
- Adding a new foreign key constraint
- Widening a `varchar` length

**Rules:**

- New columns MUST be nullable or have a `DEFAULT` value (existing rows cannot retroactively provide a value)
- Use `IF NOT EXISTS` / column-existence checks for idempotency
- **Do not** update FullSchema for new tables; the incremental migration's `IF NOT EXISTS` DDL runs safely on both fresh and existing databases (see Guiding Principle 4 and Section 9.2)
- No application downtime required

### 3.2 Destructive (Breaking) Changes

Changes that alter or remove existing structures. These can break running application instances.

**Examples:**

- Dropping a table or column
- Changing a column type (e.g., `varchar` to `integer`)
- Renaming a table or column
- Tightening a `NOT NULL` constraint on existing data
- Removing or replacing a unique constraint or index

**Rules:**

- Verify no application code references the removed/renamed structure
- For column type changes, include a data migration step (e.g., `UPDATE ... SET new_col = CAST(old_col AS ...)`)
- For renames, consider a two-phase approach: add new column, migrate data, remove old column
- `NOT NULL` constraints require ensuring all existing rows have values first
- Index/constraint replacements should drop old and create new in the same migration (see `1740300000000-SharesPartialUniqueIndex.ts`)

### 3.3 Gray Areas

**Adding `NOT NULL` columns with defaults:** Safe for new rows but requires `DEFAULT` in the `ALTER TABLE` statement so existing rows get backfilled. Technically additive, but test with production-scale data volumes (large table `ALTER` can lock for extended periods).

**Changing default values:** Only affects future rows, but can cause behavioral drift between old and new data. Document the change clearly.

**Replacing indexes/constraints:** The window between `DROP INDEX` and `CREATE INDEX` creates a brief period without constraint enforcement. Wrap in a transaction if the constraint prevents data corruption.

---

## 4. Evolution Checklist

Complete this checklist for every database schema change. This is the most important section of this document.

### 4.1 Before Implementation

- [ ] Classify the change: Additive (Section 3.1) or Destructive (Section 3.2)?
- [ ] If adding a new entity: Does a table already exist in FullSchema? (avoid duplicate `CREATE TABLE`)
- [ ] If modifying an existing table: What is the earliest migration that creates the table? Ensure your migration timestamp comes after it.
- [ ] Check: Do any other migrations modify the same table? Ensure no ordering conflicts.

### 4.2 Entity Changes

- [ ] Add or update the entity file in `apps/api/src/{module}/entities/{name}.entity.ts`
- [ ] If new entity: Register it in `app.module.ts` TypeOrmModule `entities` array
- [ ] If new entity: Add corresponding module imports (service, controller, etc.)
- [ ] Verify entity column names match migration column names exactly (TypeORM uses decorators to derive column names)

### 4.3 Migration File

- [ ] Create migration file in `apps/api/src/migrations/`
- [ ] Filename: `{timestamp}-{PascalCaseDescription}.ts` (see Section 5)
- [ ] Class name: `{PascalCaseDescription}{timestamp}`
- [ ] Set `name` property: `'{PascalCaseDescription}{timestamp}'`
- [ ] `up()`: Use `IF NOT EXISTS` / column-existence checks for idempotency
- [ ] `down()`: Use `IF EXISTS` for safe reversal
- [ ] `down()`: Document ownership if the table is also in FullSchema
- [ ] Verify the migration compiles: `pnpm --filter api build`

### 4.4 CD Pipeline Verification

- [ ] Run migrations locally against a clean database: drop and recreate, then `pnpm --filter api typeorm migration:run`
- [ ] Run migrations locally against an existing database (simulates staging): run against dev DB that already has the tables from `synchronize: true`
- [ ] Verify `run-migrations.ts` picks up the new migration file (it globs `dist/migrations/*.js`)
- [ ] Check deploy workflow: `docker compose run --rm api node dist/run-migrations.js` will execute the migration

### 4.5 Downstream Checks

- [ ] If the change affects API DTOs or responses: run `pnpm api:generate` to regenerate the API client
- [ ] If the change adds/modifies columns used by the desktop app's direct DB access (if any): update Rust code
- [ ] If the change affects shared types in `packages/crypto/`: update both TS and Rust implementations
- [ ] Run tests: `pnpm --filter api test`

---

## 5. Naming & Timestamp Conventions

### Migration File Naming

```text
{unix_ms_timestamp}-{PascalCaseDescription}.ts
```

**Timestamp:** Use a Unix timestamp in milliseconds. Choose a value that:

- Is later than all existing migration timestamps, **unless** backfilling a prerequisite (e.g., a missing `CREATE TABLE`) for an already-merged migration — in that case, choose a gap timestamp earlier than the dependent migration but later than all migrations that precede it
- Is earlier than any planned follow-up migration that depends on this one
- For `CREATE TABLE` migrations: must be earlier than any migration that modifies the same table

**Description:** Use PascalCase with a clear verb prefix:

| Pattern                | Use Case              | Example                             |
| ---------------------- | --------------------- | ----------------------------------- |
| `Add{Feature}`         | New table or column   | `AddSharesTables`, `AddTokenPrefix` |
| `Make{Column}Nullable` | Nullability change    | `MakeFolderIpnsTeeFieldsNullable`   |
| `Add{Name}Constraint`  | New constraint/index  | `AddAuthMethodsUniqueConstraint`    |
| `{Table}{ChangeType}`  | Table-specific change | `SharesPartialUniqueIndex`          |
| `FullSchema`           | Baseline (reserved)   | `FullSchema`                        |

### Class & Property Naming

```typescript
export class AddSharesTables1740250000000 implements MigrationInterface {
  name = 'AddSharesTables1740250000000';
  // ...
}
```

The class name is `{Description}{Timestamp}`. The `name` property must match exactly.

### Constraint & Index Naming Prefixes

| Prefix | Type                    | Example                   |
| ------ | ----------------------- | ------------------------- |
| `PK_`  | Primary key             | `PK_shares`               |
| `FK_`  | Foreign key             | `FK_shares_sharer`        |
| `UQ_`  | Unique constraint/index | `UQ_shares_active_triple` |
| `IDX_` | Non-unique index        | `IDX_shares_sharer_id`    |

Format: `{prefix}{table_name}_{column(s) or description}`

---

## 6. Current Schema Reference

12 tables as of Phase 14 (version 0.15.0):

| #   | Table                     | Entity File                                 | Purpose                                   | Foreign Keys                              |
| --- | ------------------------- | ------------------------------------------- | ----------------------------------------- | ----------------------------------------- |
| 1   | `users`                   | `auth/entities/user.entity.ts`              | User accounts (one per Web3Auth key)      | --                                        |
| 2   | `refresh_tokens`          | `auth/entities/refresh-token.entity.ts`     | JWT refresh token hashes                  | `userId` -> `users.id`                    |
| 3   | `auth_methods`            | `auth/entities/auth-method.entity.ts`       | Linked auth methods (wallet, email, etc.) | `userId` -> `users.id`                    |
| 4   | `vaults`                  | `vault/entities/vault.entity.ts`            | Encrypted vault root keys and IPNS names  | `owner_id` -> `users.id`                  |
| 5   | `pinned_cids`             | `vault/entities/pinned-cid.entity.ts`       | IPFS CID pin tracking for quota           | `user_id` -> `users.id`                   |
| 6   | `folder_ipns`             | `ipns/entities/folder-ipns.entity.ts`       | IPNS name -> CID mapping cache            | `user_id` -> `users.id`                   |
| 7   | `tee_key_state`           | `tee/tee-key-state.entity.ts`               | Current TEE key epoch (singleton)         | --                                        |
| 8   | `tee_key_rotation_log`    | `tee/tee-key-rotation-log.entity.ts`        | TEE key rotation audit log                | --                                        |
| 9   | `ipns_republish_schedule` | `republish/republish-schedule.entity.ts`    | IPNS auto-republish schedule              | `user_id` -> `users.id`                   |
| 10  | `shares`                  | `shares/entities/share.entity.ts`           | User-to-user share grants                 | `sharer_id`, `recipient_id` -> `users.id` |
| 11  | `share_keys`              | `shares/entities/share-key.entity.ts`       | Per-item encrypted keys for shares        | `share_id` -> `shares.id`                 |
| 12  | `device_approvals`        | `device-approval/device-approval.entity.ts` | MFA device approval requests              | -- (uses `user_id` varchar, not FK)       |

All entity files are relative to `apps/api/src/`.

**Note:** `device_approvals` uses `user_id` as a plain `varchar` rather than a foreign key to `users.id`. This is by design -- device approvals reference users by their Web3Auth identifier string, not the internal UUID. This table is not in the FullSchema baseline; it is created by its own incremental migration (`1740000000000-AddDeviceApprovals.ts`).

### Migration File Inventory

| Timestamp       | File                                 | Type               | Tables Affected                           |
| --------------- | ------------------------------------ | ------------------ | ----------------------------------------- |
| `1700000000000` | `FullSchema.ts`                      | Baseline           | 11 tables (all except `device_approvals`) |
| `1737520000000` | `MakeFolderIpnsTeeFieldsNullable.ts` | Alter column       | `folder_ipns`                             |
| `1738972800000` | `AddTokenPrefix.ts`                  | Add column + index | `refresh_tokens`                          |
| `1739800000000` | `AddRecordTypeToFolderIpns.ts`       | Add column         | `folder_ipns`                             |
| `1740000000000` | `AddDeviceApprovals.ts`              | Create table       | `device_approvals`                        |
| `1740200000000` | `AddAuthMethodsUniqueConstraint.ts`  | Replace index      | `auth_methods`                            |
| `1740250000000` | `AddSharesTables.ts`                 | Create table       | `shares`, `share_keys`                    |
| `1740300000000` | `SharesPartialUniqueIndex.ts`        | Replace constraint | `shares`                                  |

---

## 7. Environment Behavior Matrix

| Aspect                      | Development                    | Test                           | Staging                        | Production                     |
| --------------------------- | ------------------------------ | ------------------------------ | ------------------------------ | ------------------------------ |
| `synchronize`               | `true`                         | `true`                         | `false`                        | `false`                        |
| Schema source               | Entity decorators (auto)       | Entity decorators (auto)       | Migration files only           | Migration files only           |
| Migration runner            | TypeORM auto-run on connect    | TypeORM auto-run on connect    | `run-migrations.ts` via Docker | `run-migrations.ts` via Docker |
| Missing migration visible?  | **No** -- table created anyway | **No** -- table created anyway | **Yes** -- deploy fails        | **Yes** -- deploy fails        |
| `migrations` table tracked? | Yes (but irrelevant)           | Yes (but irrelevant)           | Yes (determines what runs)     | Yes (determines what runs)     |

**Configuration source:** `apps/api/src/app.module.ts` lines 83-85:

```typescript
synchronize: ['development', 'test'].includes(
  configService.get<string>('NODE_ENV', 'development')
),
```

**Migration runner:** `apps/api/src/run-migrations.ts` -- standalone script that initializes a `DataSource` with `entities: ['dist/**/*.entity.js']` and `migrations: ['dist/migrations/*.js']`, calls `dataSource.runMigrations()`, and exits.

**Deploy workflow:** `.github/workflows/deploy-staging.yml` runs:

```bash
docker compose -f docker-compose.staging.yml run --rm \
  api node dist/run-migrations.js
```

This executes before `docker compose up -d`, ensuring migrations complete before the application starts.

---

## 8. Dangerous Patterns

### 8.1 `synchronize: true` Masking Missing Migrations

**The problem:** In dev/test, TypeORM reads entity decorators and auto-creates tables. A developer adds `@Entity('shares')`, the table appears, tests pass, the PR ships. On staging, the deploy runs `run-migrations.js` -- but no migration creates the `shares` table. The application starts and immediately fails with `relation "shares" does not exist`.

**The fix:** Every PR that adds a new `@Entity()` must include a `CREATE TABLE` migration. Code reviewers must check for this. See Section 4.3.

### 8.2 Migration Timestamp Ordering

**The problem:** `1740300000000-SharesPartialUniqueIndex.ts` modifies the `shares` table. If a developer creates the `shares` table in migration `1740400000000` (a later timestamp), TypeORM runs the index modification first -- on a table that doesn't exist yet.

**The fix:** `CREATE TABLE` migrations must have the earliest timestamp among all migrations that touch the same table. When adding a new table, verify no existing migration references it.

### 8.3 `down()` Ownership Conflicts

**The problem:** Both `FullSchema.ts` and `AddSharesTables.ts` create the `shares` table. If you revert `AddSharesTables` on a database where `FullSchema` created the table, you drop a table you don't "own".

**The fix:** `down()` should use `DROP TABLE IF EXISTS` and include a comment explaining the ownership ambiguity. The `AddSharesTables.ts` migration does this correctly:

```typescript
public async down(queryRunner: QueryRunner): Promise<void> {
  // On staging/production this migration created both tables, so dropping them here is correct.
  // On fresh databases, FullSchema (1700000000000) created these tables and this migration
  // only added indexes. Reverting only this migration on a fresh DB will drop FullSchema-owned
  // tables; ensure FullSchema is also reverted to maintain consistency.
  await queryRunner.query(`DROP TABLE IF EXISTS "share_keys" CASCADE`);
  await queryRunner.query(`DROP TABLE IF EXISTS "shares" CASCADE`);
}
```

### 8.4 Non-Idempotent DDL

**The problem:** `CREATE TABLE` without `IF NOT EXISTS` fails on databases where `synchronize: true` already created the table (e.g., if a staging database was previously run in dev mode, or if FullSchema already created the table).

**The fix:** Always use `IF NOT EXISTS` for `CREATE TABLE`, `CREATE INDEX`, and column-existence checks for `ALTER TABLE ADD COLUMN`. PostgreSQL does not support `ALTER TABLE ADD COLUMN IF NOT EXISTS` before version 9.6, but CipherBox targets PostgreSQL 15+.

---

## 9. Historical Incidents

### 9.1 Phase 14: Missing `shares` and `share_keys` Tables (PR #186)

**Date:** 2026-02-21
**Severity:** Staging deploy failure
**Root cause:** Phase 14 added `Share` and `ShareKey` entities with `@Entity()` decorators, plus a migration (`1740300000000-SharesPartialUniqueIndex`) that modified the `shares` table's unique constraint. But no migration created the `shares` or `share_keys` tables themselves. In dev/test, `synchronize: true` auto-created them. On staging, the partial unique index migration failed with `relation "shares" does not exist`.

**Resolution:**

1. Created `1740250000000-AddSharesTables.ts` with `CREATE TABLE IF NOT EXISTS` for both tables (timestamp before the index migration)
2. Documented the incident in `.learnings/` and added the TypeORM migration discipline rule to `MEMORY.md`
3. Note: FullSchema was **not** updated — it is a point-in-time snapshot (see Guiding Principle 4 and Section 9.2)

**Lesson:** `synchronize: true` in dev/test is invisible safety net that masks missing migrations. Every new `@Entity()` requires a corresponding `CREATE TABLE` migration.

### 9.2 Clarification: FullSchema Does Not Need Every Table

**Date:** 2026-02-22

During the creation of this protocol, the `device_approvals` table was identified as missing from `FullSchema.ts`. Initial analysis suggested this was a gap, but on review: FullSchema is a point-in-time baseline, not a living document. Fresh database deployments run FullSchema first, then all incremental migrations. The `1740000000000-AddDeviceApprovals.ts` migration uses `CREATE TABLE IF NOT EXISTS` and runs on both fresh and existing databases. There is no need to duplicate the DDL into FullSchema.

---

## 10. References

- **Migration files:** `apps/api/src/migrations/`
- **FullSchema baseline:** `apps/api/src/migrations/1700000000000-FullSchema.ts`
- **Entity files:** `apps/api/src/{module}/entities/*.entity.ts`
- **TypeORM config:** `apps/api/src/app.module.ts` (lines 83-85 for `synchronize` setting)
- **Migration runner:** `apps/api/src/run-migrations.ts`
- **Deploy workflow:** `.github/workflows/deploy-staging.yml` (line 287)
- **Metadata Evolution Protocol:** [docs/METADATA_EVOLUTION_PROTOCOL.md](METADATA_EVOLUTION_PROTOCOL.md)
- **Metadata Schema Reference:** [docs/METADATA_SCHEMAS.md](METADATA_SCHEMAS.md)
- **Phase 14 learnings:** `.learnings/2026-02-22-staging-migration-missing-create-table.md`

---

_Protocol version: 1.0_
_Last updated: 2026-02-22_
_Applies to: All database entities and migrations in `apps/api/src/`_
