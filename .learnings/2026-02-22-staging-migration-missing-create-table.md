# Staging Migration Missing CREATE TABLE

**Date:** 2026-02-22

## Original Prompt

> it seems like there was a problem running the migration during the staging deployment. you can check the logs on Github or ssh in to the server to figure that one out. Please dont just push through the migrations by executing them directly on the server. Fix the actual problem of migrations not running correctly from the CD pipeline.

## What I Learned

- **`synchronize: true` in dev/test hides missing migrations.** TypeORM auto-creates tables from entity decorators, so you never notice that no `CREATE TABLE` migration exists. The gap only surfaces in staging/production where `synchronize: false`.
- **A migration that modifies a table is not sufficient** — you also need a migration that creates the table. Phase 14 added `SharesPartialUniqueIndex` (modifies `shares` unique constraint) but never added a migration to create `shares` and `share_keys`.
- **The pattern already existed in the codebase.** `1740000000000-AddDeviceApprovals.ts` correctly handled this exact scenario — it was added retroactively for a table that had been auto-created by synchronize. Phase 14 should have followed the same pattern.
- **Migration timestamp ordering matters.** The create-table migration must have a timestamp earlier than any migration that modifies the table. Used `1740250000000` (before `1740300000000`).
- **FullSchema baseline does NOT need updating.** It is a point-in-time snapshot. Fresh databases run FullSchema first, then all incremental migrations in timestamp order. The incremental migration's `CREATE TABLE IF NOT EXISTS` handles creation on fresh databases too.

## What Would Have Helped

- A CI check or pre-merge validation that compares entity definitions against migration coverage — ensuring every `@Entity()` has a corresponding `CREATE TABLE` in either FullSchema or an incremental migration
- A checklist item in the PR template: "If you added new entities, did you add a CREATE TABLE migration?"
- Running the migration runner against a fresh database in CI (not just `synchronize: true`) to catch this class of error

## Key Files

- `apps/api/src/app.module.ts` — lines 83-85: `synchronize` conditional on NODE_ENV
- `apps/api/src/migrations/` — all migration files, ordered by timestamp
- `apps/api/src/migrations/1700000000000-FullSchema.ts` — baseline for fresh databases
- `apps/api/src/run-migrations.ts` — migration runner used in staging deploy
- `.github/workflows/deploy-staging.yml` — lines 286-287: migration step in deploy pipeline
- `apps/api/src/shares/entities/` — the entities that were missing CREATE TABLE migrations
