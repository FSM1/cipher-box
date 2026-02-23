---
created: 2026-02-22T14:30
title: Disable synchronize:true in dev and CI to surface missing migrations
area: api
files:
  - apps/api/src/app.module.ts:83-85
  - apps/api/jest.config.js
  - apps/api/src/run-migrations.ts
---

## Problem

TypeORM `synchronize: true` in dev and test environments auto-creates tables from entity decorators, hiding missing `CREATE TABLE` migrations until staging/production deploys fail. Phase 14 hit this exact issue — `shares` and `share_keys` entities had no migration, and the staging deploy broke with `relation "shares" does not exist`.

Setting `synchronize: false` in all environments forces developers to write migrations before they can interact with new tables, catching gaps at development time rather than deploy time.

## Solution

1. Change `apps/api/src/app.module.ts` lines 83-85 to set `synchronize: false` for all environments
2. Update test setup (jest config / test harness) to run migrations against ephemeral test databases instead of relying on auto-sync
3. Add a dev convenience script (`pnpm --filter api migrate:dev`) that runs pending migrations, so the DX stays smooth
4. Document that existing dev databases need a one-time reset (`DROP DATABASE cipherbox; CREATE DATABASE cipherbox;` then run migrations)
5. Update `docs/DATABASE_EVOLUTION_PROTOCOL.md` environment behavior matrix to reflect the change
