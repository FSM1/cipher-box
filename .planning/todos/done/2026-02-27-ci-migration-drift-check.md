---
created: 2026-02-27T15:30
title: Add CI migration drift check via TypeORM migration:generate
area: api
files:
  - .github/workflows/ci.yml
  - apps/api/src/data-source.ts
---

## Problem

Missing CREATE TABLE migrations can slip through even with synchronize:false — a developer might forget to generate a migration after adding/modifying an entity. The current safeguard (dev server fails on startup) only catches this locally, not in CI.

## Solution

Add a CI job that detects entity-vs-migration drift automatically:

1. Start a fresh Postgres database (already available in CI via service container)
2. Run all existing migrations against it (`typeorm migration:run`)
3. Run `typeorm migration:generate` to diff entity decorators against the migrated schema
4. If the generated migration is non-empty, fail the job — entities are out of sync with migrations

This is the same pattern as the existing `api-spec` CI job that verifies the OpenAPI client is up to date.

Hand-rolled migrations remain the convention (cleaner, idempotent with IF NOT EXISTS). This check is purely a safety net to catch drift before it reaches staging.
