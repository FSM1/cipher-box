# Quick Task 260401-5ft: Expose API version on /health endpoint

**Status:** Complete
**Date:** 2026-04-01
**Commit:** ba5e9de

## Changes

- **`apps/api/src/health/health.controller.ts`** — Added `version` field to health endpoint response. Reads from `npm_package_version` env var (set by pnpm) with fallback to `package.json`. Response shape: `{ status, info, error, details, version }`.
- **`apps/api/src/health/health.controller.spec.ts`** — New unit test verifying version field presence (semver pattern) and preservation of existing health check fields.

## Verification

- Unit tests pass: `pnpm --filter @cipherbox/api exec jest --testPathPattern health.controller.spec --no-coverage`
- OpenAPI spec and generated API client updated: `packages/api-client/openapi.json`, `packages/api-client/src/models/healthControllerCheck200.ts`
