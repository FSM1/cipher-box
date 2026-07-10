---
created: 2026-07-02
title: Web vitest is not run in CI and ipns.service.test.ts is broken locally
area: testing
files:
  - apps/web/src/services/__tests__/ipns.service.test.ts
  - .github/workflows/ci.yml
resolves_phase: 78
---

## Problem

Found during Phase 68 ship (simplify/verify pass):

1. The CI `Test` job runs coverage for `api`, `crypto`, `core`, `sdk-core`, `sdk`, and `api-client` — it never runs `pnpm --filter @cipherbox/web test`. The 10 `apps/web/src/**/*.test.ts` files only run locally.
2. `apps/web/src/services/__tests__/ipns.service.test.ts` currently fails at collect time (locally, on this branch AND against origin/main's `ipns.service.ts`): the `vi.mock('@cipherbox/api-client')` factory only defines the three controller fns, but the module graph pulls `apps/web/src/lib/api-config.ts`, whose module scope calls `createAxiosInstance(apiConfig)` — vitest's strict mock guard throws `No "createAxiosInstance" export is defined on the "@cipherbox/api-client" mock`. Pre-existing, NOT introduced by Phase 68 (verified by running the test against origin/main's service file).

## Solution

- Fix the mock: add `createAxiosInstance: vi.fn(() => ({}))` and `setApiClientConfig: vi.fn()` to the `@cipherbox/api-client` factory in `ipns.service.test.ts` (or mock `../lib/api-config` directly).
- Decide whether `pnpm --filter @cipherbox/web test` should join the CI `Test` job. Per testing doctrine apps/web logic should live in the SDK, but these 10 legacy `.test.ts` files exist and silently rot without a CI gate — either wire them into CI or migrate/retire them.
