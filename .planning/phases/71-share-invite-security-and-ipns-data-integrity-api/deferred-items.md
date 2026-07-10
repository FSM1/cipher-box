# Deferred Items — Phase 71

## From Plan 71-08

- `pnpm --filter @cipherbox/api exec tsc --noEmit` reports pre-existing errors, none of which are in this plan's changed files (`apps/api/src/shares/shares.service.ts` / `.spec.ts`). The reported errors are located in OTHER files: `@cipherbox/crypto` module-resolution failures (stale/missing `packages/crypto/dist`, a known cross-package dist-staleness issue — clears after building crypto), null-narrowing errors in `apps/api/src/ipns/ipns-verify-cache.spec.ts`, and an `HttpArgumentsHost` import mismatch in `apps/api/src/metrics/http-metrics.interceptor.spec.ts`. All are unchanged vs `origin/main` and not CI-gated (the `pnpm typecheck` gate excludes `apps/api tsc`). Out of scope for this plan — not fixed.

## From Plan 71-05

- `pnpm --filter sdk-e2e exec tsc --noEmit -p tsconfig.json` reports 3 pre-existing `TS18048 'possibly undefined'` errors in `tests/sdk-e2e/src/suites/bin-operations.test.ts` (lines 83, 91, 107) unrelated to this plan's change (`ipns-publish-gate.test.ts` Test 21). File last touched in an unrelated historical commit (#588, well before Phase 71). `ipns-publish-gate.test.ts` itself typechecks with zero errors. Out of scope for this plan — not fixed. (Note: cross-package dist staleness required a one-time `pnpm install` + `pnpm --filter @cipherbox/{crypto,core,api-client,sdk-core,sdk} build` before typecheck could resolve workspace package types at all — this is environment setup, not a code fix.)
