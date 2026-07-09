# Deferred Items — Phase 71

## From Plan 71-08

- `pnpm --filter @cipherbox/api exec tsc --noEmit` reports pre-existing errors unrelated to this plan's change (`apps/api/src/shares/shares.service.ts` / `.spec.ts`): `@cipherbox/crypto` module resolution failures (stale/missing `packages/crypto/dist`, known cross-package dist-staleness issue), a couple of pre-existing `ipns.service.ts` null-narrowing errors, and an `HttpArgumentsHost` import mismatch in `http-metrics.interceptor.spec.ts`. None reference `shares.service.ts`/`shares.service.spec.ts`. Out of scope for this plan — not fixed.

## From Plan 71-05

- `pnpm --filter sdk-e2e exec tsc --noEmit -p tsconfig.json` reports 3 pre-existing `TS18048 'possibly undefined'` errors in `tests/sdk-e2e/src/suites/bin-operations.test.ts` (lines 83, 91, 107) unrelated to this plan's change (`ipns-publish-gate.test.ts` Test 21). File last touched in an unrelated historical commit (#588, well before Phase 71). `ipns-publish-gate.test.ts` itself typechecks with zero errors. Out of scope for this plan — not fixed. (Note: cross-package dist staleness required a one-time `pnpm install` + `pnpm --filter @cipherbox/{crypto,core,api-client,sdk-core,sdk} build` before typecheck could resolve workspace package types at all — this is environment setup, not a code fix.)
