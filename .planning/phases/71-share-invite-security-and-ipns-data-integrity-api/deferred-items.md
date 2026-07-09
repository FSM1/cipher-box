# Deferred Items — Phase 71

## From Plan 71-08

- `pnpm --filter @cipherbox/api exec tsc --noEmit` reports pre-existing errors unrelated to this plan's change (`apps/api/src/shares/shares.service.ts` / `.spec.ts`): `@cipherbox/crypto` module resolution failures (stale/missing `packages/crypto/dist`, known cross-package dist-staleness issue), a couple of pre-existing `ipns.service.ts` null-narrowing errors, and an `HttpArgumentsHost` import mismatch in `http-metrics.interceptor.spec.ts`. None reference `shares.service.ts`/`shares.service.spec.ts`. Out of scope for this plan — not fixed.
