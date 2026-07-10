# Deferred Items — Phase 71

All items originally deferred during execution were resolved during the ship review (PR #599).

## Resolved during ship

### Pre-existing `tsc --noEmit` errors (from Plans 71-08 / 71-05)

Fixed in this branch — `pnpm --filter @cipherbox/api exec tsc --noEmit` and
`tests/sdk-e2e` `tsc --noEmit -p tsconfig.json` both pass clean:

- `apps/api/src/ipns/ipns-verify-cache.spec.ts` (TS2352): cast the `IpnsService` instance
  via `unknown` before `Record<string, unknown>`.
- `apps/api/src/metrics/http-metrics.interceptor.spec.ts` (TS2724): `@nestjs/common` does
  not re-export `HttpArgumentsHost` from its package root — derive the type locally as
  `ReturnType<ExecutionContext['switchToHttp']>` instead of importing it.
- `tests/sdk-e2e/src/suites/bin-operations.test.ts` (TS18048 ×3): non-null assert the
  `.find(...)` results that are already `expect(...).toBeTruthy()`-guarded (lines 83/91/107).

(These were pre-existing, unchanged vs `origin/main`, and not CI-gated — the `pnpm typecheck`
gate excludes `apps/api tsc` — but were small enough to fix rather than carry.)
