# Staging Load Tests: Throttle Bypass Not Working

## Date: 2026-03-29

## Context

Running SDK load tests (`tests/load/`) against staging with 200 concurrent clients.
All clients hit 429 ThrottlerException despite `THROTTLE_BYPASS_SECRET` being correctly configured.

## Investigation Findings

### What works

- **curl with bypass header**: 20 concurrent requests → all 200 OK
- **Node.js fetch with bypass header**: 20 concurrent requests → all 200 OK
- **CI load tests**: Work because `NODE_ENV=test` sets relaxed limits (200/sec, 2000/min)
- **Env vars visible**: `process.env.THROTTLE_BYPASS_SECRET` correct in Node child processes

### What doesn't work

- **vitest load test scenarios**: Hit 429s when creating accounts in batches of 5
- Only 10/200 accounts were created before throttle kicked in

### The throttle configuration gap

| Setting       | CI (`NODE_ENV=test`) | Staging (`NODE_ENV=staging`)   |
| ------------- | -------------------- | ------------------------------ |
| Short limit   | 200/sec              | 10/sec                         |
| Medium limit  | 2000/min             | 100/min                        |
| Bypass header | Works (but unneeded) | Should work, doesn't in vitest |

### The bypass guard (apps/api/src/common/guards/throttler-bypass.guard.ts)

```typescript
if (secret && process.env.NODE_ENV !== 'production') {
  const header = request.headers['x-throttle-bypass'];
  if (header && safeEqual(header, secret)) return true; // Skip throttling
}
return super.canActivate(context); // Normal throttle check
```

### Why CI doesn't need bypass

CI sets `NODE_ENV=test` → limits are 200/sec → effectively no throttle for 50-client tests.
The bypass header is sent but irrelevant since the high limits are never hit.

### Possible root causes (unresolved)

1. **Caddy reverse proxy rate limiting**: Caddy sits in front of the NestJS API on staging. If Caddy has its own rate limiter, the NestJS bypass guard never sees the request.
2. **Vitest worker thread env isolation**: If vitest's worker pool doesn't inherit parent env vars, `THROTTLE_BYPASS_SECRET` would be empty in the test-harness module.
3. **createTestAccount does 3 API calls per account**: test-login + publishVaultKeyBlob + vault/init. Batches of 5 = 15 concurrent requests. Even with bypass, this may overwhelm something.

### Architecture concern

`tests/sdk-e2e/src/fixtures/test-harness.ts` uses raw `fetch()` for auth flow instead of the `@cipherbox/api-client` package. The api-client handles auth headers, retries, and interceptors. Using it consistently would reduce surface area for header/config mismatches.

## Resolution Path

1. Add debug logging to test-harness fetch calls to confirm bypass header is being sent at runtime
2. Check Caddy config on staging VPS for rate limiting rules
3. Test with `NODE_ENV=test` on staging temporarily to isolate whether the issue is bypass vs limits
4. Consider migrating test-harness auth flow to use api-client package

## Key files

- `apps/api/src/common/guards/throttler-bypass.guard.ts` — bypass logic
- `apps/api/src/app.module.ts` — throttle limit config (lines 59-74)
- `tests/sdk-e2e/src/fixtures/test-harness.ts` — raw fetch with bypass header
- `tests/load/src/harness/client-pool.ts` — pool creation calling test-harness
- `.github/workflows/load-test.yml` — CI setup (NODE_ENV=test)
- `.github/workflows/deploy-staging.yml` — staging setup (NODE_ENV=staging)
