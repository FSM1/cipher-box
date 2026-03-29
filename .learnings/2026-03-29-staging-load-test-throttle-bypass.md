# Staging Load Tests: Running Multiple Tests Simultaneously Causes 429s

## Date: 2026-03-29

## Context

Running SDK load tests (`tests/load/`) against staging with 200 concurrent clients.
Initial runs hit 429 ThrottlerException, but investigation revealed the bypass mechanism works correctly.

## Root Cause

**Two load tests were launched simultaneously against the same staging instance** (sustained-load with 200 clients + BYO capacity ceiling with 50 clients). The combined load saturated the staging API. The throttle bypass header was being sent and accepted, but the server couldn't handle 250+ concurrent account creation flows.

## How We Confirmed

1. curl with bypass header: 20 concurrent -> all 200 OK
2. Node.js fetch with bypass header: 50 concurrent -> all 200 OK
3. vitest with `createClientPool(20)`: 20/20 in 4.7s
4. vitest with `createClientPool(50)`: 50/50 in 10.0s
5. Both tests together: 429s after ~10 accounts (server saturated)

The bypass header skips rate limiter **guards**, but doesn't make the server infinitely scalable. The staging VPS has finite resources.

## Rules

- **Never run multiple load test scenarios concurrently against staging** -- run them sequentially
- The `tests/load/.env` must be sourced before running: `set -a && source .env && set +a`
- vitest does NOT auto-load `.env` files -- env must be sourced in the shell

## Throttle Config Reference

| Setting       | CI (NODE_ENV=test) | Staging (NODE_ENV=staging) |
| ------------- | ------------------ | -------------------------- |
| Short limit   | 200/sec            | 10/sec                     |
| Medium limit  | 2000/min           | 100/min                    |
| Bypass header | Works (unneeded)   | Works (required)           |

## Key Files

- `apps/api/src/common/guards/throttler-bypass.guard.ts` -- bypass logic
- `apps/api/src/app.module.ts` -- throttle limit config (lines 59-74)
- `tests/sdk-e2e/src/fixtures/test-harness.ts` -- account creation with bypass header
- `tests/load/src/harness/client-pool.ts` -- pool creation (batches of 5)
- `tests/load/.env` -- staging load test configuration (not auto-loaded by vitest)
