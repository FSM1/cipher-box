---
created: 2026-03-22T18:13:02.874Z
title: Investigate throttle bypass gap for per-endpoint Throttle decorators
area: api
files:
  - apps/api/src/common/guards/throttler-bypass.guard.ts
  - apps/api/src/ipns/ipns.controller.ts:39
  - apps/api/src/ipns/ipns.controller.ts:81
  - apps/api/src/ipns/ipns.controller.ts:123
  - apps/api/src/auth/auth.controller.ts:63
  - apps/api/src/auth/auth.controller.ts:182
  - apps/api/src/auth/auth.controller.ts:265
  - apps/api/src/auth/controllers/identity.controller.ts:123
  - apps/api/src/auth/controllers/identity.controller.ts:142
  - apps/api/src/auth/controllers/identity.controller.ts:195
  - apps/api/src/auth/controllers/identity.controller.ts:216
  - apps/api/src/device-approval/device-approval.controller.ts:31
---

## Problem

Load tests against local API show high error rates (23/60 uploads failed with 429, 146/174 folder ops failed) despite `BypassableThrottlerGuard` being active and `THROTTLE_BYPASS_SECRET` configured.

**Root cause identified:** The API has two layers of rate limiting:

1. **Controller-level `@UseGuards(ThrottlerGuard)`** — uses `BypassableThrottlerGuard` (bypass works here)
2. **Per-endpoint `@Throttle()` decorators** — override the default limits with stricter per-endpoint caps

The `@Throttle()` decorator configures limits that the `ThrottlerGuard` enforces. Since `BypassableThrottlerGuard` extends `ThrottlerGuard` and short-circuits in `canActivate()` before the parent checks limits, the bypass **should** work for both layers. However, the load test still shows 429s on IPNS publish — this needs investigation.

**Possible explanations:**

1. The `@Throttle` limits are being enforced by a different mechanism (unlikely — NestJS throttler uses the guard for both)
2. The 429s originate from IPFS/Kubo itself, not the CipherBox API throttler (the IPNS publish makes external HTTP calls to the delegated routing service)
3. The bypass header isn't reaching the IPNS publish requests — the SDK's `createAndPublishIpnsRecord` calls through the api-client axios singleton which should have `defaultHeaders`, but this needs verification
4. The per-endpoint `@Throttle` decorator overrides the guard class entirely (unlikely but check NestJS throttler internals)

**IPNS publish endpoint limits (the bottleneck):**

- `POST /ipns/publish` — 10 per minute per user
- `POST /ipns/publish-batch` — 5 per minute per user
- `GET /ipns/resolve` — 30 per minute per user

Each SDK `uploadFile` triggers: 1 IPFS add + 1 IPNS publish (file metadata) + 1 IPNS publish (folder metadata) = 2 IPNS publishes per upload. With 3 concurrent clients doing 20 uploads each, that's 120 IPNS publishes — far exceeding 10/min even per-user.

**Other per-endpoint `@Throttle` limits:**

- `POST /auth/login` — 10 per 60s
- `DELETE /auth/account` — 3 per 60s
- `POST /auth/test-login` — 5 per 15min (blocks rapid account creation in load tests)
- `POST /identity/email/send-otp` — 5 per 15min
- `POST /identity/email/verify-otp` — 5 per 15min
- `GET /identity/wallet/nonce` — 10 per 60s
- `POST /identity/wallet` — 5 per 15min
- `POST /device-approval/request` — 3 per 60s

## Solution

### Step 1: Verify bypass header reaches IPNS publish

Add temporary logging in `BypassableThrottlerGuard.canActivate()` to confirm the header is present on IPNS publish requests. If the header is missing, the issue is in the axios `defaultHeaders` propagation.

### Step 2: Check if 429 comes from API or upstream

Inspect the 429 response body — the CipherBox API throttler returns `{"statusCode":429,"message":"ThrottlerException: Too Many Requests"}`. If the response body is different, the 429 comes from IPFS/Kubo or the mock IPNS routing service.

### Step 3: Fix the bypass gap

If the bypass works at the guard level but `@Throttle` overrides it, the fix is to make `BypassableThrottlerGuard.handleRequest()` also short-circuit (not just `canActivate()`). Alternatively, `@Throttle` just sets metadata that the guard reads — if `canActivate()` returns `true` before calling `super`, the `@Throttle` metadata is never consulted.

### Step 4: Consider per-endpoint bypass behavior

Some `@Throttle` limits are security-critical (OTP send, account delete) and should NOT be bypassed even in tests. Others (IPNS publish) are infrastructure protection and should be bypassable. May need a mechanism to mark specific endpoints as bypass-eligible vs always-throttled.
