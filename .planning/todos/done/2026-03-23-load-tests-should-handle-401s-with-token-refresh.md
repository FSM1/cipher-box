---
created: 2026-03-23T21:50:00.000Z
title: Load tests should handle 401s with token refresh
area: testing
files:
  - tests/load/src/harness/client-pool.ts
  - tests/load/src/workloads/file-workload.ts
  - tests/sdk-e2e/src/fixtures/test-harness.ts
---

## Problem

At high concurrency (75-100 clients), load tests start failing with 401 errors partway through. This happens because JWT tokens expire during long-running test suites but the load test harness does not refresh them. A real client would handle the 401 by refreshing the token and retrying the request.

Observed during Phase 19.2 concurrency probe:

- 75 clients: 10 errors (mix of 401s, 500s, "Key wrapping failed", "Folder not loaded")
- 100 clients: widespread failures starting at file 16-17 per client
- Errors cascade: a 401 causes "Folder not loaded" on subsequent uploads because client state becomes inconsistent

## Solution

1. Add token refresh logic to the load test `PoolClient` — intercept 401 responses, re-authenticate via `/auth/test-login`, update the auth header, and retry the failed request
2. Handle "Folder not loaded" gracefully — reload folder metadata after auth refresh before retrying upload
3. This would allow testing at higher concurrency without auth-related noise, giving cleaner data on actual IPFS/Kubo bottlenecks
4. Consider a proactive refresh (e.g., refresh when token is within 60s of expiry) to avoid the 401 entirely
