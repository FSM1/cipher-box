---
created: 2026-03-23T20:59:55.096Z
title: Investigate removal of mock-ipns-routing layer
area: api
files:
  - apps/api/.env:23
  - apps/api/src/ipns/delegated-routing.client.ts
  - tests/sdk-e2e/src/fixtures/test-harness.ts
---

## Problem

The `mock-ipns-routing` service (`localhost:3001`) was originally needed for local dev because there was no real delegated routing endpoint available. Now that someguy is properly configured and running on `<docker-host>:8190` as part of the Docker stack, the mock layer may be unnecessary.

The API `.env` was pointing to `http://localhost:3001` (mock) but has been switched to `http://<docker-host>:8190` (someguy) for load testing. If someguy works reliably for local dev, the mock-ipns-routing service, its startup scripts, and any related configuration can be removed to simplify the dev stack.

## Solution

1. Verify someguy on <docker-host>:8190 works reliably for all IPNS resolution scenarios (publish, resolve, batch)
2. Run SDK E2E tests against someguy instead of mock-ipns-routing to confirm compatibility
3. If stable: remove mock-ipns-routing from the codebase (service code, Docker config, dev setup docs)
4. Update `.env.example` to point to someguy by default
5. Update any CI workflows that start mock-ipns-routing
