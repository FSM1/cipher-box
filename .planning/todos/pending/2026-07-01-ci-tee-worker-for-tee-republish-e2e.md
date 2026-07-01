---
created: 2026-07-01T00:00:00.000Z
title: Provision a TEE worker in the CI sdk-e2e job so tee-republish runs in CI
area: ci
severity: low
files:
  - .github/workflows/ci.yml
  - tests/sdk-e2e/src/suites/tee-republish.test.ts
---

> Deferred from the Phase 67 ship. The `tee-republish` sdk-e2e suite is currently gated
> to LOCAL runs only (`describe.skipIf(!!process.env.CI)`) because CI's `sdk-e2e` job
> provisions neither a TEE worker (host :3002) nor a `cipherbox` DB (it uses
> `cipherbox_test` and does not export `DB_DATABASE` to the e2e step). The suite was
> verified locally as the documented publish gate (2/2 green), but CI cannot currently
> exercise the relay→TEE→DB round-trip.

## Problem

`tee-republish.test.ts` needs the full live stack (TEE worker, `cipherbox` DB, redis,
BullMQ). The CI `sdk-e2e` job (`.github/workflows/ci.yml` ~L368) only starts postgres
(`cipherbox_test`) + the API. So the round-trip regression is not CI-gated — only local.

## Proposed fix

Either:

1. Add a `tee-worker` service (simulator mode, `TEE_MODE=simulator`) to the `sdk-e2e` job,
   wire `TEE_WORKER_URL=http://localhost:3002` + `TEE_WORKER_SECRET` on the API, run the
   schedule-collapse migration, and export `DB_DATABASE` to the e2e step so the suite's
   `DB_CONFIG` points at the CI DB (and drop the `SKIP_TEE_LIVE` CI gate); or
2. Leave it local-only (current state) and document that the tee-republish round-trip is a
   local pre-merge gate for TEE/IPNS-lifecycle changes.

Option 1 makes the round-trip a durable CI gate; option 2 keeps CI lean. Decide based on
how often the TEE contract changes.
