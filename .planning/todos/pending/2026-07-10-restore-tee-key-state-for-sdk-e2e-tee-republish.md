---
created: 2026-07-10
title: Restore tee_key_state so sdk-e2e tee-republish suite passes locally
area: testing
files:
  - tests/sdk-e2e/src/suites/tee-republish.test.ts
  - apps/api/src/tee/tee.service.ts
---

## Problem

During the Phase 71 ship SDK E2E gate, the two `tee-republish.test.ts` cases (Test A:
same-CID/same-seq re-sign with later EOL; Test B: tombstoned name never re-signed) fail
with `tee_key_state is empty — ensure the TEE worker is running and has been initialised`.

Root cause is environmental, NOT a Phase 71 regression:
- The Phase 71 gate required a **DB reset** to apply the greenfield share-cutover migration
  (for the D-06 Test 21 live backstop). The reset wiped `tee_key_state`.
- On API restart the `TeeService` tried to re-sync from the tee-worker but got
  `epoch: undefined` from `/health` and a **401** from `GET :3002/public-key` (the
  tee-worker container is healthy but the API's `TEE_WORKER_SECRET` / epoch handshake did
  not repopulate `tee_key_state`).
- `tests/sdk-e2e/src/suites/tee-republish.test.ts` is **unchanged vs origin/main** and
  Phase 71 touched no TEE code. All other 103/105 sdk-e2e tests pass (rotation-crash-safety
  green after the D-05 forward-CAS-race fix).

## Solution

Follow the TEE-republish e2e stack recipe to repopulate `tee_key_state` before running the
suite:
- Ensure `apps/api/.env` `TEE_WORKER_SECRET` matches the `cipherbox-tee-worker` container's
  `TEE_WORKER_SECRET` (`${TEE_WORKER_SECRET:-dev-secret}` in docker/docker-compose.yml).
- Restart the tee-worker (simulator mode) so it generates/serves the current epoch key, then
  restart the API so `TeeService` syncs `tee_key_state.current_public_key` on init.
- Re-run `pnpm --filter @cipherbox/sdk-e2e test -- tee-republish` and confirm Tests A/B pass.

Environmental / testing-infra only — does not gate Phase 71 correctness.
