---
created: 2026-03-29T12:08:47.961Z
title: Debug BYO-IPFS register-cid 400 errors on staging
area: api
files:
  - tests/load/src/workloads/byo-file-workload.ts
  - packages/sdk-core/src/pinning/pinata-provider.ts
  - apps/api/src/modules/ipfs/ipfs.controller.ts
---

## Problem

BYO-IPFS load tests against staging with Pinata provider: `byo-pin` succeeds (p50=718ms, 20/20 files pinned to Pinata) but `register-cid` and `ipns-publish` both return HTTP 400 from the CipherBox API.

The flow is: encrypt file → pin to Pinata → register CID with CipherBox API → publish IPNS. The Pinata pin works, but the CipherBox API rejects the subsequent CID registration.

Likely causes:

- Test accounts created by load harness may not have BYO mode configured in their vault metadata
- Staging API's BYO endpoint may expect parameters the load test workload doesn't send
- register-cid endpoint validation may reject CIDs from external providers

Discovered during Phase 34 load testing. Pinata JWT auth confirmed working
(direct upload test returned 200 with valid CID). Note: the capacity ceiling
baselines in `staging-byo-capacity-ceiling.json` show all pins failing with
403 -- those were captured while the Pinata free tier was exhausted. After
account cleanup, single-client pin succeeded (p50=718ms) but register-cid
still returned 400.

## Solution

1. Check what `register-cid` expects vs what `byo-file-workload.ts` sends — compare request body
2. Verify test accounts have BYO provider config in their IPNS metadata (the load harness may skip BYO config seeding)
3. Check staging API logs for the 400 error response body to get the specific validation failure
4. May need to add BYO config seeding step to `createByoClientPool` in client-pool.ts
