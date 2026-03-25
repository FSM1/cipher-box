---
created: 2026-03-24T00:25:28.379Z
title: Fix bin IPNS name 404 resolution failure
area: api
files:
  - apps/api/src/ipns/ipns.service.ts
---

## Problem

IPNS resolution for a specific name (`k51qzi5uqu5dkxgkhr6l6lb70d6i1hakdbleq1sy54qx32wdsev3cca3cqioil`) returns 404 from `/ipns/resolve`. Discovered during phase 20 UAT. This appears to be the recycle bin IPNS name.

Server-side logs show:

- Delegated routing fails with "Unsupported wire type 4" for this name
- DB cache fallback also has no record, resulting in 404

The bin IPNS record was likely never published to delegated routing or the DB cache entry was lost/never created.

## Solution

1. Verify this is the bin IPNS name for the test account
2. Check if `initializeBin` properly publishes the initial IPNS record and creates the DB cache entry
3. May need a "repair bin" flow that re-publishes the IPNS record if the DB cache is missing
