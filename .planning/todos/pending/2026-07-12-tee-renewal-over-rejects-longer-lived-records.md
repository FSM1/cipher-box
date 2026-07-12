---
created: 2026-07-12T00:00:00.000Z
title: TEE renewal marks a healthy longer-lived IPNS record stale instead of skipping
area: tee-worker
severity: low
files:
  - apps/tee-worker/src/services/ipns-signer.ts
  - apps/tee-worker/src/routes/republish.ts
  - apps/api/src/republish/republish.service.ts
---

> Surfaced by Greptile (P1) on the Phase 76 PR (#610). The strictly-later-EOL throw is
> deliberate and tested (`ipns-signer.test.ts:145` asserts a 96h original lifetime is rejected)
> — this todo is the downstream-consequence refinement, NOT a bug in the invariant itself.

## Problem

`renewIpnsRecord` throws `EolRollbackError` whenever the new 48h EOL is not strictly later than
the existing record's validity (`ipns-signer.ts:77`). For a record whose existing EOL is
legitimately farther out than the 48h renewal window (e.g. a name published with a >48h
lifetime), every renewal throws → the republish route returns `success:false` → the API
increments the schedule failure count until the entry is marked stale — even though the record
is healthy and does not need renewal. In the worst case the API stops republishing a name that
then actually expires (data-availability regression).

Reachability today is narrow: TEE-managed records are minted with a fixed 48h lifetime, so
existing EOL is normally ≤48h and 6h renewals always advance. This only triggers if a name under
TEE management ever carries a >48h EOL.

## Suggested fix

Distinguish "existing EOL already ≥ prospective new EOL" (healthy — skip renewal, report
success, leave the valid record untouched) from a genuine rollback. Since both manifest as
`new <= existing`, the safe interpretation is: never publish a non-advancing record, but treat
the skip as a SUCCESS (record still valid) rather than a failure that accrues toward staleness.
Thread the skip signal through `routes/republish.ts` and `republish.service.ts` so the schedule
failure counter is not incremented. Add a unit + schedule-accounting test.
