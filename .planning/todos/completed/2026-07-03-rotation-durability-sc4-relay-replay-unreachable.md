---
created: 2026-07-03T00:00:00Z
title: Rotation-durability SC-4 unreachable — API DB-canonical resolve floors relay replay
area: api
files:
  - apps/api/src/ipns/ipns.service.ts
  - tests/web-e2e/tests/rotation-durability.spec.ts
source: 68.1-VERIFICATION.md (human-approved deferral, override 2 of 2), 68.1-28 SC-4 root-cause doc
---

## Problem

`rotation-durability.spec.ts` SC-4 (stale relay-replay after key rotation must be
rejected/survived) cannot be exercised: the API's `resolveRecord` path applies a
DB-canonical sequence floor, so a replayed stale IPNS record from the relay is
unreachable by construction — the test's attack precondition can never occur through
the API. Recorded as a human-approved deferral override in the Phase 68.1
verification (152/180 pass in isolation; SC-4 is the only true residual). Note: the
68.1-28 root-cause doc labels this "GAP-7", which collides with the shared-move
picker GAP-7 — tracked in session notes as GAP-8.

## Solution

Needs an API architecture decision first, then either:

- Decide the DB-canonical floor IS the durability guarantee → redesign SC-4 to
  assert the floor behavior directly (e.g. API-level test that a lower-sequence
  publish/resolve is rejected), and retire the relay-replay scenario; or
- Decide relay-replay must be survivable without the DB floor (e.g. degraded/DR
  mode) → make the code path reachable under a test flag and keep SC-4 as written.

Either way, un-defer the spec so the suite has zero expected failures.
