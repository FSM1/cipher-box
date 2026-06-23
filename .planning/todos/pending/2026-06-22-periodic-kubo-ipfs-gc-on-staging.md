---
created: 2026-06-22T22:01:24.000Z
title: Enable periodic Kubo IPFS garbage collection on staging
area: infra
severity: medium
source: GitHub issue #547 (migrated to file-todo) — 2026-06-22 staging load-test re-baseline regression
files:
  - docker/docker-compose.staging.yml
  - docker/docker-compose.yml
---

## Problem

A 2026-06-22 staging load-test re-baselining sweep (the `upload-throughput`, `mixed-workload`,
and `sustained-load` scenarios from `tests/load/`, run via the `Load Tests` workflow against
`api-staging.cipherbox.cc`) found upload throughput ~halved and p50/p95 ~doubled vs the Phase 19.2
staging baseline.

**Root cause:** Kubo IPFS datastore bloat. The repo had grown to 6.2 GB / 294,811 objects, but only
~489 MB / 17,875 CIDs were actually pinned/live — ~93% was unpinned garbage accumulated from months
of load-test churn (create then delete leaves orphaned blocks until GC). The oversized pebbleds store
exceeded Kubo's 2 GB memory cap, pushing pins to disk: server-side pin mean latency 1.37s → 3.02s
(+120%), which halved upload throughput.

## Immediate remediation (already done)

Ran `ipfs repo gc` on staging — 294,811 → 20,038 objects, on-disk 5.9 GB → 2.5 GB.

## Action — make GC recurring so this can't silently recur

Pick one:

1. Kubo daemon auto-GC — set `Datastore.GCPeriod` (e.g. `1h`) and run the daemon with `--enable-gc`,
   wired via the `ipfs` service in `docker/docker-compose.staging.yml` (and `docker/docker-compose.yml`
   for parity).
2. Cron a `docker compose exec -T ipfs ipfs repo gc --silent` on the VPS.

Already done (PR #548): Kubo's mem cap was raised 2 GB → 3 GB — both
`docker/docker-compose.staging.yml` (ipfs service) and `docker/docker-compose.yml` set `memory: 3G`.
No further mem-cap action needed unless the 3 GB store is again exceeded.

Also consider:

- Load-test hygiene: the load harness generates most of this garbage. GC before/after baseline runs,
  or have the harness clean up its test accounts' content (it deletes accounts but blocks linger
  until GC).
- Minor: `cipherbox_drift_orphaned_pins_total` = 39 (Kubo pins not tracked in DB) — tighten the
  unpin → GC reconciliation.

## References

- PR #548 — Kubo tuning + the staging-perf writeup
- `docs/CAPACITY.md` §1.5 — re-baseline findings
