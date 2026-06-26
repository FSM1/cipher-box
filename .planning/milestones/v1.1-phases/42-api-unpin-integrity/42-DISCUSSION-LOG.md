# Phase 42: API unpin integrity - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-12
**Phase:** 42-api-unpin-integrity
**Areas discussed:** Non-owned unpin response, Ordering & reconciliation, BYO rows in refcount, Historical leaked data, Rate limiting, Response DTO, Web quota refresh, Upload/unpin race

---

## Non-owned unpin response

| Option                  | Description                                                                       | Selected |
| ----------------------- | --------------------------------------------------------------------------------- | -------- |
| No-op + audit log       | success:true, touch nothing; warn log + metric when CID exists under another user | ✓        |
| Uniform 403 + audit log | 403 for every no-row call (no existence oracle), same telemetry                   |          |
| Plain no-op success     | success:true, no telemetry                                                        |          |

**User's choice:** Silent 2XX no-op + audit log

**Notes:** User probed the threat model before deciding: how would an attacker know a CID, and is the endpoint public? Established: endpoint is JWT-only on the public API with open signup; CIDs are public identifiers (Kubo swarm port 4001 public with server profile → DHT provider records; IPNS resolves publicly; share recipients retain CIDs after revocation). User also asked for explicit downsides of the loud 403: oracle risk if 403/404 split, misleading semantics for benign double-delete races, monitoring conflation requiring the same audit check anyway, warn-log noise in the Phase 30 pipeline.

---

## Ordering & reconciliation

| Option                      | Description                                                         | Selected |
| --------------------------- | ------------------------------------------------------------------- | -------- |
| Row first, Kubo best-effort | Transactional row delete + refcount under per-CID lock, then pin/rm | ✓        |
| Kubo first, then row        | Physical unpin before bookkeeping                                   |          |

| Option                 | Description                                                             | Selected |
| ---------------------- | ----------------------------------------------------------------------- | -------- |
| Outbox + drift report  | Transactional pending_unpins + BullMQ retry + read-only pin-ls diff job | ✓        |
| Outbox only            | Transactional pending_unpins + retry job, no drift visibility           |          |
| Warn-log + metric only | No new table or job                                                     |          |

**User's choice:** Row first + outbox + drift report

**Notes:** User challenged whether the outbox eliminates the need for a pin-ls reconciliation job. Resolution: the outbox is airtight only if (a) the pending_unpins insert shares the transaction with the row delete, and (b) the refcount decision runs under a per-CID lock (Postgres advisory xact lock) — otherwise concurrent deleters of the same CID strand an untracked pin. The drift report is detection-only (never deletes) covering historical orphans and future bugs.

---

## BYO rows in refcount

| Option                 | Description                                                     | Selected |
| ---------------------- | --------------------------------------------------------------- | -------- |
| Count all rows equally | No schema change; advisory rows may delay pin/rm (self-healing) | ✓        |
| Add origin column      | Migration + per-mode origin assignment; advisory never gates    |          |

**User's choice:** Count all rows equally

**Notes:** Discussion established the BYO delete flow is broken in both directions today (external nodes never unpinned, advisory rows never removed); the new endpoint semantics fix the server side for free since Kubo "not pinned" is tolerated.

---

## Historical leaked data

| Option                       | Description                                              | Selected |
| ---------------------------- | -------------------------------------------------------- | -------- |
| One-shot backfill            | Diff non-BYO rows against Kubo pin ls, delete stale rows | ✓        |
| Report first, clean manually | Drift report lists stale rows; ops trigger deletion      |          |
| Skip                         | Forward fix only                                         |          |

**User's choice:** One-shot backfill (non-BYO users only)

---

## Rate limiting

| Option                        | Description                                                | Selected |
| ----------------------------- | ---------------------------------------------------------- | -------- |
| Global only + alert           | Keep 10/s global guard; Grafana alert on cross-user metric | ✓        |
| Generous long-window throttle | e.g. 20k/day dedicated @Throttle                           |          |
| Tight like register-cid       | 100/hr — breaks bulk deletes                               |          |

**User's choice:** Global only + alert

---

## Response DTO

| Option                   | Description                                              | Selected |
| ------------------------ | -------------------------------------------------------- | -------- |
| Keep opaque success:true | Identical response for all outcomes; no oracle           | ✓        |
| Add debug fields         | rowDeleted/kuboUnpinned/refsRemaining — leaks references |          |

**User's choice:** Keep opaque

---

## Web quota refresh

| Option                 | Description                                            | Selected |
| ---------------------- | ------------------------------------------------------ | -------- |
| Optimistic + reconcile | Local removeUsage + fetchQuota() authoritative refetch | ✓        |
| Refetch only           | Drop local decrement                                   |          |
| Leave web untouched    | Strictly apps/api phase                                |          |

**User's choice:** Optimistic + reconcile

---

## Upload/unpin race

| Option                       | Description                                                   | Selected |
| ---------------------------- | ------------------------------------------------------------- | -------- |
| Accept + document            | Cryptographically negligible; avoid hot-path Kubo verify      | ✓        |
| Close with lock + pin verify | Airtight; adds a Kubo call per upload (Phase 19.2 regression) |          |

**User's choice:** Accept + document

---

## Claude's Discretion

- Metric names/labels for audit telemetry and drift report (follow `cipherbox_*` conventions)
- `pending_unpins` schema and BullMQ job naming/scheduling
- Backfill script vehicle and batch sizing
- Severity split between "CID unknown" and "CID owned by another user" no-row logging

## Deferred Ideas

- Wire `provider.unpin` into BYO client delete flows (external nodes accumulate pins forever)
- Writable-share version-prune leak (`shared-write.ts:450` drops `prunedCids` without unpinning)
- Upload/unpin race hardening — revisit only if the drift report shows occurrences
