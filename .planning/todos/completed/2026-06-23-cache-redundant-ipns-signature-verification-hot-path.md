---
created: 2026-06-23T15:56:53.000Z
title: Investigate caching/short-circuiting redundant IPNS signature verification on the publish/resolve hot path
area: perf
severity: low
source: GitHub issue #549 (migrated to file-todo) — 2026-06-23 staging upload-throughput re-baseline
files:
  - apps/api/src/ipns/ipns.service.ts
---

## Context

A 2026-06-23 staging load-test re-baseline (`upload-throughput @ 50 clients`) found upload throughput
~10 ops/s vs the 15.10 ops/s Phase 19.2 baseline, on the same 2-vCPU staging box.

Root cause was investigated (see `docs/CAPACITY.md` §1.5 and PR #548): the regression is **per-operation
CPU cost, not op count or accumulated state**. Ruled out:

- **Object/pin count** — a GC (294,811 → 20,038 objects) and an account cleanup (pin set 17,880 → 308)
  both failed to move throughput.
- **Op count** — constant (3 pins + 2 IPNS publishes per upload; the per-file IPNS model predates the
  baseline).
- **Kubo version / someguy** — 0.40 → 0.42 gave no gain; someguy has run `SOMEGUY_DHT=accelerated`
  since before the baseline.

The cause is **IPNS signature verification + durability hardening added after the baseline**: #448
(IPNS signature storage + verification, 2026-04-04), #529 (signedRecord validation/verification
hardening), #543 (write-path durability hardening), #544 (verify-coverage chokepoint + CAS gate).
Every publish/resolve now performs Ed25519 verification + validation + durability fsync + CAS gating,
so each operation costs more CPU on a 2-core box.

## Opportunity

The API frequently **signs** an IPNS record on publish and then **verifies** records on the resolve
path — likely re-verifying records it just produced and persisted. Investigate caching or
short-circuiting redundant verification of records the API itself just signed/wrote (the DB is
authoritative), **without weakening the zero-knowledge integrity model**.

## Scope / questions

- Map where verification happens: the signed-record verify chokepoint from #544, `resolveRecord` in
  `apps/api/src/ipns/ipns.service.ts`, and the publish path.
- Profile the publish/resolve hot path to confirm the magnitude of the per-op verification cost.
- Propose a safe short-circuit, e.g. skip re-verifying DB-authoritative records this server just
  signed/persisted, while **still** verifying externally-sourced / DHT records (someguy resolves) and
  anything not produced by this server. Must not reduce integrity guarantees for untrusted inputs.
- Consider a short-TTL verified-record cache keyed by `(ipnsName, sequenceNumber, signature)`.

## Acceptance

A proposal (ideally with a measured per-op cost estimate and a prototype) that recovers verification
CPU on the publish/resolve hot path without weakening IPNS integrity verification of untrusted /
DHT-sourced records.

## References

- `docs/CAPACITY.md` §1.5 — re-baseline findings
- PR #548 — Kubo tuning + the writeup
- Hot-path PRs: #448, #529, #543, #544
