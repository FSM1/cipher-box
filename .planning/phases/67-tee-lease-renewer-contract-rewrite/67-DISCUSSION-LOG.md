# Phase 67: TEE Lease-Renewer Contract Rewrite - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-01
**Phase:** 67-tee-lease-renewer-contract-rewrite
**Areas discussed:** Renewer contract (verify-in-enclave), Schedule collapse extent, Migration durability, TEE round-trip proof

---

## Renewer contract — verify in enclave?

| Option | Description | Selected |
|--------|-------------|----------|
| Verify in enclave | Relay sends marshaled signedRecord + encrypted key; TEE parses, verifies the Ed25519 signature against publicKeyFromIpnsName(ipnsName), asserts name↔key↔record-pubkey, re-signs same CID+seq with later EOL. Bundles @cipherbox/core IPNS verify into the worker. Holds against a compromised relay. | ✓ |
| Re-sign from canonical row | Relay reads ipns_records and passes latestCid/seq/signedRecord; TEE re-signs without independently verifying. Simpler, no core dep, but trusts the relay not to hand a forged tuple. | |

**User's choice:** Verify in enclave (Recommended)
**Notes:** The contract "cannot originate or repoint a CID" is only true if the TEE validates the incoming signature itself — re-signing a relay-read row relocates trust to the relay. §7.1 already lists `packages/core/src/ipns` in the enclave-contract blast radius, so the parse/verify dependency is sanctioned.

---

## Schedule collapse extent (TEE-03)

| Option | Description | Selected |
|--------|-------------|----------|
| Pure scheduler | Drop only the 4 duplicated columns; keep ipns_republish_schedule as nextRepublishAt/lastRepublishAt/consecutiveFailures/status/lastError; JOIN to ipns_records for signing inputs. | ✓ |
| Fold into ipns_records, drop table | Move scheduling metadata onto ipns_records, drop the schedule table. Maximal minimization but mixes churn-y retry/status state into the CAS-guarded canonical row. | |

**User's choice:** Pure scheduler (Recommended)
**Notes:** §6.3 explicitly offers both. Pure-scheduler keeps churn off the integrity-authoritative row; the only crypto-bearing duplicate (`encrypted_ipns_key`) is what gets dropped, satisfying the D-11 minimization lens without contaminating `ipns_records`.

---

## Migration durability / client recovery (§6.7-item-3)

| Option | Description | Selected |
|--------|-------------|----------|
| TEE guard + signal; defer client re-enroll | TEE refuses keys older than currentEpoch−1, re-wraps only to its own internally-derived currentEpoch, emits a "re-enroll required" signal; client re-wrap consumer rides Phase 68/69. | ✓ |
| Build client re-enroll path now | Implement the full client-side re-wrap recovery in Phase 67 too. Fuller durability now, but pulls 68/69 client work forward. | |

**User's choice:** TEE guard + signal; defer client re-enroll (Recommended)
**Notes:** §6.7 offers both alternatives. Deferral is safe — the 4-week × 2 epoch grace + greenfield means no key ages past `currentEpoch − 1` mid-milestone. Mirrors Phase 66 D-04 (schema/gate here, live caller defers).

---

## TEE round-trip proof (success criterion 4)

| Option | Description | Selected |
|--------|-------------|----------|
| Local docker + sdk-e2e | Add the worker to docker-compose.yml (simulator) + a new sdk-e2e round-trip asserting same-seq/same-CID/later-EOL; deterministic republish trigger. CI-regression-gated. | ✓ |
| Staging only | Prove on staging (already runs the worker). No local compose change, but manual and not CI-gated. | |
| Unmock unit + staging smoke | Unmock the signer in the Vitest unit suite + a staging smoke. Lighter, but never exercises the real client→relay→TEE→resolve round-trip. | |

**User's choice:** Local docker + sdk-e2e (Recommended) — locked after a testability question.
**Notes:** User asked whether the test would enforce its own scheduling on the relay to make the IPNS refresh fire at the right time. Resolved before locking: republish is a BullMQ `'republish'` queue whose `process()` calls `processRepublishBatch()`, and `getDueEntries()` selects `nextRepublishAt <= now`. The e2e (1) sets the schedule row's `nextRepublishAt` to the past (DB-poke, à la `bump-ipns-sequence.ts`) and (2) enqueues one job — determinism comes from the test, not the 6h cron. Planner research flag: the exact enqueue/trigger surface in `republish.module.ts`, the local-compose `TEE_WORKER_URL` wiring, and sourcing the marshaled record from `ipns_records`. De-risk fallback (if the round-trip proves brittle): unmock the signer in the tee-worker Vitest suite + a staging smoke.

---

## Todos Folded (cross-reference)

All three folded into scope:

- `2026-06-30-ipns-idempotent-same-seq-cid-equivocation.md` — same-seq CID equivocation; resolved by the lease-renewer contract (renewal path), client-path reconciliation flagged to planner.
- `2026-06-29-createsubfolder-tee-republish-wiring.md` (resolves_phase: 67) — wire `encryptedIpnsPrivateKey`/`keyEpoch` into the published record so subfolders enroll.
- `2026-06-24-harden-validity-type-and-vector-expiry-lockstep.md` — emit `ValidityType == 0` on the re-signed record; broader cross-layer verify hardening planner-scoped.

---

## Claude's Discretion

- Pre-publish tombstone/revoked gate (REQUIRED; factoring discretion) — today's only guard runs post-publish (`syncIpnsRecordSequence:390`), so it must move to batch selection + renewal CAS.
- Whether the EOL-only renewal reuses `upsertIpnsRecord`'s idempotent branch vs a dedicated renewal CAS (must be the same equality CAS).
- Shape of the "re-enroll required" signal; raw vs re-marshaled record sent to the TEE; internal migration factoring.

## Deferred Ideas

- Client re-enroll consumer → Phase 68/69.
- Broader cross-layer `ValidityType` verify hardening → planner-scoped, may defer.
- Client publish-path equal-seq CID equivocation tightening → may exceed scope.
- Richer `ipns_records` status enum → revisit only if needed.

---

## Verification note

Before CONTEXT.md was committed, the load-bearing code/spec facts were adversarially re-verified by a 6-cluster parallel refutation pass (18 claims). All confirmed against the live tree (2026-07-01), with two immaterial nuances: the encrypted-key duplicate uses a different column name per table (`encrypted_ipns_key` vs `encrypted_ipns_private_key`), and the CAS generation predicate is `generation <= CAST(:incoming AS bigint)`. Key sharpening finding: the existing tombstone guard runs post-publish, so a pre-publish gate is required.
