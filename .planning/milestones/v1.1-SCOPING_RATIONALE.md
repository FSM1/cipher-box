# Scoping Rationale: CipherBox v1.1 IPFS Infrastructure

**Documented:** 2026-03-07
**Context:** Captures key decisions, tradeoffs, and rejected alternatives from the v1.1 scoping discussion.

---

## Milestone Vision

The original goal was "make the database auth-only" — move everything possible from PostgreSQL to IPFS/IPNS so the server becomes a pure relay. The scoping discussion revealed this is **aspirational for v1.1 but not fully achievable** due to hard dependencies on server-side state.

**Realistic v1.1 outcome:** Migrate vault crypto material off DB, improve IPNS reliability via self-hosting, add BYO-IPFS for data sovereignty, and establish performance baselines. The database remains authoritative for auth, conflict detection, TEE key storage, and share management.

---

## Decision 1: `folder_ipns` Stays Authoritative (Not Advisory)

### What was considered

Making `folder_ipns` "advisory" — IPNS resolution via self-hosted Someguy becomes the primary source of truth, with the DB demoted to a performance cache.

### What `folder_ipns` does today (6 roles)

1. **CID cache** — `latestCid` stores the most recent CID per IPNS name. Fallback when network resolution fails.
2. **Sequence number tracking** — `sequenceNumber` is the authoritative counter for optimistic concurrency. The API checks `expectedSequenceNumber` against the DB value and returns 409 Conflict on mismatch.
3. **TEE key storage** — `encryptedIpnsPrivateKey` + `keyEpoch` hold IPNS private keys wrapped with TEE public key for republishing.
4. **TEE republish scheduling** — The republish cron queries `folder_ipns` to find records needing republishing.
5. **User folder enumeration** — `getAllFolderIpns(userId)` lists all IPNS names for a user.
6. **Resolve fallback** — `resolveRecord()` checks both network AND DB, preferring whichever has the higher sequence number (`ipns.service.ts:326-336`).

### Why "advisory" was rejected

Three of the six roles have **hard blocking dependencies** on server-side state:

- **TEE republishing** needs `encryptedIpnsPrivateKey` from this table. No alternative server-side storage exists. This column must stay.
- **Optimistic concurrency** requires atomic sequence number comparison in PostgreSQL. Moving to "resolve IPNS first, then compare" introduces race conditions — two clients resolve the same stale value, both think they're current. The DB check is inherently stronger.
- **Republish scheduling** queries this table to find what needs republishing.

The practical gain would be small: `latestCid` already works as a "best-of-both" cache (picks the fresher source). Switching from "DB fallback" to "IPNS primary" is essentially reordering the resolution chain, which the Someguy self-hosting already improves.

### Decision

Skip advisory `folder_ipns` for v1.1. Deferred as IPNS-06 to v1.2 requirements. The Someguy self-hosting improves IPNS reliability enough that the DB fallback triggers less often. The table stays as-is — it's pulling its weight across all 6 roles.

---

## Decision 2: IPNS Resolution Keeps DB-First Strategy (Not DHT-First)

### The concession

A milestone called "IPFS Infrastructure" might suggest moving IPNS resolution to be DHT-primary — resolve via self-hosted Someguy/Kubo first, fall back to DB only on failure. The scoping discussion explicitly chose the opposite: **DB-first with async DHT verification**.

### Current flow (before v1.1)

```text
resolveRecord()
  -> DelegatedRoutingClient.resolve() -> delegated-ipfs.dev (primary, 10s timeout)
  -> folder_ipns DB query (fallback on 502/timeout)
  -> Compare sequence numbers, return highest
```

### v1.1 flow (IPNS-02)

```text
resolveRecord()
  -> folder_ipns DB query (primary, <5ms)
  -> Return DB result immediately to caller
  -> Async: Kubo DHT resolve via self-hosted Someguy (background)
     -> If DHT has higher sequence number, update DB cache
     -> If DHT fails, no-op (DB is authoritative for our own records)
```

### Why DB-first instead of DHT-first

1. **Latency:** DB query completes in <5ms. DHT resolution, even self-hosted, has a median of 0.3-0.4s (ProbeLab data) and a long tail. Users should never wait for the DHT on the hot path.
2. **DB is already correct for our own records.** Every publish writes to `folder_ipns` atomically. The DB always has the latest CID that _we_ published. The only scenario where DHT has a fresher value is if another node published for the same IPNS name — which doesn't happen in CipherBox's architecture.
3. **Graceful degradation is free.** If Someguy/Kubo is down, nothing changes — the DB result is already returned. No timeout, no retry, no user-visible degradation (IPNS-04).
4. **Async verification catches staleness.** The background DHT check is a consistency audit, not a user-facing operation. If a TEE republish advanced the sequence number and the DB hasn't caught up, the async check self-heals.

### What this means for "IPFS-native"

This is a pragmatic concession: the DB remains the primary source of truth for IPNS resolution, not IPFS. The milestone improves IPNS _infrastructure_ (self-hosting, reliability) without making it the _authority_. True DHT-primary resolution is deferred to v1.2 (IPNS-06: folder_ipns CID cache made advisory) and depends on proving Someguy reliability at scale.

---

## Decision 3: rootFolderKey Migration to IPFS (Accepted with Permanent DB Fallback)

### Tradeoff

Moving `encryptedRootFolderKey` from the `vaults` table into an IPFS vault blob v2 achieves true zero-knowledge (server stores zero crypto material). However, this makes IPNS resolution a login-critical dependency.

### Mitigation

- DB copy of `encryptedRootFolderKey` retained as a **permanent fallback** — not removed after migration
- Phase 19 (IPNS reliability) is a prerequisite: IPNS must be reliable before rootFolderKey migration makes it login-adjacent
- Lazy migration on next folder metadata publish — no flag day, no forced re-login

### Why `encryptedRootIpnsPrivateKey` is deprecated separately

This column is **already redundant** — the root IPNS private key is deterministically derivable via HKDF from the user's secp256k1 key. Deprecating it is a cleanup, not a migration.

---

## Decision 4: BYO-IPFS Uses Server-Relay (Not Client-Direct)

### Tradeoff

Client-direct uploads to user's IPFS node would be simpler and reduce server load, but:

- CORS/connectivity issues with arbitrary IPFS endpoints
- Server-side quota tracking breaks (can't observe what wasn't relayed)
- **Optimistic concurrency breaks** — IPNS publishes must flow through the API for sequence number checks (BYO-06)

### Decision

Server-relay mode for v1.1. Client-direct deferred as BYO-08 to v1.2 for power users willing to accept the tradeoffs.

---

## Decision 5: Performance Baselines Split Across Two Phases

### Rationale

User requested client-side instrumentation and load testing scripts to understand scaling thresholds — not just server metrics.

Phase 18 (server-side Prometheus, before any changes) establishes the "before" picture. Phase 22 (client-side timing, k6 load tests, capacity docs) comes last because all features must be stable for meaningful baselines. This sandwiching ensures we can measure the impact of phases 19-21.

---

## Decision 6: Shares/Device Approvals Stay in PostgreSQL

### Why not IPFS

- **Shares** require query patterns incompatible with IPFS: filter by recipient, by status, by revocation state. Would need a CRDT inbox protocol.
- **Device approvals** are inherently transactional (approve/reject workflow with server-side validation).
- **Republish schedule** is a server-side cron concern.

### Deferred research

CRDT-based share discovery via IPNS inbox is tracked as a v1.2 research item (IPNS-05). See `todos/pending/2026-02-22-crdt-ipns-inbox-sharing.md`.

---

## Decision 7: IPNS PubSub and DNSLink Rejected

| Alternative          | Why rejected                                                                                                                  |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| **IPNS over PubSub** | Only works when publisher and resolver share PubSub peers. Not persistent. Doesn't scale to thousands of IPNS names per user. |
| **DNSLink**          | Requires DNS infrastructure per user. Propagation is slow. Incompatible with per-folder/per-file IPNS model.                  |

---

## Tables Not Migrated (v1.1)

For reference, these PostgreSQL tables remain and why:

| Table                     | Stays because                                                        |
| ------------------------- | -------------------------------------------------------------------- |
| `users`                   | Auth — indexed lookups by hashed identifier                          |
| `auth_methods`            | Auth — MFA factor storage                                            |
| `refresh_tokens`          | Auth — session management                                            |
| `folder_ipns`             | TEE keys, sequence numbers, republish scheduling (see Decisions 1-2) |
| `ipns_republish_schedule` | Server-side cron scheduling                                          |
| `shares` / `share_keys`   | Query-heavy, needs CRDT inbox for IPFS (see Decision 6)              |
| `device_approvals`        | Transactional approve/reject workflow                                |
| `pinned_cids`             | Quota tracking (alternative needed before removal)                   |

---

Documented from v1.1 scoping session, 2026-03-07
