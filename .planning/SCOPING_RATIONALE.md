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

## Decision 2: rootFolderKey Migration to IPFS (Accepted with Permanent DB Fallback)

### Tradeoff

Moving `encryptedRootFolderKey` from the `vaults` table into an IPFS vault blob v2 achieves true zero-knowledge (server stores zero crypto material). However, this makes IPNS resolution a login-critical dependency.

### Mitigation

- DB copy of `encryptedRootFolderKey` retained as a **permanent fallback** — not removed after migration
- Phase 19 (IPNS reliability) is a prerequisite: IPNS must be reliable before rootFolderKey migration makes it login-adjacent
- Lazy migration on next folder metadata publish — no flag day, no forced re-login

### Why `encryptedRootIpnsPrivateKey` is deprecated separately

This column is **already redundant** — the root IPNS private key is deterministically derivable via HKDF from the user's secp256k1 key. Deprecating it is a cleanup, not a migration.

---

## Decision 3: BYO-IPFS Uses Server-Relay (Not Client-Direct)

### Tradeoff

Client-direct uploads to user's IPFS node would be simpler and reduce server load, but:

- CORS/connectivity issues with arbitrary IPFS endpoints
- Server-side quota tracking breaks (can't observe what wasn't relayed)
- **Optimistic concurrency breaks** — IPNS publishes must flow through the API for sequence number checks (BYO-06)

### Decision

Server-relay mode for v1.1. Client-direct deferred as BYO-08 to v1.2 for power users willing to accept the tradeoffs.

---

## Decision 4: Performance Baselines Split Across Two Phases

### Rationale

User requested client-side instrumentation and load testing scripts to understand scaling thresholds — not just server metrics.

Phase 18 (server-side Prometheus, before any changes) establishes the "before" picture. Phase 22 (client-side timing, k6 load tests, capacity docs) comes last because all features must be stable for meaningful baselines. This sandwiching ensures we can measure the impact of phases 19-21.

---

## Decision 5: Shares/Device Approvals Stay in PostgreSQL

### Why not IPFS

- **Shares** require query patterns incompatible with IPFS: filter by recipient, by status, by revocation state. Would need a CRDT inbox protocol.
- **Device approvals** are inherently transactional (approve/reject workflow with server-side validation).
- **Republish schedule** is a server-side cron concern.

### Deferred research

CRDT-based share discovery via IPNS inbox is tracked as a v1.2 research item (IPNS-05). See `todos/pending/2026-02-22-crdt-ipns-inbox-sharing.md`.

---

## Decision 6: IPNS PubSub and DNSLink Rejected

| Alternative          | Why rejected                                                                                                                  |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| **IPNS over PubSub** | Only works when publisher and resolver share PubSub peers. Not persistent. Doesn't scale to thousands of IPNS names per user. |
| **DNSLink**          | Requires DNS infrastructure per user. Propagation is slow. Incompatible with per-folder/per-file IPNS model.                  |

---

## Tables Not Migrated (v1.1)

For reference, these PostgreSQL tables remain and why:

| Table                     | Stays because                                                     |
| ------------------------- | ----------------------------------------------------------------- |
| `users`                   | Auth — indexed lookups by hashed identifier                       |
| `auth_methods`            | Auth — MFA factor storage                                         |
| `refresh_tokens`          | Auth — session management                                         |
| `folder_ipns`             | TEE keys, sequence numbers, republish scheduling (see Decision 1) |
| `ipns_republish_schedule` | Server-side cron scheduling                                       |
| `shares` / `share_keys`   | Query-heavy, needs CRDT inbox for IPFS (see Decision 5)           |
| `device_approvals`        | Transactional approve/reject workflow                             |
| `pinned_cids`             | Quota tracking (alternative needed before removal)                |

---

Documented from v1.1 scoping session, 2026-03-07
