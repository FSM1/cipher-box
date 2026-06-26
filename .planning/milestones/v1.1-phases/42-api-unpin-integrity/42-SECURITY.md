---
phase: 42
slug: api-unpin-integrity
status: verified
threats_open: 0
asvs_level: 1
created: 2026-06-13
---

# Phase 42 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
| -------- | ----------- | ------------- |
| authenticated caller → `guardedUnpin(userId, cid)` | `userId` from verified JWT; `cid` is an untrusted public identifier — knowing it must not confer deletion authority | userId (trusted), cid (untrusted) |
| client → `POST /ipfs/unpin` | `req.user.id` from JWT is the sole authority; `dto.cid` is client-supplied and untrusted | bearer token, cid |
| `guardedUnpin` → Postgres transaction | concurrent deleters of a deduped CID race on refcount; serialized by advisory lock | row ownership, refcount |
| `guardedUnpin` / drain → Kubo pin/rm | external service; post-commit, best-effort, idempotent | cid (no key material) |
| browser → API `/vault/quota` | client reads its own authoritative quota; no write, no key material | usedBytes/limitBytes (own user only) |
| drift report → Kubo pin/ls | read-only enumeration of server pins; no write authority | cid list (read-only) |
| operator → backfill script | human runs ad-hoc; holds DB delete authority over `pinned_cids` (non-BYO only) | DELETE authority |
| migration runner → Postgres | additive-only DDL applied to live schema | DDL (IF NOT EXISTS) |
| Prometheus scrape → Grafana alert | aggregate counter rate consumed by an alert | unlabeled counts only (no CID/userId) |

---

## Threat Register

| Threat ID | Category | Component | Disposition | Mitigation | Status |
| --------- | -------- | --------- | ----------- | ---------- | ------ |
| T-42-01 | Tampering | DB migrations | mitigate | Additive-only DDL (`CREATE/DROP ... IF [NOT] EXISTS`), no ALTER/delete; `down()` drops only new objects — `migrations/*-AddPendingUnpins.ts`, `*-AddPinnedCidCidIndex.ts` | closed |
| T-42-02 | Information Disclosure | Prometheus counters | accept | Unlabeled aggregate counts; no CID/userId/key on `/metrics` | closed |
| T-42-03 | Denial of Service | entity registration | mitigate | `PendingUnpin` registered in `app.module.ts` entities array (no boot-time `EntityMetadataNotFoundError`) — `app.module.ts:26,101` | closed |
| T-42-04 | Information Disclosure | quota reconcile | accept | `/vault/quota` returns only the caller's own usage; bearer-authenticated | closed |
| T-42-05 | Denial of Service | `fetchQuota` reconcile blocking delete | mitigate | Fire-and-forget `void fetchQuota().then(...)`; `fetchQuota` never rejects, so the delete flow is unaffected — `delete.service.ts:24-26` | closed |
| T-42-06 | Tampering | cross-tenant unpin via CID knowledge | mitigate | Ownership check `findOne({ userId, cid })` before any Kubo/quota path; no-row path touches nothing — `vault.service.ts:265` | closed |
| T-42-07 | Information Disclosure | CID-existence oracle | mitigate | `guardedUnpin` returns void on all no-row sub-cases; controller returns constant `{ success: true }`; cross-user signal only in telemetry — `vault.service.ts:272`, `ipfs.controller.ts:154` | closed |
| T-42-08 | Tampering | refcount race (premature/double global pin/rm) | mitigate | `pg_advisory_xact_lock(abs(hashtext($1)::bigint))` as first txn statement; `orIgnore()` dedupes outbox insert — `vault.service.ts:262,292` | closed |
| T-42-09 | Denial of Service | quota inflation via failed deletes | mitigate | Row delete (= quota decrement) committed in-txn; Kubo pin/rm post-commit best-effort, never rolls back the credit — `vault.service.ts:276,301-308` | closed |
| T-42-10 | Denial of Service | BYO advisory row blocking foreign unpin | accept | Equal-refcount semantics: a BYO row can only over-retain a pin, never force a pin/rm; self-heals on BYO delete | closed |
| T-42-11 | Tampering | upload/unpin race leaving row-but-no-pin | accept | Requires identical ciphertext + sub-second window (cryptographically negligible); drift report detects (D-13) | closed |
| T-42-12 | Tampering | migration applied to wrong DB | mitigate | Runs against dev DataSource only; additive `IF NOT EXISTS` makes re-application a no-op | closed |
| T-42-13 | Denial of Service | partially-applied migration | mitigate | `up()` idempotent (`IF NOT EXISTS`); `down()` drops only new objects | closed |
| T-42-14 | Tampering | cross-tenant unpin at HTTP boundary | mitigate | `unpin()` forwards `req.user.id` to `guardedUnpin`; no controller path reaches raw `ipfsProvider.unpinFile` — `ipfs.controller.ts:152-154` | closed |
| T-42-15 | Information Disclosure | response-shape oracle | mitigate | `unpin()` returns the constant `{ success: true }` for every outcome; no `refsRemaining`/status field — `ipfs.controller.ts:154` | closed |
| T-42-16 | Elevation of Privilege | compensation path bypassing ownership | mitigate | Upload rollback routes through `guardedUnpin` (ownership + refcount); `{ suppressCrossUserAudit: true }` only mutes telemetry, not the checks — `ipfs.controller.ts:128-130` | closed |
| T-42-17 | Repudiation | quota double-count | mitigate | `fileUnpins.inc()` lives solely in `guardedUnpin`; controller never increments — `vault.service.ts:310` | closed |
| T-42-18 | Tampering | drift report auto-GC destroying pins | mitigate | `runDriftReport` is strictly read-only — counter inc + warn log only, no `.delete`/pin rm path — `pending-unpin.processor.ts:72-101` | closed |
| T-42-19 | Denial of Service | outbox row never drained | accept | Stuck row over-retains disk only, never destroys content; self-heals; gauge surfaces queue depth | closed |
| T-42-20 | Denial of Service | poisoned retry queue (BYO "not pinned") | mitigate | Drain calls `ipfsProvider.unpinFile`, which swallows "not pinned" → row deleted, not retried forever — `pending-unpin.processor.ts:57-58` | closed |
| T-42-21 | Information Disclosure | NDJSON parse failure crashing drift job | mitigate | `pin/ls` fetch wrapped in try/catch with `AbortSignal.timeout(30s)`; per-line parse tolerance; outage logs and skips — `pending-unpin.processor.ts:109-142` | closed |
| T-42-22 | Tampering | backfill deleting legitimate BYO rows | mitigate | Candidate query filters `vaults.is_byo_user = false` AND `selectRowsToDelete` re-asserts `isByoUser === false` — `backfill-pinned-cids.ts:135`, `backfill-helpers.ts:30` | closed |
| T-42-23 | Denial of Service | empty/unreachable Kubo wiping all rows | mitigate | Failed `pin ls` fetch or empty set aborts with `exit(1)` and zero deletes before any DELETE — `backfill-pinned-cids.ts:94,105,116` | closed |
| T-42-24 | Tampering | accidental destructive default run | mitigate | Loud MODE banner; `--dry-run` previews; deletes id-scoped (`WHERE id = ANY`), never blanket `DELETE FROM` — `backfill-pinned-cids.ts:66-73,176` | closed |
| T-42-25 | Information Disclosure | DB credentials leaked in error output | mitigate | Reuses the `run-migrations.ts` secret-redacting error handler (`host\|password\|user(name)=` masked) — `backfill-pinned-cids.ts:210` | closed |
| T-42-26 | Information Disclosure | alert leaking sensitive identifiers | accept | Alert reads an unlabeled aggregate counter rate only (no CID/userId) | closed |
| T-42-27 | Repudiation | abuse going unnoticed without a throttle | mitigate | Grafana alert on `cipherbox_unpin_cross_user_attempts_total` rate provides the abuse-visibility path (D-10) — `docker/grafana/alerts/unpin-cross-user-attempts.json:26,42` | closed |
| T-42-28 | Tampering | hardcoded datasource/folder UIDs breaking provisioning | mitigate | Alert keeps `GRAFANA_*` placeholder UIDs for per-env substitution at provision time — `unpin-cross-user-attempts.json:5,24,36` | closed |
| T-42-SC | Tampering | supply chain (npm/pip/cargo installs) | accept | Zero new dependencies introduced across all 8 plans (RESEARCH Package Legitimacy Audit) | closed |

_Status: open · closed_
_Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)_

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
| ------- | ---------- | --------- | ----------- | ---- |
| AR-42-01 | T-42-02 | Unlabeled aggregate counters only; no CID/userId/key material on `/metrics` | Phase 42 plan (42-01) | 2026-06-13 |
| AR-42-02 | T-42-04 | `/vault/quota` returns only the authenticated caller's own usage | Phase 42 plan (42-02) | 2026-06-13 |
| AR-42-03 | T-42-10 | BYO refcount can only over-retain a pin, never force a pin/rm; self-heals | Phase 42 plan (42-03) | 2026-06-13 |
| AR-42-04 | T-42-11 | Upload/unpin row-no-pin race cryptographically negligible; drift report detects (D-13) | Phase 42 plan (42-03) | 2026-06-13 |
| AR-42-05 | T-42-19 | Outbox stuck row over-retains disk only; self-heals; gauge surfaces depth | Phase 42 plan (42-06) | 2026-06-13 |
| AR-42-06 | T-42-26 | Alert reads an unlabeled aggregate counter rate only | Phase 42 plan (42-08) | 2026-06-13 |
| AR-42-07 | T-42-SC | Zero new dependencies introduced across all 8 plans | Phase 42 plan (all) | 2026-06-13 |

_Accepted risks do not resurface in future audit runs._

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
| ---------- | ------------- | ------ | ---- | ------ |
| 2026-06-13 | 29 | 29 | 0 | gsd-security-auditor (sonnet) |

Notes: 22 mitigate-disposition threats verified present in the committed implementation (branch `feat/api-unpin-integrity`); 7 accepted risks confirmed on record. Several mitigations were refactored after the original plan (advisory-lock merged into one inline statement; `fetchQuota` boolean contract; `AbortSignal.timeout` on the Kubo fetch; `suppressCrossUserAudit` on the upload-rollback compensation) — the current code was verified to still satisfy each threat's intent.

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-06-13
