---
phase: 71
slug: share-invite-security-and-ipns-data-integrity-api
status: audited
nyquist_compliant: true
wave_0_complete: true
created: 2026-07-09
audited: 2026-07-10
---

# Phase 71 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Derived from `71-RESEARCH.md` § Validation Architecture. Anchored to Success
> Criteria SC#1–SC#6 (SC#3 amended per D-03) and decisions D-01…D-09 — this is a
> todo-driven phase with no mapped REQ-IDs (`phase_req_ids: null`).
>
> **Retroactive audit (2026-07-10):** All rows below were confirmed against the
> actual, executed spec/e2e files post-implementation (static read, no new tests
> written — none were needed). 0 gaps. See "Audit Findings" below.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Jest (`ts-jest`) for `apps/api` unit tests; Vitest for `tests/sdk-e2e` integration |
| **Config file** | `apps/api/jest.config.js` (rootDir `src`, testRegex `.*\.spec\.ts$`, coverage 85% lines/stmt/fn, 78% branch); `tests/sdk-e2e/vitest.config.ts` |
| **Quick run command** | `pnpm --filter @cipherbox/api test -- --testPathPattern="share-invite\|shares\.service\|ipns\.service"` |
| **Full suite command** | `pnpm --filter @cipherbox/api test` (unit — all repos/DataSource mocked, no live services) |
| **Live-stack suite** | `pnpm --filter sdk-e2e test` (D-06 first-publish race — REQUIRES `docker compose -f docker/docker-compose.yml up -d` + `pnpm --filter @cipherbox/api dev` + `migration:run`) |
| **Estimated runtime** | ~seconds (unit); minutes + manual bootstrap (sdk-e2e) |

> Note: `apps/api` Jest coverage thresholds are **global** (85% lines); there is **no** per-file
> threshold on `share-invite.service.ts`. D-09's coverage lift is a completeness goal, not a
> CI-gating one.

---

## Sampling Rate

- **After every task commit:** `pnpm --filter @cipherbox/api test -- --testPathPattern=<touched-file-basename>`
- **After every plan wave:** `pnpm --filter @cipherbox/api test` (full unit suite, ~seconds, no live services)
- **Before `/gsd-verify-work`:** Full `apps/api` unit suite green (primary gate)
- **Max feedback latency:** ~30s (unit); sdk-e2e first-publish case is a `checkpoint:human-verify` item if the executor cannot start the live stack autonomously

---

## Per-Task Verification Map

> Task IDs are filled during planning/execution. Behavior→test rows below come from
> `71-RESEARCH.md` and MUST each be represented by a plan task's `<acceptance_criteria>`/`<verify>`.

| SC / Decision | Secure Behavior | Test Type | Automated Command | File / Location | Status |
|---------------|-----------------|-----------|-------------------|-------------|--------|
| SC#1 / D-01 | `createInvite` rejects when sharer does not own `rootIpnsName` (vault lookup) | unit | `… --testPathPattern=share-invite.service` | `share-invite.service.spec.ts:147` `describe('createInvite — root-ownership gate (D-01/SC#1)')` — throws `ForbiddenException` | ✅ green |
| SC#1 / D-01 | `createInvite` succeeds when sharer owns the root (positive) | unit | same | `share-invite.service.spec.ts:156` — persists when caller is registered owner | ✅ green |
| SC#1 / D-01 | `SharesService.createShare` rejects when sharer does not own `shareRootIpnsName` (direct-share path) | unit | `… --testPathPattern=shares.service` | `shares.service.spec.ts:131` — `throws ForbiddenException … (D-01/SC#1)` | ✅ green |
| SC#2 / D-07 | Re-claim with write invite over read-only share upgrades `encryptedWriteKey` | unit | `… --testPathPattern=share-invite.service` | `share-invite.service.spec.ts:335` `read→write widen upgrades the existing share and calls manager.save` | ✅ green |
| SC#2 / D-07 | Re-claim with lower/equal invite is a no-op (no downgrade) | unit | same | `share-invite.service.spec.ts:313` `same-level re-claim is a no-op` | ✅ green |
| SC#2 / D-07 | **Backstop:** a write-capable share is NEVER downgraded by any non-widening re-claim | unit (negative assertion) | same | `share-invite.service.spec.ts:384` `BACKSTOP: a read-only re-claim over a write-capable share never downgrades encryptedWriteKey` | ✅ green |
| SC#3 / D-04 | DB rejects out-of-bounds `claim_count` even if app code bypassed | live Postgres (documented, non-Jest) | live `UPDATE … claim_count=-1` inside `BEGIN…ROLLBACK` | `71-VERIFICATION.md:32` — executed against running `cipherbox-postgres`, raised `23514 check_violation` on `CHK_share_invites_claim_count`; rolled back, zero residual rows. Migration `1750000000000-ApiSchemaCutover.ts` (CHECK constraint) + `share-invite.entity.ts:13` (`@Check`) confirm the constraint is wired. | ✅ green (documented manual, executed) |
| SC#4 / D-05 | Same-seq + different-CID republish → 400 | unit | `… --testPathPattern=ipns.service` | `ipns.service.spec.ts:2122` `rejects same-seq republish with a DIFFERENT CID (D-05: equivocation)` | ✅ green |
| SC#4 / D-05 | Same-seq + SAME-CID republish still succeeds, seq unchanged | unit | same | `ipns.service.spec.ts:2144` `allows idempotent republish (embedded = DB seq, SAME CID) without incrementing DB sequenceNumber` | ✅ green |
| SC#4 / D-05 | **Backstop:** TEE lease-renewer never reaches `upsertIpnsRecord` same-seq branch | structural (documented) | — | `ipns.service.spec.ts:2111-2120` inline comment block documents `republish.service.ts renewIpnsRecordEol` never calls `upsertIpnsRecord`/`publishRecord` | ✅ green (documented) |
| SC#4 / D-06 | Concurrent first-publish of same new `ipnsName` → one 200 + one 409 | unit (mocked 23505) + sdk-e2e (real race) | unit `…ipns.service`; e2e `pnpm --filter sdk-e2e test -- ipns-publish-gate` | unit: `ipns.service.spec.ts:2261` `describe('first-publish INSERT-race translation (D-06/SC#4)')` — 23505→409, non-23505 rethrown unchanged. Live: `tests/sdk-e2e/src/suites/ipns-publish-gate.test.ts:367` `Test 21 (D-06)` — two concurrent real first-publishes, asserts exactly one fulfilled + one rejected(409), final resolved seq=1. Orchestrator evidence: live-passed. | ✅ green |
| SC#5 / D-08 | `revokeForItems` issues one DELETE, returns correct affected counts | unit | `… --testPathPattern=shares.service` | `shares.service.spec.ts:334` `describe('revokeForItems')` — single query-builder DELETE + transactional invite revoke, zero-count and undefined-affected edge cases covered | ✅ green |
| SC#6 / D-09 | `createInvite`/`getInvitesForItem`/`revokeInvite` covered with realistic fixtures | unit | `… --testPathPattern=share-invite.service --coverage` | `share-invite.service.spec.ts` — `describe('createInvite …')` L137, `describe('getInvitesForItem')` L411, `describe('revokeInvite')` L440, all with realistic UUID/hex fixtures | ✅ green |
| — / D-09 | `shares.controller.spec.ts` uses contract-valid UUIDs/keys (CodeRabbit NIT3) | unit | `… --testPathPattern=shares.controller` | `shares.controller.spec.ts:25` — secp256k1 hex pubkeys (`04` + 128 hex chars) mirroring share-invite fixtures | ✅ green |
| — / D-03 | Root-uniqueness index intentionally dropped (decision, not a coverage gap) | documented decision | — | `shares.controller.spec.ts:14-17` inline comment records the drop rationale (SC#3 amended); covered by vault uniqueness elsewhere, no test required | ✅ documented (no test needed) |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Audit Findings (retroactive, 2026-07-10)

All 7 audited dimensions have real, executed behavioral coverage. No gaps found — 0 tests were written or modified by this audit; static read of existing spec/e2e files was sufficient in every case.

| Dimension | Verdict |
|-----------|---------|
| D-01/SC#1 ownership gate (invite path) | Confirmed — `share-invite.service.spec.ts` reject (403) + accept |
| D-01/SC#1 ownership gate (direct-share path) | Confirmed — `shares.service.spec.ts:131` reject (403) |
| D-05/D-06 same-seq CID guard + first-publish race | Confirmed — `ipns.service.spec.ts` unit (mocked 23505→409, equivocation 400) AND `ipns-publish-gate.test.ts` Test 21 live concurrent race (real Postgres, one 200 + one 409); orchestrator-reported live pass treated as run evidence per task scope |
| D-07/SC#2 widen-only + never-downgrade backstop | Confirmed — `share-invite.service.spec.ts` widen-upgrade + no-op + explicit BACKSTOP negative-assertion test |
| D-08/SC#5 direct-DELETE bulk revoke | Confirmed — `shares.service.spec.ts:334` single-DELETE query-builder path, edge cases (empty list, zero-affected, undefined-affected) |
| D-09/SC#6 realistic-fixture coverage | Confirmed — `share-invite.service.spec.ts` 3 describe blocks (createInvite/getInvitesForItem/revokeInvite) + `shares.controller.spec.ts` contract-valid secp256k1 fixtures |
| D-04 CHECK constraint | Confirmed — migration + entity `@Check` (static) AND live psql `23514` evidence recorded in `71-VERIFICATION.md:32` (executed inside `BEGIN…ROLLBACK`, zero residual rows) |
| D-03 root-uniqueness index drop | Confirmed as DECISION not gap — documented in test fixture comments and `71-CONTEXT.md`; vault uniqueness is the substitute guard, no test obligation |

Run evidence relied upon (not re-run by this audit, per task instruction): `apps/api` Jest 894/894 green, `sdk-core` 363 + `sdk` 362 green, sdk-e2e Test 21 live-passed.

---

## Wave 0 Requirements

- [x] `share-invite.service.spec.ts` — `describe('createInvite')` (D-01 reject + accept), `describe('getInvitesForItem')`, `describe('revokeInvite')` (D-09); idempotent re-claim block with D-07 widen positive/negative cases (confirmed L137-467)
- [x] `ipns.service.spec.ts` — Pitfall-4 block rewritten → same-CID-succeeds + different-CID-rejects (D-05, L2122-2166); first-publish 23505→409 case (D-06, L2261-2299)
- [x] `shares.service.spec.ts` — `revokeForItems` tests use sequenced `execute` mocks (D-08, L334-390)
- [x] `shares.controller.spec.ts` — contract-valid secp256k1 hex fixtures (D-09, L25)
- [x] `tests/sdk-e2e/src/suites/ipns-publish-gate.test.ts` — Test 21 first-publish concurrent-race case (D-06, L367); the only test type proving the real Postgres unique-constraint race — live-passed per orchestrator evidence
- [x] D-04 CHECK constraint — documented live `psql`/transactional verification recorded in `71-VERIFICATION.md:32` (Jest mocks DataSource, so this stays a documented-manual step by design, not a gap)

---

## Manual-Only Verifications

| Behavior | SC / Decision | Why Manual | Test Instructions |
|----------|---------------|------------|-------------------|
| `claim_count` CHECK constraint enforcement | SC#3 / D-04 | `apps/api` Jest mocks the DataSource — no real DB in unit suite | On a migrated dev DB: `UPDATE share_invites SET claim_count = -1 WHERE id = '<uuid>'`, confirm Postgres `23514 check_violation`. Record in VERIFICATION.md if no integration harness is wired. |
| First-publish concurrent race (real DB) | SC#4 / D-06 | Genuine DB-level concurrency needs live Postgres | `docker compose up -d` + api dev + `migration:run`, then run the sdk-e2e first-publish case; treat as `checkpoint:human-verify` if the executor cannot bootstrap the stack. |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] Backstop edges (D-05 downgrade-never, D-07 downgrade-never, D-04 DB CHECK, D-06 real race) have explicit non-inferable coverage or a documented manual step
- [x] No watch-mode flags
- [x] Feedback latency < 30s (unit)
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved (retroactive audit, 2026-07-10) — 0 gaps, 13/13 rows green, all backstops evidenced.
