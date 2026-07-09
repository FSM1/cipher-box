---
phase: 71
slug: share-invite-security-and-ipns-data-integrity-api
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-09
---

# Phase 71 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Derived from `71-RESEARCH.md` § Validation Architecture. Anchored to Success
> Criteria SC#1–SC#6 (SC#3 amended per D-03) and decisions D-01…D-09 — this is a
> todo-driven phase with no mapped REQ-IDs (`phase_req_ids: null`).

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

| SC / Decision | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------------|-----------------|-----------|-------------------|-------------|--------|
| SC#1 / D-01 | `createInvite` rejects when sharer does not own `rootIpnsName` (vault lookup) | unit | `… --testPathPattern=share-invite.service` | ❌ W0 (new `describe('createInvite')`) | ⬜ pending |
| SC#1 / D-01 | `createInvite` succeeds when sharer owns the root (positive) | unit | same | ❌ W0 | ⬜ pending |
| SC#2 / D-07 | Re-claim with write invite over read-only share upgrades `writeDescriptorRef` | unit | same | ❌ W0 | ⬜ pending |
| SC#2 / D-07 | Re-claim with lower/equal invite is a no-op (no downgrade) | unit | same | ❌ W0 | ⬜ pending |
| SC#2 / D-07 | **Backstop:** a write-capable share is NEVER downgraded by any non-widening re-claim | unit (property-style, negative assertion) | same | ❌ W0 (anomaly-only edge — positive-widen test insufficient) | ⬜ pending |
| SC#3 / D-04 | DB rejects out-of-bounds `claim_count` even if app code bypassed | integration (real Postgres) OR documented manual | `migration:run` + raw `UPDATE … claim_count=-1` expects `23514` | ❌ W0 (Jest mocks DataSource — cannot unit-test) | ⬜ pending |
| SC#4 / D-05 | Same-seq + different-CID republish → 400 | unit | `… --testPathPattern=ipns.service` | ❌ W0 (rewrite Pitfall-4 test) | ⬜ pending |
| SC#4 / D-05 | Same-seq + SAME-CID republish still succeeds, seq unchanged | unit | same | ❌ W0 (new positive case) | ⬜ pending |
| SC#4 / D-05 | **Backstop:** TEE lease-renewer never reaches `upsertIpnsRecord` same-seq branch | structural (documented) | — | proven by inspection; add guard comment/assertion in spec | ⬜ pending |
| SC#4 / D-06 | Concurrent first-publish of same new `ipnsName` → one 200 + one 409 | unit (mocked 23505) + sdk-e2e (real race) | unit `…ipns.service`; e2e `…ipns-publish-gate` | ❌ W0 both | ⬜ pending |
| SC#5 / D-08 | `revokeForItems` issues one DELETE, returns correct affected counts | unit | `… --testPathPattern=shares.service` | ❌ W0 (rewrite find+remove → execute mocks) | ⬜ pending |
| SC#6 / D-09 | `createInvite`/`getInvitesForItem`/`revokeInvite` covered with realistic fixtures | unit | `… --testPathPattern=share-invite.service --coverage` | ❌ W0 (3 new describe blocks) | ⬜ pending |
| — / D-09 | `shares.controller.spec.ts` uses contract-valid UUIDs/keys (CodeRabbit NIT3) | unit | `… --testPathPattern=shares.controller` | ✅ exists, fixture edits only | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `share-invite.service.spec.ts` — `describe('createInvite')` (D-01 reject + accept), `describe('getInvitesForItem')`, `describe('revokeInvite')` (D-09); extend idempotent re-claim block with D-07 widen positive/negative cases
- [ ] `ipns.service.spec.ts` — rewrite Pitfall-4 block (lines 2111-2137) → same-CID-succeeds + different-CID-rejects (D-05); add first-publish 23505→409 case (D-06)
- [ ] `shares.service.spec.ts` — rewrite `revokeForItems` tests: sequenced `execute` mocks (D-08)
- [ ] `shares.controller.spec.ts` — swap placeholder fixtures for contract-valid UUIDs / full IPNS names / full-length hex keys (D-09)
- [ ] `tests/sdk-e2e/src/suites/ipns-publish-gate.test.ts` — add first-publish concurrent-race case (D-06); only test type that proves the real Postgres unique-constraint race
- [ ] D-04 CHECK constraint — integration spec against real Postgres, OR documented manual `psql` verification (Jest mocks DataSource)

---

## Manual-Only Verifications

| Behavior | SC / Decision | Why Manual | Test Instructions |
|----------|---------------|------------|-------------------|
| `claim_count` CHECK constraint enforcement | SC#3 / D-04 | `apps/api` Jest mocks the DataSource — no real DB in unit suite | On a migrated dev DB: `UPDATE share_invites SET claim_count = -1 WHERE id = '<uuid>'`, confirm Postgres `23514 check_violation`. Record in VERIFICATION.md if no integration harness is wired. |
| First-publish concurrent race (real DB) | SC#4 / D-06 | Genuine DB-level concurrency needs live Postgres | `docker compose up -d` + api dev + `migration:run`, then run the sdk-e2e first-publish case; treat as `checkpoint:human-verify` if the executor cannot bootstrap the stack. |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] Backstop edges (D-05 downgrade-never, D-07 downgrade-never, D-04 DB CHECK, D-06 real race) have explicit non-inferable coverage or a documented manual step
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s (unit)
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
