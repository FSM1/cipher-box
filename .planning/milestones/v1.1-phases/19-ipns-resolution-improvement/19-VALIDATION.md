---
phase: 19
slug: ipns-resolution-improvement
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-07
---

# Phase 19 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                        |
| ---------------------- | ------------------------------------------------------------ |
| **Framework**          | Jest 29.x                                                    |
| **Config file**        | `apps/api/jest.config.ts`                                    |
| **Quick run command**  | `pnpm --filter @cipherbox/api test -- --testPathPattern=ipns` |
| **Full suite command** | `pnpm --filter @cipherbox/api test`                          |
| **Estimated runtime**  | ~15 seconds                                                  |

---

## Sampling Rate

- **After every task commit:** Run `pnpm --filter @cipherbox/api test -- --testPathPattern=ipns`
- **After every plan wave:** Run `pnpm --filter @cipherbox/api test`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID   | Plan | Wave | Requirement | Test Type   | Automated Command                                                       | File Exists | Status     |
| --------- | ---- | ---- | ----------- | ----------- | ----------------------------------------------------------------------- | ----------- | ---------- |
| 19-01-01  | 01   | 1    | IPNS-01     | infra       | `docker compose -f docker/docker-compose.staging.yml config --services` | N/A         | ⬜ pending |
| 19-01-02  | 01   | 1    | IPNS-01     | infra       | Manual: `docker compose ps` on staging shows someguy healthy            | N/A         | ⬜ pending |
| 19-02-01  | 02   | 1    | IPNS-01     | unit        | `pnpm --filter @cipherbox/api test -- delegated-routing`                | ✅          | ⬜ pending |
| 19-02-02  | 02   | 1    | IPNS-04     | unit        | `pnpm --filter @cipherbox/api test -- ipns.service`                     | ✅          | ⬜ pending |
| 19-03-01  | 03   | 1    | IPNS-04     | unit        | `pnpm --filter @cipherbox/api test -- metrics`                          | ❌ W0       | ⬜ pending |
| 19-03-02  | 03   | 1    | IPNS-02     | unit        | `pnpm --filter @cipherbox/api test -- ipns.service`                     | ✅          | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] `apps/api/src/metrics/metrics.service.spec.ts` — stubs for IPNS-04 histogram registration verification
- [ ] Staging smoke test checklist — verify Someguy container health + IPNS resolve via API (manual)

_Existing `delegated-routing.client.spec.ts` and `ipns.service.spec.ts` cover IPNS-01, IPNS-02, IPNS-04 core logic. No new test files needed for URL swap._

---

## Manual-Only Verifications

| Behavior                                    | Requirement | Why Manual                                           | Test Instructions                                                                    |
| ------------------------------------------- | ----------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Someguy container healthy on staging         | IPNS-01     | Requires deployed staging infra                      | SSH to staging, `docker compose ps`, verify someguy shows "healthy"                  |
| API resolves IPNS via Someguy (not delegated-ipfs.dev) | IPNS-01 | Requires live Someguy with DHT connectivity    | `curl https://api-staging.cipherbox.cc/ipns/resolve/<known-name>`, check API logs    |
| Recovery tool docs reference self-hosted option | IPNS-03  | Documentation review                                 | Review `.env.example` comments and OpenAPI descriptions                              |
| No user-visible errors when DHT unreachable | IPNS-04     | Requires network partition simulation on staging     | Stop someguy container, verify API returns DB-cached data without errors              |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
