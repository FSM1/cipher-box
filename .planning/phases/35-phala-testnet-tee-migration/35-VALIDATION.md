---
phase: 35
slug: phala-testnet-tee-migration
status: draft
nyquist_compliant: true
wave_0_complete: false
created: 2026-03-29
---

# Phase 35 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                             |
| ---------------------- | ------------------------------------------------- |
| **Framework**          | Jest (API-side TEE tests) + manual staging verify |
| **Config file**        | `apps/api/jest.config.ts`                         |
| **Quick run command**  | `pnpm --filter api test -- --testPathPattern tee` |
| **Full suite command** | `pnpm --filter api test`                          |
| **Estimated runtime**  | ~30 seconds                                       |

---

## Sampling Rate

- **After every task commit:** Run `pnpm --filter api test -- --testPathPattern tee`
- **After every plan wave:** Run `pnpm --filter api test`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type   | Automated Command                                      | File Exists  | Status     |
| ------- | ---- | ---- | ----------- | ----------- | ------------------------------------------------------ | ------------ | ---------- |
| TBD     | TBD  | TBD  | SC-1        | smoke       | `curl https://{endpoint}/health`                       | N/A (infra)  | ⬜ pending |
| TBD     | TBD  | TBD  | SC-2        | e2e         | Manual staging republish verify                        | N/A (manual) | ⬜ pending |
| TBD     | TBD  | TBD  | SC-3        | integration | `pnpm --filter api test -- tee`                        | ❌ W0        | ⬜ pending |
| TBD     | TBD  | TBD  | SC-4        | perf        | Manual Grafana histogram comparison                    | N/A (manual) | ⬜ pending |
| TBD     | TBD  | TBD  | SC-5        | unit        | `grep -c tee-worker docker/docker-compose.staging.yml` | N/A (verify) | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] `tee-worker/src/__tests__/tee-keys.test.ts` — unit tests for key derivation (simulator mode)
- [ ] `tee-worker/src/__tests__/key-manager.test.ts` — unit tests for ECIES decrypt + epoch fallback
- [ ] `tee-worker/src/__tests__/ipns-signer.test.ts` — unit tests for IPNS record signing
- [ ] `tee-worker/src/__tests__/auth.test.ts` — unit tests for auth middleware

---

## Manual-Only Verifications

| Behavior                | Requirement | Why Manual                           | Test Instructions                                                      |
| ----------------------- | ----------- | ------------------------------------ | ---------------------------------------------------------------------- |
| CVM deployment + health | SC-1        | Requires Phala Cloud infrastructure  | `curl https://{endpoint}/health` returns `{ healthy: true, epoch: N }` |
| End-to-end republish    | SC-2        | Requires running staging + Phala CVM | Trigger republish job, verify IPNS records resolve                     |
| Republish latency       | SC-4        | Requires Grafana + staging baselines | Compare histogram before/after in Grafana                              |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
