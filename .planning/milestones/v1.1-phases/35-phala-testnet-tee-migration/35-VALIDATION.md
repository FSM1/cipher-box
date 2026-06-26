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

| Property               | Value                                                               |
| ---------------------- | ------------------------------------------------------------------- |
| **Framework**          | Vitest (tee-worker) + Jest (API-side) + manual staging verify       |
| **Config file**        | `apps/tee-worker/vitest.config.ts`, `apps/api/jest.config.ts`       |
| **Quick run command**  | `cd apps/tee-worker && pnpm test`                                   |
| **Full suite command** | `pnpm --filter cipherbox-tee-worker test && pnpm --filter api test` |
| **Estimated runtime**  | ~30 seconds                                                         |

---

## Sampling Rate

- **After every task commit:** Run `cd apps/tee-worker && pnpm test`
- **After every plan wave:** Run full suite
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan  | Wave | Requirement | Test Type   | Automated Command                                      | File Exists  | Status  |
| ------- | ----- | ---- | ----------- | ----------- | ------------------------------------------------------ | ------------ | ------- |
| 01-T8   | 35-01 | W1   | -           | build       | `cd apps/tee-worker && pnpm exec tsc --noEmit`         | N/A (build)  | pending |
| 02-T2   | 35-02 | W2   | SC-3        | unit        | `cd apps/tee-worker && pnpm test`                      | W2           | pending |
| 03-T5   | 35-03 | W2   | -           | build       | `cd apps/tee-worker && pnpm exec tsc --noEmit`         | N/A (build)  | pending |
| 06-T2   | 35-06 | W4   | SC-1        | smoke       | `curl https://{endpoint}/health`                       | N/A (infra)  | pending |
| 06-T4   | 35-06 | W4   | SC-2        | e2e         | Manual staging republish verify                        | N/A (manual) | pending |
| 06-T3   | 35-06 | W4   | SC-3        | integration | CVM key persistence across restarts                    | N/A (manual) | pending |
| 06-T5   | 35-06 | W4   | SC-4        | perf        | Manual Grafana histogram comparison                    | N/A (manual) | pending |
| 04-T1   | 35-04 | W3   | SC-5        | verify      | `grep -c tee-worker docker/docker-compose.staging.yml` | N/A (verify) | pending |

_Status: pending / green / red / flaky_

---

## Wave 1 Requirements

- [ ] `apps/tee-worker/package.json` depends on `@cipherbox/crypto`, `@cipherbox/core`, `@cipherbox/sdk-core` (workspace deps)
- [ ] `apps/tee-worker/src/services/ipns-signer.ts` imports from `@cipherbox/core` (not direct ipns/libp2p)
- [ ] `apps/tee-worker/src/services/key-manager.ts` imports from `@cipherbox/crypto` (not direct eciesjs)
- [ ] `apps/tee-worker/src/services/migration-worker.ts` uses KuboProvider/PsaProvider from `@cipherbox/sdk-core`
- [ ] `tsc --noEmit` passes for tee-worker

---

## Wave 2 Requirements

- [ ] `apps/tee-worker/src/__tests__/tee-keys.test.ts` — unit tests for key derivation (simulator mode)
- [ ] `apps/tee-worker/src/__tests__/key-manager.test.ts` — unit tests for epoch fallback orchestration
- [ ] `apps/tee-worker/src/__tests__/auth.test.ts` — unit tests for auth middleware
- [ ] `apps/tee-worker/src/__tests__/republish.test.ts` — unit tests for republish route batch processing
- [ ] NOTE: No ipns-signer.test.ts needed — IPNS creation is tested in @cipherbox/core

---

## Manual-Only Verifications

| Behavior                | Requirement | Why Manual                           | Test Instructions                                                      |
| ----------------------- | ----------- | ------------------------------------ | ---------------------------------------------------------------------- |
| CVM deployment + health | SC-1        | Requires Phala Cloud infrastructure  | `curl https://{endpoint}/health` returns `{ healthy: true, epoch: N }` |
| End-to-end republish    | SC-2        | Requires running staging + Phala CVM | Trigger republish job, verify IPNS records resolve                     |
| Republish latency       | SC-4        | Requires Grafana + staging baselines | Compare histogram before/after in Grafana                              |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 1/2 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 1 covers shared package integration build verification
- [ ] Wave 2 covers TEE-specific unit tests (not duplicating shared package tests)
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
