---
phase: 26
slug: observability-ux-tuning
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-26
---

# Phase 26 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                              |
| ---------------------- | ------------------------------------------------------------------ |
| **Framework**          | vitest (load tests), Playwright (journey tests)                    |
| **Config file**        | `tests/load/vitest.config.ts`, `tests/web-e2e/playwright.config.ts` |
| **Quick run command**  | `pnpm --filter load test -- --reporter=verbose`                    |
| **Full suite command** | `pnpm --filter load test && cd tests/web-e2e && pnpm exec playwright test` |
| **Estimated runtime**  | ~120 seconds                                                       |

---

## Sampling Rate

- **After every task commit:** Run `pnpm --filter load test -- --reporter=verbose`
- **After every plan wave:** Run full suite command
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 120 seconds

---

## Per-Task Verification Map

| Task ID   | Plan | Wave | Requirement | Test Type    | Automated Command                          | File Exists | Status     |
| --------- | ---- | ---- | ----------- | ------------ | ------------------------------------------ | ----------- | ---------- |
| 26-01-01  | 01   | 1    | OBS-01      | integration  | Grafana API query for alert rules          | ❌ W0       | ⬜ pending |
| 26-01-02  | 01   | 1    | OBS-01      | integration  | Verify alert rule JSON structure           | ❌ W0       | ⬜ pending |
| 26-02-01  | 02   | 2    | OBS-02      | unit         | `pnpm --filter sdk-core test`              | ✅          | ⬜ pending |
| 26-02-02  | 02   | 2    | OBS-02      | e2e          | Playwright journey timing comparison       | ✅          | ⬜ pending |
| 26-02-03  | 02   | 2    | OBS-02      | load         | `pnpm --filter load test`                  | ✅          | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- Existing infrastructure covers all phase requirements.
- Load test harness (vitest) and journey tests (Playwright) from Phase 22 already in place.
- Grafana alert rule validation is manual (API call to Grafana Cloud) — no new test stubs needed.

---

## Manual-Only Verifications

| Behavior                        | Requirement | Why Manual                        | Test Instructions                                              |
| ------------------------------- | ----------- | --------------------------------- | -------------------------------------------------------------- |
| Grafana alerts fire on threshold breach | OBS-01 | Requires live Grafana Cloud instance | Deploy alert rules, simulate load spike, verify alert in Grafana UI |
| DB fallback rate alert triggers  | OBS-01      | Requires network degradation scenario | Stop Someguy, verify fallback rate alert fires within 5 minutes |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
