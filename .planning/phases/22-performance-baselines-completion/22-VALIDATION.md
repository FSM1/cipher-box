---
phase: 22
slug: performance-baselines-completion
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-25
---

# Phase 22 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                                          |
| ---------------------- | ------------------------------------------------------------------------------ |
| **Framework**          | vitest + Playwright + k6                                                       |
| **Config file**        | `vitest.config.ts` / `playwright.config.ts` / `tests/load/k6/`                 |
| **Quick run command**  | `pnpm vitest run --reporter=verbose packages/sdk-core/src/perf/`               |
| **Full suite command** | `pnpm vitest run && cd tests/web-e2e && pnpm exec playwright test tests/perf/` |
| **Estimated runtime**  | ~60 seconds                                                                    |

---

## Sampling Rate

- **After every task commit:** Run `pnpm vitest run --reporter=verbose packages/sdk-core/src/perf/`
- **After every plan wave:** Run `pnpm vitest run && cd tests/web-e2e && pnpm exec playwright test tests/perf/`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

| Task ID  | Plan | Wave | Requirement | Test Type | Automated Command                                       | File Exists | Status     |
| -------- | ---- | ---- | ----------- | --------- | ------------------------------------------------------- | ----------- | ---------- |
| 22-01-01 | 01   | 1    | PERF-05     | unit      | `pnpm vitest run packages/sdk-core/src/perf/`           | ❌ W0       | ⬜ pending |
| 22-01-02 | 01   | 1    | PERF-05     | unit      | `pnpm vitest run packages/sdk-core/src/perf/`           | ❌ W0       | ⬜ pending |
| 22-02-01 | 02   | 1    | PERF-06     | e2e       | `pnpm exec playwright test tests/perf/journeys.spec.ts` | ❌ W0       | ⬜ pending |
| 22-03-01 | 03   | 2    | PERF-07     | load      | `k6 run tests/load/k6/concurrent-ops.js`                | ❌ W0       | ⬜ pending |
| 22-04-01 | 04   | 2    | PERF-08     | manual    | Review `docs/CAPACITY.md` content                       | ❌ W0       | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] `packages/sdk-core/src/perf/__tests__/timing.test.ts` — stubs for PERF-05 instrumentation
- [ ] `tests/web-e2e/tests/perf/journeys.spec.ts` — stubs for PERF-06 journey timings
- [ ] `tests/load/k6/concurrent-ops.js` — stubs for PERF-07 load test scripts

_Existing vitest/Playwright infrastructure covers framework needs. k6 may need install._

---

## Manual-Only Verifications

| Behavior                   | Requirement | Why Manual                                       | Test Instructions                                                                                    |
| -------------------------- | ----------- | ------------------------------------------------ | ---------------------------------------------------------------------------------------------------- |
| Capacity document accuracy | PERF-08     | Requires human review of scaling recommendations | Review `docs/CAPACITY.md` for completeness, coherence of projections, and actionable recommendations |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
