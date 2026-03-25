---
phase: 22
slug: performance-baselines-completion
status: draft
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-25
---

# Phase 22 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                                                           |
| ---------------------- | ----------------------------------------------------------------------------------------------- |
| **Framework**          | vitest + Playwright                                                                             |
| **Config file**        | `vitest.config.ts` / `playwright.config.ts`                                                     |
| **Quick run command**  | `pnpm vitest run --reporter=verbose packages/sdk-core/src/__tests__/perf.test.ts`               |
| **Full suite command** | `pnpm vitest run && cd tests/web-e2e && pnpm exec playwright test tests/journey-timing.spec.ts` |
| **Estimated runtime**  | ~60 seconds                                                                                     |

---

## Sampling Rate

- **After every task commit:** Run `pnpm vitest run --reporter=verbose packages/sdk-core/src/__tests__/perf.test.ts`
- **After every plan wave:** Run `pnpm vitest run && cd tests/web-e2e && pnpm exec playwright test tests/journey-timing.spec.ts`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

| Task ID  | Plan | Wave | Requirement | Test Type | Automated Command                                                            | File Exists | Status     |
| -------- | ---- | ---- | ----------- | --------- | ---------------------------------------------------------------------------- | ----------- | ---------- |
| 22-01-01 | 01   | 1    | PERF-05     | unit      | `pnpm vitest run packages/sdk-core/src/__tests__/perf.test.ts`               | ❌ W0       | ⬜ pending |
| 22-01-02 | 01   | 1    | PERF-05     | unit      | `pnpm vitest run packages/sdk-core/src/__tests__/perf.test.ts`               | ❌ W0       | ⬜ pending |
| 22-02-01 | 02   | 1    | PERF-06     | e2e       | `cd tests/web-e2e && pnpm exec playwright test tests/journey-timing.spec.ts` | ❌ W0       | ⬜ pending |
| 22-02-02 | 02   | 1    | PERF-06     | manual    | Review `.planning/baselines/22-journey-baselines.md`                         | ❌ W0       | ⬜ pending |
| 22-03-01 | 03   | 1    | PERF-07     | unit      | `cd tests/load && pnpm exec vitest run --no-coverage upload-throughput`      | ❌ W0       | ⬜ pending |
| 22-03-02 | 03   | 1    | PERF-08     | manual    | Review `docs/CAPACITY.md` content                                            | ❌ W0       | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] `packages/sdk-core/src/__tests__/perf.test.ts` — created by Plan 22-01 Task 1 (TDD)
- [ ] `tests/web-e2e/tests/journey-timing.spec.ts` — created by Plan 22-02 Task 1
- [ ] `tests/load/src/harness/thresholds.ts` — created by Plan 22-03 Task 1 (TDD)

_All Wave 0 artifacts are created inline as TDD tasks within the plans._

---

## Manual-Only Verifications

| Behavior                   | Requirement | Why Manual                                       | Test Instructions                                                                                    |
| -------------------------- | ----------- | ------------------------------------------------ | ---------------------------------------------------------------------------------------------------- |
| Capacity document accuracy | PERF-08     | Requires human review of scaling recommendations | Review `docs/CAPACITY.md` for completeness, coherence of projections, and actionable recommendations |
| Journey baselines document | PERF-06     | Requires human review of timing data             | Review `.planning/baselines/22-journey-baselines.md` for reasonable timing values                    |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 60s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-03-25
