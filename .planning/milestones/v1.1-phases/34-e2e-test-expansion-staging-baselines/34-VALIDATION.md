---
phase: 34
slug: e2e-test-expansion-staging-baselines
status: validated
nyquist_compliant: true
wave_0_complete: true
created: 2026-06-12
validated: 2026-06-12
note: Backfilled retroactively from 34-RESEARCH.md "Validation Architecture" after phase completion (gsd-health W009 remediation). Phase was already executed and verified — see 34-VERIFICATION.md.
---

# Phase 34 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

## Test Infrastructure

| Property               | Value                                                                               |
| ---------------------- | ----------------------------------------------------------------------------------- |
| **Framework**          | @playwright/test 1.57.0                                                             |
| **Config file**        | `tests/web-e2e/playwright.config.ts` (local), `playwright.load.config.ts` (staging) |
| **Quick run command**  | `cd tests/web-e2e && pnpm exec playwright test tests/<spec>.spec.ts`                |
| **Full suite command** | `cd tests/web-e2e && pnpm exec playwright test`                                     |

## Sampling Rate

- **Per task commit:** `cd tests/web-e2e && pnpm exec playwright test tests/<new-spec>.spec.ts`
- **Per wave merge:** `cd tests/web-e2e && pnpm exec playwright test` (full suite)
- **Phase gate:** Full suite green + staging runs documented

## Success Criteria → Test Map

No formal requirement IDs for this phase (test coverage and baseline capture). Success criteria map directly to test files:

| Success Criterion              | Test Type                  | Verification                                 | Status |
| ------------------------------ | -------------------------- | -------------------------------------------- | ------ |
| AES-CTR streaming playback E2E | E2E (Playwright)           | `streaming-playback.spec.ts` runs green      | DONE   |
| Batch download E2E             | E2E (Playwright)           | `batch-download.spec.ts` runs green          | DONE   |
| Media preview E2E              | E2E (Playwright)           | `media-preview.spec.ts` runs green           | DONE   |
| Shared deleteAccount teardown  | Code inspection + test run | All specs' afterAll hooks call deleteAccount | DONE   |
| BYO-IPFS load baselines        | Manual staging run         | Baseline numbers documented                  | DONE   |
| Staging metrics baselines      | Manual staging run         | Journey timing + load test results captured  | DONE   |

## Wave 0 Gaps (all closed during execution)

- [x] `tests/web-e2e/tests/streaming-playback.spec.ts`
- [x] `tests/web-e2e/tests/media-preview.spec.ts`
- [x] `tests/web-e2e/tests/batch-download.spec.ts`
- [x] `tests/web-e2e/utils/cleanup-helpers.ts` — shared deleteAccount helper
- [x] `tests/web-e2e/fixtures/files/` media fixtures (video, small video, audio, PDF)

All files confirmed present on disk at backfill time. Per-plan outcomes are recorded in `34-0N-SUMMARY.md`; phase verification in `34-VERIFICATION.md`.
