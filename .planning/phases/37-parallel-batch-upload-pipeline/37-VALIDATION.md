---
phase: 37
slug: parallel-batch-upload-pipeline
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-30
---

# Phase 37 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                                                   |
| ---------------------- | --------------------------------------------------------------------------------------- |
| **Framework**          | Vitest 3.x                                                                              |
| **Config file**        | `packages/sdk-core/vitest.config.ts` (unit), `tests/web-e2e/playwright.config.ts` (E2E) |
| **Quick run command**  | `pnpm --filter @cipherbox/sdk-core test -- --reporter=verbose`                          |
| **Full suite command** | `pnpm test` (all packages)                                                              |
| **Estimated runtime**  | ~30 seconds                                                                             |

---

## Sampling Rate

- **After every task commit:** Run `pnpm --filter @cipherbox/sdk-core test && pnpm --filter @cipherbox/sdk test`
- **After every plan wave:** Run `pnpm test && pnpm typecheck`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID  | Plan | Wave | Requirement | Test Type | Automated Command                                                                   | File Exists | Status     |
| -------- | ---- | ---- | ----------- | --------- | ----------------------------------------------------------------------------------- | ----------- | ---------- |
| 37-01-01 | 01   | 1    | D-03        | unit      | `pnpm --filter @cipherbox/sdk vitest run --reporter=verbose`                        | ❌ W0       | ⬜ pending |
| 37-01-02 | 01   | 1    | D-05        | unit      | `pnpm --filter @cipherbox/sdk vitest run --reporter=verbose`                        | ❌ W0       | ⬜ pending |
| 37-01-03 | 01   | 1    | D-09        | unit      | `pnpm --filter @cipherbox/sdk vitest run --reporter=verbose`                        | ❌ W0       | ⬜ pending |
| 37-01-04 | 01   | 1    | D-10        | unit      | `pnpm --filter @cipherbox/sdk vitest run --reporter=verbose`                        | ❌ W0       | ⬜ pending |
| 37-02-01 | 02   | 1    | D-07        | E2E       | `pnpm --filter @cipherbox/web-e2e exec playwright test tests/full-workflow.spec.ts` | ✅          | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] `packages/sdk/src/__tests__/upload-batch.test.ts` — stubs for D-03, D-05, D-09, D-10
- [ ] `packages/sdk/vitest.config.ts` — confirm test discovery works (file exists but no tests yet)
- [ ] p-limit dependency: `pnpm --filter @cipherbox/sdk add p-limit`

_If none: "Existing infrastructure covers all phase requirements."_

---

## Manual-Only Verifications

| Behavior                        | Requirement | Why Manual                                    | Test Instructions                                                                 |
| ------------------------------- | ----------- | --------------------------------------------- | --------------------------------------------------------------------------------- |
| UI responsiveness during upload | D-07        | Subjective: UI should not freeze during batch | Drop 5+ files, verify progress bars animate smoothly and UI remains interactive   |
| Memory pressure under load      | D-02        | Requires profiling tools                      | Upload 3x 50MB files, check Chrome DevTools Memory tab doesn't spike above ~500MB |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
