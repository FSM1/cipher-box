---
phase: 31
slug: structural-decomposition
status: draft
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-28
---

# Phase 31 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                                          |
| ---------------------- | ------------------------------------------------------------------------------ |
| **Framework**          | vitest (SDK unit tests) + Playwright (E2E)                                     |
| **Config file**        | `packages/sdk-core/vitest.config.ts`, `packages/sdk/vitest.config.ts`, `tests/web-e2e/playwright.config.ts` |
| **Quick run command**  | `pnpm --filter @cipherbox/sdk-core test && pnpm --filter @cipherbox/sdk test`  |
| **Full suite command** | `pnpm --filter @cipherbox/sdk-core test && pnpm --filter @cipherbox/sdk test && cd tests/web-e2e && pnpm exec playwright test` |
| **Estimated runtime**  | ~30 seconds (unit) / ~5 minutes (full with E2E)                               |

---

## Sampling Rate

- **After every task commit:** Run `pnpm --filter @cipherbox/sdk-core test && pnpm --filter @cipherbox/sdk test`
- **After every plan wave:** Run `pnpm build` (verifies all barrel re-exports resolve + type-checks)
- **Before `/gsd:verify-work`:** Full suite including E2E must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID   | Plan | Wave | Requirement       | Test Type    | Automated Command                                  | File Exists | Status     |
| --------- | ---- | ---- | ----------------- | ------------ | -------------------------------------------------- | ----------- | ---------- |
| 31-01-01  | 01   | 1    | Tree utils in SDK | unit         | `pnpm --filter @cipherbox/sdk-core test`           | existing    | pending |
| 31-01-02  | 01   | 1    | Error utils in SDK| unit         | `pnpm --filter @cipherbox/sdk test`                | existing    | pending |
| 31-02-01  | 02   | 2    | Barrel re-exports | build        | `pnpm build`                                       | existing    | pending |
| 31-02-02  | 02   | 2    | No import breaks  | build+test   | `pnpm build && pnpm --filter @cipherbox/sdk test`  | existing    | pending |
| 31-03-01  | 03   | 3    | Hook splits       | build        | `pnpm build`                                       | existing    | pending |
| 31-03-02  | 03   | 3    | Component splits  | build        | `pnpm build`                                       | existing    | pending |
| 31-03-03  | 03   | 3    | E2E passing       | e2e          | `cd tests/web-e2e && pnpm exec playwright test`    | existing    | pending |

_Status: pending / green / red / flaky_

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements:
- SDK unit test suites already exist for sdk-core/folder and sdk/share
- Build verification via `pnpm build` catches all type/export errors
- E2E tests (sharing-workflow, writable-shares, full-workflow, recycle-bin) verify behavior

_No new test infrastructure needed._

---

## Manual-Only Verifications

| Behavior                           | Requirement    | Why Manual         | Test Instructions                               |
| ---------------------------------- | -------------- | ------------------ | ----------------------------------------------- |
| No behavior change after decomp    | All            | Structural only    | Run all E2E tests, verify identical behavior     |

---

## Validation Sign-Off

- [x] All tasks have automated verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 30s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
