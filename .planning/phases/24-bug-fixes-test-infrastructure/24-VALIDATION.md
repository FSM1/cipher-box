---
phase: 24
slug: bug-fixes-test-infrastructure
status: draft
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-25
---

# Phase 24 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                             |
| ---------------------- | ----------------------------------------------------------------- |
| **Framework**          | vitest (unit/integration), Playwright (E2E)                       |
| **Config file**        | `vitest.config.ts` (root), `playwright.config.ts` (tests/web-e2e) |
| **Quick run command**  | `pnpm test`                                                       |
| **Full suite command** | `pnpm test && cd tests/web-e2e && pnpm exec playwright test`      |
| **Estimated runtime**  | ~60 seconds                                                       |

---

## Sampling Rate

- **After every task commit:** Run `pnpm test`
- **After every plan wave:** Run `pnpm test && cd tests/web-e2e && pnpm exec playwright test`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

| Task ID  | Plan | Wave | Requirement | Test Type   | Automated Command                                                                                                     | File Exists    | Status     |
| -------- | ---- | ---- | ----------- | ----------- | --------------------------------------------------------------------------------------------------------------------- | -------------- | ---------- |
| 24-01-01 | 01   | 1    | BUGFIX-01   | unit        | `pnpm --filter @cipherbox/sdk build && pnpm --filter @cipherbox/sdk test`                                             | Yes (updating) | ⬜ pending |
| 24-01-02 | 01   | 1    | BUGFIX-02   | unit        | `pnpm --filter @cipherbox/core build && pnpm --filter @cipherbox/core test && pnpm --filter @cipherbox/web typecheck` | Yes (updating) | ⬜ pending |
| 24-02-01 | 02   | 1    | TEST-03     | integration | `cd tests/load && npx tsc --noEmit`                                                                                   | ❌ W0          | ⬜ pending |
| 24-02-02 | 02   | 1    | TEST-01     | integration | `cd tests/load && npx tsc --noEmit`                                                                                   | ❌ W0          | ⬜ pending |
| 24-03-01 | 03   | 1    | TEST-02     | E2E         | `grep -c 'export-file\|panel-export' apps/web/public/recovery.html \| xargs test 0 -eq`                               | Yes            | ⬜ pending |
| 24-03-02 | 03   | 1    | TEST-02     | E2E         | `cd tests/web-e2e && npx tsc --noEmit --skipLibCheck`                                                                 | ❌ W0          | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [x] Unit tests for BUGFIX-01 bin auto-repair in `packages/sdk/src/__tests__/bin.test.ts` — exists, new cases added in Plan 24-01 Task 1
- [x] Unit tests for BUGFIX-02 device registry v2 migration in `packages/core/src/__tests__/registry.test.ts` — exists, new cases added in Plan 24-01 Task 2
- [ ] Test stubs for TEST-01 headless load tests — created in Plan 24-02 Task 2
- [ ] Test stubs for TEST-02 vault recovery E2E — created in Plan 24-03 Task 2
- [ ] Test stubs for TEST-03 auth refresh in load tests — created in Plan 24-02 Task 1

_BUGFIX-01 and BUGFIX-02 Wave 0 gaps closed: test files exist and Plan 24-01 tasks include adding new test cases with `<verify>` commands that run tests (not just build). TEST-01/02/03 Wave 0 files are created by their respective plans._

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
| -------- | ----------- | ---------- | ----------------- |

_All phase behaviors have automated verification._

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 60s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** ready
