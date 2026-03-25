---
phase: 24
slug: bug-fixes-test-infrastructure
status: draft
nyquist_compliant: false
wave_0_complete: false
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

| Task ID  | Plan | Wave | Requirement | Test Type   | Automated Command                               | File Exists | Status     |
| -------- | ---- | ---- | ----------- | ----------- | ----------------------------------------------- | ----------- | ---------- |
| 24-01-01 | 01   | 1    | BUGFIX-01   | integration | `pnpm test`                                     | ❌ W0       | ⬜ pending |
| 24-01-02 | 01   | 1    | BUGFIX-02   | unit        | `pnpm test`                                     | ❌ W0       | ⬜ pending |
| 24-02-01 | 02   | 2    | TEST-01     | integration | `pnpm test`                                     | ❌ W0       | ⬜ pending |
| 24-02-02 | 02   | 2    | TEST-02     | E2E         | `cd tests/web-e2e && pnpm exec playwright test` | ❌ W0       | ⬜ pending |
| 24-02-03 | 02   | 2    | TEST-03     | integration | `pnpm test`                                     | ❌ W0       | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] Test stubs for BUGFIX-01 bin IPNS resolution
- [ ] Test stubs for BUGFIX-02 device registry parsing
- [ ] Test stubs for TEST-01 headless load tests
- [ ] Test stubs for TEST-02 vault recovery E2E
- [ ] Test stubs for TEST-03 auth refresh in load tests

_Existing test infrastructure (vitest + Playwright) covers framework needs. Wave 0 adds test files only._

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
| -------- | ----------- | ---------- | ----------------- |

_All phase behaviors have automated verification._

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
