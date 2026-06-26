---
phase: 36
slug: inline-upload-progress
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-30
---

# Phase 36 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                                                                              |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------ |
| **Framework**          | Playwright (web E2E) + Vitest (unit)                                                                               |
| **Config file**        | `tests/web-e2e/playwright.config.ts`                                                                               |
| **Quick run command**  | `pnpm typecheck && pnpm lint`                                                                                      |
| **Full suite command** | `BASE_URL=https://app-staging.cipherbox.cc pnpm --filter @cipherbox/web-e2e exec playwright test --timeout 180000` |
| **Estimated runtime**  | ~30 seconds (typecheck+lint), ~120 seconds (E2E)                                                                   |

---

## Sampling Rate

- **After every task commit:** Run `pnpm typecheck && pnpm lint`
- **After every plan wave:** Run full E2E suite against staging
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID  | Plan | Wave | Requirement | Test Type   | Automated Command                 | File Exists | Status     |
| -------- | ---- | ---- | ----------- | ----------- | --------------------------------- | ----------- | ---------- |
| 36-01-01 | 01   | 1    | D-01/D-02   | static      | `pnpm typecheck`                  | ✅          | ⬜ pending |
| 36-01-02 | 01   | 1    | D-03/D-04   | static      | `pnpm typecheck`                  | ✅          | ⬜ pending |
| 36-01-03 | 01   | 1    | D-07/D-08   | static      | `pnpm typecheck`                  | ✅          | ⬜ pending |
| 36-01-04 | 01   | 1    | D-09/D-10   | static      | `pnpm typecheck`                  | ✅          | ⬜ pending |
| 36-02-01 | 02   | 2    | D-05/D-06   | visual/E2E  | Playwright MCP                    | ❌ W0       | ⬜ pending |
| 36-02-02 | 02   | 2    | D-11        | static/grep | `grep -r "UploadModal" apps/web/` | ✅          | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- Existing infrastructure covers all phase requirements.
- E2E upload tests may need CSS selector updates if class names change.

_No new test framework installation required._

---

## Manual-Only Verifications

| Behavior                       | Requirement | Why Manual                         | Test Instructions                                                                |
| ------------------------------ | ----------- | ---------------------------------- | -------------------------------------------------------------------------------- |
| Green flash + swap animation   | D-05/D-06   | Timing-dependent CSS animation     | Upload file, observe 1s green flash, verify smooth transition to normal file row |
| Error state with retry/dismiss | D-09/D-10   | Requires simulating upload failure | Disable network, upload file, verify red bar + retry/dismiss buttons appear      |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
