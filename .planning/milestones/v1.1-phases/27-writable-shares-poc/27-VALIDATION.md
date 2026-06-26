---
phase: 27
slug: writable-shares-poc
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-26
---

# Phase 27 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                                 |
| ---------------------- | --------------------------------------------------------------------- |
| **Framework**          | vitest (unit/integration), Playwright (E2E)                           |
| **Config file**        | `vitest.config.ts` (packages), `playwright.config.ts` (tests/web-e2e) |
| **Quick run command**  | `pnpm --filter api test -- --run`                                     |
| **Full suite command** | `pnpm test && cd tests/web-e2e && pnpm exec playwright test`          |
| **Estimated runtime**  | ~30 seconds (unit), ~120 seconds (E2E)                                |

---

## Sampling Rate

- **After every task commit:** Run `pnpm --filter api test -- --run`
- **After every plan wave:** Run `pnpm test`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status     |
| ------- | ---- | ---- | ----------- | --------- | ----------------- | ----------- | ---------- |
| TBD     | TBD  | TBD  | TBD         | TBD       | TBD               | TBD         | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] Existing test infrastructure covers unit tests for shares service, IPNS service
- [ ] E2E sharing test exists in `tests/web-e2e/tests/sharing.spec.ts`

_If none: "Existing infrastructure covers all phase requirements."_

---

## Manual-Only Verifications

| Behavior                            | Requirement       | Why Manual                               | Test Instructions                                                                           |
| ----------------------------------- | ----------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------- |
| Multi-writer conflict resolution UX | Conflict handling | Requires two concurrent browser sessions | Open shared folder in two browsers, upload simultaneously, verify 409 retry and sync banner |
| Write-revoke silent downgrade       | Revocation UX     | Requires timed permission change         | Share with write, revoke while recipient has folder open, verify [RW] → [RO] transition     |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
