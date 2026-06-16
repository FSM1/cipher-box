---
phase: 48
slug: sdk-self-bootstrap-regression-fix-and-shared-folder-metadata
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-16
---

# Phase 48 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                                                                        |
| ---------------------- | -------------------------------------------------------------------------------------------- |
| **Framework**          | vitest (`packages/sdk`, `packages/sdk-core`, `apps/web`) · jest (`apps/api`) · Playwright (`tests/web-e2e`) |
| **Config file**        | per-package `vitest.config.ts` / jest config · `tests/web-e2e/playwright.config.ts`          |
| **Quick run command**  | `pnpm --filter @cipherbox/sdk test`                                                           |
| **Full suite command** | `pnpm --filter @cipherbox/sdk test && pnpm --filter @cipherbox/api test`                      |
| **Estimated runtime**  | ~60–120 seconds (unit) · web-e2e ~15 min via dispatch                                         |

> Do NOT run all workspace suites concurrently (RAM). REQ-1 acceptance is the web-e2e **integration** gate, dispatched not run locally.

---

## Sampling Rate

- **After every task commit:** Run the relevant package's quick command (`pnpm --filter <pkg> test`)
- **After every plan wave:** Run the full suite command above
- **Before `/gsd-verify-work`:** Unit suites green AND REQ-1 web-e2e dispatch green
- **Max feedback latency:** 120 seconds (unit) — e2e gate is async via dispatch

---

## Per-Task Verification Map

| Task ID   | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
| --------- | ---- | ---- | ----------- | ---------- | --------------- | --------- | ----------------- | ----------- | ------ |
| TBD       | —    | —    | REQ-1..4    | —          | filled during planning | — | filled during planning | ❌ W0 | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky — the planner/Nyquist auditor fills concrete rows per task._

---

## Wave 0 Requirements

- [ ] REQ-1: SDK unit test for the `loadFolder` sequence-guard (existing-fresher entry NOT overwritten by a stale resolve)
- [ ] REQ-3: SDK unit tests for `sharedFolderTree` reconcile + `sharedFolder:updated` emission
- [ ] REQ-4: unit tests for `itemName` ECIES wrap/unwrap and the lazy-backfill decision (encrypt-on-next-load) logic

_Otherwise existing infrastructure covers phase requirements._

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
| -------- | ----------- | ---------- | ----------------- |
| Both bin-restore-after-reload + version-restore specs green | REQ-1 | Browser/IPNS integration; runs in CI not unit | `gh workflow run web-e2e.yml --ref <fix-branch>` then confirm the "Web E2E Tests" run is green PRE-MERGE |
| Cold former-seed call sites still work | REQ-2 | Requires reload → mutate into a never-navigated subfolder | Manual UAT in the web app after REQ-1 is green |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
