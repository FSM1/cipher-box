---
phase: 72
slug: sdk-write-plane-durability-and-correctness
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-10
---

# Phase 72 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Detailed per-criterion mapping lives in `72-RESEARCH.md` (`## Validation Architecture`).

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | vitest (SDK unit + sdk-e2e), Playwright (web-e2e) |
| **Config file** | `packages/sdk/vitest.config.ts`, `tests/sdk-e2e/vitest.config.ts`, `tests/web-e2e/playwright.config.ts` |
| **Quick run command** | `pnpm --filter @cipherbox/sdk test` |
| **Full suite command** | sdk unit + `pnpm --filter @cipherbox/sdk-e2e test` (needs local API + docker stack) + web-e2e for shared paths |
| **Estimated runtime** | ~30s (sdk unit) · ~3–6min (sdk-e2e live) · ~12min (web-e2e full) |

---

## Sampling Rate

- **After every task commit:** Run `pnpm --filter @cipherbox/sdk test` (fast, no live stack)
- **After every plan wave:** Run the SDK unit suite; run sdk-e2e after any write-chain / IPNS-publish change
- **Before `/gsd-verify-work`:** SDK unit green + sdk-e2e green (write-chain-rotation, move-restore-content) + web-e2e writable-shares green
- **Max feedback latency:** ~30s (unit) between commits

---

## Per-Task Verification Map

> Seed row — the planner/executor fills one row per task with its real command and requirement ref.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 72-01-01 | 01 | 1 | SC#1 delete drops WriteChildRef | — | Write-chain shrinks on hard-delete; no resurrection under concurrent-write merge | sdk-e2e | `pnpm --filter @cipherbox/sdk-e2e test` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] Re-enable / rewrite `packages/sdk/src/__tests__/move-in-shared-folder.test.ts` (currently `describe.skip` — SC#5 has no live regression gate today)
- [ ] Extend `tests/sdk-e2e/src/suites/write-chain-rotation.test.ts` seed identification by provenance (SC#6)
- [ ] Repair `packages/sdk/src/__tests__/upload-batch.test.ts` mocks to the current `SealedChildRef` shape (SC#6)

*Existing vitest + sdk-e2e + web-e2e infrastructure otherwise covers all phase requirements — no framework install needed.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Fresh listing (size/date) after an in-place edit | SC#4 | listingCache invalidation is observable in the running web app, not a pure unit assertion | Upload a file, replace content with a larger file in the web app, confirm the list row size/date update without a manual refresh |

*All other phase behaviors have automated verification (see `72-RESEARCH.md` `## Validation Architecture`).*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references (skipped move test, brittle rotation seed capture, drifted upload-batch mocks)
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
