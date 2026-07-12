---
phase: 78
slug: recovery-tool-v3-vault-load-guards-web-ux-and-ci-guards
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-12
---

# Phase 78 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution. Source: 78-RESEARCH.md `## Validation Architecture`.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Playwright (`@playwright/test`) for web-e2e; Vitest for `apps/web` unit (non-blocking, D-06) and `packages/sdk` (CI-gated) |
| **Config file** | `tests/web-e2e/playwright.config.ts` (e2e); `apps/web/vite.config.ts` `test` field (vitest) |
| **Quick run command** | `cd apps/web && pnpm vitest run` (unit, ~0.5s once dist built); `pnpm --filter @cipherbox/web-e2e test -- <spec>` (single e2e) |
| **Full suite command** | `pnpm test:web-e2e` (all specs, ~14min wall-clock, 3 CI workers) |
| **Estimated runtime** | ~0.5s unit / ~14min full e2e |

---

## Sampling Rate

- **After every task commit:** `pnpm lint` (SC3a), `cd apps/web && pnpm vitest run` (SC3b/SC2 regression), targeted single-spec Playwright run for the touched area
- **After every plan wave:** `recovery.spec.ts` + the two new race specs
- **Before `/gsd-verify-work`:** Full `pnpm test:web-e2e` green with zero `test.fixme`/`test.skip`
- **Max feedback latency:** ~30 seconds (unit + single spec); full suite reserved for phase gate

---

## Per-Task Verification Map

> Task IDs assigned at plan time. Requirement → test mapping below is lifted from 78-RESEARCH.md and MUST be honored by the plans' `<acceptance_criteria>` / `must_haves`.

| Requirement | Behavior | Test Type | Automated Command | File Exists |
|-------------|----------|-----------|-------------------|-------------|
| SC1 | recovery.html recovers a v3 vault via IPFS-direct gateway walk, zero API dependency | e2e | `pnpm --filter @cipherbox/web-e2e test -- recovery.spec.ts` | ⚠️ currently `test.fixme` — un-fixme is the exit criterion |
| SC2 | Download/restore actions show progress spinners wired through `download.store` | e2e / manual | Playwright assertion on spinner DOM if practical, else Puppeteer/manual per CLAUDE.md | ❌ W0 gap |
| SC3a | `apps/web/src` cannot import `sdk-core`/`core` or call raw IPFS at runtime | lint (CI) | `pnpm lint` (after new ESLint rule) | ✅ lint job exists; rule wiring is new |
| SC3b | Residual `apps/web` `*.test.ts` suite passes | unit | `cd apps/web && pnpm vitest run` (after building crypto/core/api-client/sdk-core/sdk) | ✅ 10 files / 67 tests green |
| SC3c item 3 | A slow poll never overwrites a newer nav-triggered folder state | e2e (new) | new spec, pattern per `shared-folder-desync.spec.ts` | ❌ W0 gap |
| SC3c item 11 | A fast navigateUp/breadcrumb click during in-flight subfolder descent never leaves the active writeKey at the wrong depth | e2e (new) | new spec / extend `writable-shares.spec.ts` | ❌ W0 gap |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `esbuild` build-size/compatibility spike for the recovery bundle (crypto+core, browser target) — pre-implementation validation before the full SC1 plan detail (Open Question 1).
- [ ] New e2e spec for SC3c item 3 (poll-monotonicity) — no existing spec covers this race.
- [ ] New e2e spec / test case for SC3c item 11 (descent-vs-restore) — add "descend-then-immediately-up" case, may live in `writable-shares.spec.ts` / `shared-folder-desync.spec.ts`.
- [ ] SC2 spinner-visibility assertion — no existing spec asserts `download.store`-driven DOM state; Playwright assertion preferred, Puppeteer/manual acceptable if impractical (flag in VERIFICATION.md).

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Recovery against a live public gateway with the CipherBox API fully absent | SC1 | Public-gateway availability/timing is non-deterministic in CI; the e2e uses a local/mock gateway | Manually point recovery.html at a public gateway (ipfs.io/dweb.link) for a real pinned vault, paste privateKey, confirm full tree decrypts with API stopped |
| Download/restore spinner visibility (if no Playwright assertion added) | SC2 | Spinner DOM state may be impractical to assert deterministically | Puppeteer/manual per CLAUDE.md UI-verification convention |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s (quick loop)
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
