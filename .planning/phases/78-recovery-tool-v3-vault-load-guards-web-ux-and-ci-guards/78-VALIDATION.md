---
phase: 78
slug: recovery-tool-v3-vault-load-guards-web-ux-and-ci-guards
status: complete
nyquist_compliant: true
wave_0_complete: true
created: 2026-07-12
validated: 2026-07-12
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
| SC1 | recovery.html recovers a v3 vault via IPFS-direct gateway walk, zero API dependency | e2e | `pnpm --filter @cipherbox/web-e2e test -- recovery.spec.ts` | ✅ un-fixme'd; active test `recovers vault files via IPFS-direct v3 read chain` (recovery.spec.ts:71), green during ship |
| SC2 | Download/restore actions show progress spinners wired through `download.store` | e2e | `pnpm --filter @cipherbox/web-e2e test -- batch-download.spec.ts` | ✅ held-fetch `toBeDisabled()` spinner-visibility assertion (batch-download.spec.ts:129), 6/6 green |
| SC3a | `apps/web/src` cannot import `sdk-core`/`core` or call raw IPFS at runtime | lint (CI) | `pnpm lint` (scoped ESLint boundary rule) | ✅ scoped `eslint.config.js` block; both gates fire on live fixtures (VERIFICATION truths 11-13) |
| SC3b | Residual `apps/web` `*.test.ts` suite passes | unit | `cd apps/web && pnpm vitest run` (after building crypto/core/api-client/sdk-core/sdk) | ✅ 10 files / 67 tests green (61 pass + 6 skip) |
| SC3c item 3 | A slow poll never overwrites a newer nav-triggered folder state | e2e (new) | `pnpm --filter @cipherbox/web-e2e test -- poll-monotonicity.spec.ts` | ✅ new `poll-monotonicity.spec.ts` test 2 (stale-poll clobber, line 116), 2/2 green on clean DB |
| SC3c item 11 | A fast navigateUp/breadcrumb click during in-flight subfolder descent never leaves the active writeKey at the wrong depth | e2e (new) + unit | `pnpm --filter @cipherbox/web-e2e test -- descent-vs-restore.spec.ts`; `pnpm --filter @cipherbox/sdk test -- shared-folder-seed-generation` | ✅ new `descent-vs-restore.spec.ts` test 3.1 (navigateUp-during-descent, line 183), 4/4 green + SDK unit `shared-folder-seed-generation.test.ts` (13 asserts) |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

All six requirements are COVERED — each has a green automated test (e2e/unit/lint). Zero MISSING, zero PARTIAL.

---

## Wave 0 Requirements

- [x] `esbuild` build-size/compatibility spike for the recovery bundle (crypto+core, browser target) — resolved: `recovery-src/build.ts` esbuild bundle inlined into `recovery.html`, single inline script, zero CDN dep (VERIFICATION truths 4, 7).
- [x] New e2e spec for SC3c item 3 (poll-monotonicity) — resolved: `tests/web-e2e/tests/poll-monotonicity.spec.ts` test 2 covers the stale-poll-vs-newer-nav race, 2/2 green on clean DB.
- [x] New e2e spec / test case for SC3c item 11 (descent-vs-restore) — resolved: `tests/web-e2e/tests/descent-vs-restore.spec.ts` test 3.1 (navigateUp-during-descent), 4/4 green, plus SDK unit `shared-folder-seed-generation.test.ts`.
- [x] SC2 spinner-visibility assertion — resolved with a deterministic Playwright assertion (not manual): `batch-download.spec.ts` holds `GET /ipfs/<cid>` in flight and asserts the store-driven download button is disabled, then re-enables on settle. 6/6 green.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Recovery against a live public gateway with the CipherBox API fully absent | SC1 | Public-gateway availability/timing is non-deterministic in CI; the e2e uses a local/mock gateway | Manually point recovery.html at a public gateway (ipfs.io/dweb.link) for a real pinned vault, paste privateKey, confirm full tree decrypts with API stopped. (Core read-chain behavior is already automated by recovery.spec.ts against a local gateway.) |

> The SC2 download/restore spinner-visibility manual fallback is no longer required — it was upgraded to a deterministic Playwright assertion in `batch-download.spec.ts` (held-fetch → disabled-button). No manual step remains for SC2.

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (all 4 Wave-0 items resolved with automated tests)
- [x] No watch-mode flags
- [x] Feedback latency < 30s (quick loop)
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved (retroactive validation, 2026-07-12)

---

## Validation Audit 2026-07-12

| Metric | Count |
|--------|-------|
| Gaps found | 4 |
| Resolved | 4 |
| Escalated | 0 |

Retroactive audit of the completed phase. The draft VALIDATION.md carried 4 open Wave-0 gaps (SC1 `test.fixme`, SC2 spinner-visibility, SC3c item-3 poll-monotonicity, SC3c item-11 descent-vs-restore). Static analysis (grep/read of the committed test tree, cross-referenced against 78-VERIFICATION.md truths 8, 9, 16, 17) confirms all four were closed during ship with green automated tests — no new tests needed to be generated:

- **SC1** — `recovery.spec.ts` un-fixme'd; active test `recovers vault files via IPFS-direct v3 read chain`; zero fixme/skip across the web-e2e suite.
- **SC2** — `batch-download.spec.ts:129` held-fetch `toBeDisabled()` spinner-visibility assertion (deterministic, replaces the manual fallback), 6/6 green.
- **SC3c item 3** — `poll-monotonicity.spec.ts:116` stale-poll-vs-newer-nav race, 2/2 green on clean DB.
- **SC3c item 11** — `descent-vs-restore.spec.ts:183` navigateUp-during-descent, 4/4 green, plus SDK unit `shared-folder-seed-generation.test.ts`.

SC3a (D-07 boundary rule) and SC3b (residual apps/web vitest, deliberately non-blocking in CI per D-06) are COVERED by lint and unit respectively. The recovery tool being intentionally SDK/API/Web3Auth-free and apps/web vitest being intentionally excluded from blocking CI are locked Phase-78 design decisions, not gaps. All requirements COVERED; phase is Nyquist-compliant.
