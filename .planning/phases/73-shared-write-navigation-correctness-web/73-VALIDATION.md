---
phase: 73
slug: shared-write-navigation-correctness-web
status: audited
nyquist_compliant: true
wave_0_complete: true
created: 2026-07-10
---

# Phase 73 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution. Derived from 73-RESEARCH.md `## Validation Architecture`.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework (logic)** | Vitest — `packages/sdk` + `packages/sdk-core` |
| **Framework (UI/nav)** | Playwright — `tests/web-e2e/` (main-push gated in CI) |
| **Config file** | `packages/sdk/vitest.config.ts`, `packages/sdk-core/vitest.config.ts` |
| **Quick run command** | `pnpm --filter @cipherbox/sdk test -- <file>.test.ts` |
| **Full suite command** | `pnpm --filter @cipherbox/sdk test` (+ `pnpm --filter @cipherbox/sdk-core test`) |
| **Web-e2e quick run** | `pnpm --filter web-e2e test -- writable-shares.spec.ts` (requires local stack; see `project-web-e2e-local-full-suite-recipe` memory) |
| **Estimated runtime** | SDK Vitest ~seconds; web-e2e minutes (local stack) |

**Repo convention (binding):** `apps/web` has zero unit tests. Hoist testable logic into `packages/sdk`/`packages/sdk-core` (Vitest); cover nav/UI behavior via Playwright web-e2e. Do NOT add apps/web unit tests.

---

## Sampling Rate

- **After every task commit:** targeted `pnpm --filter @cipherbox/sdk test -- <file>` (or sdk-core) for the SDK change in that task. No per-commit web-e2e (local stack, too slow).
- **After every plan wave:** full `packages/sdk` + `packages/sdk-core` Vitest suites; targeted local `playwright test` over the touched specs (`writable-shares`, `shared-folder-desync`, `rotation-ux`) — not the full web-e2e suite.
- **Before `/gsd-verify-work`:** full SDK Vitest green; the four touched web-e2e specs (`writable-shares.spec.ts`, `shared-folder-desync.spec.ts`, `rotation-ux.spec.ts`, smoke `sharing-workflow.spec.ts`) run locally green. Full CI web-e2e only runs on merge to main.
- **Max feedback latency:** SDK Vitest < 30s (per-task loop).

---

## Per-Task Verification Map

> Task IDs are assigned by the planner (`{N}-{plan}-{task}`). Rows below are the SC→test contract each task must satisfy; the planner maps concrete task IDs onto these SCs.

| SC | Behavior | Test Type | Automated Command | File Exists | Status |
|----|----------|-----------|-------------------|-------------|--------|
| SC1 | Write into a deep shared subfolder succeeds after navigate-up / breadcrumb restore | web-e2e | `playwright test writable-shares.spec.ts` (new descend-2 / up-1 / write case) | ✅ extend | ⬜ pending |
| SC2 | Nav-stack restore reflects fresh children after a remote mutation | web-e2e | `playwright test shared-folder-desync.spec.ts` (new deeper-mutate case) | ✅ extend | ⬜ pending |
| SC3 | `resolveFileMetadata` / `downloadFromIpns` / `resolveNodeIdentity` fail closed on `signatureVerified:false` (floor-gated) | SDK Vitest | `vitest run resolve-node-identity.test.ts resolve-child-identity.test.ts` + new file-metadata facade test | ✅ 2 existing / ❌ W0 new | ⬜ pending |
| SC4 | `publishNodeFn` surfaces `{tombstoned:true}` on a real 410; classifier reachable from a real shared write | SDK Vitest (sdk-core 410→tombstoned) + web-e2e (rotation-ux upgrade) | `vitest run` (sdk-core ipns) + `playwright test rotation-ux.spec.ts -g "WRITE-03"` | ❌ W0 new sdk-core unit / ✅ e2e upgrade | ⬜ pending |
| SC5 | Drag payload kind matches resolved listing (`isFileRefResolved`) | web-e2e (regression — no new assertion) | `playwright test writable-shares.spec.ts` | ✅ no new file | ⬜ pending |
| SC6 | Consolidated restore helper behaves identically to pre-refactor dual paths | web-e2e (regression) | `playwright test writable-shares.spec.ts shared-folder-desync.spec.ts` | ✅ existing = gate | ⬜ pending |
| SC7 | No remaining refs to the removed dead folder-IPNS path; write behavior unchanged | web-e2e (regression) + grep gate | `grep -rn "resolveFolderIpnsPrivateKey" apps/web/src` returns 0 + `playwright test writable-shares.spec.ts` | ✅ existing = gate | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [x] New/extended SDK Vitest covering `resolveFileMetadata` / `downloadFromIpns` fail-closed (`signatureVerified:false`) — `packages/sdk/src/__tests__/file-metadata-facade.test.ts` (2 fail-closed cases asserting `rejects.toThrow(/unverified record/)` with `signatureVerified:false`, plus `resolveNodeIdentity` covered in `resolve-node-identity.test.ts`). Green (SC3).
- [x] New SDK-core Vitest for `createAndPublishIpnsRecord` 410 → `{tombstoned:true}` mapping — `packages/sdk-core/src/__tests__/ipns.test.ts` (`SC4(a)` maps 410→`{success:false, tombstoned:true}`, plus regression guard that a 500 rethrows unchanged). Green (SC4).
- [x] New `writable-shares.spec.ts` case: descend 2 levels, navigate up 1, write from restored depth — test `8.4b` (uploads from restored depth-1, asserts file visible + zero `[role="alert"]` toasts) (SC1).
- [x] Extended `shared-folder-desync.spec.ts` case: mutate from owner while grantee navigated deeper, then navigate up, assert fresh children — test "Grantee sees fresh children…" (owner adds file at left depth, grantee navigates up, asserts owner file visible) (SC2).
- [x] Rewritten `rotation-ux.spec.ts` D-01/WRITE-03 case: real classifier-driven flow via real `POST /ipns/tombstone` → publish 410 → classifier → two-stage toast contract, no direct toast injection (SC4).

---

## Manual-Only Verifications

| Behavior | SC | Why Manual | Test Instructions |
|----------|-----|------------|-------------------|
| Full shared-nav write/restore flow under the live stack | SC1, SC2, SC4 | web-e2e is main-push gated in CI; not run on the phase branch by CI | Run the four touched specs locally against the docker stack per `project-web-e2e-local-full-suite-recipe` before `/gsd-verify-work` |

*All logic-level behaviors (SC3, SC4 mapping) have automated SDK Vitest coverage; only the end-to-end nav flow is local-run rather than CI-on-branch.*

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or a Wave 0 dependency (all 9 plans carry automated verify refs)
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (SC3 facade test, SC4 sdk-core 410 test, 3 e2e cases) — all present and behavior-verified
- [x] No watch-mode flags
- [x] Feedback latency < 30s (SDK loop) — sdk 6.2s, sdk-core 1.5s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** COMPLIANT — audited 2026-07-10. All 5 Wave 0 items exist and genuinely exercise the target behavior (test bodies read, not just filenames). SDK Vitest (`file-metadata-facade`, `resolve-node-identity`) and sdk-core Vitest (`ipns` 410→tombstoned) run green locally. The 3 web-e2e cases (SC1 `8.4b`, SC2 desync deeper-mutate, SC4 rotation classifier-driven) are behaviorally correct and assert real outcomes; they are main-push gated in CI and run locally per the Manual-Only table. 0 gaps.
