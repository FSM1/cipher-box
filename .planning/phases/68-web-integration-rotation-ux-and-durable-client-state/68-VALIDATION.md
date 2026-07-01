---
phase: 68
slug: web-integration-rotation-ux-and-durable-client-state
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-01
---

# Phase 68 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Vitest (`apps/web/vitest.config.ts`: `environment: 'node'`, `globals: true`; `packages/sdk` uses its own vitest config) |
| **Config file** | `apps/web/vitest.config.ts` (include: `src/**/*.test.ts` only — `.spec.ts` is silently skipped, SC#5) |
| **Quick run command** | `pnpm --filter @cipherbox/web test -- <file-glob>` (sdk: `pnpm --filter @cipherbox/sdk test -- <file-glob>`) |
| **Full suite command** | `pnpm --filter @cipherbox/web test && pnpm --filter @cipherbox/sdk test` |
| **Estimated runtime** | ~30–60 seconds (web + sdk unit suites) |

Rotation-engine correctness (crash-safety, resume, content-key rotation, HIGH-3/HIGH-4) is already proven in `packages/sdk-core/src/__tests__` and `tests/sdk-e2e`. Phase 68 validates only the **web/sdk-client wiring** into that engine and the durable high-water persistence/enforcement — it does not re-prove engine internals.

---

## Sampling Rate

- **After every task commit:** Run `pnpm --filter <touched-package> test -- <touched-file>` (targeted).
- **After every plan wave:** Run `pnpm --filter @cipherbox/web test` and `pnpm --filter @cipherbox/sdk test` (full suites).
- **Before `/gsd-verify-work`:** Both full suites green AND `find apps/web/src -name "*.spec.ts"` returns empty (SC#5).
- **Max feedback latency:** 60 seconds.

---

## Per-Task Verification Map

> Task IDs are assigned during planning/execution. This map seeds the requirement → test-strategy mapping the planner and executor fill in per task. Every task that touches a success-criterion path MUST carry an `<automated>` verify or a Wave 0 dependency.

| Req / SC | Behavior | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists |
|----------|----------|------------|-----------------|-----------|-------------------|-------------|
| ROT-07 / SC#1 / §7.3 test 5 | `{nodeId→highestGeneration}` persists across a simulated page reload; a downgrade is rejected fail-closed after restart | Colluding-relay stale/replayed record (§4.3 M1) | Regression → throw, never silent accept | unit | `pnpm --filter @cipherbox/web test -- rotation-state.test.ts` | ❌ W0 |
| SC#2 | `executeLazyRotation` deleted; delete/move/rename-on-scope-exit call `rotateReadFromNode`; `addShareKeys`/`reWrapForRecipients` removed from fan-out | T-63-17 grant-omission | Scope-exit ⇒ rotate invariant preserved | unit (spy on injected `rotate`, mirror `scope.test.ts`) | `pnpm --filter @cipherbox/sdk test -- client-rotation.test.ts` | ❌ W0 |
| SC#3 | `folderTree` reconciled vs current `sequenceNumber` before rotation publish; reconcile failure defers (never skips) | `#489`/`#494` desync | Defer, never silent missed revocation | unit (mock mismatched sequence, assert no publish + defer notice) | `pnpm --filter @cipherbox/sdk test -- client-rotation.test.ts` | ❌ W0 |
| SC#4 / §7.3 test 13 | Durable `{nodeId→highestSeq}` high-water wired into `resolveIpnsRecord`; within-generation seq regression → fail-closed | Colluding-relay stale-seq (§6.5) | Regression → throw, never silent accept | unit (mock lower seq than stored high-water, assert throw) | `pnpm --filter @cipherbox/web test -- ipns.service.test.ts` | ❌ W0 |
| §7.3 test 14 | First-contact/cold-device rollback rejected via `SealedChildRef.versionFloor` (no local high-water yet) | Cold-device rollback (§2.6) | Below-floor seq from relay → rejected | unit (fresh client, no local high-water, below-floor seq → reject) | `pnpm --filter @cipherbox/web test -- rotation-state.test.ts` | ❌ W0 |
| SC#5 | No `.spec.ts` files under `apps/web/src` | — | — | static shell check | `find apps/web/src -name "*.spec.ts"` (must be empty) | n/a |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] **Test-environment IndexedDB shim** — `apps/web/vitest.config.ts` is `environment: 'node'` (no native `indexedDB`). Confirm whether `fake-indexeddb` is already a devDependency in the monorepo (not found in research); if absent, add it (or switch the durable-store test file's environment to `jsdom`/`happy-dom`). **Real infra gap, not a nitpick** — blocks SC#1/ROT-07/§7.3 test 5/14.
- [ ] `apps/web/src/services/rotation-state.test.ts` — durable high-water persistence + monotonic-max + regression rejection + restart survival (SC#1, §7.3 test 5/14).
- [ ] `packages/sdk/src/__tests__/client-rotation.test.ts` (or extend `client.test.ts`) — scope-exit `rotateReadFromNode` wiring + reconcile-defer, using the proven `vi.fn()` injection pattern from `scope.test.ts` (SC#2, SC#3).
- [ ] `apps/web/src/services/ipns.service.test.ts` — confirm at plan time whether `ipns.service.ts` has any existing coverage before assuming greenfield; seq high-water fail-closed enforcement (SC#4, §7.3 test 13).

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Rotation-progress badge states (root-cut spinner → tail-walk pill → resuming-after-reload) render correctly in the app header | D-02/D-03 (UI-SPEC) | Visual/DOM state across a real page reload mid-walk; Puppeteer MCP can screenshot but state-machine timing is best human-confirmed | Trigger a revocation on a shared subtree, observe `Revoking access…` → `Finishing revocation…`, reload mid-walk, confirm `Resuming revocation…` |
| Toast copy + action buttons (`Refresh access`, `Retry`) match UI-SPEC exactly | D-01/D-04/D-05/D-06/D-08 | Copy/interaction fidelity | Drive each failure path, confirm exact strings and action button presence per UI-SPEC table |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references (IndexedDB test shim is the critical one)
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
