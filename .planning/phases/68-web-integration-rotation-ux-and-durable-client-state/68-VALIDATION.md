---
phase: 68
slug: web-integration-rotation-ux-and-durable-client-state
status: approved
nyquist_compliant: true
wave_0_complete: false
created: 2026-07-01
---

# Phase 68 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Testing Doctrine (authoritative — see docs/TESTING.md)

**`apps/web` UI is NOT unit-tested.** Core logic lives in the SDK (`packages/sdk`, `packages/sdk-core`) and is unit-tested with Vitest; the web app is a thin adapter/UI layer covered ONLY by Web E2E (Playwright, `tests/web-e2e/tests/*.spec.ts`). Consequences for Phase 68:

- **SDK (Vitest, PR gate):** durable high-water state machine (monotonic-max + fail-closed regression), seq/generation resolve enforcement, scope-exit rotate + reconcile-defer, owner-reconcile logic. All behind injected interface seams so no browser API is needed in the unit test.
- **`apps/api` (Jest `.spec.ts`, PR gate):** the new `PATCH :shareId/grant` route — apps/api IS unit-tested, this is correct.
- **Web E2E (Playwright, push-to-main gate):** every user-observable flow AND the true durability proof — badge lifecycle, toasts + action buttons, co-writer Refresh-access, and the SC#1 real-browser-reload durability assertion. A "persists across reload" claim MUST be a real browser reload here — an in-memory-map unit test is rejected at review as "in-memory only."
- **No `apps/web/src/**/*.test.ts` added by this phase; no `fake-indexeddb` shim.** SC#5 is satisfied trivially (zero new apps/web test files; `find apps/web/src -name "*.spec.ts"` stays empty — web-e2e specs live under `tests/web-e2e/`).

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **SDK logic** | Vitest — `packages/sdk` and `packages/sdk-core` (existing configs; `scope.test.ts` `vi.fn()` injection pattern is the analog) |
| **API route** | Jest — `apps/api` (`.spec.ts`, existing) |
| **UI + durability** | Playwright — `tests/web-e2e/` (`playwright.config.ts`, existing rich suite: `sharing-workflow`, `writable-shares`, `bin-restore-after-reload`, …) |
| **SDK quick run** | `pnpm --filter @cipherbox/sdk test -- <file>` / `pnpm --filter @cipherbox/sdk-core test -- <file>` |
| **API quick run** | `pnpm --filter @cipherbox/api test -- <file>` |
| **Web E2E full** | `pnpm test:web-e2e` (requires full stack: PostgreSQL, IPFS, Redis, API, mock-ipns-routing, web build) |
| **Estimated runtime** | SDK/API unit ~30–60s; web-e2e minutes (push-to-main gate, not per-commit) |

---

## Sampling Rate

- **After every task commit:** targeted SDK/API unit run for the touched module (`pnpm --filter <pkg> test -- <file>`).
- **After every plan wave:** `pnpm --filter @cipherbox/sdk test`, `pnpm --filter @cipherbox/sdk-core test`, `pnpm --filter @cipherbox/api test` full suites.
- **Before `/gsd-verify-work`:** SDK + API unit suites green; the new web-e2e spec(s) green locally against a full stack; `find apps/web/src -name "*.spec.ts"` empty (SC#5).
- **Max feedback latency (unit tier):** 60 seconds. (web-e2e is the slower push-to-main tier by design.)

---

## Per-Task Verification Map

> Task IDs are assigned during planning/execution. Tier column marks where each behavior is proven.

| Req / SC | Behavior | Tier | Automated Command | File Exists |
|----------|----------|------|-------------------|-------------|
| ROT-07 / SC#1 (logic) | high-water `{nodeId→highestGeneration}` monotonic-max; generation regression → fail-closed throw | SDK unit | `pnpm --filter @cipherbox/sdk test -- <high-water>.test.ts` | ❌ W0 (new) |
| ROT-07 / SC#1 (durability) | map persists to real IndexedDB and rejects a downgrade AFTER a real page reload | web-e2e | `pnpm test:web-e2e -- rotation-durability` (new spec) | ❌ W0 (new) |
| SC#2 | `executeLazyRotation` deleted; delete/move/rename-on-scope-exit call `rotateReadFromNode` in `packages/sdk/client.ts`; `addShareKeys`/`reWrapForRecipients` fan-out + callers rerouted | SDK unit | `pnpm --filter @cipherbox/sdk test -- client-rotation.test.ts` | ❌ W0 (new) |
| SC#3 | `folderTree` reconciled vs current `sequenceNumber` before publish; reconcile failure defers (never skips) | SDK unit | `pnpm --filter @cipherbox/sdk test -- client-rotation.test.ts` | ❌ W0 (new) |
| SC#4 / §7.3 test 13 | seq high-water enforcement in the resolve chokepoint; within-generation seq regression → fail-closed | SDK unit | `pnpm --filter @cipherbox/sdk test -- <resolve-enforce>.test.ts` | ❌ W0 (new) |
| SC#4 (observable) | relay regression surfaces as the fail-closed toast, mutation not applied | web-e2e | `pnpm test:web-e2e -- rotation-durability` (assert toast) | ❌ W0 (new) |
| §7.3 test 14 | first-contact/cold-device rollback rejected via `SealedChildRef.versionFloor` (no local high-water) | SDK unit | `pnpm --filter @cipherbox/sdk test -- <resolve-enforce>.test.ts` | ❌ W0 (new) |
| D-01/D-06 (UX) | co-writer stale-write → `Refresh access` / revoked → terminal; defer-exhausted → `Retry` | web-e2e | `pnpm test:web-e2e -- rotation-ux` (new spec) | ❌ W0 (new) |
| D-02/D-03 (UX) | badge: `Revoking access…` → `Finishing revocation…` → `Resuming revocation…` after reload | web-e2e | `pnpm test:web-e2e -- rotation-ux` | ❌ W0 (new) |
| D-10/D-11 | new `PATCH :shareId/grant` owner-only; updates `readDescriptorRef`/`rootGeneration` | API unit | `pnpm --filter @cipherbox/api test -- shares.controller.spec.ts` | ❌ W0 (new) |
| SC#5 | no `.spec.ts` under `apps/web/src` | static | `find apps/web/src -name "*.spec.ts"` (must be empty) | n/a |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] New SDK unit test files (Vitest) for the hoisted logic — durable high-water state machine, resolve seq/generation enforcement — using injected storage/resolve seams (no browser API in the unit test). Analog: `packages/sdk-core/src/rotation/scope.test.ts`.
- [ ] New web-e2e Playwright spec(s) under `tests/web-e2e/tests/` — `rotation-durability.spec.ts` (real-reload durability + fail-closed toast, SC#1/SC#4) and `rotation-ux.spec.ts` (badge lifecycle + co-writer/defer UX, D-01/D-02/D-03/D-06). Analog: `tests/web-e2e/tests/bin-restore-after-reload.spec.ts` (reload pattern) + `sharing-workflow.spec.ts`.
- [ ] `apps/api` `shares.controller.spec.ts` extension (Jest) for the new PATCH route.
- [ ] **No `fake-indexeddb` shim, no new `apps/web/src` unit tests** — explicitly removed vs. the initial plan set (doctrine correction).

*The IndexedDB test-env shim is no longer a Wave-0 gap: durable-store behavior is proven by real IndexedDB in web-e2e, and the pure logic is proven in the SDK over an injected map.*

---

## Manual-Only Verifications

*All phase behaviors have automated verification via the SDK-unit + web-e2e tiers above. Optional: Puppeteer MCP screenshot of the three badge states for a visual sanity check during `/gsd-verify-work`.*

---

## Validation Sign-Off

- [x] All tasks have an `<automated>` verify at the correct tier (SDK unit / API unit / web-e2e) or a Wave 0 dependency
- [x] No new `apps/web/src/**/*.test.ts`; no `fake-indexeddb`
- [x] Durability/UI claims proven by web-e2e (real reload), logic proven by SDK unit
- [x] Sampling continuity: no 3 consecutive tasks without an automated verify
- [x] Feedback latency < 60s at the unit tier
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-07-01 (plan-checker re-verification, revised 10-plan set)
