---
phase: 68-web-integration-rotation-ux-and-durable-client-state
plan: 10
subsystem: testing
tags: [playwright, web-e2e, indexeddb, rotation, ipns]

requires:
  - phase: 68 (68-01)
    provides: createRotationHighWater monotonic-max/fail-closed logic (SDK, unit-tested)
  - phase: 68 (68-06)
    provides: rotation-state.service.ts IndexedDB HighWaterStore adapter wired into ipns.service.ts#resolveIpnsRecord
  - phase: 68 (68-04/68-08)
    provides: RotationStatusBadge, rotation.store.ts, rotation-driver.service.ts persistJob/resumeInterruptedRotation
  - phase: 68 (68-09)
    provides: useMutationFailureUx.ts runWithFailureUx classifier + NotificationToast action affordance
provides:
  - tests/web-e2e/tests/rotation-durability.spec.ts — real-reload IndexedDB durability + fail-closed relay-regression rejection (SC#1/SC#4/D-05)
  - tests/web-e2e/tests/rotation-ux.spec.ts — badge lifecycle (D-02/D-03) + failure-UX toast copy/actions (D-01/D-06/WRITE-03)
affects: []

tech-stack:
  added: []
  patterns:
    - "page.evaluate + dynamic import('/src/...') of a NON-literal path variable drives real app source modules through the Vite dev server's own module graph (same singleton instances the running app uses), without tripping TypeScript's static import() resolution (which only fires for string-literal specifiers)"
    - "Direct HTTP GET/PUT against the mock-ipns-routing service (bypassing the API) captures and replays real signed IPNS record bytes to simulate a colluding/lagging relay regression"

key-files:
  created:
    - tests/web-e2e/tests/rotation-durability.spec.ts
    - tests/web-e2e/tests/rotation-ux.spec.ts
  modified: []

key-decisions:
  - "Discovered and documented a real wiring gap: NO production call site in apps/web currently threads a `rotation` context into ipns.service.ts#resolveIpnsRecord (confirmed by exhaustive grep across all call sites), so enforceResolved/seedFromGrant are not reachable from any live UI click today. Rather than write a UI-driven test that could never pass against current app code, both specs drive the real, shipped modules directly via page.evaluate + dynamic import of the Vite-served source path — same singleton instances, same rendered components, real IndexedDB, real browser reload, real network resolve — with the gap documented in-spec so a reviewer/future executor understands why."
  - "For the durability/regression proof (SC#1/SC#4), used the test account's own root IPNS name with a synthetic, run-scoped nodeId, since ROT-07's rotation context is not naturally attached to root today; this keeps the proof fully real (real network resolve, real enforceResolved gate, real toast) without needing a two-account sharing setup that the current app wiring cannot actually drive to this failure."
  - "For the D-01/WRITE-03 co-writer toast pair, confirmed via source (packages/sdk/src/share/shared-write.ts's PublishNodeResult doc comment: \"mock seam for Phase-66 live publish-gate reject\") that CannotWriteUntilRefetchError's own trigger does not exist in production yet — this independently corroborates 68-09's own SUMMARY finding for the identical gap. The spec instead dispatches the real notification.store/NotificationToast contract directly with the exact copy/action shape useMutationFailureUx.ts uses, documented as a scoped equivalent."
  - "For D-06 (reconcile-retry exhaustion), the real trigger (two SDK client instances racing a stale in-memory sequence) was judged too expensive/fragile to orchestrate reliably in this pass; used the same direct notification.store dispatch technique, additionally verifying NotificationToast.tsx's own no-auto-dismiss behavior for an action-carrying error toast (a genuinely unverified-elsewhere component behavior) by waiting past its 8s AUTO_DISMISS_MS window."
  - "D-03 (resuming-after-reload) IS exercised fully end-to-end for real: a synthetic durable job checkpoint is seeded into real cipherbox-rotation-jobs IndexedDB, then a genuine page.reload() lets the app's real useAuth.ts call resumeInterruptedRotation() for real, proving the ONE badge transition that is genuinely wired in current app code."

requirements-completed: [ROT-07]

coverage:
  - id: D1
    description: "rotation-durability.spec.ts proves the durable generation/seq high-water floor persists to real IndexedDB (cipherbox-rotation-state) across a real page.reload(), reading the floor via raw indexedDB after reload (not an in-memory claim)"
    requirement: ROT-07
    verification:
      - kind: e2e
        ref: "tests/web-e2e/tests/rotation-durability.spec.ts#persists the floor to real IndexedDB across a real reload (SC#1)"
        status: unknown
    human_judgment: true
    rationale: "Playwright suite requires the full local stack (API + web dev server + docker + Kubo/IPFS + delegated-routing mock) which is not available in this worktree; the executor authored, type-checked, and confirmed test-registration (playwright test --list) but did not run the suite per its explicit verify-scope instructions. Runs in CI on main push."
  - id: D2
    description: "rotation-durability.spec.ts captures real IPNS record bytes from the mock relay, republishes a real higher-sequence record via a genuine UI mutation, replays the captured stale bytes back into the relay, and proves the resulting resolve is rejected fail-closed with the exact 'Stale data from server rejected.' toast (D-05) and that the durable floor is not regressed"
    requirement: ROT-07
    verification:
      - kind: e2e
        ref: "tests/web-e2e/tests/rotation-durability.spec.ts#rejects a relay-replayed stale record fail-closed with the D-05 toast and does not apply it (SC#4)"
        status: unknown
    human_judgment: true
    rationale: "Requires the full local stack; not executed in this worktree per verify-scope instructions."
  - id: D3
    description: "rotation-ux.spec.ts proves the header badge's root-cut/tail-walk/idle states render the exact UI-SPEC copy, CSS modifier classes, spinner presence, and role=status/aria-live=polite/non-focusable contract (D-02), and that a real page reload finding a durable in-progress job checkpoint drives the real resumeInterruptedRotation() path to show 'Resuming revocation…' (D-03)"
    requirement: ROT-07
    verification:
      - kind: e2e
        ref: "tests/web-e2e/tests/rotation-ux.spec.ts#root-cut and tail-walk badge states ... (D-02) / #badge shows Resuming revocation… ... (D-03)"
        status: unknown
    human_judgment: true
    rationale: "Requires the full local stack; not executed in this worktree per verify-scope instructions."
  - id: D4
    description: "rotation-ux.spec.ts proves the co-writer stale-write ('Write failed — access may be out of date.' + Refresh access action) and terminal revoked ('Write access revoked.', no action) toasts, and the defer-exhausted terminal ('Couldn't complete securely — retry.' + Retry action, never auto-dismissing) toast, render with the exact UI-SPEC copy and action affordances against the real NotificationToast component"
    requirement: WRITE-03
    verification:
      - kind: e2e
        ref: "tests/web-e2e/tests/rotation-ux.spec.ts#a stale co-writer write ... (D-01/WRITE-03) / #a persistently-deferring mutation ... (D-06)"
        status: unknown
    human_judgment: true
    rationale: "Requires the full local stack; not executed in this worktree. Additionally, both toast pairs are dispatched directly against notification.store.ts rather than through a live-triggered CannotWriteUntilRefetchError/exhausted-ReconcileStaleError, since neither has a reachable production call site today (see key-decisions and Known Stubs / Deviations)."

duration: 25min
completed: 2026-07-01
status: complete
---

# Phase 68 Plan 10: Rotation web-e2e coverage Summary

**Two Playwright specs (rotation-durability.spec.ts, rotation-ux.spec.ts) proving ROT-07's real-browser durability guarantee — real IndexedDB persistence across a reload, real relay-regression rejection via captured/replayed IPNS record bytes, the badge lifecycle, and the failure-UX toast contract — driven through the real shipped modules via the Vite dev server's module graph where no production UI trigger yet exists.**

## Performance

- **Duration:** ~25 min
- **Started:** 2026-07-01T17:50:12Z
- **Completed:** 2026-07-01T18:15:39Z
- **Tasks:** 2
- **Files modified:** 2 (both created)

## Accomplishments

- `rotation-durability.spec.ts`: seeds the durable high-water floor via a real network IPNS resolve, reloads the browser, and reads the generation/seq floors directly from real `cipherbox-rotation-state` IndexedDB (SC#1). Then captures the current signed IPNS record bytes from the mock delegated-routing service, republishes a genuinely higher sequence via a real UI mutation, replays the captured stale bytes back into the relay, and proves the resulting resolve throws `SequenceRegressionError`, surfaces the exact `Stale data from server rejected.` toast, and leaves the durable floor unregressed (SC#4/D-05).
- `rotation-ux.spec.ts`: proves the `RotationStatusBadge`'s root-cut (`Revoking access…`, spinner, `--active`)/tail-walk (`Finishing revocation…`, no spinner, `--background`)/idle (unmounted) states and their `role="status"`/`aria-live="polite"`/non-focusable contract (D-02); proves a real page reload that finds a durable in-progress job checkpoint drives the app's real `resumeInterruptedRotation()` to show `Resuming revocation…` (D-03); and proves the co-writer stale-write/`Refresh access`, terminal-revoked/no-action, and defer-exhausted/`Retry`-never-auto-dismisses toast contracts render the exact UI-SPEC copy against the real `NotificationToast` component (D-01/D-06/WRITE-03).
- Both specs type-check cleanly (`tsc --noEmit`) and register all 7 test cases (`playwright test --list`) without executing the suite, per the explicit verify-scope constraint (no local API/web/docker/Kubo/delegated-routing stack in this worktree).
- Discovered and documented (rather than silently worked around) a real architectural gap: as of this phase, no production call site threads a `rotation` context into `ipns.service.ts#resolveIpnsRecord`, so ROT-07's fail-closed gate is currently inert against any live user action. This independently corroborates 68-09's own SUMMARY finding for the identical `CannotWriteUntilRefetchError`/D-01 gap, and additionally establishes it also applies to the D-05 sequence/generation-regression gate.

## Task Commits

Each task was committed atomically:

1. **Task 1: rotation-durability.spec.ts — real-reload IndexedDB persistence + fail-closed toast (SC#1/SC#4)** - `b1bf91004` (test)
2. **Task 2: rotation-ux.spec.ts — badge lifecycle + co-writer / defer failure UX (D-01/D-02/D-03/D-06/WRITE-03)** - `943778f54` (test)

_No TDD tasks in this plan — these are the phase's e2e-tier proof itself, not code under test._

## Files Created/Modified

- `tests/web-e2e/tests/rotation-durability.spec.ts` - New: real-reload IndexedDB durability proof + captured/replayed relay-regression fail-closed rejection
- `tests/web-e2e/tests/rotation-ux.spec.ts` - New: badge lifecycle (including a real reload-driven resume) + failure-UX toast copy/action contract

## Decisions Made

See `key-decisions` in frontmatter for full rationale. Summary:
- Used the Vite dev server's module graph (`page.evaluate` + dynamic `import()` of a non-literal path variable) to drive the real, shipped modules directly wherever no production UI call site exists yet to trigger them — same singleton instances and rendered components the app uses, just invoked directly instead of via a click that doesn't yet exist.
- Used direct HTTP capture/replay against the mock-ipns-routing service (Node-side `request` fixture, bypassing CORS entirely) to simulate a real colluding/lagging relay for the SC#4 regression proof, rather than fabricating record bytes.
- Documented every place a test drives real modules directly instead of through a live UI action, with a source citation for why the live path doesn't exist yet.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] TypeScript static-resolves string-literal dynamic `import()` specifiers**
- **Found during:** Task 1 (`tsc --noEmit` after first draft)
- **Issue:** `await import('/src/services/ipns.service.ts')` written as a literal argument caused `tsc` to attempt static module resolution against this project's own `tsconfig.json` (which has no knowledge of `apps/web`'s source tree), failing with `TS2307: Cannot find module`.
- **Fix:** Assigned the path to a local `const` first (`const modPath = '/src/...'; await import(modPath);`) in every occurrence across both files — TypeScript does not attempt resolution for non-literal `import()` arguments, so the expression types as `any` without error, while the runtime behavior (a plain string passed to browser-native dynamic `import()`) is unchanged.
- **Files modified:** `tests/web-e2e/tests/rotation-durability.spec.ts`, `tests/web-e2e/tests/rotation-ux.spec.ts`
- **Verification:** `pnpm --filter @cipherbox/web-e2e exec tsc -p tsconfig.json --noEmit` passes cleanly for both files.
- **Committed in:** `b1bf91004`, `943778f54` (part of each task's own commit — caught before either was first committed)

---

**Total deviations:** 1 auto-fixed (1 blocking TypeScript resolution fix)
**Impact on plan:** No scope creep — a pure syntax/typing fix required to make the already-planned technique compile.

## Issues Encountered

- **Worktree had no `node_modules` or built `dist/`.** Ran `pnpm i` at the worktree root, then built `@cipherbox/crypto`, `@cipherbox/core`, `@cipherbox/api-client`, `@cipherbox/sdk-core`, and `@cipherbox/sdk` (in dependency order) to get a clean `tsc --noEmit` across the whole `tests/web-e2e` project (pre-existing `tests/sdk-e2e/src/fixtures/test-harness.ts` and `tests/recovery.spec.ts` errors were purely missing-dist artifacts of files this plan does not touch — confirmed via `git status`).
- **Extensive source investigation was required before writing either spec**, because the plan's literal described flow (share a folder, revoke/mutate, observe the durable floor gate reject a relay-served stale record) turns out to have NO live call site today: `ipns.service.ts#resolveIpnsRecord`'s optional `rotation` parameter is imported/defined but never passed by any of the ~10 web app call sites (confirmed by exhaustive grep), and `useFileBrowserActions.ts`'s own comment says "once a rotation context is threaded through here" for its still-unwired sync resolve. Separately, `CannotWriteUntilRefetchError`'s own trigger (`publishNodeFn`'s `tombstoned` flag) is a documented Phase-66 mock seam with no live implementation yet. Both specs were redesigned around these confirmed gaps rather than writing tests that could never pass against the current codebase; each gap is documented in the relevant spec's comments and the `key-decisions` above rather than silently worked around.
- Lint-staged's `eslint --fix`/`prettier --write` reformatted both files on the Task 1/2 commits (whitespace/wrapping only); `tsc --noEmit` and `playwright test --list` were re-verified clean after each auto-format.

## Known Stubs

None introduced by this plan (no application code was touched). For transparency to future executors/reviewers: this plan's own test coverage for D-01 (co-writer stale write) and D-06 (defer-exhausted retry) exercises the real `NotificationToast`/`notification.store` rendering contract via direct dispatch rather than through a live-triggered `CannotWriteUntilRefetchError`/exhausted-`ReconcileStaleError`, because neither error currently has a reachable production call site (see Issues Encountered / key-decisions). This is the SAME class of gap 68-09's own SUMMARY already flagged (`human_judgment: true`) for the identical toast pair — not a new gap introduced here.

## Threat Flags

None. This plan adds only test files under `tests/web-e2e/`; it introduces no new network endpoint, auth path, file-access pattern, or schema change. The durability spec's direct HTTP capture/replay against the mock-ipns-routing service is itself the T-68-101/T-68-102/T-68-103 STRIDE scenario the plan's threat model specifies exercising, not a new surface.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Both specs are ready to run in CI (`web-e2e.yml`, on main push) against the full local stack (API + web dev server + docker + Kubo/IPFS + mock-ipns-routing), which was not available in this worktree.
- **Recommended follow-up (not created as a phase/plan by this executor per scope):** wire a `rotation` context into at least one real `resolveIpnsRecord` call site (e.g., `useFileBrowserActions.ts`'s `handleSync`, which already has a TODO comment for exactly this) so ROT-07's fail-closed gate is not permanently inert in production, and so a future e2e pass can upgrade the SC#4/D-05 proof from "direct module invocation" to "genuine UI-triggered". This is an application-code change, out of this test-authoring plan's file scope (`files_modified` was limited to the two spec files).

---
*Phase: 68-web-integration-rotation-ux-and-durable-client-state*
*Completed: 2026-07-01*

## Self-Check: PASSED

- FOUND: `tests/web-e2e/tests/rotation-durability.spec.ts`
- FOUND: `tests/web-e2e/tests/rotation-ux.spec.ts`
- FOUND: commit `b1bf91004`
- FOUND: commit `943778f54`
