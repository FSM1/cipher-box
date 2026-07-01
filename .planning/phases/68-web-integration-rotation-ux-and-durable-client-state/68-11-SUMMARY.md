---
phase: 68-web-integration-rotation-ux-and-durable-client-state
plan: 11
subsystem: auth
tags: [ipns, rotation, anti-rollback, sdk, playwright, e2e]

requires:
  - phase: 68-web-integration-rotation-ux-and-durable-client-state
    provides: "68-01 RotationHighWater/enforceResolved SDK logic; 68-06 IndexedDB-backed rotation-state.service.ts adapter; 68-05 reconcileFolderSequence chokepoint; 68-10 rotation-durability.spec.ts module-invocation proof"
provides:
  - "Optional rotationHighWater injection seam on CipherBoxClientConfig"
  - "reconcileFolderSequence gates its resolve through enforceResolved before the ReconcileStaleError check, propagating SequenceRegressionError/GenerationRegressionError fail-closed"
  - "useAuth.ts injects the IndexedDB-backed rotationHighWater into every live SDK client"
  - "useFileBrowserActions.ts's handleSync threads a real ResolveRotationContext"
  - "rotation-durability.spec.ts SC#4 proof upgraded to a genuine UI-driven mutation"
affects: [rotation, sdk-client, web-file-browser, web-e2e]

tech-stack:
  added: []
  patterns:
    - "Fail-closed gate injected via optional client config field, defaulting to zero enforcement when absent (matches existing rotationCallbacks pattern)"
    - "Reconcile-time gate call placed outside the resolve try/catch so regression errors propagate to the mutation caller instead of being swallowed by transient-network handling"

key-files:
  created: []
  modified:
    - packages/sdk/src/types.ts
    - packages/sdk/src/client.ts
    - packages/sdk/src/__tests__/client-rotation.test.ts
    - apps/web/src/hooks/useAuth.ts
    - apps/web/src/components/file-browser/useFileBrowserActions.ts
    - tests/web-e2e/tests/rotation-durability.spec.ts

key-decisions:
  - "reconcileFolderSequence passes nodeGeneration from the in-memory folderTree entry (this.folderTree.get(ipnsName)?.nodeGeneration ?? 0), never the resolved envelope's generation, per EnforceResolvedParams semantics"
  - "handleSync's ResolveRotationContext uses generation: 0 since useFolderStore's FolderNode carries no generation field for root — matches the SDK client's own ?? 0 default"
  - "rotation-durability.spec.ts now drives the SC#4 rejection via two real UI renames (seed + bump + reject) instead of direct page.evaluate module invocation; page.evaluate is retained ONLY for read-only IndexedDB floor inspection and identifying the account's own rootIpnsName, never for invoking resolveIpnsRecord/enforceResolved directly"

patterns-established:
  - "A resolve chokepoint gated by an optional RotationHighWater seam is proven both at the unit tier (fake enforceResolved via vi.fn) and the e2e tier (real UI mutation) without requiring any apps/web unit test file (SC#5)"

requirements-completed: [ROT-07]

coverage:
  - id: D1
    description: "reconcileFolderSequence gates its resolve through the injected RotationHighWater.enforceResolved, throwing SequenceRegressionError/GenerationRegressionError fail-closed on a below-floor resolve, and is unchanged (zero enforcement) when no rotationHighWater is configured"
    requirement: "ROT-07"
    verification:
      - kind: unit
        ref: "packages/sdk/src/__tests__/client-rotation.test.ts#CipherBoxClient — reconcile-time enforceResolved fail-closed (Gap 1 / SC#4)"
        status: pass
    human_judgment: false
  - id: D2
    description: "The IndexedDB-backed rotationHighWater is injected into the live web SDK client (useAuth.ts), and useFileBrowserActions.ts's handleSync threads a real ResolveRotationContext instead of an ungated resolve"
    requirement: "ROT-07"
    verification:
      - kind: unit
        ref: "grep -n rotationHighWater apps/web/src/hooks/useAuth.ts; grep -n 'resolveIpnsRecord(rootIpnsName' apps/web/src/components/file-browser/useFileBrowserActions.ts"
        status: pass
    human_judgment: false
  - id: D3
    description: "rotation-durability.spec.ts's SC#4 assertion proves the fail-closed rejection via a genuine UI-driven rename mutation over the live reconcileFolderSequence/enforceResolved path, asserting the D-05 toast and an unregressed durable floor"
    requirement: "ROT-07"
    verification:
      - kind: e2e
        ref: "tests/web-e2e/tests/rotation-durability.spec.ts#rejects a relay-replayed stale record fail-closed via a genuine UI mutation, with the D-05 toast, and does not apply it (SC#4)"
        status: unknown
    human_judgment: true
    rationale: "Full execution requires the local API + web dev server + docker + Kubo + mock delegated-routing stack, not available in this executor sandbox; runs in CI on main push per project doctrine (docs/TESTING.md). Spec authorship, typecheck-clean status, and playwright test --list registration were verified live in this pass."

duration: 25min
completed: 2026-07-01
status: complete
---

# Phase 68 Plan 11: Live Wiring of the ROT-07 Fail-Closed Anti-Rollback Gate Summary

**Wires the previously-inert `RotationHighWater.enforceResolved` gate into the SDK client's own `reconcileFolderSequence` resolve and the web app's `handleSync`, closing VERIFICATION Gap 1 (BLOCKER).**

## Performance

- **Duration:** 25 min
- **Started:** 2026-07-01T21:37:00Z
- **Completed:** 2026-07-01T22:02:00Z
- **Tasks:** 3
- **Files modified:** 6

## Accomplishments

- `CipherBoxClientConfig` gained an optional `rotationHighWater` injection seam; `reconcileFolderSequence` now calls `rotationHighWater.enforceResolved` on every resolved seq/generation before its existing `ReconcileStaleError` check, with the call placed outside the resolve try/catch so `SequenceRegressionError`/`GenerationRegressionError` propagate to the mutation caller (and thence to `useMutationFailureUx`'s D-05 classifier) rather than being silently swallowed.
- `useAuth.ts` injects the real IndexedDB-backed `rotationHighWater` (from `rotation-state.service.ts`) into every live SDK client, making the SDK-internal gate reachable for every revocation-triggering mutation (`renameItem`/`deleteItem`/`deleteToBin`/`moveItem`) without any apps/web-side logic duplication.
- `useFileBrowserActions.ts`'s `handleSync` now threads a real `ResolveRotationContext` (`nodeId: rootIpnsName`, `generation: 0`, `versionFloor: rootFolder.sequenceNumber`) into its resolve, closing the in-code TODO and giving the background sync path the same fail-closed protection as folder mutations.
- `rotation-durability.spec.ts`'s SC#4 test is re-authored to trigger the rejection via two real UI renames (seed, then bump, then a rejected rename after replaying stale relay bytes) instead of direct `page.evaluate` module invocation — the stale "NO production call site" scope note is removed and replaced with a description of the now-live path.

## Task Commits

1. **Task 1a (RED): Failing test for reconcile-time enforceResolved gate** - `cf01a92ff` (test)
2. **Task 1b (GREEN): Gate reconcileFolderSequence resolve through enforceResolved** - `0b5929c45` (feat)
3. **Task 2: Inject rotationHighWater and thread handleSync's rotation context** - `97a527b2a` (feat)
4. **Task 3: Upgrade rotation-durability.spec.ts to a genuine UI-driven proof** - `5f0cfaa7e` (test)

_TDD gate sequence for Task 1: `test(68-11)` (RED, 2 tests failed as expected against pre-implementation code) → `feat(68-11)` (GREEN, all 21 tests pass: 18 prior + 3 new). No REFACTOR commit was needed — the implementation required no cleanup pass._

## Files Created/Modified

- `packages/sdk/src/types.ts` - Added optional `rotationHighWater?: RotationHighWater` field to `CipherBoxClientConfig`
- `packages/sdk/src/client.ts` - `reconcileFolderSequence` now calls `this.config.rotationHighWater?.enforceResolved(...)` before the `ReconcileStaleError` equality check
- `packages/sdk/src/__tests__/client-rotation.test.ts` - New describe block "reconcile-time enforceResolved fail-closed (Gap 1 / SC#4)" with 3 cases (below-floor rejection + rotateReadFromNode not called, above-floor pass-through with exact params assertion, unconfigured-client backward-compat)
- `apps/web/src/hooks/useAuth.ts` - Imports and passes `rotationHighWater` from `rotation-state.service.ts` into `initSdkClient`'s config
- `apps/web/src/components/file-browser/useFileBrowserActions.ts` - `handleSync` passes a real `ResolveRotationContext` to `resolveIpnsRecord`; removed the stale TODO comment
- `tests/web-e2e/tests/rotation-durability.spec.ts` - Re-authored SC#4 test to drive the rejection via real rename UI actions; added `ContextMenuPage`/`RenameDialogPage` imports and a shared `readDurableFloors` helper; updated the module-level SCOPE NOTE

## Decisions Made

- `reconcileFolderSequence`'s `enforceResolved` call sources `generation` from `this.folderTree.get(ipnsName)?.nodeGeneration ?? 0` (the in-memory reader mirror), never the freshly-resolved envelope's own generation, per `EnforceResolvedParams`' documented semantics (generation must be the reader's expected value, not the attacker-controlled resolved value).
- `handleSync`'s `ResolveRotationContext.generation` is hardcoded to `0` because `useFolderStore`'s `FolderNode` type carries no generation field for root — this exactly matches the SDK client's own `?? 0` fallback, so both live call sites degrade identically when no richer generation signal is available.
- The e2e spec's SC#4 proof now uses TWO real UI renames (one to seed/bump the durable floor, a second attempted after replaying stale relay bytes) rather than reusing the original single mutation from the previous SUMMARY — this was necessary because the rejection assertion needs a mutation that occurs AFTER the stale-bytes replay, and the dialog does not close on a failed rename (confirmed by reading `RenameDialog.tsx`/`handleRenameConfirm`), so the spec drives the form fields directly (`clearAndEnterName` + `clickSave`) rather than the `.rename()` convenience helper for that final step.

## Deviations from Plan

None - plan executed exactly as written. The three tasks' `<action>` and `<verify>` blocks were followed as specified; no Rule 1-4 auto-fixes were needed.

## Issues Encountered

None. All verification commands passed on the first attempt for Tasks 1 and 2. `pnpm --filter @cipherbox/sdk exec tsc -b --force` surfaces a long-standing set of pre-existing type errors in quarantined test files (`client.test.ts`, `integration.test.ts`, `move-in-shared-folder.test.ts`, etc. — Node v3 migration debt unrelated to this plan); confirmed via `git stash` that these errors are identical with and without this plan's changes, so they are out of this plan's scope per the executor's SCOPE BOUNDARY rule and were not touched.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- VERIFICATION Gap 1 (BLOCKER) is closed: the fail-closed anti-rollback gate is now reachable from two live code paths (every folder mutation via `reconcileFolderSequence`, and background sync via `handleSync`), each proven at the appropriate tier (SDK unit tests; e2e spec registered and typecheck-clean, execution deferred to CI per project doctrine).
- Gap 2 (folderTree not refreshed after `performScopeExitRotation`, "should-fix, non-blocking") from `68-VERIFICATION.md` is NOT addressed by this plan — it was scoped out per the plan's stated objective (Gap 1 only). A follow-up plan is recommended before the next full-phase verification pass if that gap is to be closed in this milestone.
- ROT-07 traceability: `REQUIREMENTS.md` should now be re-verified against both Gap-1-closure truths before flipping the requirement to "Complete" — this SUMMARY documents the code-level closure; the phase's `/gsd-verify-work` or a targeted re-verification pass should confirm end-to-end.

---

*Phase: 68-web-integration-rotation-ux-and-durable-client-state*
*Completed: 2026-07-01*
