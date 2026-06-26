---
phase: 54-e2e-test-infra-typing
plan: 04
subsystem: e2e-test-infra
tags: [typescript-migration, e2e-scripts, runner-scripts, mjs-removal]
requires: [54-02, 54-03]
provides:
  - "all 8 desktop-e2e runner scripts invoke tsx <name>.ts (no node *.mjs)"
  - "zero .mjs helper scripts remain in the 7 migrated paths"
affects:
  - tests/desktop-e2e/scripts/run-all.sh
  - tests/desktop-e2e/scripts/run-all.ps1
  - tests/desktop-e2e/scripts/test-round-trip.sh
  - tests/desktop-e2e/scripts/test-round-trip.ps1
  - tests/desktop-e2e/scripts/test-cross-client-sync.sh
  - tests/desktop-e2e/scripts/test-cross-client-sync.ps1
  - tests/desktop-e2e/scripts/test-conflict-detection.sh
  - tests/desktop-e2e/scripts/test-conflict-detection.ps1
tech-stack:
  added: []
  patterns: ["tsx invocation in lockstep across .sh and .ps1 runners", "git rm of superseded .mjs originals"]
key-files:
  created: []
  modified:
    - tests/desktop-e2e/scripts/run-all.sh
    - tests/desktop-e2e/scripts/run-all.ps1
    - tests/desktop-e2e/scripts/test-round-trip.sh
    - tests/desktop-e2e/scripts/test-round-trip.ps1
    - tests/desktop-e2e/scripts/test-cross-client-sync.sh
    - tests/desktop-e2e/scripts/test-cross-client-sync.ps1
    - tests/desktop-e2e/scripts/test-conflict-detection.sh
    - tests/desktop-e2e/scripts/test-conflict-detection.ps1
    - packages/sdk-core/scripts/edit-filepointer.ts
    - packages/sdk-core/scripts/rename-folder.ts
    - packages/sdk-core/scripts/verify-filepointer.ts
    - tests/e2e-helpers/auth.ts
  deleted:
    - packages/sdk-core/scripts/edit-filepointer.mjs
    - packages/sdk-core/scripts/rename-folder.mjs
    - packages/sdk-core/scripts/verify-filepointer.mjs
    - tests/desktop-e2e/scripts/bump-ipns-sequence.mjs
    - tests/desktop-e2e/scripts/test-move-content.mjs
    - tests/web-e2e/staging-perf-wallet.mjs
    - apps/desktop/src-tauri/generate-test-vectors.mjs
decisions:
  - "Intentional divergence preserved (D-07): test-cross-client-sync.ps1 still has NO rename-folder call — not added"
  - "ensure_verifier_runtime / Ensure-VerifierRuntime dist-existence guards retained (tsx still resolves @cipherbox/sdk-core to dist/index.mjs at runtime)"
  - "Dangling .mjs self-references in usage strings + auth.ts doc comment updated to .ts to satisfy the no-dangling-reference gate"
metrics:
  duration: ~15m
  completed: 2026-06-20
---

# Phase 54 Plan 04: Lockstep Runner Switch + .mjs Removal Summary

Closed the E2E TypeScript migration: switched all 8 desktop-e2e runner scripts from `node <name>.mjs` to `tsx <name>.ts` in lockstep across `.sh` and `.ps1` (D-06), then deleted the 7 superseded `.mjs` originals (D-05). The intentional `test-cross-client-sync.ps1` rename-folder omission is preserved (D-07). After this plan, `node *.mjs` is gone from every E2E invocation path.

## What Was Done

### Task 1 — switch all 8 runner scripts node to tsx in lockstep (commit a3fef67d3)

All 8 runner scripts updated together so the `.sh` and `.ps1` paths stay in parity (the root cause of the Windows-only `#509` break was that they had diverged):

- `run-all.{sh,ps1}` → `test-move-content.ts`
- `test-round-trip.{sh,ps1}` → `verify-filepointer.ts`
- `test-cross-client-sync.sh` → `verify-filepointer.ts` + `edit-filepointer.ts` + `rename-folder.ts` (3 calls)
- `test-cross-client-sync.ps1` → `verify-filepointer.ts` + `edit-filepointer.ts` (2 calls — rename-folder intentionally omitted, D-07)
- `test-conflict-detection.{sh,ps1}` → `bump-ipns-sequence.ts`

Bash form: `pnpm exec tsx "<path>/<name>.ts"` preserving the `TEST_SECRET="..."` env prefix and all args. PowerShell form: `& pnpm exec tsx <pathVar>` with the path variable's extension changed `.mjs → .ts`, preserving the `$env:TEST_SECRET` assignment and all args. The `ensure_verifier_runtime` / `Ensure-VerifierRuntime` dist-existence guards were left as-is — tsx still resolves `@cipherbox/sdk-core` to `dist/index.mjs` at runtime, so the guard remains valid.

### Task 2 — delete the 7 .mjs originals + dangling-reference cleanup (this commit)

- `git rm` of all 7 `.mjs` originals: `packages/sdk-core/scripts/{edit-filepointer,rename-folder,verify-filepointer}.mjs`, `tests/desktop-e2e/scripts/{bump-ipns-sequence,test-move-content}.mjs`, `tests/web-e2e/staging-perf-wallet.mjs`, `apps/desktop/src-tauri/generate-test-vectors.mjs`.
- Updated 4 dangling self-references from `.mjs` to `.ts` so the no-dangling-reference gate passes: the `Usage:` strings in `edit-filepointer.ts`, `rename-folder.ts`, and `verify-filepointer.ts` (each printed its own old `.mjs` basename), and the `tests/e2e-helpers/auth.ts` doc comment that cited `edit-filepointer.mjs` as the verbatim-extraction source. These are pure string/comment edits with no behavioral effect.

## Key Decisions / Findings

### D-07: cross-client-sync.ps1 rename-folder omission preserved

`test-cross-client-sync.ps1` deliberately does NOT invoke `rename-folder` (per 54-RESEARCH Open Question 2). The lockstep update kept that divergence — it was not silently "fixed" by adding a rename-folder call. The Task 1 grep gate asserts zero `rename-folder` references in that file.

### Verifier runtime guards retained

The dist-existence guards in `test-round-trip.{sh,ps1}` were intentionally NOT removed. `tsx` transpiles the helper `.ts` on the fly but the helper still imports `@cipherbox/sdk-core`, which resolves to `dist/index.mjs` at runtime — so the dist must exist, and the guard stays valid (54-RESEARCH Pitfall 5).

## Deviations from Plan

None substantive. The plan listed the `.mjs` paths as `files_modified` (deletions). The 4 dangling-reference edits to `.ts`/`auth.ts` are within Task 2's stated action ("update any such comment to the .ts/tsx form rather than leaving a dangling .mjs reference") and are required for the Task 2 verify gate to pass.

Note: Task 1 (the 8 runner scripts) was committed separately as `a3fef67d3` in a prior session; this plan's final commit completes Task 2 (the `.mjs` deletions + dangling-reference cleanup + this summary).

## Verification Results

- Task 1 grep gate: PASS — 0 `node *.mjs` helper invocations remain across the 8 runners; 9 `tsx .ts` helper invocations present; `test-cross-client-sync.ps1` has 0 `rename-folder` references.
- Task 2 gate part A: PASS — `git ls-files` shows 0 `.mjs` in the 7 migrated paths; 0 dangling `.mjs` references across `tests apps packages scripts .github`.
- Task 2 static gate: PASS — `pnpm typecheck` exit 0 (builds crypto/core/api-client/sdk-core/sdk dist + scripts tsconfig + root typecheck) and `pnpm lint` exit 0.

## Manual Verification Required (per 54-VALIDATION.md)

The desktop `run-all.sh` and web-e2e suites are the behavioral verification for the lockstep switch — they require a live stack and were NOT run here (project memory: GSD subagents must not run full E2E/unit suites). Flagged for the phase verifier.

## Not Done (out of scope)

- No new package installs (RESEARCH Package Legitimacy Audit: none).
- No runner logic, ordering, or messaging changes beyond the `node *.mjs → tsx *.ts` invocation swap.

## Self-Check: PASSED

All 8 runner scripts invoke `tsx <name>.ts` with no `node *.mjs` helper invocations; all 7 `.mjs` originals are deleted (0 tracked); no dangling `.mjs` reference remains; `pnpm typecheck` + `pnpm lint` both exit 0.
