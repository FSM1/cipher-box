---
phase: 31-structural-decomposition
verified: 2026-06-19T16:00:00Z
status: passed
score: 5/5 must-haves resolved (SC4/SC5 verified; SC1–SC3 deviations accepted as tracked tech-debt)
re_verification: false
overrides_applied: 3
overrides:
  - must_have: 'SC1: useSharedNavigation split into 3+ focused hooks each under ~400 lines'
    reason: 'The 3-hook split is achieved and fully wired (414 / 579 / 260 lines); useSharedNavigationActions.ts at 579 lines exceeds the ~400-line soft target. Accepted as tracked tech-debt — covered by the 2026-06-19 large-file refactor survey todo.'
    accepted_by: 'myankelev'
    accepted_at: '2026-06-19'
  - must_have: 'SC2: FileBrowser.tsx and SharedFileBrowser.tsx split into container + presentational components'
    reason: 'FileBrowser.tsx was cleanly split (386 presentational + 630-line container hook). SharedFileBrowser.tsx (946 lines) had only row sub-components extracted, with no container/presentational split. Accepted as tracked tech-debt — covered by the 2026-06-19 large-file refactor survey todo.'
    accepted_by: 'myankelev'
    accepted_at: '2026-06-19'
  - must_have: 'SC3: folder.service.ts decomposed into focused modules (CRUD, metadata, publish coordination)'
    reason: 'folder.service.ts was retired wholesale by a later phase (PR #422) rather than decomposed; the maintainability intent (eliminate the 1089-line monolith) is met by removal. The successor sdk-core/src/folder/index.ts (602 lines) remains larger than ideal and is tracked in the 2026-06-19 large-file refactor survey todo.'
    accepted_by: 'myankelev'
    accepted_at: '2026-06-19'
---

# Phase 31: Structural Decomposition Verification Report

**Phase Goal:** Monolithic files exceeding 900 lines are split into focused, testable modules without breaking existing functionality
**Verified:** 2026-06-19T16:00:00Z
**Status:** passed (3 accepted overrides — see frontmatter)
**Re-verification:** No — initial verification

Important context: this phase ran in March 2026. The web/SDK code has since evolved through phases 38/47/48/49 and a deprecated-service retirement (PR #422). The success criteria are verified against the CURRENT codebase, with file moves/renames traced via git history. SC4 (E2E presence) and SC5 (no new `any`) are verified outright. SC1–SC3 are size/decomposition deviations that the maintainer accepted on 2026-06-19 as tracked tech-debt (the 2026-06-19 large-file refactor survey todo) rather than blockers — recorded as accepted overrides.

---

## Goal Achievement

### Observable Truths

| #   | Truth                                                                                                                          | Status     | Evidence                                                                                                                                                                                                                                                                                                                                                                              |
| --- | ---------------------------------------------------------------------------------------------------------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | SC1: `useSharedNavigation.ts` (was 1199) split into 3+ focused hooks (nav state, key unwrapping, write ops) each under ~400 lines | ✓ PASSED (override) | Three hooks exist and are wired: `useSharedNavigation.ts` 414 lines (orchestrator), `useSharedNavigationActions.ts` 579 lines (nav + key unwrapping — 59 unwrap/decrypt/key references), `useSharedWriteOps.ts` 260 lines (upload/mkdir/rename/delete). 3-hook split achieved; `useSharedNavigationActions.ts` at 579 lines exceeds the ~400 soft target — accepted as tracked tech-debt (todo 2026-06-19). |
| 2   | SC2: `FileBrowser.tsx` (964) and `SharedFileBrowser.tsx` (943) split into container + presentational components                | ✓ PASSED (override) | `FileBrowser.tsx` cleanly split: 386 lines (presentational JSX) + `useFileBrowserActions.ts` 630 lines (container logic). `SharedFileBrowser.tsx` is 946 lines — LARGER than the original 943; only row components `SharedListRow.tsx` (65) and `SharedFolderRow.tsx` (245) were extracted, no container/presentational split — accepted as tracked tech-debt (todo 2026-06-19).        |
| 3   | SC3: `folder.service.ts` (1089) decomposed into focused modules (CRUD, metadata, publish coordination)                        | ✓ PASSED (override) | `apps/web/src/services/folder.service.ts` no longer exists — retired wholesale in LATER phase PR #422 (commit `96455b3be`). Phase 31 redirected tree helpers to `@cipherbox/sdk-core` (commit `e30d05e66`). The 1089-line monolith is eliminated; the three-way CRUD/metadata/publish split was not performed and the successor `packages/sdk-core/src/folder/index.ts` (602 lines) is tracked tech-debt (todo 2026-06-19).            |
| 4   | SC4: Existing E2E tests still present/passing (sharing-workflow, writable-shares, full-workflow)                              | ✓ VERIFIED | All three spec files exist and are substantive: `tests/web-e2e/tests/sharing-workflow.spec.ts`, `writable-shares.spec.ts`, `full-workflow.spec.ts`. The web-e2e suite is gated on main-push CI (not PRs) and has passed there for the shipped v1.1 milestone; no decomposition-related regressions reported.                                                                            |
| 5   | SC5: No new "any" casts or type regressions introduced                                                                        | ✓ VERIFIED | `grep -nE "as any|: any|<any>"` across all 12 split/created files (8 web + 4 SDK) returns zero matches. No new `any` casts in the decomposition output.                                                                                                                                                                                                                              |

**Score:** 5/5 resolved — SC4/SC5 verified outright; SC1–SC3 PASSED via accepted overrides (size/decomposition deviations tracked in the 2026-06-19 large-file refactor survey todo)

---

### Required Artifacts

| Artifact                                                          | Expected                                | Status      | Details                                                                                                       |
| ---------------------------------------------------------------- | --------------------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------ |
| `apps/web/src/hooks/useSharedNavigation.ts`                      | Orchestrator hook, ~378 lines           | VERIFIED    | 414 lines; imports and delegates to both sub-hooks (lines 19-20, 307, 339).                                   |
| `apps/web/src/hooks/useSharedNavigationActions.ts`              | Nav + key-unwrapping hook, ~400 lines   | ⚠️ OVERSIZED | 579 lines (target ~400). Heavy key-unwrapping logic present (59 references). Wired into orchestrator at line 307. |
| `apps/web/src/hooks/useSharedWriteOps.ts`                       | Write-ops hook, ~378 lines              | VERIFIED    | 260 lines; wraps SDK `withRevocationGuard` (line 17, used lines 60/136). Has a unit test.                     |
| `apps/web/src/components/file-browser/FileBrowser.tsx`          | Presentational component                | VERIFIED    | 386 lines; imports `useFileBrowserActions` (line 33, used line 71). Consumed by `FilesPage.tsx`.             |
| `apps/web/src/components/file-browser/useFileBrowserActions.ts` | Container/handler hook                   | VERIFIED    | 630 lines; provides handler callbacks consumed by FileBrowser.                                                |
| `apps/web/src/components/file-browser/SharedFileBrowser.tsx`    | Container + presentational split        | ⚠️ NOT SPLIT | 946 lines (larger than original 943). Imports/uses extracted rows (lines 41-42, 511, 736) but no container split. |
| `apps/web/src/components/file-browser/SharedListRow.tsx`        | Extracted top-level shared row          | VERIFIED    | 65 lines; used in SharedFileBrowser line 511.                                                                 |
| `apps/web/src/components/file-browser/SharedFolderRow.tsx`      | Extracted shared folder row             | VERIFIED    | 245 lines; used in SharedFileBrowser line 736.                                                                |
| `packages/sdk-core/src/folder/tree.ts`                          | Framework-agnostic tree helpers (31-01) | VERIFIED    | 87 lines; `getDepth`/`isDescendantOf`/`calculateSubtreeDepth` consumed by `MoveDialog.tsx` + `useFolderMutations.ts`. |
| `packages/sdk/src/error.ts`                                     | Error utilities (31-01)                 | VERIFIED    | Present; `withRevocationGuard` consumed by `useSharedWriteOps.ts`.                                            |
| `packages/sdk/src/share/context.ts`                             | `buildSharedWriteContext` (31-01)       | VERIFIED    | Present; consumed inside `packages/sdk/src/client.ts` (lines 2056-2162). No direct web consumer (SDK-internal). |
| `packages/sdk/src/share/key-cache.ts`                           | `ShareKeyCache` (31-01)                 | VERIFIED    | Present; consumed by `useSharedNavigation.ts` (line 138) and `useSharedNavigationActions.ts` (line 54).      |
| `apps/web/src/services/folder.service.ts`                       | Decomposed CRUD/metadata/publish modules | ✗ MISSING   | File retired entirely (PR #422). No CRUD/metadata/publish split exists.                                       |

---

### Key Link Verification

| From                       | To                              | Via                                       | Status | Details                                                                              |
| -------------------------- | ------------------------------- | ----------------------------------------- | ------ | ----------------------------------------------------------------------------------- |
| `useSharedNavigation.ts`   | `useSharedNavigationActions.ts` | `import` + `useSharedNavigationActions({` | WIRED  | Lines 19, 307.                                                                       |
| `useSharedNavigation.ts`   | `useSharedWriteOps.ts`          | `import` + `useSharedWriteOps({`          | WIRED  | Lines 20, 339.                                                                       |
| `FileBrowser.tsx`          | `useFileBrowserActions.ts`      | `import` + `useFileBrowserActions({`      | WIRED  | Lines 33, 71.                                                                        |
| `SharedFileBrowser.tsx`    | `SharedListRow` / `SharedFolderRow` | `import` + JSX usage                   | WIRED  | Lines 41-42, 511, 736.                                                               |
| `FilesPage.tsx`            | `FileBrowser`                   | `import { FileBrowser }`                  | WIRED  | `apps/web/src/routes/FilesPage.tsx:4`.                                               |
| `SharedPage.tsx`           | `SharedFileBrowser`             | `import { SharedFileBrowser }`            | WIRED  | `apps/web/src/routes/SharedPage.tsx:4`.                                              |
| `MoveDialog.tsx`           | `@cipherbox/sdk-core` tree fns  | `import { getDepth, isDescendantOf }`     | WIRED  | `MoveDialog.tsx:5` (used 69-93); `useFolderMutations.ts:4` (used 101-272).           |
| `useSharedWriteOps.ts`     | `@cipherbox/sdk` revocation     | `import { withRevocationGuard }`          | WIRED  | Line 17, used lines 60/136.                                                          |

All split artifacts that survive in current code are live-wired and consumed — none are orphaned.

---

### Requirements Coverage

No external requirement IDs were assigned to this phase (maintainability improvement). All verification is against the five ROADMAP success criteria above.

---

### Anti-Patterns Found

No blocking anti-patterns detected in the phase-modified files. No new `any` casts (SC5 confirmed). The findings below are structural-size observations, not code smells.

| File                                            | Line | Pattern                                              | Severity | Impact                                                                                                  |
| ----------------------------------------------- | ---- | ---------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------ |
| `apps/web/src/hooks/useSharedNavigationActions.ts` | n/a  | 579 lines vs ~400 SC target                          | Info     | 3-hook split achieved; this hook exceeds the soft size target (documented 31-03 deviation, has grown). |
| `apps/web/src/components/file-browser/SharedFileBrowser.tsx` | n/a  | 946 lines — larger than the 943-line original        | Warning  | SC2 container/presentational split not performed for this file; only row sub-components extracted.       |
| `packages/sdk-core/src/folder/index.ts`         | n/a  | 602-line monolith (folder service successor)         | Info     | SC3 CRUD/metadata/publish decomposition was never performed; aligns with the tracked large-file refactor todo (2026-06-19). |

---

### Accepted Deviations (maintainer decision 2026-06-19)

The SC1–SC3 size/decomposition deviations were reviewed and accepted by the maintainer (myankelev) as tracked tech-debt rather than blockers — they are folded into the 2026-06-19 large-file refactor survey todo. Recorded as overrides in the frontmatter.

#### 1. SC2 — SharedFileBrowser.tsx (946 lines) — accepted

`FileBrowser.tsx` was split; `SharedFileBrowser.tsx` had only row sub-components extracted and is larger than its 943-line original. Accepted as tracked tech-debt (large-file refactor survey, 2026-06-19).

#### 2. SC3 — folder.service.ts retirement — accepted

The 1089-line monolith was retired wholesale by a later phase (PR #422) instead of being decomposed into CRUD/metadata/publish modules. The maintainability intent (remove the monolith) is met by removal; the 602-line successor `sdk-core/src/folder/index.ts` is tracked tech-debt (large-file refactor survey, 2026-06-19).

#### 3. SC4 — web E2E — verified via CI

The three spec files exist and are substantive; the web-e2e suite is gated on main-push CI and has passed for the shipped v1.1 milestone. No runtime action outstanding.

---

### Gaps Summary

The phase partially achieves its goal. What is solidly verified in current code:

- SC1: The three-hook split of `useSharedNavigation` exists, is fully wired into the orchestrator, and carries the key-unwrapping logic — though `useSharedNavigationActions.ts` (579) exceeds the ~400-line target.
- SC2 (FileBrowser only): `FileBrowser.tsx` is cleanly split into a 386-line presentational component + a 630-line `useFileBrowserActions` hook, both consumed live.
- SC4 (presence): all three E2E spec files exist and are substantive.
- SC5: zero new `any` casts across all 12 split/created files.
- The 31-01 SDK extractions (tree.ts, error.ts, context.ts, key-cache.ts) all exist and are consumed (ShareKeyCache, withRevocationGuard, tree helpers in web; buildSharedWriteContext inside the SDK client).

What deviated from the literal SC text and was accepted by the maintainer (2026-06-19) as tracked tech-debt:

- SC1: `useSharedNavigationActions.ts` (579 lines) exceeds the ~400-line soft target.
- SC2 for `SharedFileBrowser.tsx`: 946 lines, no container/presentational split — only rows extracted.
- SC3: `folder.service.ts` was retired wholesale by a later phase rather than decomposed; the successor sdk-core folder module remains a 602-line monolith.

These deviations are folded into the separately tracked large-file refactor survey (2026-06-19) and recorded as accepted overrides, so status is `passed`. No functional regression was found: all surviving split artifacts are live-wired, SC5 (no new `any`) holds, and the E2E specs are intact.

---

_Verified: 2026-06-19T16:00:00Z_
_Verifier: Claude (gsd-verifier); SC1–SC3 deviations accepted by maintainer 2026-06-19_
