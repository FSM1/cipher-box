---
phase: 74-rust-and-fuse-rotation-revocation-soundness
plan: 07
subsystem: testing
tags: [desktop-e2e, fuse, winfsp, rotation, revocation, ipns, real-mount]

# Dependency graph
requires:
  - phase: 74-rust-and-fuse-rotation-revocation-soundness
    provides: "refresh_rotated_inode_read_keys(inodes, result) -- generalized multi-node FUSE inode read_key refresh (74-03, SC1)"
  - phase: 74-rust-and-fuse-rotation-revocation-soundness
    provides: "FuseRotationDeps::query_grants_rooted_at/update_grant/delete_grant real overrides delegating through RotationTransport (74-05, SC2)"
  - phase: 74-rust-and-fuse-rotation-revocation-soundness
    provides: "WinFsp handle_rename reordered to fuser D-15d pipeline + new destination scope-exit gate (74-06, SC3)"
provides:
  - "shared-scope-exit-rotation.mts Part C: depth>=2 (grant-root -> folderB -> fileC/fileSibling) decryptability-invariant leg + retained-vs-revoked (Eve/Carol) leg"
  - "shared-scope-exit-rotation.mts Part D: overwrite-rename-against-covered-destination leg (Frank/Grace), WinFsp-authoritative on Windows CI"
  - "tests/desktop-e2e/tsconfig.json -- new, first typecheck coverage for the desktop-e2e script directory"
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Revoked-vs-retained recipient pair sharing the SAME grant root, with the revoked recipient's share explicitly DELETE'd before the mutation fires -- the only way to distinguish 'genuinely cut off' from 'active grantee re-minted' now that query_grants_rooted_at (74-05) re-mints every still-active grant rooted at a rotated node"
    - "resolveFileMetadata-based canReadFile() decryptability probe, mirroring canRead()'s loadFolderMetadata pattern, for File-node (not just Folder-node) invariants"

key-files:
  created:
    - tests/desktop-e2e/tsconfig.json
  modified:
    - tests/desktop-e2e/scripts/shared-scope-exit-rotation.mts
    - tests/desktop-e2e/scripts/run-all.sh
    - tests/desktop-e2e/scripts/run-all.ps1

key-decisions:
  - "Combined the plan's 'deep leg' and 'second-recipient leg' into ONE Part C scenario (Eve revoked, Carol retained, both sharing the same depth-2 DeepGrant tree) rather than two separate legs -- this is the only construction that actually exercises 74-05's re-mint semantics correctly (see Known Risk below) and avoids a redundant second grant-root/tree setup."
  - "Explicitly DELETE (revoke) the 'revoked' recipient's share BEFORE triggering the covered mutation in both Part C and Part D, keeping a second recipient's grant active to satisfy the ancestor covering-grant gate. This is required by 74-05's real behavior: query_grants_rooted_at now re-mints every STILL-ACTIVE grant rooted at a rotated node, so an active-but-untouched recipient is retained, not cut off, by design (T-74-15's fix)."
  - "fileC (the delete target in Part C) is asserted as an INFO-level, non-blocking probe, not a hard SC1 gate -- once a recipient has independently derived a leaf file's read key, a later rotation of its (now-deleted) parent does not retroactively re-protect that already-known key against the immutable, content-addressed IPFS blob. This is a documented forward-secrecy boundary, not a regression of this phase's fix. The hard SC1 gate is folderB (an INTERMEDIATE node that DOES get walked/rotated) and fileSibling (a RETAINED File node at the same depth, exercising 74-03's InodeKind::File refresh arm)."
  - "Created tests/desktop-e2e/tsconfig.json (did not exist) -- the plan's own verify command referenced it as if it existed; without it there was no way to typecheck any .mts/.ts file in tests/desktop-e2e at all. Mirrors the tests/web-e2e tsconfig.json pattern, extended to include ../e2e-helpers (the shared auth helper the desktop-e2e scripts import by relative path)."

requirements-completed: [SC1, SC2, SC3]

coverage:
  - id: D1
    description: "Depth>=2 scope-exit decryptability invariant: a revoked recipient (Eve) cannot decrypt an intermediate Folder node (folderB) NOR a retained sibling File node (fileSibling) with her pre-rotation keys after a covered scope-exit delete two levels down (fileC) -- proves 74-03's generalized refresh_rotated_inode_read_keys closes the deep-path bypass"
    requirement: SC1
    verification:
      - kind: e2e
        ref: "tests/desktop-e2e/scripts/shared-scope-exit-rotation.mts Part C (dispatched via tests/desktop-e2e/scripts/run-all.sh Step 8 / run-all.ps1 Step 8, .github/workflows/desktop-e2e.yml, macOS/Linux/Windows matrix)"
        status: unknown
    human_judgment: true
    rationale: "Real-mount desktop-e2e requires a built Tauri desktop binary + live FUSE-T/fuser/WinFsp mount + API + IPNS round-trip -- infra/CI-gated by design (autonomous:false), not runnable on this host. Static verification performed instead: tsc typecheck clean, tsx module-resolution smoke-run clean, eslint/prettier clean. Live pass/fail is deferred to the dispatched CI matrix; see Deferred to CI section."
  - id: D2
    description: "Retained-vs-revoked distinction: a retained recipient (Carol), never revoked, is re-minted to the new generation via a polled /shares/received change and still decrypts folderB post-rotation -- proves 74-05's FuseRotationDeps grant seam (query_grants_rooted_at/update_grant) fires and does not over-broadly cut active grantees"
    requirement: SC2
    verification:
      - kind: e2e
        ref: "tests/desktop-e2e/scripts/shared-scope-exit-rotation.mts Part C (same dispatch as D1)"
        status: unknown
    human_judgment: true
    rationale: "Same real-mount/CI-gated constraint as D1."
  - id: D3
    description: "Overwrite-rename against a covered destination: a revoked recipient (Frank) cannot decrypt the shared folder after sourceFile.txt is renamed onto destFile.txt (an overwrite); a retained recipient (Grace) is re-minted and keeps access -- proves 74-06's WinFsp handle_rename destination scope-exit gate rotates on overwrite (authoritative on Windows CI) and is a regression guard on fuser (macOS/Linux, already-correct D-15d dest gate)"
    requirement: SC3
    verification:
      - kind: e2e
        ref: "tests/desktop-e2e/scripts/shared-scope-exit-rotation.mts Part D, dispatched on Windows via run-all.ps1 Step 8 (authoritative) and on macOS/Linux via run-all.sh Step 8 (regression guard)"
        status: unknown
    human_judgment: true
    rationale: "WinFsp requires the Windows CI runner (no local WinFsp toolchain on macOS, per project memory project-winfsp-build-ci-only-macos) AND a built desktop binary + live mount on all 3 platforms -- fully CI-gated, autonomous:false."

# Metrics
duration: ~40min
completed: 2026-07-11
status: complete
---

# Phase 74 Plan 07: Desktop-E2E Deep/Retained-vs-Revoked/WinFsp-Rename Verification Legs Summary

**Extended `shared-scope-exit-rotation.mts` with two new real-mount legs (Part C: depth>=2 decryptability + retained-vs-revoked; Part D: WinFsp overwrite-rename dest-gate) jointly proving SC1/SC2/SC3, plus the missing `tests/desktop-e2e/tsconfig.json` needed to typecheck them at all — the live 3-platform CI run is deferred (autonomous:false, real-mount + built desktop binary required).**

## Performance

- **Duration:** ~40 min
- **Completed:** 2026-07-11
- **Tasks:** 2 (both `auto`, authored end-to-end; live verification deferred to CI per the plan's `autonomous: false` designation)
- **Files modified:** 3 (1 new)

## Accomplishments

- **Part C (`shared-scope-exit-rotation.mts`, SC1+SC2):** built a depth>=2 tree (`DeepGrant-{tag}/folderB/{fileC.txt, fileSibling.txt}`) shared to two recipients on the SAME grant root — Eve (explicitly revoked via `DELETE /shares/:shareId` before the covered delete fires) and Carol (stays active). After the covered scope-exit delete of `fileC.txt`, asserts: Eve's pre-rotation keys can no longer decrypt `folderB` (an intermediate Folder node) NOR `fileSibling` (a retained File node at the same depth) — the exact deep-path bypass 74-03's `refresh_rotated_inode_read_keys` closes, at BOTH kind arms (`InodeKind::Folder` and `InodeKind::File`). Carol's grant is polled until `/shares/received` shows a genuinely re-minted `encryptedReadKey` (proves `FuseRotationDeps::query_grants_rooted_at`/`update_grant`, 74-05, actually fired), and her new key still decrypts `folderB`.
- **Part D (`shared-scope-exit-rotation.mts`, SC3):** built `RenameOverwrite-{tag}/{destFile.txt, sourceFile.txt}` shared to Frank (revoked pre-rename) and Grace (retained). Performs an overwrite-rename (`sourceFile.txt` -> `destFile.txt`) through the mount and asserts Frank's stale key fails post-rename while Grace's re-minted key succeeds — the runtime proof for 74-06's WinFsp `handle_rename` destination scope-exit gate (authoritative on Windows CI) and a regression guard on fuser's already-correct dest gate (macOS/Linux).
- Added `canReadFile()` (mirrors `canRead()`, using `resolveFileMetadata` from `@cipherbox/sdk-core` for File-node decryptability) and `pollGrantRemint()` (polls `/shares/received` until a share's `encryptedReadKey` genuinely changes) as new shared helpers.
- Added `authenticateRecipient()` to factor out the 4 new recipient identities (Eve/Carol/Frank/Grace) without touching Bob's existing Part A/B setup lines.
- Updated `run-all.sh`/`run-all.ps1` Step 8 comments to document the new Part C/D coverage (the existing invocation line already runs the whole script, so no new step/line was needed — confirmed via `grep` that no duplicate rename-overwrite leg pre-existed, per RESEARCH Assumption A3).
- **Created `tests/desktop-e2e/tsconfig.json`** (did not exist anywhere in the repo before this plan) — the plan's own verify command assumed it, but `tests/desktop-e2e` had zero typecheck coverage. Mirrors `tests/web-e2e/tsconfig.json`, extended with `../e2e-helpers/**/*.ts` since the desktop-e2e scripts import that shared auth helper by relative path, not as a package dependency.

## Task Commits

Each task was committed atomically:

1. **Task 1: Deep scope-exit + second-recipient legs** - `e1c12911e` (test) — Part C AND Part D both landed in this commit (see Deviations below); `tests/desktop-e2e/tsconfig.json` created in the same commit since it was required to typecheck Task 1's own work.
2. **Task 2: WinFsp overwrite-rename leg + run-all wiring** - `15ede4ec4` (test) — `run-all.sh`/`run-all.ps1` Step 8 comment updates only (Part D's code was already committed in Task 1's commit).

**Plan metadata:** committed separately at the end of this execution (see `git log` after this SUMMARY lands).

## Files Created/Modified

- `tests/desktop-e2e/scripts/shared-scope-exit-rotation.mts` — Part C (deep decryptability + retained-vs-revoked) and Part D (WinFsp overwrite-rename dest-gate) added; Parts A/B (existing D-16 shallow legs) left byte-for-byte unchanged. New helpers: `canReadFile`, `authenticateRecipient`, `pollGrantRemint`. New import: `resolveFileMetadata`, `renameSync`.
- `tests/desktop-e2e/tsconfig.json` — new; first typecheck config for this test directory.
- `tests/desktop-e2e/scripts/run-all.sh` / `run-all.ps1` — Step 8 header comments extended to document Part C/D coverage; invocation lines unchanged (already correct).

## Decisions Made

See `key-decisions` in frontmatter. The most consequential one: Part C/D's revoked recipients are explicitly `DELETE`'d before the covered mutation fires (not just "left active but expected to be cut off," as Part A's original Bob leg does) — see **Known Risk** below for why this matters and why Part A was left untouched anyway.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Created missing `tests/desktop-e2e/tsconfig.json`**
- **Found during:** Task 1, running the plan's own declared verify command
- **Issue:** The plan's `<verify><automated>` step for Task 1 was `npx tsc -p tests/desktop-e2e/tsconfig.json --noEmit` — no such file existed anywhere in the repo (confirmed via `find`), and `tests/desktop-e2e` had zero typecheck coverage in CI or locally.
- **Fix:** Created `tests/desktop-e2e/tsconfig.json` extending `tsconfig.base.json`, mirroring `tests/web-e2e/tsconfig.json`'s shape (`noEmit`, `moduleResolution: bundler`), with `include` covering `scripts/**/*.ts`, `scripts/**/*.mts`, and `../e2e-helpers/**/*.ts` (the shared auth helper imported by relative path).
- **Files modified:** `tests/desktop-e2e/tsconfig.json` (new)
- **Verification:** `npx tsc -p tests/desktop-e2e/tsconfig.json --noEmit` exits 0 with zero errors across the whole directory (all pre-existing scripts + this plan's additions).
- **Committed in:** `e1c12911e` (Task 1 commit)

**2. [Process deviation, not a Rule 1-3 auto-fix] Part D landed in Task 1's commit, not Task 2's**
- **Found during:** Committing Task 1
- **Issue:** Parts C and D were authored together in a single large `Edit` to `shared-scope-exit-rotation.mts` (both insert into the same file, adjacent to each other, sharing helpers) before either was committed. By the time Task 1's commit was staged, Part D's code was already present in the working tree and got swept into the `git add`.
- **Fix:** Did not attempt to split the already-committed diff after the fact (no `git reset`/amend, per the no-amend policy). Task 2's commit contains only the `run-all.sh`/`run-all.ps1` wiring-comment updates; the SUMMARY documents Part D's actual landing commit (`e1c12911e`) explicitly so the audit trail is accurate.
- **Files modified:** none beyond what's already listed.
- **Verification:** `git log --oneline -4` confirms both commits exist with the described contents; `git show e1c12911e --stat` / `git show 15ede4ec4 --stat` corroborate the split.
- **Committed in:** N/A (documentation-only correction, no code change).

---

**Total deviations:** 2 (1 blocking-issue auto-fix, 1 process/commit-boundary note)
**Impact on plan:** The tsconfig fix was necessary for the plan's own verify step to be runnable at all — pure addition, no existing behavior changed. The commit-boundary deviation has zero functional impact (all required code is committed and correct); it only affects which of the two per-task commits contains which lines.

## Known Risk (flagged for follow-up, not fixed in this plan)

**Part A's existing "Bob" assertion (`shared-scope-exit-rotation.mts`, unchanged in this plan) may no longer reflect correct post-74-05 behavior.**

Part A shares the grant root to Bob and keeps his share ACTIVE (never revoked) through the covered delete, then asserts Bob's key fails post-rotation — this was correct when `FuseRotationDeps::query_grants_rooted_at` was still the ROT-04 no-op default (nobody was ever re-minted). Now that 74-05 wires a REAL `query_grants_rooted_at` (`GET /shares/sent`, filtered by `root_node_id == node_id`), Bob's still-active grant — rooted exactly at the grant-root node that the walk visits — should, by the corrected design, be **re-minted, not cut off** (this is the literal fix for T-74-15, "retained recipient wrongly cut"). If that reasoning is right, a live CI run of Part A post-74-05 may now see `bobCanReadAfterRotation === true`, flipping Part A's `FAIL` branch.

This plan's own instructions were explicit — "Keep the existing shallow D-16 leg intact and passing" / "The existing shallow leg is unchanged and still asserted" — and modifying Part A's fundamental test semantics is a testing-strategy decision beyond this plan's declared scope (Rule 4 territory: an architectural/design call, not a bug fix), so **Part A was left completely untouched**, byte-for-byte. Parts C/D avoid this ambiguity by construction (the "revoked" recipient in each is explicitly `DELETE`'d before the mutation, matching 74-05's real semantics precisely).

**Recommended next step:** when the CI matrix is dispatched (see below), watch Part A's own Step 8 output specifically. If Bob's post-rotation `canRead` unexpectedly returns `true`, that is NOT a regression introduced by this plan — it is Part A's pre-existing assertion needing an update to match 74-05's corrected retained-recipient behavior, and should be filed as a follow-up todo/plan rather than silently patched.

## Deferred to desktop-e2e CI (dispatch-gated; live FUSE/WinFsp mount not run locally)

Per this plan's `autonomous: false` designation, the live 3-platform run requires a built Tauri desktop binary, a live FUSE-T (macOS) / fuser (Linux) / WinFsp (Windows) mount, the API, and a real IPNS round-trip — none of which are feasible to construct in this session (per project memory `project-headless-desktop-fuse-uat` and `project-winfsp-build-ci-only-macos`). The exact CI job that runs this:

```
gh workflow run "desktop-e2e" --ref feat/rust-and-fuse-rotation-revocation-soundness
```
(`.github/workflows/desktop-e2e.yml`, matrix over macOS/Linux/Windows, `bash tests/desktop-e2e/scripts/run-all.sh` on macOS/Linux and `powershell -File tests/desktop-e2e/scripts/run-all.ps1` on Windows — Step 8 in both.)

**What each leg asserts, per platform:**

| Leg | SC | macOS/Linux (fuser/FUSE-T) | Windows (WinFsp) |
|---|---|---|---|
| Part A/B (existing, unchanged) | D-16 baseline | Shallow single-recipient delete rotation + private-delete no-rotation | Same |
| Part C (new) | SC1, SC2 | Depth>=2 decryptability invariant (Eve revoked, cannot read folderB/fileSibling); Carol retained, re-minted, still reads folderB | Same — exercises the SAME `FuseRotationDeps`/rotation-engine code paths, no WinFsp-specific logic in Part C |
| Part D (new) | SC3 | Regression guard on fuser's already-correct D-15d dest gate (`rename.rs`) | **Authoritative** proof of 74-06's WinFsp `handle_rename` destination scope-exit gate fix (`platform/windows/write_ops.rs`) |

**Also still outstanding from 74-06** (not this plan's scope, but blocks calling SC3 fully closed): the `Cargo Check & Test (Windows)` CI job must run and pass the two new WinFsp unit tests (`rename_enotempty_destination_rejects_before_gate_with_no_rotation_attempt`, `rename_overwriting_a_covered_destination_gates_dest_ino_scope_exit`) — per 74-06's own SUMMARY, this was still pending dispatch as of that plan's completion.

## What WAS verified locally

- `npx tsc -p tests/desktop-e2e/tsconfig.json --noEmit` — exit 0, zero errors, covering every `.ts`/`.mts` file in `tests/desktop-e2e/scripts` plus the imported `tests/e2e-helpers` auth module.
- `node node_modules/tsx/dist/cli.mjs tests/desktop-e2e/scripts/shared-scope-exit-rotation.mts` (no args) — confirmed the file transpiles and all imports (`@cipherbox/sdk-core`, `@cipherbox/core`, `@cipherbox/crypto`, `../../e2e-helpers/auth`) resolve at runtime; execution reaches and throws the expected `parseArgs` usage error (proves the module graph loads cleanly, nothing further was exercised since no live mount/API was available).
- `npx eslint --fix` + `npx eslint` (clean, 0 errors) on the modified `.mts` file — prettier/import-order issues auto-fixed.
- `bash -n tests/desktop-e2e/scripts/run-all.sh` — syntax-valid.
- `grep -n 'shared-scope-exit-rotation' tests/desktop-e2e/scripts/run-all.ps1 tests/desktop-e2e/scripts/run-all.sh` — both invoke the (now-extended) script; Task 2's own verify command, passing.
- `grep -rniE "rename.*overwrite|overwrite.*rename"` across `tests/desktop-e2e/scripts/*` before authoring Part D — confirmed no pre-existing rename-overwrite leg (RESEARCH Assumption A3), so Part D extends rather than duplicates.
- PowerShell syntax for `run-all.ps1` could NOT be locally verified (`pwsh` not installed on this host) — Windows CI is the authoritative syntax/runtime check, consistent with project memory `project-winfsp-build-ci-only-macos`.

## Issues Encountered

None beyond the Known Risk and the commit-boundary note documented above.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- All three phase-74 Success Criteria (SC1, SC2, SC3) now have real-mount desktop-e2e coverage authored and wired into both `run-all.sh` and `run-all.ps1`; live confirmation is dispatch-gated (see Deferred section).
- Before closing Phase 74, dispatch: (1) the `desktop-e2e` workflow on all 3 platforms for this branch, watching specifically for Part A's Bob-retained-vs-revoked question (Known Risk); (2) `Cargo Check & Test (Windows)` for 74-06's still-pending WinFsp unit tests.
- No blockers for any other phase-74 plan; this was the terminal verification plan (wave 3, depends on 74-03/74-05/74-06, all complete).

---
*Phase: 74-rust-and-fuse-rotation-revocation-soundness*
*Completed: 2026-07-11*

## Self-Check: PASSED

- FOUND: tests/desktop-e2e/scripts/shared-scope-exit-rotation.mts
- FOUND: tests/desktop-e2e/tsconfig.json
- FOUND: tests/desktop-e2e/scripts/run-all.sh
- FOUND: tests/desktop-e2e/scripts/run-all.ps1
- FOUND: .planning/phases/74-rust-and-fuse-rotation-revocation-soundness/74-07-SUMMARY.md
- FOUND commit: e1c12911e (test(74-07): add deep scope-exit + retained-vs-revoked desktop-e2e legs)
- FOUND commit: 15ede4ec4 (test(74-07): add WinFsp overwrite-rename covered-destination e2e leg)
