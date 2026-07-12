---
phase: 79-web-kind-discrimination-completion-and-deferred-test-revival
plan: 02
subsystem: ui
tags: [react, typescript, kind-discrimination, file-browser, navigation, invite]

# Dependency graph
requires:
  - phase: 79-web-kind-discrimination-completion-and-deferred-test-revival (plan 01, wave 1 sibling)
    provides: ResolvedChild.createdAt + isFileRefResolved/sortItems fixes in FileList.tsx/SharedFileBrowser.tsx
provides:
  - resolvedByIpnsName exposed from useFileBrowserActions for FileBrowser.tsx/dialog consumption (Wave 2)
  - Real resolved itemType ('file' | 'folder') at all six call sites in useFileBrowserActions.ts (five mutation handlers + shift-select sort)
  - Documented, intentional ipnsName-keyed folder identity in useFolderNavigation.ts (NON-CHANGE)
  - Recorded decision + grep evidence for the invite-layer itemType gap (InviteInfo.itemType dropped)
affects: [79-03, 79-web-kind-discrimination Wave 2 dialog/label wiring]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "isFileRefResolved(item, resolvedByIpnsName) ? 'file' : 'folder' is the canonical kind-resolution call shape reused at every call site (no local isFolder helper)"

key-files:
  created: []
  modified:
    - apps/web/src/components/file-browser/useFileBrowserActions.ts
    - apps/web/src/hooks/useFolderNavigation.ts
    - apps/web/src/services/invite.service.ts

key-decisions:
  - "Task 2: useFolderNavigation.ts folder identity is intentionally ipnsName-keyed -- deleted the stale Node.id TODO and replaced with a permanent rationale comment; introduced ZERO behavior change (comment-only diff, verified via git diff)"
  - "Task 3: InviteInfo.itemType dropped entirely (option c) -- grep-verified InviteLinkTab.tsx (the sole fetchInvitesForItem consumer) never reads invite.itemType, and no ResolvedChild/parent listing exists at the invite layer to resolve a real kind from"
  - "Task 1: also fixed a sixth phase-63 marker (handleSelect's shift-select range sort) not explicitly listed among the five stub sites, because the plan's own acceptance criteria requires zero phase-63/65 markers file-wide"

requirements-completed: []

coverage:
  - id: D1
    description: "useFileBrowserActions exposes resolvedByIpnsName on its return object, unblocking Wave-2 dialog/label wiring"
    verification:
      - kind: unit
        ref: "grep -c resolvedByIpnsName apps/web/src/components/file-browser/useFileBrowserActions.ts (21, incl. return-object entry at line 630)"
        status: pass
    human_judgment: false
  - id: D2
    description: "The five hardcoded-folder itemType stubs (batch delete/move, rename, delete, move confirm) now resolve real kind via isFileRefResolved; a sixth stub in the shift-select sort was also fixed to keep the file marker-free"
    verification:
      - kind: unit
        ref: "grep -rn 'phase 63|phase 65' apps/web/src/components/file-browser/useFileBrowserActions.ts (zero matches)"
        status: pass
      - kind: unit
        ref: "tsc -b (apps/web) — passes with no errors"
        status: pass
    human_judgment: false
  - id: D3
    description: "useFolderNavigation.ts stale Node.id TODO deleted and replaced with a rationale comment; ipnsName-keyed navigation identity is unchanged (NON-CHANGE, no re-key introduced)"
    verification:
      - kind: unit
        ref: "grep -rn 'phase 63|phase 65' apps/web/src/hooks/useFolderNavigation.ts (zero matches); git diff shows comment-only change (1 file, 5 insertions, 1 deletion)"
        status: pass
    human_judgment: false
  - id: D4
    description: "Invite-layer itemType decision recorded: InviteInfo.itemType field dropped (option c), with grep evidence that no consumer reads it"
    verification:
      - kind: unit
        ref: "grep -rn 'phase 63|phase 65' apps/web/src/services/invite.service.ts (zero matches); grep -n itemType apps/web/src/components/file-browser/InviteLinkTab.tsx (zero matches); tsc -b passes"
        status: pass
    human_judgment: false

patterns-established:
  - "Wherever a SealedChildRef needs file-vs-folder classification without a `.kind` field, resolve via isFileRefResolved(item, resolvedByIpnsName) -- never reimplement a local isFolder helper"

duration: ~15min
completed: 2026-07-11
status: complete
---

# Phase 79 Plan 02: Web Kind-Discrimination Completion (useFileBrowserActions/useFolderNavigation/invite.service) Summary

**Exposed resolvedByIpnsName from useFileBrowserActions and resolved all six itemType stubs via isFileRefResolved; documented ipnsName-keyed folder identity as intentional (zero behavior change); dropped InviteInfo.itemType (grep-verified unused)**

## Performance

- **Duration:** ~15 min
- **Completed:** 2026-07-11
- **Tasks:** 3
- **Files modified:** 3

## Accomplishments

- `useFileBrowserActions` now returns `resolvedByIpnsName`, unblocking Wave-2 dialog/label wiring in `FileBrowser.tsx`
- All five hardcoded-folder `itemType` stubs (batch delete, batch move, rename, delete, move) now resolve the real kind via `isFileRefResolved(item, resolvedByIpnsName)`, matching the pre-existing call shape already used at lines 416/480 in the same file
- A sixth, previously-unlisted `phase 63` marker in the shift-select range sort (`handleSelect`) was also fixed with the same folders-first-then-alpha comparator used in `FileList.tsx`'s `sortItems`, since the plan's acceptance criteria require zero deferred-phase markers file-wide
- `useFolderNavigation.ts`'s stale "use Node.id for the folder ID" TODO is deleted and replaced with a permanent rationale comment citing the 68.1/68.2-09 orphaned-store-entry precedent — folder identity remains ipnsName-keyed with **zero code-behavior change** (verified via `git diff`: comment-only)
- `invite.service.ts`'s `InviteInfo.itemType` field is dropped entirely after grep-verifying its sole consumer (`InviteLinkTab.tsx`) never reads it, and no `ResolvedChild`/parent listing exists at the invite layer to resolve a real kind from

## Task Commits

Each task was committed atomically:

1. **Task 1: Expose resolvedByIpnsName and resolve the five hardcoded-folder itemType stubs** - `7e0bbae3e` (feat)
2. **Task 2: Delete the stale Node.id folder-identity TODO (NON-CHANGE, keep ipnsName-keying)** - `32bd1eadc` (docs)
3. **Task 3: Record an explicit decision for the invite-layer itemType** - `22d793193` (refactor)

## Files Created/Modified

- `apps/web/src/components/file-browser/useFileBrowserActions.ts` - Returns `resolvedByIpnsName`; five mutation-handler call sites and the shift-select sort now resolve real kind via `isFileRefResolved` instead of hardcoded `'folder'`
- `apps/web/src/hooks/useFolderNavigation.ts` - Stale Node.id TODO replaced with a rationale comment; no behavior change
- `apps/web/src/services/invite.service.ts` - `InviteInfo.itemType` field removed; `fetchInvitesForItem`'s mapping no longer sets a hardcoded `itemType`

## Decisions Made

**Task 2 — NON-CHANGE recorded explicitly (per plan constraint 1):** Folder identity in `useFolderNavigation.ts` stays keyed by `ipnsName`, matching the `fNode.children.find((c) => c.ipnsName === targetFolderId)` lookup earlier in the same function and the route-param convention used throughout the file. The stale TODO instructing a future dev to re-key to `Node.id` was deleted and replaced with a one-line rationale comment citing the 68.1/68.2-09 orphaned-store-entry precedent. `git diff` confirms this was a comment-only change: 1 file changed, 5 insertions(+), 1 deletion(-); `id: targetFolderId` is unchanged, and no `id: node.id` / `id: resolvedChild.id` / `id: folderRef.id` assignment was introduced. **Do not "fix" this back to Node.id in future work.**

**Task 3 — invite-layer itemType decision (per plan constraint 2):** Per the plan's decision procedure, ran `grep -rn "itemType" apps/web/src` first. Found `InviteInfo.itemType: string` declared in `invite.service.ts` and hardcoded to `'folder'` in `fetchInvitesForItem`'s mapping, but **zero** reads of `invite.itemType` anywhere in `InviteLinkTab.tsx` — the sole importer of `InviteInfo` and the only caller of `fetchInvitesForItem` (verified via a full `grep -n "invite\b" apps/web/src/components/file-browser/InviteLinkTab.tsx`, which shows only `invite.id`, `invite.createdAt`, `invite.expiresAt` referenced in the JSX). Since (a) there is no `ResolvedChild`/parent listing in scope at `fetchInvitesForItem`'s call site to resolve a real kind, and (b) no consumer reads the field at all, **option (c)** was chosen: `itemType` is dropped from `InviteInfo` entirely rather than kept as an undocumented best-effort default. `tsc -b` confirms `InviteLinkTab.tsx` (and the rest of `apps/web`) still typechecks cleanly with the field removed.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed a sixth phase-63 marker in useFileBrowserActions.ts not listed among the five stub sites**
- **Found during:** Task 1
- **Issue:** The plan named five hardcoded-folder `itemType` stub sites (lines ~497/514/542/556/569), but the file also carried a sixth `TODO(phase 63)` marker inside `handleSelect`'s shift-select range-selection sort (`[...children].sort((a, b) => a.name.localeCompare(...))`, alphabetical-only because `SealedChildRef` has no `.type`). The plan's own acceptance criteria require `grep -rn "phase 63|phase 65"` to return zero across the file, so this marker also had to be resolved.
- **Fix:** Applied the same folders-first-then-alpha comparator already used in `FileList.tsx`'s `sortItems` (per 79-PATTERNS.md), using `isFileRefResolved(a, resolvedByIpnsName)` / `isFileRefResolved(b, resolvedByIpnsName)` to classify each item before the alpha tiebreak. Added `resolvedByIpnsName` to `handleSelect`'s dependency array.
- **Files modified:** `apps/web/src/components/file-browser/useFileBrowserActions.ts`
- **Verification:** `grep -rn "phase 63|phase 65" apps/web/src/components/file-browser/useFileBrowserActions.ts` returns zero; `tsc -b` passes.
- **Committed in:** `7e0bbae3e` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 Rule 1 bug fix)
**Impact on plan:** In-scope fix required to satisfy the plan's own acceptance criteria for the file. No scope creep — same file, same pattern already prescribed for the five listed sites.

## Issues Encountered

None.

## Known Stubs

None — no hardcoded empty values, placeholder text, or unwired data sources were introduced or left behind in this plan's files.

## Threat Flags

None — no new network endpoints, auth paths, file-access patterns, or schema changes were introduced. The T-79-02 threat register entry (folder-identity re-key temptation) was explicitly mitigated per Task 2's NON-CHANGE.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `resolvedByIpnsName` is now exposed from `useFileBrowserActions` — Wave-2 work wiring `FileBrowser.tsx` dialogs/labels to real kind can proceed without further hook changes.
- `useFolderNavigation.ts`'s ipnsName-keyed identity is documented; future work should not re-key to `Node.id`.
- `InviteInfo` no longer carries an unused `itemType` field; any future work that needs invite-layer kind discrimination must add a real data source (option b from the plan, resolving via `invite.shareRootIpnsName`) rather than reintroducing a hardcoded default.
- No blockers for downstream plans in this phase.

---
*Phase: 79-web-kind-discrimination-completion-and-deferred-test-revival*
*Completed: 2026-07-11*

## Self-Check: PASSED

- FOUND: apps/web/src/components/file-browser/useFileBrowserActions.ts
- FOUND: apps/web/src/hooks/useFolderNavigation.ts
- FOUND: apps/web/src/services/invite.service.ts
- FOUND: commit 7e0bbae3e
- FOUND: commit 32bd1eadc
- FOUND: commit 22d793193
