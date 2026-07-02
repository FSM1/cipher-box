---
phase: 68-web-integration-rotation-ux-and-durable-client-state
plan: 02
subsystem: ui
tags: [share, grant, rotation, api-client, typescript]

requires:
  - phase: 68-web-integration-rotation-ux-and-durable-client-state
    provides: sharesControllerGetReceivedShares/sharesControllerGetSentShares generated API client functions (pre-existing, unused until now)
provides:
  - Real (non-throwing) fetchReceivedShares/fetchSentShares backed by the v2.0 grant API
  - Extended ReceivedShare/SentShare store types carrying readDescriptorRef, rootGeneration (number), rootNodeId
  - Deletion of the dead executeLazyRotation, reWrapForRecipients, and web addShareKeys fan-out functions
affects: [68-05, 68-10]

tech-stack:
  added: []
  patterns:
    - "DTO->store reshape functions (toReceivedShare/toSentShare) isolate the v2.0 grant shape from legacy web types"
    - "Fail-closed numeric parse (parseRootGeneration): non-finite/absent -> undefined, never NaN/0"

key-files:
  created: []
  modified:
    - apps/web/src/services/share.service.ts
    - apps/web/src/stores/share.store.ts
    - apps/web/src/hooks/useAuth.ts
    - apps/web/src/hooks/useSharedNavigation.ts

key-decisions:
  - "itemType has no source in the v2.0 grant DTO (Node model dropped the file/folder discriminant at the grant layer); kept as an optional/undefined field on ReceivedShare/SentShare rather than guessing a default, since its only live reader (SharedListRow.tsx, out of scope for this plan) tolerates undefined without a type error"
  - "itemName has no plaintext source in the v2.0 DTO (only itemNameEncrypted ciphertext); populated as '' for both received and sent shares rather than adding an inline vault-key decrypt step, since decrypting was outside this plan's stated 'thin adapter' scope and would introduce untested new crypto-handling surface"
  - "permission is derived from writeDescriptorRef !== null (write) vs null (read) — a sound 1:1 mapping, not a placeholder"
  - "encryptedKey/encryptedIpnsKey (legacy per-share wrapped keys) made optional on both store types since SC#2 deletes their only producers; zero remaining live readers confirmed via repo-wide grep before loosening"
  - "useAuth.ts's entire shareCallbacks config block removed rather than patched with a no-op addShareKeys, because upload-batch.test.ts already documents shareCallbacks as dead at the SDK level (D-03 removed the per-recipient fan-out; getCoveringShares is 'never called')"
  - "useSharedNavigation.ts's SeedSharedFolderArgs/addShareKeysFn field is a required SDK type (SharedFolderState.addShareKeysFn) that could not be removed without touching packages/sdk (explicitly out of scope); wired to a no-op instead, which changes no observed behavior since the deleted web addShareKeys always threw"

patterns-established: []

requirements-completed: [ROT-07]

coverage:
  - id: D1
    description: "fetchReceivedShares/fetchSentShares call the real generated API and return grant rows carrying readDescriptorRef, rootGeneration (parsed number), and rootNodeId"
    requirement: "ROT-07"
    verification:
      - kind: unit
        ref: "grep -c 'deferred to Phase 68' apps/web/src/services/share.service.ts (function-body inspection, see Deviations)"
        status: pass
      - kind: other
        ref: "pnpm --filter @cipherbox/web exec tsc -b"
        status: pass
    human_judgment: false
  - id: D2
    description: "executeLazyRotation, reWrapForRecipients, and the web addShareKeys fan-out function are deleted with no inline replacement; SDK ShareCallbacks/SharedFolderState.addShareKeysFn seams are untouched"
    requirement: "ROT-07"
    verification:
      - kind: unit
        ref: "grep -rn --include='*.ts' -E 'executeLazyRotation|reWrapForRecipients' apps/web/src (empty)"
        status: pass
      - kind: unit
        ref: "git diff HEAD~3 -- packages/sdk (empty)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Received/sent share list UI (SharedListRow.tsx, out of scope) does not regress: itemType/itemName gracefully degrade (undefined/empty) rather than crashing, since the v2.0 DTO has no source for them"
    human_judgment: true
    rationale: "Real-browser rendering of the shared list with live grant data is only exercisable via the 68-10 web-e2e rotation-ux spec or manual UAT — this plan adds zero apps/web tests per docs/TESTING.md doctrine"

duration: 14min
completed: 2026-07-01
status: complete
---

# Phase 68 Plan 02: Rewire share fetch to v2.0 grant API + delete dead key fan-out Summary

**Rewired `fetchReceivedShares`/`fetchSentShares` to the real `sharesControllerGetReceivedShares`/`sharesControllerGetSentShares` API, extended the web's `ReceivedShare`/`SentShare` types with `readDescriptorRef`/`rootGeneration`/`rootNodeId`, and deleted the dead `executeLazyRotation`/`reWrapForRecipients`/web-`addShareKeys` fan-out (SC#2/D-12).**

## Performance

- **Duration:** 14 min
- **Started:** 2026-07-01T16:26:20Z
- **Completed:** 2026-07-01T16:40:05Z
- **Tasks:** 2 completed
- **Files modified:** 4

## Accomplishments

- `fetchReceivedShares`/`fetchSentShares` now call the real generated API-client functions instead of throwing the Phase-68-deferred stub, giving the web client its first real grant data path.
- `ReceivedShare`/`SentShare` store types carry `readDescriptorRef: string`, `rootGeneration?: number` (parsed fail-closed from the DTO's numeric string), and `rootNodeId: string` — this is the D-07 prerequisite for ROT-07's durable rotation-floor seed.
- Deleted `executeLazyRotation`, `reWrapForRecipients`, and the web `addShareKeys` fan-out function (zero remaining callers, confirmed by grep) — the O(recipients) per-mutation key-wrap loop SC#2/D-12 retires.
- Removed the now-vestigial `shareCallbacks` config block from `useAuth.ts`'s SDK client init, and no-op'd the `addShareKeysFn` seed callback in `useSharedNavigation.ts` (required SDK type, cannot be removed without touching `packages/sdk`, which is out of scope).

## Task Commits

1. **Task 1: Rewire fetchReceivedShares/fetchSentShares to real API + extend store types** — `4a9e78695` (feat) — also includes Task 2's `share.service.ts` deletions (see Issues Encountered)
2. **Task 2: Delete executeLazyRotation + reWrapForRecipients + addShareKeys fan-out and its web callers** — `3aad30699` (feat) — `useAuth.ts` / `useSharedNavigation.ts` call-site changes

**Plan metadata:** committed alongside this SUMMARY.

## Files Created/Modified

- `apps/web/src/services/share.service.ts` — rewired fetch functions to the real API; added `parseRootGeneration`/`toReceivedShare`/`toSentShare` reshape helpers; deleted `executeLazyRotation`, `reWrapForRecipients`, and the web `addShareKeys` fan-out function.
- `apps/web/src/stores/share.store.ts` — extended `ReceivedShare`/`SentShare` with `readDescriptorRef`, `rootGeneration`, `rootNodeId`; loosened `itemType`/`encryptedKey`/`encryptedIpnsKey` to optional (no live readers or no v2.0 DTO source).
- `apps/web/src/hooks/useAuth.ts` — removed the dead `shareCallbacks` config block from the SDK client init.
- `apps/web/src/hooks/useSharedNavigation.ts` — removed the `addShareKeys` import; `seedActiveSharedFolder`'s `addShareKeysFn` is now a no-op (required SDK-typed field).

## Decisions Made

- See `key-decisions` in frontmatter for the itemType/itemName/permission/legacy-field-optionality/shareCallbacks-removal rationale.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Task 1's own verify script checks the whole file, not just the two fetch functions**
- **Found during:** Task 1 verification
- **Issue:** The plan's `<verify><automated>` for Task 1 asserts `grep -c "deferred to Phase 68" apps/web/src/services/share.service.ts` equals 0 across the ENTIRE file. But the file has 7 other stub functions (`createShare`, `updateSharePermission`, `fetchShareKeys`, `fetchPendingRotations`, `updateShareKey`, `completeShareRotation`, plus `addShareKeys` until Task 2 deletes it) that are intentionally out of scope for this plan (per 68-RESEARCH.md's explicit "sized modestly — rewire 2 fetch functions + extend 2 types, not a rabbit hole" framing). A literal 0-count would require gutting or reimplementing 6+ unrelated stub functions — a massive scope expansion not requested by the objective, acceptance criteria, or must-haves.
- **Fix:** Verified the specific intent instead — confirmed `fetchReceivedShares`/`fetchSentShares` function bodies no longer contain the throw (inspected via `awk` range-print) and that `sharesControllerGetReceivedShares`/`sharesControllerGetSentShares` are called. Left the other 6 out-of-scope stub functions untouched.
- **Files modified:** None beyond the planned Task 1 files.
- **Verification:** `awk '/^export async function fetchReceivedShares/,/^}/'` and the `fetchSentShares` equivalent show real API calls, no throw. Full-file grep count is 6 (was 9 originally; -2 from Task 1's two functions, -1 from Task 2's `addShareKeys` deletion).
- **Committed in:** `4a9e78695`

**2. [Process note, not a code deviation] Task 1 and Task 2 edits to `share.service.ts` landed in a single commit**
- **Found during:** Commit staging
- **Issue:** Because both tasks touch the same file (`share.service.ts`) and I edited it in one pass before running the first `git add`/`git commit`, the Task 2 deletions (`executeLazyRotation`, `reWrapForRecipients`, web `addShareKeys`) ended up in commit `4a9e78695` (labeled Task 1) rather than a separate Task 2 commit for that file. `useAuth.ts`/`useSharedNavigation.ts` (also Task 2) landed correctly in the second commit `3aad30699`.
- **Fix:** No functional impact — both tasks' acceptance criteria are satisfied by the final state; documenting the commit-boundary drift here for traceability rather than rewriting history.
- **Files modified:** N/A (documentation-only note).
- **Verification:** `git show --stat 4a9e78695` confirms both the fetch rewiring and the three deletions are present in that commit.
- **Committed in:** `4a9e78695`, `3aad30699`

---

**Total deviations:** 2 (1 auto-fixed verify-script scope correction, 1 commit-boundary process note)
**Impact on plan:** No scope creep. The verify-script correction kept the plan's own stated "modest, 2-function" scope intact rather than ballooning into a 9-function stub rewrite. The commit-boundary note is informational only — final code state matches both tasks' acceptance criteria.

## Issues Encountered

- The v2.0 grant DTO (`ReceivedShareResponseDto`/`SentShareResponseDto`) has no `itemType`, no plaintext `itemName`, and no `encryptedKey`/`encryptedIpnsKey` fields — a bigger shape change than the plan's objective text implied at first read. Resolved by keeping those fields on the store types (required where a live out-of-scope reader — `SharedListRow.tsx` — needs a concrete type, optional where SC#2's own deletions make them dead) rather than expanding scope to touch `SharedListRow.tsx` or add new decrypt-at-fetch-time logic. See `key-decisions`.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- The D-07 grant data path (readDescriptorRef/rootGeneration/rootNodeId reaching the web store) is now live, unblocking 68-05's SDK-side rotation-floor seeding logic and the 68-10 web-e2e rotation-durability spec (real grant -> seed -> reject-downgrade).
- Known gap for a future plan: `itemType`/plaintext `itemName` display in the "Shared with me" list (`SharedListRow.tsx`) currently renders with `itemType: undefined` (defaults to file icon) and an empty display name for freshly-fetched shares, since the v2.0 API dropped those fields. Not a blocker for ROT-07, but worth flagging for whichever phase restores full-fidelity shared-list UI (referenced elsewhere in this codebase as "phase 63 Node read-chain" work).

---
*Phase: 68-web-integration-rotation-ux-and-durable-client-state*
*Completed: 2026-07-01*

## Self-Check: PASSED

All files (`share.service.ts`, `share.store.ts`, `useAuth.ts`, `useSharedNavigation.ts`) and both commit hashes (`4a9e78695`, `3aad30699`) verified present on disk / in git log.
