---
phase: 16-advanced-sync
verified: 2026-03-03T13:30:00Z
status: passed
score: 3/3 must-haves verified
must_haves:
  truths:
    - 'Client detects when another device has published a newer IPNS sequence number and alerts the user before overwriting'
    - 'On conflict, both web and desktop clients automatically re-sync the folder and retry the operation once'
    - 'Persistent conflicts (retry also fails) surface an error to the user without infinite loops'
  artifacts:
    - path: 'apps/api/src/ipns/dto/publish.dto.ts'
      provides: 'expectedSequenceNumber optional field on PublishIpnsDto and PublishIpnsEntryDto'
    - path: 'apps/api/src/ipns/ipns.service.ts'
      provides: 'ConflictException (409) on BigInt sequence mismatch in upsertFolderIpns'
    - path: 'apps/api/src/ipns/ipns.controller.ts'
      provides: '409 ApiResponse documentation on both publish endpoints'
    - path: 'apps/api/src/ipns/ipns.service.spec.ts'
      provides: '5 conflict detection unit tests (stale rejection, matching acceptance, backward compat, batch conflict, batch success)'
    - path: 'apps/web/src/lib/errors.ts'
      provides: 'isConflictError() utility detecting .status === 409'
    - path: 'apps/web/src/services/ipns.service.ts'
      provides: 'expectedSequenceNumber parameter threaded through createAndPublishIpnsRecord'
    - path: 'apps/web/src/services/folder.service.ts'
      provides: 'expectedSequenceNumber passed in updateFolderMetadata and buildFolderIpnsRecord'
    - path: 'apps/web/src/hooks/useFolderMutations.ts'
      provides: 'Conflict catch-resync-retry on all 6 folder mutation handlers'
    - path: 'apps/web/src/hooks/useFileOperations.ts'
      provides: 'Conflict catch-resync-retry on addFile and addFiles handlers'
    - path: 'apps/web/src/stores/sync.store.ts'
      provides: 'conflict status, setConflict(), clearConflict() actions'
    - path: 'apps/web/src/components/file-browser/SyncIndicator.tsx'
      provides: 'Amber spinning icon for conflict state'
    - path: 'apps/desktop/src-tauri/src/api/ipns.rs'
      provides: 'PublishResult enum (Success|Conflict), expected_sequence_number on IpnsPublishRequest, 409 parsing'
    - path: 'apps/desktop/src-tauri/src/fuse/mod.rs'
      provides: 'merge_folder_children(), conflict handling in spawn_metadata_publish with re-fetch+merge+retry'
    - path: 'tests/e2e/tests/conflict-detection.spec.ts'
      provides: '3 Playwright E2E tests (upload conflict, folder conflict, negative per-file test)'
    - path: 'tests/e2e/utils/conflict-helpers.ts'
      provides: 'bumpServerSequence helper for simulating concurrent device publishes'
    - path: 'tests/e2e-desktop/scripts/test-conflict-detection.sh'
      provides: 'Bash FUSE conflict detection test script (2 scenarios)'
    - path: 'tests/e2e-desktop/scripts/test-conflict-detection.ps1'
      provides: 'PowerShell FUSE conflict detection test script (2 scenarios)'
  key_links:
    - from: 'folder.service.ts updateFolderMetadata'
      to: 'ipns.service.ts createAndPublishIpnsRecord'
      via: 'expectedSequenceNumber: params.sequenceNumber.toString()'
    - from: 'useFolderMutations.ts handlers'
      to: 'folder.service.ts updateFolderMetadata'
      via: 'try-catch isConflictError -> resyncFolder -> retry'
    - from: 'useFileOperations.ts addFile/addFiles'
      to: 'folder.service.ts addFileToFolder -> buildFolderIpnsRecord'
      via: 'try-catch isConflictError -> resyncFolder -> retry'
    - from: 'sync.store.ts setConflict/clearConflict'
      to: 'SyncIndicator.tsx conflict case'
      via: 'useSyncStore() status === conflict -> amber spinning icon'
    - from: 'desktop api/ipns.rs publish_ipns'
      to: 'fuse/mod.rs spawn_metadata_publish'
      via: 'match PublishResult::Conflict -> re-fetch + merge_folder_children + retry'
human_verification:
  - test: 'Upload a file from two browser tabs simultaneously to same folder'
    expected: 'Second upload triggers 409, auto-re-syncs, both files appear'
    why_human: 'Requires two authenticated sessions modifying same folder concurrently'
  - test: 'Verify amber spinning SyncIndicator appears briefly during conflict re-sync'
    expected: 'SyncIndicator turns amber during re-sync, returns to green checkmark after'
    why_human: 'Visual and timing verification of transient UI state'
  - test: 'Desktop FUSE: write file while another device publishes'
    expected: 'Desktop detects conflict, merges, file is accessible'
    why_human: 'Requires running desktop app with FUSE mount and API concurrently'
---

# Phase 16: Advanced Sync Verification Report

**Phase Goal:** Conflict detection via API-level optimistic concurrency on IPNS folder publishes. When two devices modify the same folder concurrently, the second publish is rejected and the client re-syncs before retrying. Offline queue and idempotent replay deferred to Milestone 3.
**Verified:** 2026-03-03T13:30:00Z
**Status:** PASSED
**Re-verification:** No -- initial verification

## Goal Achievement

### Observable Truths

| #   | Truth                                                                                                                | Status   | Evidence                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| --- | -------------------------------------------------------------------------------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Client detects when another device has published a newer IPNS sequence number and alerts the user before overwriting | VERIFIED | API returns 409 ConflictException with currentSequenceNumber when expectedSequenceNumber mismatches (BigInt comparison in upsertFolderIpns). Web sends expectedSequenceNumber via folder.service.ts updateFolderMetadata and buildFolderIpnsRecord. Desktop sends via IpnsPublishRequest.expected_sequence_number. SyncIndicator shows amber conflict state.                                                                                          |
| 2   | On conflict, both web and desktop clients automatically re-sync the folder and retry the operation once              | VERIFIED | Web: 8 conflict handler sites across useFolderMutations.ts (6 handlers: create, rename, move, moveItems, delete, deleteItems) and useFileOperations.ts (2 handlers: addFile, addFiles). Pattern: catch 409 -> setConflict -> resyncFolder -> jitter -> retry. Desktop: spawn_metadata_publish matches PublishResult::Conflict -> re-resolve sequence -> fetch+decrypt remote metadata -> merge_folder_children -> jitter -> re-encrypt -> retry once. |
| 3   | Persistent conflicts (retry also fails) surface an error to the user without infinite loops                          | VERIFIED | Web: retry catch block checks isConflictError(retryErr) and throws `new Error('Conflict persists after re-sync. Please try again.')` -- no loop. Desktop: second PublishResult::Conflict match logs error and returns `Err("Persistent conflict for ...")` -- no loop. Exactly single retry in both clients.                                                                                                                                          |

**Score:** 3/3 truths verified

### Required Artifacts

| Artifact                                                 | Expected                                      | Status   | Details                                                                                                                                                                                                                |
| -------------------------------------------------------- | --------------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `apps/api/src/ipns/dto/publish.dto.ts`                   | expectedSequenceNumber field                  | VERIFIED | Lines 86-96 (PublishIpnsDto) and 197-206 (PublishIpnsEntryDto): optional string field with numeric regex validation                                                                                                    |
| `apps/api/src/ipns/ipns.service.ts`                      | 409 ConflictException on mismatch             | VERIFIED | Lines 177-189: BigInt comparison, throws ConflictException with currentSequenceNumber. Batch propagates ConflictException (line 142).                                                                                  |
| `apps/api/src/ipns/ipns.controller.ts`                   | 409 ApiResponse docs                          | VERIFIED | Lines 61-65 (publish) and 103-107 (publish-batch): @ApiResponse 409 Conflict documented                                                                                                                                |
| `apps/api/src/ipns/ipns.service.spec.ts`                 | 5 conflict detection tests                    | VERIFIED | Lines 752-884: describe('conflict detection') with 5 tests, all 44 tests pass                                                                                                                                          |
| `apps/web/src/lib/errors.ts`                             | isConflictError utility                       | VERIFIED | 39 lines, checks .status === 409 on thrown Error objects                                                                                                                                                               |
| `apps/web/src/services/ipns.service.ts`                  | expectedSequenceNumber parameter              | VERIFIED | Line 43: parameter in createAndPublishIpnsRecord signature, line 67: passed to API call                                                                                                                                |
| `apps/web/src/services/folder.service.ts`                | expectedSequenceNumber in publish chain       | VERIFIED | updateFolderMetadata line 271: passes sequenceNumber.toString(). buildFolderIpnsRecord line 333: includes in folder record payload. checkAndRotateIfNeeded line 1036: catches isConflictError during lazy rotation.    |
| `apps/web/src/hooks/useFolderMutations.ts`               | Conflict retry on all 6 handlers              | VERIFIED | isConflictError appears at lines 136, 145, 252, 261, 356, 371, 542, 556, 632, 641, 745, 754 covering create, rename, move, moveItems, delete, deleteItems                                                              |
| `apps/web/src/hooks/useFileOperations.ts`                | Conflict retry on addFile/addFiles            | VERIFIED | isConflictError at lines 140, 149 (addFile) and 297 (addFiles). resyncFolder helper at line 31.                                                                                                                        |
| `apps/web/src/stores/sync.store.ts`                      | conflict status type and actions              | VERIFIED | Line 3: SyncStatus includes 'conflict'. Lines 72-82: setConflict() and clearConflict() actions.                                                                                                                        |
| `apps/web/src/components/file-browser/SyncIndicator.tsx` | Amber conflict indicator                      | VERIFIED | Lines 32-44: conflict case renders spinning SVG with sync-indicator-icon--conflict class                                                                                                                               |
| `apps/web/src/App.css`                                   | Conflict CSS class                            | VERIFIED | Line 2361: .sync-indicator-icon--conflict with amber color var(--color-warning, #f59e0b)                                                                                                                               |
| `apps/web/src/api/models/publishIpnsDto.ts`              | Generated client has field                    | VERIFIED | Line 21: expectedSequenceNumber?: string                                                                                                                                                                               |
| `apps/desktop/src-tauri/src/api/ipns.rs`                 | PublishResult enum + expected_sequence_number | VERIFIED | Lines 10-18: PublishResult::Success and Conflict{current_sequence_number}. Line 86: expected_sequence_number field. Lines 97-125: publish_ipns returns PublishResult, parses 409 body.                                 |
| `apps/desktop/src-tauri/src/fuse/mod.rs`                 | merge_folder_children + conflict handling     | VERIFIED | Lines 242-297: merge_folder_children with HashMap-based additive merge (76 lines). Lines 362-453: spawn_metadata_publish with full conflict handling (re-fetch, merge, jitter, retry once, persistent conflict error). |
| `apps/desktop/src-tauri/src/fuse/write_ops.rs`           | All construction sites updated                | VERIFIED | Line 455: None for new folder, line 504: Some(seq.to_string()) for parent publish                                                                                                                                      |
| `apps/desktop/src-tauri/src/fuse/operations.rs`          | Per-file publish uses None                    | VERIFIED | Line 293: expected_sequence_number: None                                                                                                                                                                               |
| `apps/desktop/src-tauri/src/commands/vault.rs`           | Vault init uses None                          | VERIFIED | Line 106: expected_sequence_number: None                                                                                                                                                                               |
| `apps/desktop/src-tauri/src/registry/mod.rs`             | Device registry uses None                     | VERIFIED | Line 122: expected_sequence_number: None                                                                                                                                                                               |
| `apps/desktop/src-tauri/src/fuse/windows/write_ops.rs`   | Windows write_ops updated                     | VERIFIED | Line 164: None for new folder, line 200: Some(seq.to_string()) for parent                                                                                                                                              |
| `apps/desktop/src-tauri/src/fuse/windows/operations.rs`  | Windows per-file uses None                    | VERIFIED | Line 366: expected_sequence_number: None                                                                                                                                                                               |
| `tests/e2e/tests/conflict-detection.spec.ts`             | 3 E2E tests                                   | VERIFIED | 308 lines, 3 serial tests: upload conflict, folder conflict, negative per-file test + cleanup                                                                                                                          |
| `tests/e2e/utils/conflict-helpers.ts`                    | bumpServerSequence helper                     | VERIFIED | 100 lines, resolve-then-unconditional-publish pattern                                                                                                                                                                  |
| `tests/e2e-desktop/scripts/test-conflict-detection.sh`   | Bash conflict test                            | VERIFIED | 204 lines, 2 test scenarios (file write conflict, directory creation conflict)                                                                                                                                         |
| `tests/e2e-desktop/scripts/test-conflict-detection.ps1`  | PowerShell conflict test                      | VERIFIED | 241 lines, equivalent 2 test scenarios                                                                                                                                                                                 |
| `tests/e2e-desktop/scripts/run-all.sh`                   | Conflict step integrated                      | VERIFIED | Invokes test-conflict-detection.sh as Step 4                                                                                                                                                                           |
| `tests/e2e-desktop/scripts/run-all.ps1`                  | Conflict step integrated                      | VERIFIED | Invokes test-conflict-detection.ps1 as Step 4                                                                                                                                                                          |

### Key Link Verification

| From                                    | To                                         | Via                                                                             | Status | Details                                                                                                                                                                                                                                 |
| --------------------------------------- | ------------------------------------------ | ------------------------------------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| folder.service.ts updateFolderMetadata  | ipns.service.ts createAndPublishIpnsRecord | expectedSequenceNumber: params.sequenceNumber.toString()                        | WIRED  | Line 271 passes pre-increment sequence; line 67 of ipns.service.ts forwards to API                                                                                                                                                      |
| folder.service.ts buildFolderIpnsRecord | batchPublishIpnsRecords                    | expectedSequenceNumber: params.sequenceNumber.toString() in record payload      | WIRED  | Line 333 includes field in batch record; line 106 of ipns.service.ts forwards to batch API                                                                                                                                              |
| useFolderMutations.ts all 6 handlers    | folder.service.ts updateFolderMetadata     | try { updateFolderMetadata } catch { isConflictError -> resyncFolder -> retry } | WIRED  | Pattern verified at 12 isConflictError check sites across all handlers                                                                                                                                                                  |
| useFileOperations.ts addFile/addFiles   | folder.service.ts addFileToFolder          | try { performAddFile } catch { isConflictError -> resyncFolder -> retry }       | WIRED  | Pattern at lines 140 and 297                                                                                                                                                                                                            |
| sync.store.ts setConflict/clearConflict | SyncIndicator.tsx                          | useSyncStore() status === 'conflict' -> amber icon                              | WIRED  | SyncIndicator imports useSyncStore (line 1), renders conflict case (line 32)                                                                                                                                                            |
| desktop publish_ipns                    | spawn_metadata_publish                     | match PublishResult::Conflict -> merge + retry                                  | WIRED  | Line 375 matches Conflict variant, lines 383-453 implement full re-sync flow                                                                                                                                                            |
| desktop all IpnsPublishRequest sites    | api/ipns.rs expected_sequence_number       | Some(seq) for folder updates, None for file/vault/registry                      | WIRED  | 9 construction sites verified: mod.rs:359, mod.rs:427, write_ops.rs:455, write_ops.rs:504, operations.rs:293, commands/vault.rs:106, registry/mod.rs:122, windows/write_ops.rs:164, windows/write_ops.rs:200, windows/operations.rs:366 |

### Requirements Coverage

| Requirement                                                                           | Status    | Blocking Issue                                                           |
| ------------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------------ |
| SYNC-04: Client detects conflicts via IPNS sequence number mismatch before publishing | SATISFIED | All truths verified; API returns 409 on mismatch, both clients handle it |

Note: SYNC-05 and SYNC-06 are explicitly deferred to Milestone 3 per ROADMAP.md.

### Anti-Patterns Found

| File                                   | Line  | Pattern                                            | Severity | Impact                                                                                                                 |
| -------------------------------------- | ----- | -------------------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------- |
| apps/web/src/lib/errors.ts             | 35-38 | getConflictSequenceNumber returns undefined (stub) | Info     | Documented limitation. Callers use IPNS re-resolution instead of server hint. Not a blocker -- alternative path works. |
| apps/desktop/src-tauri/src/fuse/mod.rs | 307   | Comment line has missing / (should be ///)         | Info     | Cosmetic only, single slash on documentation comment line                                                              |
| apps/desktop/src-tauri/src/fuse/mod.rs | 396   | Comment line has missing / (should be //)          | Info     | Cosmetic only, single slash on inline comment line                                                                     |

No blockers found. The getConflictSequenceNumber stub is intentional and documented -- callers re-sync via IPNS resolution which is the correct approach.

### Build & Test Verification

| Check                              | Status | Details                                                        |
| ---------------------------------- | ------ | -------------------------------------------------------------- |
| API unit tests                     | PASS   | 44/44 tests pass including 5 conflict detection tests (0.829s) |
| Web build (TypeScript + Vite)      | PASS   | No type errors, clean build in 3.13s                           |
| Desktop cargo check (fuse feature) | PASS   | Compiles with 42 pre-existing warnings, 0 errors               |

### Human Verification Required

### 1. Concurrent Upload from Two Browser Tabs

**Test:** Open two browser tabs logged into the same account. Upload a file in tab A. While tab A's sync is in progress, upload a different file in tab B.
**Expected:** One tab gets a 409 conflict, amber spinner appears briefly, then both files appear in both tabs after re-sync.
**Why human:** Requires two authenticated sessions modifying the same folder concurrently -- cannot simulate programmatically with static analysis.

### 2. Amber SyncIndicator Visibility

**Test:** Trigger a conflict scenario (e.g., using bumpServerSequence from browser console, then upload a file). Watch the SyncIndicator in the header.
**Expected:** SyncIndicator turns amber and spins during the re-sync window (100-500ms jitter + network time), then returns to green checkmark.
**Why human:** Transient visual state that depends on timing and rendering -- cannot verify with static code analysis.

### 3. Desktop FUSE Concurrent Write

**Test:** Mount the FUSE filesystem. Write a file to ~/CipherBox/. While the debounced publish is pending, bump the server sequence via curl. Write a second file.
**Expected:** First publish succeeds. Second publish gets 409, desktop re-syncs with merge, both files remain accessible via ls and cat.
**Why human:** Requires running desktop app with active FUSE mount, timing writes around the debounce window, and verifying filesystem state.

### Gaps Summary

No gaps found. All three observable truths are fully verified:

1. **Conflict detection** is implemented end-to-end: API accepts expectedSequenceNumber (optional, backward-compatible), performs BigInt comparison, throws ConflictException with 409 status and currentSequenceNumber in body. Both web and desktop clients send expectedSequenceNumber on all folder IPNS publishes and correctly omit it for per-file publishes.

2. **Automatic re-sync and retry** is implemented in both clients: Web uses a consistent pattern across all 8 mutation handlers (6 folder + 2 file-add) with resyncFolder helper that re-resolves IPNS and updates the store. Desktop uses merge_folder_children for additive merge that preserves both devices' changes. Both add random jitter (100-500ms) to break symmetry.

3. **Persistent conflict surfacing** is verified: Web throws a user-facing "Conflict persists after re-sync. Please try again." error after single retry failure. Desktop logs error and returns Err with descriptive message. Neither client loops -- exactly one retry attempt.

E2E test coverage is comprehensive: 3 Playwright web tests (upload conflict, folder conflict, negative per-file), 2 desktop bash scenarios, 2 desktop PowerShell scenarios, all integrated into test orchestrators.

---

_Verified: 2026-03-03T13:30:00Z_
_Verifier: Claude (gsd-verifier)_
