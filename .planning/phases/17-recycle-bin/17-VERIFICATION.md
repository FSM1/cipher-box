---
phase: 17-recycle-bin
verified: 2026-03-04T02:34:07Z
status: passed
score: 8/8 must-haves verified
---

# Phase 17: Recycle Bin Verification Report

**Phase Goal:** Deleted files and folders are moved to a recycle bin with time-limited retention instead of being permanently destroyed. Users can recover items to their original vault location and manually empty the bin to free storage space.
**Verified:** 2026-03-04T02:34:07Z
**Status:** PASSED
**Re-verification:** No -- initial verification

## Goal Achievement

### Observable Truths

| #   | Truth                                                                               | Status   | Evidence                                                                                                                                                                                                                                                                                       |
| --- | ----------------------------------------------------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Deleting a file/folder moves it to a recycle bin instead of permanently removing it | VERIFIED | `useFolderMutations.ts` calls `addToBin` (line 628, 748) instead of `unpinFromIpfs` (no unpinFromIpfs references remain). Desktop `handle_unlink` and `handle_rmdir` create `BinEntry` and call `spawn_bin_entry_publish`.                                                                     |
| 2   | User can browse bin contents and restore any item to its original folder location   | VERIFIED | `BinBrowser.tsx` (533 lines) renders flat list with `useBin()` hook. `restoreFromBin` in `bin.service.ts` resolves target folder, handles name collisions, recursive parent restore (max depth 5), root fallback.                                                                              |
| 3   | User can manually empty the entire bin or permanently delete individual items       | VERIFIED | `BinBrowser.tsx` has Empty Bin button (line 326) with confirmation dialog. Context menu has "Restore" and "Delete Permanently" actions (line 500-515). `permanentlyDelete` and `emptyBin` in `bin.service.ts` unpin CIDs and update quota.                                                     |
| 4   | Bin items are automatically purged after the retention period expires               | VERIFIED | `purgeExpired` in `bin.service.ts` (line 374) filters entries past retention, cleans up CIDs, publishes updated metadata. Called via `useBin.loadBin` (non-blocking auto-purge on bin page load).                                                                                              |
| 5   | User can multi-select bin items for batch restore or batch permanent delete         | VERIFIED | `BinBrowser.tsx` has checkbox selection, shift-click range select, selection bar with batch restore (line 469) and batch delete (line 482) buttons. `useBin` exposes `restoreMultiple` and `permanentDeleteMultiple`.                                                                          |
| 6   | Desktop FUSE deletions create cross-platform-compatible bin entries                 | VERIFIED | Rust `crypto/bin.rs` has `RecycleBinMetadata`, `BinEntry`, `BinItemType` with `#[serde(rename_all = "camelCase")]` matching TypeScript types. HKDF info `cipherbox-recycle-bin-ipns-v1` matches across both platforms. `spawn_bin_entry_publish` in `fuse/mod.rs` handles full IPNS lifecycle. |
| 7   | Bin is initialized on login and cleared on logout                                   | VERIFIED | `useAuth.ts` calls `initializeBin` (line 178) in fire-and-forget block after device registry init. `clearBin` called on both logout paths (lines 456, 470). Retention config fetched via `vaultControllerGetConfig` (line 190).                                                                |
| 8   | API serves retention config via GET /vault/config                                   | VERIFIED | `vault.controller.ts` has `@Get('config')` endpoint (line 44). `vault.service.ts` reads `RECYCLE_BIN_RETENTION_DAYS` from ConfigService with default 30 (line 40). Generated API client has `vaultControllerGetConfig` function.                                                               |

**Score:** 8/8 truths verified

### Required Artifacts

| Artifact                                                 | Expected                               | Status   | Details                                                                                                  |
| -------------------------------------------------------- | -------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------- |
| `packages/crypto/src/bin/types.ts`                       | RecycleBinMetadata + BinEntry types    | VERIFIED | 59 lines, full type definitions with FilePointer/FolderEntry imports                                     |
| `packages/crypto/src/bin/derive-ipns.ts`                 | HKDF derivation for bin IPNS keypair   | VERIFIED | 66 lines, uses `deriveKey` with info `cipherbox-recycle-bin-ipns-v1`                                     |
| `packages/crypto/src/bin/encrypt.ts`                     | ECIES encrypt/decrypt for bin metadata | VERIFIED | 68 lines, uses wrapKey/unwrapKey with validateBinMetadata                                                |
| `packages/crypto/src/bin/schema.ts`                      | Runtime validation for bin metadata    | VERIFIED | 123 lines, validates version, sequenceNumber, entries array, entry fields                                |
| `packages/crypto/src/bin/index.ts`                       | Barrel exports                         | VERIFIED | 15 lines, exports all types, functions                                                                   |
| `packages/crypto/src/index.ts`                           | Re-exports bin module                  | VERIFIED | Lines 121-129 export all bin symbols                                                                     |
| `apps/api/src/vault/vault.controller.ts`                 | GET /vault/config endpoint             | VERIFIED | Line 44, authenticated, returns VaultConfigResponseDto                                                   |
| `apps/api/src/vault/vault.service.ts`                    | getConfig method                       | VERIFIED | Line 39, reads RECYCLE_BIN_RETENTION_DAYS with default 30                                                |
| `apps/web/src/stores/bin.store.ts`                       | Zustand bin store                      | VERIFIED | 105 lines, entries, loading, sequenceNumber, retentionDays, CRUD actions                                 |
| `apps/web/src/services/bin.service.ts`                   | Bin IPNS lifecycle service             | VERIFIED | 641 lines, initializeBin, addToBin, restoreFromBin, permanentlyDelete, emptyBin, purgeExpired            |
| `apps/web/src/hooks/useBin.ts`                           | React hook for bin operations          | VERIFIED | 199 lines, wraps service with loading/error state, daysRemaining helper                                  |
| `apps/web/src/hooks/useFolderMutations.ts`               | Delete flow calls addToBin             | VERIFIED | addToBin called at lines 628, 748. No unpinFromIpfs references remain.                                   |
| `apps/web/src/services/folder.service.ts`                | Returns removedChild from delete       | VERIFIED | deleteFolder returns removedChild (FolderEntry), deleteFileFromFolder returns removedChild (FilePointer) |
| `apps/web/src/hooks/useAuth.ts`                          | Bin init on login, clear on logout     | VERIFIED | initializeBin at line 178, clearBin at lines 456, 470, config fetch at line 190                          |
| `apps/web/src/routes/BinPage.tsx`                        | /bin route page                        | VERIFIED | 41 lines, AppShell + BinBrowser, auth guard                                                              |
| `apps/web/src/routes/index.tsx`                          | /bin route registered                  | VERIFIED | Line 17, `<Route path="/bin" element={<BinPage />} />`                                                   |
| `apps/web/src/components/file-browser/BinBrowser.tsx`    | Flat list bin view                     | VERIFIED | 533 lines, useBin hook, sorting, multi-select, context menu, confirm dialogs                             |
| `apps/web/src/components/file-browser/BinListItem.tsx`   | Bin item row                           | VERIFIED | 159 lines, type indicators, relative time, retention countdown                                           |
| `apps/web/src/components/file-browser/BinEmptyState.tsx` | Empty state                            | VERIFIED | 31 lines, wastebasket icon, retention info                                                               |
| `apps/web/src/components/layout/AppSidebar.tsx`          | Bin nav item                           | VERIFIED | Line 27, NavItem to="/bin" with bin icon                                                                 |
| `apps/web/src/styles/bin-browser.css`                    | Bin-specific styles                    | VERIFIED | 257 lines, terminal/cyberpunk aesthetic                                                                  |
| `apps/desktop/src-tauri/src/crypto/bin.rs`               | Rust bin types + encrypt/decrypt       | VERIFIED | 170 lines, RecycleBinMetadata, BinEntry, BinItemType, ECIES encrypt/decrypt, UUID/MIME helpers           |
| `apps/desktop/src-tauri/src/crypto/hkdf.rs`              | derive_bin_ipns_keypair                | VERIFIED | BIN_HKDF_INFO constant (line 33), derive_bin_ipns_keypair function (line 128)                            |
| `apps/desktop/src-tauri/src/crypto/mod.rs`               | pub mod bin + re-exports               | VERIFIED | Line 8, line 21                                                                                          |
| `apps/desktop/src-tauri/src/fuse/write_ops.rs`           | handle_unlink/rmdir create bin entries | VERIFIED | bin_entry_data captured at lines 273/623, spawn_bin_entry_publish called at lines 353/727                |
| `apps/desktop/src-tauri/src/fuse/mod.rs`                 | spawn_bin_entry_publish helper         | VERIFIED | Line 482, pub(crate) function                                                                            |
| `tests/e2e/page-objects/pages/bin.page.ts`               | Bin page object                        | VERIFIED | 170 lines, navigation, item query, context menu actions                                                  |
| `tests/e2e/tests/recycle-bin.spec.ts`                    | Playwright E2E test suite              | VERIFIED | 312 lines, 6 test cases (TC01-TC06)                                                                      |
| `tests/e2e/page-objects/index.ts`                        | BinPage barrel export                  | VERIFIED | Line 33                                                                                                  |
| `tests/e2e-desktop/scripts/test-recycle-bin.sh`          | Desktop E2E bash script                | VERIFIED | 135 lines                                                                                                |
| `tests/e2e-desktop/scripts/test-recycle-bin.ps1`         | Desktop E2E PowerShell script          | VERIFIED | 158 lines                                                                                                |
| `tests/e2e-desktop/scripts/run-all.sh`                   | Step 5 recycle bin                     | VERIFIED | Line 89, test-recycle-bin.sh invocation                                                                  |
| `tests/e2e-desktop/scripts/run-all.ps1`                  | Step 5 recycle bin                     | VERIFIED | Line 100, test-recycle-bin.ps1 invocation                                                                |

### Key Link Verification

| From                    | To                                | Via                                                          | Status | Details                                                                                |
| ----------------------- | --------------------------------- | ------------------------------------------------------------ | ------ | -------------------------------------------------------------------------------------- |
| `bin/derive-ipns.ts`    | `keys/derive.ts`                  | deriveKey HKDF                                               | WIRED  | Line 48: `deriveKey({ inputKey, salt: BIN_HKDF_SALT, info: BIN_HKDF_INFO })`           |
| `bin/encrypt.ts`        | `ecies/encrypt` + `ecies/decrypt` | wrapKey/unwrapKey                                            | WIRED  | Line 12-13: imports wrapKey, unwrapKey; used in encryptBinMetadata/decryptBinMetadata  |
| `useFolderMutations.ts` | `bin.service.ts`                  | addToBin call                                                | WIRED  | Line 7: import, Lines 628/748: fire-and-forget calls in handleDelete/handleDeleteItems |
| `bin.service.ts`        | `@cipherbox/crypto` bin module    | deriveBinIpnsKeypair, encryptBinMetadata, decryptBinMetadata | WIRED  | Line 16-27: all crypto functions imported and used                                     |
| `bin.service.ts`        | `ipns.service.ts`                 | createAndPublishIpnsRecord, resolveIpnsRecord                | WIRED  | Line 29: imported, used in saveBinMetadata (line 108) and loadBinMetadata (line 55)    |
| `useAuth.ts`            | `bin.service.ts`                  | initializeBin                                                | WIRED  | Line 24: import, Line 178: called after login                                          |
| `useAuth.ts`            | `bin.store.ts`                    | clearBin                                                     | WIRED  | Line 25: import, Lines 456/470: called on both logout paths                            |
| `BinBrowser.tsx`        | `useBin.ts`                       | useBin hook                                                  | WIRED  | Line 11: import, Line 35: hook call with destructured operations                       |
| `routes/index.tsx`      | `BinPage.tsx`                     | Route registration                                           | WIRED  | Line 5: import, Line 17: Route element                                                 |
| `AppSidebar.tsx`        | `/bin` route                      | NavItem link                                                 | WIRED  | Line 27: `<NavItem to="/bin" icon="bin" label="Bin" ...>`                              |
| Rust `hkdf.rs`          | TS `derive-ipns.ts`               | Same HKDF info string                                        | WIRED  | Both use `cipherbox-recycle-bin-ipns-v1`                                               |
| Rust `bin.rs`           | TS `types.ts`                     | Matching serde camelCase                                     | WIRED  | `#[serde(rename_all = "camelCase")]` produces identical JSON field names               |
| `write_ops.rs`          | `mod.rs`                          | spawn_bin_entry_publish                                      | WIRED  | Lines 353/727: called after folder metadata update in unlink/rmdir                     |
| `recycle-bin.spec.ts`   | `bin.page.ts`                     | BinPage page object                                          | WIRED  | Import and usage across 6 test cases                                                   |
| `test-recycle-bin.sh`   | `run-all.sh`                      | Step 5 integration                                           | WIRED  | Line 89 in run-all.sh                                                                  |

### Requirements Coverage

| Requirement                               | Status    | Evidence                                                                                              |
| ----------------------------------------- | --------- | ----------------------------------------------------------------------------------------------------- |
| BIN-01: Soft-delete moves items to bin    | SATISFIED | addToBin replaces unpinFromIpfs in delete flow                                                        |
| BIN-02: Browse and restore from bin       | SATISFIED | BinBrowser with flat list, restore via context menu and batch                                         |
| BIN-03: Manual empty and permanent delete | SATISFIED | Empty Bin button, Delete Permanently context menu action                                              |
| BIN-04: Auto-purge after retention period | SATISFIED | purgeExpired called on bin load, configurable retention via API                                       |
| BIN-05: Bin storage counts against quota  | SATISFIED | CIDs stay pinned during soft-delete (quota unchanged); permanentlyDelete unpins and calls removeUsage |

### Anti-Patterns Found

| File             | Line | Pattern                    | Severity | Impact                                                    |
| ---------------- | ---- | -------------------------- | -------- | --------------------------------------------------------- |
| `bin.service.ts` | 274  | "placeholder node" comment | Info     | Intentional lazy loading for restored folders, not a stub |
| `bin.service.ts` | 58   | `return null`              | Info     | Normal flow: no existing bin metadata yet                 |

No blocker or warning-level anti-patterns found.

### Build Verification

| Check                                     | Result                |
| ----------------------------------------- | --------------------- |
| `pnpm --filter @cipherbox/crypto build`   | PASSED (41ms)         |
| `pnpm --filter web build`                 | PASSED (3.81s)        |
| No unpinFromIpfs in useFolderMutations.ts | CONFIRMED             |
| No TODO/FIXME stubs in bin service        | CONFIRMED (0 matches) |

### Human Verification Required

### 1. Full Delete-Restore Workflow

**Test:** Log in, upload a file, delete it, navigate to /bin, verify it appears with correct metadata, right-click Restore, navigate back to files, verify file is back.
**Expected:** File moves to bin on delete, shows correct name/path/date/size/retention, restores to original location.
**Why human:** Requires live IPNS publish/resolve cycle and visual verification of UI state transitions.

### 2. Permanent Delete and Quota

**Test:** Delete a file, navigate to /bin, right-click Delete Permanently, confirm. Check quota (Settings or API) to verify space was reclaimed.
**Expected:** Item removed from bin, CID unpinned, quota decreases by file size.
**Why human:** Requires verifying IPFS unpin and quota store update against live API.

### 3. Empty Bin Confirmation Flow

**Test:** Delete multiple files, navigate to /bin, click Empty Bin, verify confirmation dialog, confirm.
**Expected:** All items removed, empty state shows, quota reclaimed.
**Why human:** Visual verification of confirmation dialog UX and empty state display.

### 4. Desktop FUSE Cross-Platform Recovery

**Test:** Delete a file via the FUSE mount (rm ~/CipherBox/file.txt), open web app /bin, verify the file appears, restore it, verify it reappears on the FUSE mount.
**Expected:** Desktop-deleted file visible in web bin, restores to FUSE mount after sync.
**Why human:** Requires running desktop app with FUSE mount and web app simultaneously.

### 5. Retention Countdown Display

**Test:** Navigate to /bin with existing items, verify "X days" countdown displays correctly, verify warning color for items near expiration.
**Expected:** Days remaining calculates correctly from deletedAt + retentionDays, amber/warning color at <= 3 days.
**Why human:** Visual verification of countdown formatting and color theming.

### Gaps Summary

No gaps found. All 8 observable truths verified with supporting artifacts at all three levels (existence, substantive, wired). The phase goal -- "Deleted files and folders are moved to a recycle bin with time-limited retention instead of being permanently destroyed. Users can recover items to their original vault location and manually empty the bin to free storage space" -- is structurally achieved across both web and desktop platforms.

The implementation covers:

- **Crypto layer:** TypeScript and Rust bin modules with matching HKDF derivation and ECIES encryption
- **API layer:** GET /vault/config endpoint with configurable retention
- **Service layer:** Full IPNS lifecycle (init, add, restore, permanent delete, empty, purge)
- **Delete flow rewiring:** All delete paths call addToBin instead of unpinning CIDs
- **UI layer:** Sidebar navigation, /bin route, flat list browser with sorting, context menu, multi-select, empty bin
- **Desktop layer:** FUSE handle_unlink/handle_rmdir create BinEntry with full FilePointer/FolderEntry data
- **E2E testing:** Playwright web tests (6 cases), desktop bash/PowerShell scripts, run-all integration

---

_Verified: 2026-03-04T02:34:07Z_
_Verifier: Claude (gsd-verifier)_
