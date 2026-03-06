# CipherBox Refactoring Tracker

> Identified 2026-03-02 | Branch: `refactor/quick-wins`

## Tier 1: High-Impact Quick Wins

### 1.1 Extract file-type utilities (Web) — ~150 lines eliminated

- [x] **Status:** DONE
- **Files:** `FileBrowser.tsx`, `SharedFileBrowser.tsx`
- **Problem:** 7 identical functions + 5 identical constant Sets copy-pasted between both files (`isTextFile`, `isImageFile`, `isPdfFile`, `isAudioFile`, `isVideoFile`, `isPreviewableFile`, `isFilePointer`, plus `TEXT_EXTENSIONS`, `IMAGE_EXTENSIONS`, etc.)
- **Fix:** Extract to `apps/web/src/utils/fileTypes.ts`

### 1.2 Extract `DelegatedRoutingClient` (API) — ~300 lines consolidated

- [x] **Status:** DONE
- **Files:** `apps/api/src/ipns/ipns.service.ts` (560 lines), `apps/api/src/republish/republish.service.ts` (446 lines)
- **Problem:** Duplicated exponential-backoff retry loops with 429/Retry-After handling, identical `delay()` helper, identical `DELEGATED_ROUTING_URL` config lookups, same URL template construction
- **Fix:** New injectable `DelegatedRoutingClient` service with `publish()` and `resolve()` methods

### 1.3 Extract shared FUSE helpers (Desktop Rust) — ~494 lines eliminated

- [x] **Status:** DONE
- **Files:** `fuse/operations.rs` (2,602 lines), `fuse/windows/operations.rs` (2,644 lines)
- **Problem:** 5 exact-duplicate functions across macOS and Windows backends:
  - `fetch_and_decrypt_content_async` — byte-for-byte identical
  - `publish_file_metadata` — near-identical
  - `fetch_and_populate_folder` — near-identical
  - `resolve_file_pointers_blocking` — near-identical
  - `mime_from_extension` — exact duplicate (35 MIME mappings)
  - Plus 4 duplicated constants (`QUOTA_BYTES`, `MAX_VERSIONS_PER_FILE`, `VERSION_COOLDOWN_MS`, `CONTENT_DOWNLOAD_TIMEOUT`)
  - Plus 3 private copies of `decrypt_metadata_from_ipfs` when `fuse::decrypt::decrypt_metadata_from_ipfs_public` already exists
- **Fix:** Move to `fuse/helpers.rs` and `fuse/constants.rs`

### 1.4 Extract `useDialogState` hook (Web) — simplifies `FileBrowser.tsx`

- [x] **Status:** DONE
- **Files:** `apps/web/src/components/file-browser/FileBrowser.tsx` (1,153 lines)
- **Problem:** 12 separate `useState` calls for dialog state + 18 open/close callbacks that are all one-liners
- **Fix:** Create `useDialogState<T>()` hook returning `[state, open, close]`

---

## Tier 2: Medium-Impact Structural Splits

### 2.1 Split `useFolder.ts` (1,262 lines) into 3 hooks

- [x] **Status:** DONE
- **Files:** `apps/web/src/hooks/useFolder.ts`
- **Problem:** 11 async operations with identical try/catch/setState boilerplate (repeated 11x), `resolveFolderById` pattern (repeated 10x), lazy IPNS migration block (repeated 3x)
- **Fix:** Split into `useFolderMutations`, `useFileOperations`, `useFileVersions`; extract `withLoading()` wrapper and `resolveFolderById()` helper

### 2.2 Split `AuthService` (669 lines, 8 injected deps)

- [x] **Status:** DONE
- **Files:** `apps/api/src/auth/auth.service.ts`
- **Problem:** 6 distinct responsibilities, cross-domain dependencies (IPFS in auth)
- **Fix:** Split into `AuthService` (core), `AuthMethodService`, `AccountService`, `TestAuthService`

### 2.3 Split `SharesService` (569 lines)

- [x] **Status:** DONE
- **Files:** `apps/api/src/shares/shares.service.ts`
- **Problem:** Natural seam at line 334 (`// Invite link methods`); controllers already split but service is monolith
- **Fix:** Extract `ShareInviteService` for invite methods

### 2.4 Split `commands.rs` (907 lines) into modules

- [x] **Status:** DONE
- **Files:** `apps/desktop/src-tauri/src/commands.rs`
- **Problem:** All Tauri IPC commands in one file, `parse_private_key_hex` duplicated 3x
- **Fix:** Split into `commands/auth.rs`, `commands/vault.rs`, `commands/sync.rs`, `commands/debug.rs`, `commands/oauth.rs`

### 2.5 Split FUSE operations by category

- [x] **Status:** DONE
- **Files:** `fuse/operations.rs`, `fuse/windows/operations.rs`
- **Problem:** Each file >2,600 lines with all filesystem callbacks mixed together
- **Fix:** Split into `read_ops.rs`, `write_ops.rs`, `dir_ops.rs` for each platform

### 2.6 Extract Redis module (API)

- [x] **Status:** DONE
- **Files:** `auth.service.ts`, `email-otp.service.ts`, `identity.controller.ts`
- **Problem:** Same `new Redis({...})` + `ConfigService` lookup + `OnModuleDestroy` quit pattern repeated 3x
- **Fix:** Create `RedisModule` with shared `REDIS_CLIENT` injection token

---

## Tier 3: Lower-Priority Cleanup

| #    | Issue                                           | Location                                               | Fix                                                 | Status |
| ---- | ----------------------------------------------- | ------------------------------------------------------ | --------------------------------------------------- | ------ |
| 3.1  | `RequestWithUser` defined twice                 | `auth.controller.ts` + `common/types.ts`               | Delete local copy, import from common               | TODO   |
| 3.2  | `findShareOrThrow` pattern 6x                   | `shares.service.ts`                                    | Extract private helper                              | TODO   |
| 3.3  | `uint8ToBase64` duplicated                      | `folder.service.ts` + `file-metadata.service.ts`       | Move to `utils/encoding.ts`                         | TODO   |
| 3.4  | `truncatePublicKey`/`truncatePubkey`            | `ShareDialog.tsx` + `SharedFileBrowser.tsx`            | Add to existing `utils/format.ts`                   | TODO   |
| 3.5  | `MAX_FOLDER_DEPTH = 20` defined 3x              | `folder.service.ts`, `useFolder.ts`, `MoveDialog.tsx`  | Single export from folder.service                   | TODO   |
| 3.6  | `InitVaultDto` hand-written alongside generated | `lib/api/vault.ts` vs `api/models/`                    | Delete hand-written, use generated                  | TODO   |
| 3.7  | REQUIRED_SHARE block 3x in `useAuth`            | `loginWithGoogle`, `loginWithEmail`, `loginWithWallet` | Extract `handleRequiredShare()` helper              | TODO   |
| 3.8  | Controller has repo access + business logic     | `identity.controller.ts`                               | Move `findOrCreateUserByIdentifier` to service      | TODO   |
| 3.9  | `publishBatch` duplicates single-record logic   | `ipns.service.ts`                                      | Extract `processSingleRecord` helper                | TODO   |
| 3.10 | Inline IPFS fetch+decode 4x                     | `useSharedNavigation.ts`                               | Reuse existing `fetchAndDecryptMetadata`            | TODO   |
| 3.11 | Catch variable inconsistency                    | 206 catch blocks use `err`/`error`/`e` randomly        | Pick one, add ESLint rule                           | TODO   |
| 3.12 | Metrics 100-line constructor                    | `metrics.service.ts`                                   | Extract `initializeMetrics()` method                | TODO   |
| 3.13 | `publicKey` 0x-normalization 2x                 | `shares.service.ts`                                    | Extract `normalizePublicKey()` to `common/utils.ts` | TODO   |
| 3.14 | `toVaultResponse` + TEE fetch 3x                | `vault.service.ts`                                     | Extract `toVaultResponseWithTeeKeys()`              | TODO   |

---

## Architecture Notes (Not Bugs, Monitor)

- **Desktop `auth.ts` (771 lines) parallels web `useAuth.ts` (510 lines)** — structural duplication from Tauri/browser split. Can't easily share.
- **12 services call `useStore.getState()` directly** — valid Zustand pattern but implicit coupling. No circular deps.
- **`generate-openapi.ts` has 39 manual imports** — must update when adding controllers. Consider auto-discovery.
- **Rust IPNS implementation (408 lines hand-rolled CBOR/protobuf)** parallels TypeScript `ipns` npm package — risks silent divergence.
- **`pendingPublishes: Set<string>` in folder store** — may be unused dead code. Audit and remove if so.
- **`quota.store.ts` calls `vaultApi` directly** — inverted dependency direction (store has network dependency).
