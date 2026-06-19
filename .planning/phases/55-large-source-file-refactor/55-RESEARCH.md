# Phase 55: Large Source-File Refactor - Research

**Researched:** 2026-06-19
**Domain:** Rust module decomposition + TypeScript barrel splits + cross-platform dedup (no external dependencies)
**Confidence:** HIGH — all findings are static code analysis against the actual worktree

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01 (tier scope):** Tier 1 + Tier 2 only. Tier 3 deferred.
- **D-02 (client.ts approach, forward-looking):** Full facade decomposition when client.ts is
  eventually tackled. `ClientCore` shared-state handle + 7-phase split to ~350-LoC delegating
  facade. Honor frozen public API + `@internal` accessors + `ClientCore.folderTree` as single
  source of truth (PR #489). Locked for the deferred phase.
- **D-03 (Tier 3 test-first):** Tier 3 gated on a separate test-backfill phase before any Tier-3
  refactor begins. No Tier-3 refactor proceeds until its test net exists.
- **D-04 (PR/plan granularity):** Batched coherent groups — lib.rs decomposition as one group,
  Windows/cross-platform dedup as one group, remaining Rust Tier-1 (write_ops) as one, TS/web
  Tier-1 (folder barrel, ipns codec, DetailsDialog, commands/auth) grouped sensibly.
- **D-05:** Public surface frozen — SDK exports, crate re-exports, component/hook signatures,
  NestJS DI byte-identical. No `pnpm api:generate`. Consumers compile with no edits.
- **D-06:** Sequencing — `lib.rs` first → rest of Tier 1 → Tier 2 dedup. Gate Rust items on BOTH
  feature sets.
- **D-07:** Per-item acceptance — split/deduped as specified; public surface unchanged; relevant
  test suite passes (both Rust feature sets where applicable); consumers compile with no edits.

### Claude's Discretion

- Exact PR/plan groupings within D-04's four coherent groups.

### Deferred Ideas (OUT OF SCOPE)

- All Tier 3 items: `client.ts`, `inode.rs`, `windows/write_ops.rs`, `SharedFileBrowser.tsx`,
  `auth.ts`, `ShareDialog.tsx`, `useAuth.ts`, `main.ts`, `bin/index.ts`,
  `useFileBrowserActions.ts`, `useSharedNavigationActions.ts`, `BinBrowser.tsx`.
- `windows/host.rs` dispatcher split (can't be exercised off Windows).
- Leave-as-is set: `apps/web/src/services/share.service.ts`,
  `packages/sdk/src/share/shared-write.ts`, `crates/sdk/src/queue.rs`,
  `crates/fuse/src/journal_helpers.rs`.

</user_constraints>

<phase_requirements>

## Phase Requirements

| ID      | Description                                                                                             | Research Support                                                          |
| ------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| HARD-06 | Split/dedup oversized source files (e.g. client.ts, lib.rs) tier-by-tier without public-API changes | All findings below enable per-file implementation; public surface confirmed frozen |

</phase_requirements>

## Summary

Phase 55 is a pure internal refactor: cut-paste + re-export for every Tier 1 item; dedup-and-extract for every Tier 2 item. No new packages, no API changes, no build changes. The entire phase is validated by: (a) existing test suites still pass (both Rust feature sets), (b) consumers compile untouched, and (c) public surface is byte-identical.

All surveyed LoC counts match the worktree exactly (every file is within ±0 lines of the survey). The survey's implementation spec for lib.rs is accurate and immediately executable. The two key dedup sites (fuse/platform/windows/operations.rs and desktop/src-tauri/src/fuse/) are structurally parallel but use slightly different call-path spellings; the shared module must normalize them. No external packages are installed.

**Primary recommendation:** Execute in four batched plan groups: (1) lib.rs 6-module decomposition, (2) Tier-1 Rust remainder (write_ops), (3) Tier-1 TypeScript/web (folder barrel, ipns codec, DetailsDialog, commands/auth), (4) Tier-2 cross-platform dedup (operations.rs, fuse/windows/mod.rs prepopulate, windows/read_ops.rs, read_ops.rs).

## Architectural Responsibility Map

| Capability                        | Primary Tier         | Secondary Tier      | Rationale                                                        |
| --------------------------------- | -------------------- | ------------------- | ---------------------------------------------------------------- |
| FUSE crate module decomposition   | crates/fuse          | —                   | Pure Rust internal; desktop consumes via re-exports              |
| Desktop mount prepopulate dedup   | Desktop FUSE bridge  | crates/fuse crate   | Lives in desktop src-tauri/src/fuse/, not in the crate itself   |
| TypeScript barrel splits          | packages/sdk-core    | packages/sdk        | sdk-core's folder/index.ts; sdk tests target the barrel         |
| NestJS codec extraction           | apps/api             | —                   | Private method extract within the same NestJS service class      |
| React component split             | apps/web             | —                   | Sub-components behind the container; no route or store change    |
| Tauri command refactor            | apps/desktop         | —                   | vault.rs already exists; load_vault_settings moves there        |

## Per-File Current-State Map

### Tier 1 Targets (all LoC verified against worktree)

#### `crates/fuse/src/lib.rs` — 3276 LoC [VERIFIED: wc -l]

**Current module/facade structure:**

Module declarations (lines 7–30):
- Unconditionally pub: `cache`, `constants`, `error`, `file_handle`, `helpers`, `inode`, `journal_helpers`
- `#[cfg(feature = "fuse")]` pub: `dir_ops`, `operations`, `read_ops`, `write_ops`
- `pub mod platform`
- `#[cfg(all(test, feature = "fuse"))]` mod: `test_support`

Existing re-exports (lines 33–36):
```rust
pub use cache::{ContentCache, MetadataCache};
pub use error::FuseError;
pub use file_handle::OpenFileHandle;
pub use inode::{InodeData, InodeTable};
```

**Top-level items by target module:**

| Item | cfg gate | Current visibility | Target module | Notes |
|------|----------|--------------------|--------------|-------|
| `NETWORK_TIMEOUT` (const) | `any(fuse,winfsp)` | (local) | `runtime.rs` | Note: operations.rs has its own private copy (`NETWORK_TIMEOUT = 3s`); lib.rs version is `10s` — leave operations.rs copy in place per survey |
| `block_with_timeout` | `any(fuse,winfsp)` | `pub` | `runtime.rs` | |
| `PendingRefresh` | `any(fuse,winfsp)` | `pub` | `events.rs` | |
| `PendingContent` | `any(fuse,winfsp)` | `pub` | `events.rs` | |
| `PendingFilePointer` | `any(fuse,winfsp)` | `pub` | `events.rs` | |
| `FsEvent` | `any(fuse,winfsp)` | `pub` | `events.rs` | |
| `UploadComplete` | `any(fuse,winfsp)` | `pub` | `events.rs` | |
| `spawn_metadata_refresh` | `any(fuse,winfsp)` | `pub` | `events.rs` | depends on `PendingRefresh` |
| `PublishQueueEntry` | `any(fuse,winfsp)` | `pub` | `publish.rs` | |
| `next_file_publish_sequence` | **NONE** (ungated) | `pub` | `publish.rs` | Only ungated item that moves — test at line 2273 moves with it |
| `resolve_ipns_for_replay` | `any(fuse,winfsp)` | `fn` (private) | `publish.rs` | **needs visibility bump to `pub(crate)`** — consumed by replay.rs |
| `classify_resolve_outcome` | `any(fuse,winfsp)` | `fn` (private) | `publish.rs` | **needs visibility bump to `pub(crate)`** — unit test + replay use it |
| `PublishCoordinator` + `impl` | `any(fuse,winfsp)` | `pub` | `publish.rs` | |
| `encrypt_metadata_to_json` | `any(fuse,winfsp)` | `pub` | `metadata.rs` | |
| `merge_folder_children` | `any(fuse,winfsp)` | `pub` | `metadata.rs` | |
| `spawn_metadata_publish` | `any(fuse,winfsp)` | `pub` | `metadata.rs` | |
| `spawn_bin_entry_publish` | `any(fuse,winfsp)` | `pub` | `metadata.rs` | |
| `ReencryptOutcome` (enum) | `any(fuse,winfsp)` | `enum` (private) | `metadata.rs` | stays private — only used within `spawn_file_meta_reencrypt` |
| `resolve_and_fetch_file_meta` | `any(fuse,winfsp)` | `async fn` (private) | `metadata.rs` | stays private |
| `spawn_file_meta_reencrypt` | `any(fuse,winfsp)` | `pub` | `metadata.rs` | |
| `CipherBoxFS` (struct) | `any(fuse,winfsp)` | `pub` | `fs.rs` | **all fields must stay `pub`** — desktop constructs via struct literal |
| `impl CipherBoxFS` | `any(fuse,winfsp)` | (impl) | `fs.rs` | Multiple inherent impl blocks across files are legal (journal_helpers.rs already does this) |
| `uuid_from_ino` | `any(fuse,winfsp)` | `fn` (private) | `fs.rs` | stays private |
| `mount_point` | `any(fuse,winfsp)` | `pub` | `fs.rs` | |
| `publish_file_metadata` use shim (lines 1390–1393) | fuse vs winfsp | (local use import) | `replay.rs` | the cfg-branched use block moves with replay.rs |
| `replay_for_vault` | `any(fuse,winfsp)` | `pub async fn` | `replay.rs` | |
| `resolve_folder_key` | `any(fuse,winfsp)` | `async fn` (private) | `replay.rs` | |
| `resolve_folder_key_cached` | `any(fuse,winfsp)` | `async fn` (private) | `replay.rs` | |
| `fetch_merge_publish_parent` | `any(fuse,winfsp)` | `async fn` (private) | `replay.rs` | |
| `publish_child_folder_metadata` | `any(fuse,winfsp)` | `async fn` (private) | `replay.rs` | |
| `replay_mkdir_entry` | `any(fuse,winfsp)` | `async fn` (private) | `replay.rs` | |
| `replay_upload_entry` | `any(fuse,winfsp)` | `async fn` (private) | `replay.rs` | |

**Test relocation (per survey Option A — co-locate):**

| Test | Location today | Move with code? |
|------|---------------|-----------------|
| `mod tests` (lines 2272–2944) | lib.rs | `next_file_publish_sequence` tests → `publish.rs`; `classify_resolve_outcome` tests → `publish.rs`; `merge_folder_children` test (T-45-08) → `metadata.rs`; replay tests (T-45-06, T-45-07, legacy_empty_name_parks, strict_resolve_bypasses_cache, REQ-5 transient-fail) → `replay.rs` |
| `mod handler_harness_tests` (lines 2949–2976) | lib.rs | **STAY in lib.rs** — spans `crate::read_ops` and `crate::test_support`; `crate::` paths stay valid via re-exports |
| `mod durability_characterization_tests` (lines 2985–3276) | lib.rs | **STAY in lib.rs** — spans write_ops mkdir + handle_release paths via handler calls |

**Required re-exports in new lib.rs (~120 LoC):**

```rust
// module declarations
pub mod runtime;
pub mod events;
pub mod publish;
pub mod metadata;
pub mod fs;
pub mod replay;

// re-exports to keep cipherbox_fuse::<X> paths stable
pub use runtime::block_with_timeout;
pub use events::{PendingRefresh, PendingContent, PendingFilePointer, FsEvent, UploadComplete, spawn_metadata_refresh};
pub use publish::{PublishQueueEntry, PublishCoordinator, next_file_publish_sequence};
pub use metadata::{encrypt_metadata_to_json, merge_folder_children, spawn_metadata_publish, spawn_bin_entry_publish, spawn_file_meta_reencrypt};
pub use fs::{CipherBoxFS, mount_point};
pub use replay::replay_for_vault;
```

**Visibility bumps needed:**
- `resolve_ipns_for_replay`: `fn` → `pub(crate) async fn` (called by replay.rs; both are in the same crate)
- `classify_resolve_outcome`: `fn` → `pub(crate) fn` (called by `resolve_ipns_for_replay` in publish.rs, and unit-tested via `super::`)

**cfg gate rule:** Every item carries its current `#[cfg(...)]` gate verbatim. `next_file_publish_sequence` has no cfg gate — publish.rs declares it without one.

**Phasing (per survey deep-dive):**

```
Phase 0: baseline — both feature sets compile + tests green
Phase 1: extract runtime.rs + events.rs (ungated const + Pending* enums + spawn_metadata_refresh)
Phase 2: extract publish.rs (PublishQueueEntry, next_file_publish_sequence, PublishCoordinator, resolve_ipns_for_replay↑, classify_resolve_outcome↑)
Phase 3: extract metadata.rs (encrypt_metadata_to_json, merge_folder_children, spawn_* fns, ReencryptOutcome)
Phase 4: extract fs.rs (CipherBoxFS struct + impl, uuid_from_ino, mount_point) — highest blast radius
Phase 5: extract replay.rs (replay_for_vault + all helpers + publish_file_metadata shim)
Phase 6: clean lib.rs to ~120 LoC + build desktop crate to confirm consumer compiles
```

Gate each phase on: `cargo test -p cipherbox-fuse` AND `cargo build -p cipherbox-fuse --no-default-features --features winfsp`.

#### `crates/fuse/src/write_ops.rs` — 1132 LoC [VERIFIED: wc -l]

**Current structure:**

Entire file is one `#[cfg(feature = "fuse")] pub(crate) mod implementation { ... }` block. Handler functions inside:

| Handler | Approx lines | Target sub-module |
|---------|-------------|-------------------|
| `handle_setattr` | ~100 | `write_ops/file_data.rs` |
| `handle_write` | ~35 | `write_ops/file_data.rs` |
| `handle_create` | ~140 | `write_ops/file_data.rs` |
| `handle_unlink` | ~170 | `write_ops/delete.rs` |
| `handle_rmdir` | ~165 | `write_ops/delete.rs` |
| `handle_mkdir` | ~260 | `write_ops/mkdir.rs` |
| `handle_rename` | ~250 | `write_ops/rename.rs` |

The ~50-line bin-publish tail that `handle_unlink` and `handle_rmdir` share is the dedup candidate. Extract into a private helper in `write_ops/delete.rs`.

**No tests co-located** in write_ops.rs (confirmed: `grep -n "#[cfg(test"` returns no output). Tests are in lib.rs `durability_characterization_tests` module which calls via `crate::write_ops::implementation::handle_mkdir` — these paths stay stable because the `pub(crate) mod implementation` facade is preserved.

**Facade shape after split (write_ops/mod.rs):**

```rust
// write_ops/mod.rs
#[cfg(feature = "fuse")]
pub(crate) mod implementation {
    mod file_data;
    mod delete;
    mod mkdir;
    mod rename;
    pub use file_data::{handle_setattr, handle_write, handle_create};
    pub use delete::{handle_unlink, handle_rmdir};
    pub use mkdir::handle_mkdir;
    pub use rename::handle_rename;
}
```

The caller path `crate::write_ops::implementation::handle_*` remains stable.

#### `packages/sdk-core/src/folder/index.ts` — 602 LoC [VERIFIED: wc -l]

**Current exports (confirmed via grep):**

```
fetchAndDecryptMetadata (async)    → load.ts
loadFolderMetadata (async)         → load.ts
createSubfolder (async)            → registration.ts
updateFolderMetadataAndPublish (async) → registration.ts
renameInFolder                     → metadata-ops.ts
deleteFromFolder                   → metadata-ops.ts
addFilePointerToFolder             → metadata-ops.ts
moveItem                           → metadata-ops.ts
uint8ToBase64 (private helper)     → stays in whichever file uses it first (load.ts or metadata-ops.ts)
addFileToFolder (async)            → registration.ts
addFilesToFolder (async)           → registration.ts
replaceFileInFolder (async)        → registration.ts
```

Plus re-exports from `./tree` and `./merge` (these stay at the top of index.ts after the split — no change).

**Consumer imports (confirmed):** `packages/sdk-core/src/index.ts` imports from `./folder` (the barrel). No file imports `./folder/index.ts` directly. Tests target `../folder` barrel → zero import churn guaranteed.

**index.ts after split (~30 LoC):**

```typescript
export { getDepth, calculateSubtreeDepth, isDescendantOf, type TreeNode } from './tree';
export { mergeChildren } from './merge';
export * from './load';
export * from './metadata-ops';
export * from './registration';
```

`fetchAndDecryptMetadata` must be importable inside `registration.ts` (the `decodeRemote` callback) — import from `./load` directly within the module.

**Existing tests:** `packages/sdk-core/src/folder/__tests__/tree.test.ts` targets `./tree`, not the barrel — unaffected.

#### `apps/api/src/ipns/ipns.service.ts` — 596 LoC [VERIFIED: wc -l]

**Codec helpers to extract (lines ~497–595, ~99 LoC):**

```
parseIpnsRecordBytes   (private async method → standalone export function)
parseCachedRecord      (private async method → standalone export function)
withCachedPublicKey    (private method → standalone export function)
```

The shared return type `{ cid, sequenceNumber, signatureV2?, data?, pubKey? }` should be exported as an interface from `ipns-record.codec.ts`.

**IpnsService after extract:** The three private methods become calls to the imported codec functions. The DI class, constructor, `@Injectable()`, and all write/read orchestration stay intact. `@Injectable()` is on the class, not the extracted functions — no NestJS DI change.

**Existing tests (all Jest):**
- `ipns.service.spec.ts` (1547 LoC) — mocks `parseIpnsRecord` at the `@cipherbox/crypto` level; references `parseCachedRecord` and `parseIpnsRecordBytes` only in comments (lines 858, 899). Tests pass through `IpnsService` public methods, so the extract is fully transparent.
- `__tests__/ipns.security.spec.ts`, `__tests__/ipns.integration.spec.ts` — same: no direct reference to private methods.

No test file imports the private methods directly. Extract is safe.

**Test command:** `pnpm --filter @cipherbox/api test` (Jest, per `package.json`).

#### `apps/web/src/components/file-browser/DetailsDialog.tsx` — 664 LoC [VERIFIED: wc -l]

**Internal component structure (confirmed via grep):**

| Component | Lines (approx) | Target file |
|-----------|---------------|-------------|
| `CopyableValue` (internal) | ~45 | `details/DetailsPrimitives.tsx` |
| `DetailRow` (internal) | ~12 | `details/DetailsPrimitives.tsx` |
| `formatDateWithTime` (internal fn) | ~14 | `details/DetailsPrimitives.tsx` |
| `VersionHistory` | ~120 | `details/VersionHistory.tsx` |
| `FileDetails` | ~90 | `details/FileDetails.tsx` |
| `FolderDetails` | ~95 | `details/FolderDetails.tsx` |
| `DetailsDialog` (exported container) | ~140 | stays in `DetailsDialog.tsx` — re-imports sub-components |

**Critical constraints (confirmed in source):**
- Two `useEffect`s in `DetailsDialog` (lines 540–578 and 581–640) both guard on `open`, `item`, and each other's resolution — they must stay in the container `DetailsDialog.tsx`.
- `void folderKey;` at line 190 is inside `VersionHistory` — it moves with `VersionHistory.tsx`.
- Biome `noCommentText`: any JSX comment workarounds present in the file must be preserved verbatim in the sub-files.

**Tests:** No `DetailsDialog.test.ts` or `DetailsDialog.spec.ts` found. This is an unguarded split — accept as-is per the survey (Tier 1, near-mechanical). The component imports no stores directly; its props are stable.

**apps/web vitest include:** `src/**/*.test.ts` only — any new test files MUST use `.test.ts` extension.

#### `apps/desktop/src-tauri/src/commands/auth.rs` — 521 LoC [VERIFIED: wc -l]

**Functions (confirmed via grep):**

| Function | Visibility | Lines (approx) | Action |
|----------|-----------|---------------|--------|
| `handle_auth_complete` | `pub async` | ~70 | stays in auth.rs |
| `load_vault_settings` | `async fn` (private) | ~50 | **move to commands/vault.rs** |
| `complete_auth_setup` | `pub(crate) async` | ~200 | refactor: extract mount/sync/device/teardown tail into private helper; keep signature |
| `handle_session_restore` | `pub async` | ~60 | stays in auth.rs |
| `try_silent_refresh` | `pub async` | ~75 | stays in auth.rs |
| `logout` | `pub async` | ~30 | stays in auth.rs |

**`commands/vault.rs` already exists** (221 LoC). `load_vault_settings` moves there — the function has no `#[tauri::command]` attribute and takes no `AppState` (takes `&ApiClient` + `&[u8; 32]`), so it's a clean cut-paste. Update the call site in auth.rs to `super::vault::load_vault_settings(...)`.

**`complete_auth_setup` tail (lines ~207–346):** The mount block (`#[cfg(any(feature = "fuse", feature = "winfsp"))]`, ~100 LoC), the device registry spawn (~25 LoC), and the window-teardown block (~10 LoC) can be factored into a private `async fn post_auth_finalize(app, state, ...)` helper. `complete_auth_setup`'s `pub(crate)` signature stays. `debug.rs` calls `super::auth::complete_auth_setup` — this import path stays stable.

**Tests:** No Rust tests co-located in auth.rs. Manual/integration verification required (desktop build + dev-key login).

---

### Tier 2 Targets

#### `crates/fuse/src/platform/windows/operations.rs` (604 LoC) + `crates/fuse/src/operations.rs` (292 LoC) [VERIFIED]

**Duplicated functions (confirmed byte-comparison):**

The three helpers are structurally identical but have surface-level differences:

| Function | operations.rs (macOS) | windows/operations.rs (Windows) | Diff |
|----------|-----------------------|--------------------------------|------|
| `fetch_and_decrypt_file_content` | calls `cipherbox_crypto::unwrap_key`, `cipherbox_crypto::decrypt_aes_ctr`, `cipherbox_crypto::decrypt_aes_gcm` | calls `cipherbox_crypto::ecies::unwrap_key`, `cipherbox_crypto::aes_ctr::decrypt_aes_ctr`, `cipherbox_crypto::aes::decrypt_aes_gcm` | module path depth differs |
| `fetch_and_decrypt_content_async` | same pattern as above | same pattern as above | module path depth |
| `publish_file_metadata` | ~80 LoC, same logic | ~100 LoC, same logic | minor structural wrapping |

The shared `content_ops.rs` normalizes to the fully-qualified submodule paths (which work on both sides). Both callers re-export:

```rust
// crates/fuse/src/operations.rs (add after extraction)
pub use crate::content_ops::{fetch_and_decrypt_file_content, fetch_and_decrypt_content_async, publish_file_metadata};

// crates/fuse/src/platform/windows/operations.rs (add after extraction)
pub use crate::content_ops::{fetch_and_decrypt_file_content, fetch_and_decrypt_content_async, publish_file_metadata};
```

**cfg gate for content_ops.rs:** `#[cfg(any(feature = "fuse", feature = "winfsp"))]` on the entire module (same as both source files). Add `pub mod content_ops;` to lib.rs (cfg-gated the same way).

**`block_with_timeout` in operations.rs:** operations.rs has its own private copy (`NETWORK_TIMEOUT = 3s`); lib.rs runtime.rs has a different value (`10s`). The content_ops.rs should call `crate::block_with_timeout` (lib.rs re-export of runtime.rs) — both current files already call the `crate::` re-export or their own local copy. Resolve: content_ops.rs imports `crate::block_with_timeout` for the sync wrapper.

#### `apps/desktop/src-tauri/src/fuse/windows/mod.rs` (550 LoC) + `apps/desktop/src-tauri/src/fuse/mod.rs` (420 LoC) [VERIFIED]

**IMPORTANT:** The survey says 550 LoC for windows/mod.rs (verified) and 420 LoC for fuse/mod.rs (VERIFIED: actual is 420, not the 550 in the objective — the objective listed it as 550). Survey says ~255 LoC duplicated.

**Prepopulate block comparison:**

The blocks are **structurally parallel but not byte-identical**:
- fuse/mod.rs uses `cipherbox_fuse::inode::ROOT_INO`, `cipherbox_core::decrypt_metadata_from_ipfs_public` (direct re-export path)
- fuse/windows/mod.rs uses `inode::ROOT_INO`, `cipherbox_core::decrypt::decrypt_metadata_from_ipfs_public` (submodule path)
- fuse/mod.rs uses `if-let` chains; windows/mod.rs uses nested `match`
- Error log messages differ slightly

The shared `fuse/prepopulate.rs` function signature accepts the parameters from both paths:

```rust
// apps/desktop/src-tauri/src/fuse/prepopulate.rs
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub async fn prepopulate_filesystem(
    api: &std::sync::Arc<cipherbox_api_client::ApiClient>,
    inodes: &mut cipherbox_fuse::inode::InodeTable,
    metadata_cache: &mut cipherbox_fuse::cache::MetadataCache,
    root_ipns_name: &str,
    root_folder_key: &[u8],
    private_key: &[u8],
    public_key: &[u8],
) -> Vec<(String, u64)>  // returns initial_sequences for coordinator seeding
```

Both mount functions call `prepopulate_filesystem(...)` and get back `initial_sequences`. The caller-specific coordinator seeding that follows the block stays in each respective mount function.

**Note on macOS-only testing:** The deferred `windows/host.rs` split is correctly deferred. The prepopulate extraction can be verified on macOS because `prepopulate.rs` compiles under `any(fuse,winfsp)` and the macOS path calls it directly.

#### `crates/fuse/src/platform/windows/read_ops.rs` — 499 LoC [VERIFIED]

**Duplicated blocks (confirmed at lines 211–250 and 397–432):**

Both `handle_open` (line 95) and `handle_read` (line 271) contain the same content-prefetch spawn block. Extracted signature:

```rust
// crates/fuse/src/platform/windows/content_fetch.rs
#[cfg(feature = "winfsp")]
pub(crate) fn spawn_content_prefetch(
    fs: &mut CipherBoxFS,
    cid: String,
    encrypted_file_key: String,
    iv: String,
    encryption_mode: String,
)
```

The only difference between the two duplicates is the log message string ("Prefetch failed" vs "Read prefetch failed"). The extracted function can use a `label: &str` parameter or unify the message.

**This is NOT a structural split** — the file stays as `platform/windows/read_ops.rs`; `content_fetch.rs` is a sibling helper in the same platform/windows/ directory.

#### `crates/fuse/src/read_ops.rs` — 1012 LoC [VERIFIED]

**Work items (per survey — confirmed against source):**

1. `PollResult` enum (line 24) + `poll_filepointer_resolution` fn (line 32): move to a shared module (e.g. `crates/fuse/src/poll.rs` or inline in `fs.rs` — both read_ops.rs and windows/read_ops.rs need this). Currently `poll_filepointer_resolution` is a `fn` (private), not `pub`. After move: `pub(crate)` so windows can use it too.

2. Three prefetch-spawn blocks (confirmed at: line 434 in handle_open path, line 612 in handle_read path, line 711 in handle_read `else` path — the third is in the lookup-time prefetch). Extract into `fn spawn_content_prefetch_fuse(fs, cid, efk, iv, enc_mode)` within read_ops.rs or a shared module.

3. **`handle_release` (line 773) MUST NOT be relocated** — CR-04/D-04 journal-fsync-before-ack invariant. The durability characterization tests in lib.rs exercise it. It stays in read_ops.rs.

**Structure stays:** The file does NOT convert to a directory module. Only the two dedup extractions above.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| cfg-gated re-exports | Conditional pub use blocks | Standard `pub use module::Item` under `#[cfg(...)]` | Rust re-exports with cfg attributes work identically to direct declarations |
| TypeScript barrel re-export | Named re-export objects | `export * from './file'` or named `export { fn } from './file'` | Zero runtime overhead; tree-shakeable |
| Multiple inherent impls | Trait objects or wrappers | `impl CipherBoxFS { ... }` in fs.rs (separate file) | Rust allows multiple inherent impl blocks on the same type across files |

## Test Relocation Strategy

### Rust (crates/fuse)

| Test | Current location | Move target | Stable import path after move |
|------|-----------------|-------------|-------------------------------|
| `next_file_publish_sequence_*` (3 tests) | lib.rs `mod tests` | `publish.rs` `#[cfg(test)] mod tests` | `super::next_file_publish_sequence` |
| `classify_resolve_outcome_*` (1 test) | lib.rs `mod tests` | `publish.rs` `#[cfg(test)] mod tests` | `super::classify_resolve_outcome` |
| `merge_folder_children_*` (T-45-08 + variants) | lib.rs `mod tests` | `metadata.rs` `#[cfg(test)] mod tests` | `super::merge_folder_children` + imports from `cipherbox_core` |
| `replay_for_vault_*` tests (T-45-06, legacy_empty_name_parks, strict_resolve_bypasses_cache, REQ-5) | lib.rs `mod tests` | `replay.rs` `#[cfg(test)] mod tests` | `super::replay_for_vault`, `super::PublishCoordinator` |
| `resolve_folder_key_cache_*` (T-45-07) | lib.rs `mod tests` | `replay.rs` `#[cfg(test)] mod tests` | `super::resolve_folder_key_cached` |
| `mod handler_harness_tests` | lib.rs | **STAY in lib.rs** | Uses `crate::read_ops::implementation::*` + `crate::test_support` — cross-module span |
| `mod durability_characterization_tests` | lib.rs | **STAY in lib.rs** | Uses `crate::write_ops::implementation::handle_mkdir` + `handle_release` — cross-module span |

### TypeScript/web

| File | Test strategy |
|------|--------------|
| `sdk-core/folder/index.ts` | Tests target `../folder` barrel — no relocation, no change |
| `apps/api/ipns/ipns.service.ts` | Tests use `IpnsService` public API through Jest mocks — no relocation |
| `apps/web/DetailsDialog.tsx` | No existing tests — nothing to relocate |
| `apps/desktop/commands/auth.rs` | No co-located tests — nothing to relocate |

## Sequencing and Batching Guidance

### Plan Group A: lib.rs 6-module decomposition (DO FIRST)

One PR (`refactor/fuse-lib-rs-decomposition`). 6 sequential phases (0–6 per survey phasing). Gate each phase on both feature sets.

**Rationale:** Largest file, most test coverage, cleanest win. Establishes the re-export pattern for the rest of the Rust work.

### Plan Group B: Remaining Tier-1 Rust — write_ops split

One PR (`refactor/fuse-write-ops-split`). Convert write_ops.rs to write_ops/ directory module; extract the ~50-line bin-publish dedup helper.

**Dependency:** Can proceed independently of Group A once A is merged (write_ops.rs is a separate fuse-feature-only module).

### Plan Group C: Tier-1 TypeScript/web

One PR or two smaller ones (`refactor/ts-tier1-splits`). The four items are independent:

1. `sdk-core/folder/index.ts` barrel split
2. `apps/api/ipns/ipns.service.ts` codec extraction
3. `apps/web/DetailsDialog.tsx` component split
4. `apps/desktop/commands/auth.rs` refactor

**No ordering dependency between them.** They touch entirely different packages.

### Plan Group D: Tier-2 cross-platform dedup

One PR (`refactor/fuse-cross-platform-dedup`). Four items:

1. `crates/fuse` content_ops.rs extraction (operations.rs + windows/operations.rs)
2. `apps/desktop/src-tauri/src/fuse/prepopulate.rs` extraction (fuse/mod.rs + windows/mod.rs)
3. `crates/fuse/src/platform/windows/content_fetch.rs` helper (windows/read_ops.rs)
4. `crates/fuse/src/read_ops.rs` PollResult move + prefetch dedup

**Dependency:** Items 1 and 3 are in crates/fuse — can be combined. Items 2 is in the desktop crate — separate from the fuse crate but same PR.

**Recommended overall order:** A → (B + C in parallel) → D.

## Common Pitfalls

### Pitfall 1: Forgetting cfg gates on moved items

**What goes wrong:** Item moves to a new file without its `#[cfg(any(feature = "fuse", feature = "winfsp"))]` gate — compiles under one feature but fails with missing symbols under the other.

**How to avoid:** Copy the `#[cfg(...)]` attribute verbatim from the source location. Check each item in the grep output above.

**Warning signs:** `cargo build -p cipherbox-fuse --no-default-features --features winfsp` fails.

### Pitfall 2: Widening visibility without noticing

**What goes wrong:** A private fn that only `resolve_ipns_for_replay` calls gets bumped to `pub` instead of `pub(crate)` — leaks implementation detail to crate consumers.

**How to avoid:** Only bump `resolve_ipns_for_replay` and `classify_resolve_outcome` to `pub(crate)`. Everything else stays at its current visibility.

### Pitfall 3: Breaking the handler_harness_tests and durability_characterization_tests

**What goes wrong:** Moving test helpers out of lib.rs breaks `crate::read_ops::implementation::handle_getattr` paths used in the handler harness.

**How to avoid:** These two test modules stay in lib.rs — they use `crate::` paths that remain valid via lib.rs re-exports.

### Pitfall 4: Splitting the two cross-guarded useEffects in DetailsDialog

**What goes wrong:** One `useEffect` handles folders (resolves IPNS to get metadataCid), the other handles files (fetches fileMeta and sets metadataCid). They share `setMetadataCid`/`setMetadataLoading` state and have guards that depend on each other's condition. Splitting them into different components breaks the cross-guarding.

**How to avoid:** Both `useEffect` hooks stay in the `DetailsDialog` container component. Only the sub-components (VersionHistory, FileDetails, FolderDetails, DetailsPrimitives) are extracted.

### Pitfall 5: content_ops.rs calling the wrong block_with_timeout

**What goes wrong:** operations.rs has its own private `block_with_timeout` with `NETWORK_TIMEOUT = 3s`; lib.rs/runtime.rs has one with `10s`. If content_ops.rs calls the wrong one, behavior changes.

**How to avoid:** content_ops.rs calls `crate::block_with_timeout` (the lib.rs/runtime.rs re-export, 10s). The private copy in operations.rs stays for operations.rs's own use — it's separate and intentional.

### Pitfall 6: debug.rs import breaks after load_vault_settings moves

**What goes wrong:** debug.rs imports `use super::auth::complete_auth_setup` (confirmed in code). If auth.rs's own call to `load_vault_settings` is refactored to `super::vault::load_vault_settings`, the import in auth.rs changes but debug.rs's import of `complete_auth_setup` stays stable.

**How to avoid:** Only the internal call site in auth.rs changes. `complete_auth_setup`'s `pub(crate)` declaration stays in auth.rs. debug.rs is unaffected.

### Pitfall 7: `void folderKey` lint suppression in VersionHistory

**What goes wrong:** Moving `VersionHistory` to a separate file without preserving `void folderKey;` (line 190) re-introduces the unused-variable lint/warning.

**How to avoid:** Move line 190 verbatim into `details/VersionHistory.tsx`.

## Code Examples

### Re-export pattern for lib.rs after split [ASSUMED: standard Rust pattern]

```rust
// crates/fuse/src/lib.rs (~120 LoC after split)
pub mod cache;
pub mod constants;
pub mod error;
pub mod file_handle;
pub mod helpers;
pub mod inode;
pub mod journal_helpers;

#[cfg(feature = "fuse")]
pub mod dir_ops;
#[cfg(feature = "fuse")]
pub mod operations;
#[cfg(feature = "fuse")]
pub mod read_ops;
#[cfg(feature = "fuse")]
pub mod write_ops;

pub mod platform;

// New modules from this refactor
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub mod runtime;
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub mod events;
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub mod publish;
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub mod metadata;
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub mod fs;
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub mod replay;
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub mod content_ops; // Tier 2

#[cfg(all(test, feature = "fuse"))]
mod test_support;

// Existing re-exports (unchanged)
pub use cache::{ContentCache, MetadataCache};
pub use error::FuseError;
pub use file_handle::OpenFileHandle;
pub use inode::{InodeData, InodeTable};

// New re-exports (keeping all cipherbox_fuse::<X> paths stable)
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub use runtime::block_with_timeout;
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub use events::{
    PendingRefresh, PendingContent, PendingFilePointer,
    FsEvent, UploadComplete, spawn_metadata_refresh,
};
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub use publish::{PublishQueueEntry, PublishCoordinator, next_file_publish_sequence};
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub use metadata::{
    encrypt_metadata_to_json, merge_folder_children,
    spawn_metadata_publish, spawn_bin_entry_publish, spawn_file_meta_reencrypt,
};
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub use fs::{CipherBoxFS, mount_point};
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub use replay::replay_for_vault;
```

### write_ops directory module facade [ASSUMED: standard Rust pattern]

```rust
// crates/fuse/src/write_ops/mod.rs
#[cfg(feature = "fuse")]
pub(crate) mod implementation {
    mod file_data;
    mod delete;
    mod mkdir;
    mod rename;
    pub use file_data::{handle_setattr, handle_write, handle_create};
    pub use delete::{handle_unlink, handle_rmdir};
    pub use mkdir::handle_mkdir;
    pub use rename::handle_rename;
}
```

### TypeScript barrel index.ts after split [ASSUMED: standard TS barrel pattern]

```typescript
// packages/sdk-core/src/folder/index.ts (~30 LoC after split)
export { getDepth, calculateSubtreeDepth, isDescendantOf, type TreeNode } from './tree';
export { mergeChildren } from './merge';
export * from './load';
export * from './metadata-ops';
export * from './registration';
```

## Validation Architecture

> `workflow.nyquist_validation` is `true` — section included.

### Test Framework

| Property | Value |
|----------|-------|
| Rust framework | `cargo test` (built-in) |
| API framework | Jest (`pnpm --filter @cipherbox/api test`) |
| sdk-core / sdk framework | Vitest (`pnpm --filter @cipherbox/sdk-core test`, `pnpm --filter @cipherbox/sdk test`) |
| apps/web framework | Vitest (`pnpm --filter @cipherbox/web test`) |
| Quick Rust run | `cargo test -p cipherbox-fuse` |
| Rust winfsp gate | `cargo build -p cipherbox-fuse --no-default-features --features winfsp` |
| Consumer compile check | `cargo build -p cipherbox-desktop` (default features) |

**Note:** `apps/web vitest include` is `src/**/*.test.ts` only — any new test files MUST use `.test.ts`, not `.spec.ts`.

### Phase Requirements → Test Map

| Req ID  | Behavior | Test Type | Automated Command | File Exists? |
|---------|----------|-----------|-------------------|--------------|
| HARD-06 | lib.rs split: all 6 modules compile + tests pass | cargo test | `cargo test -p cipherbox-fuse` | Yes (existing tests in lib.rs) |
| HARD-06 | lib.rs split: winfsp feature compiles | cargo build | `cargo build -p cipherbox-fuse --no-default-features --features winfsp` | N/A (build) |
| HARD-06 | write_ops split: handler paths stable | cargo test | `cargo test -p cipherbox-fuse` | Yes (durability tests in lib.rs) |
| HARD-06 | sdk-core folder barrel: consumers compile | vitest | `pnpm --filter @cipherbox/sdk-core test` | Yes (tree.test.ts + sdk integration) |
| HARD-06 | sdk-core folder barrel: sdk package compiles | vitest | `pnpm --filter @cipherbox/sdk test` | Yes (existing sdk __tests__/) |
| HARD-06 | ipns.service codec extract: API tests pass | jest | `pnpm --filter @cipherbox/api test` | Yes (ipns.service.spec.ts 1547 LoC) |
| HARD-06 | DetailsDialog split: web builds | vitest | `pnpm --filter @cipherbox/web test` | Yes (existing web tests) |
| HARD-06 | commands/auth.rs refactor: desktop builds | cargo build | `cargo build -p cipherbox-desktop` | N/A (build) |
| HARD-06 | Tier-2 content_ops.rs: both feature sets | cargo test + build | `cargo test -p cipherbox-fuse` + winfsp build | Yes (existing tests) |
| HARD-06 | Tier-2 prepopulate.rs: desktop builds | cargo build | `cargo build -p cipherbox-desktop` | N/A (build) |
| HARD-06 | Public surface byte-identical | tsc / compile check | `pnpm --filter @cipherbox/sdk-core build` (tsc) | Yes |

### Sampling Rate

- **Per task commit (Rust):** `cargo test -p cipherbox-fuse` (runs in ~10–30s with no network)
- **Per task commit (TS):** relevant package's `pnpm test` command
- **Per wave merge:** All of the above + `cargo build -p cipherbox-fuse --no-default-features --features winfsp` + `cargo build -p cipherbox-desktop`
- **Phase gate:** All suite green before `/gsd-verify-work`

### Wave 0 Gaps

None — this phase creates no new test files. All validation is the existing test suites run against refactored code. The acceptance condition is existing tests still pass.

## Security Domain

This is a pure internal refactor with no logic changes, no new inputs, no new cryptographic operations, and no changes to the server API surface.

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | No auth logic changes |
| V3 Session Management | No | No session logic changes |
| V4 Access Control | No | No access control changes |
| V5 Input Validation | No | No new inputs |
| V6 Cryptography | No | No crypto code changes — crypto functions are moved verbatim, not modified |

The only security-adjacent note: `load_vault_settings` moves to `vault.rs` — it performs ECIES unwrap of vault settings. The move is cut-paste with no logic change; the security contract (`NOT AES-GCM`, `ecies::unwrap_key`, graceful fallback to defaults) is preserved verbatim. No security review required beyond confirming the function body is identical before and after.

## Project Constraints (from CLAUDE.md)

| Constraint | Applies to This Phase |
|------------|----------------------|
| TypeScript: prefer string literals over enums | Yes — no new enums introduced; if codec types need string-union shapes, use `'read' \| 'write'` etc. |
| No `pnpm api:generate` | Yes — explicitly required; this phase has no API DTO changes |
| Branch protection: never push to main | Yes — all work on `refactor/*` feature branches via PRs |
| Conventional commits: `refactor(scope): description` | Yes |
| No parenthesized text in commit subject | Yes — `refactor(fuse): split lib.rs into 6 modules` not `refactor(fuse): split lib.rs (6 modules)` |
| apps/web vitest include is `*.test.ts` only | Yes — no new spec files |
| CipherBoxFS fields must stay `pub` | Yes — desktop constructs via struct literal; confirmed in analysis above |
| Do not split `apps/web/src/services/share.service.ts` | Yes — leave-as-is confirmed |
| Do not split `crates/fuse/src/journal_helpers.rs` | Yes — leave-as-is confirmed |

## Environment Availability

Step 2.6: This phase is code-only changes (no new runtimes, services, or CLI tools required beyond the existing Rust/Node.js toolchain). No external dependency audit needed.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Multiple Rust inherent impl blocks for `CipherBoxFS` across files is legal | lib.rs deep-dive | Rust actually requires single inherent impl in some edge cases — but journal_helpers.rs already does this, so it's confirmed working in practice [LOW RISK] |
| A2 | The `block_with_timeout` timeout difference (operations.rs: 3s vs lib.rs: 10s) is intentional | Tier 2 content_ops | If wrong, the shared content_ops.rs should preserve the 3s value for the sync fetch path — executor must verify by reading both call sites |
| A3 | The prepopulate blocks in fuse/mod.rs and windows/mod.rs are "conceptually" equivalent but not byte-identical | Tier 2 prepopulate | Confirmed in static analysis: different Rust paths (`cipherbox_core::decrypt::` vs `cipherbox_core::`), different match/if-let style. The shared function must normalize. |

**If this table is populated:** Assumptions A1–A3 are low-risk and have mitigations stated inline. No user confirmation required before execution.

## Open Questions

1. **`block_with_timeout` timeout for content_ops.rs**
   - What we know: operations.rs has private NETWORK_TIMEOUT = 3s; lib.rs/runtime.rs has 10s. Both exist for different reasons (sync filesystem callback vs general async).
   - What's unclear: Which timeout the shared `fetch_and_decrypt_file_content` in content_ops.rs should use.
   - Recommendation: Use `crate::block_with_timeout` (10s from runtime.rs) to match the lib.rs-level usage; if the fuse-feature `operations.rs` sync path needs 3s, leave `fetch_and_decrypt_file_content` in `operations.rs` rather than pulling to content_ops.rs (adjust scope accordingly). Executor should verify current behavior before deciding.

2. **`next_file_publish_sequence` has no `#[cfg(...)]` gate**
   - What we know: The function is ungated; its `#[cfg(test)]` test mod uses `super::` directly.
   - What's unclear: Whether publish.rs should declare it ungated too, or gate it `any(fuse,winfsp)`.
   - Recommendation: Keep ungated (it's a pure utility fn with no platform dependency). The test in lib.rs's `mod tests` (ungated) can move to publish.rs's own `mod tests` (ungated). No issue.

## Sources

### Primary (HIGH confidence)

- Static analysis of all 12 source files via `wc -l`, `grep`, and `Read` tool — all LoC counts verified against current worktree HEAD
- `.planning/todos/pending/2026-06-19-large-file-refactor-candidates.md` — survey with per-file implementation specs; validated against actual code
- `.planning/phases/55-large-source-file-refactor/55-CONTEXT.md` — locked decisions D-01..D-07

### Secondary (MEDIUM confidence)

- Standard Rust module system patterns (multiple inherent impl, re-exports, cfg-gated modules) [ASSUMED — standard language features, no external source needed]
- TypeScript barrel/re-export patterns [ASSUMED — standard language features]

## Metadata

**Confidence breakdown:**

- Per-file current state: HIGH — verified from actual source
- lib.rs module assignments: HIGH — cross-checked survey against grep of all top-level items
- Duplication site analysis: HIGH — read both sides byte-by-byte for operations.rs; confirmed structural parallels for prepopulate blocks
- Sequencing/batching: HIGH — follows survey + locked decisions verbatim
- Pitfalls: HIGH — derived from actual code patterns found in analysis

**Research date:** 2026-06-19
**Valid until:** This phase's execution window — code is static between now and execution
