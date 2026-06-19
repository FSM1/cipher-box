# Phase 55: Large Source-File Refactor - Pattern Map

**Mapped:** 2026-06-19
**Files analyzed:** 17 new/modified files (Tier 1 + Tier 2)
**Analogs found:** 17 / 17

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `crates/fuse/src/runtime.rs` | Rust submodule, cfg-gated | transform | `crates/fuse/src/journal_helpers.rs` (cfg gate shape) | role-match |
| `crates/fuse/src/events.rs` | Rust submodule, cfg-gated | event-driven | `crates/fuse/src/journal_helpers.rs` | role-match |
| `crates/fuse/src/publish.rs` | Rust submodule, cfg-gated | request-response | `crates/fuse/src/journal_helpers.rs` | role-match |
| `crates/fuse/src/metadata.rs` | Rust submodule, cfg-gated | transform | `crates/fuse/src/journal_helpers.rs` | role-match |
| `crates/fuse/src/fs.rs` | Rust submodule with inherent impl on cross-file struct | CRUD | `crates/fuse/src/journal_helpers.rs` (cross-file impl) | exact |
| `crates/fuse/src/replay.rs` | Rust submodule, cfg-gated | request-response | `crates/fuse/src/journal_helpers.rs` | role-match |
| `crates/fuse/src/lib.rs` (modified) | Rust crate root with cfg-gated mod decls + re-exports | — | `crates/fuse/src/lib.rs` (current shape) | self |
| `crates/fuse/src/write_ops/mod.rs` | Rust directory-module facade | CRUD | `crates/fuse/src/operations.rs` (implementation facade shape) | exact |
| `crates/fuse/src/write_ops/file_data.rs` | Rust private submodule inside facade | CRUD | `crates/fuse/src/write_ops.rs` (current handler bodies) | exact |
| `crates/fuse/src/write_ops/delete.rs` | Rust private submodule inside facade | CRUD | `crates/fuse/src/write_ops.rs` | exact |
| `crates/fuse/src/write_ops/mkdir.rs` | Rust private submodule inside facade | CRUD | `crates/fuse/src/write_ops.rs` | exact |
| `crates/fuse/src/write_ops/rename.rs` | Rust private submodule inside facade | CRUD | `crates/fuse/src/write_ops.rs` | exact |
| `crates/fuse/src/content_ops.rs` | Rust shared cfg-gated helper module (Tier 2 dedup) | file-I/O | `crates/fuse/src/journal_helpers.rs` (cfg gate + cross-feature pattern) | role-match |
| `crates/fuse/src/platform/windows/content_fetch.rs` | Rust winfsp-only private helper | file-I/O | `crates/fuse/src/platform/windows/read_ops.rs` (sibling) | role-match |
| `apps/desktop/src-tauri/src/fuse/prepopulate.rs` | Rust cfg-gated shared helper in desktop crate | batch | `apps/desktop/src-tauri/src/fuse/mod.rs` (cfg gate + use pattern) | role-match |
| `packages/sdk-core/src/folder/load.ts` | TS barrel-sibling module | request-response | `packages/sdk-core/src/folder/merge.ts` + `tree.ts` | exact |
| `packages/sdk-core/src/folder/metadata-ops.ts` | TS barrel-sibling module | transform | `packages/sdk-core/src/folder/merge.ts` | exact |
| `packages/sdk-core/src/folder/registration.ts` | TS barrel-sibling module | request-response | `packages/sdk-core/src/folder/merge.ts` | exact |
| `packages/sdk-core/src/folder/index.ts` (modified) | TS barrel re-export root | — | `apps/web/src/components/file-browser/index.ts` | exact |
| `apps/api/src/ipns/ipns-record.codec.ts` | TS pure-helper extracted from NestJS service | transform | `apps/api/src/ipns/ipns.service.ts` (codec section, lines 497–595) | exact |
| `apps/web/src/components/file-browser/details/DetailsPrimitives.tsx` | React extracted sub-component | transform | `apps/web/src/components/file-browser/DetailsDialog.tsx` (internal components) | exact |
| `apps/web/src/components/file-browser/details/VersionHistory.tsx` | React extracted sub-component | request-response | `apps/web/src/components/file-browser/DetailsDialog.tsx` | exact |
| `apps/web/src/components/file-browser/details/FileDetails.tsx` | React extracted sub-component | request-response | `apps/web/src/components/file-browser/DetailsDialog.tsx` | exact |
| `apps/web/src/components/file-browser/details/FolderDetails.tsx` | React extracted sub-component | request-response | `apps/web/src/components/file-browser/DetailsDialog.tsx` | exact |
| `apps/desktop/src-tauri/src/commands/vault.rs` (modified) | Rust Tauri command module receiving moved fn | CRUD | `apps/desktop/src-tauri/src/commands/vault.rs` (current shape) | self |

## Pattern Assignments

### Group A: `crates/fuse/src/{runtime,events,publish,metadata,fs,replay}.rs`

**Analog:** `crates/fuse/src/journal_helpers.rs`

These six files are the split-out siblings carved from `lib.rs`. `journal_helpers.rs` is the only existing example of a non-root module that:
- Uses `#[cfg(any(feature = "fuse", feature = "winfsp"))]` per item
- Adds a second `impl crate::CipherBoxFS { ... }` block on the shared struct (cross-file inherent impl)
- Lives at the same level as the other `crates/fuse/src/*.rs` modules

**cfg gate pattern** (`crates/fuse/src/journal_helpers.rs` lines 22, 32, 110):
```rust
#[cfg(any(feature = "fuse", feature = "winfsp"))]
use crate::inode::{InodeKind, ROOT_INO};

#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub struct UploadJournalResult { ... }

#[cfg(any(feature = "fuse", feature = "winfsp"))]
impl crate::CipherBoxFS {
    pub async fn build_upload_journal_entry(...) { ... }
}
```

**Convention to replicate in each new module:**
- Every item gets its own `#[cfg(...)]` attribute verbatim from its current location in `lib.rs`
- `fs.rs` adds `impl crate::CipherBoxFS { ... }` (second inherent impl block — legal because `journal_helpers.rs` already does it)
- `publish.rs` bumps `resolve_ipns_for_replay` and `classify_resolve_outcome` to `pub(crate)` — all other items keep current visibility
- `next_file_publish_sequence` in `publish.rs` has NO cfg gate (it is ungated in `lib.rs` today — copy without a gate)

**Module declaration and re-export shape in `lib.rs` after split** (lines 7–36 as template, plus new additions):
```rust
// New module decls to add to lib.rs (cfg-gated same as items inside):
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

// Re-exports to keep cipherbox_fuse::<X> paths stable:
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

**Existing re-exports that stay unchanged** (`lib.rs` lines 33–36):
```rust
pub use cache::{ContentCache, MetadataCache};
pub use error::FuseError;
pub use file_handle::OpenFileHandle;
pub use inode::{InodeData, InodeTable};
```

---

### Group B: `crates/fuse/src/write_ops/{mod.rs,file_data.rs,delete.rs,mkdir.rs,rename.rs}`

**Analog:** `crates/fuse/src/write_ops.rs` (current, lines 1–6) + `crates/fuse/src/operations.rs` (impl facade shape)

The `write_ops.rs` file (and `platform/windows/operations.rs`) both demonstrate the `pub(crate) mod implementation { ... }` facade that the directory module must preserve exactly.

**Current facade header** (`crates/fuse/src/write_ops.rs` lines 1–6):
```rust
//! Write operations for macOS FUSE filesystem.
//!
//! Contains handler logic for: write, create, setattr, rename, unlink, rmdir, mkdir.

#[cfg(feature = "fuse")]
pub(crate) mod implementation {
```

**`write_ops/mod.rs` shape after conversion to directory module:**
```rust
//! Write operations for macOS FUSE filesystem.
//!
//! Contains handler logic for: write, create, setattr, rename, unlink, rmdir, mkdir.

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

**Each submodule (`file_data.rs`, `delete.rs`, `mkdir.rs`, `rename.rs`) structure:**
- No `#[cfg(...)]` gate on the file itself — the cfg gate is on the `implementation` block in `mod.rs` that wraps all sub-`mod` declarations
- The handler functions inside are plain `pub fn` (visible within the `implementation` block)
- Copy the `use` imports from the current top of `write_ops.rs` into whichever submodule needs them

**Caller path stays stable** — `crate::write_ops::implementation::handle_mkdir` continues to resolve because `mod.rs` is the new `write_ops` module root.

**Bin-publish dedup:** Extract the shared ~50-line tail from `handle_unlink` and `handle_rmdir` into a private `fn publish_bin_entry_on_delete(...)` inside `delete.rs`. Both handlers call it.

---

### Group C: `packages/sdk-core/src/folder/{load.ts,metadata-ops.ts,registration.ts}`

**Analog:** `packages/sdk-core/src/folder/merge.ts` and `packages/sdk-core/src/folder/tree.ts`

These existing siblings demonstrate the pattern: a plain TS module in the `folder/` directory that `export`s named functions, consumed by `index.ts` re-exporting them.

**`merge.ts` export shape** (line 21):
```typescript
export function mergeChildren(
```

**`tree.ts` export shape** (lines 12, 24, 44, 73):
```typescript
export type TreeNode = { ... };
export function getDepth(...): number { ... }
export function calculateSubtreeDepth(...): number { ... }
export function isDescendantOf(...): boolean { ... }
```

**Convention for `load.ts`, `metadata-ops.ts`, `registration.ts`:**
- Named `export function` / `export async function` (no default exports)
- Import from `@cipherbox/crypto`, `@cipherbox/core`, `../types`, `../ipfs` — same pattern as current `index.ts` lines 9–31
- `registration.ts` imports `fetchAndDecryptMetadata` from `./load` (not re-imported through the barrel)

**`index.ts` after split** (~30 LoC — analog: `apps/web/src/components/file-browser/index.ts`):
```typescript
export { getDepth, calculateSubtreeDepth, isDescendantOf, type TreeNode } from './tree';
export { mergeChildren } from './merge';
export * from './load';
export * from './metadata-ops';
export * from './registration';
```

**Barrel re-export shape** (`apps/web/src/components/file-browser/index.ts` lines 1–19):
```typescript
/**
 * File browser components barrel export.
 */

export { FileBrowser } from './FileBrowser';
export { FileList } from './FileList';
// ... named re-exports
```

For the folder barrel, `export *` is preferred (all exports are functions, no name collisions) so the barrel stays minimal and zero-churn.

---

### Group C (continued): `apps/api/src/ipns/ipns-record.codec.ts`

**Analog:** `apps/api/src/ipns/ipns.service.ts` lines 497–595 (the three private methods being extracted)

This is a pure-helper extraction from a NestJS service: three `private` methods become standalone exported functions in a sibling file. There is no existing `*.codec.ts` in the codebase — this is the first. The pattern to replicate is the return-type interface extraction + standalone function shape.

**Current private method shape** (`apps/api/src/ipns/ipns.service.ts` lines ~497–515):
```typescript
private async parseIpnsRecordBytes(recordBytes: Uint8Array): Promise<{
  cid: string;
  sequenceNumber: string;
  signatureV2?: string;
  data?: string;
  pubKey?: string;
}> {
  // ...
}

private async parseCachedRecord(cached: FolderIpns | null): Promise<{ ... } | null> {
  // ...
}

private withCachedPublicKey(
  result: { cid: string; sequenceNumber: string; ... },
  publicKey?: Buffer
): { ... } { ... }
```

**`ipns-record.codec.ts` shape after extraction:**
```typescript
// apps/api/src/ipns/ipns-record.codec.ts
import { parseIpnsRecord } from '@cipherbox/crypto';
import type { FolderIpns } from './entities/folder-ipns.entity';
import { HttpException, HttpStatus, Logger } from '@nestjs/common';

export interface IpnsRecordFields {
  cid: string;
  sequenceNumber: string;
  signatureV2?: string;
  data?: string;
  pubKey?: string;
}

export async function parseIpnsRecordBytes(
  recordBytes: Uint8Array,
  logger: Logger,
): Promise<IpnsRecordFields> { ... }

export async function parseCachedRecord(
  cached: FolderIpns | null,
  logger: Logger,
): Promise<IpnsRecordFields | null> { ... }

export function withCachedPublicKey(
  result: IpnsRecordFields,
  publicKey?: Buffer,
): IpnsRecordFields { ... }
```

Key points:
- `Logger` is passed as a parameter (no NestJS DI — these are plain functions, not injectable)
- `@Injectable()` stays on `IpnsService` only — do NOT apply it to codec functions
- `IpnsService` replaces `this.parseIpnsRecordBytes(...)` with `parseIpnsRecordBytes(..., this.logger)` etc.
- Export the `IpnsRecordFields` interface so callers can type-check against it

---

### Group C (continued): `apps/web/src/components/file-browser/details/{DetailsPrimitives,VersionHistory,FileDetails,FolderDetails}.tsx`

**Analog:** `apps/web/src/components/file-browser/DetailsDialog.tsx` (source file, lines 1–75 for imports + component internal structure)

No existing `details/` subdirectory exists. The split creates it. The pattern to replicate is the internal component structure already present in `DetailsDialog.tsx`.

**Import shape for sub-components** (`DetailsDialog.tsx` lines 1–17):
```typescript
import { useState, useEffect, useCallback, useRef } from 'react';
import type {
  FolderChild,
  FilePointer,
  FolderEntry,
  FileMetadata,
  VersionEntry,
} from '@cipherbox/core';
import { Modal } from '../ui/Modal';
import { useFolderStore } from '../../stores/folder.store';
import { useAuthStore } from '../../stores/auth.store';
// ...
import '../../styles/details-dialog.css';
```

**Convention for sub-components in `details/`:**
- Sub-components import from `../ui/Modal`, `../../stores/...`, etc. using the same relative depth (`../../` for items two levels up from `details/`)
- CSS import (`../../styles/details-dialog.css`) stays in the container `DetailsDialog.tsx` only — sub-components do not re-import it
- `DetailsPrimitives.tsx` exports `CopyableValue`, `DetailRow`, and `formatDateWithTime` as named exports
- `VersionHistory.tsx` must include `void folderKey;` (line 190 of current file) verbatim — do NOT drop it
- `DetailsDialog.tsx` imports sub-components: `import { VersionHistory } from './details/VersionHistory';` etc.
- The two `useEffect` hooks (lines 540–578, 581–640) stay in `DetailsDialog.tsx` — they are NOT moved to any sub-component

**File-browser barrel (`index.ts`) does NOT need updating** — `DetailsDialog` is not in the barrel; it is imported directly by the page that uses it.

---

### Group C (continued): `apps/desktop/src-tauri/src/commands/vault.rs` (receives `load_vault_settings`)

**Analog:** `apps/desktop/src-tauri/src/commands/vault.rs` (current shape, lines 1–30)

**Current module header** (lines 1–3):
```rust
//! Vault initialization and decryption commands.

use crate::state::AppState;
```

**Convention for adding `load_vault_settings`:**
- Cut-paste the function body verbatim; no logic change
- `load_vault_settings` takes `&ApiClient` + `&[u8; 32]` — no `AppState`, no `#[tauri::command]`
- Keep it `pub(crate)` (not `pub`) — only auth.rs calls it
- In `auth.rs`: update internal call site to `super::vault::load_vault_settings(...)`
- `commands/mod.rs` (lines 1–20) already re-exports vault with `pub use vault::*` — `load_vault_settings` is pub(crate) so it does NOT appear in the public re-export; no mod.rs change needed

**`commands/mod.rs` re-export shape** (lines 7–20 — do not change):
```rust
mod auth;
mod vault;
mod sync;
mod oauth;
#[cfg(debug_assertions)]
mod debug;
mod util;

pub use auth::*;
pub use sync::*;
pub use oauth::*;
#[cfg(debug_assertions)]
pub use debug::*;
```

Note: `vault` is NOT in `pub use` — vault functions are called via `super::vault::` within the commands module, not exposed as Tauri commands. This stays unchanged.

---

### Group D: `crates/fuse/src/content_ops.rs` (Tier 2 dedup)

**Analog:** `crates/fuse/src/journal_helpers.rs` (cfg-gated shared module that both fuse + winfsp features consume)

**`lib.rs` addition** (add alongside other new module decls):
```rust
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub mod content_ops;
```

**Re-export in `crates/fuse/src/operations.rs` and `crates/fuse/src/platform/windows/operations.rs`** (add after extraction):
```rust
pub use crate::content_ops::{
    fetch_and_decrypt_file_content,
    fetch_and_decrypt_content_async,
    publish_file_metadata,
};
```

**`content_ops.rs` header and cfg gate** (mirror `journal_helpers.rs` lines 22–23):
```rust
#[cfg(any(feature = "fuse", feature = "winfsp"))]
use crate::block_with_timeout; // crate re-export from runtime.rs (10s timeout)

#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub async fn fetch_and_decrypt_file_content(...) { ... }
```

Use fully-qualified submodule paths (`cipherbox_crypto::ecies::unwrap_key`, `cipherbox_crypto::aes_ctr::decrypt_aes_ctr`, `cipherbox_crypto::aes::decrypt_aes_gcm`) — these work on both feature sets. See RESEARCH.md Open Question 1 for the `block_with_timeout` timeout decision; executor must verify before finalizing.

---

### Group D (continued): `apps/desktop/src-tauri/src/fuse/prepopulate.rs`

**Analog:** `apps/desktop/src-tauri/src/fuse/mod.rs` (lines 1–30 for cfg gate and re-export pattern)

**`fuse/mod.rs` cfg + re-export shape** (lines 8–27):
```rust
#[allow(unused_imports)]
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub use cipherbox_fuse::{
    CipherBoxFS, PublishCoordinator, PendingRefresh, PendingContent, PendingFilePointer, UploadComplete,
    encrypt_metadata_to_json, spawn_bin_entry_publish, mount_point,
};
```

**`prepopulate.rs` header:**
```rust
//! Shared IPNS prepopulate logic for macOS (fuse) and Windows (winfsp) mounts.

#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub async fn prepopulate_filesystem(
    api: &std::sync::Arc<cipherbox_api_client::ApiClient>,
    inodes: &mut cipherbox_fuse::inode::InodeTable,
    metadata_cache: &mut cipherbox_fuse::cache::MetadataCache,
    root_ipns_name: &str,
    root_folder_key: &[u8],
    private_key: &[u8],
    public_key: &[u8],
) -> Vec<(String, u64)> { ... }
```

Add `pub mod prepopulate;` to `fuse/mod.rs` (cfg-gated `any(fuse,winfsp)`). Both `fuse/mod.rs` mount fn and `fuse/windows/mod.rs` mount_impl call `crate::fuse::prepopulate::prepopulate_filesystem(...)`.

---

### Group D (continued): `crates/fuse/src/platform/windows/content_fetch.rs`

**Analog:** `crates/fuse/src/platform/windows/read_ops.rs` (sibling in the same directory; the duplicated block is within it)

**`content_fetch.rs` shape** (winfsp-only, per RESEARCH.md):
```rust
//! Shared content-prefetch helper for WinFsp read operations.

#[cfg(feature = "winfsp")]
pub(crate) fn spawn_content_prefetch(
    fs: &mut crate::CipherBoxFS,
    cid: String,
    encrypted_file_key: String,
    iv: String,
    encryption_mode: String,
    label: &str,   // "Prefetch failed" vs "Read prefetch failed"
) { ... }
```

Add `mod content_fetch;` inside the `#[cfg(feature = "winfsp")] pub mod implementation { ... }` block in `platform/windows/read_ops.rs` (or at the top level of the platform/windows module — check where read_ops.rs declares it). This is NOT added to lib.rs; it is a module-local file.

---

### Shared Patterns

#### Rust cfg gate: `#[cfg(any(feature = "fuse", feature = "winfsp"))]`

**Source:** `crates/fuse/src/journal_helpers.rs` lines 22, 32, 110, 457, 466, 476
**Apply to:** Every item in `runtime.rs`, `events.rs`, `publish.rs`, `metadata.rs`, `fs.rs`, `replay.rs`, `content_ops.rs`, `prepopulate.rs`
```rust
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub struct Foo { ... }

#[cfg(any(feature = "fuse", feature = "winfsp"))]
impl Foo { ... }
```

#### Rust cfg gate: `#[cfg(feature = "winfsp")]` only

**Apply to:** `content_fetch.rs`

#### Rust cross-file inherent impl

**Source:** `crates/fuse/src/journal_helpers.rs` line 111
**Apply to:** `crates/fuse/src/fs.rs` (second `impl CipherBoxFS` block in a different file)
```rust
#[cfg(any(feature = "fuse", feature = "winfsp"))]
impl crate::CipherBoxFS {
    pub fn method_name(...) { ... }
}
```

#### Rust facade directory module (`pub(crate) mod implementation`)

**Source:** `crates/fuse/src/write_ops.rs` lines 5–6
**Apply to:** `crates/fuse/src/write_ops/mod.rs`
```rust
#[cfg(feature = "fuse")]
pub(crate) mod implementation {
    mod file_data;
    // ...
    pub use file_data::{handle_setattr, ...};
}
```

#### TypeScript barrel `export *`

**Source:** `apps/web/src/components/file-browser/index.ts` lines 1–19 (named form); adapt to `export *` for folder barrel
**Apply to:** `packages/sdk-core/src/folder/index.ts` after split
```typescript
export * from './load';
export * from './metadata-ops';
export * from './registration';
```

#### React sub-component file structure

**Source:** `apps/web/src/components/file-browser/DetailsDialog.tsx` internal component definitions
**Apply to:** `details/*.tsx` sub-components
- Named export per file (`export function ComponentName(props: Props) { ... }`)
- Props types defined inline in each file (no shared props barrel needed)
- No default exports

## No Analog Found

None. All files have an analog in the codebase.

## Metadata

**Analog search scope:** `crates/fuse/src/`, `apps/desktop/src-tauri/src/`, `packages/sdk-core/src/folder/`, `apps/api/src/ipns/`, `apps/web/src/components/file-browser/`
**Files scanned:** ~15 source files read directly
**Pattern extraction date:** 2026-06-19
