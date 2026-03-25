---
phase: 23-rust-sdk-extraction
plan: 05
subsystem: sdk
tags: [rust, crate, sync-daemon, write-queue, key-state, device-registry, tauri]

# Dependency graph
requires:
  - phase: 23-02
    provides: cipherbox-core crate with domain types and registry types
  - phase: 23-03
    provides: cipherbox-api-client crate with ApiClient and IPFS/IPNS functions
provides:
  - cipherbox-sdk crate with SyncDaemon, WriteQueue, KeyState, registry operations, CipherBoxSdkClient
  - Desktop AppState wrapping SDK KeyState via Arc<KeyState>
  - Desktop sync thin bridge mapping SyncStatus to TrayStatus
affects: [23-06-desktop-shell-cleanup, 23-07-ci-workspace]

# Tech tracking
tech-stack:
  added: [cipherbox-sdk]
  patterns: [generic-callback-pattern, sdk-key-state-wrapping, api-client-type-alias-re-export]

key-files:
  created:
    - crates/sdk/Cargo.toml
    - crates/sdk/src/lib.rs
    - crates/sdk/src/client.rs
    - crates/sdk/src/sync.rs
    - crates/sdk/src/queue.rs
    - crates/sdk/src/state.rs
    - crates/sdk/src/registry.rs
    - crates/sdk/src/error.rs
  modified:
    - Cargo.toml
    - apps/desktop/src-tauri/Cargo.toml
    - apps/desktop/src-tauri/src/state.rs
    - apps/desktop/src-tauri/src/sync/mod.rs
    - apps/desktop/src-tauri/src/registry/mod.rs
    - apps/desktop/src-tauri/src/commands/auth.rs
    - apps/desktop/src-tauri/src/commands/vault.rs
    - apps/desktop/src-tauri/src/commands/sync.rs
    - apps/desktop/src-tauri/src/api/client.rs
    - apps/desktop/src-tauri/src/api/types.rs
    - apps/desktop/src-tauri/src/fuse/mod.rs
    - apps/desktop/src-tauri/src/fuse/windows/mod.rs
    - apps/desktop/src-tauri/src/tray/mod.rs

key-decisions:
  - 'SyncDaemon uses Arc<dyn Fn(SyncStatus) + Send + Sync> generic callback instead of Tauri AppHandle'
  - 'Desktop api/client.rs re-exports cipherbox_api_client::ApiClient as type alias to avoid dual-type mismatch'
  - 'TeeKeysResponse re-exported from cipherbox_api_client in desktop types.rs for shared type with SDK KeyState'
  - 'Registry accepts DeviceInfo struct parameter instead of using keyring/hostname directly, keeping OS-specific code in desktop'

patterns-established:
  - 'SDK wrapping pattern: Desktop AppState.sdk wraps Arc<KeyState>, all key material accessed via state.sdk.*'
  - 'Thin bridge pattern: Desktop sync/mod.rs creates SDK SyncDaemon with a closure that maps SyncStatus to TrayStatus'
  - 'Type alias re-export: crate::api::client::ApiClient re-exports cipherbox_api_client::ApiClient to unify types across desktop modules'

requirements-completed: [RSDK-07]

# Metrics
duration: 12min
completed: 2026-03-24
---

# Phase 23 Plan 05: cipherbox-sdk Crate Extraction Summary

**Extracted stateful SDK crate (SyncDaemon, WriteQueue, KeyState, registry) with generic callbacks, desktop app rewired as thin Tauri shell wrapping Arc<KeyState>**

## Performance

- **Duration:** 12 min
- **Started:** 2026-03-24T10:43:41Z
- **Completed:** 2026-03-24T10:56:00Z
- **Tasks:** 2
- **Files modified:** 24

## Accomplishments

- Created cipherbox-sdk crate with SyncDaemon (generic status callback, no Tauri dependency), WriteQueue (FIFO offline write queue), KeyState (zeroizable key material), device registry operations, and CipherBoxSdkClient top-level orchestrator
- Rewired desktop app to use SDK: AppState wraps Arc<KeyState>, sync is a thin bridge, registry delegates to SDK, all state._ references updated to state.sdk._
- 152 desktop tests pass, cargo check exits 0 for both SDK and desktop crates
- SyncDaemon is fully Tauri-free -- uses Arc<dyn Fn(SyncStatus)> callback instead of AppHandle

## Task Commits

Each task was committed atomically:

1. **Task 1: Create cipherbox-sdk crate** - `2ca2fc130` (feat)
2. **Task 2: Rewire desktop app to use cipherbox-sdk** - `cf69b4b97` (feat)

## Files Created/Modified

### Created

- `crates/sdk/Cargo.toml` - SDK crate manifest (no tauri/keyring deps)
- `crates/sdk/src/lib.rs` - Public API: re-exports CipherBoxSdkClient, KeyState, SyncDaemon, WriteQueue, SdkError
- `crates/sdk/src/client.rs` - CipherBoxSdkClient with start_sync/stop_sync/clear
- `crates/sdk/src/sync.rs` - SyncDaemon with generic callback, IPNS polling, error sanitization
- `crates/sdk/src/queue.rs` - WriteQueue with UploadHandler trait, FIFO retry logic
- `crates/sdk/src/state.rs` - KeyState with zeroize-on-clear for all sensitive fields
- `crates/sdk/src/registry.rs` - Device registry operations with DeviceInfo parameter pattern
- `crates/sdk/src/error.rs` - SdkError enum with From impls for CryptoError, CoreError, IpnsError, ApiError
- `crates/fuse/src/lib.rs` - Stub lib.rs to unblock workspace compilation (deviation fix)

### Modified

- `Cargo.toml` - Added crates/sdk to workspace members and cipherbox-sdk to workspace deps
- `apps/desktop/src-tauri/Cargo.toml` - Added cipherbox-sdk + cipherbox-api-client deps, removed hostname
- `apps/desktop/src-tauri/src/state.rs` - AppState wraps Arc<KeyState>, clear_keys() delegates to sdk.clear()
- `apps/desktop/src-tauri/src/sync/mod.rs` - Thin bridge creating SyncDaemon with tray status callback
- `apps/desktop/src-tauri/src/registry/mod.rs` - Delegates to cipherbox_sdk::registry, keeps keyring local
- `apps/desktop/src-tauri/src/api/client.rs` - Re-exports cipherbox_api_client::ApiClient
- `apps/desktop/src-tauri/src/api/types.rs` - Re-exports TeeKeysResponse from cipherbox_api_client
- `apps/desktop/src-tauri/src/commands/auth.rs` - All state._ -> state.sdk._
- `apps/desktop/src-tauri/src/commands/vault.rs` - All state._ -> state.sdk._
- `apps/desktop/src-tauri/src/commands/sync.rs` - Uses SDK sync daemon via bridge
- `apps/desktop/src-tauri/src/fuse/mod.rs` - All state.api -> state.sdk.api
- `apps/desktop/src-tauri/src/fuse/windows/mod.rs` - All state.api -> state.sdk.api
- `apps/desktop/src-tauri/src/tray/mod.rs` - state.api/user_id -> state.sdk.api/user_id

### Deleted

- `apps/desktop/src-tauri/src/sync/queue.rs` - Moved to crates/sdk/src/queue.rs
- `apps/desktop/src-tauri/src/sync/tests.rs` - Queue tests in desktop still pass via SDK re-exports

## Decisions Made

- **Generic callback for SyncDaemon:** `Arc<dyn Fn(SyncStatus) + Send + Sync>` replaces `tauri::AppHandle`. Desktop bridges this to tray status via a closure. Enables unit testing sync logic without Tauri.
- **Type alias re-export for ApiClient:** Desktop's `api/client.rs` re-exports `cipherbox_api_client::ApiClient` instead of maintaining a duplicate type. All existing `crate::api::ipfs::*` and `crate::api::ipns::*` functions work unchanged.
- **TeeKeysResponse re-export:** Instead of maintaining duplicate struct, desktop re-exports from `cipherbox_api_client` to share type with SDK's KeyState.
- **DeviceInfo parameter pattern:** SDK registry takes DeviceInfo struct instead of calling keyring/hostname directly. OS-specific device ID retrieval stays in desktop app.
- **IpnsError in SdkError:** Added `Ipns(#[from] IpnsError)` variant to SdkError since IPNS record creation/marshaling returns IpnsError, not CoreError.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Created crates/fuse/src/lib.rs stub**

- **Found during:** Task 1 (SDK crate compilation)
- **Issue:** The crates/fuse directory from prior plan 23-04 had Cargo.toml and source files but no lib.rs, causing workspace compilation failure
- **Fix:** Created minimal lib.rs with `pub mod error; pub mod inode;` to allow workspace-level cargo check
- **Files modified:** crates/fuse/src/lib.rs
- **Verification:** `cargo check -p cipherbox-sdk` succeeds
- **Committed in:** 2ca2fc130 (Task 1 commit)

**2. [Rule 3 - Blocking] Added IpnsError variant to SdkError**

- **Found during:** Task 1 (SDK crate compilation)
- **Issue:** registry.rs uses `?` on create*ipns_record/marshal_ipns_record which return `Result<*, IpnsError>`, but SdkError only had `From<CoreError>`, not `From<IpnsError>`
- **Fix:** Added `Ipns(#[from] cipherbox_core::ipns::IpnsError)` variant to SdkError
- **Files modified:** crates/sdk/src/error.rs
- **Verification:** `cargo check -p cipherbox-sdk` exits 0
- **Committed in:** 2ca2fc130 (Task 1 commit)

**3. [Rule 3 - Blocking] Added cipherbox-api-client dependency to desktop**

- **Found during:** Task 2 (desktop compilation)
- **Issue:** Desktop registry/mod.rs imports `cipherbox_api_client::ApiClient` but the crate wasn't in desktop's Cargo.toml
- **Fix:** Added `cipherbox-api-client = { workspace = true }` to desktop Cargo.toml
- **Files modified:** apps/desktop/src-tauri/Cargo.toml
- **Verification:** `cargo check -p cipherbox-desktop` succeeds
- **Committed in:** cf69b4b97 (Task 2 commit)

**4. [Rule 3 - Blocking] Re-exported ApiClient and TeeKeysResponse types**

- **Found during:** Task 2 (desktop compilation)
- **Issue:** Desktop had its own `api::client::ApiClient` and `api::types::TeeKeysResponse` types distinct from `cipherbox_api_client`'s. SDK KeyState uses crate types, causing type mismatch errors (17 errors).
- **Fix:** Made `api/client.rs` a re-export of `cipherbox_api_client::ApiClient` and `api/types.rs` re-export `TeeKeysResponse` from the crate
- **Files modified:** apps/desktop/src-tauri/src/api/client.rs, apps/desktop/src-tauri/src/api/types.rs
- **Verification:** `cargo check -p cipherbox-desktop` exits 0 with no type mismatch errors
- **Committed in:** cf69b4b97 (Task 2 commit)

---

**Total deviations:** 4 auto-fixed (all Rule 3 - blocking issues)
**Impact on plan:** All auto-fixes necessary for compilation. The type unification (deviations 3-4) was the most significant -- bridging two identical-but-distinct ApiClient types required making the desktop's local copy a re-export of the crate version. No scope creep.

## Issues Encountered

None beyond the deviations documented above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- cipherbox-sdk crate is ready for use by future CLI or integration test harnesses
- Desktop app is thinner: state management, sync, and registry logic delegated to SDK
- Plan 23-06 (desktop shell cleanup) can further reduce desktop code by migrating remaining api/ipfs/ipns helper functions to cipherbox_api_client
- Plan 23-07 (CI workspace builds) can add workspace-level cargo test

---

_Phase: 23-rust-sdk-extraction_
_Completed: 2026-03-24_
