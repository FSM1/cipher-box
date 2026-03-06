---
phase: 09-desktop-client
plan: 07
subsystem: desktop
tags: [tauri, rust, tray, sync, offline-queue, menu-bar, ipns-polling]

# Dependency graph
requires:
  - phase: 09-04
    provides: Auth, API client, AppState with keys
  - phase: 09-05
    provides: FUSE read operations, inode table, cache layer, mount/unmount
  - phase: 09-06
    provides: FUSE write operations, temp-file commit, folder mutation
provides:
  - System tray menu bar icon with status state machine (NotConnected/Mounting/Syncing/Synced/Offline/Error)
  - Tray menu with Open CipherVault, Sync Now, Login, Logout, Quit actions
  - Background sync daemon polling IPNS every 30s with sequence number comparison
  - Offline write queue (memory-only) with FIFO processing and retry logic
  - Unit tests for WriteQueue (enqueue, process, retry, FIFO order)
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - 'TrayStatus state machine drives menu item enable/disable'
    - 'tokio::select! on timer tick OR manual sync channel'
    - 'Memory-only write queue with max 5 retries per item'
    - 'Sequence number comparison for change detection (not CID)'

key-files:
  created:
    - apps/desktop/src-tauri/src/tray/mod.rs
    - apps/desktop/src-tauri/src/tray/status.rs
    - apps/desktop/src-tauri/src/sync/mod.rs
    - apps/desktop/src-tauri/src/sync/queue.rs
    - apps/desktop/src-tauri/src/sync/tests.rs
  modified:
    - apps/desktop/src-tauri/src/main.rs
    - apps/desktop/src-tauri/src/commands.rs

key-decisions:
  - 'Memory-only write queue (items lost on quit) — acceptable for v1 tech demo'
  - 'Sequence number comparison for sync detection (not CID) — per Phase 7 decision'
  - 'ActivationPolicy::Accessory hides Dock icon, menu bar only'
  - 'Reactive sync via readdir refresh, not proactive push'

# Metrics
duration: 5min
completed: 2026-02-08
---

# Phase 9 Plan 7: System Tray, Background Sync & Offline Queue Summary

> Menu bar tray icon with status, background IPNS polling (30s), and offline write queue with retry

## Performance

- **Duration:** 5 min
- **Completed:** 2026-02-08
- **Tasks:** 1 (+ manual checkpoint verification)
- **Files modified:** 7

## Accomplishments

- Implemented TrayStatus state machine (NotConnected, Mounting, Syncing, Synced, Offline, Error) with human-readable labels
- Built tray menu with Open CipherVault, Sync Now, Login/Logout, and Quit actions
- Implemented background SyncDaemon with 30s IPNS polling via tokio::select!
- Created WriteQueue with FIFO processing, retry logic (max 5), and encrypted-at-rest queue items
- Added 5 unit tests for WriteQueue (enqueue, process success/failure, FIFO order, empty state)
- Wired tray status updates throughout auth and mount lifecycle in main.rs

## Files Created/Modified

- `apps/desktop/src-tauri/src/tray/mod.rs` — Tray icon builder, menu items, event handlers (open/sync/login/logout/quit)
- `apps/desktop/src-tauri/src/tray/status.rs` — TrayStatus enum with label() and is_connected()
- `apps/desktop/src-tauri/src/sync/mod.rs` — SyncDaemon with 30s poll loop, IPNS sequence comparison, network detection
- `apps/desktop/src-tauri/src/sync/queue.rs` — WriteQueue with enqueue/process/retry, stores already-encrypted content
- `apps/desktop/src-tauri/src/sync/tests.rs` — Unit tests for WriteQueue operations
- `apps/desktop/src-tauri/src/main.rs` — Added tray and sync module declarations, spawn SyncDaemon after mount
- `apps/desktop/src-tauri/src/commands.rs` — OAuth popup cleanup, webview reload on re-login

## UAT Results

All 15 manual tests completed:

- 14 passed (several after applying fixes during testing)
- 1 open issue: Test 2 (tray status flaky on first login, intermittent keychain error)
- 16 total fixes applied during UAT across FUSE-T NFS, webview lifecycle, and mount management

## Security Review

Completed security review with 4 parallel review agents:

- 6 High findings — all addressed (memory zeroization, FUSE permissions, temp files, cache cleanup)
- 5 Medium findings — all addressed (token prefix lookup, temp dir permissions, lock discipline, mount permissions)
- 7 Low findings — backlogged in LOW-SEVERITY-BACKLOG.md
- Positive: cryptographic implementation quality confirmed, zero-knowledge guarantee preserved

## Deviations from Plan

None — plan executed as specified.

## Next Phase Readiness

- Phase 9 (Desktop Client) is complete
- All 7 success criteria met:
  1. Web3Auth login in desktop app
  2. FUSE mount at ~/CipherBox after login
  3. Files open in native apps (Preview, TextEdit)
  4. Save files through FUSE (transparent encryption)
  5. System tray with status icon
  6. Refresh tokens in macOS Keychain
  7. Background sync in system tray
- Ready for Phase 10 (Data Portability)

---

_Phase: 09-desktop-client_
_Completed: 2026-02-08_
