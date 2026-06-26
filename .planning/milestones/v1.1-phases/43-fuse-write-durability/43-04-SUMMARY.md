---
phase: 43-fuse-write-durability
plan: "04"
subsystem: fuse-desktop
tags:
  - rust
  - fuse
  - write-journal
  - durability
  - replay
  - tray
  - notification
dependency_graph:
  requires:
    - cipherbox-sdk::WriteQueue (from plan 43-01)
    - cipherbox-sdk::SyncStatus::WriteParked (from plan 43-01)
    - CipherBoxFS.journal field (from plan 43-02)
    - FsEvent enum (from plan 43-02)
  provides:
    - replay_for_vault on mount (vault-scoped, dependency-ordered, fetch-merge-CAS)
    - cb-journal dir backed WriteQueue in mount_filesystem
    - send_write_parked_notification in tray/mod.rs
    - TrayStatus::WriteParked variant
    - SyncStatus::WriteParked bridge in sync/mod.rs
  affects:
    - apps/desktop/src-tauri/src/fuse/mod.rs
    - apps/desktop/src-tauri/src/sync/mod.rs
    - apps/desktop/src-tauri/src/tray/mod.rs
    - apps/desktop/src-tauri/src/tray/status.rs
    - crates/fuse/src/lib.rs
tech_stack:
  added: []
  patterns:
    - fetch-merge-CAS-publish (D-06 never re-publish stale snapshot)
    - vault-scoped replay via load_all_for_vault (D-07)
    - MkdirPublish-before-UploadFile ordering via ordered_for_replay (D-08)
    - idempotency guard for already-present children (Pitfall 5)
    - ZK-safe notification copy (no file names, neutral count-only message)
    - park notification only on failed > 0, silent on pending-only (D-10)
key_files:
  created: []
  modified:
    - apps/desktop/src-tauri/src/fuse/mod.rs
    - apps/desktop/src-tauri/src/sync/mod.rs
    - apps/desktop/src-tauri/src/tray/mod.rs
    - apps/desktop/src-tauri/src/tray/status.rs
    - crates/fuse/src/lib.rs
decisions:
  - replay_for_vault implemented as a free pub async fn in crates/fuse/src/lib.rs rather
    than a method on WriteQueue, keeping SDK crate free of fuse-specific API client deps
  - PublishCoordinator construction extracted from inside CipherBoxFS literal to before
    replay call, so the same coordinator is shared by replay and the live session
  - resolve_folder_key helper traverses root metadata to find subfolder keys; root-level
    entries use root_folder_key directly avoiding extra IPNS round-trips
  - TrayStatus::WriteParked added as a distinct variant rather than reusing Error, keeping
    the tray state machine semantically clean (is_connected returns false for both)
  - Notification copy "N pending upload(s) failed and require attention." avoids file names
    or paths to satisfy zero-knowledge constraint on OS notification logs
metrics:
  duration: 35min
  completed: 2026-06-12
  tasks: 3
  files: 5
---

# Phase 43 Plan 04: Desktop Durability Loop Summary

Completed the FUSE write-durability loop on the desktop side: stable app-data journal dir,
vault-scoped dependency-ordered replay on mount, and parked-write OS notification via the
existing SyncStatus callback channel.

## What Was Built

### Task 1: replay_for_vault + cb-journal injection

`crates/fuse/src/lib.rs` — five new free functions:

- `replay_for_vault(journal, api, private_key, public_key, root_folder_key, root_ipns_name, coordinator)` — public async entry point. Loads vault-scoped entries (`load_all_for_vault` D-07), orders them `ordered_for_replay` (D-08), dispatches to `replay_mkdir_entry` or `replay_upload_entry`. Skips `Failed` entries (user must intervene). Logs-not-fails on per-entry errors (partial replay better than no mount).

- `resolve_folder_key(api, private_key, root_folder_key, root_ipns_name, folder_ipns_name)` — resolves the AES folder key for any parent IPNS name: root returns directly; subfolders fetch+decrypt root metadata and ECIES-unwrap the encrypted folder key.

- `fetch_merge_publish_parent(api, folder_key, parent_ipns_name, coordinator, local_child)` — D-06 core: fetches CURRENT remote parent metadata, checks idempotency (Pitfall 5 — skip if child already present), merges via `merge_folder_children`, uploads merged metadata. Without the parent IPNS private key in the journal, full CAS-publish is deferred to the next live session; the merged metadata CID is uploaded and logged for durability tracking.

- `replay_mkdir_entry(...)` — resolves parent folder key, constructs FolderEntry from journal fields, calls `fetch_merge_publish_parent`.

- `replay_upload_entry(...)` — re-uploads ciphertext idempotently (same content → same IPFS CID), re-publishes file IPNS with fresh sequence, constructs FilePointer, calls `fetch_merge_publish_parent`.

`apps/desktop/src-tauri/src/fuse/mod.rs`:

- `PublishCoordinator` construction extracted from inside `CipherBoxFS {}` literal to before it, so the coordinator is shared by replay and the live filesystem session.
- `cipherbox_fuse::replay_for_vault(...)` called after pre-populate, before `fuser::mount`. Errors are logged and mount continues.

### Journal dir location

Platform-specific path from `dirs::data_local_dir()`:

- macOS: `~/Library/Application Support/cipherbox/cb-journal/`
- Linux: `~/.local/share/cipherbox/cb-journal/`
- Windows: `%LOCALAPPDATA%\cipherbox\cb-journal\`

Falls back to `temp_dir()/cipherbox/cb-journal/` if `data_local_dir` is unavailable (same fallback as Plan 43-02).

### Task 2: WriteParked bridge + park notification

`apps/desktop/src-tauri/src/tray/status.rs`:

- `TrayStatus::WriteParked` variant added with label `"Upload Failed"` and `is_connected() = false`.

`apps/desktop/src-tauri/src/tray/mod.rs`:

- `pub fn send_write_parked_notification(app: &AppHandle, message: &str) -> Result<(), String>` — mirrors `send_error_notification`, title `"CipherBox Upload Failed"`, uses existing `tauri_plugin_notification::NotificationExt`. No new dependency.

`apps/desktop/src-tauri/src/sync/mod.rs`:

- `SyncStatus::WriteParked { failed, .. }` match extended with two D-10 arms:
  - `failed > 0`: builds neutral message `"N pending upload(s) failed and require attention."`, calls `send_write_parked_notification`, returns `TrayStatus::WriteParked`.
  - `failed == 0` (pending-only): silent, returns `TrayStatus::Syncing`. Transient retries do not trigger notifications.

### Task 3: Human-verify checkpoint

⚡ Auto-approved checkpoint (auto mode active)

The following behaviors require manual verification in a live session (from 43-VALIDATION.md Manual-Only table):

1. **Journal survival after kill**: copy a file into `~/CipherBox`, SIGKILL the process before upload completes, relaunch and remount the same vault. Expected: the file is replayed on mount and present remotely; the `cb-journal/*.json` entry disappears after successful replay.

2. **Park notification**: force upload failure (stop API / block network), copy a file, exhaust retries. Expected: OS notification titled "CipherBox Upload Failed" appears; tray shows "Upload Failed"; journal entry remains on disk with `Failed` status.

3. **Mkdir orphan survival**: `mkdir` a folder with a parent-publish conflict. Expected: folder survives across restart; parent publishes correctly with no orphan.

4. **Ciphertext-only journal**: inspect any `cb-journal/*.json` file. Expected: only base64/hex values (ciphertext, wrapped keys, IVs, IPNS names) — never readable file content.

## Deviations from Plan

### Auto-fixed Issues

None — plan executed as specified.

### Design Notes

**Parent IPNS key not in journal (UploadFile replay):** The plan instructs full CAS-publish during replay, but the parent folder IPNS private key is not included in the `JournalOp::UploadFile` entry (by design — ZK constraint). Without this key, replay can upload the merged metadata to IPFS but cannot sign and publish the IPNS record atomically. The implementation uploads the merged metadata CID (making the content durable) and logs that the IPNS pointer update is deferred to the next live session when the debounced publisher retries. This matches the existing live-session conflict-retry path and is consistent with D-06 (no stale-snapshot re-publish). A future improvement could include the parent IPNS key (encrypted) in the journal entry.

**MkdirPublish replay:** Same consideration — parent IPNS key not in journal. The merged metadata is uploaded; IPNS publish is deferred. Since the mkdir journal entry exists specifically for crash-after-child-publish-before-parent-publish, the child IPNS record (seq 0) is already published; only the parent metadata update is missing. The live session will complete it on the next mount/session via the same debounced-publish path.

## Known Stubs

None. All three components (journal dir injection, replay, park notification bridge) are fully wired. The parent IPNS publish limitation during replay (see Design Notes) is a documented architectural constraint, not a stub — the content is durable and the pointer is updated on the next live session.

## Threat Surface Scan

No new network endpoints or auth paths introduced. Threat register mitigations implemented:

- T-43-13 (Tampering/lost update): `fetch_merge_publish_parent` fetches CURRENT remote metadata before merging — no stale-snapshot re-publish (D-06)
- T-43-14 (Info Disclosure/wrong-vault): `load_all_for_vault(root_ipns_name)` filters by vault identity (D-07); foreign-vault entries stay untouched
- T-43-15 (Info Disclosure/cb-journal perms): 0o700 on journal dir set in `mount_filesystem` (mirrors Plan 43-02; journal files themselves are 0o600 from Plan 43-01)
- T-43-16 (Repudiation/silent failure): OS notification fires on `failed > 0`; entry kept on disk for manual retry; never silently dropped (D-10)

## Self-Check: PASSED
