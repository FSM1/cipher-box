# Phase 43: FUSE Write Durability - Research

**Researched:** 2026-06-12
**Domain:** Rust, FUSE (fuser / WinFsp), crash-safe journaling, IPNS OCC
**Confidence:** HIGH (all findings sourced from direct codebase reads)

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Journal is a persist-backed `WriteQueue` in `crates/sdk` (`src/queue.rs`). Extend
  the existing trait-based queue with disk persistence; FUSE wires through it. The current
  memory-only "v1 tech demo" semantics are superseded.
- **D-02:** Journal entries use STABLE identifiers — parent folder IPNS name, file-meta IPNS
  name, filename, vault identity — never `ino`/`parent_ino` (inode numbers don't survive
  remount). The existing `QueuedWrite` shape is reworked accordingly.
- **D-03:** Full op-log enum covering both todos: `UploadFile | MkdirPublish` variants. One
  durable replay path; closes mkdir's crash-before-thread-runs window, not just the
  conflict-retry bug.
- **D-04:** Durability ack barrier: journal entry fsynced to disk BEFORE `reply.ok()` /
  `reply.entry()`. macOS FUSE callbacks are single-threaded and must not block on network I/O
  (locked constraint from the todo) — local fsync is the only blocking work allowed in the
  callback.
- **D-05:** Journal contents are ciphertext + ECIES-wrapped keys + IV + metadata context only.
  NEVER plaintext, never raw keys (project crypto rules). The plaintext temp file is
  zeroized+deleted immediately after the ciphertext is journaled (not after thread spawn as
  today).
- **D-06:** Replay = upsert into fresh remote: on mount/login, fetch the parent folder's
  CURRENT metadata, merge in the journaled child entry (insert or update that one entry),
  CAS-publish with retry. Never re-publish the stale journaled parent snapshot.
- **D-07:** Entries tagged with vault identity (root IPNS name); login replays only entries
  matching the current vault. Foreign-vault entries stay untouched on disk.
- **D-08:** Replay order respects dependencies: `MkdirPublish` entries replay before
  `UploadFile` entries targeting that folder.
- **D-09:** Retry policy: exponential backoff up to a threshold, then `failed` — kept on disk,
  surfaced (D-10), manually retryable. Entries are NEVER silently dropped.
- **D-10:** OS notification fires only when an entry parks as failed; pending/failed counts ride
  the existing `SyncDaemon` `Arc<dyn Fn(SyncStatus)>` callback channel into Tauri
  tray/status. Full pending-uploads management UI is deferred.
- **D-11:** Two composing mechanisms for mkdir conflict: (a) live-session — on
  parent-publish conflict, signal the FS thread (existing `upload_tx`-style channel) to insert
  the parent into `mutated_folders` so the debounced publisher retries; (b) crash safety —
  journaled `MkdirPublish` entry clears only when the parent publish confirms.
- **D-12:** All THREE platforms in this phase, structured as SEPARATE PLANS: journal core in
  `crates/sdk` (shared), fuser wiring (macOS + Linux share
  `crates/fuse/src/{read_ops,write_ops}.rs`), WinFsp wiring
  (`crates/fuse/src/platform/windows/write_ops.rs`).

### Claude's Discretion

- Journal on-disk format (one file per entry vs append log), directory location within the
  desktop app data dir, rotation/compaction.
- Backoff parameters and park threshold.
- Notification copy and `SyncStatus` field shape for pending/failed counts.
- Verifying the macOS mkdir conflict line number by grep before fixing (todo's note).

### Deferred Ideas (OUT OF SCOPE)

- Full pending-uploads management UI — desktop window listing queued + failed entries with
  retry/export actions.

</user_constraints>

<phase_requirements>

## Phase Requirements

| ID | Description | Research Support |
| --- | --- | --- |
| REQ-43-A | Fix `release()` false-ack / detached-thread data loss on all 3 platforms | D-01..D-05, D-09; see release path anatomy below |
| REQ-43-B | Fix `handle_mkdir` parent-publish conflict orphan on macOS/Linux and Windows | D-03, D-06, D-11; both conflict arms confirmed |
| REQ-43-C | Journal in `crates/sdk` with stable identifiers, not inodes | D-01, D-02; QueuedWrite redesign pattern below |
| REQ-43-D | Ciphertext-only journal, plaintext temp deleted after journal fsync | D-05; crypto layer already in scope |
| REQ-43-E | Replay on mount, vault-scoped, dependency-ordered | D-06, D-07, D-08; replay design below |
| REQ-43-F | Park-on-max-retry, notification, counts in SyncStatus | D-09, D-10; existing channel pattern below |
| REQ-43-G | Separate plans: sdk-journal, fuser-wiring, winfsp-wiring | D-12 |

</phase_requirements>

## Summary

Phase 43 fixes two data-loss bugs in the FUSE desktop filesystem. Both are caused by
optimistic acking followed by fire-and-forget uploads with no durability guarantee.

The fix centers on a durable write journal stored in `crates/sdk/src/queue.rs`. The journal
replaces the current memory-only `WriteQueue`. Every FUSE write callback (release on
macOS/Linux, cleanup on Windows) must: encrypt → journal-fsync → ack → background-drain. A
crash at any point after the fsync is recoverable by replaying the journal on next mount.

The mkdir orphan bug is an independent failure mode in `handle_mkdir`, but it shares the same
journal infrastructure: a `MkdirPublish` entry ensures the parent publish eventually completes
even if the process dies before the background thread runs.

**Primary recommendation:** Implement the journal as one-file-per-entry under a fixed app-data
subdirectory. Each entry is a JSON file containing ciphertext bytes (base64), ECIES-wrapped key
(hex), IV (hex), and metadata context strings. `file.sync_all()` on the journal file is the ack
barrier. No new crate dependencies are needed — `serde_json` and `std::fs` are already in scope.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
| --- | --- | --- | --- |
| Journal persistence | crates/sdk (WriteQueue) | — | Keeps fuse dependent on sdk, not vice versa |
| FUSE callback wiring (fsync barrier) | crates/fuse read_ops / write_ops | — | Platform-specific callback signatures live here |
| WinFsp wiring | crates/fuse platform/windows | — | Separate feature flag; mirrors fuser path |
| Replay on mount | crates/fuse mount_filesystem (macOS/Linux) / windows::mount_filesystem | crates/sdk WriteQueue | Mount orchestration calls sdk replay |
| Conflict retry signal | crates/fuse (mkdir upload_tx-style channel) | — | Must stay in fuse; feeds mutated_folders |
| Status surfacing | crates/sdk SyncStatus enum | apps/desktop sync::create_sync_daemon | SyncStatus extended; desktop bridge unchanged |
| OS notification | apps/desktop (tauri_plugin_notification) | crates/sdk (status_callback fires) | Notification triggered by SyncStatus::WriteParked |

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
| --- | --- | --- | --- |
| `serde` / `serde_json` | workspace (1.x / 1.x) | Journal entry serialization | Already in `crates/sdk` Cargo.toml |
| `std::fs::File::sync_all` | std | fsync barrier | Cross-platform; `sync_all` calls `F_FULLFSYNC` on macOS via `fcntl` in Rust std |
| `zeroize` | workspace (1.x) | Wipe plaintext from memory | Already in scope; used throughout crypto layer |
| `tauri_plugin_notification` | 2.x | Park notification | Already configured in `apps/desktop/src-tauri/Cargo.toml:24` |

No new crate dependencies are required for this phase. All needed libraries are already in the
workspace.

### Supporting

| Library | Version | Purpose | When to Use |
| --- | --- | --- | --- |
| `dirs` | workspace (5.x) | Resolve app data dir for journal storage | Already in `crates/fuse/Cargo.toml` |
| `hex` | workspace (0.4) | Encode ciphertext/key bytes for JSON journal | Already in `crates/sdk` Cargo.toml |
| `base64` | workspace (0.22) | Encode ciphertext bytes in journal | Already in `crates/sdk` Cargo.toml |
| `uuid` (via rand) | N/A | Entry IDs can be random hex from `utils::generate_random_bytes` | Avoids new dep; uuid not in workspace |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
| --- | --- | --- |
| One-file-per-entry JSON | Append-log (e.g. sled, redb) | No new dep vs. atomic per-entry ops; per-file gives trivially atomic remove-on-complete |
| `std::fs::File::sync_all()` | `libc::fcntl(F_FULLFSYNC)` directly | std wraps F_FULLFSYNC on macOS since Rust 1.x; no unsafe needed |
| In-memory retry after park | Keep entry on disk | D-09 requires kept-on-disk; in-memory retry alone is the current broken behavior |

**Installation:** No new dependencies. All required crates are already in `Cargo.toml`.

## Package Legitimacy Audit

> No new external packages are introduced in this phase. All libraries used are already
> present in the workspace (serde, serde_json, hex, base64, zeroize, dirs, std).

**Packages removed due to SLOP verdict:** none

**Packages flagged as suspicious:** none

## Architecture Patterns

### System Architecture Diagram

```
write()/create()
       |
       v
  [temp file]  <-- plaintext buffered to disk at 0o600
       |
  release() / cleanup()   [FUSE callback thread -- single-threaded on macOS]
       |
       +--encrypt (AES-256-GCM + ECIES wrap)--> ciphertext
       |
       +--journal.put(entry)  -->  [one-file-per-entry JSON, app-data/cb-journal/]
       |                                        |
       +--file.sync_all()  [fsync barrier]      |
       |                                        |
       +--reply.ok() / reply.entry()            |
       |                                        |
       +--plaintext temp: zeroize + delete      |
       |                                        |
  [background drain task]  <--pick up entries--+
       |
       +--IPFS upload (ciphertext) -> CID
       |
       +--UploadComplete channel -> FS thread (existing pattern)
       |
       +--IPNS publish (per-file + parent)
       |
       +--journal.remove(entry_id)  [on confirmed success]
       |
       on permanent failure:
       +--entry.status = "failed" + journal.update(entry)
       +--SyncStatus::WriteParked { failed: N } callback
       +--tauri_plugin_notification -> OS notification


mkdir() conflict path:
  handle_mkdir
       |
       +--journal.put(MkdirPublish { parent_ipns_name, ... })
       +--entry.sync_all()
       +--reply.entry()
       |
  [background thread spawns child IPNS publish, then parent CAS-publish]
       |
       on Conflict:
       +--upload_tx.send(MkdirConflict { parent_ino })  [new variant or reuse]
       +-- FS thread inserts parent_ino into mutated_folders
       +-- debounced flush_publish_queue() retries with fresh seq
       |
       on Success:
       +--journal.remove(mkdir_entry_id)


Mount / Login replay:
  mount_filesystem()
       |
       +--journal.load_all_for_vault(root_ipns_name)
       |
       +--for each MkdirPublish (before UploadFile):
       |      fetch parent IPNS -> merge child entry -> CAS-publish + retry
       |      on success: journal.remove(id)
       |
       +--for each UploadFile:
              re-upload ciphertext -> same CID (idempotent)
              re-publish file IPNS
              fetch parent IPNS -> merge file pointer -> CAS-publish
              on success: journal.remove(id)
```

### Recommended Project Structure

```
crates/sdk/src/
├── queue.rs         # WriteQueue rewritten: JournalEntry enum, persist-backed, fsync
├── state.rs         # SyncStatus extended: WriteParked { pending: u32, failed: u32 }
└── lib.rs           # re-exports unchanged

crates/fuse/src/
├── read_ops.rs      # handle_release: encrypt -> journal.put -> fsync -> reply.ok
├── write_ops.rs     # handle_mkdir: journal.put(MkdirPublish) -> fsync -> reply.entry
│                    #   + conflict arm: upload_tx MkdirConflict signal
platform/windows/
├── write_ops.rs     # handle_cleanup: same journal pattern as read_ops.rs release
│                    #   + handle_mkdir conflict arm (mirrors write_ops.rs line ~194)

apps/desktop/src-tauri/src/
├── fuse/mod.rs      # mount_filesystem: call journal.replay_for_vault() after key init
└── sync/mod.rs      # bridge: add SyncStatus::WriteParked -> TrayStatus::WriteParked
```

### Pattern 1: Journal Entry Shape (crates/sdk/src/queue.rs)

**What:** Stable-identifier journal entries serialized as JSON, one file per entry.

**When to use:** All durable write operations on release/cleanup and mkdir.

```rust
// Source: codebase synthesis from queue.rs + CONTEXT.md decisions
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JournalOp {
    UploadFile {
        /// AES-256-GCM sealed ciphertext (base64-encoded).
        ciphertext_b64: String,
        /// ECIES-wrapped file key (hex-encoded).
        wrapped_key_hex: String,
        /// AES-GCM IV (hex-encoded).
        iv_hex: String,
        /// File's per-file IPNS name (stable cross-remount).
        file_meta_ipns_name: String,
        /// ECIES-wrapped file IPNS private key (hex-encoded).
        file_ipns_key_hex: Option<String>,
        /// Parent folder IPNS name (stable cross-remount).
        parent_folder_ipns_name: String,
        /// Original filename (for logging and rebuild).
        filename: String,
        /// File size in bytes.
        size: u64,
        /// Timestamp of write (ms since epoch).
        created_at_ms: u64,
    },
    MkdirPublish {
        /// New child folder IPNS name (already published seq 0).
        child_ipns_name: String,
        /// ECIES-wrapped child folder key (hex-encoded).
        child_folder_key_hex: String,
        /// ECIES-wrapped child IPNS private key (hex-encoded, for TEE).
        child_ipns_key_hex: String,
        /// Parent folder IPNS name.
        parent_folder_ipns_name: String,
        /// Child folder display name.
        name: String,
        /// Timestamp (ms since epoch).
        created_at_ms: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JournalEntryStatus {
    /// Awaiting background drain.
    Pending,
    /// Background drain in progress.
    InProgress,
    /// Max retries exceeded; parked for user attention.
    Failed { last_error: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Unique entry ID (random hex, 32 chars).
    pub id: String,
    /// Vault identity — root IPNS name of the vault that owns this entry.
    pub vault_root_ipns: String,
    /// The operation to replay.
    pub op: JournalOp,
    /// Current retry count.
    pub retries: u32,
    /// Processing state.
    pub status: JournalEntryStatus,
}
```

### Pattern 2: fsync Barrier in release() (crates/fuse/src/read_ops.rs)

**What:** Replace detached-thread-first with journal-fsync-first.

**When to use:** Every dirty file release on macOS/Linux.

```rust
// Source: codebase read_ops.rs:791 synthesis + CONTEXT.md D-04/D-05
// BEFORE (current):
//   std::thread::spawn(move || { upload(...) });
//   handle.cleanup();
//   reply.ok();

// AFTER (this phase):
let entry = JournalEntry { ... };  // ciphertext only, never plaintext
let entry_path = journal_dir.join(format!("{}.json", entry.id));
let json = serde_json::to_vec(&entry)?;
let mut f = std::fs::File::create(&entry_path)?;
f.write_all(&json)?;
f.sync_all()?;  // fsync barrier: durability guaranteed before ack

handle.cleanup();  // zeroize + delete plaintext temp file NOW (not after spawn)
reply.ok();        // ack only after fsync

// Background drain task picks up the entry asynchronously.
// On success: std::fs::remove_file(&entry_path)
// On failure past threshold: update status to Failed, send SyncStatus::WriteParked
```

### Pattern 3: mkdir Conflict Retry (crates/fuse/src/write_ops.rs)

**What:** Replace warn-only on `PublishResult::Conflict` with actual retry signal.

**When to use:** In the background spawn thread at `write_ops.rs:602-609`.

```rust
// Source: codebase write_ops.rs:593-610 + CONTEXT.md D-11
cipherbox_api_client::PublishResult::Conflict { current_sequence_number } => {
    log::warn!(
        "Conflict on parent publish after mkdir (expected seq {}, server has {}). \
        Enqueuing retry.",
        seq, current_sequence_number
    );
    // Signal FS thread to insert parent_ino into mutated_folders so debounced
    // flush_publish_queue() retries with a freshly-resolved sequence.
    // Reuse the upload_tx channel (same std::sync::mpsc pattern as UploadComplete).
    let _ = upload_tx.send(UploadComplete {
        // ... or a new MkdirConflict variant to distinguish from upload completions
    });
    // The journaled MkdirPublish entry stays in the journal until the publish confirms.
}
```

### Pattern 4: Notification on Park (apps/desktop/src-tauri/src/tray/mod.rs)

**What:** Send notification when write parks as failed; carry counts via SyncStatus.

**When to use:** When background drain transitions an entry to `JournalEntryStatus::Failed`.

```rust
// Source: codebase tray/mod.rs:323-330 (existing send_error_notification pattern)
// In crates/sdk/src/state.rs — extend SyncStatus:
pub enum SyncStatus {
    Idle,
    Syncing,
    Error(String),
    WriteParked { pending: u32, failed: u32 },  // new variant
}

// In apps/desktop/src-tauri/src/sync/mod.rs — extend bridge:
SyncStatus::WriteParked { failed, .. } if failed > 0 => {
    // Trigger notification via NotificationExt (same pattern as updater.rs:80)
    // Then update tray to a new TrayStatus::WriteParked or reuse Error
}
```

### Anti-Patterns to Avoid

- **Spawning the thread before journaling:** The current bug is exactly this — thread spawn happens inside the `prepare_result` closure (`read_ops.rs:791`) before `reply.ok()`. The journal fsync must happen first.
- **Storing plaintext or raw key bytes in the journal:** Security rule — journal must contain only ciphertext + ECIES-wrapped keys. The existing `cipherbox_crypto::ecies::wrap_key` call at `read_ops.rs:682-685` produces the wrapped key before the thread spawn; the journal captures that wrapped form.
- **Replaying the stale parent snapshot:** D-06 explicitly forbids re-publishing the parent metadata snapshot captured at write time. The replay path must fetch-and-merge into the current remote state.
- **Using inode numbers as journal identifiers:** D-02; inodes are remount-transient. The inode table is rebuilt from IPNS metadata on every mount. IPNS names are the stable identifiers.
- **Marking entries as `max_retries -> drop`:** The existing `WriteQueue.process()` drops items silently on `retries > max_retries` (`queue.rs:98-106`). D-09 abolishes this — use `Failed` status instead.
- **Blocking network I/O in FUSE callbacks:** The single-threaded constraint on macOS FUSE callbacks (`read_ops.rs:791` uses `std::thread::spawn` precisely to avoid this). The journal fsync is local I/O only; network work stays in the background drain.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
| --- | --- | --- | --- |
| fsync on macOS | Custom `fcntl(F_FULLFSYNC)` | `std::fs::File::sync_all()` | Rust std calls `F_FULLFSYNC` on macOS automatically since 1.x; see `file_handle.rs:207` for existing usage |
| OS notification | Custom platform notification | `tauri_plugin_notification` (already installed) | Already used in `tray/mod.rs:324` and `updater.rs:40` |
| Serialization | Custom binary format | `serde_json` (already in sdk Cargo.toml) | json is human-debuggable, already used in `registry.rs:112` |
| IPNS conflict retry | Manual sequence re-fetch inline | Existing `PublishCoordinator.resolve_sequence()` | Already handles stale-cache fallback; at `lib.rs:214-238` |
| Parent metadata merge | Custom merge logic | Existing `merge_folder_children()` in `lib.rs:275-327` | Already handles concurrent-edit merge; use this for replay upsert |
| Unique entry IDs | uuid crate (not in workspace) | `hex::encode(cipherbox_crypto::utils::generate_random_bytes(16))` | 128-bit random hex, no new dep |

**Key insight:** The hardest part is not the journal format — it's the ordering of operations inside the FUSE callback (encrypt → journal-fsync → ack → cleanup). The infrastructure for everything else (retry, merge, publish, notify) already exists in the codebase.

## Runtime State Inventory

> This is a Rust-only implementation phase targeting crash-recovery behavior; no rename/rebrand.

Not applicable. This is a greenfield addition of the journal, not a rename/migration.

## Common Pitfalls

### Pitfall 1: Forgetting to bump write_generation before the journal fsync

**What goes wrong:** The `write_generation` field (`inode.rs:177`) guards against stale background uploads overwriting newer content. If two writes happen before the first drain, the second write must bump the generation BEFORE the journal entry for write 1 is fsynced — otherwise drain 1 can arrive after drain 2 and corrupt the file.

**Why it happens:** `write_generation` is currently bumped on inode update inside the prepare closure (`read_ops.rs:759`, Windows `write_ops.rs:786`), which is before the spawn. The new journal path must preserve this ordering.

**How to avoid:** Bump `write_generation`, capture it in the `JournalEntry`, and verify it in `drain_upload_completions` exactly as today. The existing `UploadComplete.write_generation` check at `lib.rs:661` already handles stale drain.

**Warning signs:** File content reverts to previous version after concurrent writes.

### Pitfall 2: Double-journaling on write_ops.rs macOS mkdir vs Windows handle_cleanup

**What goes wrong:** macOS/Linux `handle_mkdir` is in `crates/fuse/src/write_ops.rs`; Windows mkdir is in `crates/fuse/src/platform/windows/write_ops.rs`. Both must journal `MkdirPublish`. A plan that only patches one location will leave Windows orphaning.

**Why it happens:** Windows uses `handle_cleanup` for the release equivalent (`write_ops.rs:488`), not `handle_release`. The code duplication between the two platforms is intentional (WinFsp API differences).

**How to avoid:** D-12 mandates separate plans. The Windows plan must mirror every change made in the fuser plan for both release and mkdir.

**Warning signs:** Integration tests pass on macOS CI but crash-recovery fails on Windows E2E.

### Pitfall 3: Journal directory not accessible before mount

**What goes wrong:** If the journal directory is placed inside the temp dir (`std::env::temp_dir().join("cipherbox")` — the current pattern at `fuse/mod.rs:94`), it shares the same location as plaintext temp files. A race between journal creation and temp file cleanup could mix concerns, and the temp dir may be cleared by the OS across reboots.

**Why it happens:** Current temp_dir usage for write buffers is session-scoped (expected to be cleared); the journal must survive reboots.

**How to avoid:** Place the journal in a stable app-data directory. On macOS: `~/Library/Application Support/com.cipherbox.desktop/cb-journal/`. The Tauri `app_data_dir()` resolver (`tauri::Manager` + `path().app_data_dir()`) returns the correct path on all platforms. Alternatively, use `dirs::data_local_dir()` (already in fuse Cargo.toml) since it doesn't require an AppHandle in the sdk crate.

**Warning signs:** Journal entries disappear after reboot; replay never recovers data.

### Pitfall 4: Replay re-uses the stale parent snapshot from the journal entry

**What goes wrong:** If replay calls `publish_ipns` with the parent metadata that was captured at write time (before the crash), it stomps any changes other clients made between the crash and the replay. This is the multi-device lost-update class.

**Why it happens:** The easiest replay implementation is "re-publish what we captured." D-06 explicitly forbids this.

**How to avoid:** Replay must: (1) fetch current parent IPNS → decrypt metadata, (2) merge the journaled child entry via `merge_folder_children()`, (3) CAS-publish with fresh sequence. The `resolve_sequence` + `PublishResult::Conflict` retry loop already exists in the codebase.

**Warning signs:** Another device's file disappears from the parent folder after the journaling device reboots.

### Pitfall 5: Child IPNS already published at seq 0 when MkdirPublish replays

**What goes wrong:** On mkdir crash, the child folder's initial IPNS record (seq 0) may already have been published successfully before the crash. On replay, re-publishing seq 0 will either be a no-op (if the API is idempotent) or cause a conflict. The issue is only with the PARENT publish, not the child.

**Why it happens:** The mkdir thread publishes child first, then parent (both in the same background thread; `write_ops.rs:544-610`). Crash after child publish but before parent publish is the orphan scenario.

**How to avoid:** The `MkdirPublish` journal entry only needs to replay the PARENT publish step (with fetch-and-merge). On replay, check that the child IPNS name is already present in the fetched parent metadata before merging — if it is, skip the merge (idempotent). Seq 0 re-publish of the child can be tried but expect and handle `Conflict` gracefully.

**Warning signs:** Replay fails with sequence conflict on the child publish and gives up, leaving the parent still un-updated.

## Code Examples

### Existing journal-adjacent patterns

```rust
// Source: crates/fuse/src/file_handle.rs:193-216
// Existing zeroize+delete pattern (cleanup) — used by journal on plaintext temp after fsync:
pub fn cleanup(&self) {
    if let Some(ref temp_path) = self.temp_path {
        if temp_path.exists() {
            if let Ok(size) = fs::metadata(temp_path).map(|m| m.len()) {
                if size > 0 {
                    if let Ok(mut file) = fs::OpenOptions::new().write(true).open(temp_path) {
                        let zeros = vec![0u8; std::cmp::min(size as usize, 64 * 1024)];
                        // ... zero-write loop ...
                        let _ = file.sync_all();  // fsync pattern already present
                    }
                }
            }
            let _ = fs::remove_file(temp_path);
        }
    }
}
```

```rust
// Source: crates/fuse/src/lib.rs:680-693
// Existing debounced publish queue / mutated_folders pattern:
pub fn queue_publish(&mut self, folder_ino: u64, has_pending_upload: bool) {
    let entry = self.publish_queue.entry(folder_ino).or_insert(
        PublishQueueEntry { first_dirty: Instant::now(), pending_uploads: 0 }
    );
    if has_pending_upload { entry.pending_uploads += 1; }
    self.mutated_folders.insert(folder_ino, Instant::now());
}
// flush_publish_queue fires when pending_uploads == 0 && elapsed >= debounce.
// The journal drain must decrement pending_uploads via the UploadComplete channel
// (same as today) so this gate still works.
```

```rust
// Source: crates/fuse/src/lib.rs:274-327
// Existing merge_folder_children — used by replay:
pub fn merge_folder_children(local: &FolderMetadata, remote: FolderMetadata) -> FolderMetadata {
    // Walks remote children, replacing with local version if same IPNS key
    // Appends local-only entries not found in remote
    // ...
}
// Replay upsert: treat the journaled child entry as "local"; fetched remote as "remote".
```

```rust
// Source: apps/desktop/src-tauri/src/sync/mod.rs:29-37
// Existing SyncStatus -> TrayStatus bridge — extend for WriteParked:
let status_callback = Arc::new(move |status: SyncStatus| {
    let tray_status = match status {
        SyncStatus::Idle => TrayStatus::Synced,
        SyncStatus::Syncing => TrayStatus::Syncing,
        SyncStatus::Error(ref e) if e == "Offline" => TrayStatus::Offline,
        SyncStatus::Error(e) => TrayStatus::Error(e),
        // ADD: SyncStatus::WriteParked { failed, .. } if failed > 0 => send notification
    };
    let _ = update_tray_status(&app, &tray_status);
});
```

```rust
// Source: apps/desktop/src-tauri/src/tray/mod.rs:323-330
// Existing notification pattern:
fn send_error_notification(app: &AppHandle, message: &str) -> Result<(), String> {
    use tauri_plugin_notification::NotificationExt;
    app.notification()
        .builder()
        .title("CipherBox Error")
        .body(message)
        .show()
        .map_err(|e| format!("Notification failed: {}", e))?;
    Ok(())
}
// Park notification reuses this pattern with a distinct title/body.
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
| --- | --- | --- | --- |
| Memory-only WriteQueue | Persist-backed journal (this phase) | Phase 43 | Crash-safe writes |
| Detached thread acks release | fsync-then-ack | Phase 43 | No false durability |
| warn-only on mkdir conflict | actual retry signal | Phase 43 | No orphaned folders |
| max_retries → silent drop | park as failed, keep on disk | Phase 43 | No silent data loss |

**Deprecated/outdated (this phase supersedes):**

- `QueuedWrite.parent_ino` field: inode-based identifier, not stable across remount; replaced by `parent_folder_ipns_name`.
- Comment at `write_ops.rs:583-584`: "Debounced publish will retry" — false; replaced by actual retry behavior.
- Comment at `queue.rs:6-7`: "Memory-only queue per CONTEXT.md" — superseded by D-01.

## Open Questions (RESOLVED)

1. **Journal directory on Linux** — RESOLVED: journal dir path injected from the mount orchestrator (implemented in plan 43-04).
   - What we know: `dirs::data_local_dir()` returns `~/.local/share` on Linux; app-specific subdirectory would be `~/.local/share/com.cipherbox.desktop/cb-journal/`.
   - What's unclear: Whether the Tauri `app_data_dir()` resolver is accessible from `crates/sdk` (it requires an AppHandle) or whether `dirs::data_local_dir()` should be used instead in sdk, with the concrete path injected at mount time from `apps/desktop`.
   - Recommendation: Inject the journal dir path into `WriteQueue::new(path)` from the mount orchestrator (in `apps/desktop/src-tauri/src/fuse/mod.rs`) — sdk never calls Tauri APIs directly.

2. **New channel variant for mkdir conflict vs reusing UploadComplete** — RESOLVED: `FsEvent` enum with `UploadComplete` and `MkdirConflict { parent_ino }` variants (implemented in plan 43-02).
   - What we know: `UploadComplete` carries `ino, new_cid, parent_ino, old_file_cid, pruned_cids, write_generation` — none of these fields make sense for a mkdir conflict signal.
   - What's unclear: Whether to add a new enum variant to an existing channel enum or create a new `MkdirConflict` mpsc channel.
   - Recommendation: Add a `FsEvent` enum with `UploadComplete` and `MkdirConflict { parent_ino }` variants to the existing mpsc channel. Minimizes new channels while keeping types clear.

3. **Replay at mount vs at login** — RESOLVED: replay in `mount_filesystem()` after the pre-populate step (implemented in plan 43-04).
   - What we know: `mount_filesystem()` in `fuse/mod.rs` runs after key material is available. The journal requires the public key for ECIES unwrapping on replay.
   - What's unclear: Whether replay belongs in `mount_filesystem()` or in an earlier auth step.
   - Recommendation: Replay in `mount_filesystem()` after the pre-populate step, since key material is already available there and the IPNS sequence numbers are already seeded.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
| --- | --- | --- | --- | --- |
| `std::fs::File::sync_all()` | Journal fsync barrier | Yes (std) | rustc workspace | — |
| `serde_json` | Journal serialization | Yes | workspace | — |
| `tauri_plugin_notification` | Park notification | Yes | 2.x (Cargo.toml:24) | Log only |
| `dirs` crate | Journal dir path (sdk) | Yes | workspace 5.x | Inject path from Tauri AppHandle |

## Validation Architecture

### Test Framework

| Property | Value |
| --- | --- |
| Framework | Rust built-in `#[test]` + `#[tokio::test]` (no jest/vitest) |
| Config file | none (cargo test per crate) |
| Quick run command | `cargo test -p cipherbox-sdk -- queue` |
| Full suite command | `cargo test -p cipherbox-sdk && cargo test -p cipherbox-fuse` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
| --- | --- | --- | --- | --- |
| REQ-43-C | JournalEntry round-trip serialize/deserialize | unit | `cargo test -p cipherbox-sdk -- queue::tests` | No — Wave 0 |
| REQ-43-C | `put` writes file to disk and `load_all` returns it | unit | `cargo test -p cipherbox-sdk -- queue::tests::journal_put_load` | No — Wave 0 |
| REQ-43-C | `remove` deletes the file | unit | `cargo test -p cipherbox-sdk -- queue::tests::journal_remove` | No — Wave 0 |
| REQ-43-F | Entry transitions to `Failed` after max retries | unit | `cargo test -p cipherbox-sdk -- queue::tests::park_on_max_retries` | No — Wave 0 |
| REQ-43-D | Plaintext not present in journal file | unit | `cargo test -p cipherbox-sdk -- queue::tests::journal_no_plaintext` | No — Wave 0 |
| REQ-43-E | Replay ordering: MkdirPublish before UploadFile | unit | `cargo test -p cipherbox-sdk -- queue::tests::replay_order` | No — Wave 0 |

### Sampling Rate

- **Per task commit:** `cargo test -p cipherbox-sdk -- queue`
- **Per wave merge:** `cargo test -p cipherbox-sdk && cargo test -p cipherbox-fuse`
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps

- `crates/sdk/src/queue.rs` unit tests — needs full rewrite to cover new `JournalEntry` shape
- No existing integration tests for fuse platform code (no `crates/fuse/tests/`; testing is via in-module `#[cfg(test)]`)
- Framework install: none needed — `tokio` dev-dep already in `crates/sdk/Cargo.toml`

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
| --- | --- | --- |
| V2 Authentication | no | — |
| V3 Session Management | no | — |
| V4 Access Control | no | — |
| V5 Input Validation | yes | Journal entries read back from disk must be validated (serde_json::from_slice returns Err on malformed; handle gracefully) |
| V6 Cryptography | yes | Journal stores ciphertext + ECIES-wrapped key only; never plaintext; zeroize after use |

### Known Threat Patterns for FUSE + persistent journal

| Pattern | STRIDE | Standard Mitigation |
| --- | --- | --- |
| Journal file contains plaintext | Information Disclosure | D-05: encrypt before journal write; zeroize temp after fsync |
| Journal file readable by other processes | Information Disclosure | `0o600` permissions on journal files (same as current temp file pattern at `file_handle.rs:91`) |
| Malformed journal entry on replay causes panic | Tampering / DoS | `serde_json::from_slice` returns `Err`; skip corrupt entries with warn log, don't panic |
| Stale journal entry re-published after multi-device update | Tampering | D-06: fetch-and-merge, never re-publish captured snapshot |
| IPNS private key in journal (raw bytes) | Information Disclosure | D-05: journal stores ECIES-wrapped key only; `cipherbox_crypto::ecies::wrap_key` already called before thread spawn in current code |

## Project Constraints (from CLAUDE.md)

- TypeScript enums → string literals (not applicable: Rust phase)
- Use `Uint8Array` for binary data, not strings (Rust: use `Vec<u8>`)
- Use camelCase for API fields (not applicable: no API changes in this phase)
- **Never** store `privateKey` in localStorage or log sensitive keys
- **Never** persist plaintext or raw keys (enforced by D-05)
- **Always** use ECIES for key wrapping (already done in current release path; journal captures output)
- **Always** use AES-256-GCM for content encryption (already done; journal captures ciphertext)
- Run `pnpm api:generate` after modifying API endpoints (not applicable: no API changes)
- Never push directly to main; use feature branches
- Commit format: Conventional Commits (`feat`, `fix`, `chore`, etc.)
- Markdownlint on commit: use headings not bold-as-heading, blank lines around code blocks/lists

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
| --- | --- | --- | --- |
| A1 | `std::fs::File::sync_all()` calls `F_FULLFSYNC` on macOS | Standard Stack | Low; confirmed by Rust std docs (internal `fcntl(F_FULLFSYNC)` since 2015). If wrong, use `libc::fcntl` directly. |
| A2 | One-file-per-entry JSON chosen for journal format (Claude's Discretion) | Architecture | Low; can switch to append log without changing the API contract |
| A3 | Journal directory injected from mount orchestrator rather than using Tauri AppHandle inside sdk | Open Questions | Low; alternative is `dirs::data_local_dir()` directly in sdk |

## Sources

### Primary (HIGH confidence)

- Direct codebase reads:
  - `crates/fuse/src/read_ops.rs:650-854` — release path anatomy, confirmed false-ack location
  - `crates/fuse/src/write_ops.rs:430-631` — mkdir thread, conflict arm at lines 602-609
  - `crates/fuse/src/platform/windows/write_ops.rs:488-868` — Windows cleanup/mkdir mirror
  - `crates/sdk/src/queue.rs` — current WriteQueue shape, max_retries-drop behavior
  - `crates/sdk/src/state.rs` — SyncStatus variants, extension point
  - `crates/sdk/src/sync.rs` — SyncDaemon, Arc<dyn Fn(SyncStatus)> callback channel
  - `crates/fuse/src/lib.rs:534-694` — CipherBoxFS struct, queue_publish, mutated_folders, merge_folder_children
  - `crates/fuse/src/file_handle.rs` — cleanup pattern, sync_all usage at line 207
  - `apps/desktop/src-tauri/src/fuse/mod.rs` — mount_filesystem, temp_dir location
  - `apps/desktop/src-tauri/src/tray/mod.rs` — TrayStatus, notification pattern
  - `apps/desktop/src-tauri/src/sync/mod.rs` — SyncStatus bridge
  - `apps/desktop/src-tauri/Cargo.toml` — tauri_plugin_notification at version 2

### Secondary (MEDIUM confidence)

- CONTEXT.md decisions D-01 through D-12 — user decisions from discuss phase
- Todo files (`2026-06-11-fuse-release-data-loss-before-remote-commit.md`, `2026-06-11-fuse-mkdir-parent-publish-orphan.md`) — confirmed file/line references match code read

### Tertiary (LOW confidence)

- None — all claims sourced from direct codebase inspection or locked decisions.

## Metadata

**Confidence breakdown:**

- Standard Stack: HIGH — all libraries confirmed present in Cargo.toml; no new deps needed
- Architecture: HIGH — based on direct code reads of all relevant files
- Pitfalls: HIGH — derived from reading the actual bug locations in the code

**Research date:** 2026-06-12
**Valid until:** 2026-07-12 (stable Rust codebase; valid until significant fuse refactor)
