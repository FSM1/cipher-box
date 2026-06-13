# Phase 43: FUSE Write Durability - Pattern Map

**Mapped:** 2026-06-12
**Files analyzed:** 7
**Analogs found:** 7 / 7

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
| --- | --- | --- | --- | --- |
| `crates/sdk/src/queue.rs` | service (journal) | file-I/O + batch | `crates/sdk/src/queue.rs` (current) | rewrite of existing |
| `crates/sdk/src/state.rs` | model | event-driven | `crates/sdk/src/state.rs` (current) | extend existing |
| `crates/fuse/src/read_ops.rs` | service (FUSE callback) | file-I/O + request-response | `crates/fuse/src/read_ops.rs` (current) | modify existing |
| `crates/fuse/src/write_ops.rs` | service (FUSE callback) | request-response | `crates/fuse/src/write_ops.rs` (current) | modify existing |
| `crates/fuse/src/platform/windows/write_ops.rs` | service (WinFsp callback) | request-response | `crates/fuse/src/platform/windows/write_ops.rs` (current) | modify existing |
| `apps/desktop/src-tauri/src/fuse/mod.rs` | provider (mount orchestrator) | request-response | `apps/desktop/src-tauri/src/fuse/mod.rs` (current) | modify existing |
| `apps/desktop/src-tauri/src/sync/mod.rs` | provider (bridge) | event-driven | `apps/desktop/src-tauri/src/sync/mod.rs` (current) | modify existing |

## Pattern Assignments

### `crates/sdk/src/queue.rs` (journal service, file-I/O + batch)

**Analog:** `crates/sdk/src/queue.rs` (full rewrite, same file)

**Current struct shape to replace** (lines 14-31):

```rust
pub struct QueuedWrite {
    pub id: String,
    pub parent_ino: u64,           // REMOVE: inode not stable across remount (D-02)
    pub encrypted_content: Vec<u8>,
    pub encrypted_file_key: Vec<u8>,
    pub iv: Vec<u8>,
    pub filename: String,
    pub created_at: Instant,       // REPLACE: Instant is not serializable
    pub retries: u32,
}
```

**New entry shape (D-02, D-03) — copy field names and doc-comment style from above:**

```rust
// serde derives follow the pattern in crates/sdk/src/state.rs (derive Debug, Clone, PartialEq)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JournalOp {
    UploadFile {
        ciphertext_b64: String,         // base64-encoded AES-256-GCM ciphertext
        wrapped_key_hex: String,        // ECIES-wrapped file key, hex
        iv_hex: String,
        file_meta_ipns_name: String,    // stable cross-remount (D-02)
        file_ipns_key_hex: Option<String>,
        parent_folder_ipns_name: String,
        filename: String,
        size: u64,
        created_at_ms: u64,             // ms since epoch, serializable
    },
    MkdirPublish {
        child_ipns_name: String,
        child_folder_key_hex: String,
        child_ipns_key_hex: String,
        parent_folder_ipns_name: String,
        name: String,
        created_at_ms: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JournalEntryStatus {
    Pending,
    InProgress,
    Failed { last_error: String },      // D-09: never drop, park instead
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    pub id: String,                     // hex::encode(generate_random_bytes(16))
    pub vault_root_ipns: String,        // D-07: vault-scoped replay
    pub op: JournalOp,
    pub retries: u32,
    pub status: JournalEntryStatus,
}
```

**WriteQueue struct replacement** — replace `VecDeque` + `max_retries` with path-backed journal:

```rust
pub struct WriteQueue {
    journal_dir: std::path::PathBuf,    // injected at new(); never calls Tauri APIs (A3)
    max_retries: u32,
}

impl WriteQueue {
    pub fn new(journal_dir: std::path::PathBuf, max_retries: u32) -> Self { ... }
    pub fn put(&self, entry: &JournalEntry) -> Result<(), String> { ... }   // write + sync_all
    pub fn remove(&self, id: &str) -> Result<(), String> { ... }            // fs::remove_file
    pub fn load_all_for_vault(&self, vault_root_ipns: &str) -> Result<Vec<JournalEntry>, String> { ... }
    pub fn update_status(&self, id: &str, status: JournalEntryStatus) -> Result<(), String> { ... }
}
```

**fsync pattern** — copy from `crates/fuse/src/file_handle.rs:207` (existing `file.sync_all()`):

```rust
// file_handle.rs:199-207 — established project sync_all pattern:
let mut f = std::fs::OpenOptions::new().write(true).create(true).open(&path)
    .map_err(|e| format!("Journal write failed: {}", e))?;
use std::io::Write;
f.write_all(&json)?;
f.sync_all()
    .map_err(|e| format!("Journal fsync failed: {}", e))?;
// 0o600 permissions follow file_handle.rs:91 pattern
#[cfg(unix)]
{
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
}
```

**Retry / park pattern** — replace lines 97-106 (current silent drop) with park:

```rust
// CURRENT (lines 97-106): items exceeding max_retries are dropped
if item.retries > self.max_retries {
    log::error!("Queued write dropped ...");  // data loss
} else { remaining.push_back(item); }

// NEW (D-09): transition to Failed status, keep on disk, fire SyncStatus callback
if entry.retries >= self.max_retries {
    let status = JournalEntryStatus::Failed { last_error: e.clone() };
    let _ = self.update_status(&entry.id, status);
    // caller receives Err to trigger SyncStatus::WriteParked
} else {
    entry.retries += 1;
    let _ = self.update_status(&entry.id, JournalEntryStatus::Pending);
}
```

**Test pattern** — copy mock handler pattern from lines 201-215; add `#[tokio::test]` wrappers matching lines 216-282 style; use `tempfile::TempDir` or `std::env::temp_dir()` for journal dir in tests.

---

### `crates/sdk/src/state.rs` (model, event-driven)

**Analog:** `crates/sdk/src/state.rs` (extend existing)

**SyncStatus extension point** (lines 16-20 — current variants):

```rust
// Current (lines 16-20):
pub enum SyncStatus {
    Idle,
    Syncing,
    Error(String),
}

// Add after Error (D-10):
// WriteParked { pending: u32, failed: u32 }
```

**Derive pattern** — match existing `#[derive(Debug, Clone, PartialEq)]` on `SyncStatus`.

**Test pattern** — copy `sync_status_variants` test at lines 211-220; add parallel test for `WriteParked` variant.

---

### `crates/fuse/src/read_ops.rs` (FUSE callback, file-I/O)

**Analog:** `crates/fuse/src/read_ops.rs` (modify `handle_release`, lines 650-848)

**Current operation order at lines 791-848 (the bug):**

```rust
// Lines 791-835: thread spawned BEFORE reply.ok() and BEFORE handle.cleanup()
std::thread::spawn(move || { ... upload ... });
// ...
handle.cleanup();   // line 844 — plaintext deleted AFTER spawn
reply.ok();         // line 848 — acks OS after spawn, not after fsync
```

**New operation order (D-04, D-05):**

```rust
// 1. encrypt (existing lines 674-687 — keep as-is)
let ciphertext = ...;
let wrapped_key = cipherbox_crypto::ecies::wrap_key(&file_key, &fs.public_key)?;
cipherbox_crypto::utils::clear_bytes(&mut file_key);

// 2. journal.put(entry) + fsync barrier (D-04)
let entry = JournalEntry { id: ..., vault_root_ipns: fs.root_ipns_name.clone(), op: JournalOp::UploadFile { ... }, retries: 0, status: JournalEntryStatus::Pending };
fs.journal.put(&entry)?;   // write + sync_all inside put()

// 3. zeroize + delete plaintext NOW (D-05) — move handle.cleanup() here, before spawn
handle.cleanup();

// 4. ack OS (line 848 pattern — reply.ok() fires after local fsync only)
reply.ok();

// 5. spawn background drain — same std::thread::spawn + rt.block_on pattern as lines 791-835
std::thread::spawn(move || { ... upload ... journal.remove(entry_id) on success ... });
```

**write_generation capture** — keep lines 759-761 ordering (bump before journal entry, capture in JournalEntry):

```rust
// Lines 759-761 — write_generation captured BEFORE spawn; preserve this ordering:
let write_gen = fs.inodes.get(ino).map(|i| i.write_generation).unwrap_or(0);
```

**UploadComplete channel** — lines 799-806, keep `upload_tx.send(UploadComplete { ... })` unchanged inside the background thread.

**flush no-op** (line 852-854) — candidate for journal fsync delegation; if needed, the flush handler can call `journal.put()` as an alternative barrier site. Keep as no-op unless D-04 design requires it.

---

### `crates/fuse/src/write_ops.rs` (FUSE callback, request-response)

**Analog:** `crates/fuse/src/write_ops.rs` (modify `handle_mkdir` conflict arm, lines 430-617)

**Journal entry before reply.entry()** (D-03, D-04) — insert after line 480 (fuse_attr built) and before `std::thread::spawn` at line 516:

```rust
// After fuse_attr is built (line 462), before thread spawn (line 516):
let mkdir_entry = JournalEntry {
    id: hex::encode(cipherbox_crypto::utils::generate_random_bytes(16)),
    vault_root_ipns: fs.root_ipns_name.clone(),
    op: JournalOp::MkdirPublish {
        child_ipns_name: ipns_name.clone(),
        child_folder_key_hex: encrypted_folder_key_hex.clone(),
        child_ipns_key_hex: encrypted_ipns_for_tee.clone().unwrap_or_default(),
        parent_folder_ipns_name: parent_ipns_name.clone(),
        name: name_str.to_string(),
        created_at_ms: ...,
    },
    retries: 0,
    status: JournalEntryStatus::Pending,
};
fs.journal.put(&mkdir_entry)?;
// reply.entry() fires after this fsync — ack barrier (D-04)
```

**Conflict arm replacement** (lines 602-609 — the false "will retry" comment):

```rust
// CURRENT (lines 602-609):
cipherbox_api_client::PublishResult::Conflict { current_sequence_number } => {
    log::warn!("Conflict on parent publish after mkdir... Debounced publish will retry.");
    // Do not record_publish -- nothing actually retries
}

// NEW (D-11): signal FS thread via upload_tx to insert parent into mutated_folders
cipherbox_api_client::PublishResult::Conflict { current_sequence_number } => {
    log::warn!("Conflict on parent mkdir publish (seq {} -> {}). Signalling retry.", seq, current_sequence_number);
    let _ = upload_tx.send(FsEvent::MkdirConflict { parent_ino });
    // Journal entry stays until parent publish confirms (D-11b)
}
```

**FsEvent enum** (new, replaces bare `UploadComplete` channel type — open question from RESEARCH.md):

```rust
// New enum wrapping both channel message types; add to crates/fuse/src/lib.rs near UploadComplete:
pub enum FsEvent {
    UploadComplete(UploadComplete),
    MkdirConflict { parent_ino: u64 },
}
// Change upload_rx / upload_tx type from mpsc::*<UploadComplete> to mpsc::*<FsEvent>
// drain_upload_completions() matches on FsEvent — adds mutated_folders.insert(parent_ino, Instant::now()) arm
```

**Channel pattern source** — `crates/fuse/src/lib.rs:566-567` (upload_tx / upload_rx declaration), `lib.rs:653-671` (drain_upload_completions usage).

---

### `crates/fuse/src/platform/windows/write_ops.rs` (WinFsp callback, request-response)

**Analog:** `crates/fuse/src/platform/windows/write_ops.rs` (mirror of fuser changes)

**handle_cleanup release path** (lines 821-865) — mirrors `read_ops.rs handle_release`:

```rust
// Lines 821-856: same thread-spawn-first bug as macOS read_ops.rs:791
std::thread::spawn(move || { ... upload ... });
// line 865: handle.cleanup() after spawn
```

Apply identical operation reorder as `read_ops.rs`: journal.put + fsync → cleanup() → (no ack; WinFsp cleanup has no reply) → spawn drain.

Note: WinFsp `handle_cleanup` has no `reply.ok()` — ack is implicit. The fsync barrier still protects against crash-before-spawn.

**mkdir conflict arm** (line ~194, confirmed by grep):

```rust
// Lines 192-194 (Windows mirror of write_ops.rs:602-609):
// TODO: Add full re-fetch+merge+retry for parent mkdir publish (v2).
// On conflict, log warning only.
```

Apply same FsEvent::MkdirConflict signal as macOS write_ops.rs conflict arm.

**Pattern note:** Windows `handle_cleanup` uses `ctx.inner.lock().unwrap()` (line 497) for FS access — ensure journal path is accessible from `WinFspContext` the same way `CipherBoxFS` fields are accessed in the fuser path.

---

### `apps/desktop/src-tauri/src/fuse/mod.rs` (mount orchestrator, request-response)

**Analog:** `apps/desktop/src-tauri/src/fuse/mod.rs` (modify `mount_filesystem`, lines 50-120+)

**Journal dir injection point** (after temp_dir at line 94):

```rust
// Lines 94-100: temp_dir created here — journal goes in stable app-data, not temp (Pitfall 3)
let temp_dir = std::env::temp_dir().join("cipherbox");  // session-scoped, keep

// ADD after temp_dir setup:
let journal_dir = app_handle
    .path()
    .app_data_dir()
    .map_err(|e| format!("Failed to resolve app data dir: {}", e))?
    .join("cb-journal");
std::fs::create_dir_all(&journal_dir)
    .map_err(|e| format!("Failed to create journal dir: {}", e))?;
#[cfg(unix)]
{
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&journal_dir, std::fs::Permissions::from_mode(0o700));
}
let journal = cipherbox_sdk::WriteQueue::new(journal_dir, 5);
```

**Replay call point** — after pre-populate (after line ~120 where root metadata is fetched):

```rust
// After pre-populate, before fuser::mount:
log::info!("Replaying durable write journal for vault {}...", root_ipns_name);
journal.replay_for_vault(&root_ipns_name, &api, &public_key, ...).await
    .unwrap_or_else(|e| log::warn!("Journal replay completed with errors: {}", e));
```

**CipherBoxFS construction** — inject `journal` into `CipherBoxFS::new(...)`. Add `pub journal: WriteQueue` field to `CipherBoxFS` struct in `crates/fuse/src/lib.rs` alongside existing fields at lines 534-570.

---

### `apps/desktop/src-tauri/src/sync/mod.rs` (bridge, event-driven)

**Analog:** `apps/desktop/src-tauri/src/sync/mod.rs` (modify `create_sync_daemon`, lines 29-38)

**SyncStatus bridge extension** (lines 31-37):

```rust
// Current (lines 31-37):
let tray_status = match status {
    SyncStatus::Idle => crate::tray::TrayStatus::Synced,
    SyncStatus::Syncing => crate::tray::TrayStatus::Syncing,
    SyncStatus::Error(ref e) if e == "Offline" => crate::tray::TrayStatus::Offline,
    SyncStatus::Error(e) => crate::tray::TrayStatus::Error(e),
    // non-exhaustive — add WriteParked here
};

// ADD match arm (D-10):
SyncStatus::WriteParked { ref failed, .. } if *failed > 0 => {
    // Trigger OS notification — same pattern as tray/mod.rs:323-330
    let msg = format!("{} file upload(s) failed and require attention.", failed);
    if let Err(e) = send_write_parked_notification(&app, &msg) {
        log::warn!("Failed to send park notification: {}", e);
    }
    crate::tray::TrayStatus::Error(msg)
}
SyncStatus::WriteParked { .. } => crate::tray::TrayStatus::Syncing,
```

## Shared Patterns

### fsync Barrier

**Source:** `crates/fuse/src/file_handle.rs:199-216`

**Apply to:** `WriteQueue::put()`, and optionally `handle_release`/`handle_cleanup` if journal.put() doesn't own the sync_all.

```rust
// file_handle.rs:206-207 — existing project pattern for sync_all:
let _ = file.sync_all();  // F_FULLFSYNC on macOS via Rust std; no libc needed
```

### OS Notification

**Source:** `apps/desktop/src-tauri/src/tray/mod.rs:322-332`

**Apply to:** `sync/mod.rs` WriteParked arm; new `send_write_parked_notification` function mirrors `send_error_notification`.

```rust
// tray/mod.rs:323-332:
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
// Copy this function; change title to "CipherBox Upload Failed" for park notification.
```

### Channel-Based FS Thread Signaling

**Source:** `crates/fuse/src/lib.rs:566-567` (channel declaration), `lib.rs:653-671` (drain loop)

**Apply to:** New `FsEvent::MkdirConflict` variant; extend `drain_upload_completions` match arm.

```rust
// lib.rs:654 — existing drain pattern to extend:
while let Ok(result) = self.upload_rx.try_recv() {
    // ADD: match on FsEvent instead of UploadComplete directly
    match result {
        FsEvent::UploadComplete(uc) => { /* existing lines 655-669 */ }
        FsEvent::MkdirConflict { parent_ino } => {
            self.mutated_folders.insert(parent_ino, std::time::Instant::now());
            // queue_publish with has_pending_upload=false so debounce fires on next cycle
            self.queue_publish(parent_ino, false);
        }
    }
}
```

### Temp File Permissions

**Source:** `crates/fuse/src/file_handle.rs:88-92`

**Apply to:** Journal file creation in `WriteQueue::put()`.

```rust
// file_handle.rs:88-92:
#[cfg(unix)]
{
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600));
}
```

### zeroize After Use

**Source:** `crates/fuse/src/read_ops.rs:687` (`clear_bytes`), `crates/sdk/src/state.rs:92-96` (zeroize pattern)

**Apply to:** After encoding plaintext into ciphertext in release path; `handle.cleanup()` must be called before `reply.ok()` (D-05).

```rust
// read_ops.rs:687 — clear_bytes immediately after wrap:
cipherbox_crypto::utils::clear_bytes(&mut file_key);
// Then handle.cleanup() for plaintext temp — move to BEFORE reply.ok()
```

## No Analog Found

All files have direct analogs in the codebase. No new-from-scratch files required.

## Metadata

**Analog search scope:** `crates/sdk/src/`, `crates/fuse/src/`, `crates/fuse/src/platform/windows/`, `apps/desktop/src-tauri/src/`

**Files scanned:** 10

**Pattern extraction date:** 2026-06-12
