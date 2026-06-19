# Phase 52: Desktop FUSE Durability & At-Rest Safety - Pattern Map

**Mapped:** 2026-06-19
**Files analyzed:** 8
**Analogs found:** 8 / 8

## File Classification

| New/Modified File                                    | Role      | Data Flow  | Closest Analog (same file or nearest)               | Match Quality |
| ---------------------------------------------------- | --------- | ---------- | --------------------------------------------------- | ------------- |
| `crates/sdk/src/queue.rs`                            | service   | file-I/O   | Same file — `WriteQueue::put` (lines 171-200)       | exact         |
| `crates/sdk/src/sync.rs`                             | utility   | transform  | Same file — `regex_replace_paths` (lines 266-285)   | exact         |
| `crates/fuse/src/lib.rs`                             | service   | event-driven | Same file — `NETWORK_TIMEOUT` + `rt.spawn` pattern (lines 59, 1282-1295) | exact |
| `crates/fuse/src/write_ops.rs`                       | service   | file-I/O   | Same file — swallowed removal at line 679           | exact         |
| `crates/fuse/src/journal_helpers.rs`                 | utility   | transform  | Same file — `wrap_key_to_hex` at line 281, `ciphertext_b64` at lines 284-286 | exact |
| `crates/fuse/src/read_ops.rs`                        | controller | request-response | Same file — durable-ack sequence at lines 814-884 | exact |
| `apps/desktop/src-tauri/src/fuse/mod.rs`             | controller | request-response | Same file — replay call at lines 278-289          | exact         |
| `apps/desktop/src-tauri/src/commands/auth.rs`        | controller | request-response | Same file — `logout()` at lines 490-521           | exact         |

---

## Pattern Assignments

### `crates/sdk/src/queue.rs` (D-01 sidecar write, D-02 GC/purge)

**Analog within file:** `WriteQueue::put` (lines 164-200), `WriteQueue::remove` (lines 203-218), `deser_opt_string` compat helper (lines 22-25).

**0o600 file creation pattern** (lines 177-186) — replicate for sidecar `.bin` write:
```rust
// Source: crates/sdk/src/queue.rs:177-186
let mut open_opts = std::fs::OpenOptions::new();
open_opts.write(true).create(true).truncate(true);
#[cfg(unix)]
open_opts.mode(0o600);

let mut file = open_opts
    .open(&path)
    .map_err(|e| format!("Journal open failed: {}", e))?;
```

**fsync + parent-dir fsync barrier** (lines 188-198) — replicate for both `<id>.bin` and `<id>.json`:
```rust
// Source: crates/sdk/src/queue.rs:188-198
file.write_all(&json)
    .map_err(|e| format!("Journal write failed: {}", e))?;

// fsync barrier: F_FULLFSYNC on macOS, fdatasync on Linux (via Rust std).
file.sync_all()
    .map_err(|e| format!("Journal fsync failed: {}", e))?;

// WR-03b: fsync the parent journal directory so the new dirent is durable.
let _ = std::fs::File::open(&self.journal_dir).and_then(|d| d.sync_all());
```

**Idempotent remove with NotFound guard** (lines 208-218) — extend `remove` to also delete `<id>.bin`:
```rust
// Source: crates/sdk/src/queue.rs:208-218
match std::fs::remove_file(&path) {
    Ok(()) => {
        let _ = std::fs::File::open(&self.journal_dir).and_then(|d| d.sync_all());
        Ok(())
    }
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
    Err(e) => Err(format!("Journal remove failed: {}", e)),
}
```

**Compat deserializer pattern** (lines 22-25) — mirror for `filename_encrypted_hex` / `name_encrypted_hex` field alias:
```rust
// Source: crates/sdk/src/queue.rs:22-25
fn deser_opt_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    let s: Option<String> = Option::deserialize(d)?;
    Ok(s.filter(|v| !v.is_empty()))
}
// New pattern: add #[serde(alias = "filename")] on filename_encrypted_hex field;
// write a parallel custom deserializer that passes plaintext through on legacy entries
// (log::warn! + use value as-is) and hex-decodes ECIES ciphertext on new entries.
```

**`load_all_for_vault` `.json`-only filter** (lines 235-237) — GC scanner must also enumerate `.bin` orphans:
```rust
// Source: crates/sdk/src/queue.rs:235-237
if path.extension().and_then(|e| e.to_str()) != Some("json") {
    continue;
}
// In gc_failed_entries: after purging matched .json, also remove the matching .bin.
// In orphan scan: collect all .bin files with no matching .json and remove them.
```

**`JournalOp::UploadFile` struct fields to modify** (lines 34-67):
```rust
// Source: crates/sdk/src/queue.rs:34-67 (current — replace ciphertext_b64 + filename)
UploadFile {
    ciphertext_b64: String,     // D-01: REPLACE with sidecar_path: PathBuf + sidecar_sha256: String
    // ... other fields unchanged ...
    filename: String,           // D-04: RENAME to filename_encrypted_hex: String (with #[serde(alias="filename")])
    size: u64,
    created_at_ms: u64,
}
// MkdirPublish.name: String  // D-04: RENAME to name_encrypted_hex: String (with #[serde(alias="name")])
```

**New methods to add — signatures consistent with existing `put`/`remove`/`load_all_for_vault`:**
```rust
// New: put_with_sidecar(entry, ciphertext: &[u8]) -> Result<(), String>
//   — streams ciphertext to <id>.bin (0o600), fsyncs, then writes+fsyncs <id>.json.
//   — If .json write fails, removes .bin before returning Err (atomic cleanup).
// New: purge_vault(vault_root_ipns: &str) -> Result<usize, String>
//   — removes all .json + .bin pairs for matching vault_root_ipns.
// New: gc_failed_entries(age_days: u64, total_size_budget: u64) -> Result<usize, String>
//   — loads all entries, filters Failed, sorts by created_at_ms, purges oldest-first.
//   — Also removes .bin files with no matching .json (orphan cleanup).
// Constants (add in queue.rs or a new constants.rs in crates/sdk):
//   pub const MAX_JOURNAL_PAYLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB
//   pub const JOURNAL_GC_MAX_AGE_DAYS: u64 = 30;
//   pub const JOURNAL_GC_MAX_SIZE_BYTES: u64 = 500 * 1024 * 1024; // 500 MiB
```

**Test pattern** (lines 335-440) — all new tests extend the existing `#[cfg(test)] mod tests` at line 335:
```rust
// Source: crates/sdk/src/queue.rs:383-398 — make_temp_queue() helper; reuse as-is
fn make_temp_queue() -> (WriteQueue, std::path::PathBuf) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("cipherbox-journal-test-{}-{}", pid, seq));
    std::fs::create_dir_all(&dir).expect("create test journal dir");
    let q = WriteQueue::new(dir.clone(), 3);
    (q, dir)
}

// Source: crates/sdk/src/queue.rs:432-440 — journal_no_plaintext pattern; extend for D-04
#[test]
fn journal_no_plaintext() { ... }
// New: journal_no_plaintext_filename — assert serialized JSON does NOT contain the
//      raw filename string after D-04 rename to filename_encrypted_hex.
```

---

### `crates/sdk/src/sync.rs` (D-05 sanitize_error path scrub)

**Analog within file:** `regex_replace_paths` (lines 266-285).

**Current scrub logic** (lines 270-283) — extend with additional prefixes:
```rust
// Source: crates/sdk/src/sync.rs:270-283
while let Some((i, c)) = chars.next() {
    if c == '/' && (input[i..].starts_with("/Users/") || input[i..].starts_with("/home/")) {
        result.push_str("[path]");
        // Skip until whitespace or end
        while let Some(&(_, next_c)) = chars.peek() {
            if next_c.is_whitespace() || next_c == '"' || next_c == '\'' {
                break;
            }
            chars.next();
        }
    } else {
        result.push(c);
    }
}
```

**D-05 additions — copy the exact skip-until-whitespace block for each new prefix:**
```rust
// Add to the existing `if c == '/' && (...)` condition:
|| input[i..].starts_with("/var/")
|| input[i..].starts_with("/tmp/")
|| input[i..].starts_with("/private/")

// Add a NEW else-if branch BEFORE the final `else { result.push(c); }`:
} else if c.is_ascii_uppercase()
    && i + 2 < input.len()
    && input[i + 1..].starts_with(":\\Users\\")
{
    // Windows: C:\Users\...  D:\Users\...  etc.
    result.push_str("[path]");
    while let Some(&(_, next_c)) = chars.peek() {
        if next_c.is_whitespace() || next_c == '"' || next_c == '\'' {
            break;
        }
        chars.next();
    }
}
```

**Tests:** Add `#[test] fn sanitize_error_extended_paths()` in the existing `mod tests` in `sync.rs`, asserting `[path]` replacement for each new prefix. Follow the same pattern as any existing `sanitize_error` tests in the file.

---

### `crates/fuse/src/lib.rs` (D-03 replay timeout, D-06 swallowed removal at lines 1494 + 1558)

**Analog within file:** `NETWORK_TIMEOUT` constant (line 59), `rt.spawn` + `tokio::time::timeout` (lines 1282-1295), `record_failure` error handling (lines 1496-1514, 1560-1578).

**`NETWORK_TIMEOUT` definition** (line 59):
```rust
// Source: crates/fuse/src/lib.rs:59
const NETWORK_TIMEOUT: Duration = Duration::from_secs(10);
// Note: operations.rs:37 has a separate 3s NETWORK_TIMEOUT for sync FS ops.
// Replay uses lib.rs:59's 10s base (confirmed: replay lives in lib.rs).
```

**`tokio::time::timeout` pattern** (lines 1282-1295) — replicate for replay entry wrapping:
```rust
// Source: crates/fuse/src/lib.rs:1282-1295
self.rt.spawn(async move {
    let result = tokio::time::timeout(NETWORK_TIMEOUT, async {
        let resp = cipherbox_api_client::ipns::resolve_ipns(&api, &fp_ipns)
            .await
            .map_err(|e| format!("{}", e))?;
        // ...
    })
    .await;
    // match result { Ok(Ok(...)) => ..., Ok(Err(e)) => ..., Err(_timeout) => ... }
});
// D-03 replay wrapping:
// mkdir replay:  tokio::time::timeout(NETWORK_TIMEOUT * 3,  replay_mkdir_entry(...)).await
// upload replay: tokio::time::timeout(NETWORK_TIMEOUT * 18, replay_upload_entry(...)).await
// On Err(_): produce Err(format!("timed out after {}s", (NETWORK_TIMEOUT * N).as_secs()))
// then feed into the existing journal.record_failure branch below.
```

**Swallowed removal at line 1494** — fix D-06 (MkdirPublish success arm):
```rust
// Source: crates/fuse/src/lib.rs:1489-1494 (current)
match result {
    Ok(()) => {
        log::info!("replay_for_vault: MkdirPublish {} replayed successfully", entry.id);
        let _ = journal.remove(&entry.id);   // <-- REPLACE
    }
// Replace with:
        if let Err(e) = journal.remove(&entry.id) {
            log::warn!(
                "replay_for_vault: failed to remove MkdirPublish journal entry {} after success: {} \
                 — entry may replay again on next mount",
                entry.id, e
            );
        }
```

**Swallowed removal at line 1558** — fix D-06 (UploadFile success arm):
```rust
// Source: crates/fuse/src/lib.rs:1551-1558 (current)
match result {
    Ok(()) => {
        log::info!("replay_for_vault: UploadFile {} ('{}') replayed successfully", entry.id, filename);
        let _ = journal.remove(&entry.id);   // <-- REPLACE
    }
// Replace with same log::warn! pattern as above, interpolating entry.id and filename.
```

**Existing `record_failure` error-logging pattern** (lines 1496-1513) — D-03 timeout errors feed into this same match; no new error-handling structure needed:
```rust
// Source: crates/fuse/src/lib.rs:1496-1513
Err(e) => {
    match journal.record_failure(entry, &e) {
        Ok(cipherbox_sdk::JournalEntryStatus::Failed { .. }) => log::error!(
            "replay_for_vault: MkdirPublish {} parked as Failed after {} retries: {}",
            entry.id, journal.max_retries, e
        ),
        Ok(_) => log::warn!(
            "replay_for_vault: MkdirPublish {} failed: {} (retry {}/{}, will retry on next mount)",
            entry.id, e, entry.retries + 1, journal.max_retries
        ),
        Err(re) => log::warn!(
            "replay_for_vault: MkdirPublish {} failed: {}; record_failure also errored: {}",
            entry.id, e, re
        ),
    }
}
```

**D-03 concurrent replay — `rt.spawn` wrapper replacing the inline `.await`** (current lines 278-289, called from fuse/mod.rs):
Replay is an `async fn`; in `fuse/mod.rs` spawn it via `rt.spawn(async move { cipherbox_fuse::replay_for_vault(...).await; })` without `.await` on the handle. See fuse/mod.rs section below for the concrete call site.

**Tests:** Add `#[tokio::test]` functions in the existing `#[cfg(test)] mod tests` block at line 2276+. For D-06: mock `WriteQueue` with a failing `remove` and assert `log::warn!` fires. For D-03: use a future that sleeps longer than the timeout and verify `Err` result.

---

### `crates/fuse/src/write_ops.rs` (D-06 swallowed removal at line 679)

**Current swallowed removal** (lines 678-680):
```rust
// Source: crates/fuse/src/write_ops.rs:678-680
// Remove journal entry now that parent publish is confirmed (D-11b).
let _ = journal_for_mkdir.remove(&mkdir_journal_entry_id);
log::info!("Parent metadata published after mkdir");
```

**D-06 fix — replicate the exact log::warn! pattern from lib.rs:**
```rust
if let Err(e) = journal_for_mkdir.remove(&mkdir_journal_entry_id) {
    log::warn!(
        "write_ops: failed to remove MkdirPublish journal entry {} after successful parent publish: {} \
         — entry may replay again on next mount",
        mkdir_journal_entry_id, e
    );
}
log::info!("Parent metadata published after mkdir");
```

---

### `crates/fuse/src/journal_helpers.rs` (D-01 size cap, D-04 name encryption)

**Analog within file:** `ciphertext_b64` encode at lines 285-286, `wrap_key_to_hex` call at line 281, `JournalEntry` construction at lines 307-324.

**Current ciphertext encoding** (lines 284-286) — D-01 replaces this:
```rust
// Source: crates/fuse/src/journal_helpers.rs:284-286
// Build journal entry referencing ciphertext only — no plaintext (D-05).
use base64::Engine;
let ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(&ciphertext);
// D-01: DELETE these lines. Instead pass &ciphertext to put_with_sidecar; store sidecar_path + sidecar_sha256.
```

**Per-entry size cap position** — insert BEFORE the ciphertext encoding block (after `let file_size = plaintext.len() as u64;` at line 222):
```rust
// Insert after line 222:
if file_size > cipherbox_sdk::MAX_JOURNAL_PAYLOAD_BYTES {
    return Err(format!(
        "File too large for journal ({} bytes > {} byte cap); refusing to write",
        file_size, cipherbox_sdk::MAX_JOURNAL_PAYLOAD_BYTES
    ));
}
```

**Existing `wrap_key_to_hex` call** (line 281) — D-04 name encryption follows the same pattern:
```rust
// Source: crates/fuse/src/journal_helpers.rs:281
.map(|raw_key| wrap_key_to_hex(raw_key, &self.public_key, "parent IPNS key"))

// D-04 analogous: encrypt filename
let filename_encrypted_hex = {
    let filename_bytes = file_name.as_bytes();
    let encrypted = cipherbox_crypto::ecies::wrap_key(filename_bytes, &self.public_key)
        .map_err(|e| format!("filename encryption failed: {}", e))?;
    hex::encode(&encrypted)
};
// Same pattern for MkdirPublish.name → name_encrypted_hex in build_mkdir_journal_entry.
```

**`JournalOp::UploadFile` construction** (lines 307-324) — update field names per D-01 + D-04:
```rust
// Source: crates/fuse/src/journal_helpers.rs:310-321 (current)
op: cipherbox_sdk::JournalOp::UploadFile {
    ciphertext_b64,               // D-01: REPLACE with sidecar_path, sidecar_sha256
    wrapped_key_hex: encrypted_file_key_hex.clone(),
    iv_hex: iv_hex.clone(),
    file_meta_ipns_name: file_meta_ipns_name.clone(),
    file_ipns_key_hex,
    parent_folder_ipns_name,
    parent_ipns_key_hex: parent_ipns_key_hex_for_journal,
    filename: file_name,          // D-04: REPLACE with filename_encrypted_hex
    size: file_size,
    created_at_ms: now_ms,
},
```

---

### `crates/fuse/src/read_ops.rs` (D-01 durable-ack with oneshot)

**Analog within file:** Existing durable-ack sequence (lines 814-884).

**Current durable-ack sequence** (lines 814-884) — D-01 must preserve this order:
```rust
// Source: crates/fuse/src/read_ops.rs:814-884
// D-04: fsync journal entry to disk BEFORE acking the OS.
fs.journal.put(&result.entry)?;             // line 815 — sync write

// CR-04: journal is durably committed — now apply the in-memory write.
// (inode mutations at lines 818-845)
// ...
handle.cleanup();                           // line 882 — D-05: zeroize plaintext
// D-04: ack OS only after local journal fsync is confirmed above.
reply.ok();                                 // line 884
```

**D-01 replacement: sidecar write via oneshot channel.** The durable-ack ORDER must be preserved:
```
1. tokio oneshot channel created
2. rt.spawn(background writer task) — writes <id>.bin (0o600) + fsyncs, writes <id>.json + fsyncs, sends Ok/Err via tx
3. rt.block_on(oneshot_rx)  ← FUSE callback thread blocks here
4. On Ok: inode mutations (lines 818-845)
5. handle.cleanup()
6. reply.ok()
7. On Err: reply.error(libc::EIO)
```

The `rt` handle is already available as `fs.rt` (used at line 874 for the upload spawn). Mirror the existing spawn pattern:
```rust
// Source: crates/fuse/src/read_ops.rs:873-884 — existing spawn of upload thread
let rt = fs.rt.clone();
let upload_tx = fs.upload_tx.clone();
// ...
// D-01 analogy: before reply.ok(), create channel and block:
let (sidecar_tx, sidecar_rx) = tokio::sync::oneshot::channel::<Result<(), String>>();
let spawn_journal = fs.journal.clone();
let spawn_entry = result.entry.clone();
let spawn_ciphertext = ciphertext.clone();
fs.rt.spawn(async move {
    let r = spawn_journal.put_with_sidecar(&spawn_entry, &spawn_ciphertext).await;
    let _ = sidecar_tx.send(r);
});
match fs.rt.block_on(sidecar_rx) {
    Ok(Ok(())) => { /* inode mutations, handle.cleanup(), reply.ok() */ }
    Ok(Err(e)) | Err(_) => { reply.error(libc::EIO); return; }
}
```

---

### `apps/desktop/src-tauri/src/fuse/mod.rs` (D-03 concurrent replay, D-02 GC constants)

**Current blocking replay call** (lines 276-289) — D-03 converts to concurrent spawn:
```rust
// Source: apps/desktop/src-tauri/src/fuse/mod.rs:276-289 (current — REPLACE)
// Replay journal entries for this vault before mounting (D-06, D-07, D-08).
cipherbox_fuse::replay_for_vault(
    &journal,
    state.sdk.api.clone(),
    &private_key,
    &public_key,
    &root_folder_key,
    &root_ipns_name,
    publish_coordinator.clone(),
    tee_public_key.as_deref(),
    tee_key_epoch,
)
.await;
```

**D-03 replacement — concurrent spawn (mirror the `rt.spawn` pattern from lib.rs:1282):**
```rust
// Clone all params needed by the spawn closure (same borrow pattern as upload spawn)
let replay_journal = journal.clone();
let replay_api = state.sdk.api.clone();
let replay_private_key = private_key.clone();
let replay_public_key = public_key.clone();
let replay_root_folder_key = root_folder_key.clone();
let replay_root_ipns_name = root_ipns_name.clone();
let replay_coordinator = publish_coordinator.clone();
let replay_tee_public_key = tee_public_key.clone();
let replay_tee_key_epoch = tee_key_epoch;
rt.spawn(async move {
    cipherbox_fuse::replay_for_vault(
        &replay_journal,
        replay_api,
        &replay_private_key,
        &replay_public_key,
        &replay_root_folder_key,
        &replay_root_ipns_name,
        replay_coordinator,
        replay_tee_public_key.as_deref(),
        replay_tee_key_epoch,
    )
    .await;
    log::info!("Background replay_for_vault complete");
});
// Proceed immediately to CipherBoxFS construction (line 291+)
```

**`JOURNAL_MAX_RETRIES` constant** (line 52) — D-02 GC constants go alongside it:
```rust
// Source: apps/desktop/src-tauri/src/fuse/mod.rs:52
pub const JOURNAL_MAX_RETRIES: u32 = 5;
// D-02 new constants (add in queue.rs or fuse/mod.rs; reference from both):
// pub const JOURNAL_GC_MAX_AGE_DAYS: u64 = 30;
// pub const JOURNAL_GC_MAX_SIZE_BYTES: u64 = 500 * 1024 * 1024; // 500 MiB
```

**Note:** Windows mirror at `apps/desktop/src-tauri/src/fuse/windows/mod.rs` also calls `replay_for_vault` (CR-06 fix). Apply the identical concurrent-spawn pattern there.

---

### `apps/desktop/src-tauri/src/commands/auth.rs` (D-02 vault purge on logout)

**Current `logout()` function** (lines 490-521) — insert purge call after unmount, before `clear_keys()`:
```rust
// Source: apps/desktop/src-tauri/src/commands/auth.rs:490-521
pub async fn logout(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    log::info!("Logging out");

    #[cfg(any(feature = "fuse", feature = "winfsp"))]
    {
        if let Err(e) = crate::fuse::unmount_filesystem() {
            log::warn!("Filesystem unmount failed (will continue logout): {}", e);
        }
        *state.mount_status.write().await = crate::state::MountStatus::Unmounted;
    }
    // ... POST /auth/logout (lines 503-506) ...
    // ... delete refresh token (lines 508-511) ...

    // Zero all sensitive keys in memory
    state.clear_keys().await;
    // ...
}
```

**D-02 purge hook — insert between unmount block and `clear_keys()`, following the `log::warn!` error-continuation pattern already used for unmount:**
```rust
// After unmount block and before state.clear_keys().await:
#[cfg(any(feature = "fuse", feature = "winfsp"))]
{
    let vault_ipns = state.sdk.root_ipns_name.read().await.clone();
    if let Some(ref ipns) = vault_ipns {
        let journal = cipherbox_fuse::get_or_create_journal(); // or however journal is accessed
        match journal.purge_vault(ipns) {
            Ok(n) => log::info!("Purged {} journal entries for vault {} on logout", n, ipns),
            Err(e) => log::warn!("Journal purge on logout failed (non-fatal): {}", e),
        }
    }
}
```

The `log::warn!` + continue pattern (lines 497-499) is the established template for non-fatal cleanup errors in `logout()`.

---

## Shared Patterns

### ECIES key wrapping (D-04 name encryption)

**Source:** `crates/fuse/src/journal_helpers.rs:150-156` (file key wrap) and line 281 (`wrap_key_to_hex` helper).
**Apply to:** `journal_helpers.rs` (write side) and `lib.rs:replay_upload_entry` / `replay_mkdir_entry` (read side).

```rust
// Write (journal_helpers.rs): wrap filename bytes exactly like the file key
let wrapped_key = cipherbox_crypto::ecies::wrap_key(&file_key, &self.public_key)
    .map_err(|e| { cipherbox_crypto::utils::clear_bytes(&mut file_key); format!("Key wrapping failed: {}", e) })?;

// D-04 name encryption (same pattern, no zeroize needed — filename is not a key):
let filename_encrypted_hex = {
    let enc = cipherbox_crypto::ecies::wrap_key(file_name.as_bytes(), &self.public_key)
        .map_err(|e| format!("filename encryption failed: {}", e))?;
    hex::encode(&enc)
};

// Replay (lib.rs): unwrap with user private key — already established at lib.rs:2103-2104
let filename_bytes = cipherbox_crypto::ecies::unwrap_key(
    &hex::decode(&filename_encrypted_hex).map_err(|e| format!("hex decode: {}", e))?,
    private_key,
).map_err(|e| format!("ecies unwrap filename: {}", e))?;
let filename = String::from_utf8(filename_bytes).map_err(|e| format!("UTF-8: {}", e))?;
```

### `log::warn!` on non-fatal cleanup errors

**Source:** `apps/desktop/src-tauri/src/commands/auth.rs:497-499`, `crates/fuse/src/lib.rs:1505-1513`.
**Apply to:** All three D-06 `journal.remove()` sites and the D-02 purge hook in `logout()`.

```rust
// Pattern (auth.rs:497-499):
if let Err(e) = crate::fuse::unmount_filesystem() {
    log::warn!("Filesystem unmount failed (will continue logout): {}", e);
}
// D-06 mirror:
if let Err(e) = journal.remove(&entry.id) {
    log::warn!("...: {} — entry may replay again on next mount", e);
}
```

### `#[cfg(unix)] OpenOptionsExt::mode(0o600)` for secure file creation

**Source:** `crates/sdk/src/queue.rs:181-182`.
**Apply to:** All new file creation paths in `put_with_sidecar` (both `.bin` and `.json`).

```rust
#[cfg(unix)]
open_opts.mode(0o600);
```

### Test structure — `#[cfg(test)] mod tests` inline

**Source:** `crates/sdk/src/queue.rs:335-440`, `crates/fuse/src/lib.rs:2276+`.
**Apply to:** All new tests — extend existing inline `mod tests` blocks, never create new test files.
- Pure logic tests: `#[test]`
- Async replay tests: `#[tokio::test]`
- Use `make_temp_queue()` helper (queue.rs:383-398) for all WriteQueue tests.

---

## No Analog Found

All files had direct analogs within the same file or crate. No files require patterns from RESEARCH.md examples alone.

---

## Metadata

**Analog search scope:** `crates/sdk/src/`, `crates/fuse/src/`, `apps/desktop/src-tauri/src/`
**Files scanned:** 8 primary source files (full or partial reads)
**Pattern extraction date:** 2026-06-19
