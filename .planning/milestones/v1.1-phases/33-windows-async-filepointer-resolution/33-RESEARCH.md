# Phase 33: Windows Async FilePointer Resolution - Research

**Researched:** 2026-03-28
**Domain:** WinFsp FUSE filesystem, async Rust, channel-based concurrency
**Confidence:** HIGH

## Summary

Phase 33 ports the channel-based async FilePointer resolution pattern to the Windows WinFsp backend. The blocking problem is identical to macOS (Phase 32): `drain_refresh_completions()` in `lib.rs` calls `block_with_timeout()` for every unresolved FilePointer sequentially, blocking the caller thread for up to `NETWORK_TIMEOUT` (10s) per FilePointer. With N files in a folder, this creates O(N \* 10s) worst-case blocking.

The existing code already demonstrates the exact pattern to follow: content prefetching in `platform/windows/read_ops.rs` uses `content_tx`/`content_rx` channels with a `prefetching` HashSet dedup guard and `drain_content_prefetches()`. FilePointer resolution needs an identical setup: a new `mpsc` channel pair, a `resolving_file_pointers` HashSet, and a drain function called from the same callback entry points.

**Primary recommendation:** Add `file_pointer_tx`/`file_pointer_rx` channel pair and `resolving_file_pointers: HashSet<u64>` to `CipherBoxFS`, replace the blocking loop in `drain_refresh_completions()` with async task spawning, and add `drain_file_pointer_completions()` calls to the Windows `open()`, `read()`, and `read_directory()` entry points.

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Use channel-based async resolution, mirroring the pattern established in Phase 32 (and the existing content prefetch pattern). Spawn tokio tasks for IPNS resolve + IPFS fetch, send results via mpsc channel, drain in next WinFsp callback.
- **D-02:** Unresolved FilePointers appear as zero-size placeholder files in Explorer. File name and directory entry visible immediately; size/content available after async resolution.
- **D-03:** Eagerly resolve all unresolved FilePointers as soon as refresh completions are drained.
- **D-04:** Retry failed resolutions 3 times with exponential backoff. File stays as zero-size placeholder during retries.
- **D-05:** Add `resolving_file_pointers: HashSet<u64>` (keyed by inode) to prevent duplicate resolution tasks.
- **D-06:** When `read()` hits an unresolved FilePointer with in-flight resolution, block with ~5s timeout. Return appropriate NTSTATUS error on timeout. Explorer retries automatically.

### Claude's Discretion

- Exact WinFsp NTSTATUS error code for unresolved files (STATUS_DEVICE_NOT_READY vs STATUS_IO_DEVICE_ERROR)
- Whether shared code can be extracted to platform-independent module or stays duplicated
- Backoff parameters matching Phase 32

### Deferred Ideas (OUT OF SCOPE)

None -- this phase is tightly scoped as a direct port.

</user_constraints>

## Standard Stack

### Core

| Library                   | Version   | Purpose                                          | Why Standard                                                |
| ------------------------- | --------- | ------------------------------------------------ | ----------------------------------------------------------- |
| winfsp                    | 0.12      | WinFsp Rust bindings for user-mode filesystem    | Already in use; provides FileSystemContext trait            |
| tokio                     | workspace | Async runtime for spawning background tasks      | Already in use for all async IO                             |
| std::sync::mpsc           | stdlib    | Channel for async task results to sync callbacks | Already used for content_tx/rx, refresh_tx/rx, upload_tx/rx |
| std::collections::HashSet | stdlib    | Deduplication guard for in-flight resolutions    | Already used for `prefetching` set                          |

### Supporting

| Library              | Version   | Purpose                                    | When to Use                                                         |
| -------------------- | --------- | ------------------------------------------ | ------------------------------------------------------------------- |
| cipherbox-api-client | workspace | IPNS resolve + IPFS fetch API calls        | FilePointer resolution: resolve IPNS name, fetch encrypted metadata |
| cipherbox-core       | workspace | `decrypt_file_metadata_from_ipfs_public()` | Decrypt fetched FileMetadata after IPFS download                    |
| log                  | workspace | Structured logging                         | Error/warn/info for resolution lifecycle                            |

No new dependencies required. All libraries are already in the workspace.

## Architecture Patterns

### Recommended Changes Structure

```
crates/fuse/src/
  lib.rs                          # Add PendingFilePointer enum, channel fields to CipherBoxFS,
                                  #   drain_file_pointer_completions(), modify drain_refresh_completions()
  platform/windows/
    read_ops.rs                   # Add drain calls in open() and read()
    dir_ops.rs                    # Add drain call in read_directory()
    operations.rs                 # Add status_device_not_ready() helper
```

### Pattern 1: Channel-Based Async Resolution (mirrors content prefetch)

**What:** Replace blocking `block_with_timeout()` loop with spawn-and-drain pattern.
**When to use:** Whenever a synchronous WinFsp callback needs results from async network I/O.

**Current blocking pattern (in `drain_refresh_completions()`, lib.rs lines 617-643):**

```rust
// BLOCKING: O(N * NETWORK_TIMEOUT) per unresolved FilePointer
for (ino, fp_ipns) in &unresolved {
    let resolve_result = block_with_timeout(&self.rt, async {
        let resp = cipherbox_api_client::ipns::resolve_ipns(&api, fp_ipns).await...;
        cipherbox_api_client::ipfs::fetch_content(&api, &resp.cid).await...
    });
    match resolve_result {
        Ok(enc_bytes) => { /* resolve_file_pointer() */ }
        Err(e) => { /* log warning */ }
    }
}
```

**New async pattern:**

```rust
// STEP 1: In drain_refresh_completions(), spawn tasks instead of blocking
for (ino, fp_ipns) in &unresolved {
    if !self.resolving_file_pointers.contains(&ino) {
        self.resolving_file_pointers.insert(ino);
        let api = self.api.clone();
        let tx = self.file_pointer_tx.clone();
        let fk = folder_key.clone();
        let ipns = fp_ipns.clone();
        self.rt.spawn(async move {
            // resolve + fetch + decrypt (with retry logic)
            let result = resolve_single_file_pointer(&api, &ipns, &fk).await;
            let _ = tx.send(PendingFilePointer { ino, ipns_name: ipns, result });
        });
    }
}

// STEP 2: New drain function called at callback entry points
pub fn drain_file_pointer_completions(&mut self) {
    while let Ok(pending) = self.file_pointer_rx.try_recv() {
        self.resolving_file_pointers.remove(&pending.ino);
        match pending.result {
            Ok(fm) => self.inodes.resolve_file_pointer(
                pending.ino, fm.cid, fm.file_key_encrypted,
                fm.file_iv, fm.size, fm.encryption_mode, fm.versions,
            ),
            Err(e) => log::warn!("FilePointer resolve failed for ino {}: {}", pending.ino, e),
        }
    }
}
```

### Pattern 2: Read-While-Resolving Poll (D-06)

**What:** When `read()` encounters an unresolved FilePointer that has in-flight resolution, poll with short sleep intervals up to 5s timeout.
**When to use:** Only in `handle_read()` when CID is empty and inode is not yet resolved.
**Example:**

```rust
// In handle_read(), when cid.is_empty() and file_meta_resolved == false:
if self.resolving_file_pointers.contains(&ino) {
    // Poll for resolution (same pattern as existing content poll in read)
    let poll_start = std::time::Instant::now();
    let max_wait = Duration::from_secs(5);
    loop {
        drop(fs);
        std::thread::sleep(Duration::from_millis(100));
        fs = ctx.inner.lock().unwrap();
        fs.drain_file_pointer_completions();
        // Check if now resolved
        if let Some(inode) = fs.inodes.get(ino) {
            if let InodeKind::File { file_meta_resolved: true, .. } = &inode.kind {
                break; // resolved, continue with normal read path
            }
        }
        if poll_start.elapsed() > max_wait {
            return Err(status_device_not_ready()); // Explorer retries
        }
    }
}
```

### Pattern 3: Retry with Exponential Backoff (D-04)

**What:** Failed IPNS resolve or IPFS fetch retries up to 3 times with exponential backoff.
**When to use:** Inside the spawned async resolution task.
**Example:**

```rust
async fn resolve_single_file_pointer(
    api: &ApiClient,
    ipns_name: &str,
    folder_key: &[u8; 32],
) -> Result<ResolvedFileMetadata, String> {
    let mut attempts = 0;
    let max_retries = 3;
    loop {
        match try_resolve(api, ipns_name, folder_key).await {
            Ok(fm) => return Ok(fm),
            Err(e) if attempts < max_retries => {
                attempts += 1;
                let delay = Duration::from_millis(500 * (1 << attempts)); // 1s, 2s, 4s
                log::warn!("FilePointer resolve attempt {} failed for {}: {}", attempts, ipns_name, e);
                tokio::time::sleep(delay).await;
            }
            Err(e) => return Err(e),
        }
    }
}
```

### Anti-Patterns to Avoid

- **Blocking in WinFsp callbacks for N files sequentially:** The whole point of this phase. Never call `block_with_timeout()` in a loop over unresolved FilePointers.
- **Holding the Mutex across async awaits:** WinFsp callbacks receive `&self` and use `Arc<Mutex<CipherBoxFS>>`. The mutex must be dropped before spawning or sleeping, and re-acquired after. The existing `read()` poll loop already demonstrates this pattern correctly.
- **Spawning duplicate resolution tasks:** Without the `resolving_file_pointers` HashSet, every `drain_refresh_completions()` call would spawn new tasks for the same FilePointers. The dedup guard is essential.

## Don't Hand-Roll

| Problem                    | Don't Build                     | Use Instead                                     | Why                                                          |
| -------------------------- | ------------------------------- | ----------------------------------------------- | ------------------------------------------------------------ |
| Async task result delivery | Custom notification/wakeup      | `std::sync::mpsc::channel`                      | Already proven in 3 other channel pairs in CipherBoxFS       |
| In-flight deduplication    | Atomic flags per inode          | `HashSet<u64>` keyed by inode                   | Simple, already used for `prefetching` keyed by CID          |
| Retry with backoff         | Custom retry loop per call site | Single `resolve_single_file_pointer()` function | Centralizes retry logic, easier to tune                      |
| Timeout on read poll       | `tokio::time::timeout`          | `Instant::now()` + sleep loop                   | Must work in sync WinFsp callback context (no async runtime) |

**Key insight:** The entire async infrastructure (channels, drain functions, dedup sets) already exists in `CipherBoxFS` for content prefetch and metadata refresh. FilePointer resolution is a third instance of the exact same pattern.

## Common Pitfalls

### Pitfall 1: Mutex Poisoning During Panic in Drain

**What goes wrong:** If `drain_file_pointer_completions()` panics (e.g., unexpected `None` from inode lookup), the Mutex is poisoned and all subsequent WinFsp callbacks fail with `PoisonError`.
**Why it happens:** `ctx.inner.lock().unwrap()` is used throughout.
**How to avoid:** Keep drain logic simple -- only `try_recv()` + `resolve_file_pointer()` + `remove()`. These are all infallible operations on HashMap/HashSet.
**Warning signs:** Explorer showing "The network path was not found" for all operations.

### Pitfall 2: Channel Backpressure / Unbounded Growth

**What goes wrong:** If resolution tasks complete faster than drains occur, the channel buffer grows unbounded.
**Why it happens:** `std::sync::mpsc` is unbounded by default.
**How to avoid:** This is acceptable for FilePointer resolution because: (a) the dedup guard limits inflight tasks to at most one per unresolved inode, and (b) the number of files per folder is bounded (typically < 1000). The existing content and refresh channels use the same unbounded approach.
**Warning signs:** Memory growth during large folder refreshes.

### Pitfall 3: Stale Resolution Results After File Mutation

**What goes wrong:** A FilePointer resolution completes, but the file was already overwritten/deleted locally before the result arrives.
**Why it happens:** The user creates or overwrites a file via Explorer while async resolution is in flight.
**How to avoid:** Check `file_meta_resolved` before applying -- if the inode was already resolved (e.g., by a local write), skip the stale async result. Also check `write_generation` if the inode was re-created.
**Warning signs:** File content reverting to old version after local save.

### Pitfall 4: Wrong Folder Key for FilePointer Decryption

**What goes wrong:** `get_unresolved_file_pointers()` returns FilePointers from multiple folders, but only one folder key is passed for decryption.
**Why it happens:** The current blocking code in `drain_refresh_completions()` uses the refresh's folder key for all unresolved pointers, not just the ones belonging to that folder.
**How to avoid:** Use `get_unresolved_file_pointers_for_parent(refresh.ino)` (already exists in inode.rs) to scope resolution to the refreshed folder. Or pass each FilePointer's parent folder key individually.
**Warning signs:** `FilePointer decrypt failed` log messages.

### Pitfall 5: NTSTATUS Code Choice Affects Explorer Retry Behavior

**What goes wrong:** Using `STATUS_IO_DEVICE_ERROR` (0xC0000185) causes Explorer to show an error dialog and stop retrying. Using `STATUS_DEVICE_NOT_READY` (0xC00000A3) causes Explorer to show a "drive not ready" prompt.
**Why it happens:** Windows translates NTSTATUS to Win32 error codes differently; some trigger user-visible dialogs.
**How to avoid:** Use `STATUS_DEVICE_NOT_READY` (0xC00000A3) for the read-while-resolving timeout. Explorer interprets this as a transient condition and retries the operation. This maps to Win32 `ERROR_NOT_READY` which is the standard "try again later" signal.
**Warning signs:** Users seeing error dialogs in Explorer during FilePointer resolution.

## Code Examples

Verified patterns from the existing codebase:

### PendingFilePointer Enum (new type, mirrors PendingContent)

```rust
// Source: modeled on PendingContent in lib.rs:82-85
pub struct PendingFilePointer {
    pub ino: u64,
    pub ipns_name: String,
    pub result: Result<ResolvedFileMetadata, String>,
}

pub struct ResolvedFileMetadata {
    pub cid: String,
    pub file_key_encrypted: String,
    pub file_iv: String,
    pub size: u64,
    pub encryption_mode: String,
    pub versions: Option<Vec<cipherbox_core::folder::VersionEntry>>,
}
```

### New CipherBoxFS Fields (added to struct in lib.rs:453-479)

```rust
// Add alongside existing channel pairs:
pub file_pointer_rx: std::sync::mpsc::Receiver<PendingFilePointer>,
pub file_pointer_tx: std::sync::mpsc::Sender<PendingFilePointer>,
pub resolving_file_pointers: std::collections::HashSet<u64>,
```

### Drain Call Sites in Windows Backend

```rust
// Source: mirrors existing drain pattern in platform/windows/read_ops.rs:108-109
// In handle_open():
fs.drain_upload_completions();
fs.drain_content_prefetches();
fs.drain_file_pointer_completions(); // NEW

// In handle_read():
fs.drain_upload_completions();
fs.drain_content_prefetches();
fs.drain_file_pointer_completions(); // NEW

// In handle_read_directory() (dir_ops.rs):
fs.drain_refresh_completions();
fs.drain_upload_completions();
fs.drain_file_pointer_completions(); // NEW
```

### NTSTATUS Helper for Device Not Ready

```rust
// Source: modeled on existing helpers in platform/windows/operations.rs:37-42
pub fn status_device_not_ready() -> FspError {
    FspError::NTSTATUS(0xC00000A3_u32 as i32)
}
```

## State of the Art

| Old Approach                                     | Current Approach                                              | When Changed | Impact                                       |
| ------------------------------------------------ | ------------------------------------------------------------- | ------------ | -------------------------------------------- |
| Blocking `block_with_timeout()` per FilePointer  | Channel-based async spawn + drain                             | Phase 32/33  | Eliminates O(N \* timeout) blocking          |
| All FilePointers resolved before READDIR returns | Placeholder files visible immediately, resolved in background | Phase 32/33  | Explorer never hangs during metadata refresh |

**Current state of `drain_refresh_completions()` (the function to modify):** Lines 605-646 of `lib.rs`. The blocking loop is at lines 617-643. This is shared code used by both macOS and Windows via the `CipherBoxFS` struct. Modifying this function benefits both platforms.

## Discretion Recommendations

### NTSTATUS Error Code: Use STATUS_DEVICE_NOT_READY (0xC00000A3)

**Recommendation:** `STATUS_DEVICE_NOT_READY` over `STATUS_IO_DEVICE_ERROR`.
**Rationale:** `STATUS_DEVICE_NOT_READY` maps to Win32 `ERROR_NOT_READY` (0x15), which Windows I/O Manager and Explorer treat as a transient condition warranting retry. `STATUS_IO_DEVICE_ERROR` (0xC0000185) maps to `ERROR_IO_DEVICE` (0x45D), which is treated as a hardware failure and may trigger error dialogs.
**Confidence:** MEDIUM -- verified NTSTATUS values from [MS-ERREF documentation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55), but Explorer retry behavior is empirical.

### Shared Code Extraction: Modify shared `drain_refresh_completions()` directly

**Recommendation:** Since `drain_refresh_completions()` is already in `lib.rs` (shared between platforms), modify it in place. The new `drain_file_pointer_completions()` and `PendingFilePointer` type also go in `lib.rs` since `CipherBoxFS` is platform-independent. No need for a separate platform-independent module -- the shared module already exists.
**Rationale:** The channel fields (`file_pointer_tx/rx`, `resolving_file_pointers`) must be on `CipherBoxFS` which is in `lib.rs`. The drain logic uses only `InodeTable` methods which are already platform-independent. Platform-specific work is only adding drain calls in the Windows callback handlers.
**Confidence:** HIGH -- follows existing architecture exactly.

### Backoff Parameters: 500ms base, 2x multiplier, 3 retries

**Recommendation:** Use delays of 1s, 2s, 4s (base 500ms \* 2^attempt) matching the typical IPNS resolution timeout characteristics.
**Rationale:** IPNS resolution over DHT typically takes 1-5s. A 500ms base with exponential backoff gives 3 retries within ~7s total, which is well under the 10s `NETWORK_TIMEOUT` constant. The existing content prefetch has no retry (single attempt with 120s timeout), so this is a new pattern specific to FilePointer resolution.
**Confidence:** MEDIUM -- based on observed IPNS timing from Phase 18/22 baselines.

## Open Questions

1. **Phase 32 execution ordering**
   - What we know: Phase 32 modifies `drain_refresh_completions()` in `lib.rs` (shared code). Phase 33 also modifies the same function.
   - What's unclear: If Phase 32 has not been implemented yet, Phase 33 must include the shared `lib.rs` changes. If Phase 32 completes first, Phase 33 only needs the Windows-specific drain calls.
   - Recommendation: Plan Phase 33 to include all necessary `lib.rs` changes (channel fields, `PendingFilePointer`, `drain_file_pointer_completions()`, modified `drain_refresh_completions()`). If Phase 32 lands first, the planner can skip the shared code tasks. The CONTEXT.md notes the phases can execute in parallel since code paths are platform-specific, but `lib.rs` is shared.

2. **CipherBoxFS constructor location**
   - What we know: `CipherBoxFS` fields are declared in `lib.rs`, but the constructor is in the desktop app's mount code (not in the crate).
   - What's unclear: Where exactly `CipherBoxFS` is instantiated so the new channel pair can be wired up.
   - Recommendation: Search for `CipherBoxFS {` in `apps/desktop/` to find the constructor and add `file_pointer_tx`, `file_pointer_rx`, `resolving_file_pointers` initialization.

## Validation Architecture

### Test Framework

| Property           | Value                                                           |
| ------------------ | --------------------------------------------------------------- |
| Framework          | PowerShell E2E scripts (desktop-e2e) + manual Explorer testing  |
| Config file        | tests/desktop-e2e/scripts/run-all.ps1                           |
| Quick run command  | `powershell tests/desktop-e2e/scripts/test-fuse-operations.ps1` |
| Full suite command | `powershell tests/desktop-e2e/scripts/run-all.ps1`              |

### Phase Requirements to Test Map

This phase has no formal requirement IDs (performance improvement). Testing focuses on:

| Behavior                                           | Test Type              | Automated Command                                                       | File Exists? |
| -------------------------------------------------- | ---------------------- | ----------------------------------------------------------------------- | ------------ |
| Explorer does not hang during metadata refresh     | manual                 | Manual: open Explorer, navigate FUSE mount during IPNS refresh          | N/A          |
| Files appear as zero-size placeholders then update | manual                 | Manual: observe file sizes in Explorer during cold mount                | N/A          |
| Read of resolving file blocks with 5s timeout      | e2e                    | `powershell tests/desktop-e2e/scripts/test-fuse-operations.ps1`         | Yes          |
| Resolution retries 3 times on failure              | unit (log observation) | Manual: check desktop log output during IPNS failure                    | N/A          |
| Cargo check compiles with winfsp feature           | build                  | `cargo check -p cipherbox-fuse --features winfsp --no-default-features` | N/A (CI)     |

### Sampling Rate

- **Per task commit:** `cargo check -p cipherbox-fuse --features winfsp --no-default-features`
- **Per wave merge:** Full E2E suite on Windows: `powershell tests/desktop-e2e/scripts/run-all.ps1`
- **Phase gate:** Windows desktop E2E passes, no Explorer hangs observed during manual testing

### Wave 0 Gaps

None -- existing test infrastructure covers compilation verification. The behavioral verification (no Explorer hangs) is inherently manual/observational. The E2E test scripts exercise file I/O operations which implicitly test that the async resolution path works (files must be readable after mount).

## Sources

### Primary (HIGH confidence)

- `crates/fuse/src/lib.rs` -- CipherBoxFS struct, drain functions, channel patterns, blocking FilePointer resolution loop (lines 605-646)
- `crates/fuse/src/inode.rs` -- InodeTable, resolve_file_pointer(), get_unresolved_file_pointers(), get_unresolved_file_pointers_for_parent()
- `crates/fuse/src/platform/windows/read_ops.rs` -- Windows read/open handlers, content prefetch pattern
- `crates/fuse/src/platform/windows/dir_ops.rs` -- Windows readdir handler, refresh drain calls
- `crates/fuse/src/platform/windows/operations.rs` -- WinFspContext, NTSTATUS helpers, FileSystemContext impl

### Secondary (MEDIUM confidence)

- [MS-ERREF NTSTATUS Values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55) -- NTSTATUS hex values for STATUS_DEVICE_NOT_READY (0xC00000A3) and STATUS_IO_DEVICE_ERROR (0xC0000185)
- [winfsp crate docs](https://docs.rs/winfsp/latest/winfsp/filesystem/trait.FileSystemContext.html) -- FileSystemContext threading model (callbacks on any thread, &self only)
- [WinFsp ntstatus.txt](https://github.com/winfsp/winfsp/blob/master/tools/gensrc/ntstatus.txt) -- WinFsp NTSTATUS mapping reference

### Tertiary (LOW confidence)

- Explorer retry behavior with STATUS_DEVICE_NOT_READY -- empirical observation, not documented by Microsoft

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH -- no new dependencies, all patterns already in codebase
- Architecture: HIGH -- direct application of existing channel+drain pattern to a third use case
- Pitfalls: HIGH -- identified from code review of existing shared state patterns
- NTSTATUS choice: MEDIUM -- values verified, but Explorer retry behavior is empirical
- Backoff parameters: MEDIUM -- based on IPNS timing observations, may need tuning

**Research date:** 2026-03-28
**Valid until:** 2026-04-28 (stable domain, patterns well-established in codebase)
