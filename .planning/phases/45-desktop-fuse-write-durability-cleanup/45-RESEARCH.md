# Phase 45: Desktop FUSE Write-Durability Cleanup - Research

**Researched:** 2026-06-14
**Domain:** Rust, cipherbox-fuse, cipherbox-sdk — hygiene refactor + test hardening
**Confidence:** HIGH (all findings sourced from direct codebase reads)

## Summary

Phase 45 is a pure hygiene + test-coverage pass over the write journal and crash-recovery
replay code introduced in Phases 43 and 44. There is NO behavior change: every refactor must
leave the crash-recovery semantics byte-for-byte equivalent. The seven scoped items are:

- **#11** — Deduplicate `fuser` / `winfsp` journal write paths into a shared helper
- **#12** — Extract journal-dir + max-retries construction into a shared helper
- **#15** — Memoize `resolve_folder_key` during replay to cut redundant network round-trips
- **#18** — Replace empty-string `file_meta_ipns_name` sentinel with `Option<String>`
- **#19** — Replace not-found string-match in replay with a typed error variant
- **#20** — Reuse `publish_file_metadata` in replay (eliminate duplicated publish logic)
- **#14** — Raise Phase-43 Rust write-durability test coverage

**Primary recommendation:** Work items #11, #12, #18, #19, #20 can be done safely in one pass
each because their blast radius is a single function or a small set of call-sites that are
all in `crates/fuse/`. Item #14 (tests) can be added as pure `#[cfg(test)]` additions.
Item #15 (memoize `resolve_folder_key`) requires the most care because it touches the async
replay loop and must preserve the BFS node-cap invariant.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
| --- | --- | --- | --- |
| Journal entry schema | crates/sdk (queue.rs) | — | Shared across fuser + winfsp |
| fuser write path (journal put) | crates/fuse/src/read_ops.rs | — | `handle_release` owns the fsync barrier |
| winfsp write path (journal put) | crates/fuse/src/platform/windows/write_ops.rs | — | `handle_cleanup` mirrors handle_release |
| fuser mkdir path (journal put) | crates/fuse/src/write_ops.rs | — | `handle_mkdir` |
| winfsp mkdir path (journal put) | crates/fuse/src/platform/windows/write_ops.rs | — | `handle_create` (dir branch) |
| Replay orchestrator | crates/fuse/src/lib.rs | — | `replay_for_vault` at lib.rs:870 |
| Replay upload helper | crates/fuse/src/lib.rs | — | `replay_upload_entry` at lib.rs:1294 |
| Replay mkdir helper | crates/fuse/src/lib.rs | — | `replay_mkdir_entry` at lib.rs:1228 |
| Parent merge + publish | crates/fuse/src/lib.rs | — | `fetch_merge_publish_parent` at lib.rs:1105 |
| resolve_folder_key | crates/fuse/src/lib.rs | — | Private async fn at lib.rs:1031 |
| publish_file_metadata | crates/fuse/src/operations.rs | — | Shared async fn at operations.rs:125 |
| Journal-dir construction | apps/desktop/src-tauri/src/fuse/mod.rs | apps/desktop/src-tauri/src/commands/sync.rs | Both build the same path: see #12 |
| Tests | crates/sdk/src/queue.rs (#[cfg(test)]) | crates/fuse/src/lib.rs (#[cfg(test)]) | |

## Concrete Code Map (Item by Item)

### Item #11 — Consolidate fuser / winfsp journal write paths

**What is duplicated:** The prepare-and-journal closure inside `handle_release` (fuser) and
`handle_cleanup` (winfsp, file branch) are structurally identical. Both:

1. Read plaintext from the temp file.
2. Encrypt with AES-256-GCM + ECIES-wrap the file key.
3. Resolve `parent_folder_ipns_name` from the inode table.
4. Wrap the parent IPNS private key with the user's EC public key.
5. Build a `JournalEntry { op: JournalOp::UploadFile { ... } }`.
6. Call `fs.journal.put(&journal_entry)?`.
7. Apply in-memory inode mutations and call `fs.queue_publish`.
8. Spawn a background upload thread calling `publish_file_metadata`.

**Exact locations:**

- fuser path: `crates/fuse/src/read_ops.rs` lines 695–1003 (the `prepare_result` closure
  starting at line 695 and the spawn block ending at line 1004).
- winfsp path: `crates/fuse/src/platform/windows/write_ops.rs` lines 791–1083 (identical
  structure: `prepare_result` closure at 791, spawn block ending at 1083).

**What differs and must stay platform-specific:**

- fuser: `reply.ok()` / `reply.error(libc::EIO)` — the POSIX reply object.
- winfsp: returns `()` from `handle_cleanup`; no equivalent error reply to the OS.
- fuser tracks `is_new_file` from `handle.temp_path.is_some() && cid.is_empty()`
  (computed before the closure at `read_ops.rs:661-667`); winfsp tracks the same
  concept as `is_new_file` computed at `write_ops.rs:759-764`.
- The `UploadSpawnParams` struct is defined inline in each file with slightly different
  field lists (`ino` is explicit in the fuser struct; winfsp captures it from outer scope).

**Proposed consolidation:** Extract a `build_upload_journal_entry` free function (or
inherent method on `CipherBoxFS`) in `crates/fuse/src/lib.rs` or a new
`crates/fuse/src/journal_helpers.rs` module that:
- Takes `&CipherBoxFS`, `ino`, `fh` and returns `Result<(JournalEntry, UploadSpawnParams), String>`.
- Both platforms call this shared fn; each platform wraps the result with its own
  reply/return-value machinery.
- Alternatively, factor out only the `JournalEntry`-building step (steps 1–6) into a helper,
  leaving the inode mutation (step 7) and spawn (step 8) in each caller.

**Similarly for mkdir/create-dir:**

- fuser mkdir: `crates/fuse/src/write_ops.rs` lines 430–689 — the closure starting at `(|| -> Result<fuser::FileAttr, String> {`).
- winfsp create-dir: `crates/fuse/src/platform/windows/write_ops.rs` lines 75–284 — the closure starting at `(|| -> Result<(FileAttrs, u64), String> {`.
- Both generate the same `JournalEntry { op: JournalOp::MkdirPublish { ... } }` with the same ECIES-wrap logic.

### Item #12 — Extract shared journal-dir + max-retries helper

**Two places construct the WriteQueue path identically:**

1. `apps/desktop/src-tauri/src/fuse/mod.rs` lines 103–117:

```rust
let journal_dir = dirs::data_local_dir()
    .unwrap_or_else(|| {
        log::warn!("data_local_dir unavailable; journal will use temp_dir...");
        std::env::temp_dir()
    })
    .join("cipherbox")
    .join("cb-journal");
std::fs::create_dir_all(&journal_dir)...;
let journal = cipherbox_sdk::WriteQueue::new(journal_dir, 5);
```

2. `apps/desktop/src-tauri/src/commands/sync.rs` — `start_sync_daemon` constructs:

```rust
dirs::data_local_dir().unwrap_or_else(std::env::temp_dir).join("cipherbox").join("cb-journal")
```

with `max_retries = 5` (per `43-08-SUMMARY.md` line 94–99).

**Proposed helper:** A `pub fn default_journal_dir() -> PathBuf` and `pub const JOURNAL_MAX_RETRIES: u32 = 5` in either `apps/desktop/src-tauri/src/fuse/mod.rs` (and re-exported) or a new `apps/desktop/src-tauri/src/journal.rs`. Both callers call the same function.

**Note:** The `crates/sdk` crate must not call `dirs::data_local_dir()` directly — that would add a Tauri-implicit coupling. The path stays in the `apps/desktop` layer, injected at construction time (as it already is).

### Item #15 — Memoize `resolve_folder_key` during replay

**Current behavior:** `replay_for_vault` calls `replay_mkdir_entry` and `replay_upload_entry`
for each journal entry. Each of those calls `resolve_folder_key` (lib.rs:1244 for mkdir,
lib.rs:1341 for upload). `resolve_folder_key` (lib.rs:1031–1090) does a BFS from root,
fetching and decrypting each level's metadata. For N entries sharing the same parent folder,
this is N identical BFS traversals.

**Locations of all `resolve_folder_key` calls in replay:**

- `replay_mkdir_entry` at lib.rs:1244–1251:
```rust
let parent_folder_key = resolve_folder_key(
    api, private_key, root_folder_key, root_ipns_name, parent_folder_ipns_name,
).await?;
```

- `replay_upload_entry` at lib.rs:1341–1348:
```rust
let parent_folder_key = resolve_folder_key(
    api, private_key, root_folder_key, root_ipns_name, parent_folder_ipns_name,
).await?;
```

**Proposed memoization:** Add a `HashMap<String, Vec<u8>>` cache (IPNS name → unwrapped folder key)
to `replay_for_vault` at lib.rs:870. Pass it as `&mut HashMap<String, Vec<u8>>` to
`replay_mkdir_entry` and `replay_upload_entry`. On cache hit, skip the BFS. On miss, run
the BFS and insert the result.

```rust
// In replay_for_vault (lib.rs:870), after `let ordered = ...`:
let mut folder_key_cache: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
// Insert root key immediately (BFS would return it trivially):
folder_key_cache.insert(root_ipns_name.to_string(), root_folder_key.to_vec());
```

Then change `replay_mkdir_entry` and `replay_upload_entry` signatures to accept
`folder_key_cache: &mut HashMap<String, Vec<u8>>` and look up before calling `resolve_folder_key`.

**Invariant preservation:** The BFS node-cap (`MAX_RESOLVE_NODES = 32` at lib.rs:1040)
and the "if folder_ipns_name == root_ipns_name, return immediately" shortcut at lib.rs:1042
both remain intact. The cache is a pure performance optimization — it does not bypass the
BFS for uncached folders.

**Security note:** The cached folder keys are in-process memory only (same lifetime as the
replay function call, which runs at mount time and returns before the FS thread starts).
No persistence of decrypted keys.

### Item #18 — Replace empty-string `file_meta_ipns_name` sentinel with `Option<String>`

**Current sentinel usage:** In `JournalOp::UploadFile`, the field `file_meta_ipns_name: String`
holds either a real IPNS name string OR an empty string `""` when the inode has no per-file
IPNS name. This empty-string sentinel pattern appears in:

1. **Write side (fuser)** — `read_ops.rs:806–808`:
```rust
let file_meta_ipns_name_str = file_meta_ipns_name
    .clone()
    .unwrap_or_default();  // <-- produces "" when None
```
Then `file_meta_ipns_name_str` is placed into `JournalOp::UploadFile { file_meta_ipns_name: file_meta_ipns_name_str, ... }`.

2. **Write side (winfsp)** — `platform/windows/write_ops.rs:881–883`:
```rust
let file_meta_ipns_name_str = file_meta_ipns_name
    .clone()
    .unwrap_or_default();  // <-- produces "" when None
```

3. **Replay side** — `replay_upload_entry` at lib.rs:1304:
```rust
file_meta_ipns_name: &str,
```
Then at lib.rs:1351–1353:
```rust
if let Some(file_ipns_key_hex_str) = file_ipns_key_hex {
    if !file_ipns_key_hex_str.is_empty() {
```
The emptiness check on `file_ipns_key_hex` (already `Option<&str>`) is correct. But
`file_meta_ipns_name` itself is used raw (e.g., at lib.rs:1397, 1441) without an emptiness
guard — callers rely on `file_ipns_key_hex` being `None` to skip the per-file publish block.

**Change required:**

- In `crates/sdk/src/queue.rs`, change:
  ```rust
  // JournalOp::UploadFile
  file_meta_ipns_name: String,
  ```
  to:
  ```rust
  file_meta_ipns_name: Option<String>,
  ```

- On write sides (fuser + winfsp), the `unwrap_or_default()` call that produces `""` is
  replaced by passing the `Option<String>` directly:
  ```rust
  // Before:
  let file_meta_ipns_name_str = file_meta_ipns_name.clone().unwrap_or_default();
  // ...
  file_meta_ipns_name: file_meta_ipns_name_str,

  // After:
  file_meta_ipns_name: file_meta_ipns_name,  // Option<String>
  ```

- In `replay_upload_entry`, change parameter `file_meta_ipns_name: &str` to
  `file_meta_ipns_name: Option<&str>`, and guard the file-IPNS publish block on
  `if let Some(ipns_name) = file_meta_ipns_name`.

- The `replay_for_vault` call site at lib.rs:978 already pattern-matches
  `JournalOp::UploadFile { file_meta_ipns_name, ... }` — update to use `Option`.

**Existing tests that exercise this path:** `make_upload_entry` in `queue.rs` tests (line 341)
sets `file_meta_ipns_name` to a fixed string `"k51filemetaipns"`. The serialization tests
(`upload_entry_round_trips`, etc.) will need to be updated to use `Some("k51filemetaipns")`.

**Breaking change scope:** `JournalEntry` is serialized as JSON to disk. Changing
`file_meta_ipns_name: String` to `file_meta_ipns_name: Option<String>` will change the
JSON representation. Serde serializes `Option::None` as `null` and `Option::Some(s)` as
the string `s` (same as before for non-None), but `null` vs `""` is a format change.
**Existing on-disk entries with `""` will fail to deserialize into `Option<String>`.**
Solution: use a serde helper that maps `""` → `None` during deserialization, OR perform a
one-time migration in `load_all_for_vault` that patches old entries. The simpler approach is
to use `#[serde(default, deserialize_with = "deserialize_option_string")]` that maps `""` to `None`.

### Item #19 — Replace not-found string-match with a typed error

**Current stringly-typed pattern:** In `spawn_bin_entry_publish` at `lib.rs:482–488`:
```rust
Err(e) => {
    let e_str = format!("{}", e);
    if e_str.to_lowercase().contains("not found") {
        (cipherbox_core::empty_bin_metadata(), None)
    } else {
        log::warn!("Failed to resolve bin IPNS: {}", e);
        return Err(format!("Bin resolve failed: {}", e));
    }
}
```

A nearly identical pattern appears in `replay_upload_entry` at lib.rs:1397–1405:
```rust
Err(e) if e.to_lowercase().contains("not found") => {
    log::info!(
        "replay: per-file IPNS '{}' not found — creating as first publish (seq 0)",
        file_meta_ipns_name
    );
    (true, next_file_publish_sequence(true, None)?)
}
Err(e) => return Err(format!("resolve file IPNS sequence: {} — retaining entry", e)),
```

The `resolve_sequence` method on `PublishCoordinator` (lib.rs:224–247) calls
`cipherbox_api_client::ipns::resolve_ipns`. The "not found" signal originates in the API
client's HTTP response — a 404 becomes an error string.

**Proposed typed error:** Add a variant to `crates/fuse/src/error.rs` (currently has
`FuseError`) or to a new `crates/api-client/src/error.rs` extension:
```rust
// In crates/fuse/src/error.rs
pub enum ReplayError {
    NotFound,       // IPNS record does not exist (404)
    Other(String),  // All other errors
}
```

Or, simpler and lower-risk: add a helper function:
```rust
fn is_ipns_not_found(e: &str) -> bool {
    e.to_lowercase().contains("not found") || e.contains("404")
}
```

The typed-error approach requires changing `resolve_sequence` to return
`Result<u64, ReplayError>` which is a larger refactor. The minimal approach for this
phase is to:

1. Define `pub enum IpnsResolveOutcome { Found(u64), NotFound, Error(String) }` in
   `crates/fuse/src/error.rs`.
2. Add a wrapper `async fn resolve_ipns_or_not_found(coordinator, api, name) -> IpnsResolveOutcome`
   that calls `resolve_sequence` and classifies the error.
3. Replace the `e.to_lowercase().contains("not found")` matches in both callers with
   match on `IpnsResolveOutcome`.

**Scope note:** Only the two call sites listed above use this pattern inside the journal
replay path. The bin publish path (`spawn_bin_entry_publish:482`) is a separate concern and
can be left as-is for this phase to keep scope tight.

### Item #20 — Reuse `publish_file_metadata` in replay

**Current duplication:** `replay_upload_entry` (lib.rs:1353–1463) contains inline logic to:

1. ECIES-unwrap the file IPNS key (lib.rs:1356–1360).
2. Convert `parent_folder_key` to `[u8; 32]` (lib.rs:1362–1366).
3. Build a `FileMetadata` struct (lib.rs:1367–1378).
4. Cast the unwrapped key to `[u8; 32]` (lib.rs:1380–1388).
5. Determine `is_first_publish` / `new_seq` via a resolve call (lib.rs:1394–1405).
6. Encrypt the `FileMetadata` with `encrypt_file_metadata` (lib.rs:1407–1408).
7. Upload to IPFS (lib.rs:1413–1416).
8. Create an IPNS record, marshal, base64-encode (lib.rs:1418–1423).
9. Compute `encrypted_ipns_for_tee` / `tee_epoch` (lib.rs:1428–1438).
10. Build `IpnsPublishRequest` and call `publish_ipns` (lib.rs:1440–1462).

**`publish_file_metadata` signature** (operations.rs:125–201):
```rust
pub async fn publish_file_metadata(
    api: &cipherbox_api_client::ApiClient,
    file_meta: &cipherbox_core::FileMetadata,
    folder_key: &[u8],
    file_ipns_private_key: &zeroize::Zeroizing<Vec<u8>>,
    file_ipns_name: &str,
    coordinator: &crate::PublishCoordinator,
    tee_public_key: Option<&[u8]>,
    tee_key_epoch: Option<u32>,
    is_first_publish: bool,
) -> Result<(), String>
```

This function already handles steps 3–10 (encrypt, upload, create IPNS record, TEE wrap,
publish). It does NOT handle step 1 (ECIES-unwrap the key) or step 5 (determine
`is_first_publish`).

**What replay_upload_entry does that publish_file_metadata does not:**

- Step 1: ECIES-unwrap — replay must do this because it receives the wrapped hex from the
  journal; `publish_file_metadata` takes the unwrapped `Zeroizing<Vec<u8>>`.
- Step 5: determine `is_first_publish` via the "not found" pattern — the live path passes
  `is_first_publish` from the caller's context; replay determines it at runtime.

**Proposed change:** In `replay_upload_entry`, after computing `file_ipns_key` (unwrapped)
and determining `is_first_publish`, call `publish_file_metadata` instead of the inline steps 3–10:

```rust
let file_meta = cipherbox_core::folder::FileMetadata {
    version: "v1".to_string(),
    cid: file_cid.clone(),
    file_key_encrypted: wrapped_key_hex.to_string(),
    file_iv: iv_hex.to_string(),
    size,
    mime_type: String::new(),
    encryption_mode: "GCM".to_string(),
    created_at: created_at_ms,
    modified_at: created_at_ms,
    versions: None,
};

if let Err(e) = publish_file_metadata(
    api, &file_meta, &parent_folder_key, &file_ipns_key,
    file_meta_ipns_name, coordinator.as_ref(),
    tee_public_key, tee_key_epoch,
    is_first_publish,
).await {
    return Err(format!("replay file IPNS publish: {}", e));
}
```

**A `cas_publish` helper** is not strictly necessary for this phase. The only CAS publish
that needs a helper is the parent publish in `fetch_merge_publish_parent`, which already
encapsulates that logic. No other caller in replay does a raw CAS publish.

**One complication:** `publish_file_metadata` (operations.rs:125) is gated behind
`#[cfg(feature = "fuse")]` (implicitly, since it's in `pub(crate) mod implementation`
under `#[cfg(feature = "fuse")]`). But `replay_upload_entry` is gated behind
`#[cfg(any(feature = "fuse", feature = "winfsp"))]`. The function must be available
under both features. Move `publish_file_metadata` out of the `#[cfg(feature = "fuse")]`
block into a top-level `#[cfg(any(feature = "fuse", feature = "winfsp"))]` function in
`lib.rs` or `operations.rs`, or expose it via a re-export.

Currently `operations.rs` is in `pub(crate) mod implementation` which is itself behind
`#[cfg(feature = "fuse")]` (operations.rs line 9). The import in `read_ops.rs:66-68`:
```rust
use crate::operations::implementation::{
    ..., publish_file_metadata,
};
```
and in `platform/windows/write_ops.rs:21-28`:
```rust
use super::super::operations::implementation::{
    ..., publish_file_metadata,
};
```

The winfsp path already imports `publish_file_metadata` from `operations.rs`, so the
function is already accessible under both features (since the winfsp build includes
`operations.rs` for this import). Verify with `cargo check --no-default-features --features winfsp`.

### Item #14 — Raise Phase-43 write-durability test coverage

**Existing tests (all in `crates/sdk/src/queue.rs` `#[cfg(test)]` at line 336):**

| Test name | What it covers |
| --- | --- |
| `upload_entry_round_trips` | Serialize/deserialize `UploadFile` entry |
| `mkdir_entry_round_trips` | Serialize/deserialize `MkdirPublish` entry |
| `journal_no_plaintext` | D-05: raw key bytes not in JSON |
| `failed_status_round_trips` | `JournalEntryStatus::Failed` serialization |
| `journal_put_load` | `put` + `load_all_for_vault` round-trip (disk) |
| `load_all_for_vault_excludes_foreign_vault` | D-07 vault scoping |
| `journal_remove` | `remove` deletes file, `load_all` returns empty |
| `update_status_persists_new_status` | `update_status` overwrites on disk |
| `park_on_max_retries` | D-09: entry kept on disk, status transitions to Failed |
| `record_failure_below_max_increments_retries` | retry increment behavior |
| `malformed_json_is_skipped_not_panicked` | T-43-03 / V5: graceful skip |
| `upload_entry_parent_ipns_key_hex_round_trips` | CR-01 / D-04 parent key in entry |
| `mkdir_entry_parent_ipns_key_hex_round_trips` | CR-01 / D-04 parent key in entry |
| `replay_order_sorts_by_created_at_within_group` | WR-01 created_at_ms ordering |
| `journal_no_plaintext_with_parent_ipns_key` | D-05 extended: parent key not raw |
| `replay_order_mkdir_before_upload` | D-08: MkdirPublish before UploadFile |
| `replay_order_preserves_relative_order_within_group` | stable sort within group |

**Tests in `crates/fuse/src/lib.rs` `#[cfg(test)]`** (line 1500):

| Test name | What it covers |
| --- | --- |
| `next_file_publish_sequence_starts_new_records_at_zero` | seq=0 on first publish |
| `next_file_publish_sequence_increments_existing_records` | seq+1 on update |
| `next_file_publish_sequence_rejects_missing_existing_sequence` | error on None |
| `replay_records_failure_and_parks_at_max_retries` | F2: retry accumulation + park |

**Tests in `apps/desktop/src-tauri/src/fuse/mod.rs` `#[cfg(test)]`** (line 319):

| Test name | What it covers |
| --- | --- |
| `merge_both_empty` | merge of two empty folders |
| `merge_disjoint_children_union` | union merge adds both sides |
| `merge_identical_uses_local` | local version wins on same IPNS key |

**Coverage gaps (items the planner should assign tests for):**

| Gap ID | Missing Behavior | Test Type | Proposed Location |
| --- | --- | --- | --- |
| T-45-01 | Crash mid-write: `put` succeeds but background upload never runs (process killed) — `load_all_for_vault` must return the entry after restart | Integration (disk) | `crates/sdk/src/queue.rs` |
| T-45-02 | Partial journal write: file exists on disk but is truncated (simulated by writing half the JSON) — `load_all` skips with warn, no panic | Unit | `crates/sdk/src/queue.rs` |
| T-45-03 | Retry exhaustion: `record_failure` called `max_retries + 1` times on the same entry; entry must remain on disk as `Failed` and NOT be removed | Unit | `crates/sdk/src/queue.rs` |
| T-45-04 | Typed sentinel path (#18): `UploadFile` entry with `file_meta_ipns_name: None` serializes to `null` and deserializes back to `None` (backward-compat serde helper) | Unit | `crates/sdk/src/queue.rs` |
| T-45-05 | Not-found typed error (#19): `IpnsResolveOutcome::NotFound` triggers `is_first_publish=true` path in replay | Unit (mock) | `crates/fuse/src/lib.rs` |
| T-45-06 | `replay_for_vault` skips `Failed` entries: put a `Failed` entry, run replay, verify the entry is NOT removed and the failed entry count stays at 1 | Integration (disk) | `crates/fuse/src/lib.rs` |
| T-45-07 | `resolve_folder_key` cache hit: if the same `parent_folder_ipns_name` appears in two journal entries, the BFS is only done once (verify via call-count mock or by checking the cache has one entry after two lookups) | Unit | `crates/fuse/src/lib.rs` |
| T-45-08 | `merge_folder_children` with both a new file and an existing file: merged result contains both; existing file's local version wins | Unit | `apps/desktop/src-tauri/src/fuse/mod.rs` or `crates/fuse/src/lib.rs` |

**Note on T-45-01:** This is not a pure unit test — it requires the journal to write to disk
and survive the end of a test function (simulating crash). The `make_temp_queue` helper in
the existing test module already creates an isolated temp dir per test; the test just needs
to not call `journal.remove()` and then call `WriteQueue::new(same_dir, _)` and
`load_all_for_vault` in a new scope.

## Standard Stack

### Core (already in workspace — no new deps)

| Library | Version | Purpose | Why Standard |
| --- | --- | --- | --- |
| `crates/sdk` | workspace | WriteQueue, JournalEntry, JournalOp | All journal types live here |
| `crates/fuse` | workspace | replay_for_vault, publish_file_metadata, merge_folder_children | All replay logic lives here |
| `serde` / `serde_json` | workspace | Journal serialization / deserialization | Already used throughout queue.rs |
| `std::fs` | std | Disk read/write for journal files | No external dep needed |
| `tokio` | workspace | Async replay execution | Already in fuse dev-deps |

### No New External Dependencies

All seven items are refactors or test additions. Zero external packages are added.

## Package Legitimacy Audit

> No new external packages are introduced in this phase.

**Packages removed due to SLOP verdict:** none
**Packages flagged as suspicious:** none

## Architecture Patterns

### System Architecture Diagram

```
[Item #14 tests]   [Item #15 memoize]   [Item #18/#19 typed]
       |                   |                     |
       v                   v                     v
crates/sdk/src/queue.rs    crates/fuse/src/lib.rs::replay_for_vault
       |                         |
       |              +----------+-----------+
       |              |                      |
       v              v                      v
#[cfg(test)]   replay_mkdir_entry   replay_upload_entry
 queue tests   (#1244 lib.rs)       (#1294 lib.rs)
                      |                      |
                      v                      v
               resolve_folder_key    resolve_folder_key  <-- #15 memoize
               (#1031 lib.rs)        (#1031 lib.rs)
                      |                      |
                      v                      v
            fetch_merge_publish_parent      [#20] -> publish_file_metadata
            (#1105 lib.rs)                  (operations.rs:125)


[Item #11 consolidation]                [Item #12 helper]
        |                                      |
  read_ops.rs:695              fuse/mod.rs:103-117
  windows/write_ops.rs:791  + commands/sync.rs:start_sync_daemon
        |                                      |
        v                                      v
  journal_helpers.rs             default_journal_dir() + JOURNAL_MAX_RETRIES
  (proposed shared build_upload_journal_entry)
```

### Recommended Project Structure (after refactor)

```
crates/fuse/src/
├── lib.rs            # replay_for_vault: add folder_key_cache (#15)
│                     # fetch_merge_publish_parent: unchanged
│                     # publish_file_metadata: move here if needed for winfsp (#20)
├── operations.rs     # publish_file_metadata stays here (already imported by winfsp)
├── read_ops.rs       # handle_release: call shared build_upload_journal_entry (#11)
├── write_ops.rs      # handle_mkdir: call shared build_mkdir_journal_entry (#11)
├── journal_helpers.rs  # NEW: build_upload_journal_entry, build_mkdir_journal_entry
│                        # (or move to lib.rs as inherent impl on CipherBoxFS)
└── platform/windows/write_ops.rs  # handle_cleanup + handle_create: call shared helpers (#11)

crates/sdk/src/
└── queue.rs          # JournalOp::UploadFile.file_meta_ipns_name: Option<String> (#18)
                      # + added tests (#14)

apps/desktop/src-tauri/src/
├── fuse/mod.rs       # use default_journal_dir() + JOURNAL_MAX_RETRIES (#12)
└── commands/sync.rs  # use default_journal_dir() + JOURNAL_MAX_RETRIES (#12)
```

### Pattern 1: Shared upload-journal-entry builder

**What:** Single function that performs the encrypt → ECIES-wrap → inode-resolve → entry-build steps common to `handle_release` and `handle_cleanup`.

**When to use:** Called by both fuser `handle_release` and winfsp `handle_cleanup` instead of inline closures.

```rust
// Source: codebase synthesis from read_ops.rs:695-925 and windows/write_ops.rs:791-1004
pub struct UploadJournalResult {
    pub entry: cipherbox_sdk::JournalEntry,
    pub ciphertext: Vec<u8>,
    pub file_meta: cipherbox_core::folder::FileMetadata,
    pub file_ipns_private_key: Option<zeroize::Zeroizing<Vec<u8>>>,
    pub file_meta_ipns_name: Option<String>,
    pub folder_key_for_file_meta: Option<Vec<u8>>,
    pub old_file_cid: Option<String>,
    pub pruned_cids: Vec<String>,
    pub write_gen: u64,
    pub parent_ino: u64,
}

impl CipherBoxFS {
    pub fn build_upload_journal_entry(
        &mut self,
        ino: u64,
        fh: u64,
        is_new_file: bool,
    ) -> Result<UploadJournalResult, String> {
        // Steps 1-6: encrypt, wrap, resolve parent IPNS, build JournalEntry
        // Steps 7+: inode mutation deferred to caller (platform-specific)
        todo!()
    }
}
```

### Pattern 2: Typed IPNS resolve outcome

```rust
// In crates/fuse/src/error.rs (or lib.rs)
pub enum IpnsResolveOutcome {
    Found(u64),
    NotFound,
    Error(String),
}

pub async fn resolve_ipns_for_replay(
    coordinator: &PublishCoordinator,
    api: &ApiClient,
    ipns_name: &str,
) -> IpnsResolveOutcome {
    match coordinator.resolve_sequence(api, ipns_name).await {
        Ok(seq) => IpnsResolveOutcome::Found(seq),
        Err(e) if e.to_lowercase().contains("not found") || e.contains("404") => {
            IpnsResolveOutcome::NotFound
        }
        Err(e) => IpnsResolveOutcome::Error(e),
    }
}
```

### Pattern 3: Memoized folder-key resolution in replay

```rust
// In replay_for_vault at lib.rs:898 (after ordered = ...):
let mut folder_key_cache: std::collections::HashMap<String, Vec<u8>> = {
    let mut m = std::collections::HashMap::new();
    m.insert(root_ipns_name.to_string(), root_folder_key.to_vec());
    m
};

// Helper wrapper:
async fn resolve_folder_key_cached(
    cache: &mut HashMap<String, Vec<u8>>,
    api: &ApiClient,
    private_key: &[u8],
    root_folder_key: &[u8],
    root_ipns_name: &str,
    folder_ipns_name: &str,
) -> Result<Vec<u8>, String> {
    if let Some(key) = cache.get(folder_ipns_name) {
        return Ok(key.clone());
    }
    let key = resolve_folder_key(api, private_key, root_folder_key, root_ipns_name, folder_ipns_name).await?;
    cache.insert(folder_ipns_name.to_string(), key.clone());
    Ok(key)
}
```

### Anti-Patterns to Avoid

- **Changing replay semantics while refactoring:** Every refactor must produce identical
  behavior to the current code. Run the existing tests before and after each item.
- **Extracting the shared helper into `crates/sdk`:** The sdk crate has no access to
  `CipherBoxFS`, `ApiClient`, or crypto utilities from `crates/fuse`. The shared helper
  must live in `crates/fuse` or `apps/desktop`.
- **Re-wrapping keys in the shared helper:** Several comments in the code (`CR-03`, `CR-02`)
  warn that keys stored in journal entries are already wrapped exactly once. Any shared helper
  that wraps again would produce doubly-wrapped keys on disk that fail to unwrap on replay.
- **Adding `async` to `pub fn put()` in WriteQueue:** The `fsync` barrier must remain
  synchronous blocking I/O inside the FUSE callback thread. The existing `std::fs::File::sync_all()`
  is correct; do not change it to async.
- **Caching folder keys across mounts:** The `folder_key_cache` proposed for #15 must be
  local to a single `replay_for_vault` call. It must NOT be persisted or shared with
  the running filesystem.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
| --- | --- | --- | --- |
| "Not found" IPNS classification | Another `.contains("not found")` match | `IpnsResolveOutcome` enum + wrapper fn (#19) | Centralizes the brittle string match |
| Folder-key BFS | A second BFS implementation | `resolve_folder_key` at lib.rs:1031 | Already implements BFS + node-cap |
| File metadata publish in replay | Inline encrypt/upload/sign/publish in replay | `publish_file_metadata` at operations.rs:125 | Already handles all steps including TEE enrollment |
| Journal path construction | A third copy of the `dirs::data_local_dir().join("cipherbox").join("cb-journal")` line | `default_journal_dir()` helper (#12) | Prevents silent drift between fuse mount and sync daemon |

## Common Pitfalls

### Pitfall 1: On-disk format break from `Option<String>` change (#18)

**What goes wrong:** Existing journal entries on disk have `"file_meta_ipns_name": ""` (an
empty string). After the type change to `Option<String>`, `serde_json` expects `null` for
`None`. Entries written by old code will fail to deserialize into the new type.

**How to avoid:** Add a custom Serde deserializer for the field that maps empty string to `None`:

```rust
fn deser_opt_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    let s: Option<String> = Option::deserialize(d)?;
    Ok(s.filter(|v| !v.is_empty()))
}
// On the field:
#[serde(default, deserialize_with = "deser_opt_string")]
pub file_meta_ipns_name: Option<String>,
```

**Warning signs:** `malformed_json_is_skipped_not_panicked` test fails; on-disk entries
loaded from a journal written before this change produce deserialization errors.

### Pitfall 2: `publish_file_metadata` feature gate mismatch (#20)

**What goes wrong:** `publish_file_metadata` is currently inside
`pub(crate) mod implementation` which is behind `#[cfg(feature = "fuse")]` in `operations.rs`.
The winfsp build (`--no-default-features --features winfsp`) already imports it via
`super::super::operations::implementation::publish_file_metadata` (windows/write_ops.rs:26),
so it compiles today only because `operations.rs` is also included in the winfsp build
(it's not behind a feature flag at the file level — the `#[cfg(feature = "fuse")]` is only
on the `mod` declaration in `lib.rs:16`).

After the #20 refactor, check that `cargo check --no-default-features --features winfsp` still passes.

**Warning signs:** CI `cargo-windows` job fails with "cannot find function `publish_file_metadata`".

### Pitfall 3: `folder_key_cache` invalidation on concurrent replay (#15)

**What goes wrong:** The cache holds folder keys decoded from the CURRENT remote state at
replay time. If a journal entry's parent folder has been mutated by another device between
when the cache was populated and when the entry is processed, the cached key is still correct
(the key is derived from the `folder_key_encrypted` field of the folder entry, which does not
change unless the folder is re-keyed; re-keying is not a supported operation). So this is not
actually a correctness risk — just a potential confusion.

**How to avoid:** Document in the cache helper that the cache holds unwrapped folder keys
and is safe to reuse for the duration of a single `replay_for_vault` call.

### Pitfall 4: Removing `is_new_file` context from shared journal builder (#11)

**What goes wrong:** `is_new_file` in `handle_release` (fuser) is computed before the closure
at `read_ops.rs:661-667`. It is passed into `publish_file_metadata` at `read_ops.rs:970`
as the `is_first_publish` parameter. If the shared builder extracts everything into a struct
but forgets to carry `is_new_file`, the per-file IPNS publish will use the wrong sequence.

**How to avoid:** Include `is_new_file: bool` (or renamed `is_first_publish: bool`) in the
`UploadJournalResult` struct returned by the shared builder.

## Validation Architecture

### Test Framework

| Property | Value |
| --- | --- |
| Framework | Rust built-in `#[test]` + `#[tokio::test]` |
| Config file | none (cargo test per crate) |
| Quick run command | `cargo test -p cipherbox-sdk -- --test-threads=4` |
| Full suite command (macOS/Linux) | `cargo test --workspace --no-default-features --features fuse` |
| Full suite command (Windows CI) | `cargo test --workspace --no-default-features --features winfsp` |
| Format check | `cargo fmt --check -p cipherbox-sdk -p cipherbox-fuse` |
| Lint | `cargo clippy -p cipherbox-sdk -p cipherbox-fuse --no-default-features --features fuse -- -D warnings` |

### Phase Requirements → Test Map

Each refactor item is validated by the tests that exercise the code path being changed.
"Behavior preserved" = same tests pass before and after the refactor.

| Item | Behavior | Test Type | Validation Command | File Exists? |
| --- | --- | --- | --- | --- |
| #11 consolidate write paths | handle_release and handle_cleanup produce identical JournalEntry | unit (disk) | `cargo test -p cipherbox-sdk -- journal_put_load` | Yes (existing) |
| #11 consolidate write paths | shared helper preserves is_new_file | unit | new test T-45-01 | No — Wave 0 |
| #12 journal-dir helper | both mount and sync daemon use same path | unit (path comparison) | new test T-45-helper | No — Wave 0 |
| #14 test coverage | crash mid-write: entry survives to next load | integration (disk) | `cargo test -p cipherbox-sdk -- T-45-01` | No — Wave 0 |
| #14 test coverage | partial journal write: skip with warn | unit | `cargo test -p cipherbox-sdk -- T-45-02` | No — Wave 0 |
| #14 test coverage | retry exhaustion: entry stays as Failed | unit | `cargo test -p cipherbox-sdk -- T-45-03` | No — Wave 0 |
| #14 test coverage | replay skips Failed entries | integration | `cargo test -p cipherbox-fuse -- T-45-06` | No — Wave 0 |
| #15 memoize resolve_folder_key | same parent_folder_ipns_name → BFS runs once | unit (mock) | `cargo test -p cipherbox-fuse -- T-45-07` | No — Wave 0 |
| #18 Option<String> sentinel | None serializes/deserializes correctly | unit | `cargo test -p cipherbox-sdk -- T-45-04` | No — Wave 0 |
| #18 Option<String> sentinel | old on-disk "" entry loads as None | unit | `cargo test -p cipherbox-sdk -- T-45-04-compat` | No — Wave 0 |
| #19 typed not-found error | NotFound → is_first_publish=true path | unit | `cargo test -p cipherbox-fuse -- T-45-05` | No — Wave 0 |
| #20 reuse publish_file_metadata | replay publish path is identical to live path | compile check | `cargo check --no-default-features --features fuse` | — |

### Sampling Rate

- **Per task commit:** `cargo test -p cipherbox-sdk -- --test-threads=4`
- **Per wave merge:** `cargo test --workspace --no-default-features --features fuse`
- **Phase gate:** Full suite green on both `fuse` and `winfsp` feature flags before `/gsd-verify-work`

### Wave 0 Gaps

- New test functions for T-45-01 through T-45-08 in `crates/sdk/src/queue.rs` and
  `crates/fuse/src/lib.rs` (no new test files needed — append to existing `#[cfg(test)]` modules)
- `crates/fuse/src/error.rs` — `IpnsResolveOutcome` enum + `resolve_ipns_for_replay` helper (#19)
- `crates/fuse/src/journal_helpers.rs` (optional) — `build_upload_journal_entry`, `build_mkdir_journal_entry` (#11)
- `apps/desktop/src-tauri/src/fuse/journal.rs` or inline in `mod.rs` — `default_journal_dir()` + `JOURNAL_MAX_RETRIES` (#12)

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
| --- | --- | --- |
| V2 Authentication | no | — |
| V3 Session Management | no | — |
| V4 Access Control | no | — |
| V5 Input Validation | yes | `serde_json::from_slice` returns Err on malformed; existing skip-with-warn behavior preserved |
| V6 Cryptography | yes | No new crypto code; refactors must not change key handling (no double-wrap, no raw key in journal) |

### Security Notes

- Every refactored code path that touches `wrapped_key_hex`, `parent_ipns_key_hex`, or
  `child_ipns_key_hex` must preserve the invariant: these fields hold user-ECIES-wrapped
  keys, never raw. Comments `CR-01`, `CR-02`, `CR-03` in the source document this.
- The shared `build_upload_journal_entry` helper must never expose plaintext or raw key bytes
  in its return value. The `UploadJournalResult` struct must hold `ciphertext: Vec<u8>` (never
  plaintext) and the file key must be zeroized before the helper returns.
- The `IpnsResolveOutcome::NotFound` path in #19 creates a first-publish with TEE enrollment.
  The TEE enrollment path in `publish_file_metadata` must be reached correctly — do not
  skip it by always treating resolves as `Found`.

## Project Constraints (from CLAUDE.md)

- TypeScript enums → string literals (not applicable: Rust-only phase)
- Never store `privateKey` in localStorage (not applicable: desktop Rust)
- Never persist plaintext or raw keys (enforced by existing CR-01/02/03 comments; refactors must preserve)
- Always use ECIES for key wrapping (preserved; no new wrapping in this phase)
- Never push directly to main; use feature branches
- Commit format: Conventional Commits — `refactor(fuse): ...` or `test(fuse): ...`
- Markdownlint enforced on commit: use headings not bold-as-heading, blank lines around code blocks/lists
- No `pnpm api:generate` needed (no API changes)

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
| --- | --- | --- | --- |
| A1 | `operations.rs` (containing `publish_file_metadata`) is compiled under both fuse and winfsp features because `lib.rs:16` has `#[cfg(feature = "fuse")] pub mod operations` but windows/write_ops.rs imports from it anyway | Item #20 | If winfsp build breaks after #20, need to move publish_file_metadata to a shared module |
| A2 | Empty-string `file_meta_ipns_name: ""` entries may exist on user machines between Phase 43 and Phase 45 deployment | Item #18 | Serde compat shim is required; without it, old entries fail to load silently |
| A3 | The memoized folder-key cache for #15 is safe because folder keys never change for the lifetime of a folder (no re-keying operation exists) | Item #15 | If a re-keying operation is added later, the cache may return stale keys |
| A4 | `commands/sync.rs` constructs the WriteQueue path via `dirs::data_local_dir()...join("cipherbox").join("cb-journal")` with `max_retries = 5` (from 43-08-SUMMARY.md description; not directly read) | Item #12 | If the actual code uses different values, the dedup helper will need adjustment |

## Open Questions

1. **Should the shared upload-journal builder (#11) be an inherent method on `CipherBoxFS` or a free function?**
   - Both fuser and winfsp paths take `&mut CipherBoxFS` — an inherent method avoids passing the struct by reference. The main risk is borrow-checker conflicts if the closure currently borrows multiple fields of `fs` simultaneously. Recommend: inherent method that takes the `ino` and `fh` parameters and accesses `self.inodes`, `self.journal`, etc. directly.

2. **For #19, should `IpnsResolveOutcome` live in `crates/fuse/src/error.rs` or `crates/fuse/src/lib.rs`?**
   - Both are fine. `error.rs` is the cleaner location for an error-related type. Recommend: `error.rs`.

3. **Does `cargo fmt` need to be run workspace-wide or per-crate after refactors?**
   - CI runs `cargo fmt --check` at the workspace level. Run `cargo fmt` before each commit on changed files.

## Sources

### Primary (HIGH confidence)

All findings from direct codebase reads:

- `crates/sdk/src/queue.rs` — `JournalEntry`, `JournalOp`, `WriteQueue`, all 17 existing tests
- `crates/fuse/src/read_ops.rs:650–1023` — `handle_release` fuser write path + journal call
- `crates/fuse/src/write_ops.rs:401–689` — `handle_mkdir` fuser mkdir path + journal call
- `crates/fuse/src/platform/windows/write_ops.rs:73–1083` — `handle_create` (dir) and `handle_cleanup` winfsp paths
- `crates/fuse/src/lib.rs:859–1493` — `replay_for_vault`, `replay_mkdir_entry`, `replay_upload_entry`, `fetch_merge_publish_parent`, `resolve_folder_key`
- `crates/fuse/src/operations.rs:125–201` — `publish_file_metadata` full signature and implementation
- `apps/desktop/src-tauri/src/fuse/mod.rs:102–117` — journal-dir construction in mount path
- `.github/workflows/ci.yml:557–647` — CI Rust test commands for all platforms

### Secondary (MEDIUM confidence)

- `.planning/phases/43-fuse-write-durability/43-08-SUMMARY.md` — confirms `commands/sync.rs` WriteQueue path and `max_retries = 5`
- `.planning/phases/43-fuse-write-durability/43-RESEARCH.md` — architectural decisions D-01..D-12

## Metadata

**Confidence breakdown:**

- Standard Stack: HIGH — all libraries confirmed present in Cargo.toml; no new deps
- Architecture: HIGH — all file:line citations from direct code reads
- Pitfalls: HIGH — derived from reading the actual implementation and CR-numbered comments
- Test gaps: HIGH — derived from exhaustive enumeration of existing `#[cfg(test)]` modules

**Research date:** 2026-06-14
**Valid until:** 2026-07-14 (stable Rust codebase; valid until another phase modifies fuse write paths)
