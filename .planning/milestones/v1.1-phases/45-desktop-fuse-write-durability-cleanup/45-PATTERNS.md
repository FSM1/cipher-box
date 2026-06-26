# Phase 45: Desktop FUSE Write-Durability Cleanup - Pattern Map

**Mapped:** 2026-06-14
**Files analyzed:** 3 (journal_helpers.rs new, error.rs additive, #[cfg(test)] additions)
**Analogs found:** 3 / 3

## File Classification

| New/Modified File                         | Role     | Data Flow    | Closest Analog                       | Match Quality |
| ----------------------------------------- | -------- | ------------ | ------------------------------------ | ------------- |
| `crates/fuse/src/journal_helpers.rs`      | utility  | transform    | `crates/fuse/src/helpers.rs`         | exact         |
| `crates/fuse/src/error.rs` (additive)     | error    | n/a          | `crates/fuse/src/error.rs` (existing FuseError) | self-analog |
| `crates/sdk/src/queue.rs` `#[cfg(test)]`  | test     | CRUD + disk  | `crates/sdk/src/queue.rs` (existing tests) | self-analog |
| `crates/fuse/src/lib.rs` `#[cfg(test)]`   | test     | async/disk   | `crates/fuse/src/lib.rs` (existing tests) | self-analog |

---

## Pattern Assignments

### 1. `crates/fuse/src/journal_helpers.rs` (utility, transform)

**Analog:** `crates/fuse/src/helpers.rs`

Mirror this because: `helpers.rs` is the established pattern for small free-function
utility modules in the fuse crate — it uses a module-level doc comment, no struct, all
`pub fn` / `pub(crate) fn`, optional `#[cfg(any(feature = "fuse", feature = "winfsp"))]`
guards, and a `#[cfg(test)] mod tests { use super::*; ... }` at the bottom.

**Module declaration in `lib.rs`** (lines 1-13 of lib.rs):

```rust
// unconditionally declared (no feature gate) — mirror this for journal_helpers
pub mod helpers;
pub mod constants;
pub mod error;

// feature-gated modules — use this form if journal_helpers is fuse+winfsp-only:
#[cfg(feature = "fuse")]
pub mod operations;
```

For `journal_helpers`, the build-entry helpers are needed by both platforms, so declare
without a feature gate (matching `helpers` and `constants`) or with
`#[cfg(any(feature = "fuse", feature = "winfsp"))]` if the helpers reference
`CipherBoxFS` types.

**Module-level doc comment pattern** (helpers.rs lines 1-4):

```rust
//! Shared helper functions for the CipherBox FUSE filesystem.
//!
//! These functions are used by both macOS (fuser) and Windows (WinFsp)
//! filesystem implementations.
```

**Function with platform feature guard** (helpers.rs lines 67-68):

```rust
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn build_folder_path(fs: &crate::CipherBoxFS, folder_ino: u64) -> String {
```

**Test module at bottom of file** (helpers.rs lines 158-161):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    // ...sync #[test] fns only (no async helpers in helpers.rs)
```

---

### 2. `crates/fuse/src/error.rs` — add `IpnsResolveOutcome` (additive)

**Analog:** `crates/fuse/src/error.rs` existing `FuseError` (the whole file, 23 lines)

Mirror this because: `FuseError` shows the exact derive macro, `thiserror` usage,
variant naming, and `#[from]` / tuple-string style that `IpnsResolveOutcome` must match.

**Full existing file** (error.rs lines 1-23):

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FuseError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] cipherbox_crypto::CryptoError),
    #[error("Core error: {0}")]
    Core(#[from] cipherbox_core::CoreError),
    #[error("API error: {0}")]
    Api(#[from] cipherbox_api_client::ApiError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Mount failed: {0}")]
    MountFailed(String),
    #[error("Unmount failed: {0}")]
    UnmountFailed(String),
    #[error("Inode not found: {0}")]
    InodeNotFound(u64),
    #[error("File handle not found: {0}")]
    FileHandleNotFound(u64),
    #[error("Permission denied")]
    PermissionDenied,
}
```

**New `IpnsResolveOutcome` to append** (not an Error itself — no `thiserror`; it is a
typed outcome enum, not an error enum):

```rust
/// Typed outcome for IPNS sequence resolution.
///
/// Replaces stringly-typed `.contains("not found")` matches in the replay path.
#[derive(Debug)]
pub enum IpnsResolveOutcome {
    /// IPNS record exists; contains the current sequence number.
    Found(u64),
    /// IPNS record does not exist (404 / "not found").
    NotFound,
    /// Resolution failed for a non-404 reason.
    Error(String),
}
```

Note: `IpnsResolveOutcome` uses `#[derive(Debug)]` only (not `Error`), matching the
`FuseError` file's `use thiserror::Error` import already present — no new import needed
for `Debug`. The variant naming uses PascalCase with payload-in-parens for data variants,
consistent with `FuseError::MountFailed(String)`.

---

### 3. `#[cfg(test)]` additions in `queue.rs` and `lib.rs`

#### 3a. `crates/sdk/src/queue.rs` — new sync tests (T-45-01..T-45-04)

**Analog:** `crates/sdk/src/queue.rs` existing test module (lines 335-401 shown)

Mirror this because: all existing sdk tests are sync `#[test]`, use `make_temp_queue()`
for disk isolation, and import with `use super::*`.

**Test module header and helpers** (queue.rs lines 335-400):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // ---- Helper builders ----

    fn make_upload_entry(id: &str, vault: &str) -> JournalEntry {
        JournalEntry {
            id: id.to_string(),
            vault_root_ipns: vault.to_string(),
            op: JournalOp::UploadFile {
                ciphertext_b64: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    b"ciphertext",
                ),
                wrapped_key_hex: hex::encode(b"wrappedkey"),
                iv_hex: hex::encode(b"iv123456"),
                file_meta_ipns_name: "k51filemetaipns".to_string(), // becomes Some(...) after #18
                file_ipns_key_hex: None,
                parent_folder_ipns_name: "k51parentfolder".to_string(),
                parent_ipns_key_hex: hex::encode(b"ecies-wrapped-parent-ipns-key"),
                filename: "test.txt".to_string(),
                size: 42,
                created_at_ms: 1_700_000_000_000,
            },
            retries: 0,
            status: JournalEntryStatus::Pending,
        }
    }

    /// Create a unique temporary directory for test isolation.
    fn make_temp_queue() -> (WriteQueue, std::path::PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let tid_raw = format!("{:?}", std::thread::current().id());
        let tid_num: String = tid_raw.chars().filter(|c| c.is_ascii_digit()).collect();
        let dir = std::env::temp_dir()
            .join(format!("cipherbox-journal-test-{}-{}", seq, tid_num));
        std::fs::create_dir_all(&dir).expect("create test journal dir");
        let q = WriteQueue::new(dir.clone(), 3);
        (q, dir)
    }

    #[test]
    fn upload_entry_round_trips() {
        let entry = make_upload_entry("abc123", "k51vault");
        let json = serde_json::to_vec(&entry).expect("serialize");
        let back: JournalEntry = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(back.id, entry.id);
        // ...
    }
```

New tests (T-45-01..T-45-04) append inside this same `mod tests` block, following
the same `#[test]` (sync) pattern. `make_temp_queue()` already handles isolation; new
disk tests just omit the final `journal.remove()` call to simulate crash survival.

#### 3b. `crates/fuse/src/lib.rs` — new async tests (T-45-05..T-45-07)

**Analog:** `crates/fuse/src/lib.rs` test module (lines 1500-1579)

Mirror this because: fuse tests that need the async replay loop use
`#[cfg(any(feature = "fuse", feature = "winfsp"))] #[tokio::test]` and build a minimal
`WriteQueue` in a per-process temp dir.

**Async test pattern** (lib.rs lines 1527-1573):

```rust
#[cfg(any(feature = "fuse", feature = "winfsp"))]
#[tokio::test]
async fn replay_records_failure_and_parks_at_max_retries() {
    use cipherbox_sdk::{JournalEntry, JournalEntryStatus, JournalOp, WriteQueue};
    use std::sync::Arc;

    let dir = std::env::temp_dir()
        .join("cb-f2-replay-park-test")
        .join(format!("{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let journal = WriteQueue::new(dir.clone(), 5);
    let vault = "k51vaultf2park";

    // ... build JournalEntry inline ...
    journal.put(&entry).unwrap();

    let api = Arc::new(cipherbox_api_client::ApiClient::new("http://127.0.0.1:1"));
    let coordinator = Arc::new(super::PublishCoordinator::new());

    super::replay_for_vault(
        &journal, api.clone(), &[0u8; 32], &[0u8; 33], &[0u8; 32], vault,
        coordinator.clone(), None, None,
    )
    .await;

    let after = journal.load_all_for_vault(vault).unwrap();
    // assert on after[...].retries / .status
}
```

New tests T-45-05/06/07 append inside the same `#[cfg(test)] mod tests` block using
the same `#[cfg(any(feature = "fuse", feature = "winfsp"))] #[tokio::test]` dual
attribute pattern. Use `process::id()` suffix for temp dir uniqueness (matches existing
style in lib.rs tests, not the `AtomicU64` pattern from queue.rs).

---

## Shared Patterns

### Serde compat shim for `Option<String>` (#18)

**Apply to:** `JournalOp::UploadFile.file_meta_ipns_name` field in `crates/sdk/src/queue.rs`

Pattern already referenced in RESEARCH.md §Pitfall 1 — no codebase analog exists yet.
Use this exact form (it is the minimal correct approach):

```rust
fn deser_opt_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    let s: Option<String> = Option::deserialize(d)?;
    Ok(s.filter(|v| !v.is_empty()))
}

// On the field inside JournalOp::UploadFile { .. }:
#[serde(default, deserialize_with = "deser_opt_string")]
pub file_meta_ipns_name: Option<String>,
```

This is the ONLY case where a custom deserializer is needed in this phase.

---

## No Analog Found

| File / Symbol                                   | Role    | Reason                                              |
| ----------------------------------------------- | ------- | --------------------------------------------------- |
| `default_journal_dir()` + `JOURNAL_MAX_RETRIES` | utility | No existing shared journal-dir helper in the repo; fuse/mod.rs and commands/sync.rs both inline the path. New helper goes in `apps/desktop/src-tauri/src/fuse/mod.rs` (re-exported) or a new `journal.rs` sibling. Pattern is straightforward: a `pub fn` returning `PathBuf` + `pub const u32`. |

---

## Metadata

**Analog search scope:** `crates/fuse/src/`, `crates/sdk/src/`
**Files read:** error.rs, helpers.rs, lib.rs (lines 1-30, 1495-1610), queue.rs (lines 330-420)
**Pattern extraction date:** 2026-06-14
