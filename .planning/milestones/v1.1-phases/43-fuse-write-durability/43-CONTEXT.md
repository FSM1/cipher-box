# Phase 43: FUSE write durability - Context

**Gathered:** 2026-06-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Make desktop FUSE writes durable across all three platforms: a persisted out-of-callback pending-upload journal so `release()` no longer falsely acks then silently loses data, and mkdir parent-publish conflicts that actually retry instead of orphaning the child folder. Scope is `crates/sdk` (journal) + `crates/fuse` (wiring, both fuser and WinFsp paths) + minimal Tauri-side surfacing. No web/app/api changes.

**The two failure modes being fixed:**

1. `release()` acks the OS, spawns a detached upload thread, and deletes the plaintext temp file before the upload starts (`crates/fuse/src/read_ops.rs:791-848`); `flush` is a no-op. Crash/kill/upload-failure after the ack = silent permanent data loss.
2. `handle_mkdir` publishes the child IPNS record (seq 0) first, then CAS-publishes the parent; on conflict it only warns — the "debounced publish will retry" comment is false (`crates/fuse/src/write_ops.rs:581-610`, Windows mirror `platform/windows/write_ops.rs:194`). The child's folder key + IPNS private key exist only in the never-published parent metadata → irrecoverable orphan. `reply.entry()` also fires before the publish thread runs (crash window).

</domain>

<decisions>
## Implementation Decisions

### Journal design

- **D-01:** The journal is a persist-backed `WriteQueue` in `crates/sdk` (`src/queue.rs` — the todo's named fix point). Extend the existing trait-based queue with disk persistence; FUSE wires through it. The current memory-only "v1 tech demo" comment and semantics are superseded.
- **D-02:** Journal entries use STABLE identifiers — parent folder IPNS name, file-meta IPNS name, filename, vault identity — never `ino`/`parent_ino` (inode numbers don't survive remount). The existing `QueuedWrite` shape is reworked accordingly.
- **D-03:** Full op-log enum covering both todos: `UploadFile | MkdirPublish` variants. One durable replay path; closes mkdir's crash-before-thread-runs window, not just the conflict-retry bug.
- **D-04:** Durability ack barrier: journal entry fsynced to disk BEFORE `reply.ok()` / `reply.entry()`. macOS FUSE callbacks are single-threaded and must not block on network I/O (locked constraint from the todo) — local fsync is the only blocking work allowed in the callback.
- **D-05:** Journal contents are ciphertext + ECIES-wrapped keys + IV + metadata context only. NEVER plaintext, never raw keys (project crypto rules). The plaintext temp file is zeroized+deleted immediately after the ciphertext is journaled (not after thread spawn as today).

### Crash recovery & replay

- **D-06:** Replay = upsert into fresh remote: on mount/login, fetch the parent folder's CURRENT metadata, merge in the journaled child entry (insert or update that one entry), CAS-publish with retry. Never re-publish the stale journaled parent snapshot — that stomps multi-device changes (the lost-update class Phase 44 addresses on the TS side).
- **D-07:** Entries are tagged with vault identity (root IPNS name); login replays only entries matching the current vault. Foreign-vault entries stay untouched on disk.
- **D-08:** Replay order respects dependencies: a journaled `MkdirPublish` replays before `UploadFile` entries targeting that folder.
- **D-09:** Retry policy: exponential backoff up to a threshold, then the entry parks as `failed` — kept on disk, surfaced (D-10), manually retryable. Entries are NEVER silently dropped (the current `max_retries`-then-drop semantics are abolished).

### Failure surfacing

- **D-10:** OS notification fires only when an entry parks as failed; pending/failed counts ride the existing `SyncDaemon` `Arc<dyn Fn(SyncStatus)>` callback channel into the Tauri shell (tray/status). Transient retries are silent. Full pending-uploads management UI is explicitly deferred (see Deferred Ideas).

### mkdir conflict handling

- **D-11:** Two composing mechanisms: (a) live-session — on parent-publish conflict, signal the FS thread (existing `upload_tx`-style channel pattern) to insert the parent into `mutated_folders` so the debounced publisher retries promptly with fresh sequence; (b) crash safety — the journaled `MkdirPublish` entry clears only when the parent publish confirms. The misleading "will retry" comment gets replaced by behavior that actually retries.

### Platform scope

- **D-12:** All THREE platforms in this phase, structured as SEPARATE PLANS (user's explicit planning directive): journal core in `crates/sdk` (shared), fuser wiring (macOS + Linux share `crates/fuse/src/{read_ops,write_ops}.rs`), WinFsp wiring (`crates/fuse/src/platform/windows/write_ops.rs:821-865` release mirror + `:194` mkdir TODO).

### Claude's Discretion

- Journal on-disk format (one file per entry vs append log), directory location within the desktop app data dir, rotation/compaction.
- Backoff parameters and park threshold.
- Notification copy and `SyncStatus` field shape for pending/failed counts.
- Verifying the macOS mkdir conflict line number by grep before fixing (todo's note — code drifts).

### Folded Todos

- `2026-06-11-fuse-release-data-loss-before-remote-commit.md` — false durability ack + detached-thread-only data; fixed by D-01..D-05, D-09.
- `2026-06-11-fuse-mkdir-parent-publish-orphan.md` — conflict warn-without-retry + orphaned child keys; fixed by D-03, D-06, D-11.

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Source requirements (the audit todos)

- `.planning/todos/pending/2026-06-11-fuse-release-data-loss-before-remote-commit.md` — release path data-loss anatomy, single-threaded-callback constraint
- `.planning/todos/pending/2026-06-11-fuse-mkdir-parent-publish-orphan.md` — mkdir orphan anatomy, both-platform requirement

### Project rules that bind this phase

- `docs/FILESYSTEM_SPECIFICATION.md` — encrypted filesystem + IPNS metadata semantics the replay must preserve
- `docs/METADATA_SCHEMAS.md` — FolderMetadata/FileMetadata/FilePointer shapes the journal entries carry
- `CLAUDE.md` §Critical Security Rules — never persist plaintext or raw keys; clear sensitive data after use

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- `crates/sdk/src/queue.rs` — trait-based `WriteQueue` + `UploadHandler` with unit tests; the persistence upgrade lands here
- `upload_tx` / `UploadComplete` channel (`crates/fuse/src/read_ops.rs:799`, `lib.rs`) — established pattern for signaling the FS thread from worker threads; reuse for mkdir conflict dirty-marking
- Debounced publish queue with safety valve (`crates/fuse/src/lib.rs:674-698`) — the retry vehicle the mkdir fix feeds
- `publish_coordinator` per-IPNS locks + `resolve_sequence` (`write_ops.rs:555-562`) — CAS publish machinery the replay path reuses
- `SyncDaemon` `Arc<dyn Fn(SyncStatus)>` callback — surfacing channel into Tauri

### Established Patterns

- Per-folder + per-file IPNS with HKDF-derived keys; OCC via `expected_sequence_number` + `PublishResult::Conflict`
- Desktop root detection by `inode::ROOT_INO` at publish call sites
- Workspace crates layering: fuse depends on sdk/core/crypto/api-client — journal in sdk keeps the dependency direction clean

### Integration Points

- `release` path: `crates/fuse/src/read_ops.rs:661-848` (macOS/Linux), `crates/fuse/src/platform/windows/write_ops.rs:821-865` (Windows)
- mkdir conflict arms: `crates/fuse/src/write_ops.rs:581-610`, `crates/fuse/src/platform/windows/write_ops.rs:~194` (verify by grep)
- `flush` no-op (`read_ops.rs:852-854`) — candidate for journal-fsync barrier if needed by the design
- Desktop app data dir (Tauri) for the journal directory; keychain pattern at `apps/desktop/src-tauri/src/keychain.rs` for identifier conventions

</code_context>

<specifics>
## Specific Ideas

- The journal is the ack barrier, not the network: `release` does encrypt → journal fsync → reply OK → background drain. A crash at any point after the fsync is recoverable by replay.
- Kubo/API idempotency on replay: re-uploading the same ciphertext yields the same CID (safe); IPNS publish uses fresh sequence resolution — replay must tolerate "already published" states.

</specifics>

<deferred>
## Deferred Ideas

- **Full pending-uploads management UI** — desktop window listing queued + failed entries with retry/export actions (user explicitly asked to note this as a future improvement; this phase ships notification + counts only).

### Reviewed Todos (not folded)

- `2026-06-11-ipns-409-retry-lost-update.md` — Phase 44's requirement (sdk-core TS merge-on-409); the replay upsert here is the Rust-side analog but the todo stays with 44.
- `2026-02-22-crdt-ipns-inbox-sharing.md`, `2026-03-30-check-remaining-github-actions-for-node-24-updates.md` — keyword noise, unrelated.

</deferred>

---

_Phase: 43-fuse-write-durability_
_Context gathered: 2026-06-12_
