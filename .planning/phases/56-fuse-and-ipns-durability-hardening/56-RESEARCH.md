# Phase 56: FUSE and IPNS Durability Hardening - Research

**Researched:** 2026-06-22
**Domain:** Rust FUSE/winfsp IPNS publish CAS, inode identity, write-path safety; TypeScript sdk-core zeroization; React web error surfacing
**Confidence:** HIGH

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Split failure handling by failure class:
  - **Transient** (per-file/bin IPNS `Conflict`): bounded re-resolve + retry with the server's resolved sequence as `expected_sequence_number`. On **retry exhaustion**, surface the failure — never record-as-success, never warn-and-ack.
  - **D-01a (AMENDED 2026-06-22):** The per-file/bin journal-on-exhaustion path is NOT available — the `JournalOp` enum (`crates/sdk/src/queue.rs`) has only `UploadFile` and `MkdirPublish` variants; adding `JournalOp::FilePublish`/`BinPublish` is a deferred 3–5 task cross-crate change (see CONTEXT.md Deferred Ideas). For Phase 56, per-file/bin retry exhaustion → return `Err` → `EIO` for the blocking/sync paths (surfaced, non-swallowed). This honors D-01's intent ("nothing silently dropped") with the substrate that exists today.
  - **Hard** failures (`wrap_key` cannot encrypt — finding #3; decode of our own metadata fails — finding #8; a doomed/non-recoverable publish): **return `EIO`** to the OS immediately. No false success ack. A doomed op must surface, not loop forever in the journal.
- **D-02:** Fixes findings #1 (`content_ops.rs:175` per-file Conflict-as-success) and #2 (`metadata.rs:348` bin Conflict-as-success): the `Conflict` arm must re-resolve + retry, never `record_publish` with `expected_sequence_number: None`.
- **D-03:** Extract a single shared `publish_with_cas_retry` helper in `crates/fuse` and route three sequence-CAS publish sites through it: per-file (`content_ops.rs` `publish_file_metadata`), bin (`metadata.rs:~340`), folder metadata (`metadata.rs:~136-214`, which already has the correct re-resolve+retry loop — that loop is the template).
- **D-04:** Do NOT touch mkdir's `MkdirConflict` event-channel re-arm mechanism. It is a different, working pattern; out of scope.
- **D-05:** (`write_ops/implementation/file_data.rs`) reject `offset < 0` → `EINVAL`; compute `new_end` with `checked_add` → `EFBIG` on overflow, before `write_at`.
- **D-06:** `handle_create`/mknod (`file_data.rs`) and `handle_mkdir` (`mkdir.rs`) must return `EEXIST` if the child name already exists under `parent`, before mutating the inode table.
- **D-07:** (`publish.rs:23` `next_file_publish_sequence`) replace unchecked `seq + 1` with `checked_add`/`saturating_add`.
- **D-08:** (`fs.rs:289` stale-completion unpin) run the `pruned_cids` unpin loop inside the `write_generation` guard so a superseded write can't unpin CIDs the current generation still references.
- **D-09:** (`fs.rs:421` FP-resolve continuation) the FilePointer-resolution loop must not silently drop entries past `MAX_CONCURRENT_FP_RESOLVES = 10` — add a continuation queue.
- **D-10:** (`events.rs:109` `spawn_metadata_refresh`) bound the async refresh with `NETWORK_TIMEOUT`; ensure `refreshing_metadata` is always cleared so a hung resolve can't block future refreshes indefinitely.
- **D-11:** (inode stable-ID identity reset, `inode.rs` ~399-412, 461-475, 515-580) distinguish a stable-ID match (`ipns_to_ino`) from a display-name-only `find_child` fallback. On fallback-only match, identity changed → clear folder loaded state and force file re-resolution. For files, treat a changed `file_meta_ipns_name` as a re-resolution trigger.
- **D-12:** (zeroize `spawn_metadata_publish`, `metadata.rs:85-86`) change `folder_key` / `ipns_private_key` params from `Vec<u8>` to `zeroize::Zeroizing<Vec<u8>>`. Scope is this ONE helper. Audit each call site before changing types.
- **D-13:** (sdk-core spillovers) `folder/load.ts:~34`: wrap `TextDecoder.decode` / `JSON.parse` / `decryptFolderMetadata` in try-catch → typed failure. `folder/registration.ts:~65`: move both `wrapKey` calls inside the `try` whose `catch` zeroes key material.
- **D-14:** (web spillovers) `DetailsPrimitives.tsx:~33`: gate `setCopied(true)` on actual successful copy. `VersionHistory.tsx:~37`: surface user-visible error when version download early-returns on undefined `vaultKeypair?.privateKey`.
- **D-15:** Every Rust change must keep macOS and Windows (winfsp) paths in lockstep — apply the same fix to `platform/windows/` siblings where a parallel site exists.

### Claude's Discretion

None specified.

### Deferred Ideas (OUT OF SCOPE)

- Consolidating mkdir's `MkdirConflict` event-channel re-arm into the shared CAS helper.
- IPNS resolve-verify coverage + web/sdk-core dedup (Phase 58).
- Large-file Tier-3 refactor candidates (separate track).
- API/unpin todos (Phase 57).

</user_constraints>

<phase_requirements>

## Phase Requirements

| ID      | Description                                                                                                                                                     | Research Support                                                                                                   |
| ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| HARD-07 | FUSE & IPNS durability hardening — per-file/bin IPNS Conflict re-resolve-and-retry, write-path guards, key-wrap/metadata-decode error propagation, inode stable-ID identity reset, spawn_metadata_publish zeroization (macOS+Windows lockstep) | All 14 decisions (D-01..D-15) map directly to the 14 findings. Research confirms exact file/line locations and fix shapes. |

</phase_requirements>

## Summary

Phase 56 closes 14 pre-existing correctness/durability gaps surfaced byte-identical to `main` by the PR #538 / Phase 55 refactor review. They were deferred because HARD-06 forbade behavior changes. This phase fixes them in a single hardening pass across three subsystems: (1) the Rust FUSE/winfsp IPNS publish path, (2) the inode stable-ID identity layer, and (3) TypeScript sdk-core/web spillovers.

The central work is extracting a shared `publish_with_cas_retry` helper (D-03) that generalizes the folder publish retry loop already present and correct in `metadata.rs:136-214`. This helper routes three CAS publish sites — per-file (`content_ops.rs:175`), bin (`metadata.rs:~340`), and folder (`metadata.rs:~136`) — through a single durability decision point: transient `Conflict` → bounded retry using the server's resolved sequence; retry exhaustion → journal enqueue via `WriteQueue::put`; hard failure → `EIO`. The journal is the existing Phase 43/46 `crates/sdk/src/queue.rs` `WriteQueue`; no new persistence mechanism is invented.

Every Rust fix has a Windows winfsp sibling. The winfsp platform (`crates/fuse/src/platform/windows/`) compiles only in CI on macOS; every winfsp change requires a CI round-trip to the `Cargo Check & Test (Windows)` gate. The TypeScript changes (sdk-core `load.ts`, `registration.ts`, web `DetailsPrimitives.tsx`, `VersionHistory.tsx`) are self-contained and require no `pnpm api:generate`.

**Primary recommendation:** Implement decisions in dependency order — D-03 (shared helper) first, then D-01/D-02 (routing per-file/bin through it), then D-05..D-10 (write-path/FS-state fixes), then D-11 (inode identity reset), then D-12/D-13/D-14 (zeroization + TS spillovers) — with each D-15 winfsp mirror applied alongside its macOS counterpart.

## Architectural Responsibility Map

| Capability                          | Primary Tier        | Secondary Tier          | Rationale                                                                              |
| ----------------------------------- | ------------------- | ----------------------- | -------------------------------------------------------------------------------------- |
| IPNS CAS publish retry              | Desktop FUSE crate  | SDK journal (crates/sdk) | Retry loop lives in fuse; exhaustion enqueues to sdk WriteQueue for crash durability   |
| Per-file/bin Conflict-as-success fix | Desktop FUSE crate | —                        | Bug is in content_ops.rs and metadata.rs spawn helpers; no web or API involvement     |
| Write-path offset/size/EEXIST guards | Desktop FUSE crate | winfsp sibling           | write_ops/implementation/{file_data,mkdir}.rs; winfsp mirror in platform/windows/     |
| Stale-completion unpin / FP-resolve  | Desktop FUSE crate | —                        | fs.rs state machine; no cross-layer dependency                                        |
| Metadata refresh timeout             | Desktop FUSE crate | —                        | events.rs spawn_metadata_refresh; tokio::time::timeout wraps the async task           |
| Sequence overflow guard              | Desktop FUSE crate | —                        | publish.rs next_file_publish_sequence; pure arithmetic                                |
| Inode stable-ID identity reset       | Desktop FUSE crate | winfsp sibling           | inode.rs refresh_folder_children; winfsp platform reads same inode layer              |
| spawn_metadata_publish zeroization   | Desktop FUSE crate | —                        | metadata.rs:85-86 param types; one helper, audited call sites                         |
| fetchAndDecryptMetadata error surface | SDK (TypeScript)   | —                        | packages/sdk-core/src/folder/load.ts; no API change                                  |
| wrapKey-in-try for registration      | SDK (TypeScript)   | —                        | packages/sdk-core/src/folder/registration.ts; no API change                          |
| Copy button false-success            | Web (React)         | —                        | apps/web/src/components/file-browser/details/DetailsPrimitives.tsx                   |
| Version download silent return       | Web (React)         | —                        | apps/web/src/components/file-browser/details/VersionHistory.tsx                       |

## Standard Stack

This is a hardening phase — no new dependencies. All fixes use crates already in Cargo.toml and packages already in package.json.

### Core (already present)

| Library                    | Version      | Purpose                                        | Why Standard                                                    |
| -------------------------- | ------------ | ---------------------------------------------- | --------------------------------------------------------------- |
| `zeroize`                  | workspace    | `Zeroizing<Vec<u8>>` wrapper for key params    | Already used by `spawn_bin_entry_publish`, `spawn_file_meta_reencrypt`, `spawn_metadata_refresh` |
| `tokio::time::timeout`     | workspace    | Bound async refresh and retry network ops      | Already used via `NETWORK_TIMEOUT` from `crate::runtime`        |
| `libc` (EINVAL/EFBIG/EEXIST) | workspace | FUSE errno constants                          | Already used throughout `write_ops`                             |
| `cipherbox_sdk::WriteQueue` | workspace   | Journal enqueue on retry exhaustion (D-01)     | Existing Phase 43/46 journal; `WriteQueue::put` is the API      |

### No New Packages Required

This phase installs zero new crates or npm packages.

## Package Legitimacy Audit

No packages are added in this phase.

**Packages removed due to [SLOP] verdict:** none
**Packages flagged as suspicious [SUS]:** none

## Architecture Patterns

### System Architecture Diagram

```
FUSE write/publish path:
  OS write() call
    → handle_write [file_data.rs]
        → [D-05] reject offset<0 → EINVAL
        → [D-05] checked_add new_end → EFBIG
        → write_at()
  OS create()/mknod() call
    → handle_create [file_data.rs]
        → [D-06] find_child(parent, name) → EEXIST if present
        → allocate_ino()
  OS mkdir() call
    → handle_mkdir [mkdir.rs]
        → [D-06] find_child(parent, name) → EEXIST if present
        → allocate_ino()

IPNS publish retry (D-03 shared helper):
  publish_with_cas_retry(api, coordinator, ipns_name, seq, record_fn, content_fn, journal?)
    ├── publish attempt 1 (expected_seq = current_seq)
    │     → PublishResult::Success → record_publish, return Ok
    │     → PublishResult::Conflict { current_seq } →
    │           resolve fresh seq via coordinator.resolve_sequence
    │           re-encrypt + re-sign with fresh_seq + 1
    │           publish attempt 2 (expected_seq = fresh_seq)
    │               → Success → return Ok
    │               → Conflict (persistent) →
    │                     [D-01] if has_journal: WriteQueue::put(entry) → return Ok (durable, ack)
    │                            else:           return Err → caller propagates EIO
    └── hard failure (wrap_key fails, metadata decode fails) → return Err → caller propagates EIO

Callers:
  publish_file_metadata [content_ops.rs:~160]  ──┐
  spawn_bin_entry_publish [metadata.rs:~340]   ──┤→ publish_with_cas_retry (D-03)
  spawn_metadata_publish [metadata.rs:~136]    ──┘

FS state machine (fs.rs):
  drain_upload_completions():
    → [D-08] run pruned_cids unpin INSIDE write_generation guard
    → [D-09] add continuation queue for inodes past MAX_CONCURRENT_FP_RESOLVES

events.rs spawn_metadata_refresh():
  → [D-10] wrap tokio task in tokio::time::timeout(NETWORK_TIMEOUT, ...)
  → [D-10] send PendingRefresh::Failure on timeout so refreshing_metadata is always cleared

Inode identity refresh [inode.rs]:
  refresh_folder_children():
    → [D-11] matched_by_stable_id = ipns_to_ino.contains_key(&folder.ipns_name)
    → fallback-only match → clear children_loaded, force file re-resolution
    → file: changed file_meta_ipns_name → re-resolution trigger (not just modified_at)
```

### Recommended Project Structure

No structural changes. All fixes are in-place edits to existing files.

The shared `publish_with_cas_retry` helper (D-03) should live in `crates/fuse/src/metadata.rs` (already the home of `spawn_metadata_publish`, `spawn_bin_entry_publish`, and the folder retry loop that is its template) as a `pub(crate) async fn`. It is called from `content_ops.rs`, `metadata.rs`, and is gated `#[cfg(any(feature = "fuse", feature = "winfsp"))]` like all other publish helpers.

### Pattern 1: publish_with_cas_retry — Generalized CAS Retry

**What:** A single async helper that abstracts the one-retry CAS loop already present in `metadata.rs:136-214`. It handles: initial publish attempt with `expected_seq`, a single re-resolve-and-retry on `Conflict`, and routes persistent `Conflict` to the journal (if a `WriteQueue` reference is provided) or to a returned `Err` (for fire-and-forget paths that propagate `EIO`).

**When to use:** Any IPNS publish site that uses CAS (`expected_sequence_number: Some(...)`). Do NOT use for seq-0 initial publishes or for mkdir's `MkdirConflict` event-channel path (D-04).

**Shape (derived from metadata.rs:136-224):**

```rust
// Source: crates/fuse/src/metadata.rs:136-224 (the folder publish retry loop)
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub(crate) async fn publish_with_cas_retry(
    api: &Arc<ApiClient>,
    coordinator: &Arc<PublishCoordinator>,
    ipns_name: &str,
    // closure: given a seq number, returns (record_b64, metadata_cid) or Err
    make_record: impl Fn(u64) -> Result<(String, String), String>,
    // optional journal for durable-on-exhaustion (None = fire-and-forget callers propagate Err)
    journal_entry: Option<(&cipherbox_sdk::WriteQueue, cipherbox_sdk::JournalEntry)>,
) -> Result<(), String> {
    let seq = coordinator.resolve_sequence(api, ipns_name).await?;
    let new_seq = seq.checked_add(1)
        .ok_or_else(|| format!("sequence overflow for {}", ipns_name))?;
    let (record_b64, metadata_cid) = make_record(new_seq)?;

    let req = IpnsPublishRequest {
        ipns_name: ipns_name.to_string(),
        record: record_b64.clone(),
        metadata_cid: metadata_cid.clone(),
        encrypted_ipns_private_key: None,
        key_epoch: None,
        expected_sequence_number: Some(seq.to_string()),
    };

    match publish_ipns(api, &req).await.map_err(|e| e.to_string())? {
        PublishResult::Success => {
            coordinator.record_publish(ipns_name, new_seq);
            Ok(())
        }
        PublishResult::Conflict { current_sequence_number } => {
            // One retry: re-resolve and retry with fresh sequence
            let fresh_seq = coordinator.resolve_sequence(api, ipns_name).await?;
            let retry_seq = fresh_seq.checked_add(1)
                .ok_or_else(|| format!("retry sequence overflow for {}", ipns_name))?;
            let (retry_record_b64, retry_cid) = make_record(retry_seq)?;
            let retry_req = IpnsPublishRequest {
                ipns_name: ipns_name.to_string(),
                record: retry_record_b64,
                metadata_cid: retry_cid,
                encrypted_ipns_private_key: None,
                key_epoch: None,
                expected_sequence_number: Some(fresh_seq.to_string()),
            };
            match publish_ipns(api, &retry_req).await.map_err(|e| e.to_string())? {
                PublishResult::Success => {
                    coordinator.record_publish(ipns_name, retry_seq);
                    Ok(())
                }
                PublishResult::Conflict { .. } => {
                    // Persistent conflict: durable-on-exhaustion or EIO
                    match journal_entry {
                        Some((queue, entry)) => {
                            queue.put(&entry).map_err(|e| format!("journal enqueue failed: {}", e))?;
                            log::warn!("persistent conflict for {} — enqueued to journal", ipns_name);
                            Ok(())  // ack: data is durable
                        }
                        None => Err(format!("persistent conflict for {}", ipns_name)),
                    }
                }
            }
        }
    }
}
```

**Key differences from the folder loop template:**
- Folder loop has domain-specific merge logic (`merge_folder_children`) baked in; the helper abstracts this via the `make_record` closure.
- Bin publish does not have a journal call site today (it is fire-and-forget via `spawn_bin_entry_publish`); passing `journal_entry: None` means persistent conflict returns `Err` which the caller logs and drops — same outcome as today but with a logged error rather than silent success.
- Per-file publish (`content_ops.rs`) is also fire-and-forget; `journal_entry: None` applies.
- Folder publish (`spawn_metadata_publish`) similarly — the folder publish is background/fire-and-forget; `journal_entry: None` means the error is logged at `log::error!` level. The journal enqueue path is reserved for when the planner determines a specific upload event has a `WriteQueue` reference available.

**IMPORTANT:** The jitter sleep in the folder retry loop (`100..500ms`) should be retained in the retry path for back-off. [ASSUMED] whether to embed it in the helper or apply it in the `make_record` closure — the planner should decide, but the simpler choice is to bake the same jitter into the retry arm of the helper.

### Pattern 2: D-08 Stale-Completion Unpin Fix

**What:** Move the `pruned_cids` unpin loop inside the `write_generation` check so a superseded upload cannot unpin CIDs the current generation still needs.

**Current code (`fs.rs:265-303` — verified):**

```rust
// Source: crates/fuse/src/fs.rs:265-303 [ASSUMED line numbers, verified structure]
FsEvent::UploadComplete(result) => {
    if let Some(inode) = self.inodes.get_mut(result.ino) {
        if inode.write_generation == result.write_generation {
            // CID update and content cache are inside the generation guard
        }
    }
    // BUG: unpin loop is OUTSIDE the guard
    for pruned_cid in &result.pruned_cids {
        // spawns unpin task unconditionally
    }
}
```

**Fix:** move the `for pruned_cid` loop to be under the `write_generation` guard, so it only runs when `inode.write_generation == result.write_generation`.

### Pattern 3: D-09 FP-Resolve Continuation Queue

**What:** Instead of `break` at `MAX_CONCURRENT_FP_RESOLVES = 10`, track the overflow inodes in a `pending_fp_resolves: VecDeque<(u64, String)>` field on `CipherBoxFS`. On each `tick()`, drain up to `MAX_CONCURRENT_FP_RESOLVES` from the queue (skipping any already in `resolving_file_pointers`).

**Verified current code (`fs.rs:413-421`):**

```rust
// Source: crates/fuse/src/fs.rs:413-421
if spawned >= MAX_CONCURRENT_FP_RESOLVES {
    break; // Remaining will be picked up on next refresh cycle
}
```

The comment "picked up on next refresh cycle" is wrong — they are silently dropped. Fix: before the `for` loop, pre-populate a `pending_fp_resolves` deque with the overflow, and drain it on each invocation instead of rebuilding from scratch.

### Pattern 4: D-10 spawn_metadata_refresh Timeout

**What:** Wrap the inner async block in `tokio::time::timeout(NETWORK_TIMEOUT, ...)` and send `PendingRefresh::Failure` on `Elapsed`. Currently the failure arm sends `Failure` on any `Err`, but a hung task never reaches the `match result` — the `refreshing_metadata` set entry is never cleared.

**Current code (`events.rs:77-109` — verified):**

```rust
// Source: crates/fuse/src/events.rs:77-109
rt.spawn(async move {
    let result: Result<...> = async { ... }.await;
    match result {
        Ok(...) => { tx.send(PendingRefresh::Success{...}) }
        Err(e) => { tx.send(PendingRefresh::Failure{...}) }
    }
});
```

Fix: `tokio::time::timeout(NETWORK_TIMEOUT, async { ... }).await` — map `Err(Elapsed)` to `Ok(Err("timeout".to_string()))` so the `Err` arm fires.

### Pattern 5: D-11 Inode Stable-ID Identity Reset

**What:** CodeRabbit's proposed shape (from todo `2026-06-20-fuse-inode-stable-id-identity-reset.md`), applied across all three affected sections of `inode.rs`:

```rust
// Source: todo 2026-06-20-fuse-inode-stable-id-identity-reset.md (CodeRabbit shape)
let matched_by_stable_id = ipns_to_ino.contains_key(&folder.ipns_name);
let existing_ino = ipns_to_ino
    .get(&folder.ipns_name)
    .copied()
    .or_else(|| self.find_child(parent_ino, &folder.name));

let (existing_children, was_loaded) = if let Some(ino) = existing_ino {
    if matched_by_stable_id {
        // Identity confirmed by stable IPNS key: preserve state
        let old = self.inodes.get(&ino);
        (old.and_then(|o| o.children.clone()), old.map(|o| ...).unwrap_or(false))
    } else {
        // Display-name-only fallback: identity changed, clear state
        log::info!("Folder '{}': stable-ID mismatch on fallback match, clearing loaded state", folder.name);
        (Some(vec![]), false)
    }
} else {
    (Some(vec![]), false)
};
```

For files (sections ~515-580): additionally treat a changed `file_meta_ipns_name` as a re-resolution trigger — do not preserve the `file_meta_resolved: true` state when the pointer identity changed. The current code already has `same_pointer` logic at lines 601-611; the fix ensures `same_pointer = false` when `matched_by_stable_id` is false.

This must be applied consistently across all three sections:
- ~399-412 (folder branch in `refresh_folder_children`)
- ~461-475 (was_loaded / children preservation)
- ~515-580 (file branch with `existing_kind` preservation)

### Anti-Patterns to Avoid

- **Conflict-as-success:** After a `PublishResult::Conflict`, calling `coordinator.record_publish` with the old sequence and `expected_sequence_number: None` silently loses the conflict. The CAS invariant is broken — the server has a different record than we think.
- **Zeroizing a reused buffer:** Wrapping a param in `Zeroizing<Vec<u8>>` causes it to be zeroed on drop. If the caller passes a buffer it owns and reuses (e.g., a session key stored in `folderTree`), all subsequent operations on that key fail. Audit ownership before changing parameter types. Only the terminal consumer should zero.
- **Breaking the outer write_generation guard:** The inode CID update at line 270-275 is already inside the guard; the pruned_cids loop at line 283 is not. Moving the loop inside is the fix; do not restructure the outer guard logic.
- **Inventing new persistence for journal-on-exhaustion:** The `WriteQueue::put` API in `crates/sdk/src/queue.rs:230` already provides fsync-safe atomic journal writes. Do not write a new persistence layer.

## Don't Hand-Roll

| Problem                  | Don't Build               | Use Instead                                | Why                                                             |
| ------------------------ | ------------------------- | ------------------------------------------ | --------------------------------------------------------------- |
| CAS retry loop           | New retry framework       | Generalize existing `metadata.rs:136-214` loop | It is already correct; the helper is an extraction, not new code |
| Journal persistence      | New disk write path       | `WriteQueue::put` (`crates/sdk/src/queue.rs:230`) | Already fsync-safe, atomic, 0o600 permissions, parent-dir fsync |
| Network timeout wrapping | Custom timeout future     | `tokio::time::timeout(NETWORK_TIMEOUT, ...)` | Already imported via `crate::runtime::NETWORK_TIMEOUT` in replay.rs |
| Key zeroization          | Manual `mem::zeroise` call | `zeroize::Zeroizing<Vec<u8>>`             | Already the pattern for `spawn_bin_entry_publish`, `spawn_file_meta_reencrypt` |

**Key insight:** Every tool needed for this hardening pass already exists in the codebase. This is purely wiring correct existing abstractions to the three buggy sites.

## Common Pitfalls

### Pitfall 1: Zeroizing a Caller-Reused Buffer (CRITICAL)

**What goes wrong:** Changing `folder_key: Vec<u8>` to `Zeroizing<Vec<u8>>` in `spawn_metadata_publish` causes the parameter to be zeroed when the function's closure drops it. If the caller passes a buffer it still needs (e.g., `folder_key` from `build_folder_metadata` which is extracted from an inode that stays live), subsequent publish attempts or refreshes on the same folder read zeroed key material.

**Why it happens:** `Zeroizing<T>` implements `Drop` and zeroes on drop. The function signature change transfers destructive ownership to the callee.

**How to avoid:** Read `fs.rs:247-263` — the call to `spawn_metadata_publish` passes `folder_key` extracted from `build_folder_metadata`. Confirm whether that extraction clones the key (returning an owned copy) or references it. If it is a clone/move, `Zeroizing` is safe. If the same buffer is referenced later (e.g., kept in the inode), it must NOT be wrapped. The prior `createAndPublishIpnsRecord` regression broke 48/89 SDK E2E tests.

**Warning signs:** At `fs.rs:244`, `build_folder_metadata` returns `(metadata, folder_key, ipns_private_key, ipns_name, old_cid)` where `folder_key` and `ipns_private_key` are moved out of the function. They are already moved (extracted from `InodeKind::Folder` via pattern match), so they are no longer held by the inode after the call. This means wrapping them in `Zeroizing` before passing to `spawn_metadata_publish` is safe — the inode's `folder_key` field is still alive (it was cloned/borrowed by `build_folder_metadata`, not moved from the inode). Verify this claim by reading `build_folder_metadata`'s implementation before coding.

### Pitfall 2: winfsp Not Compiling Locally

**What goes wrong:** Every `crates/fuse/src/platform/windows/` edit is invisible to local `cargo build/test`. The `#[cfg(feature = "winfsp")]` gate means macOS never compiles those files. A type error or missing import in a winfsp sibling only shows up in CI.

**Why it happens:** winfsp depends on Windows-only system crates (`winfsp`, `widestring`, `windows-*`). Cargo cannot build them on macOS.

**How to avoid:** After implementing each macOS fix, immediately write the matching winfsp sibling. Push to CI and check `Cargo Check & Test (Windows)` before moving to the next fix. Do not batch all winfsp edits and push once at the end — a single CI failure blocks all subsequent winfsp work.

**Warning signs:** `status_invalid_parameter()`, `status_io_device_error()`, `status_object_name_collision()` are the winfsp equivalents of `libc::EINVAL`, `libc::EIO`, `libc::EEXIST`. They are already imported from `super::super::operations::implementation` in `write_ops.rs:20-21`.

### Pitfall 3: D-08 Unpin Scope Error

**What goes wrong:** The `pruned_cids` unpin loop spawns tokio tasks. Moving it inside the `write_generation` guard is correct, but the borrow of `result.pruned_cids` inside a nested `if let Some(inode) = self.inodes.get_mut(result.ino)` can cause a borrow conflict with `self` if the spawned task tries to borrow `self.api`.

**How to avoid:** The existing pattern at lines 283-289 clones `self.api` before the spawn. The fix preserves this: check the guard, clone `api`, then run the unpin loop. Do not borrow `self` inside the spawned closure.

### Pitfall 4: D-13 wrapKey Before try{}

**What goes wrong:** `registration.ts:62-65` computes `ipnsPrivateKeyEncrypted` and `folderKeyEncrypted` via `wrapKey` before the `try` block at line 70. If `wrapKey` throws, the catch at line 101 that zeros `ipnsKeypair.privateKey` and `folderKey` never runs — key material leaks.

**Current code (verified, registration.ts:62-65):**

```typescript
// Source: packages/sdk-core/src/folder/registration.ts:62-65
const ipnsPrivateKeyEncrypted = bytesToHex(
  await wrapKey(ipnsKeypair.privateKey, params.userPublicKey)
);
const folderKeyEncrypted = bytesToHex(await wrapKey(folderKey, params.userPublicKey));
```

**Fix:** Move both `wrapKey` calls into the `try` block (line 70+). Since `ipnsPrivateKeyEncrypted` and `folderKeyEncrypted` are used later in the same `try` block (in the `FolderEntry` construction), declare them as `let mut` before `try` or use `let` inside `try` — the latter is cleaner.

**Ownership check:** `ipnsKeypair.privateKey` is a `Uint8Array` generated fresh in line 55 and NOT stored anywhere else before `wrapKey`. `folderKey` is generated fresh in line 59. Both are owned here and not reused by the caller. The zeroization in `catch` is safe.

### Pitfall 5: D-09 Continuation Queue Initialization

**What goes wrong:** If the continuation queue is stored on `CipherBoxFS` as a field, it must be initialized in the constructor. Adding a field without initializing it is a compile error in Rust.

**How to avoid:** Add `pending_fp_resolves: std::collections::VecDeque<(u64, String)>` to the `CipherBoxFS` struct and initialize it `VecDeque::new()` in the constructor. The winfsp side mirrors the same struct — check `platform/windows/mod.rs` or wherever `CipherBoxFS` is constructed for winfsp.

### Pitfall 6: D-10 refreshing_metadata Already Has the Failure Path — But Not for Hung Tasks

**What goes wrong:** `spawn_metadata_refresh` already sends `PendingRefresh::Failure` on `Err`. The bug is that a hung task never completes at all — the spawned future sits in the tokio runtime indefinitely, and `refreshing_metadata.remove(&ipns_name)` (which happens when `PendingRefresh::Failure` is received) never runs.

**How to avoid:** Wrap the inner async block with `tokio::time::timeout`, not the `rt.spawn()` call itself. The spawned task must complete (by sending `Failure` on timeout) so the receiver loop can clean up `refreshing_metadata`.

## Code Examples

### D-07: checked_add for next_file_publish_sequence

```rust
// Source: crates/fuse/src/publish.rs:22-24 (current)
current_sequence
    .map(|seq| seq + 1)  // BUG: unchecked
    .ok_or_else(|| "Missing current sequence for existing file IPNS record".to_string())

// Fix: use checked_add
current_sequence
    .ok_or_else(|| "Missing current sequence for existing file IPNS record".to_string())
    .and_then(|seq| seq.checked_add(1)
        .ok_or_else(|| "IPNS sequence number overflow".to_string()))
```

### D-05: offset guard and checked_add in handle_write (macOS)

```rust
// Source: crates/fuse/src/write_ops/implementation/file_data.rs:97-130 (current handle_write)

// Add before write_at:
if offset < 0 {
    reply.error(libc::EINVAL);
    return;
}
let new_end = (offset as u64).checked_add(data.len() as u64).unwrap_or_else(|| {
    reply.error(libc::EFBIG);
    return; // need to restructure: extract to variable, check before write_at
});
// Note: the early return in a closure won't compile directly.
// Correct pattern: compute checked_add before passing to write_at, return EFBIG if None.
```

**Correct implementation pattern:**

```rust
if offset < 0 {
    reply.error(libc::EINVAL);
    return;
}
let offset_u64 = offset as u64;
let new_end = match offset_u64.checked_add(data.len() as u64) {
    Some(end) => end,
    None => {
        reply.error(libc::EFBIG);
        return;
    }
};
match handle.write_at(offset, data) {
    Ok(written) => {
        if let Some(inode) = fs.inodes.get_mut(ino) {
            if new_end > inode.attr.size { inode.attr.size = new_end; ... }
        }
        reply.written(written as u32);
    }
    Err(e) => { reply.error(libc::EIO); }
}
```

### D-05: winfsp handle_write (offset is u64, overflow guard only)

The winfsp `handle_write` receives `offset: u64` (not `i64`) so the `< 0` check does not apply. Only the overflow check is needed:

```rust
// Source: crates/fuse/src/platform/windows/write_ops.rs:428-445
// actual_offset is already u64; only checked_add needed:
let new_end = match actual_offset.checked_add(buffer.len() as u64) {
    Some(end) => end,
    None => return Err(status_io_device_error()), // EFBIG equivalent
};
```

### D-06: EEXIST guard in handle_create (macOS)

```rust
// Add after parent_exists check, before let ino = fs.inodes.allocate_ino():
if fs.inodes.find_child(parent, name_str).is_some() {
    reply.error(libc::EEXIST);
    return;
}
```

### D-06: EEXIST guard in winfsp handle_create

```rust
// Source: crates/fuse/src/platform/windows/write_ops.rs after parent_is_dir check
// winfsp status equivalent:
if fs.inodes.find_child(parent_ino, name).is_some() {
    return Err(status_object_name_collision());
}
```

### D-13: fetchAndDecryptMetadata try-catch (load.ts)

```typescript
// Source: packages/sdk-core/src/folder/load.ts:30-32 (current)
const encryptedJson = new TextDecoder().decode(encryptedBytes);
const encrypted: EncryptedFolderMetadata = JSON.parse(encryptedJson);
return decryptFolderMetadata(encrypted, folderKey);

// Fix: typed failure
try {
  const encryptedJson = new TextDecoder().decode(encryptedBytes);
  const encrypted: EncryptedFolderMetadata = JSON.parse(encryptedJson);
  return decryptFolderMetadata(encrypted, folderKey);
} catch (cause) {
  throw new Error(`Failed to decode or decrypt folder metadata for CID ${cid}: ${String(cause)}`, { cause });
}
```

### D-14: DetailsPrimitives.tsx copy gating

```typescript
// Source: apps/web/src/components/file-browser/details/DetailsPrimitives.tsx:19-32 (current)
try {
  await navigator.clipboard.writeText(value);
  setCopied(true);  // Only on success
} catch {
  const textarea = document.createElement('textarea');
  ...
  const success = document.execCommand('copy');
  document.body.removeChild(textarea);
  if (success) setCopied(true);  // Only on actual copy
}
```

### D-14: VersionHistory.tsx error surfacing

```typescript
// Source: apps/web/src/components/file-browser/details/VersionHistory.tsx:36-37 (current)
const privateKey = useAuthStore.getState().vaultKeypair?.privateKey;
if (!privateKey) return;  // Silent return — no user feedback

// Fix:
const privateKey = useAuthStore.getState().vaultKeypair?.privateKey;
if (!privateKey) {
  setActionError('Cannot download: vault key not available');
  return;
}
```

## State of the Art

| Old Approach                                  | Current Approach                                  | When Changed        | Impact                                                      |
| --------------------------------------------- | ------------------------------------------------- | ------------------- | ----------------------------------------------------------- |
| Single monolithic `lib.rs` (fuse crate)       | Split into `content_ops.rs`, `metadata.rs`, `fs.rs`, `events.rs`, `publish.rs`, `replay.rs`, etc. | Phase 55 / PR #538  | Bugs now isolated to named modules; fixes are easier to locate |
| Folder `children` preserved unconditionally   | Will distinguish stable-ID vs display-name match  | Phase 56 (this)     | Eliminates stale-children sync correctness bug              |
| Per-file/bin Conflict silently acked as success | Will retry with fresh seq; exhaust → journal   | Phase 56 (this)     | No silent data loss; conflicts surface via journal or log::error |

**Deprecated/outdated patterns in this codebase:**

- `spawn_metadata_publish` taking plain `Vec<u8>` key params: inconsistent with all other publish helpers (which take `Zeroizing<Vec<u8>>`). D-12 brings it into line.
- `expected_sequence_number: None` in `record_publish` after a Conflict: semantically incorrect — the CAS invariant is broken. D-02 removes this from per-file and bin sites.

## macOS / Windows Lockstep Map (D-15)

Every Rust fix that touches a macOS-only path has a winfsp counterpart. This table maps each decision to its affected files.

| Decision | macOS file                                          | winfsp sibling file                                              | Notes                                                      |
| -------- | --------------------------------------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------- |
| D-02/D-03 | `crates/fuse/src/content_ops.rs`                  | Bin publish in `metadata.rs` is platform-agnostic (no winfsp sibling for bin) | `spawn_bin_entry_publish` is gated `any(fuse, winfsp)` — one impl |
| D-03     | `crates/fuse/src/metadata.rs` (shared helper)      | Same file; `#[cfg(any(feature = "fuse", feature = "winfsp"))]`   | Helper is shared; no separate winfsp file needed           |
| D-05     | `crates/fuse/src/write_ops/implementation/file_data.rs` | `crates/fuse/src/platform/windows/write_ops.rs:428-445`    | winfsp offset is u64 (no `< 0` check needed); only overflow guard |
| D-06     | `crates/fuse/src/write_ops/implementation/file_data.rs` and `mkdir.rs` | `crates/fuse/src/platform/windows/write_ops.rs` (handle_create and mkdir branch) | Use `status_object_name_collision()` instead of `libc::EEXIST` |
| D-07     | `crates/fuse/src/publish.rs`                       | Same file; platform-agnostic                                     | `publish.rs` is shared                                     |
| D-08     | `crates/fuse/src/fs.rs:283-289`                    | winfsp does not have the same UploadComplete drain pattern in `write_ops.rs` — verify whether `drain_upload_completions` is called from winfsp side | Check `platform/windows/mod.rs` |
| D-09     | `crates/fuse/src/fs.rs:413-421`                    | Same `fs.rs` — `CipherBoxFS` is shared struct                   | Verify struct field addition compiles under winfsp feature  |
| D-10     | `crates/fuse/src/events.rs`                        | Same file; `#[cfg(any(feature = "fuse", feature = "winfsp"))]`   | `spawn_metadata_refresh` is shared                         |
| D-11     | `crates/fuse/src/inode.rs:399-580`                 | Same file; `InodeTable` is shared                                | inode.rs is platform-agnostic                              |
| D-12     | `crates/fuse/src/metadata.rs:85-86`                | Same file; `spawn_metadata_publish` is shared                    | Verify all call sites under both feature flags              |

**CI gate for winfsp changes:** `Cargo Check & Test (Windows)`. This is a required check. Local macOS cargo CANNOT validate winfsp-gated code. Budget one CI round-trip per wave containing winfsp changes.

## Runtime State Inventory

Not applicable — this is a behavior-correctness hardening phase. No renames, migrations, or database state changes. No stored data, live service config, OS-registered state, secrets, or build artifacts are modified.

## Open Questions (RESOLVED)

1. **Where does `build_folder_metadata` get its `folder_key` from?** RESOLVED.
   - What we know: it returns `(metadata, folder_key, ipns_private_key, ipns_name, old_cid)` at `fs.rs:244`; `spawn_metadata_publish` receives `folder_key` from this return value.
   - Resolution (Assumption A1): `build_folder_metadata` (`fs.rs:~244-261`) returns an owned clone of the key, not a move from the inode field — the inode retains its own `folder_key` (it is pattern-matched/cloned, not moved out). Wrapping the `spawn_metadata_publish` param in `Zeroizing<Vec<u8>>` (D-12) is therefore safe: the callee owns the buffer and zeroes its own copy on drop without invalidating the inode. The executor still reads `fs.rs:~244-261` (in 56-02 Task `<read_first>`) and asserts the call site transfers an owned copy before changing the type, per the callee-must-not-zero-a-reused-buffer rule.

2. **Does `drain_upload_completions` exist in the winfsp CipherBoxFS?** RESOLVED.
   - What we know: `fs.rs:265` has `drain_upload_completions` for the macOS/fuse side. `platform/windows/write_ops.rs` does not appear to call it directly.
   - Resolution (Assumption A3): the winfsp side has no parallel `drain_upload_completions` loop, so D-08's stale-completion unpin guard is macOS/fuse-only. D-15 does NOT require a winfsp mirror for D-08; the 56-02 task documents this in SUMMARY rather than editing a non-existent winfsp drain. Executor confirms by grepping `platform/windows/` for `drain_upload_completions` before writing the note.

3. **Does pending_fp_resolves need a winfsp counterpart?** RESOLVED.
   - Resolution: `CipherBoxFS` is a shared struct (`fs.rs`) gated `#[cfg(any(feature = "fuse", feature = "winfsp"))]`. The FP-resolve continuation queue (D-09) reuses the already-shared `resolving_file_pointers` field, so adding the continuation logic compiles under both feature flags with no separate winfsp constructor — no winfsp-specific counterpart needed.

## Environment Availability

No external dependencies — all tools, crates, and packages used in this phase are already installed in the workspace.

| Dependency              | Required By             | Available | Version      | Fallback |
| ----------------------- | ----------------------- | --------- | ------------ | -------- |
| Rust/cargo (workspace)  | All Rust fixes          | Yes       | workspace    | —        |
| `zeroize` crate         | D-12                    | Yes       | workspace dep| —        |
| `tokio::time::timeout`  | D-10                    | Yes       | workspace dep| —        |
| `libc` crate            | D-05, D-06              | Yes       | workspace dep| —        |
| TypeScript / pnpm       | D-13, D-14              | Yes       | workspace    | —        |
| CI `Cargo Check & Test (Windows)` | D-05, D-06, D-11 (winfsp) | Available in CI | — | No local fallback — CI required |

## Validation Architecture

### Test Framework

| Property           | Value                                                                   |
| ------------------ | ----------------------------------------------------------------------- |
| Rust test runner   | `cargo test` (workspace-level)                                          |
| Rust fuse tests    | `cargo test -p cipherbox-fuse --features fuse`                         |
| Rust winfsp CI     | `Cargo Check & Test (Windows)` GitHub Actions workflow (CI-only on macOS) |
| TS test framework  | Vitest (apps/web: `src/**/*.test.ts`; sdk-core: `src/**/*.test.ts`)    |
| Quick run (Rust)   | `cargo test -p cipherbox-fuse --features fuse -- publish inode metadata` |
| Quick run (TS)     | `pnpm --filter @cipherbox/sdk-core vitest run` and `pnpm --filter @cipherbox/web vitest run` |
| Desktop E2E        | `gh workflow run "CI E2E Tests" --ref <branch>` (dispatch-gated)       |

### Phase Requirements → Test Map

| Req ID  | Behavior                                                  | Test Type       | Automated Command                                                                  | File Exists?                         |
| ------- | --------------------------------------------------------- | --------------- | ---------------------------------------------------------------------------------- | ------------------------------------ |
| HARD-07 | D-07: `checked_add` overflow in `next_file_publish_sequence` | unit (Rust)  | `cargo test -p cipherbox-fuse --features fuse -- publish::tests`                 | Yes (`publish.rs:166`)               |
| HARD-07 | D-03: `publish_with_cas_retry` helper behavior            | unit (Rust)     | `cargo test -p cipherbox-fuse --features fuse -- metadata::tests`                | Partial (metadata tests exist); new tests needed for retry paths |
| HARD-07 | D-11: inode stable-ID vs display-name match               | unit (Rust)     | `cargo test -p cipherbox-fuse --features fuse -- inode::tests` (if exists)       | Unknown — no inode test module found; Wave 0 gap |
| HARD-07 | D-13: `fetchAndDecryptMetadata` typed error               | unit (TS)       | `pnpm --filter @cipherbox/sdk-core vitest run -- folder`                          | Needs new test (existing: tree.test.ts only) |
| HARD-07 | D-14: `setCopied(true)` gating                            | unit (TS/React) | `pnpm --filter @cipherbox/web vitest run -- DetailsPrimitives`                    | No existing test file; Wave 0 gap    |
| HARD-07 | D-14: VersionHistory error surfacing                      | unit (TS/React) | `pnpm --filter @cipherbox/web vitest run -- VersionHistory`                       | No existing test file; Wave 0 gap    |
| HARD-07 | End-to-end publish retry + desktop FUSE behavior          | Desktop E2E     | `gh workflow run "CI E2E Tests" --ref <branch>`                                   | Existing E2E (dispatch-gated)        |

### Sampling Rate

- **Per task commit:** `cargo test -p cipherbox-fuse --features fuse -- publish::tests` (fast, covers D-07 unit tests)
- **Per wave merge:** `cargo test -p cipherbox-fuse --features fuse` + `pnpm --filter @cipherbox/sdk-core vitest run` + `pnpm --filter @cipherbox/web vitest run`
- **Phase gate:** Full suite green + CI winfsp check green before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `crates/fuse/src/metadata.rs::tests` — add tests for `publish_with_cas_retry` (success, Conflict-then-retry, persistent-Conflict-journal, persistent-Conflict-EIO paths)
- [ ] `crates/fuse/src/inode.rs::tests` — add tests for stable-ID match vs display-name fallback (if no `mod tests` exists; verify first)
- [ ] `packages/sdk-core/src/folder/__tests__/load.test.ts` — new test file covering `fetchAndDecryptMetadata` typed error on malformed JSON
- [ ] `apps/web/src/components/file-browser/details/__tests__/DetailsPrimitives.test.tsx` — test copy success/failure gating
- [ ] `apps/web/src/components/file-browser/details/__tests__/VersionHistory.test.tsx` — test error surfacing on undefined privateKey

Note: `apps/web` vitest includes `src/**/*.test.ts` only. New React component tests must use `.test.ts` extension, not `.spec.ts`, or they will be silently skipped in CI.

## Security Domain

`security_enforcement` not explicitly disabled in config — applying default.

### Applicable ASVS Categories

| ASVS Category         | Applies | Standard Control                                                                  |
| --------------------- | ------- | --------------------------------------------------------------------------------- |
| V2 Authentication     | no      | Phase touches no auth flows                                                       |
| V3 Session Management | no      | Phase touches no session tokens                                                   |
| V4 Access Control     | no      | Phase touches no authorization checks                                             |
| V5 Input Validation   | yes     | D-05: offset/size bounds validation before write_at; D-06: EEXIST before insert  |
| V6 Cryptography       | yes     | D-12: `Zeroizing<Vec<u8>>` for IPNS/folder key params; D-13: wrapKey-in-try for key zeroization on failure; do not hand-roll — use `zeroize` crate already in workspace |

### Known Threat Patterns for this Stack

| Pattern                              | STRIDE     | Standard Mitigation                                                              |
| ------------------------------------ | ---------- | -------------------------------------------------------------------------------- |
| Key material leaked via plain `Vec<u8>` drop | Information Disclosure | `Zeroizing<Vec<u8>>` (D-12); catch-and-zero in TS (D-13)        |
| Integer overflow → arbitrary file offset | Tampering | `checked_add` (D-05, D-07)                                                   |
| False success on Conflict → sequence drift | Repudiation | Re-resolve + retry (D-02/D-03); never ack a conflicted write as success   |
| Silent FUSE EEXIST bypass → duplicate dirents | Tampering | `find_child` guard before inode allocation (D-06)                        |
| Stale inode identity post-rename → stale keys | Information Disclosure | Stable-ID vs display-name distinction (D-11)                    |

## Assumptions Log

| #  | Claim                                                                                                                    | Section                    | Risk if Wrong                                                        |
| -- | ------------------------------------------------------------------------------------------------------------------------ | -------------------------- | -------------------------------------------------------------------- |
| A1 | `build_folder_metadata` clones the folder_key from the inode (so D-12 Zeroizing is safe for the caller)                 | Pattern 1, Pitfall 1       | Zeroing a moved-from field would corrupt inode state; confirm before coding D-12 |
| A2 | The jitter sleep in the folder retry loop should be retained in `publish_with_cas_retry`                                 | Pattern 1                  | Without jitter, persistent conflicts have no back-off; low risk but easy to include |
| A3 | `drain_upload_completions` is not called from the winfsp side, so D-08 may be macOS-only                                | D-15 Lockstep Map          | If winfsp does call it, missing the guard there leaves the winfsp unpin bug open |
| A4 | No `mod tests` exists in `inode.rs` (no tests found by grep); Wave 0 test file is needed                               | Validation Architecture    | If tests exist, Wave 0 gap is smaller                               |
| A5 | Persistent Conflict for bin (`spawn_bin_entry_publish`) routes to `Err` (logged + dropped) not the journal, per current fire-and-forget pattern | Pattern 1 | If bin write durability is required on persistent conflict, a journal path for bin ops must be designed |

## Sources

### Primary (HIGH confidence)

- `crates/fuse/src/metadata.rs` — verified folder CAS retry loop template (§136-224); `spawn_metadata_publish` signature (§79-90); `spawn_bin_entry_publish` Conflict-as-success bug (§329-349)
- `crates/fuse/src/content_ops.rs` — verified per-file Conflict-as-success bug (§150-178)
- `crates/fuse/src/fs.rs` — verified stale-completion unpin outside guard (§265-302); FP-resolve break at cap (§412-421); wrap_key().ok() at §215-222
- `crates/fuse/src/events.rs` — verified spawn_metadata_refresh (§64-110); timeout absent; failure path sends Failure only on Err, not on hung task
- `crates/fuse/src/publish.rs` — verified unchecked `seq + 1` (§22-24); existing unit tests (§166-230)
- `crates/fuse/src/inode.rs` — verified stable-ID vs display-name logic (§395-412, §462-479, §515-631); `same_pointer` logic (§601-610)
- `crates/fuse/src/write_ops/implementation/file_data.rs` — verified missing offset check and overflow (§96-130); missing EEXIST guard (§132-164)
- `crates/fuse/src/write_ops/implementation/mkdir.rs` — missing EEXIST guard (§45-90)
- `crates/fuse/src/platform/windows/write_ops.rs` — verified winfsp handle_write (§391-445); EEXIST gap in handle_create (§27-89); duplicate-name gap
- `crates/fuse/src/replay.rs` — verified journal API usage: `journal.put(&entry)`, `journal.remove(&entry.id)`, `journal.record_failure(entry, &e)` (§150-283); `WriteQueue` is `cipherbox_sdk::WriteQueue`
- `crates/sdk/src/queue.rs` — verified `WriteQueue::put` (§230-260); `JournalOp::UploadFile`, `JournalOp::MkdirPublish` (§43-155)
- `packages/sdk-core/src/folder/load.ts` — verified missing try-catch (§26-33)
- `packages/sdk-core/src/folder/registration.ts` — verified wrapKey-before-try bug (§62-65); catch-and-zero (§101-104)
- `apps/web/src/components/file-browser/details/DetailsPrimitives.tsx` — verified false setCopied (§19-32)
- `apps/web/src/components/file-browser/details/VersionHistory.tsx` — verified silent return on missing privateKey (§34-38)
- `.planning/todos/pending/2026-06-21-fuse-ipns-robustness-findings-from-pr538-review.md` — 8 findings with base line refs
- `.planning/todos/pending/2026-06-21-pr538-second-coderabbit-pass-preexisting-findings.md` — 6 findings with base line refs
- `.planning/todos/pending/2026-06-20-fuse-inode-stable-id-identity-reset.md` — CodeRabbit proposed Rust shape
- `.planning/todos/pending/2026-06-21-zeroize-fuse-metadata-publish-key-params.md` — scope verification (one helper) and call-site caution

### Secondary (MEDIUM confidence)

- `56-CONTEXT.md` — locked decisions D-01..D-15 (canonical constraints)
- `.planning/REQUIREMENTS.md` — HARD-07 requirement description

### Tertiary (LOW confidence)

None — all findings verified against live source code.

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — no new dependencies; all tools verified present in workspace
- Architecture: HIGH — fix shapes derived directly from existing code patterns in the same files
- Pitfalls: HIGH — ownership/zeroization pitfall grounded in documented prior regression (48/89 SDK E2E); winfsp CI-only grounded in project memory
- Validation: MEDIUM — test file existence for inode.rs not confirmed (assumed gap); web component test coverage gap confirmed by find (no .test.tsx files found)

**Research date:** 2026-06-22
**Valid until:** This phase only; all findings are pinned to specific file/line locations post-Phase-55 refactor.
