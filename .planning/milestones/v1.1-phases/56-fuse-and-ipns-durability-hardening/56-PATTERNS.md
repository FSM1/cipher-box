# Phase 56: FUSE and IPNS Durability Hardening - Pattern Map

**Mapped:** 2026-06-22
**Files analyzed:** 14 (all modifications, one new helper)
**Analogs found:** 14 / 14

## File Classification

| Modified / New File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `crates/fuse/src/metadata.rs` (new helper + folder site) | service | request-response | self — existing folder retry loop §136-224 | exact |
| `crates/fuse/src/content_ops.rs` (per-file Conflict arm) | service | request-response | `metadata.rs` folder retry loop | role-match |
| `crates/fuse/src/publish.rs` (checked_add) | utility | transform | self — existing `next_file_publish_sequence` | exact |
| `crates/fuse/src/fs.rs` (unpin guard D-08, FP-continue D-09) | service | event-driven | self — existing `drain_upload_completions` / FP spawn loop | exact |
| `crates/fuse/src/events.rs` (timeout D-10) | service | event-driven | `fs.rs` FP resolve timeout already uses `tokio::time::timeout` | role-match |
| `crates/fuse/src/inode.rs` (stable-ID D-11) | utility | transform | self — existing `ipns_to_ino` vs `find_child` dual lookup §399-412 | exact |
| `crates/fuse/src/write_ops/implementation/file_data.rs` (D-05, D-06) | middleware | request-response | self — existing `EINVAL`/`EBADF`/`EIO` returns in same file | exact |
| `crates/fuse/src/write_ops/implementation/mkdir.rs` (D-06) | middleware | request-response | `file_data.rs` EEXIST pattern | role-match |
| `crates/fuse/src/platform/windows/write_ops.rs` (D-05, D-06 winfsp) | middleware | request-response | `file_data.rs` + `mkdir.rs` macOS counterparts | role-match |
| `packages/sdk-core/src/folder/load.ts` (D-13) | service | request-response | `registration.ts` try/catch-zero block §101-104 | role-match |
| `packages/sdk-core/src/folder/registration.ts` (D-13) | service | request-response | self — existing `try` block §70-105 | exact |
| `apps/web/src/components/file-browser/details/DetailsPrimitives.tsx` (D-14) | component | request-response | `VersionHistory.tsx` try/catch/setActionError pattern | role-match |
| `apps/web/src/components/file-browser/details/VersionHistory.tsx` (D-14) | component | request-response | self — existing `setActionError` pattern in `handleRestore` / `handleDelete` | exact |

## Pattern Assignments

---

### `crates/fuse/src/metadata.rs` — new `publish_with_cas_retry` helper (D-03) + folder site

**Analog:** `metadata.rs` §136-224 — the existing `spawn_metadata_publish` Conflict arm (the template to generalize)

**The existing correct folder retry loop** (`metadata.rs:136-224`):

```rust
// metadata.rs:81-90 — current spawn_metadata_publish signature (to be patched for D-12)
pub fn spawn_metadata_publish(
    api: Arc<ApiClient>,
    rt: tokio::runtime::Handle,
    metadata: cipherbox_core::folder::FolderMetadata,
    folder_key: Vec<u8>,          // D-12: change to Zeroizing<Vec<u8>>
    ipns_private_key: Vec<u8>,    // D-12: change to Zeroizing<Vec<u8>>
    ipns_name: String,
    old_metadata_cid: Option<String>,
    coordinator: Arc<PublishCoordinator>,
)

// metadata.rs:116-124 — initial publish request with CAS expected_sequence_number
let req = cipherbox_api_client::IpnsPublishRequest {
    ipns_name: ipns_name.clone(),
    record: record_b64,
    metadata_cid: new_cid.clone(),
    encrypted_ipns_private_key: None,
    key_epoch: None,
    expected_sequence_number: Some(seq.to_string()),  // CAS: pass current seq
};

// metadata.rs:125-135 — Success arm records publish
match cipherbox_api_client::ipns::publish_ipns(&api, &req)
    .await
    .map_err(|e| format!("{}", e))?
{
    cipherbox_api_client::PublishResult::Success => {
        coordinator.record_publish(&ipns_name, new_seq);
        if let Some(old) = old_metadata_cid {
            let _ = cipherbox_api_client::ipfs::unpin_content(&api, &old).await;
        }
        log::info!("Background metadata publish succeeded for {}", ipns_name);
    }

// metadata.rs:136-196 — Conflict arm: re-resolve, jitter sleep, re-encrypt, retry
    cipherbox_api_client::PublishResult::Conflict {
        current_sequence_number,
    } => {
        log::warn!(
            "Conflict for {}: expected seq {}, server has {}",
            ipns_name, seq, current_sequence_number
        );

        let fresh_seq = coordinator.resolve_sequence(&api, &ipns_name).await?;
        // [folder-specific: re-fetch and merge remote metadata]

        let jitter_ms = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
            % 400) as u64
            + 100;
        tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;

        // re-encrypt with fresh_seq+1 ...
        let retry_req = cipherbox_api_client::IpnsPublishRequest {
            ipns_name: ipns_name.clone(),
            record: retry_b64,
            metadata_cid: retry_cid,
            encrypted_ipns_private_key: None,
            key_epoch: None,
            expected_sequence_number: Some(fresh_seq.to_string()),  // CAS: fresh seq
        };

        // metadata.rs:198-222 — inner match: Success records, persistent Conflict → Err
        match cipherbox_api_client::ipns::publish_ipns(&api, &retry_req)
            .await
            .map_err(|e| format!("{}", e))?
        {
            cipherbox_api_client::PublishResult::Success => {
                coordinator.record_publish(&ipns_name, retry_seq);
                let _ = cipherbox_api_client::ipfs::unpin_content(&api, &new_cid).await;
                log::info!(
                    "Conflict resolved for {} after retry (seq {})",
                    ipns_name, retry_seq
                );
            }
            cipherbox_api_client::PublishResult::Conflict { .. } => {
                // D-01: on persistent Conflict → Err propagates to log::error; for
                // sites with a journal, enqueue via WriteQueue::put instead (see
                // Shared Patterns — Journal Enqueue below).
                let _ = cipherbox_api_client::ipfs::unpin_content(&api, &new_cid).await;
                let _ = cipherbox_api_client::ipfs::unpin_content(
                    &api, &retry_cid_for_cleanup,
                ).await;
                return Err(format!("Persistent conflict for {}", ipns_name));
            }
        }
    }
}
```

**Zeroizing param pattern** (from `spawn_bin_entry_publish` §236-241, which already uses it — copy this exact shape for D-12):

```rust
// metadata.rs:236-241 — spawn_bin_entry_publish signature (already Zeroizing — copy for D-12)
pub fn spawn_bin_entry_publish(
    api: Arc<ApiClient>,
    rt: tokio::runtime::Handle,
    entry: cipherbox_core::bin::BinEntry,
    user_private_key: Zeroizing<Vec<u8>>,   // ← target shape for D-12
    user_public_key: Vec<u8>,
    coordinator: Arc<PublishCoordinator>,
)
```

**events.rs `spawn_metadata_refresh` already wraps `folder_key` in `Zeroizing`** (events.rs:75 — the third analog):

```rust
// events.rs:69-76 — already uses Zeroizing<Vec<u8>> for folder_key
pub fn spawn_metadata_refresh(
    rt: &tokio::runtime::Handle,
    api: std::sync::Arc<cipherbox_api_client::ApiClient>,
    tx: std::sync::mpsc::Sender<PendingRefresh>,
    ino: u64,
    ipns_name: String,
    folder_key: zeroize::Zeroizing<Vec<u8>>,  // ← exact shape for D-12
)
```

**Call site for D-12** (`fs.rs:247-263` — `build_folder_metadata` returns owned values, not references):

```rust
// fs.rs:250-261 — folder_key and ipns_private_key are moved from build_folder_metadata
let (metadata, folder_key, ipns_private_key, ipns_name, old_cid) =
    self.build_folder_metadata(folder_ino)?;
spawn_metadata_publish(
    self.api.clone(),
    self.rt.clone(),
    metadata,
    folder_key,       // D-12: wrap in Zeroizing before passing
    ipns_private_key, // D-12: wrap in Zeroizing before passing
    ipns_name,
    old_cid,
    self.publish_coordinator.clone(),
);
```

**D-12 ownership confirmation** (`fs.rs:95-130`): `build_folder_metadata` extracts `folder_key` and `ipns_private_key` via `.to_vec()` / `.clone()` from the inode, then returns them as owned `Vec<u8>`. The inode's own fields are NOT consumed — the inode holds `Zeroizing<Vec<u8>>` for `folder_key` already (set in `mkdir.rs:82`). Wrapping the returned clone in `Zeroizing<Vec<u8>>` at the call site (fs.rs:251) is safe.

---

### `crates/fuse/src/content_ops.rs` — per-file Conflict-as-success bug (D-02)

**Analog:** `metadata.rs:136-224` folder retry loop (above)

**Current buggy Conflict arm** (`content_ops.rs:162-175`):

```rust
// content_ops.rs:154-177 — BUG: Conflict arm skips record_publish but still falls through
// to coordinator.record_publish(file_ipns_name, new_seq) at line 175
let req = cipherbox_api_client::IpnsPublishRequest {
    ipns_name: file_ipns_name.to_string(),
    record: record_b64,
    metadata_cid: file_meta_cid.clone(),
    encrypted_ipns_private_key: encrypted_ipns_for_tee,
    key_epoch: tee_epoch,
    expected_sequence_number: None,  // BUG: no CAS — per-file publish sends None
};
match cipherbox_api_client::ipns::publish_ipns(api, &req)
    .await
    .map_err(|e| e.to_string())?
{
    cipherbox_api_client::PublishResult::Success => {}
    cipherbox_api_client::PublishResult::Conflict { .. } => {
        log::warn!(
            "Unexpected conflict on per-file IPNS publish for {}",
            file_ipns_name
        );
        // BUG: falls through to record_publish below — conflict recorded as success
    }
}

coordinator.record_publish(file_ipns_name, new_seq);  // line 175 — runs even on Conflict
```

**Fix shape:** Add `expected_sequence_number: Some(seq.to_string())` and in the Conflict arm, re-resolve + retry using the folder retry loop template above. On persistent Conflict, return `Err` (fire-and-forget caller logs at `log::error!`).

---

### `crates/fuse/src/metadata.rs` — bin publish Conflict-as-success bug (D-02)

**Current buggy bin Conflict arm** (`metadata.rs:340-348`):

```rust
// metadata.rs:329-349 — spawn_bin_entry_publish Conflict arm (BUG: silently drops)
match cipherbox_api_client::ipns::publish_ipns(&api, &req)
    .await
    .map_err(|e| format!("{}", e))?
{
    cipherbox_api_client::PublishResult::Success => {
        coordinator.record_publish(&bin_ipns_name, new_seq);
        if let Some(old) = existing_cid {
            let _ = cipherbox_api_client::ipfs::unpin_content(&api, &old).await;
        }
        log::info!("Bin entry published");
    }
    cipherbox_api_client::PublishResult::Conflict {
        current_sequence_number,
    } => {
        log::warn!(
            "Bin IPNS publish conflict (expected {}, server {})",
            seq, current_sequence_number
        );
        // BUG: no retry, no journal, no Err — silently acked as "fine"
    }
}
```

**Fix shape:** Apply same one-retry CAS loop as the folder template. `journal_entry: None` for bin (fire-and-forget); persistent Conflict → `Err` → `log::error!` in outer block (line 353-355).

---

### `crates/fuse/src/publish.rs` — sequence overflow (D-07)

**Current unchecked arithmetic** (`publish.rs:21-23`):

```rust
// publish.rs:21-23 — BUG: unchecked seq + 1 (u64 overflow at MAX)
current_sequence
    .map(|seq| seq + 1)
    .ok_or_else(|| "Missing current sequence for existing file IPNS record".to_string())
```

**Fix pattern** (replace with):

```rust
current_sequence
    .ok_or_else(|| "Missing current sequence for existing file IPNS record".to_string())
    .and_then(|seq| {
        seq.checked_add(1)
            .ok_or_else(|| "IPNS sequence number overflow".to_string())
    })
```

---

### `crates/fuse/src/fs.rs` — stale unpin guard (D-08)

**Current buggy unpin loop** (`fs.rs:283-289`): the `pruned_cids` loop is outside the `write_generation` guard:

```rust
// fs.rs:265-302 — BUG: unpin loop at 283 is OUTSIDE the generation guard at 270
pub fn drain_upload_completions(&mut self) {
    while let Ok(event) = self.upload_rx.try_recv() {
        match event {
            FsEvent::UploadComplete(result) => {
                if let Some(inode) = self.inodes.get_mut(result.ino) {
                    if inode.write_generation == result.write_generation {
                        // CID + content cache updates (INSIDE guard — correct)
                        if let crate::inode::InodeKind::File { ref mut cid, .. } = inode.kind {
                            *cid = result.new_cid.clone();
                        }
                    }
                }
                // [gap check for content cache at 276-282 also inside guard]
                for pruned_cid in &result.pruned_cids {  // ← line 283 BUG: outside guard
                    let api = self.api.clone();
                    let cid = pruned_cid.clone();
                    self.rt.spawn(async move {
                        let _ = cipherbox_api_client::ipfs::unpin_content(&api, &cid).await;
                    });
                }
```

**Fix:** move the `for pruned_cid` loop (lines 283-289) inside the second `write_generation` guard block (around line 276). Pattern: clone `self.api` inside the guard before spawning, matching the existing pattern at line 284.

---

### `crates/fuse/src/fs.rs` — FP-resolve continuation queue (D-09)

**Current drop-on-cap** (`fs.rs:413-421`):

```rust
// fs.rs:412-421 — BUG: break silently drops inodes past cap
const MAX_CONCURRENT_FP_RESOLVES: usize = 10;
let mut spawned = 0;
for (ino, fp_ipns) in unresolved {
    if self.resolving_file_pointers.contains(&ino) {
        continue; // Already in-flight
    }
    if spawned >= MAX_CONCURRENT_FP_RESOLVES {
        break; // Remaining will be picked up on next refresh cycle  ← WRONG: they are dropped
    }
    self.resolving_file_pointers.insert(ino);
    spawned += 1;
    // ...spawn task...
}
```

**Fix shape:** Add `pending_fp_resolves: std::collections::VecDeque<(u64, String)>` field to `CipherBoxFS` struct (initialize `VecDeque::new()` in constructor). On overflow, push to queue instead of `break`. At start of FP loop iteration, drain from queue first.

---

### `crates/fuse/src/events.rs` — metadata refresh timeout (D-10)

**Current missing timeout** (`events.rs:77-109`): the `rt.spawn(async move { ... })` never times out; hung resolves hold `refreshing_metadata` forever:

```rust
// events.rs:77-109 — BUG: no timeout; hung task never sends Failure
rt.spawn(async move {
    let result: Result<(cipherbox_core::folder::FolderMetadata, String), String> = async {
        let resolve_resp = cipherbox_api_client::ipns::resolve_ipns(&api, &ipns_name)
            .await
            .map_err(|e| format!("resolve: {}", e))?;
        let encrypted_bytes =
            cipherbox_api_client::ipfs::fetch_content(&api, &resolve_resp.cid)
                .await
                .map_err(|e| format!("fetch: {}", e))?;
        let metadata = cipherbox_core::decrypt::decrypt_metadata_from_ipfs_public(
            &encrypted_bytes,
            &folder_key,
        )
        .map_err(|e| format!("decrypt: {}", e))?;
        Ok((metadata, resolve_resp.cid))
    }
    .await;

    match result {
        Ok((metadata, cid)) => { let _ = tx.send(PendingRefresh::Success { ino, ipns_name, metadata, cid }); }
        Err(e) => {
            log::warn!("Metadata refresh failed for {}: {}", ipns_name, e);
            let _ = tx.send(PendingRefresh::Failure { ipns_name });
        }
    }
});
```

**Analog for timeout pattern** (`fs.rs:427` — `tokio::time::timeout(NETWORK_TIMEOUT, ...)` already used in FP resolve task):

```rust
// fs.rs:427-428 — existing timeout pattern to copy for D-10
let result = tokio::time::timeout(NETWORK_TIMEOUT, async {
    let resp = cipherbox_api_client::ipns::resolve_ipns(&api, &fp_ipns).await
```

**Fix:** wrap the inner `async { ... }` in `tokio::time::timeout(NETWORK_TIMEOUT, ...)` and map `Err(tokio::time::error::Elapsed)` to a `PendingRefresh::Failure` send.

---

### `crates/fuse/src/inode.rs` — stable-ID identity reset (D-11)

**Existing dual-lookup pattern** (`inode.rs:399-402` — this is what to extend):

```rust
// inode.rs:399-402 — current: OR of stable-ID and display-name (correct lookup, missing identity check)
let existing_ino = ipns_to_ino
    .get(&folder.ipns_name)
    .copied()
    .or_else(|| self.find_child(parent_ino, &folder.name));
```

**Current unconditional state preservation** (`inode.rs:462-479` — BUG: doesn't distinguish how match was found):

```rust
// inode.rs:462-479 — BUG: preserves children + was_loaded even on display-name-only fallback
let (existing_children, was_loaded) = if existing_ino.is_some() {
    let old = self.inodes.get(&ino);
    let ch = old.and_then(|o| o.children.clone());
    let loaded = old
        .map(|o| {
            matches!(
                &o.kind,
                InodeKind::Folder {
                    children_loaded: true,
                    ..
                }
            )
        })
        .unwrap_or(false);
    (ch, loaded)
} else {
    (Some(vec![]), false)
};
```

**Fix shape** (from CodeRabbit proposed shape in todo `2026-06-20-fuse-inode-stable-id-identity-reset.md`):

```rust
// Capture whether match was by stable IPNS key or display-name fallback
let matched_by_stable_id = ipns_to_ino.contains_key(&folder.ipns_name);

let (existing_children, was_loaded) = if existing_ino.is_some() {
    if matched_by_stable_id {
        // Stable ID confirmed: preserve children + loaded state
        let old = self.inodes.get(&ino);
        let ch = old.and_then(|o| o.children.clone());
        let loaded = old.map(|o| matches!(&o.kind, InodeKind::Folder { children_loaded: true, .. }))
            .unwrap_or(false);
        (ch, loaded)
    } else {
        // Display-name fallback: identity changed — clear loaded state
        log::info!(
            "Folder '{}': stable-ID mismatch on fallback match, clearing loaded state",
            folder.name
        );
        (Some(vec![]), false)  // force re-load
    }
} else {
    (Some(vec![]), false)
};
```

**File branch analog** (`inode.rs:601-610` — `same_pointer` check — extend to use `matched_by_stable_id`):

```rust
// inode.rs:601-610 — existing same_pointer check (currently uses IPNS name equality)
let same = file_meta_ipns_name.as_deref()
    == Some(file_pointer.file_meta_ipns_name.as_str());

// D-11 fix: if NOT matched_by_stable_id (display-name fallback), force same_pointer = false
// regardless of IPNS name match — identity changed, re-resolution required.
```

Apply the same pattern across all three sections: ~399-412 (folder lookup), ~462-479 (children preservation), ~515-580 (file branch `same_pointer`).

---

### `crates/fuse/src/write_ops/implementation/file_data.rs` — offset guard + EEXIST (D-05, D-06)

**Existing errno pattern in same file** (`file_data.rs:97-130`):

```rust
// file_data.rs:97-130 — current handle_write (missing offset guard and checked_add)
pub fn handle_write(
    fs: &mut CipherBoxFS,
    ino: u64,
    fh: u64,
    offset: i64,
    data: &[u8],
    reply: ReplyWrite,
) {
    let handle = match fs.open_files.get_mut(&fh) {
        Some(h) => h,
        None => {
            reply.error(libc::EBADF);  // ← existing errno return pattern to copy
            return;
        }
    };

    match handle.write_at(offset, data) {
        Ok(written) => {
            let new_end = offset as u64 + data.len() as u64;  // BUG: unchecked, and offset not guarded
```

**D-05 fix shape** (insert before `write_at` call):

```rust
// Add at top of handle_write, before the write_at match:
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
```

**Existing ENOENT guard in handle_create** (`file_data.rs:153-163`) — copy pattern for D-06 EEXIST:

```rust
// file_data.rs:153-163 — existing guard pattern (copy for EEXIST)
if parent_exists != Some(true) {
    reply.error(libc::ENOENT);
    return;
}

// D-06: add immediately after the parent_exists check, before allocate_ino():
if fs.inodes.find_child(parent, name_str).is_some() {
    reply.error(libc::EEXIST);
    return;
}
```

---

### `crates/fuse/src/write_ops/implementation/mkdir.rs` — EEXIST guard (D-06)

**Analog:** `file_data.rs` EEXIST pattern (above). The mkdir `handle_mkdir` is inside a closure that returns `Result<_, String>` — error propagation is via `?` + early return pattern in `mkdir.rs:40-99`, not direct `reply.error`. Read the existing error-return shape at `mkdir.rs:52-54`:

```rust
// mkdir.rs:52-53 — existing Err return pattern inside closure
let wrapped_folder_key = cipherbox_crypto::wrap_key(&folder_key, &fs.public_key)
    .map_err(|e| format!("Folder key wrapping failed: {}", e))?;
```

**D-06 fix shape** (add before `allocate_ino()` at mkdir.rs:58, inside the closure):

```rust
if fs.inodes.find_child(parent, name_str).is_some() {
    return Err(format!("EEXIST: '{}' already exists under parent {}", name_str, parent));
    // caller maps String errors to reply.error(libc::EEXIST) — verify the outer match
}
```

Note: verify how the closure's `Err` is converted to an errno reply in the outer scope of `handle_mkdir` before implementing.

---

### `crates/fuse/src/platform/windows/write_ops.rs` — winfsp lockstep (D-15)

**Existing winfsp errno constants** (`write_ops.rs:20-21` — import already present):

```rust
// platform/windows/write_ops.rs:20-21 — winfsp status equivalents
use crate::platform::windows::operations::implementation::{
    status_invalid_parameter, status_io_device_error, status_object_name_collision,
    status_object_name_not_found, WinFspContext, WinFspFileContext,
};
```

**Existing winfsp handle_create** (`write_ops.rs:27-103`): parent check at line 61-68 returns `status_object_name_not_found()`. D-06 EEXIST guard inserts after line 68:

```rust
// Add after parent_is_dir check (line 68), before the is_dir branch:
if fs.inodes.find_child(parent_ino, name).is_some() {
    return Err(status_object_name_collision());  // EEXIST equivalent
}
```

**D-05 winfsp shape** (`write_ops.rs:428-445` area): winfsp `handle_write` takes `offset: u64` (not `i64`), so no `< 0` check. Only overflow guard:

```rust
// winfsp handle_write — add before write_at:
let new_end = match actual_offset.checked_add(buffer.len() as u64) {
    Some(end) => end,
    None => return Err(status_io_device_error()),  // EFBIG equivalent
};
```

**CI-only warning:** These files compile ONLY under `#[cfg(feature = "winfsp")]`. Local macOS `cargo` cannot build them. Push winfsp changes with each macOS wave to CI (`Cargo Check & Test (Windows)` is the only validation gate).

---

### `packages/sdk-core/src/folder/load.ts` — fetchAndDecryptMetadata try-catch (D-13)

**Current missing try-catch** (`load.ts:30-33`):

```typescript
// load.ts:30-33 — BUG: TextDecoder.decode / JSON.parse / decryptFolderMetadata can throw
// with opaque errors; no try-catch
const encryptedJson = new TextDecoder().decode(encryptedBytes);
const encrypted: EncryptedFolderMetadata = JSON.parse(encryptedJson);
return decryptFolderMetadata(encrypted, folderKey);
```

**Analog:** `registration.ts:101-104` try/catch pattern (already in the same package):

```typescript
// registration.ts:101-104 — existing catch-and-zero pattern to copy error-wrapping from
} catch (error) {
  ipnsKeypair.privateKey.fill(0);
  folderKey.fill(0);
  throw error;
}
```

**Fix shape** (wrap the three statements):

```typescript
try {
  const encryptedJson = new TextDecoder().decode(encryptedBytes);
  const encrypted: EncryptedFolderMetadata = JSON.parse(encryptedJson);
  return decryptFolderMetadata(encrypted, folderKey);
} catch (cause) {
  throw new Error(
    `Failed to decode or decrypt folder metadata for CID ${cid}: ${String(cause)}`,
    { cause }
  );
}
```

---

### `packages/sdk-core/src/folder/registration.ts` — wrapKey inside try (D-13)

**Current bug** (`registration.ts:62-65`): both `wrapKey` calls are before the `try` at line 70, so if either throws, the `catch` at 101-104 that zeroes `ipnsKeypair.privateKey` / `folderKey` never runs:

```typescript
// registration.ts:62-65 — BUG: wrapKey calls before try block
const ipnsPrivateKeyEncrypted = bytesToHex(
  await wrapKey(ipnsKeypair.privateKey, params.userPublicKey)
);
const folderKeyEncrypted = bytesToHex(await wrapKey(folderKey, params.userPublicKey));

// registration.ts:70 — try block starts here (too late)
try {
```

**Ownership check** (`registration.ts:55-65`): `ipnsKeypair.privateKey` is generated fresh at line 55 and not stored anywhere before `wrapKey`. `folderKey` is generated at line 59. Both are owned here and not reused by the caller. Moving them inside the try is safe — the `catch` zero is the terminal owner.

**Fix:** move lines 62-65 to inside the `try` block (after line 70). Since `folderKeyEncrypted` and `ipnsPrivateKeyEncrypted` are used later in the same `try` block (in the `FolderEntry` at line 83+), no scoping issue arises.

---

### `apps/web/src/components/file-browser/details/DetailsPrimitives.tsx` — copy false-success (D-14)

**Current bug** (`DetailsPrimitives.tsx:17-34`): `setCopied(true)` at line 32 runs unconditionally regardless of whether `navigator.clipboard.writeText` or `execCommand('copy')` actually succeeded:

```typescript
// DetailsPrimitives.tsx:17-34 — BUG: setCopied(true) unconditional
const handleCopy = useCallback(async () => {
  if (timeoutRef.current) clearTimeout(timeoutRef.current);
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    // Fallback for older browsers
    const textarea = document.createElement('textarea');
    textarea.value = value;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');       // return value ignored
    document.body.removeChild(textarea);
  }
  setCopied(true);  // ← BUG: runs even if both paths failed
  timeoutRef.current = setTimeout(() => setCopied(false), 2000);
}, [value]);
```

**Fix shape:**

```typescript
const handleCopy = useCallback(async () => {
  if (timeoutRef.current) clearTimeout(timeoutRef.current);
  let success = false;
  try {
    await navigator.clipboard.writeText(value);
    success = true;
  } catch {
    const textarea = document.createElement('textarea');
    textarea.value = value;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    success = document.execCommand('copy');
    document.body.removeChild(textarea);
  }
  if (success) {
    setCopied(true);
    timeoutRef.current = setTimeout(() => setCopied(false), 2000);
  }
}, [value]);
```

---

### `apps/web/src/components/file-browser/details/VersionHistory.tsx` — silent return (D-14)

**Current bug** (`VersionHistory.tsx:36-37`): `if (!privateKey) return` provides no user feedback:

```typescript
// VersionHistory.tsx:36-37 — BUG: silent return, no user feedback
const privateKey = useAuthStore.getState().vaultKeypair?.privateKey;
if (!privateKey) return;
```

**Analog:** `VersionHistory.tsx:32` already has `setActionError` state; `handleRestore` and `handleDelete` already use it (lines 70-75):

```typescript
// VersionHistory.tsx:32 + 54 — existing error state + pattern
const [actionError, setActionError] = useState<string | null>(null);
// ...
} catch {
  setActionError('Failed to restore version');  // ← copy this pattern
}
```

**Fix shape:**

```typescript
const privateKey = useAuthStore.getState().vaultKeypair?.privateKey;
if (!privateKey) {
  setActionError('Cannot download: vault key not available');
  return;
}
```

---

## Shared Patterns

### CAS Publish with expected_sequence_number

**Source:** `crates/fuse/src/metadata.rs:116-124` (folder publish request)
**Apply to:** `content_ops.rs` per-file publish, `metadata.rs` bin publish

The shared `publish_with_cas_retry` helper (D-03) must use `expected_sequence_number: Some(seq.to_string())` on all CAS publish attempts. The `None` form (`expected_sequence_number: None`) is reserved for initial sequence-0 publishes only.

### Journal Enqueue (WriteQueue::put)

**Source:** `crates/sdk/src/queue.rs:230-260`
**Apply to:** persistent Conflict arm in `publish_with_cas_retry` (D-01) when a journal reference is available

```rust
// queue.rs:230 — WriteQueue::put signature
pub fn put(&self, entry: &JournalEntry) -> Result<(), String>

// replay.rs:156 — existing call site (usage pattern to copy)
if let Err(e) = journal.remove(&entry.id) {
    log::warn!("...");
}
// for new journal enqueue on persistent Conflict:
queue.put(&entry).map_err(|e| format!("journal enqueue failed: {}", e))?;
log::warn!("persistent conflict for {} — enqueued to journal", ipns_name);
```

### Zeroizing Key Parameters

**Source:** `crates/fuse/src/events.rs:75` (already uses `Zeroizing<Vec<u8>>`)
**Apply to:** `spawn_metadata_publish` params `folder_key` and `ipns_private_key` (D-12)

All publish helpers except `spawn_metadata_publish` already use `Zeroizing<Vec<u8>>`. D-12 brings it into alignment. **Do NOT** zero a buffer the caller still holds — confirm `build_folder_metadata` returns an owned clone (confirmed at `fs.rs:95-130`: it does `.to_vec()` / `.clone()` from the inode).

### tokio::time::timeout for network ops

**Source:** `crates/fuse/src/fs.rs:427` (FP resolve already wraps with `tokio::time::timeout(NETWORK_TIMEOUT, ...)`)
**Apply to:** `events.rs:77` `spawn_metadata_refresh` inner async block (D-10)

```rust
// fs.rs:427 — existing timeout pattern
let result = tokio::time::timeout(NETWORK_TIMEOUT, async {
    let resp = cipherbox_api_client::ipns::resolve_ipns(&api, &fp_ipns).await
```

### Typed error wrapping in TypeScript

**Source:** `packages/sdk-core/src/folder/registration.ts:101-104`
**Apply to:** `load.ts:30-33` fetchAndDecryptMetadata (D-13)

Wrap thrown errors with `new Error(..., { cause })` to preserve the causal chain while adding contextual information (CID, function name).

### winfsp errno constants

**Source:** `crates/fuse/src/platform/windows/write_ops.rs:20-21`
**Apply to:** all D-05/D-06 winfsp mirrors

| macOS errno | winfsp equivalent |
|---|---|
| `libc::EINVAL` | `status_invalid_parameter()` |
| `libc::EIO` / EFBIG | `status_io_device_error()` |
| `libc::EEXIST` | `status_object_name_collision()` |
| `libc::ENOENT` | `status_object_name_not_found()` |

## No Analog Found

All files have close analogs in the existing codebase. No entries.

## winfsp Lockstep Reference (D-15)

| Decision | macOS file(s) | winfsp sibling | CI gate required? |
|---|---|---|---|
| D-03/D-02 (per-file) | `content_ops.rs` | No winfsp sibling (per-file publish is macOS-only path) | No |
| D-03/D-02 (bin) | `metadata.rs` | Same file (`any(fuse, winfsp)`) | No (shared) |
| D-03 (folder helper) | `metadata.rs` | Same file (`any(fuse, winfsp)`) | No (shared) |
| D-05 | `write_ops/implementation/file_data.rs` | `platform/windows/write_ops.rs` (overflow only; offset is u64) | Yes |
| D-06 (file) | `write_ops/implementation/file_data.rs` | `platform/windows/write_ops.rs` handle_create | Yes |
| D-06 (mkdir) | `write_ops/implementation/mkdir.rs` | `platform/windows/write_ops.rs` mkdir branch | Yes |
| D-07 | `publish.rs` | Same file (platform-agnostic) | No |
| D-08 | `fs.rs:283-289` | Verify `drain_upload_completions` not called from winfsp side | Check before implementing |
| D-09 | `fs.rs` (`CipherBoxFS` struct) | Same struct used by both platforms | Verify field init in winfsp ctor |
| D-10 | `events.rs` | Same file (`any(fuse, winfsp)`) | No |
| D-11 | `inode.rs` | Same file (`InodeTable` is shared) | No |
| D-12 | `metadata.rs:85-86` | Same file | No |

## Metadata

**Analog search scope:** `crates/fuse/src/`, `crates/sdk/src/`, `packages/sdk-core/src/folder/`, `apps/web/src/components/file-browser/details/`
**Files read:** 13 source files
**Pattern extraction date:** 2026-06-22
