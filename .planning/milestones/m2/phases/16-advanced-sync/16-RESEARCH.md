# Phase 16: Advanced Sync (Conflict Detection) - Research

**Researched:** 2026-03-03
**Domain:** IPNS publish conflict detection via optimistic concurrency
**Confidence:** HIGH

## Summary

Phase 16 adds conflict detection to IPNS folder publishes using API-level optimistic concurrency. The mechanism is: clients send their expected sequence number with each publish request; the API compares it against the stored value in `folder_ipns` and rejects mismatches. On rejection, the client re-syncs and retries.

The codebase is well-positioned for this change. The `folder_ipns` table already tracks `sequence_number` (bigint), the publish endpoint already returns the new sequence number, and both clients already track sequence numbers locally. The key work is: (1) adding an `expectedSequenceNumber` field to publish DTOs, (2) checking it in `upsertFolderIpns`, (3) returning a 409 Conflict response, and (4) handling that response on both web and desktop clients with re-sync + retry logic.

**Primary recommendation:** Add a single `expectedSequenceNumber` optional field to the publish DTO. When present, the API validates it against the stored value. When absent (backward compatibility for per-file publishes), no check is performed. Return HTTP 409 with a body containing the current server sequence number so the client knows how far behind it is.

## Current Architecture

### How IPNS Publish Works Today

**Publish Flow (both clients):**

1. Client modifies folder state locally (add/remove/rename child)
2. Client encrypts updated folder metadata with folder key (AES-256-GCM)
3. Client uploads encrypted metadata blob to IPFS (gets CID back)
4. Client creates IPNS record: signs `value=/ipfs/{CID}` with Ed25519 key, increments local sequence number
5. Client calls `POST /ipns/publish` (or `POST /ipns/publish-batch`) with: ipnsName, base64 record, metadataCid
6. API's `upsertFolderIpns` increments the DB sequence number and stores new CID
7. API relays the signed IPNS record to delegated-ipfs.dev (best-effort)
8. API returns `{ success, ipnsName, sequenceNumber }`

**Critical observation:** The API currently increments `sequenceNumber` unconditionally on every publish. There is NO check that the client's sequence number matches the server's. Two devices publishing simultaneously will both succeed, and the second will silently overwrite the first's metadata CID.

### Sequence Number Management

**API side (`upsertFolderIpns` in `ipns.service.ts` lines 158-239):**

- On existing record: `sequenceNumber = BigInt(existing.sequenceNumber) + 1n`
- On new record: `sequenceNumber = '0'`
- No comparison with any client-provided value

**Web client (`folder.service.ts`):**

- Each `FolderNode` stores `sequenceNumber: bigint` in the Zustand store
- On load: sequence comes from `resolveIpnsRecord` response
- On publish: local sequence is incremented before IPNS record creation (`newSeq = params.sequenceNumber + 1n`)
- The API response's `sequenceNumber` is stored back via `updateFolderSequence`
- **Gap:** The local sequence in the IPNS record body and the API's DB sequence can diverge if two devices publish concurrently

**Desktop client (`PublishCoordinator` in `fuse/mod.rs` lines 123-209):**

- `seq_cache: HashMap<String, u64>` -- monotonic (only increases)
- `resolve_sequence()` calls `resolve_ipns` API, returns `max(resolved, cached)`
- `record_publish()` updates cache after successful publish
- Per-folder publish locks prevent concurrent local publishes
- **Gap:** The sequence resolved from the API reflects remote state, but another device could publish between resolve and publish

### The folder_ipns Table

```
folder_ipns
-----------
id                        uuid PK
user_id                   uuid FK -> users(id) ON DELETE CASCADE
ipns_name                 varchar(255) -- IPNS name (k51... format)
latest_cid                varchar(255) nullable -- current metadata CID
sequence_number           bigint default 0 -- incremented on each publish
encrypted_ipns_private_key bytea nullable -- ECIES-wrapped for TEE
key_epoch                 int nullable -- TEE key rotation epoch
is_root                   boolean default false
record_type               varchar(10) default 'folder' -- 'folder' or 'file'
created_at                timestamp
updated_at                timestamp

UNIQUE(user_id, ipns_name)
INDEX(user_id)
```

**Key fields for conflict detection:**

- `sequence_number` -- the authoritative server-side counter, always incremented by the API
- `record_type` -- enables filtering: conflict checks apply only to `'folder'` records (per CONTEXT.md decision)

## Publish Endpoints

### POST /ipns/publish (single)

**Current DTO (`PublishIpnsDto`):**

```typescript
{
  ipnsName: string;         // k51... IPNS name
  record: string;           // base64 IPNS record
  metadataCid: string;      // CID of encrypted metadata
  encryptedIpnsPrivateKey?: string; // hex, for TEE
  keyEpoch?: number;
}
```

**Current Response (`PublishIpnsResponseDto`):**

```typescript
{
  success: boolean;
  ipnsName: string;
  sequenceNumber: string; // new seq as string
}
```

### POST /ipns/publish-batch

**Current DTO (`BatchPublishIpnsDto`):**

```typescript
{
  records: PublishIpnsEntryDto[]; // max 200
}
```

Each `PublishIpnsEntryDto` has same fields as `PublishIpnsDto` plus optional `recordType: 'folder' | 'file'`.

**Current Response (`BatchPublishIpnsResponseDto`):**

```typescript
{
  results: PublishIpnsResponseDto[];
  totalSucceeded: number;
  totalFailed: number;
}
```

**Rate limits:**

- Single publish: 10/min/user
- Batch publish: 5/min/user (each batch up to 200 records)

## Web Client Publish Flow

### Where Folder Publishes Happen

Every folder mutation flows through `updateFolderMetadata` in `folder.service.ts`:

```typescript
export async function updateFolderMetadata(params: {
  folderId: string;
  children: FolderChild[];
  folderKey: Uint8Array;
  ipnsPrivateKey: Uint8Array;
  ipnsName: string;
  sequenceNumber: bigint; // <-- current known sequence
  encryptedIpnsPrivateKey?: string;
  keyEpoch?: number;
}): Promise<{ cid: string; newSequenceNumber: bigint }>;
```

**Callers of `updateFolderMetadata` (i.e., all folder publish points):**

1. `useFolderMutations.handleCreate` -- creates subfolder, publishes parent + new folder
2. `useFolderMutations.handleRename` -- renames item, publishes parent via `renameFolder`/`renameFile`
3. `useFolderMutations.handleMove` -- moves item, publishes source and destination
4. `useFolderMutations.handleMoveItems` -- batch move, publishes dest then source
5. `useFolderMutations.handleDelete` -- deletes item, publishes parent via `deleteFolder`/`deleteFileFromFolder`
6. `useFolderMutations.handleDeleteItems` -- batch delete, publishes parent
7. `useFileOperations.handleAddFile` -- uploads file, batch publishes file IPNS + folder via `addFileToFolder`
8. `useFileOperations.handleAddFiles` -- multi-file upload, batch publishes all files + folder via `addFilesToFolder`
9. `useFileOperations.handleUpdateFile` -- updates file content (publishes file IPNS only, NOT folder -- **no conflict check needed**)
10. `checkAndRotateIfNeeded` -- lazy key rotation, publishes folder

**Batch publish path (`addFileToFolder`, `addFilesToFolder`):**
These use `buildFolderIpnsRecord` + `batchPublishIpnsRecords` instead of `updateFolderMetadata`. The folder record is one entry in the batch alongside file records. Conflict detection must also work here.

### Sequence Number Tracking in Web Client

The `FolderNode` in Zustand stores `sequenceNumber: bigint`. Updates:

- On initial load: from `resolveIpnsRecord` response
- On publish: `updateFolderSequence(parentId, newSequenceNumber)` after publish succeeds
- On sync poll: `updateFolderSequence('root', resolved.sequenceNumber)` after detecting remote changes

**Important:** Only the root folder is polled for remote changes during sync. Subfolder changes are detected indirectly (root metadata changes -> subfolder metadata is stale).

## Desktop Client Publish Flow

### Where Folder Publishes Happen

Desktop FUSE mutations call `CipherBoxFS::update_folder_metadata(folder_ino)` which calls `spawn_metadata_publish`:

```rust
fn spawn_metadata_publish(
    api: Arc<ApiClient>,
    rt: tokio::runtime::Handle,
    metadata: FolderMetadata,
    folder_key: Vec<u8>,
    ipns_private_key: Vec<u8>,
    ipns_name: String,
    old_metadata_cid: Option<String>,
    coordinator: Arc<PublishCoordinator>,
)
```

**Inside `spawn_metadata_publish`:**

1. Acquire per-folder publish lock (`coordinator.get_lock`)
2. Encrypt metadata (CPU-only)
3. `coordinator.resolve_sequence(api, ipns_name)` -- gets current seq from API
4. Upload encrypted metadata to IPFS
5. Create IPNS record with `new_seq = seq + 1`
6. Call `POST /ipns/publish`
7. `coordinator.record_publish(ipns_name, new_seq)`

**FUSE write operations that trigger folder publish:**

- `handle_create` -- new file (via debounce queue)
- `handle_unlink` -- delete file (immediate via `update_folder_metadata`)
- `handle_mkdir` -- new folder (immediate, spawns background thread)
- `handle_rmdir` -- delete folder (immediate via `update_folder_metadata`)
- `handle_rename` -- rename/move (immediate via `update_folder_metadata`)
- `release` -- file upload complete (via debounce queue)

### PublishCoordinator Details

```rust
pub struct PublishCoordinator {
    seq_cache: Mutex<HashMap<String, u64>>,      // monotonic local cache
    publish_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>, // per-IPNS serialize
}
```

**`resolve_sequence` behavior:**

- Calls `resolve_ipns` API -> gets remote seq
- Returns `max(remote_seq, cached_seq)` -- prevents rollback
- On resolve failure with cache hit: returns cached value (fallback)
- On resolve failure without cache: returns error (prevents publishing with unknown seq)

**The per-folder lock prevents concurrent local publishes** but does NOT prevent conflicts from another device publishing between resolve and publish. This is the exact gap that conflict detection fills.

## Sync & Polling Mechanism

### Web Client Sync

**`useSyncPolling` hook (`useSyncPolling.ts`):**

- 30s polling interval via `useInterval`
- Pauses when tab is backgrounded or offline
- Fires immediately on mount, visibility regain, and reconnect
- Updates sync store status: idle -> syncing -> success/error

**Sync callback (`FileBrowser.tsx` lines 116-164):**

1. Resolve root IPNS name via `resolveIpnsRecord`
2. Compare `resolved.sequenceNumber` with `rootFolder.sequenceNumber`
3. If remote > local: fetch and decrypt new metadata, update store
4. Only polls root folder -- subfolder sync is implicit (root metadata changes reference subfolders)

**Extension point for conflict re-sync:** The sync callback can be triggered on-demand by calling `doSync()`. After a 409 conflict response, the client could call the sync logic and then retry the operation.

### Desktop Client Sync

**`SyncDaemon` (`sync/mod.rs`):**

- 30s polling interval via tokio timer
- `sync_now_rx` channel for manual triggers (tray "Sync Now" button)
- `poll()`: resolves root IPNS, compares sequence numbers, logs changes
- On change: metadata cache TTL (30s) handles refresh on next FUSE access
- Tray status transitions: Syncing -> Synced / Offline / Error

**Extension point for conflict re-sync:** The SyncDaemon's `sync_now_rx` channel can trigger immediate re-sync. On conflict, the FUSE publish thread could send to this channel.

## UI Status Indicators

### Web - SyncIndicator

**States (`sync.store.ts`):**

```typescript
type SyncStatus = 'idle' | 'syncing' | 'success' | 'error';
```

**Visual (`SyncIndicator.tsx`):**

- `syncing`: spinning circle icon, "Syncing..."
- `success`: checkmark icon, "Synced"
- `error`: warning icon with exclamation, "Sync failed"
- `idle`: static circle icon, "Sync"

**Extension needed:** Add a `'conflict'` status (or reuse `'syncing'` during conflict re-sync). A toast notification would be appropriate for the web -- brief, non-blocking, auto-dismissing.

### Desktop - TrayStatus

**States (`tray/status.rs`):**

```rust
enum TrayStatus {
    NotConnected,
    Mounting,
    Syncing,
    Synced,
    Offline,
    Error(String),
}
```

**Extension needed:** Add `Conflict` variant or use `Error("Conflict: re-syncing...")`. OS notification via `tauri-plugin-notification` (already in `Cargo.toml`).

## Batch Operations

### Multi-file Upload

`addFilesToFolder` creates N file IPNS records + 1 folder IPNS record and sends them all in one `batchPublishIpnsRecords` call. The folder record is the one that needs conflict detection.

**Important design question:** In a batch publish where individual records can fail independently, should a folder conflict fail the entire batch (preventing the file records from publishing too) or only fail the folder record?

**Recommendation:** Fail the entire batch when a folder record has a conflict. Reason: the file IPNS records are pointless without the folder record succeeding, because the folder metadata is what makes the files discoverable. Publishing file records but failing the folder record creates orphaned file IPNS records.

This means: for batch publishes containing a `recordType: 'folder'` entry with `expectedSequenceNumber`, validate the folder entry FIRST. If it conflicts, reject the whole batch with 409.

### Move Operations

`handleMove` and `handleMoveItems` publish to two folders sequentially (add-before-remove pattern). If the destination publish succeeds but the source publish conflicts:

- The item appears in both folders temporarily
- After re-sync, the client sees the conflict on the source folder
- Retry: re-read source folder, remove item, re-publish
- The add-before-remove pattern means data is safe (item exists in at least one folder)

## Recommendations

### 1. API Changes

**Add to `PublishIpnsDto` and `PublishIpnsEntryDto`:**

```typescript
@IsOptional()
@IsString()
@Matches(/^\d+$/, { message: 'expectedSequenceNumber must be a numeric string' })
expectedSequenceNumber?: string;
```

**Modify `upsertFolderIpns` in `ipns.service.ts`:**

```typescript
// Before incrementing sequence_number:
if (expectedSequenceNumber !== undefined && existing) {
  const expected = BigInt(expectedSequenceNumber);
  const current = BigInt(existing.sequenceNumber);
  if (expected !== current) {
    throw new ConflictException({
      message: 'Sequence number mismatch',
      currentSequenceNumber: existing.sequenceNumber,
      expectedSequenceNumber: expectedSequenceNumber,
    });
  }
}
```

**HTTP response:** 409 Conflict with body:

```json
{
  "statusCode": 409,
  "message": "Sequence number mismatch",
  "currentSequenceNumber": "5",
  "expectedSequenceNumber": "3"
}
```

**Batch publish behavior:** When processing batch records, if ANY folder-type record with `expectedSequenceNumber` conflicts, stop processing and return 409 for the entire batch. File-type records do not use `expectedSequenceNumber`.

### 2. Web Client Changes

**In `updateFolderMetadata`:** Pass the current `sequenceNumber` as `expectedSequenceNumber` in the publish request.

**In `createAndPublishIpnsRecord`:** Accept and forward `expectedSequenceNumber` to the API call.

**Conflict handling (in each hook that calls `updateFolderMetadata`):**

```typescript
try {
  await folderService.updateFolderMetadata({...});
} catch (err) {
  if (isConflictError(err)) {
    // 1. Show toast: "Folder updated by another device, re-syncing..."
    // 2. Re-sync: resolve IPNS, fetch & decrypt metadata, update store
    // 3. Re-read fresh folder state from store
    // 4. Re-apply the user's operation on the fresh state
    // 5. Retry publish with fresh sequence number
  }
  throw err;
}
```

**Retry strategy:** Single retry after re-sync. If the retry also conflicts (highly unlikely), surface error to user. No infinite retry loops.

**Toast notification style:** Inline toast at the bottom of the file browser, auto-dismiss after 5 seconds. States: "Re-syncing..." (spinner), "Synced - operation completed" (checkmark), or "Conflict persists - please try again" (warning).

### 3. Desktop Client Changes

**In `spawn_metadata_publish`:** After `coordinator.resolve_sequence`, pass the resolved sequence as `expectedSequenceNumber` in the publish request.

**In `IpnsPublishRequest` struct:** Add `expected_sequence_number: Option<String>`.

**Conflict handling:**

```rust
match publish_ipns(&api, &req).await {
    Ok(()) => { ... }
    Err(e) if is_conflict_error(&e) => {
        // 1. Send OS notification: "Folder updated by another device, re-syncing"
        // 2. Trigger sync daemon: sync_now_tx.send(()).await
        // 3. Wait for sync to complete (or use a short delay)
        // 4. Re-read metadata, re-build folder metadata, retry publish
    }
    Err(e) => { ... }
}
```

**OS notification via tauri-plugin-notification:**

```rust
use tauri_plugin_notification::NotificationExt;
app_handle.notification()
    .builder()
    .title("CipherBox")
    .body("Folder updated by another device, re-syncing...")
    .show()
    .ok();
```

### 4. Backward Compatibility

`expectedSequenceNumber` is optional. When absent:

- Existing behavior preserved (unconditional increment)
- Per-file IPNS publishes continue to use last-write-wins (no `expectedSequenceNumber`)
- TEE republish continues to work (it does not set `expectedSequenceNumber`)
- Old clients (before this update) continue to work until upgraded

### 5. API Client Regeneration

After modifying the API DTOs and adding the 409 response, run `pnpm api:generate` to regenerate the typed client. The web app will then have type-safe access to the new field.

## Common Pitfalls

### Pitfall 1: Race Between Resolve and Publish

**What goes wrong:** Client resolves seq=5, another device publishes (seq becomes 6), client publishes with expectedSeq=5, gets 409.
**Why it happens:** Normal multi-device usage. The resolve-then-publish pattern has an inherent TOCTOU window.
**How to avoid:** This is expected behavior -- the conflict detection is designed to catch this. The client's response (re-sync + retry) handles it.

### Pitfall 2: Stale Zustand Closures in Retry Logic

**What goes wrong:** The retry callback uses the original `parentFolderState` from the closure, which has the stale sequence number and children.
**Why it happens:** React hook callbacks capture state at render time.
**How to avoid:** In retry logic, ALWAYS re-read from `useFolderStore.getState()` to get fresh folder state. This is a known pattern in this codebase (see MEMORY.md "Zustand stale closures in async callbacks").

### Pitfall 3: Infinite Retry on Persistent Conflict

**What goes wrong:** Two devices in a tight loop modifying the same folder cause infinite conflict retries.
**Why it happens:** Each retry triggers a new publish which conflicts with the other device's retry.
**How to avoid:** Limit to 1 retry per operation. If the retry also conflicts, surface an error to the user. Consider adding random jitter (100-500ms) before retry to break symmetry.

### Pitfall 4: Batch Publish Partial Conflict

**What goes wrong:** In a batch with 10 file records + 1 folder record, the folder conflicts but file records have already been processed.
**Why it happens:** Current batch processing runs records concurrently with `Promise.allSettled`.
**How to avoid:** For batches containing a folder record with `expectedSequenceNumber`, validate the folder record FIRST. If it conflicts, return 409 for the entire batch before processing any records.

### Pitfall 5: Move Operation Half-Conflict

**What goes wrong:** Destination publish succeeds, source publish gets 409. Item exists in both folders.
**Why it happens:** Move is two separate publish operations (add-before-remove).
**How to avoid:** This is actually safe due to add-before-remove pattern. On source conflict: re-sync source folder, re-verify item is still in source children, re-publish removal. The item temporarily appears in both folders but data is not lost.

### Pitfall 6: Desktop Publish Lock Does Not Prevent Remote Conflicts

**What goes wrong:** Developer assumes `PublishCoordinator.get_lock` prevents all conflicts.
**Why it happens:** The lock only serializes local publishes from the same desktop process.
**How to avoid:** The lock is necessary (prevents local race conditions) but not sufficient (does not prevent remote device conflicts). Both the local lock AND the API-level conflict check are needed.

### Pitfall 7: Conflict During Lazy Key Rotation

**What goes wrong:** `checkAndRotateIfNeeded` publishes re-encrypted metadata, but another device published since the last sync.
**Why it happens:** Key rotation resolves IPNS, re-encrypts, publishes -- standard TOCTOU window.
**How to avoid:** Key rotation publish should also use `expectedSequenceNumber`. On conflict, re-sync, re-read metadata, and re-encrypt with the new key using the fresh children.

## Don't Hand-Roll

| Problem                     | Don't Build                | Use Instead                          | Why                                                                                     |
| --------------------------- | -------------------------- | ------------------------------------ | --------------------------------------------------------------------------------------- |
| Conflict detection protocol | Custom distributed locking | HTTP 409 + `expectedSequenceNumber`  | Standard optimistic concurrency pattern; proven at scale                                |
| OS notifications on desktop | Custom notification system | `tauri-plugin-notification`          | Already a dependency, handles macOS/Windows/Linux                                       |
| Web toast notifications     | Custom toast from scratch  | Simple CSS transition + `setTimeout` | The existing codebase uses inline components, not a toast library; keep it consistent   |
| Retry backoff               | Custom exponential backoff | Single retry with random jitter      | Conflicts are rare (30s poll interval >> publish duration); complex backoff is overkill |

## Code Examples

### API: Conflict Check in upsertFolderIpns

```typescript
// In ipns.service.ts, modify upsertFolderIpns:
private async upsertFolderIpns(
  userId: string,
  ipnsName: string,
  metadataCid: string,
  encryptedIpnsPrivateKey?: string,
  keyEpoch?: number,
  recordType: 'folder' | 'file' = 'folder',
  expectedSequenceNumber?: string,  // NEW
): Promise<FolderIpns> {
  const existing = await this.getFolderIpns(userId, ipnsName);

  if (existing && expectedSequenceNumber !== undefined) {
    const expected = BigInt(expectedSequenceNumber);
    const current = BigInt(existing.sequenceNumber);
    if (expected !== current) {
      throw new ConflictException({
        statusCode: 409,
        message: 'Sequence number mismatch: folder was modified by another device',
        currentSequenceNumber: existing.sequenceNumber,
        expectedSequenceNumber,
      });
    }
  }

  // ... rest of existing upsert logic unchanged
}
```

### Web: Conflict Error Detection

```typescript
// In a shared utility:
export function isConflictError(error: unknown): error is Error & {
  status: number;
  body: { currentSequenceNumber: string };
} {
  if (!(error instanceof Error)) return false;
  const e = error as Error & { status?: number };
  return e.status === 409;
}
```

### Desktop: Conflict Error Detection

```rust
// In api/ipns.rs, modify publish_ipns return type:
pub enum PublishResult {
    Success,
    Conflict { current_sequence_number: String },
}

pub async fn publish_ipns(
    client: &ApiClient,
    request: &IpnsPublishRequest,
) -> Result<PublishResult, String> {
    let resp = client.authenticated_post("/ipns/publish", request).await
        .map_err(|e| format!("IPNS publish failed: {}", e))?;

    if resp.status().as_u16() == 409 {
        // Parse conflict response to get current sequence number
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        let current_seq = body["currentSequenceNumber"]
            .as_str()
            .unwrap_or("0")
            .to_string();
        return Ok(PublishResult::Conflict {
            current_sequence_number: current_seq
        });
    }
    // ... existing error handling
}
```

## Risk Assessment

### Low Risk

- **API DTO change:** Adding an optional field is backward-compatible
- **409 response code:** Standard HTTP semantics, well-understood
- **Web toast notification:** Simple UI addition, no complex state

### Medium Risk

- **Batch publish conflict handling:** Need to restructure batch processing to validate folder records first. Current `Promise.allSettled` concurrent processing must be changed to sequential for folder records with conflict checks.
- **Desktop conflict retry in FUSE context:** The FUSE callback thread spawns a background publish thread. On conflict, the retry must re-read inode state which may have changed. Need careful locking.
- **Move operation half-conflict:** Safe due to add-before-remove, but the retry logic for the source removal needs to handle the case where the item was already removed by the other device's sync.

### Low Probability but High Impact

- **TypeORM race condition:** Two publish requests arriving simultaneously could both read the same `sequenceNumber` before either writes. Using a DB-level `WHERE sequence_number = expected` in the UPDATE query (instead of read-then-compare) would be more robust. Consider using TypeORM's query builder with a conditional update.

## Open Questions

1. **DB-level vs application-level check:**
   - Current plan: read record, compare in TypeScript, then update
   - More robust: `UPDATE folder_ipns SET sequence_number = seq + 1 WHERE sequence_number = expected RETURNING *`
   - Recommendation: Use DB-level `WHERE` clause for atomicity. The application-level read-compare-write has a TOCTOU gap under high concurrency.
   - **Confidence:** MEDIUM -- need to verify TypeORM supports conditional updates well

2. **Should subfolder sync be added?**
   - Currently only root folder is polled on web. If a conflict occurs on a subfolder, the client needs to re-sync that specific subfolder.
   - Recommendation: On conflict, resolve the specific folder's IPNS (not just root), fetch and decrypt, update store. This is already how `loadFolder` works.
   - **Confidence:** HIGH -- the resolve infrastructure exists

3. **TEE republish interaction:**
   - TEE republishes use `sequence_number` from the `republish_schedules` table. TEE does NOT use `expectedSequenceNumber`.
   - Does a TEE republish increment the `folder_ipns.sequence_number`? Looking at the code, TEE publishes go through the same `upsertFolderIpns` path, which increments unconditionally.
   - This means a TEE republish could cause a client conflict even though the content hasn't changed (same CID, just refreshed IPNS TTL).
   - Recommendation: Only set `expectedSequenceNumber` on client publishes. TEE republishes continue without it. The DB sequence will still increment on TEE republish, but since TEE uses the same CID, the client's next sync will see a higher sequence number with identical content -- triggering a no-op refresh.
   - **Confidence:** HIGH -- TEE publish path already uses the same upsert without expected seq

## Sources

### Primary (HIGH confidence)

- `apps/api/src/ipns/entities/folder-ipns.entity.ts` -- DB schema
- `apps/api/src/ipns/ipns.service.ts` -- publish logic, upsertFolderIpns
- `apps/api/src/ipns/ipns.controller.ts` -- endpoints
- `apps/api/src/ipns/dto/publish.dto.ts` -- request/response DTOs
- `apps/web/src/services/ipns.service.ts` -- client-side publish
- `apps/web/src/services/folder.service.ts` -- folder mutations
- `apps/web/src/hooks/useFolderMutations.ts` -- React hook callers
- `apps/web/src/hooks/useFileOperations.ts` -- file upload callers
- `apps/web/src/hooks/useSyncPolling.ts` -- sync polling
- `apps/web/src/stores/sync.store.ts` -- sync state
- `apps/web/src/components/file-browser/SyncIndicator.tsx` -- UI indicator
- `apps/web/src/components/file-browser/FileBrowser.tsx` -- sync callback
- `apps/desktop/src-tauri/src/fuse/mod.rs` -- PublishCoordinator, CipherBoxFS
- `apps/desktop/src-tauri/src/fuse/write_ops.rs` -- FUSE write operations
- `apps/desktop/src-tauri/src/sync/mod.rs` -- SyncDaemon
- `apps/desktop/src-tauri/src/api/ipns.rs` -- Rust API client
- `apps/desktop/src-tauri/src/tray/status.rs` -- TrayStatus enum

### Secondary (MEDIUM confidence)

- HTTP 409 Conflict semantics -- standard HTTP/1.1 (RFC 9110 Section 15.5.10)
- Optimistic concurrency control -- well-established database pattern

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH -- no new libraries needed, all changes are in existing code
- Architecture: HIGH -- direct codebase investigation, all relevant files read
- Pitfalls: HIGH -- identified from actual code patterns and known project issues (MEMORY.md)
- Batch handling: MEDIUM -- recommended approach clear but implementation requires restructuring existing batch logic
- DB-level atomicity: MEDIUM -- recommended but TypeORM conditional update syntax needs verification during implementation

**Research date:** 2026-03-03
**Valid until:** 2026-04-03 (stable domain, no external dependency changes)
