# Phase 17: Recycle Bin - Research

**Researched:** 2026-03-04
**Domain:** Client-side encrypted bin metadata, soft-delete flows, IPNS lifecycle management
**Confidence:** HIGH

## Summary

The recycle bin feature introduces a soft-delete layer between the user's action (delete) and permanent data destruction (CID unpin). Instead of immediately unpinning CIDs and removing children from folder metadata, the delete flow will: (1) remove the item from its parent folder's metadata, (2) add a bin entry to a new encrypted bin IPNS record, and (3) defer CID unpinning until permanent delete or auto-purge.

The architecture follows CipherBox's established zero-knowledge metadata pattern: a new IPNS record (the "bin index") encrypted with the user's public key via ECIES, deterministically discoverable via HKDF key derivation (same pattern as vault IPNS and device registry IPNS). Each bin entry preserves enough information to restore items to their original location. The bin IPNS record syncs across devices using the existing 30s IPNS polling mechanism.

The implementation touches four layers: (1) the `@cipherbox/crypto` package (new bin metadata types and HKDF derivation), (2) web app services/stores/hooks/components (bin store, bin service, bin page, modified delete flows), (3) API backend (env-configurable retention constant, served to client), and (4) desktop FUSE (redirecting unlink/rmdir from permanent delete to soft-delete via webview IPC).

**Primary recommendation:** Create a new `RecycleBinMetadata` IPNS record (ECIES-encrypted, HKDF-derived) that stores flat bin entries. Modify existing delete flows to write to the bin instead of unpinning. Add a `/bin` route with flat list view. Purge expired entries client-side on bin load.

## Standard Stack

No new libraries are needed. The recycle bin is built entirely from existing CipherBox patterns and libraries.

### Core (already in project)

| Library              | Version  | Purpose                                                 | Why Used Here                                   |
| -------------------- | -------- | ------------------------------------------------------- | ----------------------------------------------- |
| `@cipherbox/crypto`  | in-repo  | ECIES encryption, HKDF derivation, IPNS record creation | Bin metadata encryption and IPNS key derivation |
| `zustand`            | existing | State management                                        | New `bin.store.ts` for bin items                |
| `react-router-dom`   | existing | Routing                                                 | New `/bin` route                                |
| `@floating-ui/react` | existing | Context menu positioning                                | Bin item context menus                          |

### Supporting (already in project)

| Library          | Purpose         | When Used                                                                                 |
| ---------------- | --------------- | ----------------------------------------------------------------------------------------- |
| `minisearch`     | Search indexing | Exclude bin items from search results (already does this -- bin items not in folder tree) |
| `@nestjs/config` | Backend config  | `RECYCLE_BIN_RETENTION_DAYS` env variable                                                 |

### No New Dependencies

This phase requires zero new npm packages. All functionality is built from existing primitives.

## Architecture Patterns

### Bin Metadata IPNS Record

A new IPNS record dedicated to the recycle bin, following the exact same pattern as the device registry:

```
Derivation:
  secp256k1 privateKey (32 bytes)
    -> HKDF-SHA256(salt="CipherBox-v1", info="cipherbox-recycle-bin-ipns-v1")
    -> 32-byte Ed25519 seed
    -> Ed25519 keypair
    -> IPNS name (deterministic, discoverable from any device)

Encryption: ECIES with user's secp256k1 publicKey
Storage: IPFS blob, addressed via bin IPNS name
```

**Why ECIES instead of AES-GCM?** The device registry uses ECIES because there is no per-record symmetric key to manage. The bin metadata follows the same rationale -- it is a single user-scoped record, not a shared folder that needs per-folder keys. ECIES with the user's public key means only the user can decrypt it. This is the established pattern (see `packages/crypto/src/registry/derive-ipns.ts`).

### RecycleBinMetadata Schema

```typescript
type RecycleBinMetadata = {
  version: 'v1';
  sequenceNumber: number; // Monotonically increasing, same pattern as DeviceRegistry
  entries: BinEntry[];
};

type BinEntry = {
  /** Unique ID for this bin entry */
  id: string; // UUID
  /** Original item type */
  itemType: 'file' | 'folder';
  /** Display name at time of deletion */
  name: string;
  /** IPNS name of the original parent folder (for restore path resolution) */
  originalParentIpnsName: string;
  /** Full breadcrumb path at deletion time (e.g., "My Vault / Documents / Reports") */
  originalPath: string;
  /** Unix timestamp (ms) when item was deleted */
  deletedAt: number;
  /** File/folder size in bytes (for quota display) */
  size: number;
  /** MIME type (files only, empty string for folders) */
  mimeType: string;

  // --- Item reference data (needed for restore and permanent delete) ---

  /** For files: the FolderChild entry that was removed from parent metadata.
   *  Stores the full FilePointer so restore can re-insert it. */
  filePointer?: FilePointer;

  /** For folders: the FolderChild entry that was removed from parent metadata.
   *  Stores the full FolderEntry so restore can re-insert it. */
  folderEntry?: FolderEntry;
};
```

**Key design decisions:**

1. **Store the full FolderChild entry**: When an item is deleted, its `FilePointer` or `FolderEntry` is preserved in the bin entry. This contains all ECIES-wrapped keys needed for restore (e.g., `folderKeyEncrypted`, `ipnsPrivateKeyEncrypted`, `fileMetaIpnsName`). Without this, restore would be impossible since the keys are client-encrypted.

2. **`originalParentIpnsName` instead of parent folder ID**: Folder IDs are internal to the in-memory tree. IPNS names are the stable, cross-device identifier (per Phase 16 merge logic). Using IPNS name enables restore even if the folder tree was rebuilt.

3. **`originalPath` as display-only breadcrumb**: Stored at deletion time for UI display. Not used for restore logic (IPNS name is the authoritative reference).

4. **File content CIDs are NOT unpinned on soft-delete**: The actual encrypted file data stays pinned on IPFS. Quota continues to count it. Only on permanent delete (manual or auto-purge) does CID unpinning occur.

5. **Folder deletion stores only the top-level FolderEntry**: The folder's own IPNS record still exists on IPFS, so its children are preserved. Restore re-adds the FolderEntry to the parent. The folder's subtree is intact because we never unpinned or modified it.

### Recommended Project Structure (new/modified files)

```
packages/crypto/src/
  bin/                            # NEW: bin metadata types
    types.ts                      # RecycleBinMetadata, BinEntry types
    derive-ipns.ts                # HKDF derivation for bin IPNS key
    schema.ts                     # Validator (same pattern as registry/schema.ts)
    index.ts                      # Barrel export

apps/web/src/
  stores/
    bin.store.ts                  # NEW: Zustand store for bin entries
  services/
    bin.service.ts                # NEW: Load/save/purge bin metadata
    delete.service.ts             # MODIFIED: soft-delete writes to bin
    folder.service.ts             # MODIFIED: deleteFileFromFolder/deleteFolder return item data
  hooks/
    useBin.ts                     # NEW: Hook for bin operations (load, restore, purge)
    useFolderMutations.ts         # MODIFIED: delete calls bin service instead of unpin
  components/
    file-browser/
      BinBrowser.tsx              # NEW: Flat list bin view
      BinListItem.tsx             # NEW: Bin item row component
      BinEmptyState.tsx           # NEW: Empty bin state
      ConfirmDialog.tsx           # REUSED: For permanent delete confirmations
      ContextMenu.tsx             # MODIFIED: Add "Delete permanently" for bin items
      SelectionActionBar.tsx      # MODIFIED/REUSED: batch restore + batch permanent delete
    layout/
      AppSidebar.tsx              # MODIFIED: Add "Bin" nav item
      NavItem.tsx                 # MODIFIED: Add 'bin' icon type
  routes/
    BinPage.tsx                   # NEW: /bin route page
    index.tsx                     # MODIFIED: Add /bin route
  styles/
    bin-browser.css               # NEW: Bin-specific styles

apps/api/src/
  vault/
    vault.service.ts              # MODIFIED: Serve retention config to client
    vault.controller.ts           # MODIFIED: Add retention days to vault config response

apps/desktop/src-tauri/src/
  fuse/
    write_ops.rs                  # MODIFIED: unlink/rmdir -> soft-delete via webview IPC
```

### Delete Flow (Soft-Delete)

```
User clicks "Delete" on file/folder
  |
  v
[1] Remove item from parent folder's children array
    (same as current: splice from children, publish updated folder metadata)
  |
  v
[2] Create BinEntry from the removed FolderChild
    - Copy FilePointer or FolderEntry
    - Record originalParentIpnsName, originalPath, deletedAt
    - Calculate size (for files: resolve file IPNS -> get size from FileMetadata)
  |
  v
[3] Add BinEntry to RecycleBinMetadata.entries
    Encrypt and publish bin IPNS record
  |
  v
[4] DO NOT unpin CIDs (data stays on IPFS for recovery)
    DO NOT unenroll from TEE republishing (IPNS records stay alive)
  |
  v
[5] Update local stores:
    - folderStore: remove item from parent children
    - binStore: add new bin entry
    - Search index: already excluded (not in folder tree)
```

### Restore Flow

```
User clicks "Restore" on bin item
  |
  v
[1] Resolve originalParentIpnsName to find the target folder
    - Walk folder tree to find folder with matching IPNS name
    - If found: restore to that folder
    - If NOT found: the parent was also deleted or moved
      -> Check if parent is also in the bin
      -> If parent in bin: recreate the folder path first (recursive restore)
      -> If parent truly gone: restore to root folder
  |
  v
[2] Add the preserved FolderChild back to the target folder's children
    - For files: re-insert the FilePointer into parent's children array
    - For folders: re-insert the FolderEntry into parent's children array
    - Check for name collisions (append " (restored)" suffix if needed)
  |
  v
[3] Publish updated parent folder metadata (IPNS)
  |
  v
[4] Remove BinEntry from RecycleBinMetadata
    Publish updated bin IPNS record
  |
  v
[5] Update local stores:
    - folderStore: add item back to parent children
    - binStore: remove bin entry
```

### Permanent Delete Flow

```
User clicks "Delete permanently" or auto-purge triggers
  |
  v
[1] For files:
    - Resolve file's IPNS name -> get FileMetadata -> get CID(s)
    - Unpin all CIDs (current version + past versions if any)
    - Update quota (removeUsage)
    - (TEE unenrollment deferred -- records expire naturally)
  |
  v
[1b] For folders:
    - Recursively resolve folder IPNS -> get all descendant file CIDs
    - Unpin all CIDs
    - Update quota
  |
  v
[2] Remove BinEntry from RecycleBinMetadata
    Publish updated bin IPNS record
  |
  v
[3] Update local stores:
    - binStore: remove entry
    - quotaStore: adjust used bytes
```

### Auto-Purge Flow (Client-Side)

```
On app load OR when user navigates to /bin:
  |
  v
[1] Load RecycleBinMetadata from IPNS
  |
  v
[2] Filter entries where (now - deletedAt) > retentionPeriodMs
  |
  v
[3] For each expired entry: execute permanent delete flow
  |
  v
[4] Publish updated bin metadata (batch - single IPNS publish)
```

**Important**: Auto-purge is client-side only. If the user never opens the app, items remain in the bin past the retention period but are purged next time the client loads. This is acceptable because:

- Storage quota still counts bin items (no free ride by not opening the app)
- The retention period is a UX guideline, not a strict SLA
- Server-side purge would require the server to decrypt bin metadata, violating zero-knowledge

### Desktop FUSE Integration

Current `handle_unlink` and `handle_rmdir` in `apps/desktop/src-tauri/src/fuse/write_ops.rs`:

1. Remove inode from local tree
2. Update folder metadata (publish to IPNS)
3. Fire-and-forget unpin of CID

**Change**: Instead of unpinning in step 3, send a message to the webview to execute the soft-delete bin service call. The webview has the user's keys and can encrypt/publish the bin metadata.

```
Current FUSE unlink:
  remove inode -> update folder IPNS -> unpin CID (fire-and-forget)

New FUSE unlink:
  remove inode -> update folder IPNS -> IPC to webview: "addToBin(item)"
```

The Rust side already sends metadata to the webview for IPNS publishing via `update_folder_metadata()`. The bin entry creation requires the user's ECIES public key for bin metadata encryption. This key is available in the webview's auth store. So the bin metadata publish must happen on the webview side.

**Minimal approach**: The Rust `handle_unlink`/`handle_rmdir` already correctly removes the child from folder metadata and publishes. The only change needed is: instead of calling `unpin_content()`, emit a Tauri event or invoke a webview JS function that calls the bin service to add the entry. The item data (FilePointer/FolderEntry) needs to be captured before removal and passed to the webview.

### Sync Across Devices

The bin IPNS record is included in the same IPNS polling mechanism as folder metadata:

- TEE republishes the bin IPNS record every 3 hours (enrolled on first bin write)
- Client polls every 30s, compares bin IPNS CID
- On change, re-fetches and decrypts bin metadata
- Local bin store is updated

**Conflict handling**: The bin metadata uses a `sequenceNumber` (same as DeviceRegistry). On concurrent modification, the conflict detection from Phase 16 applies. Use optimistic concurrency: if sequence mismatch on publish, re-read remote, merge entries, retry.

**Merge strategy for bin entries**: Additive merge (union of entries). If both devices deleted different items simultaneously, the merged bin has both. If the same item appears in both (same bin entry ID), keep the one with the earlier `deletedAt` (or either -- they are identical since the same item was deleted).

## Don't Hand-Roll

| Problem                     | Don't Build           | Use Instead                                                                           | Why                                                              |
| --------------------------- | --------------------- | ------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| IPNS key derivation for bin | Custom key generation | HKDF with `cipherbox-recycle-bin-ipns-v1` info string, same pattern as vault/registry | Domain-separated, deterministic, established pattern             |
| Bin metadata encryption     | Custom scheme         | ECIES with user's publicKey (same as DeviceRegistry)                                  | Zero-knowledge, user-scoped, no symmetric key to manage          |
| Flat list UI                | Custom file browser   | Adapt existing `FileListItem` component pattern                                       | Consistent UX, reuse selection/context menu logic                |
| Confirmation dialogs        | New dialog component  | Existing `ConfirmDialog` component                                                    | Already supports destructive styling, loading state              |
| Multi-select                | Custom selection      | Existing `SelectionActionBar` pattern from FileBrowser                                | Consistent interaction, already supports batch operations        |
| Auto-purge scheduling       | Server-side cron      | Client-side check on load/navigate                                                    | Zero-knowledge constraint -- server cannot read bin metadata     |
| Environment config          | Hardcoded values      | NestJS `ConfigService` with `RECYCLE_BIN_RETENTION_DAYS`                              | Follows existing pattern (Redis, DB, CORS all use ConfigService) |

**Key insight:** Every infrastructure piece needed for the recycle bin already exists in CipherBox. The bin is essentially a "special folder" with ECIES encryption (like device registry) instead of AES-GCM encryption (like regular folders), plus business logic for retention and restore.

## Common Pitfalls

### Pitfall 1: Orphaned IPNS Records Accumulating

**What goes wrong:** Every deleted item's IPNS record remains enrolled in TEE republishing. If a user deletes hundreds of files and never permanently deletes them, the TEE republish queue grows indefinitely.
**Why it happens:** Soft-delete intentionally keeps IPNS records alive for restore.
**How to avoid:** On permanent delete, add TEE unenrollment (if an API endpoint exists by then -- currently deferred to "Phase 14 TODO"). At minimum, document this as a known limitation. The republish service already has capacity warnings at 1000+ records.
**Warning signs:** TEE republish queue depth metric growing without plateau.

### Pitfall 2: Bin Metadata Blob Size Growth

**What goes wrong:** If a user deletes hundreds of items, each BinEntry contains a full FolderEntry or FilePointer. The bin metadata blob grows, increasing IPFS upload/download time.
**Why it happens:** Each BinEntry preserves the full FolderChild for restore.
**How to avoid:**

- Auto-purge on load keeps the bin bounded by retention period
- A 30-day retention with typical usage (say 100 items deleted per month) results in ~50KB of bin metadata. This is well within acceptable limits.
- Add a safety check: if bin metadata exceeds 1MB, warn the user and suggest emptying the bin.
  **Warning signs:** Bin load time > 2s.

### Pitfall 3: Stale `originalParentIpnsName` After Folder Moves

**What goes wrong:** User deletes a file from folder A, then moves folder A to a different location. The bin entry's `originalParentIpnsName` still points to folder A's IPNS name, which is correct (IPNS names don't change on move). But the `originalPath` display string is now inaccurate.
**Why it happens:** The display path is captured at deletion time.
**How to avoid:** Accept that `originalPath` is "path at deletion time" -- display it with a note "(at time of deletion)". The IPNS-based restore logic will correctly find the moved folder regardless of its current location in the tree.
**Warning signs:** User confusion when displayed path doesn't match current folder structure.

### Pitfall 4: Concurrent Delete-and-Restore Race

**What goes wrong:** On device A, user deletes a file. On device B (before sync), user tries to access the same file. After sync, device B sees the file is gone.
**Why it happens:** IPNS polling is 30s. Within that window, the two devices have divergent state.
**How to avoid:** This is the same eventual consistency the app already handles for all operations. The sync mechanism (Phase 16) already handles concurrent modifications. The bin just adds a recovery path -- the user can restore the file from the bin on any device.
**Warning signs:** None specific -- this is inherent to eventual consistency.

### Pitfall 5: Deleting Shared Items

**What goes wrong:** User deletes a file that is actively shared with another user. The file goes to the owner's bin, but the recipient loses access.
**Why it happens:** The share references the item by IPNS name. When removed from the folder, the share's reference becomes dangling.
**How to avoid:** For v1, accept this behavior -- the owner's delete takes precedence. The shared user will see a resolution error for that IPNS name. Future enhancement: notify shared users when a shared item is deleted.
**Warning signs:** Share recipients see "file not found" errors.

### Pitfall 6: Restoring to a Deleted Parent Folder

**What goes wrong:** User deletes folder A (which contained file B), then tries to restore file B. The original parent (folder A) no longer exists in the folder tree.
**Why it happens:** File B's `originalParentIpnsName` points to folder A, which is itself in the bin.
**How to avoid:** Implement the "recreate path" logic from CONTEXT.md:

1. Look up `originalParentIpnsName` in the folder tree
2. If not found, check if a bin entry exists with a matching IPNS name
3. If parent is in bin, restore the parent first (recursively)
4. If parent is nowhere (permanently deleted), restore to root
   This must be clearly implemented with recursion guards (max depth) to prevent infinite loops.
   **Warning signs:** "Folder not found" errors during restore.

### Pitfall 7: Size Calculation for Folder Bin Entries

**What goes wrong:** When deleting a folder, its `size` for quota display and purge-time unpin requires resolving all descendant file metadata IPNS records. This is expensive.
**Why it happens:** Folder metadata only contains FilePointers (no inline size), and the folder tree may have deep nesting.
**How to avoid:**

- On delete: if the folder's subtree is loaded in the folder store, calculate size from loaded data. If not fully loaded, use 0 as size and display "Unknown" in the bin.
- On permanent delete: resolve the full subtree to unpin all CIDs. This is inherently async and can be done in background.
- Accept that folder size in the bin view may be approximate or unknown.
  **Warning signs:** Long delays during folder deletion if trying to resolve all descendant sizes eagerly.

## Code Examples

### Bin IPNS Key Derivation (follows registry pattern exactly)

```typescript
// Source: modeled on packages/crypto/src/registry/derive-ipns.ts
const BIN_HKDF_SALT = new TextEncoder().encode('CipherBox-v1');
const BIN_HKDF_INFO = new TextEncoder().encode('cipherbox-recycle-bin-ipns-v1');

export async function deriveBinIpnsKeypair(userPrivateKey: Uint8Array): Promise<{
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  ipnsName: string;
}> {
  if (userPrivateKey.length !== SECP256K1_PRIVATE_KEY_SIZE) {
    throw new CryptoError('Invalid private key size for bin derivation', 'INVALID_KEY_SIZE');
  }

  const ed25519Seed = await deriveKey({
    inputKey: userPrivateKey,
    salt: BIN_HKDF_SALT,
    info: BIN_HKDF_INFO,
    outputLength: 32,
  });

  const ed25519PublicKey = await ed.getPublicKeyAsync(ed25519Seed);
  const ipnsName = await deriveIpnsName(ed25519PublicKey);

  return { privateKey: ed25519Seed, publicKey: ed25519PublicKey, ipnsName };
}
```

### Bin Metadata Encryption/Decryption (follows registry pattern)

```typescript
// Source: modeled on packages/crypto/src/registry/index.ts
export async function encryptBinMetadata(
  metadata: RecycleBinMetadata,
  userPublicKey: Uint8Array
): Promise<Uint8Array> {
  const json = JSON.stringify(metadata);
  const plaintext = new TextEncoder().encode(json);
  return wrapKey(plaintext, userPublicKey); // ECIES encrypt
}

export async function decryptBinMetadata(
  ciphertext: Uint8Array,
  userPrivateKey: Uint8Array
): Promise<RecycleBinMetadata> {
  const plaintext = await unwrapKey(ciphertext, userPrivateKey);
  const json = new TextDecoder().decode(plaintext);
  return validateBinMetadata(JSON.parse(json));
}
```

**Note:** The `wrapKey`/`unwrapKey` in CipherBox is ECIES encrypt/decrypt, not just symmetric key wrapping. It works on arbitrary-length plaintext (the ECIES implementation handles the internal AES encryption). This is confirmed by the DeviceRegistry pattern which encrypts the entire registry JSON blob via ECIES.

### Bin Store (Zustand)

```typescript
// Source: modeled on stores/sync.store.ts and stores/share.store.ts
type BinState = {
  entries: BinEntry[];
  isLoading: boolean;
  isLoaded: boolean;
  error: string | null;
  sequenceNumber: number;
  binIpnsName: string | null;

  setEntries: (entries: BinEntry[], seq: number) => void;
  addEntry: (entry: BinEntry) => void;
  removeEntry: (entryId: string) => void;
  removeEntries: (entryIds: string[]) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  setBinIpnsName: (name: string) => void;
  clearBin: () => void;
};
```

### Soft-Delete in Folder Mutations (modified handleDelete)

```typescript
// In useFolderMutations.ts handleDelete, REPLACE the unpin fire-and-forget with:

// Instead of:
//   resolveIpnsRecord(ipnsName).then(r => unpinFromIpfs(r.cid))
// Do:
//   await binService.addToBin({ item, parentIpnsName, parentPath })

// The bin service handles:
// 1. Creating the BinEntry from the removed FolderChild
// 2. Loading current bin metadata
// 3. Appending the entry
// 4. Encrypting and publishing the updated bin IPNS record
```

### Sidebar Addition

```tsx
// In AppSidebar.tsx, add between "Shared" and "Settings":
<NavItem to="/bin" icon="bin" label="Bin" active={location.pathname.startsWith('/bin')} />
```

### Retention Configuration (API side)

```typescript
// In vault.service.ts or a new config endpoint
const RECYCLE_BIN_RETENTION_DAYS = this.configService.get<number>(
  'RECYCLE_BIN_RETENTION_DAYS',
  30 // default 30 days for production
);

// Exposed to client via vault config or a new /config endpoint
// Client reads this on login and stores in auth/vault store
```

```
# .env.example
RECYCLE_BIN_RETENTION_DAYS=30

# .env (staging)
RECYCLE_BIN_RETENTION_DAYS=2
```

### Client-Side Retention Constant

```typescript
// The retention period (in ms) comes from the API config response
// Stored in vault store or a dedicated config store
const RETENTION_MS = retentionDays * 24 * 60 * 60 * 1000;

function isExpired(entry: BinEntry): boolean {
  return Date.now() - entry.deletedAt > RETENTION_MS;
}

function daysRemaining(entry: BinEntry): number {
  const elapsed = Date.now() - entry.deletedAt;
  const remaining = RETENTION_MS - elapsed;
  return Math.max(0, Math.ceil(remaining / (24 * 60 * 60 * 1000)));
}
```

## State of the Art

| Old Approach (before this phase)     | New Approach (this phase)                   | Impact                                     |
| ------------------------------------ | ------------------------------------------- | ------------------------------------------ |
| Delete = immediate unpin + permanent | Delete = soft-delete to bin, deferred unpin | Items are recoverable for retention period |
| No bin metadata IPNS                 | HKDF-derived bin IPNS record                | Cross-device bin sync                      |
| FUSE unlink = permanent              | FUSE unlink = soft-delete                   | Desktop deletions are recoverable from web |
| Quota freed on delete                | Quota freed on permanent delete only        | Bin items count against quota              |

**Deprecated/outdated:**

- The current `deleteFile()` in `delete.service.ts` that directly unpins will be replaced by a soft-delete path. The `unpinFromIpfs` call moves to the permanent delete flow.

## Open Questions

1. **ECIES max plaintext size for bin metadata**
   - What we know: DeviceRegistry uses ECIES for the entire blob. The eciesjs library uses AES-256-GCM internally for the payload, so there's no practical size limit.
   - What's unclear: Performance with very large bin metadata (1000+ entries). Each entry is ~500 bytes, so 1000 entries = ~500KB ECIES payload.
   - Recommendation: Test with 1000 entries during implementation. Add a safety cap (e.g., 5000 entries max) with a warning to empty the bin.

2. **TEE enrollment for the bin IPNS record**
   - What we know: TEE republishing keeps IPNS records alive. The bin IPNS record needs to be enrolled (same as vault, device registry, all folder IPNS records).
   - What's unclear: The bin IPNS key is derived via HKDF, not randomly generated. Is the TEE enrollment path the same? (Answer: yes, the TEE receives the encrypted IPNS private key regardless of derivation method.)
   - Recommendation: Enroll the bin IPNS key with TEE on first bin write, same as vault/registry IPNS enrollment.

3. **Folder size in bin entries**
   - What we know: Files have `size` in their FileMetadata. Folders don't have a single size -- need to sum all descendant files.
   - What's unclear: How to handle partially-loaded folder trees (not all subfolders are loaded in memory).
   - Recommendation: For files, use the known size from FileMetadata (resolved at delete time if possible). For folders, store 0 and display "Folder" without size. Size is only critical for quota (which is tracked server-side via pins anyway).

4. **Batch operations and IPNS publish count**
   - What we know: Deleting multiple items from the same folder = 1 folder IPNS publish + 1 bin IPNS publish.
   - What's unclear: With optimistic concurrency, if the bin publish conflicts, the folder publish already succeeded. Need atomic-like behavior.
   - Recommendation: Use add-before-remove pattern: write to bin first, then remove from folder. If bin publish fails, items stay in both places (recoverable). On next load, detect duplicates and reconcile.

## Sources

### Primary (HIGH confidence)

- `packages/crypto/src/registry/derive-ipns.ts` -- HKDF derivation pattern for IPNS keys
- `packages/crypto/src/vault/derive-ipns.ts` -- Vault IPNS derivation pattern
- `packages/crypto/src/registry/schema.ts` -- Registry validator pattern
- `apps/web/src/services/folder.service.ts` -- Delete flow (lines 400-504)
- `apps/web/src/hooks/useFolderMutations.ts` -- Delete hook implementation (lines 541-629)
- `apps/web/src/services/delete.service.ts` -- Current unpin service
- `apps/web/src/stores/folder.store.ts` -- Folder state management
- `apps/web/src/stores/quota.store.ts` -- Quota tracking
- `apps/web/src/components/layout/AppSidebar.tsx` -- Current sidebar structure
- `apps/web/src/components/file-browser/ContextMenu.tsx` -- Context menu pattern
- `apps/web/src/components/file-browser/ConfirmDialog.tsx` -- Confirmation dialog pattern
- `apps/web/src/components/file-browser/SelectionActionBar.tsx` -- Multi-select pattern
- `apps/desktop/src-tauri/src/fuse/write_ops.rs` -- FUSE unlink/rmdir (lines 250-310, 547-610)
- `docs/METADATA_SCHEMAS.md` -- All metadata schemas documented
- `00-Preliminary-R&D/Documentation/TECHNICAL_ARCHITECTURE.md` -- Encryption architecture

### Secondary (MEDIUM confidence)

- `apps/desktop/src-tauri/src/fuse/mod.rs` -- merge_folder_children pattern for conflict resolution (applicable to bin merge)
- `apps/api/src/vault/vault.service.ts` -- Quota implementation and ConfigService usage
- `apps/api/src/app.module.ts` -- NestJS ConfigModule setup

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH -- no new libraries, all patterns are established in the codebase
- Architecture: HIGH -- directly modeled on existing DeviceRegistry and folder metadata patterns
- Bin metadata design: HIGH -- ECIES + HKDF is the exact same pattern used twice already (vault, registry)
- Delete/restore flows: HIGH -- well-understood from reading the existing delete implementation
- Desktop FUSE changes: MEDIUM -- the general approach is clear but IPC mechanism for bin writes needs validation during implementation
- Pitfalls: HIGH -- derived from direct code reading and understanding of IPNS lifecycle

**Research date:** 2026-03-04
**Valid until:** 2026-04-04 (stable -- no external dependencies changing)
