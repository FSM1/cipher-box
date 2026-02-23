---
created: 2026-01-22T15:51
title: Atomic file upload flow with client-side CID
area: api
files:
  - apps/web/src/services/upload.service.ts
  - apps/api/src/ipfs/ipfs.controller.ts
  - apps/api/src/vault/vault.service.ts
---

## Problem

The current file upload flow requires the webapp to make multiple sequential requests to the API:

1. Upload encrypted file blob to IPFS (via API)
2. Create file metadata record
3. Update folder metadata (IPNS publish)

This multi-request approach has several drawbacks:

- **Not atomic**: If any step fails, the system can be left in an inconsistent state (e.g., file uploaded but metadata not created)
- **Increased latency**: Multiple round trips to the backend
- **Complex error handling**: Client must manage rollback logic for partial failures
- **Race conditions**: Concurrent uploads could conflict on folder metadata updates

## Solution

Optimize to a single atomic backend call that handles the entire upload flow:

1. **Client-side CID calculation**: Compute the CID of the encrypted blob locally before upload
   - Use `multiformats` or `ipfs-unixfs` library to calculate CID client-side
   - This allows the client to know the final CID before uploading

2. **Single atomic request**: Send all data in one request:
   - Encrypted file blob
   - Pre-calculated CID (for verification)
   - File metadata (name, size, encrypted file key, etc.)
   - Folder update details (parent folder ID, new folder metadata JSON)
   - IPNS signature for folder update (signed client-side)

3. **Backend atomic handling**:
   - Verify client-calculated CID matches after pinning
   - Create file record in database
   - Update folder metadata and IPNS in single transaction
   - Rollback all changes if any step fails

4. **Benefits**:
   - Single network round-trip
   - Server-side atomicity guarantees
   - Simpler client error handling
   - No partial state possible

**Key technical considerations**:

- CID calculation must match Pinata/IPFS pinning result exactly
- Need to handle chunking for large files (UnixFS DAG structure)
- IPNS signature must be prepared client-side with knowledge of final metadata

## Brainstorm Notes (2026-01-22)

### Core Atomicity Challenge

IPNS publish is external to the DB transaction — once published, cannot rollback:

```text
[DB Transaction]                    [External Call]
┌─────────────────────┐            ┌─────────────────┐
│ 1. Pin to IPFS      │            │                 │
│ 2. Record in DB     │ ──commit──>│ 3. Publish IPNS │
│ 3. Update quota     │            │                 │
└─────────────────────┘            └─────────────────┘
    Can rollback                    Cannot rollback
```

### Failure Scenarios Analyzed

| Scenario            | DB State    | IPFS State  | IPNS State | User Impact       |
| ------------------- | ----------- | ----------- | ---------- | ----------------- |
| All succeed         | Recorded    | Pinned      | Updated    | ✅ Perfect        |
| IPFS pin fails      | Rolled back | Nothing     | Nothing    | ✅ Clean retry    |
| DB fails after pin  | Rolled back | Orphan blob | Nothing    | ⚠️ Wasted storage |
| IPNS fails after DB | Recorded    | Pinned      | **Stale**  | ❌ File invisible |

### Options Evaluated

#### Option A: Accept Partial State + Client Retry

- Pin → Record → Commit → Try IPNS
- On IPNS failure: return `{ cid, ipnsError: true }`, client retries IPNS
- Pros: Simple, file safely stored, client already has IPNS capability
- Cons: Client retry logic, brief invisible window

#### Option B: Optimistic IPNS (Publish First)

- Pin → Publish IPNS → Record → Commit
- Pros: File always visible if exists
- Cons: Worse failure mode (IPNS references non-existent file)

#### Option C: Two-Phase with Pending State

- Record with `status: pending`, publish IPNS, then `status: confirmed`
- Pros: Clear visibility, background retry
- Cons: Complex state model, UI changes needed

#### Option D: Idempotent Retry with Deduplication

- Accept `{ expectedCid, idempotencyKey }`, skip completed steps on retry
- Pros: True atomic from client view, safe retries
- Cons: Need idempotency storage (Redis/DB), more complexity

### Recommended Approach

**Option A with enhancement** — response includes granular status:

```typescript
{
  cid: string;
  recorded: boolean;
  ipnsPublished: boolean;
  retryToken?: string;  // If IPNS failed, token to retry just that part
}
```

**Rationale:**

1. File safety paramount — once pinned and recorded, data is safe
2. IPNS is eventually consistent anyway (30s polling)
3. Client already handles IPNS signing
4. Matches zero-knowledge model
5. "Invisible file" window typically <1 second

### Client-Side CID Options

**For v1 (simpler):** Keep CID calculation server-side, just reduce to one request
**For v2 (full):** Add `ipfs-unixfs-importer` for client-side CID, enables offline-first

### Open Questions

- Is client-side CID essential for v1, or is single request sufficient?
- Exact chunking algorithm match with Pinata for large files?
- Should this be a new phase or quick task?

### CodeRabbit Review Notes (2026-02-07, PR #55)

CodeRabbit independently identified the same per-file IPNS publish bottleneck:

- **Call chain per file:** `addFile()` → `addFileToFolder()` → `updateFolderMetadata()` → `createAndPublishIpnsRecord()` — each triggering a separate IPNS publish (~2s each)
- **Suggested approach:** Create `addFilesToFolder` / `updateFolderMetadataBatch` function so `createAndPublishIpnsRecord` is invoked once after all files are added
- **Keep `addFile` for single-file use**, batch path calls `updateFolderMetadata` once at the end
- **Key files confirmed:** `EmptyState.tsx` (handleDrop loop), `useFileUpload.ts`, `upload.service.ts`, `folder.service.ts` (`addFileToFolder`, `updateFolderMetadata`)

---

<!-- Decision pending — return to this after Phase 7 -->
