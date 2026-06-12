# Phase 44: IPNS conflict handling - Research

**Researched:** 2026-06-13
**Domain:** IPNS optimistic-concurrency control, folder metadata three-way merge, file record CAS
**Confidence:** HIGH

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- D-01: Three-way merge. `updateFolderMetadataAndPublish` gains optional `baseChildren` param (backward compatible). On 409: re-fetch + decrypt remote, diff base/local/remote per entry — local add/keep, local delete/drop (edit-beats-delete: keep remote version if remote modified after base), remote add/keep, modified-in-both/last-write-wins by `modifiedAt`.
- D-02: No `baseChildren` passed → degrade to children union + log warning. Migration path only.
- D-03: After merge: re-encrypt and re-upload merged metadata (new CID) before republishing. Never bump seq on stale state.
- D-04: 4 attempts total with exponential backoff + jitter. Each attempt = re-resolve seq + re-fetch remote + merge + re-encrypt + re-upload + CAS publish.
- D-05: After exhaustion: throw typed `ConflictError` (carrying ipnsName, attempts, last remote seq). Route into existing v1.0 optimistic-concurrency conflict-detection UX.
- D-06: Extend CAS to file IPNS publishes: pass `expectedSequenceNumber` wherever file records publish (the `updateFileMetadata` → `replaceFileInFolder` path and callers).
- D-07: File conflict semantics = latest-wins + loser-becomes-version. On 409: re-fetch remote file metadata; newest `modifiedAt` wins as current content pointer; losing write's content entry preserved in `versions[]`. `versions[]` merges by union deduped by `cid`, sorted by timestamp, capped by Phase 39 `maxVersionsPerFile`; overflow becomes `prunedCids` flowing through Phase 42-fixed guarded endpoint.
- D-08: Sweep TS callers in-phase: web hooks (`useFileOperations`, folder ops, bin/share flows), `packages/sdk` client methods, and `packages/sdk/src/share/shared-write.ts`. Update to (a) pass `baseChildren` snapshots and (b) handle `ConflictError` via existing conflict surfaces. Write shares are the headline multi-writer case.
- D-09: Rust FUSE 409-merge parity explicitly deferred.

### Claude's Discretion

- `ConflictError` exact shape/fields and how existing conflict UI consumes it.
- Backoff base/cap values and jitter distribution.
- Merge unit-test matrix structure (base/local/remote permutations) and whether to add shared test vectors.
- Where the three-way merge helper lives in sdk-core (pure function, unit-testable).

### Deferred Ideas (OUT OF SCOPE)

- Rust FUSE 409-merge parity.
- Full CRDT model (deferred to `2026-02-22-crdt-ipns-inbox-sharing.md`).

</user_constraints>

## Summary

Phase 44 fixes two silent data-loss paths in `packages/sdk-core`. The folder path (`updateFolderMetadataAndPublish`) currently does one retry on 409, re-resolving only the sequence number while keeping the stale CID — defeating the server's CAS and silently overwriting the concurrent writer's children. The file path (`updateFileMetadata`) does a resolve-then-seq+1-publish with a full TOCTOU window and no CAS at all.

The fix is: (1) add a `mergeAndPublishFolderChildren` helper (pure function) that does a three-way merge of `base`/`local`/`remote` `FolderChild[]` per D-01, (2) embed a 4-attempt retry loop in `updateFolderMetadataAndPublish` that re-fetches, merges, re-encrypts, and re-uploads before each CAS publish attempt, (3) extend `updateFileMetadata` with `expectedSequenceNumber` CAS + 409 conflict handling using latest-wins semantics with the loser preserved in `versions[]`, and (4) sweep all TS callers (18 total call sites identified across `packages/sdk/src/client.ts`, `packages/sdk/src/bin/index.ts`, `packages/sdk/src/share/shared-write.ts`, and `apps/web/src/hooks/`) to pass `baseChildren` snapshots and route `ConflictError` to the existing sync-banner conflict UI.

**Primary recommendation:** Implement the three-way merge helper as a pure exported function in `packages/sdk-core/src/folder/merge.ts`, tested in isolation with a permutation matrix, before wiring it into the retry loop in `folder/index.ts`.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
| --- | --- | --- | --- |
| Three-way merge logic | `packages/sdk-core` (library) | — | Pure function over decrypted data; no store/React deps |
| Retry loop + backoff | `packages/sdk-core/src/folder/index.ts` | — | Merge lives where publish lives; callers get a single call contract |
| File CAS extend | `packages/sdk-core/src/file/index.ts` | — | Same location as the TOCTOU bug |
| ConflictError class | `packages/sdk-core/src/errors.ts` (new) | — | Must be importable by sdk-core callers without sdk dependency |
| Caller adoption (baseChildren) | `packages/sdk/src/client.ts`, `bin/`, `share/` | `apps/web/src/hooks/` | All existing callers of the folder-publish API |
| Conflict UX routing | `apps/web/src/hooks/folder-helpers.ts` | sync.store | `withConflictRetry` wrapper already shows conflict banner |

## Standard Stack

### Core

All packages are already present in the monorepo — no new external dependencies required.

| Library | Version | Purpose | Why Standard |
| --- | --- | --- | --- |
| `@cipherbox/sdk-core` | workspace | Three-way merge + retry loop | The bug lives here |
| `@cipherbox/core` types | workspace | `FolderChild`, `FileMetadata`, `VersionEntry` | Canonical type definitions |
| `vitest` | existing | Unit tests for merge permutations | Already configured in sdk-core |

### No New External Dependencies

This phase adds zero external packages. All required functions (`fetchAndDecryptMetadata`, `resolveIpnsRecord`, `createAndPublishIpnsRecord`, `encryptFolderMetadata`) already exist in `packages/sdk-core/src/`.

## Architecture Patterns

### System Architecture Diagram

```
Caller (web hook / SDK client / shared-write)
  │  passes: children (local), baseChildren (snapshot), sequenceNumber
  ▼
updateFolderMetadataAndPublish (sdk-core/folder/index.ts:174)
  │
  ├─ attempt 1..4
  │    ├─ re-resolve seq via resolveIpnsRecord (authoritative)
  │    ├─ re-fetch + decrypt remote via fetchAndDecryptMetadata
  │    ├─ mergeChildren(base, local, remote) → merged  [NEW pure fn]
  │    ├─ encryptFolderMetadata(merged) → encrypted
  │    ├─ addToIpfs(encrypted) → newCid
  │    └─ createAndPublishIpnsRecord(expectedSequenceNumber=resolvedSeq)
  │         ├─ Success → return { cid, newSequenceNumber }
  │         └─ 409   → backoff+jitter, next attempt
  │
  └─ After 4 failures → throw ConflictError { ipnsName, attempts, lastRemoteSeq }

updateFileMetadata (sdk-core/file/index.ts:181)
  │  NEW: accepts expectedSequenceNumber
  │
  ├─ resolve seq → build record
  ├─ batchPublishIpnsRecords(expectedSequenceNumber=resolvedSeq)
  │    ├─ Success → done
  │    └─ 409   → re-fetch remote FileMetadata
  │              → latest-wins: compare local.modifiedAt vs remote.modifiedAt
  │              → loser entry → merged into versions[]
  │              → cap versions[] by maxVersionsPerFile → prunedCids
  │              → re-encrypt + re-upload + retry publish
  │              → 2nd 409 → throw ConflictError
  └─
```

### Recommended Project Structure

New files:

```
packages/sdk-core/src/
├── folder/
│   ├── index.ts          # updateFolderMetadataAndPublish (modified)
│   └── merge.ts          # NEW: mergeChildren() pure fn
├── file/
│   └── index.ts          # updateFileMetadata (modified, CAS + conflict)
└── errors.ts             # NEW: ConflictError class
```

### Pattern 1: Three-Way Merge Function Signature

**What:** Pure `(base, local, remote) → merged` over `FolderChild[]`. Keyed by a stable identity — use `id` (UUID) as the primary key; `ipnsName`/`fileMetaIpnsName` is a structural property that changes on re-creation, while `id` is stable.

**When to use:** Called inside the retry loop after every 409. Also exported for unit testing.

```typescript
// Source: design from CONTEXT.md D-01 + types from @cipherbox/core
export function mergeChildren(
  base: FolderChild[],
  local: FolderChild[],
  remote: FolderChild[]
): FolderChild[] {
  const baseById = new Map(base.map((c) => [c.id, c]));
  const localById = new Map(local.map((c) => [c.id, c]));
  const remoteById = new Map(remote.map((c) => [c.id, c]));
  const allIds = new Set([...localById.keys(), ...remoteById.keys()]);
  const merged: FolderChild[] = [];

  for (const id of allIds) {
    const b = baseById.get(id);
    const l = localById.get(id);
    const r = remoteById.get(id);

    if (l && !b && !r) { merged.push(l); continue; }  // local add
    if (r && !b && !l) { merged.push(r); continue; }  // remote add
    if (l && r && !b) {                                // added by both
      merged.push(l.modifiedAt >= r.modifiedAt ? l : r); continue;
    }
    if (!l && b) {
      // local delete: edit-beats-delete — keep if remote modified after base
      if (r && b && r.modifiedAt > b.modifiedAt) { merged.push(r); }
      continue;
    }
    if (!r && b) { merged.push(l!); continue; }       // remote delete, local wins
    if (l && r) {
      merged.push(l.modifiedAt >= r.modifiedAt ? l : r); continue;
    }
  }
  return merged;
}
```

**Stable identity note:** `FolderEntry.id` and `FilePointer.id` are UUIDs generated at creation time. They do NOT change across renames or content updates — correct key for merge.

### Pattern 2: ConflictError Class

**What:** Typed error thrown after all retry attempts exhausted.

**Modelled on:** `BinNotLoadedError` in `packages/sdk/src/client.ts` (extends Error, sets name). Place in `packages/sdk-core/src/errors.ts` so it's importable by sdk-core itself.

```typescript
// Source: BinNotLoadedError pattern at packages/sdk/src/client.ts:38
export class ConflictError extends Error {
  readonly ipnsName: string;
  readonly attempts: number;
  readonly lastRemoteSeq: bigint;

  constructor(ipnsName: string, attempts: number, lastRemoteSeq: bigint) {
    super(
      `IPNS conflict unresolved after ${attempts} attempts for ${ipnsName} (remote seq: ${lastRemoteSeq})`
    );
    this.name = 'ConflictError';
    this.ipnsName = ipnsName;
    this.attempts = attempts;
    this.lastRemoteSeq = lastRemoteSeq;
  }
}

export function isConflictExhausted(error: unknown): error is ConflictError {
  return error instanceof ConflictError;
}
```

### Pattern 3: Retry Loop with Exponential Backoff + Jitter

**What:** Replaces the current 2-attempt loop at `folder/index.ts:204-232`.

**Backoff design:** Base 100ms, doubles per attempt, cap 1500ms, uniform jitter ±50% of computed delay. 4 attempts covers: 100ms, 200ms, 400ms backoffs before final fail. Matches Rust FUSE jitter pattern at `crates/fuse/src/lib.rs:389-392`.

```typescript
// [ASSUMED] — backoff values chosen by reasoning, not a library spec
const BACKOFF_BASE_MS = 100;
const BACKOFF_CAP_MS = 1500;

function retryDelayMs(attempt: number): number {
  const base = Math.min(BACKOFF_BASE_MS * 2 ** attempt, BACKOFF_CAP_MS);
  return base * (0.5 + Math.random() * 0.5); // 50–100% of base
}
```

### Pattern 4: File CAS via batchPublishIpnsRecords

**Current gap:** `updateFileMetadata` resolves sequence then publishes — no `expectedSequenceNumber` passed to `batchPublishIpnsRecords`. The batch endpoint accepts `expectedSequenceNumber` per-record (confirmed in `ipns/index.ts:119` type definition).

**Fix:** After resolving sequence, pass it as `expectedSequenceNumber` in the batch payload. On failure (batch returns `totalFailed > 0` OR throws 409), re-fetch the remote file metadata and apply latest-wins + loser-becomes-version.

**Important:** The batch endpoint returns `{ totalFailed, totalSucceeded }` on partial failure — it does NOT throw a 409. The single-record `createAndPublishIpnsRecord` throws a 409 error object. For file CAS, `batchPublishIpnsRecords` needs to return conflict signal. Check whether the batch API supports per-record conflict response — if not, use `createAndPublishIpnsRecord` directly for file records (same as `updateFolderMetadataAndPublish` already does for folders).

**Recommendation:** Use `createAndPublishIpnsRecord` for file records in the conflict path (matching the folder pattern) rather than `batchPublishIpnsRecords`, so 409 throws a detectable error.

### Pattern 5: Versions[] Merge for File Conflict

**What:** On file 409, winner's `versions[]` becomes the merged union of both writes' version arrays.

```typescript
// Source: reasoning from D-07 + VersionEntry shape at packages/core/src/file/types.ts:10
function mergeVersions(
  a: VersionEntry[] | undefined,
  b: VersionEntry[] | undefined,
  maxVersions: number
): { versions: VersionEntry[]; prunedCids: string[] } {
  const combined = [...(a ?? []), ...(b ?? [])];
  // Deduplicate by cid (same content uploaded twice → one entry)
  const seenCid = new Set<string>();
  const deduped = combined.filter((v) => {
    if (seenCid.has(v.cid)) return false;
    seenCid.add(v.cid);
    return true;
  });
  // Sort newest first
  deduped.sort((x, y) => y.timestamp - x.timestamp);
  const versions = deduped.slice(0, maxVersions);
  const prunedCids = deduped.slice(maxVersions).map((v) => v.cid);
  return { versions, prunedCids };
}
```

### Anti-Patterns to Avoid

- **Bumping seq on stale CID:** The exact bug being fixed. Never `currentSeq + 1n` without re-uploading a fresh CID.
- **Trusting the 409 response body's `currentSequenceNumber`:** `errors.ts:35` documents that the custom axios instance does not attach the response body. Always re-resolve via `resolveIpnsRecord` for authoritative seq.
- **Using `fileMetaIpnsName` as merge key for folder children:** It's a structural field, not identity. Use `id` (UUID).
- **Calling `batchPublishIpnsRecords` for CAS on file records expecting 409 throw:** The batch endpoint returns `totalFailed > 0` instead of throwing; use `createAndPublishIpnsRecord` to get a detectable 409.
- **Storing `ConflictError` in the `packages/sdk` error.ts:** The class must be in `packages/sdk-core/src/errors.ts` because `updateFolderMetadataAndPublish` throws it, and `sdk-core` cannot import from `sdk`.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
| --- | --- | --- | --- |
| Re-fetching remote metadata | Custom fetch logic | `fetchAndDecryptMetadata` + `resolveIpnsRecord` already in sdk-core | Already handles v1 JSON + v2 binary blobs transparently |
| CAS publish | Custom HTTP headers | `expectedSequenceNumber` param in `createAndPublishIpnsRecord` | Already wired to the server's CAS check |
| 409 error detection | String-matching | `isConflictError()` in `packages/sdk/src/error.ts` | Handles both `.status` and `.response.status` shapes |
| Base64 encoding | `btoa(String.fromCharCode(...spread))` | Loop-based `uint8ToBase64` already in `folder/index.ts:358` | Avoids call-stack overflow on large records |

## Caller Sweep Map

Complete list of `updateFolderMetadataAndPublish` call sites that require `baseChildren` addition:

### `packages/sdk/src/client.ts` (8 direct calls)

| Line | Method | Has local children context | baseChildren source |
| --- | --- | --- | --- |
| 414 | `createFolder` | `parent.children` before add | `parent.children` (snapshot before mutation) |
| 432 | `createFolder` (empty subfolder init) | `[]` | `[]` always (new folder) |
| 499 | `renameItem` | `folder.children` before rename | `folder.children` snapshot |
| 550 | `moveItem` (dest) | `dest.children` before add | `dest.children` snapshot |
| 560 | `moveItem` (source) | `source.children` before remove | `source.children` snapshot |
| 617 | `deleteItem` | `folder.children` before remove | `folder.children` snapshot |
| 726 | `uploadFile` | `folder.children` before add | `folder.children` snapshot |
| 990 | `uploadFiles` | `folder.children` batch | snapshot before loop |

### `packages/sdk/src/bin/index.ts` (2 calls)

| Line | Method | baseChildren source |
| --- | --- | --- |
| 242 | `addToBin` | `folder.children` before remove |
| 339 | `restoreFromBin` | `targetFolder.children` before add |

### `packages/sdk/src/share/shared-write.ts` (4 calls)

| Line | Function | baseChildren source |
| --- | --- | --- |
| 201 | `uploadToSharedFolder` | `swCtx.children` |
| 296 | `createSharedSubfolder` | `swCtx.children` |
| 350 | `renameInSharedFolder` | `swCtx.children` |
| 377 | `deleteFromSharedFolder` | `swCtx.children` |

**Note:** `shared-write.ts` is the D-08 headline case — currently on union fallback (no `baseChildren` passed). All 4 functions must move to three-way merge.

### `apps/web/src/hooks/useFileOperations.ts` (1 indirect + 1 fire-and-forget)

| Line | Context | Notes |
| --- | --- | --- |
| addFileToFolder call path (line 109) | Uses `addFileToFolder` which calls `buildFolderIpnsRecord` + `batchPublishIpnsRecords`, not `updateFolderMetadataAndPublish` directly | `addFileToFolder` / `addFilesToFolder` use batch path — separate CAS analysis needed |
| 461 | Fire-and-forget `updateFolderMetadataAndPublish` after file update | Uses `parentFolder.children` as both local and implicit base |

### `apps/web/src/hooks/useFileVersions.ts` (2 fire-and-forget)

Both are lazy-migration folder re-publishes (lines 126, 251) — low priority for base snapshot since they run after the main operation, but should still pass a base.

### `addFileToFolder` / `addFilesToFolder` in `packages/sdk-core/src/folder/index.ts`

These use `buildFolderIpnsRecord` → `batchPublishIpnsRecords` with `expectedSequenceNumber`, not `updateFolderMetadataAndPublish`. The batch path already passes CAS via `expectedSequenceNumber` in `folderResult.record`. However, the batch endpoint does not throw 409 — it returns `totalFailed`. These batch paths are a **separate conflict surface** that is NOT covered by the `updateFolderMetadataAndPublish` retry loop fix. Consider: do `addFileToFolder` / `addFilesToFolder` need their own retry? The CONTEXT.md does not explicitly call this out. Per the planner's discretion, these can be noted as a follow-on.

## Common Pitfalls

### Pitfall 1: seq-resolve race — trusting 409 body instead of re-resolving

**What goes wrong:** The 409 response body contains `currentSequenceNumber`, but `errors.ts:35` documents the custom axios instance does NOT attach response body to thrown errors. Using a stale hint leads to another 409 on next attempt.

**How to avoid:** Always call `resolveIpnsRecord` after every 409 for authoritative seq, ignoring any hint from the error object.

**Warning signs:** Second attempt immediately gets another 409.

### Pitfall 2: DB-seq vs record-seq divergence

**What goes wrong:** The server self-increments sequence in the DB (`ipns.service.ts:246`) instead of reading from the signed record. So the DB seq and the IPNS record seq can diverge. Re-resolving via the API returns the DB seq, which may be higher than what the record was signed with.

**How to avoid:** Always re-sign the IPNS record with the resolved DB seq. Do NOT try to correct or fix this divergence — it's a known protocol issue to be addressed separately.

**Warning signs:** `resolveIpnsRecord` returns a seq that doesn't match `createIpnsRecord`'s internal seq.

### Pitfall 3: Children keyed by name instead of id in merge

**What goes wrong:** Two writers can each add a child with the same name (valid if added concurrently before either sees the other). Keying by name would falsely merge them.

**How to avoid:** Key the merge by `child.id` (UUID, stable), not `child.name`.

### Pitfall 4: maxVersionsPerFile constant not honoring vault settings

**What goes wrong:** `file/index.ts:28` has `const MAX_VERSIONS_PER_FILE = 10` hardcoded. Phase 39 made this user-configurable, but `sdk-core`'s `updateFileMetadata` doesn't have access to the Zustand vault settings store.

**How to avoid:** Add `maxVersionsPerFile?: number` parameter to `updateFileMetadata`. Default to `10` when not provided (backward compat). Callers that have vault settings pass the user's value. Web callers read from `useVaultSettingsStore` before calling.

**Warning signs:** User's configured max is ignored in conflict-resolution version merges.

### Pitfall 5: baseChildren parameter backward compatibility

**What goes wrong:** All 18 call sites not yet updated will hit the union fallback (D-02) if `baseChildren` is omitted. This is intentional but must log a warning so devs notice during the sweep.

**How to avoid:** Make `baseChildren` optional in the param object. Add `console.warn('[sdk-core] updateFolderMetadataAndPublish: baseChildren not provided...')` inside the D-02 fallback path. Every site in the sweep MUST pass it.

## Runtime State Inventory

Not applicable — this is a code change to publish logic, not a rename/refactor/migration phase. No stored data, live service config, OS-registered state, secrets, or build artifacts need updating.

## Code Examples

### Existing Re-Fetch Building Blocks

```typescript
// Source: packages/sdk-core/src/folder/index.ts:46-60
export async function fetchAndDecryptMetadata(
  cid: string,
  folderKey: Uint8Array,
  ctx: SdkContext
): Promise<FolderMetadata> { ... }

// Source: packages/sdk-core/src/ipns/index.ts:182
export async function resolveIpnsRecord(
  ipnsName: string,
  ctx?: SdkContext
): Promise<{ cid: string; sequenceNumber: bigint; signatureVerified: boolean } | null> { ... }
```

### Existing CAS Plumbing (folder path already uses it)

```typescript
// Source: packages/sdk-core/src/folder/index.ts:207-217
await createAndPublishIpnsRecord({
  ipnsPrivateKey: params.ipnsPrivateKey,
  ipnsName: params.ipnsName,
  metadataCid: cid,
  sequenceNumber: newSeq,
  expectedSequenceNumber: currentSeq.toString(), // <-- CAS check
  ctx: params.ctx,
});
```

### Existing 409 Detection Pattern

```typescript
// Source: packages/sdk-core/src/folder/index.ts:220-223
const is409 =
  (err as Error & { status?: number }).status === 409 ||
  (err as Error & { response?: { status?: number } }).response?.status === 409;
if (!is409 || attempt > 0) throw err;
```

### Existing Rust Merge (reference for TS analog)

The Rust FUSE already has a union-based merge at `crates/fuse/src/lib.rs:285-324`. Its strategy is: iterate remote, prefer local version of each child (last-writer wins on content), then append any local-only additions. This is a simpler union than the three-way merge D-01 requires, but confirms the merge-on-409 pattern is established.

### Test Helper Pattern (sdk-core vitest mocking)

```typescript
// Source: packages/sdk-core/src/__tests__/ipns.test.ts:5-8
vi.mock('@cipherbox/api-client', () => ({
  ipnsControllerPublishRecord: vi.fn(),
  ipnsControllerPublishBatch: vi.fn(),
  ipnsControllerResolveRecord: vi.fn(),
}));
// Test framework: vitest (confirmed packages/sdk-core/vitest.config.ts)
// Test run command: pnpm --filter @cipherbox/sdk-core test
// Single file: pnpm --filter @cipherbox/sdk-core test src/__tests__/folder.test.ts
```

## Rust SDK Confirmation (Deferred Parity)

The Rust FUSE at `crates/fuse/src/lib.rs:326-439` (`spawn_metadata_publish`) already implements:

- `expectedSequenceNumber` in the publish request (line 366)
- On `Conflict` response: re-resolves seq, re-fetches remote metadata, calls `merge_folder_children`, re-uploads merged content, retries publish (lines 377-431)
- 1-retry only (2 total attempts) before returning a persistent-conflict error

**Conclusion:** The Rust SDK CAS-publish path (`spawn_metadata_publish`) has the same fundamental structure but does NOT have the same lost-update bug because it already re-fetches remote and merges before the retry. However, it only does 1 retry (vs D-04's 4), and `merge_folder_children` is a union merge (not three-way — no base), so it can still silently drop deletes. This is the deferred parity gap referenced in D-09.

**There is no blocking Rust work for Phase 44.** The Rust path handles folder writes for the FUSE desktop mount, not the same write paths as this phase.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
| --- | --- | --- | --- |
| 1-attempt seq-only retry (never re-fetches) | 4-attempt merge-and-republish loop | This phase | Eliminates lost updates |
| No CAS for file records | `expectedSequenceNumber` on file publishes | This phase | Closes TOCTOU window |
| Generic Error thrown on final 409 | Typed `ConflictError` with metadata | This phase | Callers can distinguish exhausted-conflict from other errors |

## Validation Architecture

### Test Framework

| Property | Value |
| --- | --- |
| Framework | vitest (confirmed in `packages/sdk-core/vitest.config.ts`) |
| Config file | `packages/sdk-core/vitest.config.ts` |
| Quick run command | `pnpm --filter @cipherbox/sdk-core test src/__tests__/folder.test.ts` |
| Full suite command | `pnpm --filter @cipherbox/sdk-core test` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
| --- | --- | --- | --- | --- |
| D-01 merge | Three-way merge permutations (local-add, remote-add, local-delete, remote-delete, modified-both, edit-beats-delete) | unit | `pnpm --filter @cipherbox/sdk-core test src/__tests__/folder-merge.test.ts` | Wave 0 |
| D-02 fallback | Union merge when baseChildren absent | unit | same file | Wave 0 |
| D-05 ConflictError | Thrown after 4 failed attempts | unit (mock publish) | `pnpm --filter @cipherbox/sdk-core test src/__tests__/folder.test.ts` | needs expansion |
| D-06 file CAS | File publish includes expectedSequenceNumber | unit (mock resolve+publish) | `pnpm --filter @cipherbox/sdk-core test src/__tests__/file.test.ts` | Wave 0 |
| D-07 loser-becomes-version | File conflict: loser content preserved in versions[] | unit | same file | Wave 0 |

### Wave 0 Gaps

- `packages/sdk-core/src/__tests__/folder-merge.test.ts` — covers D-01/D-02 merge permutation matrix
- `packages/sdk-core/src/__tests__/file.test.ts` — covers D-06/D-07 file CAS + conflict semantics
- `packages/sdk-core/src/errors.ts` — ConflictError class (new file)
- `packages/sdk-core/src/folder/merge.ts` — mergeChildren pure function (new file)

## Security Domain

| ASVS Category | Applies | Standard Control |
| --- | --- | --- |
| V2 Authentication | no | — |
| V3 Session Management | no | — |
| V4 Access Control | no | — |
| V5 Input Validation | yes | Merge function must handle malformed/missing `modifiedAt` (default 0) |
| V6 Cryptography | yes | Re-encrypt merged metadata with AES-256-GCM via `encryptFolderMetadata` — never pass plaintext to IPFS |

### Security Notes

- The merge operates on **decrypted** metadata in-memory — re-encryption must happen before upload (D-03).
- `ConflictError` must NOT include plaintext child data in its message or properties — `ipnsName` and `lastRemoteSeq` are safe metadata.
- Per `ipns-write-auth-is-cryptographic.md`: server self-increments seq and does not verify IPNS signatures. The CAS check (`expectedSequenceNumber`) is the only server-side protection against the lost-update. This phase relies on it being enforced correctly.

## Project Constraints (from CLAUDE.md)

- Use TypeScript for all code; string literals over enums.
- Use `Uint8Array` for binary data.
- Use camelCase for API fields, snake_case for DB columns.
- Include proper error handling for crypto operations.
- Clear sensitive data from memory after use (`fill(0)` on private keys).
- **Never** send unencrypted keys to server.
- **Always** use AES-256-GCM for content encryption.
- Run `pnpm api:generate` after any API endpoint changes (this phase does not add endpoints, so not required unless a DTO is added).
- Commit the regenerated API client files if any API changes are made.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
| --- | --- | --- | --- |
| A1 | Retry backoff values (100ms base, cap 1500ms) | Architecture Patterns / Pattern 3 | Suboptimal backoff: adjust values, no data-loss risk |
| A2 | `createAndPublishIpnsRecord` is preferred over `batchPublishIpnsRecords` for file CAS because batch doesn't throw 409 | Architecture Patterns / Pattern 4 | May need API investigation; if batch does throw 409 per record, can use batch |
| A3 | `addFileToFolder`/`addFilesToFolder` batch conflict path is out of scope | Caller Sweep Map | If these also get 409 conflicts in practice, they need a separate retry |

## Open Questions

1. **Does `batchPublishIpnsRecords` propagate per-record 409 errors to the caller, or only `totalFailed`?**
   - What we know: `batchPublishIpnsRecords` returns `{ totalFailed, totalSucceeded }` on partial success.
   - What's unclear: Whether the server returns a per-record conflict signal in the batch response body that the TS client currently ignores.
   - Recommendation: Check `apps/api/src/ipns/ipns.service.ts` batch endpoint response shape. If it embeds per-record conflict info, the batch path can be extended. Otherwise use `createAndPublishIpnsRecord` for file CAS.

2. **Is `maxVersionsPerFile` needed as a parameter to `updateFileMetadata` in sdk-core, or is the hardcoded `MAX_VERSIONS_PER_FILE = 10` acceptable for the conflict path?**
   - What we know: Web callers read from `useVaultSettingsStore`; sdk-core has no access to Zustand.
   - What's unclear: Whether conflict-resolution version merges must respect the user's custom limit.
   - Recommendation: Add optional `maxVersionsPerFile` param, default 10. Web callers pass `useVaultSettingsStore.getState().settings.maxVersionsPerFile`.

## Sources

### Primary (HIGH confidence)

- `packages/sdk-core/src/folder/index.ts` — exact lines 174-238 of the buggy loop; all reusable helpers
- `packages/sdk-core/src/file/index.ts` — exact lines 181-260 of the TOCTOU path
- `packages/sdk-core/src/ipns/index.ts` — `createAndPublishIpnsRecord`, `batchPublishIpnsRecords`, `resolveIpnsRecord`
- `packages/sdk/src/error.ts` — `isConflictError`, `withConflictRetry` (single retry only)
- `packages/sdk/src/client.ts` — all 8 `updateFolderMetadataAndPublish` call sites
- `packages/sdk/src/bin/index.ts` — 2 call sites
- `packages/sdk/src/share/shared-write.ts` — 4 call sites
- `crates/fuse/src/lib.rs:285-439` — Rust merge + retry reference implementation
- `packages/core/src/folder/types.ts` — `FolderChild`, `FolderEntry` canonical shapes
- `packages/core/src/file/types.ts` — `FileMetadata`, `VersionEntry`, `FilePointer` canonical shapes
- `apps/web/src/lib/errors.ts` — documents that 409 body is not attached to thrown error
- `apps/web/src/hooks/folder-helpers.ts` — `withConflictRetry` web wrapper → sync-banner UI
- `apps/web/src/hooks/useFileOperations.ts` — web-side caller sweep
- `.planning/notes/ipns-write-auth-is-cryptographic.md` — server CAS realities

### Secondary (MEDIUM confidence)

- `.planning/phases/44-ipns-conflict-handling/44-CONTEXT.md` — locked decisions
- `.planning/todos/pending/2026-06-11-ipns-409-retry-lost-update.md` — original bug report

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — all packages are workspace-internal, no external deps
- Architecture: HIGH — code paths read directly from source
- Pitfalls: HIGH — based on confirmed code patterns (errors.ts body-not-attached, seq self-increment)
- Caller sweep: HIGH — exhaustive grep of all call sites verified

**Research date:** 2026-06-13
**Valid until:** N/A (code-internal, no external library versions)
