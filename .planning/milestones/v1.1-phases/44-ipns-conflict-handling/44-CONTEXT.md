# Phase 44: IPNS conflict handling - Context

**Gathered:** 2026-06-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Stop lost updates on concurrent IPNS writes in `packages/sdk-core` (TypeScript): on 409, re-fetch remote folder metadata and three-way merge before republishing, and extend CAS coverage to file records. Sweep TS callers (web hooks, `packages/sdk`, shared-write) to pass base snapshots and handle conflict errors. **Full CRDT model is explicitly OUT of scope** — deferred by ROADMAP to the CRDT-inbox research todo. Rust FUSE merge parity is also deferred (Phase 43's journal replay covers the Rust crash path).

**The two failure modes being fixed:**

1. `updateFolderMetadataAndPublish` (`packages/sdk-core/src/folder/index.ts:204-233`): on 409 it re-resolves only the sequence number and republishes the SAME stale CID with a bumped seq — defeating the server's CAS; a second device's or write-share recipient's changes are silently erased. One retry, then throw.
2. `updateFileMetadata` (`packages/sdk-core/src/file/index.ts:225-231`): no CAS at all — resolve-then-`seq+1`-publish with a TOCTOU window; concurrent file replaces clobber each other's `versions[]` and content pointers.

**Architectural constraint (locked):** conflict resolution MUST be client-side — the zero-knowledge server cannot read or merge encrypted metadata, and IPNS write authorization is key possession, not server policy (see `ipns-write-auth-is-cryptographic.md`). The server self-increments sequence numbers (known DB-seq vs record-seq divergence, `ipns.service.ts:543`) — the CAS work must tolerate this, not fix it (that's the protocol-hardening thread).

</domain>

<decisions>
## Implementation Decisions

### Folder merge on 409

- **D-01:** Three-way merge. `updateFolderMetadataAndPublish` gains an optional `baseChildren` param (backward compatible) — the children snapshot the local edit was derived from. On 409: re-fetch + decrypt the remote folder metadata, then diff base/local/remote per entry:
  - in local, not in base → local add → keep
  - in base, not in local → local delete → drop (but **edit-beats-delete**: if remote modified the entry after base, keep the remote version)
  - in remote, not in base → remote add → keep
  - modified in both → per-entry last-write-wins by `modifiedAt`
- **D-02:** When no `baseChildren` is passed: degrade to children union (never loses adds; deletes may resurrect) + log a warning. This is the migration path, not the end state — D-08 sweeps callers to pass base.
- **D-03:** After merge, re-encrypt and re-upload the merged metadata (new CID) before republishing — never bump the sequence on stale state.

### Retry budget

- **D-04:** 4 attempts total with exponential backoff + jitter (concurrent write-share writers must not stampede in lockstep). Each attempt = re-resolve seq + re-fetch remote + merge + re-encrypt + re-upload + CAS publish.
- **D-05:** After exhaustion, throw a typed `ConflictError` (carrying ipnsName, attempts, last remote seq) that callers route into the existing v1.0 optimistic-concurrency conflict-detection UX. No silent failure, no silent overwrite.

### File record CAS + merge

- **D-06:** Extend CAS to file IPNS publishes: pass `expectedSequenceNumber` wherever file records publish (the `updateFileMetadata` → `replaceFileInFolder` path and its callers).
- **D-07:** File conflict semantics = latest-wins + loser-becomes-version: on 409, re-fetch remote file metadata; the write with newest `modifiedAt` is the current content pointer; the losing write's content entry is preserved in `versions[]` (no user data destroyed). `versions[]` merges by union, deduped by `cid`, sorted by timestamp, capped per the Phase 39 user-configurable `maxVersionsPerFile` vault setting; overflow becomes `prunedCids` whose unpins flow through the Phase 42-fixed guarded endpoint.

### Caller adoption

- **D-08:** Sweep TS callers in-phase: web hooks (`useFileOperations`, folder ops, bin/share flows), `packages/sdk` client methods, and `packages/sdk/src/share/shared-write.ts` updated to (a) pass `baseChildren` snapshots (the folder-store children the edit was computed from) and (b) handle `ConflictError` via existing conflict surfaces. Write shares are the headline multi-writer case — `shared-write.ts` must not remain on union fallback.
- **D-09:** Rust FUSE 409-merge parity is explicitly deferred (see Deferred Ideas). Phase 43's journal replay already does upsert-into-fresh-remote for the crash path; the live-session debounced publish rebuilds from the inode tree (op-replay-like) and keeps its current behavior this phase.

### Claude's Discretion

- `ConflictError` exact shape/fields and how existing conflict UI consumes it.
- Backoff base/cap values and jitter distribution.
- Merge unit-test matrix structure (base/local/remote permutations) and whether to add shared test vectors.
- Where the three-way merge helper lives in sdk-core (pure function, unit-testable).

### Folded Todos

- `2026-06-11-ipns-409-retry-lost-update.md` — both findings (folder stale-CID republish, file TOCTOU) are this phase's requirements; fixed by D-01..D-08.

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Source requirements

- `.planning/todos/pending/2026-06-11-ipns-409-retry-lost-update.md` — both failure modes with line references and constraints

### Architecture context (user-flagged)

- `.planning/notes/ipns-write-auth-is-cryptographic.md` — why merge is client-side-only; server publish-path realities (row routing, self-incremented seq) the CAS work must tolerate
- `.planning/seeds/blind-share-social-graph.md` — related protocol-hardening direction; do not implement, but don't foreclose it
- `.planning/todos/pending/2026-02-22-crdt-ipns-inbox-sharing.md` — the deferred CRDT research this phase explicitly does NOT do (reference only, not folded)

### Project rules that bind this phase

- `docs/METADATA_SCHEMAS.md` — FolderMetadata v2 / FileMetadata / VersionEntry shapes the merge operates on
- `docs/METADATA_EVOLUTION_PROTOCOL.md` — if any metadata field additions prove necessary, they follow this protocol (current design needs none)
- `docs/FILESYSTEM_SPECIFICATION.md` — IPNS publish/sequence semantics

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- `resolveIpnsRecord` + `fetchAndDecryptMetadata` (sdk-core) — the re-fetch half of merge-on-409 already exists (handles v1 JSON + v2 binary blobs transparently)
- `createAndPublishIpnsRecord` with `expectedSequenceNumber` (folder path) — the CAS plumbing to extend to file records
- Phase 39 vault settings (`maxVersionsPerFile`, version cooldown) — version-cap source for D-07
- Existing conflict-detection UX from v1.0 (optimistic concurrency feature) — `ConflictError` destination
- `withPerf` wrappers — keep new merge path instrumented like existing ops

### Established Patterns

- OCC via `expectedSequenceNumber` → server 409 with `currentSequenceNumber` (Phase 27 writable-shares relies on it)
- Bin/share ops take explicit context objects; share module accepts callback functions (transport-decoupled) — merge helper should follow the pure-function style
- `Uint8Array` for binary, zeroize keys after use

### Integration Points

- `packages/sdk-core/src/folder/index.ts:174-238` — merge loop lands here
- `packages/sdk-core/src/file/index.ts:160-260` — file CAS + merge lands here
- `packages/sdk/src/share/shared-write.ts:450` — multi-writer caller; also currently drops `prunedCids` (pre-existing leak noted in Phase 42's deferred ideas — do not let the sweep regress it further)
- Web folder store (`useFolderStore`) — source of `baseChildren` snapshots and `sequenceNumber` per folder

</code_context>

<specifics>
## Specific Ideas

- Merge must be a pure, separately unit-tested function: `(base, local, remote) → merged` over `FolderChild[]` — the publish loop wraps it. Permutation tests over add/delete/edit combinations are the heart of this phase's verification.
- The retry loop's re-fetch must use the 409 response's `currentSequenceNumber` as a hint but re-resolve authoritatively — the server's DB-seq vs record-seq divergence means trusting either blindly is wrong.

</specifics>

<deferred>
## Deferred Ideas

- **Rust FUSE 409-merge parity** — bring the three-way merge to `crates/fuse`'s debounced publish path; today it rebuilds from the inode tree which approximates op-replay but can still stomp remote-only changes between refreshes.
- **Full CRDT model** — explicitly deferred by ROADMAP to `2026-02-22-crdt-ipns-inbox-sharing.md` research.

### Reviewed Todos (not folded)

- `2026-02-22-crdt-ipns-inbox-sharing.md` — referenced as the deferral target, intentionally not folded.

</deferred>

---

_Phase: 44-ipns-conflict-handling_
_Context gathered: 2026-06-12_
