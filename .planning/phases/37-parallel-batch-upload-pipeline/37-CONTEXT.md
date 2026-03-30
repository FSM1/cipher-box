# Phase 37: Parallel Batch Upload Pipeline - Context

**Gathered:** 2026-03-30
**Status:** Ready for planning

<domain>
## Phase Boundary

Replace sequential per-file upload loop with parallel encrypt+pin pipeline and single folder metadata update. Currently, `useDropUpload` loops through files sequentially — each file calls `client.uploadFile()` which does encrypt → IPFS pin → add FilePointer → publish folder IPNS. That's N IPNS publishes for N files. This phase reduces that to 1 publish per batch and enables concurrent file processing via Web Workers.

Scope: TypeScript SDK (`@cipherbox/sdk`, `@cipherbox/sdk-core`) and web app (`apps/web`). No Rust SDK or desktop FUSE changes.

</domain>

<decisions>
## Implementation Decisions

### Concurrency Model

- **D-01:** Fixed concurrency pool of 3 concurrent encrypt+pin operations. Pool size is a constant — easy to tune later.
- **D-02:** Pipeline-style processing: encrypt file → pin to IPFS → free ciphertext → next slot. Do NOT buffer all encrypted files before pinning (avoids 3x 100MB memory spikes).

### SDK API Shape

- **D-03:** New `uploadFiles()` batch method on `CipherBoxClient` (TypeScript SDK). Accepts multiple files, runs encrypt+pin in parallel internally, collects all FilePointers, then does ONE folder metadata update + ONE IPNS publish.
- **D-04:** Existing `uploadFile()` remains unchanged for single-file uploads and retry of failed files.
- **D-05:** `uploadFiles()` must re-read folder metadata just before the final publish to mitigate the stale-children race (another device may have published new children during the batch window).
- **D-06:** Progress reporting via per-file callbacks — the batch method needs to surface per-file progress to the Zustand store for inline progress rows.

### Web Worker Encryption

- **D-07:** Offload file encryption to Web Workers for true parallelism. Main thread stays responsive for progress bars and drag-drop interactions.
- **D-08:** This folds in the existing todo "Offload large file encryption to Web Worker" — that todo is now part of this phase's scope.

### Error & Partial Failure

- **D-09:** Publish successes, surface errors. If 3 of 5 files encrypt+pin successfully, publish those 3 to folder metadata. Failed files show inline error rows with retry buttons (existing Phase 36 error UX).
- **D-10:** One publish per batch — wait for all concurrency slots to drain (success or fail) across the entire batch, then publish all successes in a single folder metadata update.
- **D-11:** Failed file retry uses existing `uploadFile()` single-file method (normal single-file upload into the already-published folder).

### Desktop Scope

- **D-12:** No Rust SDK or FUSE changes in this phase. Desktop uploads arrive one-at-a-time through filesystem `release()` callbacks — the FUSE layer has no batch context. A separate phase would be needed for FUSE write-coalescing.

### Claude's Discretion

- Web Worker communication protocol (postMessage structure, transferable buffers)
- Whether `uploadFiles()` lives on `CipherBoxClient` directly or as a separate sdk-core function composed by the client
- Exact error types and retry semantics within the batch pipeline
- Whether to add a new sdk-core `encryptAndPinFile()` primitive that `uploadFiles()` composes internally

### Folded Todos

- "Offload large file encryption to Web Worker" (from `2026-02-07-web-worker-large-file-encryption.md`) — folded into D-07/D-08

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Upload Pipeline (current implementation)

- `apps/web/src/hooks/useDropUpload.ts` — Current sequential upload loop (lines 113-133), duplicate handling, SDK integration
- `apps/web/src/services/upload.service.ts` — Single-file encrypt+pin service (to be replaced by Worker-based pipeline)
- `apps/web/src/services/file-crypto.service.ts` — Encryption logic that will move into Web Worker

### Upload State & UI (Phase 36 output)

- `apps/web/src/stores/upload.store.ts` — Per-file Zustand store with status/progress/cancel tracking
- `apps/web/src/components/file-browser/UploadListItem.tsx` — Inline progress row component (Phase 36)

### SDK Layer (batch method target)

- `packages/sdk/src/client.ts` — `uploadFile()` at line 658; new `uploadFiles()` method goes here
- `packages/sdk-core/src/` — Core upload/IPNS functions composed by the client

### IPFS Upload

- `apps/web/src/lib/api/ipfs.ts` — `addToIpfs()` with axios progress events

### Architecture

- `00-Preliminary-R&D/Documentation/TECHNICAL_ARCHITECTURE.md` — Encryption specs, key hierarchy
- `.planning/codebase/ARCHITECTURE.md` — SDK layer stack, Zustand store inventory

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- `useUploadStore` (Zustand): Already tracks per-file status, progress, cancel sources. Batch pipeline plugs directly into existing `addFile()`, `updateFileProgress()`, `setFileStatus()` actions.
- `uploadFile()` on SDK client: Template for the new `uploadFiles()` — same encrypt+pin+register flow but batched.
- `sdkCore.batchPublishIpnsRecords()`: Already exists for batching file IPNS records — can be reused.
- `sdkCore.updateFolderMetadataAndPublish()`: Existing folder publish function — called once at end of batch.
- `withRetry()` in `upload.service.ts`: Exponential backoff wrapper, reusable for per-file retry within the pool.

### Established Patterns

- SDK operations serialized via `withOperation()` — `uploadFiles()` will be a single operation containing internal parallelism.
- `Promise.allSettled()` used in `uploadFile()` for concurrent file IPNS + folder publish — same pattern applies to batch encrypt+pin.
- Phase 36 established inline progress rows — this phase only changes the upload orchestration, not the UI rendering.

### Integration Points

- `useDropUpload.handleFileDrop()` — Entry point that switches from sequential loop to calling `client.uploadFiles()`.
- `CipherBoxClient.folderTree` — Internal state updated atomically after batch publish.
- `ensureFolderRegistered()` — Must be called before batch upload (already done in handleFileDrop).

</code_context>

<specifics>
## Specific Ideas

- The concurrency pool size (3) should be a named constant, easy to change when adaptive sizing is implemented later.
- Re-read folder metadata before final publish to handle stale-children race — this is a new pattern not in the current `uploadFile()`.
- Web Workers should handle encryption only, not IPFS upload (upload needs auth tokens and axios which are main-thread concerns).

</specifics>

<deferred>
## Deferred Ideas

- **Adaptive concurrency based on file size** — More concurrent slots for small files, fewer for large. Implement when fixed pool of 3 proves insufficient.
- **FUSE write-coalescing for desktop** — Buffer all `release()` calls within a time window, then batch-publish folder metadata once. Requires FUSE architecture changes.
- **Accumulated retry batching** — If many files fail and are retried, batch the retries into a single folder publish instead of N individual publishes. Implement if failure rates warrant it.

### Reviewed Todos (not folded)

- "Research CRDT-based IPNS inbox for serverless share discovery" — unrelated to upload pipeline (score: 0.6, matched on IPNS keyword only)
- "Investigate removal of mock-ipns-routing layer" — API/test infrastructure concern, not upload pipeline
- "Check remaining GitHub Actions for Node 24 updates" — CI concern, not upload pipeline

</deferred>

---

_Phase: 37-parallel-batch-upload-pipeline_
_Context gathered: 2026-03-30_
