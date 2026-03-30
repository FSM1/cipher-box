# Phase 37: Parallel Batch Upload Pipeline - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-03-30
**Phase:** 37-parallel-batch-upload-pipeline
**Areas discussed:** Concurrency model, SDK API shape, Web Worker encryption, Error & partial failure, Desktop SDK feature equivalence

---

## Concurrency Model

| Option                      | Description                                                              | Selected |
| --------------------------- | ------------------------------------------------------------------------ | -------- |
| Fixed pool of 3             | 3 concurrent encrypt+pin operations. Balances throughput vs memory.      | ✓        |
| Fixed pool of 5             | More aggressive, 5x 100MB = 500MB memory pressure risk.                  |          |
| Adaptive based on file size | More slots for small files, fewer for large. Adds scheduling complexity. |          |

**User's choice:** Fixed pool of 3
**Notes:** User confirmed this is easy to change later, wants adaptive sizing noted as deferred idea for future implementation.

---

## SDK API Shape

| Option                                | Description                                                                                            | Selected |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------ | -------- |
| New uploadFiles() batch method        | Batch method on SDK, handles encrypt+pin in parallel, ONE folder publish. Existing uploadFile() stays. | ✓        |
| Decompose into primitives             | Expose encryptAndPin() + batchRegisterFiles(). Consumers orchestrate.                                  |          |
| Keep uploadFile(), batch at web layer | No SDK changes, web app calls uploadFile() concurrently.                                               |          |

**User's choice:** New uploadFiles() batch method
**Notes:** User requested detailed pros/cons analysis before deciding. Key insight: Option C is fundamentally broken (withOperation serializes, defeating parallelism; concurrent calls race on folder.children). Option B's foot guns (orphaned CIDs, SDK state divergence, sequence number conflicts) stem from splitting an operation that needs to be atomic. User agreed SDK is the right place for this complexity — "this sort of complexity is exactly the purpose of creating the SDK."

---

## Web Worker Encryption

| Option                | Description                                                                                                            | Selected |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------- | -------- |
| Yes, fold it in       | Parallel encryption on main thread blocks UI. Workers unlock true parallelism. Natural fit while redesigning pipeline. | ✓        |
| No, keep separate     | Ship parallel pipeline first, add Workers later. Smaller scope but touches pipeline twice.                             |          |
| Optional stretch goal | Design for Workers but don't implement. Pluggable encrypt function.                                                    |          |

**User's choice:** Fold it in
**Notes:** No additional discussion needed.

---

## Error & Partial Failure

| Option                            | Description                                                                         | Selected |
| --------------------------------- | ----------------------------------------------------------------------------------- | -------- |
| Publish successes, surface errors | If 3 of 5 succeed, publish those 3. Failed files show inline error rows with retry. | ✓        |
| All-or-nothing                    | Any failure blocks all. Unpin successful CIDs, show batch error.                    |          |
| Hold and retry, then publish      | Auto-retry failed files before publishing. Maximizes success count.                 |          |

**User's choice:** Publish successes, surface errors
**Notes:** Clarified that publish happens once after the ENTIRE batch drains (all concurrency slots finished across all files), not per pool cycle. Failed file retry uses existing single-file uploadFile() method. Accumulated retry batching noted as deferred idea.

---

## Desktop SDK Feature Equivalence

**User's question:** Would the desktop app also benefit from a batch upload method in the Rust SDK?

**Analysis:** Desktop uploads arrive one-at-a-time through FUSE `release()` callbacks. When copying 10 files, macOS/Windows calls write→release per file individually. The FUSE layer has no batch context — it doesn't know 10 files are coming. A Rust `upload_files()` would exist for API parity but the FUSE layer can't naturally use it without a write-coalescing layer.

**Decision:** Phase scoped to TypeScript SDK + web app only. FUSE write-coalescing noted as deferred idea.

---

## Claude's Discretion

- Web Worker communication protocol
- Internal SDK composition of uploadFiles()
- Error types and retry semantics
- Whether to add encryptAndPinFile() as internal sdk-core primitive

## Deferred Ideas

- Adaptive concurrency based on file size
- FUSE write-coalescing for desktop batch publish optimization
- Accumulated retry batching for failed files
