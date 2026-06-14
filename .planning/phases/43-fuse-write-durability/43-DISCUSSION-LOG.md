# Phase 43: FUSE write durability - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-12
**Phase:** 43-fuse-write-durability
**Areas discussed:** Durability model & journal, Crash recovery & replay, Failure surfacing, mkdir scope & platforms

---

## Durability model & journal

| Option                                  | Description                                                    | Selected |
| --------------------------------------- | -------------------------------------------------------------- | -------- |
| Persist-backed WriteQueue in crates/sdk | Extend queue.rs (todo's named fix point) with disk persistence | ✓        |
| New journal module in crates/fuse       | FUSE-local op-log; duplicates queue logic                      |          |

| Option                 | Description                                        | Selected |
| ---------------------- | -------------------------------------------------- | -------- |
| Uploads + mkdir op-log | One durable replay path; closes mkdir crash window | ✓        |
| Uploads only           | Smaller; mkdir keeps its crash window              |          |

**User's choice:** Persist-backed WriteQueue, full op-log coverage

**Notes:** Locked without asking (constraints from todo + crypto rules): journal fsync before ack (single-threaded callbacks), ciphertext + wrapped keys only, stable IDs not inode numbers, plaintext temp zeroized after journaling.

---

## Crash recovery & replay

| Option                        | Description                                               | Selected |
| ----------------------------- | --------------------------------------------------------- | -------- |
| Upsert into fresh remote      | Fetch current parent metadata, merge journaled child, CAS | ✓        |
| Re-publish journaled snapshot | Blind republish; stomps multi-device changes              |          |

| Option                      | Description                                           | Selected |
| --------------------------- | ----------------------------------------------------- | -------- |
| Backoff then park + surface | Exponential backoff → failed state on disk, retryable | ✓        |
| Drop after max retries      | Silent data loss returns                              |          |
| Infinite retry              | Poisoned queue head wedges everything                 |          |

**User's choice:** Upsert into fresh remote; backoff then park + surface

---

## Failure surfacing

| Option                        | Description                                            | Selected |
| ----------------------------- | ------------------------------------------------------ | -------- |
| Notify on park + status count | OS notification on park; counts via SyncStatus channel | ✓        |
| Notification only             | No pending-count exposure                              |          |
| Full pending-uploads UI       | List + retry/export actions in desktop window          |          |

**User's choice:** Notify on park + status count for this phase; user explicitly asked that the full pending-uploads UI be noted as a future improvement (captured in Deferred Ideas).

---

## mkdir scope & platforms

| Option                         | Description                  | Selected |
| ------------------------------ | ---------------------------- | -------- |
| macOS + Windows together       | Both in phase, single effort |          |
| macOS first, Windows follow-up | Phase 32→33 precedent        |          |

**User's choice:** Free-text — ALL THREE platforms (macOS, Linux, Windows) handled in this phase, structured as SEPARATE PLANS. macOS + Linux share the fuser codepath; Windows is the WinFsp mirror.

**Notes:** Locked without asking: live-session mkdir conflict signals the FS thread to dirty-mark the parent (prompt debounced retry); journaled MkdirPublish entry clears only on confirmed parent publish.

---

## Claude's Discretion

- Journal on-disk format, location, rotation/compaction
- Backoff parameters and park threshold
- Notification copy; SyncStatus field shape for counts
- Grep-verify the macOS mkdir conflict line number before fixing

## Deferred Ideas

- Full pending-uploads management UI (user-requested future improvement)
