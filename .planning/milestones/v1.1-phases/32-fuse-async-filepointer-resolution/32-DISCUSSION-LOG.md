# Phase 32: FUSE Async FilePointer Resolution - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-03-28
**Phase:** 32-FUSE Async FilePointer Resolution
**Areas discussed:** Resolution strategy, Stale data handling, Resolution priority, Error resilience, Windows parity, Deduplication guard, Open-while-resolving

---

## Resolution Strategy

| Option                 | Description                                                                                                             | Selected |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------- | -------- |
| Channel-based async    | Mirror existing content prefetch pattern: spawn tokio tasks, send results via mpsc channel, drain in next FUSE callback | ✓        |
| Batch resolve endpoint | New API endpoint that resolves multiple IPNS names in one HTTP call                                                     |          |
| You decide             | Let Claude pick during planning                                                                                         |          |

**User's choice:** Channel-based async
**Notes:** Recommended because the pattern is already proven in the codebase (content_rx/prefetching).

---

## Stale Data Handling

| Option                        | Description                                                        | Selected |
| ----------------------------- | ------------------------------------------------------------------ | -------- |
| Zero-size placeholder         | File appears in listing with 0 bytes. Opening triggers resolution. | ✓        |
| Hide until resolved           | File doesn't appear in readdir until IPNS resolves.                |          |
| Show cached size if available | Use previous metadata if cached, zero-size otherwise.              |          |

**User's choice:** Zero-size placeholder
**Notes:** Finder shows the file name immediately — no confusion about missing files.

---

## Resolution Priority

| Option                          | Description                                                                                       | Selected |
| ------------------------------- | ------------------------------------------------------------------------------------------------- | -------- |
| Eager on refresh                | Spawn resolution for all unresolved FilePointers as soon as drain_refresh_completions finds them. | ✓        |
| Lazy on first access            | Only resolve when open()/read() is called on an unresolved file.                                  |          |
| Hybrid: eager parent, lazy deep | Eagerly resolve files in currently-browsed folder, lazily resolve deeper folders.                 |          |

**User's choice:** Eager on refresh
**Notes:** Files resolve in background within seconds of metadata arriving.

---

## Error Resilience

| Option                               | Description                                                                     | Selected |
| ------------------------------------ | ------------------------------------------------------------------------------- | -------- |
| Retry with backoff, keep placeholder | Retry 3 times with exponential backoff. File stays as zero-size placeholder.    | ✓        |
| Mark failed, skip on future drains   | After N failures, mark inode as permanently unresolved until next full refresh. |          |
| You decide                           | Let Claude design the error strategy during planning.                           |          |

**User's choice:** Retry with backoff, keep placeholder
**Notes:** Finder remains stable — user sees the file but can't open it until resolved.

---

## Windows Parity

| Option                    | Description                                             | Selected |
| ------------------------- | ------------------------------------------------------- | -------- |
| Both platforms            | Fix both macOS FUSE-T and Windows WinFsp in this phase. |          |
| macOS only, Windows later | Focus on FUSE-T/SMB. Windows as follow-up phase.        | ✓        |
| You decide                | Let Claude assess Windows severity during planning.     |          |

**User's choice:** macOS only, Windows later
**Notes:** Windows changes require a Windows machine for testing. The follow-up Windows phase can execute in parallel with macOS since changes are in platform-specific code paths.

---

## Deduplication Guard

| Option        | Description                                                                                                | Selected |
| ------------- | ---------------------------------------------------------------------------------------------------------- | -------- |
| HashSet guard | Add `resolving_file_pointers: HashSet<u64>` mirroring the existing `prefetching: HashSet<String>` pattern. | ✓        |
| You decide    | Let Claude pick the dedup mechanism.                                                                       |          |

**User's choice:** HashSet guard
**Notes:** Consistent with established codebase pattern.

---

## Open-While-Resolving

| Option                           | Description                                                                     | Selected |
| -------------------------------- | ------------------------------------------------------------------------------- | -------- |
| Block with short timeout         | Wait up to 5s for in-flight resolution. Return EIO on timeout. Finder retries.  | ✓        |
| Return EAGAIN immediately        | Signal "try again later". Fast but some apps don't handle EAGAIN well.          |          |
| Trigger sync resolve as fallback | Fall back to blocking resolve for just that one file if async hasn't completed. |          |

**User's choice:** Block with short timeout
**Notes:** 5s timeout balances responsiveness with giving async resolution time to complete.

---

## Claude's Discretion

- Exact exponential backoff parameters
- Channel buffer sizes
- Whether to reuse content_rx or create separate filepointer_rx channel
- Internal poll loop implementation in open/read

## Deferred Ideas

- Windows WinFsp async FilePointer resolution — follow-up phase
- Batch IPNS resolve API endpoint — future optimization
