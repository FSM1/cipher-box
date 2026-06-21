# Phase 52: Desktop FUSE Durability & At-Rest Safety - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-19
**Phase:** 52-desktop-fuse-durability-at-rest-safety
**Areas discussed:** WR-06 write path, Journal GC/retention, WR-07 replay, IN-03 at-rest names

---

## WR-06 — Large-file journal write path

| Option                       | Description                                                                                                   | Selected |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------ | -------- |
| Sidecar + off-thread         | Sidecar `<id>.bin` + heavy write/fsync off the shared callback thread; originating release() still awaits durability; + size cap. | ✓        |
| Sidecar only (on-thread)     | Move ciphertext out of JSON only. Fixes OOM/alloc, but large write+F_FULLFSYNC still blocks the FS.            |          |
| Sidecar + off-thread + cap   | Above + a hard per-file size ceiling routing oversized files to a separate path / fail-fast.                   |          |

**User's choice:** Sidecar + off-thread (D-01)
**Notes:** Must preserve the Phase-43 durable-ack contract — release() awaits its own entry's fsync even though the heavy write is off the shared thread.

---

## Journal GC / retention

| Option                        | Description                                                                                          | Selected |
| ----------------------------- | --------------------------------------------------------------------------------------------------- | -------- |
| GC + logout + cross-vault purge | Age+size GC of parked Failed entries, purge current vault on logout, purge vault entries on account switch/delete. | ✓        |
| Minimal (logout + age GC)     | Purge-on-logout + age-based GC only. No size budget, no proactive cross-vault sweep.                  |          |
| Add size-ceiling backpressure | Recommended model + hard total-journal size ceiling that backpressures new journaling.                |          |

**User's choice:** GC + logout + cross-vault purge (D-02)
**Notes:** Closes the cross-vault leak (shared journal dir was only filtered, never cleaned). Planner sets concrete default caps.

---

## WR-07 — Replay durability

| Option                    | Description                                                                                     | Selected |
| ------------------------- | ---------------------------------------------------------------------------------------------- | -------- |
| Timeout + concurrent w/ mount | Per-entry tokio timeout AND replay runs concurrently with mount (mount never waits).            | ✓        |
| Timeout only              | Per-entry timeout but replay stays before mount (mount waits, bounded by timeout × entries).     |          |
| Concurrent only           | Replay concurrent with mount but no per-entry timeout (mount instant, hung entry spins forever). |          |

**User's choice:** Timeout + concurrent with mount (D-03)
**Notes:** Mirror the existing NETWORK_TIMEOUT discipline used elsewhere in the desktop stack.

---

## IN-03 — At-rest journaled names

| Option               | Description                                                                                       | Selected |
| -------------------- | ------------------------------------------------------------------------------------------------- | -------- |
| Encrypt journaled names | Encrypt the name in the entry (key available at write/replay time).                              |          |
| Omit name if not needed | Drop the plaintext name entirely if replay can reconstruct it from FileMetadata/path; encrypt as fallback if required. | ✓        |
| Document and defer   | Accept the local-only 0600 risk for now; comment and revisit.                                      |          |

**User's choice:** Omit name if not needed (D-04)
**Notes:** Conditional — planning first establishes whether replay needs the plaintext name; prefer omission, encryption is the fallback. Either way no plaintext item name persists at rest.

---

## Claude's Discretion

- Phase sequencing (WR-06 → WR-07 → IN-03 → IN-04/IN-05) suggested in CONTEXT.md; planner may refine.
- Concrete GC default caps (age window, size budget) and the WR-07 timeout multiplier left to the planner.
- IN-04 (extend sanitize_error scrub list) and IN-05 (log::warn! on swallowed journal.remove) were pre-locked by the todo — included by default, not discussed as forks.

## Deferred Ideas

None — discussion stayed within phase scope.
