# Phase 44: IPNS conflict handling - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-12
**Phase:** 44-ipns-conflict-handling
**Areas discussed:** Folder merge strategy, Retry budget, File CAS + merge, Caller adoption scope

---

## Folder merge strategy

| Option                  | Description                                                                   | Selected |
| ----------------------- | ----------------------------------------------------------------------------- | -------- |
| Three-way merge         | Optional baseChildren param; base/local/remote diff with edit-beats-delete    | ✓        |
| Op-replay transform API | Signature becomes transform(remoteChildren) callback; every call site reworks |          |
| Union-only              | Never loses adds; concurrent deletes resurrect                                |          |

**User's choice:** Three-way merge

**Notes:** The delete-resurrection trap drove this: single encrypted blob can't distinguish "I deleted X" from "remote added X" without either op intent or the base snapshot. Callers already hold the base (folder store children + sequenceNumber), so three-way is achievable backward-compatibly.

---

## Retry budget

| Option                                  | Description                                         | Selected |
| --------------------------------------- | --------------------------------------------------- | -------- |
| 4 attempts, backoff+jitter, typed error | ConflictError into existing conflict-detection UX   | ✓        |
| Keep 1 retry, just add merge            | Minimal; insufficient under multi-writer contention |          |
| Aggressive (8+) with long backoff       | Converges but hangs UI-adjacent flows               |          |

**User's choice:** 4 attempts, backoff+jitter, typed error

---

## File CAS + merge

| Option                              | Description                                                       | Selected |
| ----------------------------------- | ----------------------------------------------------------------- | -------- |
| Latest-wins + loser becomes version | Newest modifiedAt is current; loser preserved in versions[] union | ✓        |
| Reject + surface conflict           | Manual resolution; bad for FUSE/headless writers                  |          |

**User's choice:** Latest-wins + loser becomes version

**Notes:** versions[] union deduped by cid, capped per Phase 39 vault settings; overflow pruned via the Phase 42-guarded unpin endpoint — the three gap-closure phases compose.

---

## Caller adoption scope

| Option                    | Description                                                        | Selected |
| ------------------------- | ------------------------------------------------------------------ | -------- |
| Sweep TS callers in-phase | web hooks + sdk client + shared-write pass base, handle errors     | ✓        |
| sdk-core internal only    | Union fallback everywhere; delete-resurrection remains in practice |          |

**User's choice:** Sweep TS callers in-phase; Rust FUSE parity deferred

---

## Claude's Discretion

- ConflictError shape and conflict-UI consumption
- Backoff base/cap and jitter distribution
- Merge test matrix structure; shared test vectors
- Location of the pure merge helper in sdk-core

## Deferred Ideas

- Rust FUSE 409-merge parity (live debounced publish path)
- Full CRDT model — ROADMAP-deferred to the CRDT-inbox research todo
