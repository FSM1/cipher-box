# Phase 56: FUSE and IPNS Durability Hardening - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-22
**Phase:** 56-fuse-and-ipns-durability-hardening
**Areas discussed:** Failure surfacing (errno), Reuse CAS engine

---

## Area selection

| Option                         | Description                                                                                  | Selected |
| ------------------------------ | -------------------------------------------------------------------------------------------- | -------- |
| Conflict-retry policy          | Per-file/bin Conflict: retry then journal vs EIO vs folder-style merge                        |          |
| Failure surfacing (errno)      | What errno unrecoverable failures return to Finder/Explorer                                   | ✓        |
| Reuse CAS engine?              | Share a Rust retry helper vs inline per-site                                                  | ✓        |
| Skip — all locked              | Write CONTEXT from ROADMAP + folded todos as-is                                               |          |

**Notes:** Conflict-retry exhaustion was folded into the Failure-surfacing discussion since
the two overlap. The remaining 10 findings have locked file/line-level directions in the
folded todos and were not re-discussed.

---

## Failure surfacing (errno)

| Option                          | Description                                                                                                                         | Selected |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | -------- |
| Split: retry→journal, hard→EIO  | Transient IPNS Conflict → bounded re-resolve/retry → Phase 43/46 journal + ack. Hard (wrap_key, decode) → EIO, no false ack.        | ✓        |
| Always EIO, never journal       | Any publish/wrap/decode failure returns EIO immediately. Simpler, but surfaces errors on normal concurrent writes.                  |          |
| Always journal-and-ack          | Every failure journals + acks. Maximizes non-blocking, but a doomed op loops forever instead of surfacing.                          |          |

**User's choice:** Split: retry→journal, hard→EIO
**Notes:** Matches the phase intent — "no durability decision left to a swallowed warning."
Transient contention recovers in the background; genuine corruption surfaces to the user.

---

## Reuse CAS engine

| Option                              | Description                                                                                                                              | Selected |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| Extract one Rust helper (3 CAS sites) | Pull folder retry loop into shared `publish_with_cas_retry`; route per-file + bin + folder through it. Leave mkdir event re-arm alone.    | ✓        |
| Inline per-site, no extraction      | Copy folder retry pattern inline at the 2 buggy sites. Smallest blast radius, keeps ~3 near-duplicate loops.                             |          |
| You decide (planner picks)          | Lock behavior only; let researcher/planner pick extract-vs-inline.                                                                       |          |

**User's choice:** Extract one Rust helper (3 CAS sites)
**Notes:** `metadata.rs:136-214` already has the correct folder retry loop — it becomes the
template. mkdir's `MkdirConflict` event-channel re-arm (mkdir.rs + platform/windows) is
explicitly excluded — different mechanism, larger refactor.

## Claude's Discretion

- Retry bound / backoff numbers for the re-resolve loop (planner picks sensible defaults,
  e.g. `NETWORK_TIMEOUT`-bounded small fixed count).
- Exact errno for non-`EIO` edge cases not enumerated.

## Deferred Ideas

- Consolidating mkdir's `MkdirConflict` event-channel re-arm into the shared CAS helper —
  larger refactor, out of scope for this hardening pass.
- IPNS resolve signature-verify coverage + web/sdk-core resolve dedup → Phase 58.
- Tier-3 large-file refactor residue → separate refactor track.
- API CID/provider/unpin hardening todos → Phase 57.
