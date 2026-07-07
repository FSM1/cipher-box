---
created: 2026-06-24
title: Reuse the verified parent sequence in replay instead of re-resolving
area: fuse
files:
  - crates/fuse/src/replay.rs
  - crates/fuse/src/publish.rs
---

## Problem

In `fetch_merge_publish_parent` (`crates/fuse/src/replay.rs:455`) the replay/merge path calls `resolve_ipns_verified` and uses only `verified.cid`, then at ~line 505 calls `coordinator.resolve_sequence`, which internally performs a **second** `resolve_ipns_verified` (`publish.rs:96`). `VerifiedResolve` already carries `sequence_number`, so the parent is resolved (and signature-verified) twice per replay merge — redundant work and an extra network round-trip on a hot path.

Surfaced by CodeRabbit during the Phase 60 ship review (finding F2). Verified real but classified **out-of-scope** for the Phase 60 strict-cutover goal and **not low-risk** (the replay/CAS/merge flow is delicate; carrying the sequence forward changes conflict-detection ordering).

## Solution

TBD — carry the `verified.sequence_number` from the first verified resolve forward into the merge/CAS check rather than re-resolving, and ensure any mismatch/conflict keeps the journal entry rather than publishing stale `remote_meta`. Needs careful review of the CAS conflict semantics and a replay-focused test before changing.
