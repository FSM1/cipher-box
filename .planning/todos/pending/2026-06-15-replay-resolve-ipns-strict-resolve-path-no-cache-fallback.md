---
created: 2026-06-15
title: Use a strict (cache-bypassing) IPNS resolve in replay classification
area: fuse
files:
  - crates/fuse/src/lib.rs:217
---

## Problem

`resolve_ipns_for_replay` (crates/fuse/src/lib.rs ~line 217) classifies the replay IPNS
resolve result via `PublishCoordinator::resolve_sequence`. That coordinator method falls
back to a cached sequence on resolve failure: `Err(e) => match self.get_cached(name) { Some(cached) => Ok(cached), None => Err(...) }`.

So a **transient / non-404** resolve failure with a cached sequence returns `Ok(cached)`,
which `resolve_ipns_for_replay` maps to `IpnsResolveOutcome::Found(cached)`. Replay then
continues (publishes at `cached + 1`) instead of routing through the typed
`IpnsResolveOutcome::Error` branch that retains the journal entry for the next mount.
The net effect: a network blip during replay can advance the sequence off a stale cached
value rather than parking the entry.

This is **pre-existing** behavior. Phase 45 (#19) replaced the old
`.to_lowercase().contains("not found")` string match with the typed enum but deliberately
preserved the exact classification — so #19 did not change this. It was flagged by
CodeRabbit on PR #491 and deferred as out of scope for that no-behavior-change cleanup.

## Solution

TBD — add a strict resolve path so only a genuine IPNS resolve success becomes `Found`:

- Add a cache-bypassing method on `PublishCoordinator` (e.g. `resolve_sequence_strict`)
  that returns `Err` on any resolve failure regardless of cache state, and call it from
  `resolve_ipns_for_replay`; OR
- Have `resolve_ipns_for_replay` call `cipherbox_api_client::ipns::resolve_ipns` directly
  and classify Found / NotFound (404) / Error itself, keeping the cache only for the
  sequence-advance step after a confirmed success.
- This is a behavior change to crash-recovery, so it needs its own tests
  (transient-failure-with-cache → entry retained, real 404 → first publish) and should
  not regress the existing replay characterization tests.

Source: CodeRabbit review on PR #491 (thread on crates/fuse/src/lib.rs:222).
