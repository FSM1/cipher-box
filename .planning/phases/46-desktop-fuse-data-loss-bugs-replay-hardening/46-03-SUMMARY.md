---
phase: 46-desktop-fuse-data-loss-bugs-replay-hardening
plan: 03
subsystem: desktop-fuse
tags: [fuse, replay, ipns, resolve, journal, parking]
requires: [46-01]
provides:
  - REQ-4 early park-return for legacy None-name UploadFile replay entries
  - REQ-5 resolve_sequence_strict cache-bypassing resolve for replay classification
affects:
  - crates/fuse/src/lib.rs
tech-stack:
  added: []
  patterns:
    - strict resolve errs on any failure, never falls back to cache (replay path only)
    - precise None-name guard parks legacy entries via record_failure instead of publishing
    - per-test isolated journal dir + unroutable API for replay characterization
key-files:
  created:
    - .planning/phases/46-desktop-fuse-data-loss-bugs-replay-hardening/46-03-SUMMARY.md
  modified:
    - crates/fuse/src/lib.rs
decisions:
  - REQ-4 guard placed ABOVE Step 1 of replay_upload_entry to avoid re-pinning content every mount (Pitfall 4)
  - PARK (not mint-fresh-IPNS) chosen for lowest blast radius and no new key material
  - resolve_sequence kept unchanged; only resolve_ipns_for_replay switches to strict (live path keeps cache resilience)
  - No metadata sweep for already-published empty-locator pointers (Assumption A5 residue documented)
metrics:
  duration: ~13m
  completed: 2026-06-15
---

# Phase 46 Plan 03: Replay-Path Hardening Summary

Two replay correctness fixes from the PR #491 follow-ups, both surgical changes in
`crates/fuse/src/lib.rs`.

## What Was Built

### REQ-4: park legacy None-name replay entries

`replay_upload_entry` previously built an empty `FilePointer` (id `"replay-"`,
`file_meta_ipns_name ""`) for legacy `None`-name entries and published it, after
which `replay_for_vault` removed the entry as "successfully replayed". Empty-name
pointers also collide in `merge_folder_children` (all key on `""`).

The fix is an early guard, placed at the top of `replay_upload_entry` (above the
ciphertext upload/pin per Pitfall 4, so legacy content is not re-pinned on every
mount):

```rust
if file_meta_ipns_name.is_none() {
    return Err(
        "legacy UploadFile entry has no per-file IPNS name -- parking (no empty FilePointer)"
            .to_string(),
    );
}
```

The guard is precise on `file_meta_ipns_name.is_none()`, so the normal `Some`-name
path is untouched. `replay_for_vault` already maps `Err` to `record_failure`
(retain/park) and `Ok` to remove, so no change there. No fresh-IPNS minting; no
new key material.

### REQ-5: strict cache-bypassing resolve in replay classification

`resolve_sequence` falls back to the cache on resolve `Err`, so a transient
network blip with a cached value returns `Ok(cached)` and replay would publish at
`cached+1` instead of parking. A new `PublishCoordinator::resolve_sequence_strict`
errs on any resolve failure (never cache fallback); on success it still returns
`max(resolved, cached)` and updates the cache. Only `resolve_ipns_for_replay`
switches to strict. The live publish path (`spawn_metadata_publish`, mkdir) keeps
`resolve_sequence` for its cache resilience, and `classify_resolve_outcome` is
unchanged so the 404-first-publish contract holds.

The resolve response field was confirmed as
`cipherbox_api_client::types::IpnsResolveResponse.sequence_number` (a `String`,
camelCase serde); the plan's `.parse::<u64>().unwrap_or(0)` is correct as written.

## Test Results

All six tests pass on the macOS dev host:

```text
test tests::legacy_empty_name_parks ... ok
test tests::empty_name_merge_collision ... ok
test tests::strict_resolve_bypasses_cache ... ok
test tests::transient_failure_retains_entry ... ok
test tests::replay_for_vault_does_not_touch_failed_entries ... ok
test tests::classify_resolve_outcome_maps_resolve_results ... ok
```

`empty_name_merge_collision` pins the motivation by placing one empty-name pointer
on the local side and one on the remote side of `merge_folder_children`; they
collapse to a single entry, confirming empty locators cannot coexist across a
merge.

## Known Residue

Already-published empty-locator FilePointers (from before this fix) are left in
place per Assumption A5. No metadata migration or sweep was added; that is out of
scope and documented here as known residue.

## Threat Model Compliance

- T-46-06 (Tampering): strict resolve errs on any failure, so a transient blip
  never advances IPNS sequence off a stale cached value; the live path keeps its
  separate cache-resilient method.
- T-46-07 (Information Disclosure): None-name entries are parked instead of
  publishing an unresolvable `"replay-"`/`""` pointer that collides in merge; no
  new key material.
- T-46-08 (Information Disclosure): tests use isolated temp journal dirs and an
  unroutable API; journal entries reference ciphertext + ECIES-wrapped keys only,
  never raw plaintext.
