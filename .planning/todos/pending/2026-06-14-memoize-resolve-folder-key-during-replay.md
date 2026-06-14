---
created: 2026-06-14T12:37:25.820Z
title: Memoize resolve_folder_key during replay
area: desktop-fuse
files:
  - crates/fuse/src/lib.rs
---

## Problem

`resolve_folder_key` in `crates/fuse/src/lib.rs` BFS-descends the vault tree from the
root (a `resolve_ipns` + `fetch_content` + decrypt per node) and is called once per
replayed entry from `replay_mkdir_entry` and `replay_upload_entry`. If a crash leaves N
files queued under the same folder, that folder's key is resolved N times, each time
re-resolving and re-fetching the whole path from root.

Mount-time replay latency is therefore super-linear in the number of queued entries
sharing a parent, and mount latency is user-visible. Folder keys do not change within a
single replay pass. Surfaced by the phase-43 `/simplify` efficiency reviewer (cold-path,
mount-only); deferred from commit a1ec69f1b.

## Solution

Thread a `HashMap<String /* ipns_name */, Vec<u8> /* folder_key */>` cache through
`replay_for_vault` and the per-entry replay calls, seeded with
`root_ipns_name -> root_folder_key`. `resolve_folder_key` checks the cache first and
inserts each key it resolves as it descends, so entries sharing a parent resolve it
once. Mount-only change; verify with a replay test that queues multiple entries under
one nested folder.
