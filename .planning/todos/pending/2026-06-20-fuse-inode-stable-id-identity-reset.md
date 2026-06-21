---
created: 2026-06-20T00:00:00.000Z
title: FUSE inode stable-ID lookup must reset identity state on display-name-only fallback
area: bug
severity: medium
source: CodeRabbit review of PR #529 (crates/fuse/src/inode.rs:399-412, also 461-475, 515-580); pre-existing, out of Phase 51 HARD-02 scope
files:
  - crates/fuse/src/inode.rs
---

## Problem

The inode refresh logic looks up an existing inode by stable ID (`ipns_to_ino.get(&folder.ipns_name)`)
but falls back to `find_child(parent_ino, &folder.name)` (display name). Later code then treats the
fallback-matched inode as the SAME folder/file identity. If remote metadata replaces an entry with a
different `ipns_name` / `file_meta_ipns_name` but keeps the same display name:

- Folders can preserve stale loaded children (the old inode's `children` are kept).
- Resolved files can keep the old CID / encryption keys when `modified_at` is unchanged.

This is a sync-correctness / cache-coherency bug in the desktop FUSE layer, independent of Phase 51
(crypto-signature / secret-leak hardening). CodeRabbit flagged it on the PR #529 review as a Major
"outside diff range" finding (the lines were only touched by Phase 51's cargo-fmt cascade).

## Solution

Distinguish a stable-ID match (`ipns_to_ino`) from a display-name-only fallback (`find_child`). When
only the fallback matches, the identity has actually changed: clear folder loaded state and force file
re-resolution (refresh CID + metadata/encryption keys). CodeRabbit's proposed direction:

```rust
let matched_by_stable_id = ipns_to_ino.contains_key(&folder.ipns_name);
let existing_ino = ipns_to_ino
    .get(&folder.ipns_name)
    .copied()
    .or_else(|| self.find_child(parent_ino, &folder.name));
// ...
let (existing_children, was_loaded) = if existing_ino.is_some() && matched_by_stable_id { ... };
```

For files, also treat a changed `file_meta_ipns_name` as a re-resolution trigger (not just `modified_at`).
Apply consistently across the affected sections (~399-412, 461-475, 515-580). Keep macOS and Windows
paths in lockstep.

## Where it belongs

Phase 52 (Desktop FUSE Durability & At-Rest Safety) — alongside the per-file IPNS conflict-handling
fix already captured in
`2026-06-20-fuse-per-file-ipns-publish-conflict-recorded-as-success.md`.
