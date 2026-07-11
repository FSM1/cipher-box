---
created: 2026-07-11T00:00:00.000Z
title: Scope-exit re-mint refetches /shares/sent for every rotated node — cache per rotation
area: desktop-fuse-rotation
severity: low
source: Phase 74 PR #607 review — coderabbit Major (performance, rotation_deps.rs:286)
files:
  - crates/fuse/src/write_ops/rotation_deps.rs
  - crates/sdk/src/rotation/engine.rs
resolves_phase: null
---

## Problem

Phase 74 (T-74-07) implemented `query_grants_rooted_at` in the FUSE
`RotationDeps` adapter (`crates/fuse/src/write_ops/rotation_deps.rs` ~:265-286).
It calls `self.transport.collect_sent_shares().await?` — a full `/shares/sent`
fetch — and then filters the result in memory by `root_node_id == node_id`.

`re_mint_grants_rooted_at` runs after EACH per-node commit during a rotation
walk, so `query_grants_rooted_at` is invoked once per rotated node. Each
invocation refetches the entire sent-share list from the API. For a large
rotated subtree and/or an owner with many active shares this is O(nodes ×
shares) network work.

## Fix

Cache the `collect_sent_shares()` result for the lifetime of a single rotation
job and filter the cached list by `root_node_id` per node, instead of hitting
the transport on every node. Populate the cache once at rotation start (or lazily
on first use), preserve the existing 0x-strip / hex-decode key parsing and the
per-share error handling. Consider a matching optimization in the TS
owner-reconcile `queryGrantsFn` for parity.

## Acceptance

A scope-exit rotation over an N-node subtree performs at most ONE
`/shares/sent` fetch (not N), and re-mint results are unchanged (retained
recipients re-minted, revoked recipients cut by absence).
