---
created: 2026-06-14T12:37:25.820Z
title: Replace empty-string journal key sentinel with Option<String>
area: desktop-fuse
files:
  - crates/fuse/src/write_ops.rs
  - crates/fuse/src/read_ops.rs
  - crates/fuse/src/platform/windows/write_ops.rs
  - crates/fuse/src/lib.rs
  - crates/sdk/src/queue.rs
---

## Problem

"Wrap failed / no key present" for a journaled IPNS key is encoded as an empty string
(`String::new()`), produced via `.unwrap_or_else(|e| { log::warn!(...); String::new() })`
at ~5 producer sites (`write_ops.rs`, `read_ops.rs`, `platform/windows/write_ops.rs`)
and decoded via `.is_empty()` checks at 3 replay sites in `lib.rs`. The invariant "this
hex is either a valid user-ECIES-wrapped key or it means park-on-replay" is re-derived
at every site, and the long CR-03 "never fall back to TEE-wrapped" comment is pasted 4x.

It is also inconsistent: `JournalOp::*::parent_ipns_key_hex` uses the empty-string
sentinel while `file_ipns_key_hex` already uses `Option<String>` — within the same
struct. A new call site that forgets the `.is_empty()` guard feeds an empty string into
`hex::decode` -> `ecies::unwrap_key` and gets a confusing crypto error instead of a
clean park.

Surfaced by the phase-43 `/simplify` altitude + simplification reviewers; deferred from
commit a1ec69f1b as a larger (schema-touching) refactor.

## Solution

Introduce one helper, e.g.
`fn wrap_ipns_key_for_journal(raw: &[u8], user_pub: &[u8]) -> Option<String>` (returns
`None` on wrap failure, logs once), and make the journal key fields `Option<String>`
uniformly in `crates/sdk/src/queue.rs` (`parent_ipns_key_hex` joins `file_ipns_key_hex`
as `Option`). Replay matches `None => return Err("park")` in one decode path. Collapses
5 producer incantations + 3 consumer guards into one helper + one decode site.

Touches the `JournalOp` schema (serde) — confirm round-trip of old on-disk entries (a
missing field deserializes to `None`, which is the correct "park" behavior). Do
alongside the fuser/winfsp consolidation todo so they share the helper.
