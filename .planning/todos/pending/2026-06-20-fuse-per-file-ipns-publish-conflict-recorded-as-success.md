---
created: 2026-06-20T00:00:00.000Z
title: FUSE per-file IPNS publish records sequence as published on server Conflict
area: bug
severity: medium
source: CodeRabbit CLI review of Phase 51 (#4 operations.rs:215, #5 windows/operations.rs:374); verified pre-existing (introduced in #352, Phase 23) — out of Phase 51 HARD-02 scope
files:
  - crates/fuse/src/operations.rs
  - crates/fuse/src/platform/windows/operations.rs
---

## Problem

In the per-file IPNS publish path, the `PublishResult::Conflict` match arm only emits a
`log::warn!` and then **falls through** — the code proceeds to record the publish
(`coordinator.record_publish` / `new_seq`) and returns `Ok(())`. So a per-file IPNS publish
that the **server rejected with a 409 Conflict** is treated as a local success: the local
`PublishCoordinator` sequence advances and diverges from the server's authoritative sequence.

- `crates/fuse/src/operations.rs` (~line 215) — macOS/Linux path.
- `crates/fuse/src/platform/windows/operations.rs` (~line 374) — WinFsp path (same bug, mirrored).

Pre-existing since the Rust SDK extraction (#352, Phase 23); Phase 51 only reformatted the
`log::warn!` line via the cargo-fmt cascade. CodeRabbit flagged it on the Phase 51 review but it is
out of HARD-02's (crypto-signature / secret-leak) domain.

### Why it matters

A divergent local sequence can cause subsequent legitimate publishes for that file to fail the
server's anti-rollback / CAS check (the local "next" sequence is ahead of what the server stored),
or mask a genuine concurrent-writer conflict that should have triggered a re-fetch/merge. This is a
desktop FUSE write-durability / IPNS-conflict-handling correctness issue.

## Solution

On `PublishResult::Conflict`, do NOT record the sequence as published — return an error (or skip the
`record_publish`/`new_seq` update and surface the conflict for retry/merge). CodeRabbit's suggested
form for operations.rs:

```rust
cipherbox_api_client::PublishResult::Conflict { current_sequence_number } => {
    return Err(format!(
        "per-file IPNS publish conflict for {} (server sequence {})",
        file_ipns_name, current_sequence_number
    ));
}
```

Apply the equivalent fix on the WinFsp path (`new_seq` recorded only on `Success`). Keep macOS and
Windows in lockstep (CI gates the winfsp build).

## Where it belongs

Phase 52 (Desktop FUSE Durability & At-Rest Safety) or alongside the Phase 44 IPNS-conflict-handling
work — NOT Phase 51. Fold into the relevant phase's scope when planning.
