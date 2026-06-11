---
created: 2026-06-11
title: FUSE release() reports success then can silently lose data
area: desktop-fuse
severity: high
files:
  - crates/fuse/src/read_ops.rs
  - crates/fuse/src/platform/windows/write_ops.rs
  - packages/sdk/src/queue.rs
---

## Problem

`flush` is a no-op (`read_ops.rs:852-854`). `release` replies OK to the OS, spawns
a detached upload thread, then immediately zeroizes and deletes the local temp file
(`read_ops.rs:835-848`). Upload failure in that thread is `log::error!`-only
(`read_ops.rs:832-834`). Same pattern on Windows (`windows/write_ops.rs:821-865`).

After the OS-acknowledged close, the only copy of the data is in-memory ciphertext
in a detached thread. A crash, a kill, or an upload failure = silent permanent data
loss after the user (and the OS) were told the write succeeded.

Severity: data loss with false durability ack.

## Solution

TBD — key considerations:

- Do not delete/zeroize the temp file until the remote commit (IPFS add + pin +
  IPNS publish) is durably confirmed.
- Add a persisted pending-upload journal so a crash can resume on restart. The SDK
  `WriteQueue` is memory-only and not wired into the FUSE/desktop path
  (`packages/sdk/src/queue.rs:6-7`) — this is the place to fix that.
- Surface upload failure to the user instead of swallowing it.
- Constraint: macOS FUSE callbacks are single-threaded and cannot block on network
  I/O, so durability must be provided by an out-of-callback durable queue, not by
  blocking `release`.
