---
created: 2026-06-21
title: Harden pre-existing FUSE/IPNS robustness gaps surfaced by PR 538 review
area: fuse
files:
  - crates/fuse/src/content_ops.rs
  - crates/fuse/src/metadata.rs
  - crates/fuse/src/fs.rs
  - crates/fuse/src/events.rs
  - crates/fuse/src/publish.rs
  - packages/sdk-core/src/folder/load.ts
---

## Context

CodeRabbit/Greptile review of PR `#538` (phase 55 refactor) surfaced 8 behavior findings. Each was verified **byte-identical to `main` at b57a9c5de** — phase 55 only MOVED this code into new modules; it did not introduce these. They were deferred because phase 55's contract (HARD-06) forbids behavior changes. They are genuine pre-existing robustness/correctness gaps worth a dedicated hardening pass.

## Findings (all pre-existing, line numbers as of the refactor)

1. `content_ops.rs:175` (`publish_file_metadata`) — for an EXISTING file record, a per-file IPNS `Conflict` is logged as a warning but still treated as a successful publish (`record_publish` called, `expected_sequence_number: None`). A real conflict should re-resolve and retry with the resolved sequence as `expected_sequence_number`, not be swallowed. (base `operations.rs:152-240`)
2. `metadata.rs:348` (bin publish) — missing-record path publishes `expected_sequence_number: Some("0")`; the `Conflict` arm warns then returns success (same conflict-as-success class as #1). (base `lib.rs:610-682`)
3. `fs.rs:223` — `wrap_key(...).ok()` silently drops file IPNS key-wrap errors, publishing a `FilePointer` without `ipns_private_key_encrypted` (republish/recovery would later fail). Propagate the error instead. (base `lib.rs:1081-1090`)
4. `fs.rs:289` — stale upload completions still unpin `pruned_cids`: the unpin loop runs outside the `write_generation` guard, so a superseded write can unpin CIDs the current generation still references. (base `lib.rs:1131-1158`)
5. `fs.rs:421` — the FilePointer-resolution loop breaks at `MAX_CONCURRENT_FP_RESOLVES = 10` and drops the remainder with no continuation queue. (base `lib.rs:1275-1283`)
6. `events.rs:109` (`spawn_metadata_refresh`) — the async refresh task has no timeout; `refreshing_metadata` is cleared only after it sends a `PendingRefresh`, so a hung resolve/fetch can block future refreshes indefinitely. Bound it with `NETWORK_TIMEOUT`. (base `lib.rs:142-185`)
7. `publish.rs:23` (`next_file_publish_sequence`) — unchecked `seq + 1` (u64 overflow at MAX). Use `checked_add`/`saturating_add`. (base `lib.rs:192-203`)
8. `load.ts:34` (`fetchAndDecryptMetadata`) — no try-catch around `TextDecoder.decode` / `JSON.parse` / `decryptFolderMetadata`; a malformed/corrupt blob throws an opaque error instead of a typed failure. (base `packages/sdk-core/src/folder/index.ts:49-63`)

## Note on #6/#7 and zeroization

If touching publish/metadata signatures here, also see the deferred `Zeroizing` todo (`2026-06-21-zeroize-fuse-metadata-publish-key-params.md`) — batch them into one hardening pass, and heed the codebase rule that a callee must not zero a caller-owned/reused buffer.
