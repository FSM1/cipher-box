---
created: 2026-06-22T00:00:00.000Z
title: Carry the legacy IPNS response in VerifyError::Legacy instead of a second raw resolve
area: refactor
severity: low
source: Phase 58 PR #544 CodeRabbit review (thread on crates/fuse/src/verify.rs:23) — deferred as heavy-lift
files:
  - crates/fuse/src/verify.rs
  - crates/fuse/src/events.rs
  - crates/fuse/src/fs.rs
  - crates/fuse/src/publish.rs
  - crates/fuse/src/metadata.rs
  - crates/fuse/src/replay.rs
---

## Problem

`resolve_ipns_verified` / `bind_verified` already hold the raw `IpnsResolveResponse`, but the
`VerifyError::Legacy` variant (D-04, all-signature-fields-absent records) is a unit variant that
DROPS the response. Every legacy caller then issues a SECOND unverified `resolve_ipns` to recover
the CID/sequence. CodeRabbit flagged that the second resolve may return a DIFFERENT record than the
one that was classified as legacy (the 30s IPNS poll / a concurrent publish could change it between
the two calls), plus it's a redundant network round-trip at each of the ~8 legacy arms.

## Why deferred (heavy-lift, low real risk)

- The legacy path is DB-CID-authoritative (signature verification is defense-in-depth, Medium), so
  using a freshly-resolved current record is not a correctness break — at worst a rare
  legacy→signed transition window where the new (now-signed) record is treated as legacy/unverified.
- The fix changes the `VerifyError::Legacy` enum shape and updates every legacy match arm across
  verify.rs + the routed FUSE sites (events/fs/publish/metadata/replay) — a multi-site refactor,
  not a one-liner.

## Action (future hardening phase)

Change `VerifyError::Legacy` to carry the raw response:

```rust
Legacy { cid: String, sequence_number: String },
```

Populate it in `bind_verified` (`None => Err(VerifyError::Legacy { cid: resp.cid.clone(), sequence_number: resp.sequence_number.clone() })`), update the `Display` impl, and replace every downstream `VerifyError::Legacy` arm's second `resolve_ipns` call with the carried fields. Also applies to verify.rs lines ~66-67 and ~130-131.
