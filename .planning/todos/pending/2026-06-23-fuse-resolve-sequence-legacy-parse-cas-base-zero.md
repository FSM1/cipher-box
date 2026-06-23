---
created: 2026-06-23T23:40:00.000Z
title: FUSE non-strict resolve_sequence invents CAS base 0 on malformed legacy sequence
area: fuse
severity: low
resolves_phase: 60
source: PR #553 CodeRabbit Major (workflow-verified pre-existing) — 2026-06-23
files:
  - crates/fuse/src/publish.rs
---

## Problem

In `PublishCoordinator::resolve_sequence` (the non-strict path, `crates/fuse/src/publish.rs`
~114-124), the `VerifyError::Legacy` arm parses the carried `sequence_number` with
`.parse::<u64>().unwrap_or_else(|e| { warn; 0 })`, then `max(resolved, cached.unwrap_or(0))`.
On a parse failure with **no cached** sequence this returns `Ok(0)` — publishing from an invented
base — whereas the strict path (`resolve_sequence_strict`, ~182-184) returns `Err` on the same
parse failure. CodeRabbit flagged the strict-vs-non-strict asymmetry on PR #553.

## Why deferred (not fixed in Phase 59)

A parallel adversarial verifier confirmed (high confidence) this is **pre-existing**, not
introduced by Phase 59:

- `git show origin/main:crates/fuse/src/publish.rs` — the pre-phase non-strict Legacy arm already
  used the identical `parse().unwrap_or_else(0)` + `max(resolved, cached.unwrap_or(0))`. Phase 59
  only changed the **source** of the sequence string (carried `Legacy { sequence_number, .. }`
  instead of a second `resolve_ipns` call) to close a TOCTOU window (T-59-04); the 0-fallback
  semantics are byte-identical to `main`.
- Blast radius is low: `sequence_number` is the API's DB-stored numeric string (`verify.rs:71`), so
  a parse failure implies a corrupt/non-numeric DB value (practically never). Even then the publish
  carries `expected_sequence_number: Some("0")` and the server enforces CAS — a stale base returns
  `PublishResult::Conflict`, and the caller re-resolves + republishes with the correct base
  (`metadata.rs:140-161`). So base 0 cannot silently overwrite a newer record; it degrades to a
  benign conflict-retry.

Outside Phase 59's diff/scope → deferred rather than expanding scope.

## Solution (Phase 60)

Mirror the strict path's validation in `resolve_sequence`: on parse failure, return `Ok(cached)`
only when a cache entry exists, else `Err(...)` — do not invent base `0`.

```rust
let resolved = match sequence_number.parse::<u64>() {
    Ok(seq) => seq,
    Err(e) => {
        if let Some(cached) = self.get_cached(ipns_name) {
            log::warn!("Failed to parse carried IPNS sequence '{}' for {}, using cached seq {}: {}", sequence_number, ipns_name, cached, e);
            return Ok(cached);
        }
        return Err(format!("Invalid IPNS sequence '{}' for {} and no cached sequence: {}", sequence_number, ipns_name, e));
    }
};
```

No existing unit test exercises this parse-failure path, so the change is low-risk. Related:
`59-REVIEW.md`, PR #553 review thread on `publish.rs:120`.
