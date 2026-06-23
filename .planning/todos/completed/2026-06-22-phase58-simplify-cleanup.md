---
created: 2026-06-22T00:00:00.000Z
title: Phase 58 IPNS verify — minor simplify/cleanup follow-ups
area: refactor
severity: low
source: Phase 58 /ship-phase simplify review — deferred to avoid churning verified crypto code before ship
files:
  - crates/fuse/src/verify.rs
  - crates/fuse/src/events.rs
  - crates/fuse/src/metadata.rs
  - crates/fuse/tests/ipns_verify_vectors.rs
  - scripts/gen-ipns-verify-vectors.ts
  - tests/vectors/ipns/verify.json
---

## Problem

The Phase 58 simplify review found the diff fundamentally clean. The following minor cleanups were
deferred to avoid touching verified, tested, security-audited crypto code immediately before ship.
None are correctness bugs.

## Safe-now (trivial, zero-risk)

1. **Dead `VerifiedResolve::signature_verified` field** (`crates/fuse/src/verify.rs:47`) — written
   (`true` in `bind_verified`, `false` in the `events.rs` legacy synthetic struct) but read only by
   the module's own unit test; no FUSE call site reads it. Remove the field, the legacy `false`
   assignment in `events.rs`, and the test assertion.
2. **Misleading test string** (`crates/fuse/src/metadata.rs` ~line 1170) — `is_ipns_not_found("404 not found")`
   passes only because the string contains "not found"; the predicate does not match a standalone
   "404". Rename to a clearer case (e.g. `"record not found"`) or add a distinct 404-only negative test.
3. **Dead `journal_entry: Option<()>` branch** (`crates/fuse/src/metadata.rs` ~lines 197-207) — the
   `if journal_entry.is_some()` and `else` arms return identical `Err`; the `Some` arm is unreachable
   (param is always `None`). Collapse the branch body to the single `Err`; keep the `journal_entry`
   parameter for deferred D-01a journal work.
4. **Unused `public_key`/`private_key` in the vector fixture** — `scripts/gen-ipns-verify-vectors.ts`
   emits `public_key` and `private_key` (filler `0101…`, not a real secret) into every entry of
   `tests/vectors/ipns/verify.json`, but neither the Rust nor JS consumer reads them. Remove from the
   7 `vectors.push(...)` sites, re-run the generator, confirm both consumers stay green.

## Defer (larger / intentional)

- **D1** `classify_vector` in `ipns_verify_vectors.rs` re-spells `bind_verified` inline (documented
  intent — pins both the api-client signature check and the core CBOR decode). Reconsider calling
  `bind_verified` directly once the test invariant is re-thought.
- **D2** Unify `metadata.rs::is_ipns_not_found` with `publish.rs::classify_resolve_outcome` (same
  predicate, different 404 coverage — may be intentional).
- **D3** `publish_with_cas_retry`'s `journal_entry: Option<()>` placeholder param — will change shape
  when D-01a journal work lands; add a TODO at the call site (`metadata.rs:611`).
