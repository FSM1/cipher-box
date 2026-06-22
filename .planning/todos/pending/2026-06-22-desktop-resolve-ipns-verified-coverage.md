---
created: 2026-06-22T00:00:00.000Z
title: Route apps/desktop/src-tauri resolve_ipns sites through resolve_ipns_verified
area: security
severity: low
source: Phase 58 security audit (58-SECURITY.md) — unregistered flag; explicitly deferred in 58-01-SUMMARY
files:
  - apps/desktop/src-tauri/src/prepopulate.rs
  - apps/desktop/src-tauri/src/vault.rs
---

## Problem

Phase 58 introduced the `resolve_ipns_verified` chokepoint and routed all 9 FUSE-crate resolve
sites through it (CBOR cid/sequence binding, scoped fail-closed). The Phase 58 security audit
flagged **6 remaining unverified `resolve_ipns` call sites in the desktop Tauri shell** that were
out of scope for Phase 58:

- `apps/desktop/src-tauri/src/prepopulate.rs` — lines ~43, ~110, ~177, ~236
- `apps/desktop/src-tauri/src/vault.rs` — lines ~21, ~250

These call the raw api-client `resolve_ipns` and trust the response CID/sequence without the
CBOR-binding verification (D-07/D-08) the FUSE crate now enforces.

## Why deferred (not a regression)

These desktop paths relied on unverified resolution **before** Phase 58 and still do — there is no
regression from the pre-phase baseline. The trust model anchor holds: "DB CID is authoritative;
signature verification is defense-in-depth (Medium)." Closing them is hardening, not a fix.

## Action (future phase)

Route each site through `resolve_ipns_verified` (or the equivalent verified wrapper available in the
desktop crate's dependency graph), applying the same per-operation scoped fail-closed posture (D-02)
the FUSE sites use. Verify line numbers by symbol before editing (they may have shifted).
