---
created: 2026-06-23T22:45:00.000Z
title: Phase 60 — complete IPNS first-publish unification and strict-equality cutover
area: infra
severity: medium
resolves_phase: 60
source: Phase 59 Finding F / code review CR-01 (deferred) — 2026-06-23
files:
  - crates/fuse/src/write_ops/implementation/mkdir.rs
  - crates/fuse/src/platform/windows/write_ops.rs
  - crates/fuse/src/verify.rs
  - crates/fuse/tests/ipns_verify_vectors.rs
  - tests/vectors/ipns/verify.json
  - scripts/gen-ipns-verify-vectors.ts
---

## Problem

Phase 59 Finding F tried to unify the IPNS first-publish embedded-sequence convention (FUSE 0 vs
SDK 1) and tighten `verify.rs` to strict `embedded_seq == resp_seq`. The deep code review caught
that this was a premature breaking change (CR-01): the resolve-side strict equality was applied
while the live folder-creation paths still embed `0`, which would fail-close resolution of every
freshly-created folder AND break existing signed records that embed 0. The strict cutover was
REVERTED (commit `0256ea486`); the skew allowance is restored and the cutover deferred here.

Current (post-Phase-59) state:

- `publish.rs::next_file_publish_sequence(is_first=true)` returns `1`; `replay.rs:628` child-folder
  first-publish embeds `1` (forward-compat changes KEPT).
- `crates/fuse/src/write_ops/implementation/mkdir.rs:173` and
  `crates/fuse/src/platform/windows/write_ops.rs:201` still embed `0` (NOT migrated).
- `verify.rs` retains the skew allowance `embedded_seq == resp_seq || (resp_seq == 1 && embedded_seq == 0)`
  (with a deferral NOTE pointing here).
- The TS SDK resolve side (`packages/sdk-core/src/ipns/index.ts`) also still has the allowance.

## Solution

Land the full cross-layer cutover in Phase 60 (IPNS Verification Cross-Layer Closeout: Desktop + API):

1. Change the interactive folder-create paths to embed `1`: `mkdir.rs:173` and
   `platform/windows/write_ops.rs:201` (`create_ipns_record(..., 1, ...)` + matching
   `coordinator.record_publish(..., 1)`), so ALL FUSE publish sites embed 1.
2. Migrate existing embedded-0 signed records: a republish pass (or TEE re-sign) so no live record
   embeds 0 before strict equality is enabled. Confirm against staging `folder_ipns` first.
3. Only then remove the skew allowance in `verify.rs` (strict `embedded_seq == resp_seq`) AND the
   parallel allowance in the TS SDK resolve path — in lockstep, cross-layer.
4. Update the cross-language vector: regenerate via `scripts/gen-ipns-verify-vectors.ts` so the
   generator is the single source of truth (set case-8 to `invalid` in the GENERATOR, not by hand),
   and update `crates/fuse/tests/ipns_verify_vectors.rs` classify_vector + the restored skew unit
   tests in `verify.rs`.

Do NOT enable strict equality on one layer before the other, and not before existing records are
migrated — that is exactly the CR-01 regression.

Related: Phase 59 `59-REVIEW.md` (CR-01/CR-02), `59-VERIFICATION.md` Post-Review Amendment.
