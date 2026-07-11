---
created: 2026-06-29
title: Dedup base64 helpers in sdk-core/share (navigate.ts + grant.ts → shared share/codec.ts)
area: sdk-core
resolves_phase: 77
files:
  - packages/sdk-core/src/share/navigate.ts
  - packages/sdk-core/src/share/grant.ts
---

## Problem

Minor DRY nit flagged by the Phase-63 PR review (greptile P2). `base64ToBytes` (and `bytesToBase64`) are defined identically in both `packages/sdk-core/src/share/navigate.ts` and `packages/sdk-core/src/share/grant.ts`. Pure duplication, no behavior difference, no public-API impact.

Deferred (not fixed in the Phase-63 PR) only to avoid re-triggering the PR review-bot loop with a no-behavior-change refactor after the substantive review was already resolved. Low priority — pick up opportunistically (e.g. during Phase 64 work in `share/`).

## Solution

Extract `bytesToBase64` / `base64ToBytes` into a shared `packages/sdk-core/src/share/codec.ts` (or reuse an existing base64 util if one exists elsewhere — check `@cipherbox/crypto`/`core` first) and import it in both files. No public API change.

## References

- CodeRabbit/greptile PR #579 review, `navigate.ts:66`
