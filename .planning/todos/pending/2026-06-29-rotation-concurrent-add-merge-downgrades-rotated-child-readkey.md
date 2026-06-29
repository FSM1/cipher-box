---
created: 2026-06-29
title: Concurrent-add CAS-409 re-merge downgrades a rotated child's readKeySealed (remote-wins) — breaks navigation
area: sdk-core
resolves_phase: 68
files:
  - packages/sdk-core/src/rotation/engine.ts
  - packages/sdk-core/src/folder/merge.ts
  - tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts
---

## Problem

Surfaced during Phase 64 (HIGH-4 / ROT-05) execution and verification (plan 64-06 + e2e 64-08, deviation #3). User decision 2026-06-29: ship Phase 64 as-is, defer this fix.

`mergeConcurrentChildren` (`packages/sdk-core/src/rotation/engine.ts`) handles the CAS-409 re-merge by calling the generic three-way `mergeChildren` (`packages/sdk-core/src/folder/merge.ts`) with a **remote-wins** conflict policy:

```
// 3. Three-way merge: union by ipnsName, remote wins, honour intentional deletes.
const mergedChildren = mergeChildren(base.children, localChildren, remote.children);
```

For the **rotation** re-merge the three inputs are:

- `base`   = parent's children before rotation (existing child under the OLD parent readKey)
- `local`  = parent's children after rotation (existing child re-sealed under the NEW parent readKey' via the D-02 out-of-band re-seal)
- `remote` = parent's currently-published children (existing child still under the OLD key + the concurrently-added child)

With **remote-wins**, the existing child present in both `local` and `remote` resolves to the **remote (OLD-key)** `readKeySealed`, discarding the rotation's D-02 re-seal. After the parent body is re-sealed under `readKey'`, an authorized reader unseals the parent with the new key, reads the child's `readKeySealed` (now under the OLD parent key), and `unsealChildReadKey` AEAD-fails → **navigation to that child is broken** after a concurrent add during rotation. (Not a revocation bypass — the merged parent body is under `readKey'`, unreadable to a revoked reader — but a liveness/correctness regression for the authorized reader.)

The HIGH-4 *minimal* requirement (a concurrent add is never silently DROPPED) IS met — the new child survives in `mergedChildren`. The bug is that the merge **downgrades** an already-rotated existing child.

The e2e test (`tests/sdk-e2e/src/suites/rotation-crash-safety.test.ts`, test 3) only asserts the concurrent child *survives*, not that the existing child remains navigable — so it passes and masks this.

## Fix

The rotation CAS-409 re-merge must be **local-wins for conflicts + add remote-only (not-in-base) children**, not remote-wins:

- children present in `local` keep the rotation's re-seal (new key) — local wins;
- children present in `remote` but absent from `base` are concurrent adds — include them (they carry the OLD parent-key seal and will be re-sealed by a subsequent rotation; per design §4.5 step 5 the concurrent add is *picked up*, full re-key is a follow-on);
- children present in `base` but absent from `remote` are intentional deletes — drop them.

Either add a rotation-specific merge (e.g. `mergeRotatedChildren` / a `localWins` flag on `mergeChildren`) or branch the policy inside `mergeConcurrentChildren`. Do NOT change the generic `mergeChildren` remote-wins default — that policy is correct for the folder-state-desync use case (`[[project-web-sdk-folder-state-desync]]`); only the rotation re-merge needs local-wins.

Strengthen the e2e (test 3) to also assert the existing rotated child is still navigable under the new parent key after the concurrent-add merge.

## Why deferred

User-decided 2026-06-29 (Phase 64 close): ship the phase with the HIGH-4 minimal property proven, fix the merge-downgrade in a rotation follow-up. Related: [[rotation-fresh-record-resume-and-sc4-double-bump]].
