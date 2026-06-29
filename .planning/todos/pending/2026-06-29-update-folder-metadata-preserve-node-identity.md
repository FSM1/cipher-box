---
created: 2026-06-29
title: updateFolderMetadataAndPublish mints a fresh UUID / resets generation on every update — preserve node identity
area: sdk-core
resolves_phase: 64
files:
  - packages/sdk-core/src/folder/registration.ts
  - packages/sdk/src/client.ts
---

## Problem

Flagged CRITICAL by the Phase-63 PR CodeRabbit review (`registration.ts:180`).

`updateFolderMetadataAndPublish` (`packages/sdk-core/src/folder/registration.ts` ~L174-175) builds the folder Node with:

```
id: params.nodeId ?? crypto.randomUUID(),
generation: params.nodeGeneration ?? 0,
```

All **six** call sites in `packages/sdk/src/client.ts` (L493, L558, L581, L629, L747, L1006) omit `nodeId` and `nodeGeneration` (confirmed by grep — neither field is passed anywhere in client.ts). Therefore **every folder metadata update mints a brand-new random UUID and resets `generation` to 0**.

Two invariants are broken on update:

1. **Node identity instability** — the folder Node's `id` is part of the AAD the parent used when it sealed the folder's child read-key (`sealChildReadKey` with `child.id`/`kind`/`generation` in `addFilePointerToFolder`). Changing the folder's `id` on a metadata update means a grantee navigating from the parent validates against a different identity than the one the key was sealed under → AAD authentication fails → navigation to the updated folder breaks.
2. **Generation reset** — `generation` is the rotation counter (one of the three counters that must never be conflated: `generation` / `keyEpoch` / `sequenceNumber`). A metadata update (add/move/delete/rename) bumps the IPNS `sequenceNumber` via CAS; it must NOT reset `generation` to 0. Resetting it corrupts the staleness-witness the read path (`navigateReadChain`) compares against and the rotation engine relies on.

Not caught by Phase-63 tests/e2e because the happy-path (create → navigate → root-rotate) does not perform a folder metadata UPDATE that is then navigated by a grantee against the pre-update binding. The app is intentionally non-runnable mid-milestone.

This is the same parent-child binding-stability class as [[move-within-scope-reseal-child-readkey]].

## Solution

Make node identity stable across metadata updates (Phase 64, alongside the move re-seal + rotation hardening):

- Make `nodeId` and `nodeGeneration` **required** on `updateFolderMetadataAndPublish` (CodeRabbit's suggested type change: `nodeId: string`, `nodeGeneration: number`; drop the `?? crypto.randomUUID()` / `?? 0` fallbacks), OR load the current node inside the function and preserve its `id`/`generation` before sealing.
- Thread the stable `id` + current `generation` through all six `client.ts` call sites from the loaded folder state (the client holds the folder's IPNS name + state; it must also carry the node UUID + current generation).
- Add a unit test asserting that an update preserves the folder Node's `id` and does not reset `generation`, and an e2e/integration test that updates a shared folder's metadata and confirms a grantee can still navigate to it from the parent.

## References

- `.planning/phases/63-read-chain-navigation-and-rotation-core/63-CONTEXT.md` (generation single-source-of-truth; the three counters)
- `docs/METADATA_SCHEMAS.md` (node/v3 schema + generation invariant)
- CodeRabbit PR #579 review, `registration.ts:180`
- [[move-within-scope-reseal-child-readkey]]; ROADMAP Phase 64
