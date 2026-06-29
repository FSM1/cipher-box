---
created: 2026-06-29
title: move-within-scope must reseal the child readKey under the new parent (design §3.5)
area: sdk-core
resolves_phase: 64
files:
  - packages/sdk-core/src/folder/metadata-ops.ts
  - packages/sdk-core/src/__tests__/folder.test.ts
---

## Problem

Surfaced by the Phase-63 security audit as **FLAG-63-U2** (non-blocking, deferred to Phase 64/68).

Design §3.5 ("Move within scope") specifies: *"Remove the `SealedChildRef` from the old parent (**reseal** + republish); add it to the new parent (**reseal** + republish). The node keeps its own `readKey`/`generation`."* The "reseal" is required because a `SealedChildRef.readKeySealed` seals the child's `readKey` under the **parent's** `readKey` (via `sealChildReadKey`). The two parents have different `readKey`s.

The Phase-63 `moveItem` (`packages/sdk-core/src/folder/metadata-ops.ts`) is a **pure link rewrite that does NOT call `sealChildReadKey`** (confirmed by the Phase-63 verifier: "moveItem … sealChildReadKey and sealNode not called", and `folder.test.ts` asserts this). It relocates the existing `SealedChildRef` — still sealed under the **source** parent's `readKey` — into the destination parent's child list verbatim.

Consequence: a grantee navigating to the moved node **via the destination path** calls `unsealChildReadKey(readKeySealed, destParentReadKey, …)`, but the ref was sealed under `srcParentReadKey` → AES-GCM AAD authentication fails → navigation breaks for the moved node under the new parent.

Phase 63 matched its (oversimplified) plan/ROADMAP wording "link rewrites only (zero re-encryption)", where "re-encryption" was read as content/body re-encryption only. The app is intentionally non-runnable mid-milestone, so this is not yet exercised end-to-end.

## Solution

In Phase 64 (or wherever the move flow is composed end-to-end), make move-within-scope **re-seal the child `readKey` under the destination parent's `readKey`** before adding the ref to the new parent:

- Compute `newReadKeySealed = sealChildReadKey(childReadKey, destParentReadKey, aad(child.id, child.kind, child.generation))` and store it on the relocated `SealedChildRef`. The child keeps its own `readKey`/`generation` (no content re-encryption, no `fileKey` change) — so "zero re-encryption" of content still holds; only the parent-link seal is rewritten.
- This requires the caller to supply both the source and destination parent `readKey`s (the unwrap of the child readkey at source, the reseal at dest). Decide whether `moveItem` takes these directly or whether the re-seal lives in the higher-level move flow that already holds the parent keys.
- Note the §3.5 "per-grant scope" subtlety (review m2): a move that changes a node's ancestor set must additionally **rotate iff** an active grant sits on an ancestor that is no longer an ancestor (this is the scope-exit predicate `hasCoveringGrant`, already present in `rotation/scope.ts`). The reseal-under-new-parent and the scope-exit-rotation are distinct concerns — both must be wired.
- Add a unit test: move a node to a new parent, then navigate from the destination and assert `'ok'` with the correct recovered content key (currently no test covers dest-path navigation after a move).

## References

- `.planning/design/2026-06-26-sharing-read-keychaining-design.md` §3.5 (move within scope), §3.6 (scope-exit rotation)
- `.planning/phases/63-read-chain-navigation-and-rotation-core/63-SECURITY.md` FLAG-63-U2
- ROADMAP Phase 64 (Rotation Soundness — Revocation Guarantees)
