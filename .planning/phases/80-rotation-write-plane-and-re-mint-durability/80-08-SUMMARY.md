---
phase: 80-rotation-write-plane-and-re-mint-durability
plan: 08
subsystem: ui
tags: [share, recipient-pins, ecies, react, sdk-facade, fail-closed]

# Dependency graph
requires:
  - phase: 80-04
    provides: "client.addRecipientPubkeyPin / client.getRecipientPubkeyPins + sdk-core assertRecipientPinned"
  - phase: 80-07
    provides: "runOwnerReconcile getPinsFn enforcement wired through buildGrantRemintCallbacks"
provides:
  - "ShareDialog issuance-time recipient-pin write (D-03c) on share creation"
  - "ShareDialog fail-closed upgrade-path pin compare (D-03d consumer 3) before re-wrap"
  - "web owner-reconcile.service.ts transport getRecipientPubkeyPins wiring — getPinsFn resolves real pins end-to-end"
  - "@cipherbox/sdk facade re-export of assertRecipientPinned (D-07-compliant web access)"
affects: [share, rotation, owner-reconcile, sdk-e2e]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Web reuses sdk-core pure pin helpers via the @cipherbox/sdk facade re-export (D-07 boundary), never importing @cipherbox/sdk-core directly"
    - "Per-reconcile-pass transport factory closes over the root's shareRootIpnsName to resolve the ipnsName-keyed client pin read from the nodeId-keyed seam"

key-files:
  created: []
  modified:
    - apps/web/src/components/file-browser/ShareDialog.tsx
    - apps/web/src/services/owner-reconcile.service.ts
    - packages/sdk/src/index.ts

key-decisions:
  - "Placed addRecipientPubkeyPin immediately after sharesControllerCreateShare (unconditional, covering both read and write shares) so a pin-write failure throws into the existing catch and surfaces a user error rather than leaving a share silently un-pinned"
  - "Re-exported assertRecipientPinned from the @cipherbox/sdk facade (mirrors the existing selectEncryptionMode re-export) to satisfy the D-07 no-restricted-imports boundary without reimplementing the compare in the web layer"
  - "Built a per-pass makeWebOwnerReconcileTransport factory that closes over the root's shareRootIpnsName — the sdk-core seam threads rootNodeId, but client.getRecipientPubkeyPins is keyed by ipnsName, and each reconcile pass is scoped 1:1 to a single root"

patterns-established:
  - "Pattern 1: D-07-compliant reuse of a pure sdk-core helper in apps/web = re-export from the @cipherbox/sdk facade, then import from the facade"
  - "Pattern 2: getPinsFn seam (nodeId-keyed) → web transport resolves via the reconcile pass's fixed shareRootIpnsName to the ipnsName-keyed client read"

requirements-completed:
  - "SC2 / D-03c (web issuance): ShareDialog writes the pasted recipient pubkey into the shared node's owner-sealed write-body pin list at grant creation"
  - "SC2 / D-03d (consumer 3 of 3): the web upgrade path verifies the server-fed recipient pubkey against the pin before re-wrapping, and the web owner-reconcile path delegates to the enforced runOwnerReconcile"

coverage:
  - id: D1
    description: "ShareDialog.handleShare commits the pasted recipient pubkey to the node's owner-sealed write-body pin list on share creation (both read and write shares) — D-03c issuance write"
    requirement: "SC2 / D-03c (web issuance)"
    verification:
      - kind: manual_procedural
        ref: "Create a share to a recipient pubkey, then read back the node's pins (getRecipientPubkeyPins) to confirm the pubkey is present — requires a running web + API + IPFS stack"
        status: unknown
    human_judgment: true
    rationale: "apps/web has no unit tests (logic lives in sdk-core, UI covered by main-push web-e2e); runtime confirmation needs the full dev stack + a real recipient pubkey, out of scope for this scoped-verification executor"
  - id: D2
    description: "ShareDialog.handleUpgrade fails closed on relay substitution — assertRecipientPinned against getRecipientPubkeyPins BEFORE resolveShareEncryptedWriteKey re-wrap (D-03d consumer 3)"
    requirement: "SC2 / D-03d (consumer 3 of 3)"
    verification:
      - kind: manual_procedural
        ref: "Attempt a read→write upgrade with a tampered recipientPublicKey → confirm the UI shows the upgrade-failure error and no re-wrap occurs"
        status: unknown
    human_judgment: true
    rationale: "Same as D1 — no web unit tests; the fail-closed path is exercised by tests/sdk-e2e (the pre-ship gate) and web-e2e on main push, neither run here per scoped-verification constraints"
  - id: D3
    description: "web owner-reconcile.service.ts transport supplies getRecipientPubkeyPins so runOwnerReconcile's 80-07 getPinsFn enforcement resolves real pins end-to-end (no more fail-closed-on-absent-seam)"
    requirement: "SC2 / D-03d (consumer 3 of 3)"
    verification:
      - kind: unit
        ref: "packages/sdk/src/share/owner-reconcile.ts buildGrantRemintCallbacks getPinsFn seam (unit-tested in sdk); web wrapper now satisfies the required transport method — typecheck confirms the OwnerReconcileTransport contract is met"
        status: pass
    human_judgment: false
  - id: D4
    description: "@cipherbox/sdk facade re-exports assertRecipientPinned so the web upgrade path reuses the sdk-core compare without violating the D-07 import boundary"
    requirement: "SC2 / D-03d (consumer 3 of 3)"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/web exec tsc -b (pass) + eslint no-restricted-imports (pass) — the facade import resolves and satisfies D-07"
        status: pass
    human_judgment: false

# Metrics
duration: 20min
completed: 2026-07-12
status: complete
---

# Phase 80 Plan 08: Web recipient-pin issuance write + D-03d consumer 3 Summary

**ShareDialog now writes the recipient pin at share creation (D-03c) and fail-closed-verifies the server-fed recipient against it before the upgrade re-wrap (D-03d), and the web owner-reconcile transport supplies getRecipientPubkeyPins so the 80-07 getPinsFn enforcement resolves real pins end-to-end.**

## Performance

- **Duration:** ~20 min
- **Started:** 2026-07-12
- **Completed:** 2026-07-12
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- **D-03c issuance write:** `ShareDialog.handleShare` calls `getSdkClient().addRecipientPubkeyPin(item.ipnsName, recipientPublicKey)` immediately after `sharesControllerCreateShare`, committing the pasted recipient pubkey to the node's owner-sealed write-body pin list for both read and write shares. The issuance-time wraps (:184/:205) remain untouched — the pin is first written here, so they stay exempt.
- **D-03d consumer 3 (upgrade path):** `ShareDialog.handleUpgrade` fetches the node's pins via `getRecipientPubkeyPins(item.ipnsName)` and calls the shared sdk-core `assertRecipientPinned` (reused through the facade — not reimplemented) BEFORE `resolveShareEncryptedWriteKey`. On mismatch/absent pin it throws into the existing upgrade-failure catch (fail-closed, no re-wrap). The server-fed `share.recipientPublicKey` decode is unchanged; only the re-wrap is gated.
- **owner-reconcile transport wiring:** replaced the module-level `webOwnerReconcileTransport` with a `makeWebOwnerReconcileTransport(shareRootIpnsName)` factory that adds `getRecipientPubkeyPins`, so `runOwnerReconcile`'s 80-07 `getPinsFn` seam resolves real pins instead of failing closed on the previously-absent optional method.

## Task Commits

Both tasks committed together in a single commit (the two ShareDialog edits + the transport wiring + the facade re-export are one cohesive fail-closed enforcement change), with the SUMMARY in the same commit per plan constraint 4.

1. **Task 1 + Task 2: D-03c issuance write + D-03d upgrade compare + reconcile transport wiring** — see commit below (feat)

## Files Created/Modified

- `apps/web/src/components/file-browser/ShareDialog.tsx` — issuance pin write in `handleShare`; fail-closed `getRecipientPubkeyPins` + `assertRecipientPinned` compare in `handleUpgrade` before the re-wrap; added `bytesToBase64` (crypto) and `assertRecipientPinned` (sdk facade) imports.
- `apps/web/src/services/owner-reconcile.service.ts` — replaced the static transport with a per-pass `makeWebOwnerReconcileTransport(shareRootIpnsName)` factory that wires `getRecipientPubkeyPins`; updated both call sites (eager login sweep + opportunistic per-folder).
- `packages/sdk/src/index.ts` — D-07-compliant facade re-export of `assertRecipientPinned` from `@cipherbox/sdk-core`.

## Decisions Made

- Unconditional `addRecipientPubkeyPin` after `createShare` (covers both read and write branches with one call) — placed inside the existing `try` so a failure surfaces the user-facing error instead of a silently un-pinned share.
- Reused `assertRecipientPinned` via a new `@cipherbox/sdk` facade re-export rather than importing `@cipherbox/sdk-core` directly (blocked by the D-07 `no-restricted-imports` eslint rule) and rather than reimplementing the compare (prohibited by the plan).
- Per-pass transport factory closing over `shareRootIpnsName` to bridge the seam's `nodeId` key to the client's `ipnsName` key — each reconcile pass is scoped to exactly one root, making the mapping 1:1.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Reused assertRecipientPinned via a @cipherbox/sdk facade re-export**
- **Found during:** Task 2 (upgrade-path compare)
- **Issue:** The plan directed importing `assertRecipientPinned` for the web compare, but `apps/web/src` is blocked from importing `@cipherbox/sdk-core` directly by the D-07 `no-restricted-imports` eslint rule, and the facade did not yet re-export it.
- **Fix:** Added `export { assertRecipientPinned } from '@cipherbox/sdk-core';` to `packages/sdk/src/index.ts` (mirroring the existing `selectEncryptionMode` re-export) and imported it from `@cipherbox/sdk` in ShareDialog. No compare logic reimplemented.
- **Files modified:** packages/sdk/src/index.ts, apps/web/src/components/file-browser/ShareDialog.tsx
- **Verification:** `tsc -b` and `eslint` (incl. no-restricted-imports) pass on the touched web files; sdk facade builds clean.
- **Committed in:** part of the plan commit.

---

**Total deviations:** 1 auto-fixed (1 blocking — necessary D-07-compliant wiring to reuse the helper).
**Impact on plan:** The facade re-export is a third modified file beyond the two in `files_modified`, but it is the minimal, precedent-following way to satisfy both "reuse the sdk-core helper" and the D-07 boundary. No API/DTO/DB change; no scope creep.

## Issues Encountered

- **Type bridging:** `client.getRecipientPubkeyPins` returns `Uint8Array[]` while `assertRecipientPinned` expects base64 `string[]` (its stored-pin encoding). Resolved by `pins.map(bytesToBase64)` in ShareDialog — the same normalization sdk-core's engine applies to `getPinsFn` output. The reconcile transport returns raw bytes as the seam expects (sdk-core normalizes internally).
- **No `typecheck` script on apps/web:** web typechecks via `tsc -b` (inside `build`). Ran `pnpm --filter @cipherbox/web exec tsc -b` directly for the type gate.

## Verification Results

- `pnpm --filter @cipherbox/web exec tsc -b` → exit 0 (clean)
- `eslint` on `ShareDialog.tsx` + `owner-reconcile.service.ts` → 0 problems (after the facade fix)
- `eslint` on `packages/sdk/src/index.ts` → 0 problems
- Dependency dists rebuilt (`@cipherbox/core`, `@cipherbox/sdk-core`, `@cipherbox/sdk`, `@cipherbox/api-client`) so the web typecheck sees the new facade export
- No `packages/api-client/` changes (no api:generate); no DB migration

## Human Verification Required

Per constraint 1 (apps/web has no unit tests; web-e2e is a main-push gate and was NOT run; sdk-e2e NOT run here), runtime confirmation is deferred:

1. Create a share to a recipient pubkey → confirm the share succeeds and the node's pin list (via `getRecipientPubkeyPins`) includes that pubkey (D1).
2. Attempt a read→write upgrade with a tampered/mismatched `recipientPublicKey` → confirm the UI shows the fail-closed upgrade error and no re-wrap occurs (D2).

The authoritative pre-ship gate is `tests/sdk-e2e` (live client→API IPNS round-trip); web-e2e runs on main push.

## D-03d Wiring Confirmation (all three points in place)

1. **Issuance pin write** — `ShareDialog.handleShare` → `addRecipientPubkeyPin(item.ipnsName, recipientPublicKey)` after createShare. ✅
2. **Upgrade-path assertRecipientPinned** — `ShareDialog.handleUpgrade` → `getRecipientPubkeyPins` + `assertRecipientPinned` before `resolveShareEncryptedWriteKey`, fail-closed. ✅
3. **web owner-reconcile getRecipientPubkeyPins transport** — `makeWebOwnerReconcileTransport(shareRootIpnsName).getRecipientPubkeyPins` → `client.getRecipientPubkeyPins`, satisfying the 80-07 `getPinsFn` seam end-to-end. ✅

## Next Phase Readiness

- D-03d now has all three enforcement consumers wired (80-06 Rust, 80-07 TS re-mint, 80-08 web). The web issuance write (D-03c) and the third fail-closed consumer are complete.
- Pre-ship: `tests/sdk-e2e` must pass (key-lifecycle change) before this branch ships.

---
*Phase: 80-rotation-write-plane-and-re-mint-durability*
*Completed: 2026-07-12*
