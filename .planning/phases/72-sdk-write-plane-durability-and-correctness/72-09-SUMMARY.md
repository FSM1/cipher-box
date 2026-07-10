---
phase: 72-sdk-write-plane-durability-and-correctness
plan: 09
subsystem: sdk-core
tags: [tee, ecies, dedup, refactor, sdk-core]

# Dependency graph
requires:
  - phase: 72-03
    provides: SDK write-plane fixes touching folder/registration.ts (no file overlap with this plan)
  - phase: 72-07
    provides: earlier SC#6 dedup work in this phase's wave sequence
provides:
  - Single wrapIpnsKeyForTee helper (packages/sdk-core/src/tee/wrap.ts) replacing the triplicated TEE fail-closed enrollment wrap
  - Three sdk-core call sites (file/index.ts, vault/index.ts, folder/registration.ts) re-pointed at the shared helper
affects: [sdk-core-tee-enrollment, sc6-dedup-closeout]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Shared TEE-wrap primitive under packages/sdk-core/src/tee/ (borrow-only, D-09-compliant)"

key-files:
  created:
    - packages/sdk-core/src/tee/wrap.ts
  modified:
    - packages/sdk-core/src/file/index.ts
    - packages/sdk-core/src/vault/index.ts
    - packages/sdk-core/src/folder/registration.ts
    - packages/sdk-core/src/index.ts

key-decisions:
  - "Only the shared wrap sequence (hexToBytes -> wrapKey -> bytesToHex) was extracted; each site's own fail-closed validation throws (empty currentPublicKey / non-integer currentEpoch, with call-site-specific error messages) were left in place at the call sites, per the plan's explicit instruction"
  - "vault/index.ts's two root-key wraps (wrapKey(rootReadKey/rootWriteKey, userPublicKey)) were left untouched — only the TEE ipns-key wrap at the former L145-149 was extracted, matching the plan's acceptance criteria"
  - "wrapIpnsKeyForTee re-exported from the sdk-core barrel (src/index.ts) for consistency with other shared sdk-core primitives, even though all three call sites use relative imports"

patterns-established:
  - "Pattern 1: shared crypto-wrap helpers for TEE enrollment live under packages/sdk-core/src/tee/, mirroring the existing folder/vault/file/rotation module split"

requirements-completed: [SC#6]

coverage:
  - id: D1
    description: "wrapIpnsKeyForTee extracted as a single shared helper and all three sdk-core TEE-wrap sites (file/index.ts, vault/index.ts, folder/registration.ts) re-pointed at it, preserving the borrow-only D-09 contract"
    requirement: "SC#6"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/sdk-core test (366 passed, 12 skipped, 31 files passed / 1 skipped)"
        status: pass
      - kind: other
        ref: "grep -c 'wrapKey(' on file/index.ts and folder/registration.ts returns 0 (inline TEE wrap removed); grep -c 'fill(0)' on tee/wrap.ts returns 0 (no zeroing of borrowed buffer)"
        status: pass
    human_judgment: false

# Metrics
duration: 8min
completed: 2026-07-10
status: complete
---

# Phase 72 Plan 09: TEE-Wrap Dedup Summary

**Extracted the triplicated TEE fail-closed enrollment wrap (validate -> hexToBytes -> wrapKey -> bytesToHex) into a single `wrapIpnsKeyForTee` helper in `packages/sdk-core/src/tee/wrap.ts`, re-pointing all three sdk-core sites.**

## Performance

- **Duration:** ~8 min
- **Completed:** 2026-07-10
- **Tasks:** 1
- **Files modified:** 5 (1 created, 4 modified)

## Accomplishments
- Created `packages/sdk-core/src/tee/wrap.ts` exporting `wrapIpnsKeyForTee(ipnsPrivateKey, currentPublicKey)`, the single shared implementation of the ECIES-wrap-under-TEE-public-key sequence
- Re-pointed all three previously-triplicated inline blocks (`file/index.ts` ~L312-313, `vault/index.ts` ~L145-149, `folder/registration.ts` ~L98-101) at the new helper, deleting the duplicated `hexToBytes`/`wrapKey`/`bytesToHex` sequence from each
- Preserved each site's own fail-closed enrollment gate (the `currentPublicKey`/`currentEpoch` validation throws with per-site error messages) unchanged — only the wrap sequence itself moved
- Preserved the D-09 borrow-only contract: the helper never zeroes `ipnsPrivateKey`; the caller remains the terminal owner
- Cleaned up now-unused `wrapKey`/`hexToBytes`/`bytesToHex` imports from `file/index.ts` and `folder/registration.ts` (fully removed) and `vault/index.ts` (removed `bytesToHex`/`hexToBytes`, kept `wrapKey`/`unwrapKey` since vault still wraps `rootReadKey`/`rootWriteKey` under the user's public key elsewhere in the same file — untouched by this plan)
- Re-exported `wrapIpnsKeyForTee` from the sdk-core barrel (`src/index.ts`)

## Task Commits

Each task was committed atomically:

1. **Task 1: Extract wrapIpnsKeyForTee and re-point the three sdk-core sites** - `6a7dad409` (refactor)

**Plan metadata:** (pending — this SUMMARY's commit)

## Files Created/Modified
- `packages/sdk-core/src/tee/wrap.ts` - New shared helper: `wrapIpnsKeyForTee(ipnsPrivateKey, currentPublicKey)`, borrow-only (D-09), doc comment states it never zeroes the caller-owned buffer
- `packages/sdk-core/src/file/index.ts` - `createFileMetadata`'s TEE block re-pointed at `wrapIpnsKeyForTee`; unused crypto imports removed
- `packages/sdk-core/src/vault/index.ts` - `publishEmptyRootNode`'s TEE block re-pointed at `wrapIpnsKeyForTee`; unused `bytesToHex`/`hexToBytes` imports removed (root-key `wrapKey`/`unwrapKey` calls untouched)
- `packages/sdk-core/src/folder/registration.ts` - `createSubfolder`'s TEE block re-pointed at `wrapIpnsKeyForTee`; unused crypto imports removed
- `packages/sdk-core/src/index.ts` - Added barrel export for `wrapIpnsKeyForTee`

## Decisions Made
- Kept each call site's fail-closed validation (empty `currentPublicKey` / non-integer `currentEpoch` checks with function-specific error messages) at the call site rather than folding into the helper, since the plan explicitly scoped extraction to "only the wrap sequence itself" and the three error messages differ per site (`createSubfolder:`, `publishEmptyRootNode:`, `createFileMetadata:` prefixes)
- `hexToBytes` inside the helper still throws on a malformed hex public key, so the fail-closed contract holds end-to-end even though the explicit `currentPublicKey`-empty check lives at the call sites
- Left vault's two `wrapKey(rootReadKey/rootWriteKey, userPublicKey)` calls (a structurally different wrap: user-key-wrapped root keys, not TEE-wrapped IPNS keys) untouched, per the plan's explicit acceptance criteria carve-out

## Deviations from Plan

None - plan executed exactly as written. One wording adjustment: the helper's doc comment initially used the literal substring `.fill(0)` to describe what NOT to do, which would have caused the acceptance criteria's `grep -c 'fill(0)' packages/sdk-core/src/tee/wrap.ts` check to return 1 instead of 0 — reworded the comment to avoid the literal pattern while preserving the same meaning (not a Rule 1-4 deviation; a documentation self-correction to satisfy the plan's own verification command before it was run).

## Issues Encountered
None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- SC#6's sdk-core half is complete: one `wrapIpnsKeyForTee` helper backs all three sdk-core TEE-wrap sites, sdk-core suite green, build clean
- Plan 08 (parallel wave, client.ts/bin.ts SC#6 work) has no file overlap with this plan
- No blockers for subsequent phase-72 plans

---
*Phase: 72-sdk-write-plane-durability-and-correctness*
*Completed: 2026-07-10*
