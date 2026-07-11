---
phase: 77-crypto-hygiene-and-terminology-canonicalization
plan: 05
subsystem: crypto
tags: [ecies, tee, sdk-core, terminology-canonicalization, hex-boundary]

# Dependency graph
requires:
  - phase: 72-tee-fail-closed-enrollment
    provides: wrapIpnsKeyForTee helper (hex-in/hex-out) shared across folder/vault/file TEE enrollment
provides:
  - "wrapIpnsKeyForTee(ipnsPrivateKey: Uint8Array, teePublicKey: Uint8Array): Promise<Uint8Array> — bytes-in/bytes-out, canonical teePublicKey param name"
  - "Hex-at-boundary convention applied to the TEE-wrap seam: hex lives only at the 3 call sites (registration.ts, vault/index.ts, file/index.ts)"
  - "ECIES round-trip test proving no behavior change"
affects: [77-09-file-index-terminology, 77-10-folder-registration-terminology]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Bytes-internal / hex-at-boundary: crypto helpers accept/return Uint8Array; hex encode/decode happens only at the wire/DTO boundary in call sites"

key-files:
  created:
    - packages/sdk-core/src/tee/__tests__/wrap.test.ts
  modified:
    - packages/sdk-core/src/tee/wrap.ts
    - packages/sdk-core/src/folder/registration.ts
    - packages/sdk-core/src/vault/index.ts
    - packages/sdk-core/src/file/index.ts

key-decisions:
  - "Used a secp256k1 keypair (via @noble/secp256k1, matching apps/tee-worker's real TEE key type and packages/crypto's ecies.test.ts pattern) for the round-trip test instead of the Ed25519 keypair mentioned in the plan's read_first — TEE public keys are secp256k1 (ECIES), not Ed25519 (IPNS identity); an Ed25519 keypair would not round-trip through wrapKey/unwrapKey."
  - "Reworded a JSDoc comment on wrap.ts to avoid the literal string 'hexToBytes' so the file satisfies the plan's exact acceptance-criteria grep (grep -c \"hexToBytes\\|bytesToHex\" wrap.ts == 0) while still documenting the caller's fail-closed hex-decode behavior."

patterns-established:
  - "TEE-wrap hex boundary: hex-decode teeKeys.currentPublicKey immediately before calling wrapIpnsKeyForTee, hex-encode the returned bytes immediately before assigning to encryptedIpnsPrivateKey — decode happens before any crypto op so a malformed key fails at hexToBytes, not inside wrapKey."

requirements-completed: [SC3]

coverage:
  - id: D1
    description: "wrapIpnsKeyForTee is bytes-in/bytes-out with canonical teePublicKey param; ECIES round-trip proven via new test"
    requirement: "SC3"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/tee/__tests__/wrap.test.ts#round-trips a 32-byte ipnsPrivateKey through ECIES wrap/unwrap"
        status: pass
    human_judgment: false
  - id: D2
    description: "All 3 callers (registration.ts, vault/index.ts, file/index.ts) hex-decode the TEE public key before calling and hex-encode the wrapped result into encryptedIpnsPrivateKey; sdk-core typechecks and the full unit suite passes with no behavior change"
    requirement: "SC3"
    verification:
      - kind: unit
        ref: "pnpm --filter @cipherbox/sdk-core test (370 passed, 12 skipped)"
        status: pass
      - kind: other
        ref: "pnpm --filter @cipherbox/sdk-core typecheck"
        status: pass
    human_judgment: false

# Metrics
duration: 20min
completed: 2026-07-11
status: complete
---

# Phase 77 Plan 05: TEE-wrap bytes-in/bytes-out Summary

**`wrapIpnsKeyForTee` is now bytes-in/bytes-out with the canonical `teePublicKey` param, and hex encode/decode moved out to its 3 call sites in sdk-core.**

## Performance

- **Duration:** ~20 min
- **Completed:** 2026-07-11T08:52:57Z
- **Tasks:** 2
- **Files modified:** 4 (1 created, 4 modified: wrap.ts, registration.ts, vault/index.ts, file/index.ts — wrap.ts counted in both)

## Accomplishments
- `wrapIpnsKeyForTee` signature changed from `(ipnsPrivateKey: Uint8Array, currentPublicKey: string): Promise<string>` to `(ipnsPrivateKey: Uint8Array, teePublicKey: Uint8Array): Promise<Uint8Array>` — no internal hex encoding/decoding, param renamed to the canonical `teePublicKey`.
- New round-trip test (`wrap.test.ts`) proves the wrapped ciphertext still ECIES-unwraps back to the original bytes via the real `wrapKey`/`unwrapKey` primitives.
- All 3 callers (`folder/registration.ts`, `vault/index.ts`, `file/index.ts`) now hex-decode `teeKeys.currentPublicKey` immediately before calling the helper and hex-encode the returned bytes immediately before assigning to `encryptedIpnsPrivateKey`.
- `TeeKeys.currentPublicKey: string` (hex) in `types.ts` left unchanged, as specified — only the internal helper switched to bytes.
- The 3 out-of-scope inline TEE-wrap duplicates (`packages/sdk/src/client.ts`, `packages/sdk/src/bin/index.ts`, `apps/web/src/services/vault-settings.service.ts`) were deliberately left untouched per the plan's scope decision.

## Task Commits

Each task was committed atomically (TDD task split into RED + GREEN commits):

1. **Task 1: Round-trip test for bytes-in/bytes-out wrapIpnsKeyForTee (RED)** - `b80036cb1` (test)
2. **Task 1: bytes-in/bytes-out signature change (GREEN)** - `b2f3aac3d` (feat)
3. **Task 2: Move the hex boundary to the 3 callers** - `251d5f388` (feat)

**Plan metadata:** (this commit, following SUMMARY.md)

_Note: TDD Task 1 produced two commits (test → feat) per the RED/GREEN gate protocol._

## Files Created/Modified
- `packages/sdk-core/src/tee/__tests__/wrap.test.ts` - New round-trip test: generates a secp256k1 TEE keypair, wraps a 32-byte key, asserts `Uint8Array` return, and asserts `unwrapKey` round-trips to the original bytes.
- `packages/sdk-core/src/tee/wrap.ts` - Bytes-in/bytes-out signature; removed internal `hexToBytes`/`bytesToHex`; param renamed `currentPublicKey` -> `teePublicKey`; JSDoc updated.
- `packages/sdk-core/src/folder/registration.ts` - `createSubfolder` now hex-decodes `currentPublicKey` before calling `wrapIpnsKeyForTee` and hex-encodes the result into `encryptedIpnsPrivateKey`.
- `packages/sdk-core/src/vault/index.ts` - `publishEmptyRootNode` now hex-decodes/encodes at the same boundary.
- `packages/sdk-core/src/file/index.ts` - `createFileMetadata` now hex-decodes/encodes at the same boundary.

## Decisions Made
- Used a secp256k1 keypair for the round-trip test (matching the TEE's actual key type in `apps/tee-worker/src/services/tee-keys.ts` and `packages/crypto/src/__tests__/ecies.test.ts`), rather than `generateEd25519Keypair` as the plan's `read_first` note suggested — TEE public keys are secp256k1/ECIES, not Ed25519/IPNS-identity, and an Ed25519 keypair would not round-trip through `wrapKey`/`unwrapKey`.
- Reworded a JSDoc comment on `wrap.ts` (removed the literal substring `hexToBytes`) so the file satisfies the plan's exact acceptance-criteria grep for "bytes-only" while still documenting that the caller's hex-decode step fails closed on malformed input.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Corrected the test keypair type from Ed25519 to secp256k1**
- **Found during:** Task 1 (writing the round-trip test)
- **Issue:** The plan's `read_first` note referenced `generateEd25519Keypair` for building the test TEE keypair, but `wrapKey`/`unwrapKey` (ECIES) operate on secp256k1 keypairs — the real TEE worker (`apps/tee-worker/src/services/tee-keys.ts`) derives secp256k1 keys, and `packages/crypto`'s own ECIES test uses `@noble/secp256k1`. An Ed25519 keypair would not round-trip through the ECIES primitives.
- **Fix:** Used `@noble/secp256k1` to generate the test keypair (`secp256k1.utils.randomPrivateKey()` / `secp256k1.getPublicKey(privateKey, false)`), matching `packages/crypto/src/__tests__/ecies.test.ts`'s established pattern.
- **Files modified:** `packages/sdk-core/src/tee/__tests__/wrap.test.ts`
- **Verification:** Round-trip test passes; `unwrapKey(wrapped, teeKeypair.privateKey)` deep-equals the original bytes.
- **Committed in:** `b80036cb1` (Task 1 RED commit)

**2. [Rule 1 - Bug] Removed a stray `hexToBytes` mention from wrap.ts's JSDoc**
- **Found during:** Task 2 (verifying acceptance criteria)
- **Issue:** A doc comment referencing `hexToBytes` by name caused `grep -c "hexToBytes\|bytesToHex" wrap.ts` to return 1 instead of the required 0, even though no actual hex logic remained in the file.
- **Fix:** Reworded the comment to say "the caller's hex-decode step" instead of naming the function.
- **Files modified:** `packages/sdk-core/src/tee/wrap.ts`
- **Verification:** `grep -c "hexToBytes\|bytesToHex" packages/sdk-core/src/tee/wrap.ts` returns 0.
- **Committed in:** `251d5f388` (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (2 Rule 1 bug fixes, both scoped to test/doc correctness)
**Impact on plan:** No scope creep — both fixes are within the plan's stated files and preserve the plan's literal acceptance criteria.

## Issues Encountered
None beyond the two auto-fixed deviations above.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- `wrapIpnsKeyForTee` and its 3 callers are ready as a stable base for Plan 77-09 (file/index.ts terminology) and Plan 77-10 (folder/registration.ts terminology) — both edit these same files in a later wave and should rebase on top of this commit's changes.
- The 3 inline TEE-wrap duplicates in `packages/sdk/src/client.ts`, `packages/sdk/src/bin/index.ts`, and `apps/web/src/services/vault-settings.service.ts` remain un-consolidated (documented, out of scope) — a future phase may want to route them through `wrapIpnsKeyForTee` as well.

---
*Phase: 77-crypto-hygiene-and-terminology-canonicalization*
*Completed: 2026-07-11*

## Self-Check: PASSED
