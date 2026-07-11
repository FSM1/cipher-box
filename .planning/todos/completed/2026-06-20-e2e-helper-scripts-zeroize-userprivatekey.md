---
created: 2026-06-20
title: Zeroize userPrivateKey and subFolderKey in E2E helper scripts
area: test-infra
phase: 55-or-later
files:
  - packages/sdk-core/scripts/verify-filepointer.ts
  - packages/sdk-core/scripts/edit-filepointer.ts
resolves_phase: 77
---

## Problem

CodeRabbit (during Phase 54 ship) flagged that several E2E helper scripts derive a `userPrivateKey` (and `verify-filepointer.ts` additionally an unwrapped `subFolderKey`) from auth data but never zero those Uint8Arrays from memory after use:

- `verify-filepointer.ts` — neither `userPrivateKey` nor `subFolderKey` is cleared.
- `edit-filepointer.ts` — clears `fileKey`, `fileIpnsPrivateKey`, and `rootIpnsKeypair.privateKey`, but NOT `userPrivateKey`.

`rename-folder.ts` already clears both `rootIpnsKeypair.privateKey` and `userPrivateKey` (`clearBytes(userPrivateKey)`), so it is the reference pattern.

## Important: PRE-EXISTING, not a Phase 54 regression

This gap existed verbatim in the original `.mjs` scripts on `origin/main` before the Phase 54 TypeScript migration:

- `verify-filepointer.mjs` (origin/main): 0 `.fill(0)`/`clearBytes` calls.
- `edit-filepointer.mjs` (origin/main): zeroed `fileKey`/`fileIpnsPrivateKey`/`rootIpnsKeypair.privateKey` only — never `userPrivateKey`.

Phase 54 was behavior-preserving (D-07): the `.ts` files keep the exact zeroization counts of their `.mjs` originals (verify 0=0, edit 3=3, rename 2=2). So this was deferred out of Phase 54's scope (migration, not security hardening of dev-only test tooling). Low real-world risk: these are local dev/CI test scripts that exit immediately after a single run, not shipped to users.

## Solution

Wrap each script's main logic in a `try`/`finally` and, in the `finally`, zero the sensitive Uint8Arrays following the `rename-folder.ts` pattern:

- `verify-filepointer.ts`: `clearBytes(userPrivateKey)`; clear `subFolderKey` (and `fileFolderKey` if it aliases a separate buffer) once `loadFolderMetadata` returns.
- `edit-filepointer.ts`: `clearBytes(userPrivateKey)` in the existing cleanup path alongside the already-cleared keys.

Verify with the desktop E2E `run-all.sh` against a live stack (behavior must be unchanged) and `pnpm typecheck && pnpm lint`. Consider routing all four scripts through the shared `tests/e2e-helpers/auth.ts` so cleanup is centralized.
