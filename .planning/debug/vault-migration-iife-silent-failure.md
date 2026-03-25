---
status: awaiting_human_verify
trigger: 'Vault v2 migration IIFE in useAuth.ts (lines 181-233) never completes. POST /vault/migrate is never called. No console.log or console.warn from migration appears in browser.'
created: 2026-03-24T12:00:00Z
updated: 2026-03-24T12:00:00Z
---

## Current Focus

hypothesis: The IIFE never starts because existingVault.migratedAt is truthy (PATH A taken) OR the IIFE starts but an await hangs forever without resolving/rejecting.
test: Diagnostic console.log added at PATH A/B branch point, IIFE entry, and before/after each await step (8 steps total).
expecting: If "Vault path decision" log shows migratedAtTruthy: true -> PATH A taken, IIFE never starts. If "Migration IIFE started" appears but stops at a step -> that step hangs/errors.
next_action: CHECKPOINT - User must login and report what console.log output they see

## Symptoms

expected: Non-migrated user logs in via PATH B in useAuth.ts. After vault keys are decrypted and set, the fire-and-forget migration IIFE should (1) ECIES-wrap rootFolderKey, (2) resolve IPNS, (3) fetch metadata from IPFS, (4) serialize as v2 blob, (5) upload to IPFS, (6) publish IPNS record, (7) call POST /vault/migrate. Console should show either success or failure log.
actual: Login succeeds, files load fine, but NO migration console output appears at all (neither success nor failure). API server logs show zero calls to /vault/migrate endpoint.
errors: No explicit errors. The IIFE is wrapped in try/catch with console.warn in catch block, but neither log line appears.
reproduction: Login with <myankelev@gmail.com> on <http://localhost:5173> (cipher-box-phase-20 worktree). Check browser console for migration-related logs.
started: First time vault v2 migration has been tested. Code was just written as part of phase 20.

## Eliminated

## Evidence

- timestamp: 2026-03-24T12:00:00Z
  checked: Code structure of IIFE at lines 174-226
  found: The try/catch wraps the ENTIRE IIFE body. There is no code between the async arrow start and the try. Any thrown error (sync or async) MUST be caught by the catch block. The only way for zero output is if (a) the IIFE never starts, or (b) an await hangs forever.
  implication: Silent failure means either the code path bypasses the IIFE entirely or one of the 7 await calls never resolves/rejects.

- timestamp: 2026-03-24T12:01:00Z
  checked: VaultResponseDto.migratedAt type and API serialization
  found: API returns migratedAt as string | null. For non-migrated user, vault.migratedAt is null in DB, toVaultResponse returns null. JavaScript `if (null)` is false, so PATH B should be entered.
  implication: Unless the DB has an unexpected value for migratedAt, the IIFE should be reached. Need runtime verification.

- timestamp: 2026-03-24T12:02:00Z
  checked: hexToBytes behavior with null input
  found: hexToBytes calls hex.startsWith('0x') which would throw TypeError on null. If existingVault.encryptedRootIpnsPrivateKey is null (vault created by phase 20 code which omits this field), decryptVaultKeys would throw, caught by outer catch at line 228, and login would fail.
  implication: Since login succeeds, the user's vault must have non-null encryptedRootIpnsPrivateKey (created by old code). This rules out the null-field crash theory.

- timestamp: 2026-03-24T12:03:00Z
  checked: Whether Blob construction with Uint8Array is correct
  found: `new Blob([v2Blob as BlobPart])` where v2Blob is Uint8Array. Uint8Array implements ArrayBufferView which is a valid BlobPart. The `as BlobPart` cast is unnecessary but harmless. Per apps/web/CLAUDE.md, passing typed arrays directly (not .buffer) is correct.
  implication: Blob construction at step 5 is not the issue.

- timestamp: 2026-03-24T12:04:00Z
  checked: TypeScript compilation
  found: `npx tsc --noEmit` produces zero errors
  implication: No type errors that could cause runtime issues

- timestamp: 2026-03-24T12:05:00Z
  checked: Added diagnostic logging to useAuth.ts
  found: 10 console.log statements added: 1 at path decision (line 111), 1 at IIFE entry (line 182), and 8 around each migration step. These will identify exactly where the execution stops.
  implication: User must login and report output to narrow down the failure point

## Resolution

root_cause:
fix:
verification:
files_changed: []
