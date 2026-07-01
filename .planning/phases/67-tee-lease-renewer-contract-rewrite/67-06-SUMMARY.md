---
phase: 67-tee-lease-renewer-contract-rewrite
plan: "06"
subsystem: tee-worker
tags: [security, tee, ipns, crypto, lease-renewer, ed25519]
dependency_graph:
  requires: ["67-02", "67-03"]
  provides: [verify-in-enclave-lease-renewer, tee-route-contract-rewrite]
  affects: [apps/tee-worker/src/routes/republish.ts, apps/tee-worker/src/__tests__/republish.test.ts]
tech_stack:
  added: []
  patterns:
    - "verify-before-decrypt ordering enforced via early-return pattern"
    - "name-key binding via deriveEd25519PublicKey + publicKeyFromIpnsName byte comparison"
    - "per-entry continue-on-failure for batch isolation"
    - "key zeroed in binding-fail branch before continue (not only in catch)"
key_files:
  created: []
  modified:
    - apps/tee-worker/src/routes/republish.ts
    - apps/tee-worker/src/__tests__/republish.test.ts
decisions:
  - "Use continue (early return from per-entry loop) for verify-fail and binding-fail paths, not throw, to keep the metrics.inc() call inline and avoid catch-block ambiguity"
  - "Use deriveEd25519PublicKey from @cipherbox/crypto (already a direct dep) instead of importing @noble/ed25519 directly (not a direct dep of cipherbox-tee-worker)"
  - "Fix binding-mismatch test assertion from not.toContain('key') to toBe exact message — 'key' in 'Name-key binding violation' is descriptive text, not key material"
metrics:
  duration: "~20 minutes"
  completed: "2026-07-01"
  tasks_completed: 1
  files_modified: 2
status: complete
---

# Phase 67 Plan 06: Republish Route Verify-in-Enclave Rewrite Summary

Rewrote the TEE republish route from a record originator (relay supplies CID + seq + epoch scalars) into a verify-in-enclave lease renewer (relay supplies marshaled signedRecord; TEE validates, binds, re-signs same CID + seq with later EOL only).

## What Was Built

**`apps/tee-worker/src/routes/republish.ts`** — complete rewrite of the per-entry signing block:

- `RepublishEntry` reshaped: `{ encryptedIpnsKey, keyEpoch, ipnsName, signedRecord }`. Removed: `latestCid`, `sequenceNumber`, `currentEpoch`, `previousEpoch`.
- `RepublishResult` extended with `requiresReEnroll?: true`.
- Per-entry flow: parse → verify (before decrypt) → decrypt → binding check → re-sign same CID+seq → epoch upgrade → zero key.
- `newSequenceNumber = parsed.sequence.toString()` — no increment (TEE-02 / §7.3 test 12).

**`apps/tee-worker/src/__tests__/republish.test.ts`** — complete rewrite:

- Real IPNS record creation and real ECIES encryption in `makeEntry()` helper.
- `renewIpnsRecord` mocked (re-signing tested in `@cipherbox/core`).
- `decryptWithFallback` / `reEncryptForEpoch` wrapped with `vi.fn()` passthroughs for call-count assertions.
- Tests: no-increment, verify-fail (decrypt spy uncalled), binding-mismatch, re-enroll, epoch upgrade, batch isolation, input validation.

## Security Invariants Verified (§7.3)

| Test | Invariant | Status |
|------|-----------|--------|
| §7.3 test 12 | `newSequenceNumber == String(parsed.sequence)` (no +1) | PROVEN |
| §7.3 test 18a | `verifyIpnsRecordSignature` runs BEFORE `decryptWithFallback`; decrypt spy uncalled on verify-fail | PROVEN |
| §7.3 test 18b | Name↔key binding mismatch rejects without emitting `signedRecord` | PROVEN |
| §7.3 test 19 | `ReEnrollRequiredError` → `requiresReEnroll: true`, safe `error: 'RE_ENROLL_REQUIRED'` string | PROVEN |
| T-67-06-T2 | `parsed.pubKey` never used for binding (uses `deriveEd25519PublicKey` + `publicKeyFromIpnsName`) | STATIC GREP |
| T-67-06-E | Epoch upgrade target = `getInternalCurrentEpoch()`, no relay scalars read | STATIC GREP |
| T-67-06-I | Key zeroed on all paths: success, binding-fail, error catch | CODE REVIEW |

## Verification Results

```
pnpm --filter cipherbox-tee-worker test
Test Files  6 passed (6)
    Tests  74 passed | 8 todo (82)
```

Static greps:

- `grep -nE "\\+ 1n|BigInt\\(entry\\.sequenceNumber\\)|entry\\.latestCid|entry\\.currentEpoch|entry\\.previousEpoch"` → no matches
- `verifyIpnsRecordSignature` at line 108, `decryptWithFallback` at line 122 — verify precedes decrypt
- `publicKeyFromIpnsName` present; `parsed.pubKey` appears only in comments (never as binding source)
- `getInternalCurrentEpoch` used as epoch-upgrade target
- `requiresReEnroll` set in both `RepublishResult` interface and catch block

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Binding-mismatch test assertion too strict**

- **Found during:** GREEN phase first run
- **Issue:** Test asserted `not.toContain('key')` to ensure no key material in error. The safe error string `'Name-key binding violation'` contains the word "key" (as a descriptive term, not key material).
- **Fix:** Changed assertion to `toBe('Name-key binding violation')` — checks the exact safe message.
- **Files modified:** `apps/tee-worker/src/__tests__/republish.test.ts`
- **Commit:** ec37f13a9

**2. [Rule 2 - Missing] `deriveEd25519PublicKey` from `@cipherbox/crypto` used instead of `@noble/ed25519` directly**

- `@noble/ed25519` is not a direct dep of `cipherbox-tee-worker` (only `hashes` and `secp256k1` are in its `@noble` node_modules). `@cipherbox/crypto` re-exports `deriveEd25519PublicKey` which wraps `ed.getPublicKey` with the required `sha512Sync` hook. Using this avoids adding a new direct dependency while ensuring the sync API is correctly configured.

## Commits

- `f883e9173` — `test(67-06): rewrite republish test suite to verify-in-enclave contract`
- `ec37f13a9` — `feat(67-06): rewrite republish route to verify-in-enclave lease renewer`

## Self-Check: PASSED

- [x] `apps/tee-worker/src/routes/republish.ts` exists and modified
- [x] `apps/tee-worker/src/__tests__/republish.test.ts` exists and modified
- [x] Commits f883e9173 and ec37f13a9 exist in git log
- [x] `pnpm --filter cipherbox-tee-worker test` exits 0, all 6 suites green
