---
phase: 67-tee-lease-renewer-contract-rewrite
plan: "04"
subsystem: sdk-core/folder
tags: [tee, ipns, ecies, subfolder-enrollment, tdd]
dependency_graph:
  requires: [67-01, 67-03]
  provides: [subfolder-tee-enrollment]
  affects: [sdk-core/folder/registration.ts]
tech_stack:
  added: []
  patterns: [ecies-wrap, fail-closed-validation, d09-terminal-owner]
key_files:
  created:
    - packages/sdk-core/src/folder/registration.test.ts
  modified:
    - packages/sdk-core/src/folder/registration.ts
decisions:
  - "ECIES-wrap of the generated IPNS private key is done in createSubfolder itself (not in the caller) — matches the pattern in vault-settings.service.ts and sdk/bin/index.ts"
  - "Fail-closed: throw before publish when currentPublicKey is empty or currentEpoch is non-finite, not after"
  - "D-09: ipnsPrivateKey not zeroed in createSubfolder; wrapKey is a callee that reads but does not consume caller-owned buffers"
metrics:
  duration: "140 seconds"
  completed: "2026-07-01"
  tasks_completed: 1
  files_changed: 2
status: complete
---

# Phase 67 Plan 04: Wire teeKeys ECIES-Wrap into createSubfolder Summary

**One-liner:** `createSubfolder` now ECIES-wraps the generated IPNS private key under the TEE public key and forwards `encryptedIpnsPrivateKey`/`keyEpoch` to the first publish, closing the silent-expiry enrollment gap for new subfolders.

## What Was Built

`createSubfolder` in `packages/sdk-core/src/folder/registration.ts` previously accepted `teeKeys` but never acted on it (the comment said "not wired yet"). The subfolder's first IPNS record was published without `encryptedIpnsPrivateKey`/`keyEpoch`, so the `ipns_records` row was missing the data the TEE renewer needs — causing silent expiry after 24 hours.

After this plan:

- When `teeKeys` is supplied, `createSubfolder` validates it fail-closed (throws if `currentPublicKey` is empty or `currentEpoch` is non-finite), then ECIES-wraps the fresh `ipnsPrivateKey` under `hexToBytes(teeKeys.currentPublicKey)` via `wrapKey`, converts the result with `bytesToHex`, and passes `encryptedIpnsPrivateKey`/`keyEpoch` into `createAndPublishIpnsRecord`.
- The returned object now includes `encryptedIpnsPrivateKey` and `keyEpoch` so callers can store them.
- When `teeKeys` is omitted, behavior is unchanged: the publish and return carry no TEE fields.
- Caller-owned keys (`ipnsPrivateKey`, `readKey`, `writeKey`) are not zeroed (D-09 terminal-owner convention).

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 (RED) | Failing tests for TEE key wiring | 090796901 | packages/sdk-core/src/folder/registration.test.ts |
| 1 (GREEN) | Wire teeKeys ECIES-wrap into createSubfolder | 1be967184 | packages/sdk-core/src/folder/registration.ts |

## Deviations from Plan

None — plan executed exactly as written.

## Security Invariants Verified

- **Fail-closed:** `currentPublicKey` empty or `currentEpoch` non-finite → throws before `createAndPublishIpnsRecord` is called.
- **Zero-knowledge:** server receives only the hex-encoded ECIES ciphertext; plaintext `ipnsPrivateKey` never leaves the client.
- **D-09:** `wrapKey` is a callee — it reads but does not consume the buffer. `ipnsPrivateKey` not zeroed.
- **Phase-60 gate:** `sequenceNumber: 1n` preserved on the first publish.

## TDD Gate Compliance

- RED commit: `090796901` — `test(67-04): add failing RED tests for createSubfolder TEE key wiring`
- GREEN commit: `1be967184` — `feat(67-04): wire teeKeys ECIES-wrap into createSubfolder publish`
- 4/4 cases passing after GREEN; full sdk-core suite (324 tests) clean.

## Self-Check: PASSED

- `packages/sdk-core/src/folder/registration.test.ts` — FOUND
- `packages/sdk-core/src/folder/registration.ts` — FOUND (wrapKey imported, "not wired yet" removed)
- Commit `090796901` — FOUND
- Commit `1be967184` — FOUND
- `pnpm --filter @cipherbox/sdk-core test -- registration` exits 0, 4 cases pass
