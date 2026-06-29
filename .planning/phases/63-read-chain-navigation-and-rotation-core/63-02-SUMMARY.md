---
phase: 63-read-chain-navigation-and-rotation-core
plan: "02"
subsystem: sdk-core/share
tags: [read-grant, ecies, invite-claim, transport-decoupled, tdd]
dependency_graph:
  requires:
    - 63-01 (navigateReadChain — consumes readDescriptorRef produced here)
    - packages/crypto (wrapKey, reWrapKey)
  provides:
    - issueReadGrant (grant issuance primitive — READ-01)
    - claimInviteReadKey (invite re-wrap primitive — READ-05)
    - ReadGrantPayload type (insertShareFn seam)
  affects:
    - Phase 65 (invite service wiring consumes claimInviteReadKey)
    - Phase 66 (shares persistence inserts via insertShareFn contract)
tech_stack:
  added:
    - packages/sdk-core/src/share/grant.ts (new file)
    - packages/sdk-core/src/__tests__/share/grant.test.ts (new file)
  patterns:
    - Transport-decoupled callback seam (insertShareFn — D-05)
    - ECIES wrapKey for grant issuance; reWrapKey for invite claim
    - Zeroization delegated to reWrapKey terminal owner (T-63-05)
    - TDD (10 tests — 5 issueReadGrant, 5 claimInviteReadKey)
key_files:
  created:
    - packages/sdk-core/src/share/grant.ts
    - packages/sdk-core/src/__tests__/share/grant.test.ts
  modified: []
decisions:
  - "Used reWrapKey (not manual unwrapKey + wrapKey) for claimInviteReadKey — delegates intermediate zeroization to reWrapKey's finally block (T-63-05)"
  - "base64 encoding for readDescriptorRef — consistent with navigate.ts (which decodes base64 refs)"
  - "ReadGrantPayload keeps recipientPublicKey as Uint8Array — hex conversion is the service layer's responsibility (Phase 66)"
metrics:
  duration: "~13 minutes"
  completed: "2026-06-29T03:26:09Z"
  tasks_completed: 2
  files_created: 2
  files_modified: 0
  tests_added: 10
status: complete
---

# Phase 63 Plan 02: Read-Grant Issuance and Invite Re-Wrap Summary

ECIES grant issuance and invite-claim re-wrap crypto primitives in `sdk-core/share/grant.ts` with full mocked-API unit coverage.

## What Was Built

### `packages/sdk-core/src/share/grant.ts`

Two exported functions:

**`issueReadGrant`** (READ-01 / §3.2):

- ONE `wrapKey` call encrypts the share-root `readKey` to the recipient's secp256k1 public key.
- The ECIES ciphertext is base64-encoded to `readDescriptorRef`.
- The grant payload is delivered to `insertShareFn` (injected callback — D-05 transport seam).
- Zero node resolves, zero `sealNode`/`unsealNode`, zero IPNS publishes.
- Granting a single-file root is structurally identical to granting a deep folder (READ-01).

**`claimInviteReadKey`** (READ-05 / D-07 / §3.11):

- `reWrapKey` (from `@cipherbox/crypto`) performs the atomic unwrap+rewrap:
  - Unwraps the invite `readDescriptorRef` with the URL-fragment ephemeral private key.
  - Re-wraps the intermediate share-root `readKey` to the claimer's public key.
  - Zeros the intermediate buffer in its own `finally` block (T-63-05 mitigation).
- Returns a standard grant `readDescriptorRef` (same base64 shape as `issueReadGrant` output).
- No per-child key fan-out array — single re-wrapped root readKey only (D-07).

### `packages/sdk-core/src/__tests__/share/grant.test.ts`

10 unit tests across two describe blocks, all mocked (D-05 — no live API):

**`issueReadGrant` (5 tests):**

1. `wrapKey` called exactly once with `(shareRootReadKey, recipientPublicKey)`
2. `insertShareFn` called once with correct payload fields including `readDescriptorRef`
3. Returns `{ shareId, readDescriptorRef }` matching the callback result
4. Folder and single-file root grants produce structurally identical payloads (READ-01)
5. `sealNode`, `resolveIpnsRecord`, `createAndPublishIpnsRecord` never called (zero side effects)

**`claimInviteReadKey` (5 tests):**

1. `reWrapKey` called with decoded invite bytes + caller-supplied keys
2. Return is base64 of `reWrapKey` result
3. Return is a plain string — no `encryptedChildKeys` property (D-07)
4. `reWrapKey` used (not separate `unwrapKey` + `wrapKey`) — intermediate zeroization delegated (T-63-05)
5. No node/IPNS side effects

## Deviations from Plan

### Task 2 TDD Ordering — GREEN Committed Before RED

**Found during:** Task 1 GREEN

**Issue:** `claimInviteReadKey` was implemented in the same `grant.ts` file as `issueReadGrant` during the Task 1 GREEN commit (`91f315b`). The Task 2 RED test commit should have preceded that.

**Fix:** Added Task 2 tests as a separate commit (`85866fe`) after Task 1 GREEN. All tests pass.

**Impact:** The TDD RED gate was skipped for Task 2. The implementation is correct and fully tested. The functions are logically coupled (same file, same encoding helpers), so co-implementation was natural.

**TDD Gate Compliance:**

- Task 1: RED commit `547d38e` (failing — module not found) → GREEN commit `91f315b` (5 tests pass). Compliant.
- Task 2: No separate RED commit. Implementation and tests landed together in `85866fe`. Non-compliant on RED gate; GREEN is verified (10/10 tests pass).

### Auto-fixed Issues

None — plan executed without unexpected bugs or blocking issues.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced.

`grant.ts` is a pure crypto utility (in-memory only). It calls:

- `wrapKey` / `reWrapKey` from `@cipherbox/crypto` (existing vetted crypto)
- `insertShareFn` (injected callback — not wired to any API endpoint this phase)

T-63-05 (intermediate key disclosure) is mitigated: `reWrapKey` zeros the intermediate in its `finally` block.
T-63-07 (per-child key fan-out leakage) is mitigated: `claimInviteReadKey` returns a single `string`, no array.

## Self-Check: PASSED

- `packages/sdk-core/src/share/grant.ts` — EXISTS
- `packages/sdk-core/src/__tests__/share/grant.test.ts` — EXISTS
- Commit `547d38eff` (test RED) — EXISTS
- Commit `91f315b01` (feat GREEN task 1) — EXISTS
- Commit `85866feb0` (feat task 2 tests + comment fix) — EXISTS
- `grep -c 'export async function issueReadGrant' grant.ts` = 1 — PASS
- `grep -c 'export async function claimInviteReadKey' grant.ts` = 1 — PASS
- `grep -c 'encryptedChildKeys' grant.ts` = 0 — PASS
- `grep -c 'enum ' grant.ts` = 0 — PASS
- `pnpm --filter @cipherbox/sdk-core test --run src/__tests__/share/grant.test.ts` — 10/10 PASS
