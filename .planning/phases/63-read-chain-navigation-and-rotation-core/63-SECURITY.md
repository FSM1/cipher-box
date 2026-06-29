---
phase: 63-read-chain-navigation-and-rotation-core
audited: 2026-06-29
asvs_level: 1
block_on: high
threats_total: 27
threats_closed: 27
threats_open: 0
verdict: SECURED
---

# Phase 63 Security Audit — Read-Chain Navigation and Rotation Core

**Auditor:** Claude (gsd-secure-phase)
**Date:** 2026-06-29
**ASVS Level:** 1 (pattern-presence verification)
**Block on:** high severity and above

## Verdict: SECURED

All 27 registered threats verified closed. Zero blocking open threats. Two unregistered surface
observations noted below (non-blocking).

---

## Threat Verification

### Plan 01 — Navigate + Load

| Threat ID | Category | Severity | Disposition | Status | Evidence |
|-----------|----------|----------|-------------|--------|----------|
| T-63-01 | Spoofing | high | mitigate | CLOSED | `navigate.ts` L151: `childRef.generation` (parent mirror) passed to `unsealChildReadKey`, NOT `childPublished.generation`. The generation-source rule (§2.6) is enforced at the single AAD call site in the hop loop. A stale-CID serve fails GCM authentication closed. |
| T-63-02 | Tampering | high | mitigate | CLOSED | No `sealAesGcmAad` / `unsealAesGcmAad` / `buildNodeAad` call in any Phase-63 file (grep returns 0 matches). `navigate.ts` and `engine.ts` call `unsealChildReadKey` / `sealChildReadKey` from `@cipherbox/core` exclusively; the codec is composed, never re-implemented. |
| T-63-03 | Information Disclosure | medium | mitigate | CLOSED | No `console.*` / `logger.*` calls in `navigate.ts`, `grant.ts`, `engine.ts`, `scope.ts`, `load.ts`, `metadata-ops.ts`, or `registration.ts`. No `localStorage` / `sessionStorage` references. No `fill(0)` calls on caller-supplied keys in `navigate.ts`. |
| T-63-04 | Denial of Service | low | accept | CLOSED | Accepted risk — see Accepted Risks section. |

### Plan 02 — Grant Issuance + Invite Claim

| Threat ID | Category | Severity | Disposition | Status | Evidence |
|-----------|----------|----------|-------------|--------|----------|
| T-63-05 | Information Disclosure | high | mitigate | CLOSED | `packages/crypto/src/ecies/rewrap.ts` L43 and L48: `plainKey.fill(0)` executes on BOTH the success path (L43, before `return reWrapped`) and the failure path (catch block L48, conditional on `plainKey !== null`). The intermediate share-root readKey buffer is always zeroed. The code comment in `grant.ts` states "finally block" but the implementation uses try/catch; both paths are covered and the security outcome is equivalent. |
| T-63-06 | Spoofing | medium | accept | CLOSED | Accepted risk — see Accepted Risks section. |
| T-63-07 | Information Disclosure | high | mitigate | CLOSED | `grant.ts` contains 0 matches for `encryptedChildKeys`. `claimInviteReadKey` returns `string` (a single base64 readDescriptorRef), not an array. No per-child key fan-out is produced anywhere in `grant.ts`. |
| T-63-08 | Tampering | low | accept | CLOSED | Accepted risk — see Accepted Risks section. |

### Plan 03 — Rotation Engine

| Threat ID | Category | Severity | Disposition | Status | Evidence |
|-----------|----------|----------|-------------|--------|----------|
| T-63-09 | Elevation of Privilege | high | mitigate | CLOSED | `engine.ts` `rotateReadFromNode` L437: `rotateOne` is called for the root node FIRST, before the BFS frontier is populated. The revoked reader's access is cut at the cheapest commit point per §4.2. |
| T-63-10 | Denial of Service | critical | mitigate | CLOSED | `engine.ts` catch block L392-397: only `readKeyPrime.fill(0)` executes on failure paths. `parentReadKey` is NEVER zeroed anywhere in `rotateOne`. The `RotateOneSkipped` return path also does not zero `parentReadKey`. The comment at L12-19 explicitly documents this rule and cites the prior 48/89 sdk-e2e incident. |
| T-63-11 | Tampering | high | transfer | CLOSED | Transfer to Phase 64 (ROT-05/HIGH-4). Transfer documentation: `engine.ts` L226-232 (`mergeConcurrentChildren` seam throws "not implemented — phase 64 (ROT-05/HIGH-4 concurrent-add merge)"); `63-CONTEXT.md` D-01 explicitly defers this to Phase 64. The gap is surfaced via a named seam rather than silently swallowed. |
| T-63-12 | Spoofing | high | mitigate | CLOSED | `engine.ts` L335-341: `sealChildReadKey` is called with `generationPrime` (= `node.generation + 1`). A holder of the old `readKey` paired with the old generation cannot unseal the rotated node; the GCM tag is bound to the new generation via AAD. |
| T-63-SC | Tampering | n/a | accept | CLOSED | Accepted risk — see Accepted Risks section. |

### Plan 04 — Folder Mutations

| Threat ID | Category | Severity | Disposition | Status | Evidence |
|-----------|----------|----------|-------------|--------|----------|
| T-63-13 | Information Disclosure | high | mitigate | CLOSED | `metadata-ops.ts` L101: exactly ONE `sealChildReadKey` call in `addFilePointerToFolder`, with no per-recipient loop. Existing grant-holders inherit transitive access via the parent readKey chain without any fan-out. |
| T-63-14 | Tampering | medium | mitigate | CLOSED | `registration.ts` L155: `updateFolderMetadataAndPublish` delegates to `publishWithCas` with expected-sequence CAS guard and three-way merge seam. |
| T-63-15 | Spoofing | medium | mitigate | CLOSED | `registration.ts` L87-92: `createAndPublishIpnsRecord` is called with `sequenceNumber: 1n` (embedded verbatim per the Phase-60 strict CAS gate — first publish with embedded seq != 1 is rejected 400). |
| T-63-16 | Information Disclosure | low | mitigate | CLOSED | `registration.ts` L94-101: `createSubfolder` returns `{node, ipnsPrivateKey, rootReadKey, rootWriteKey}` without zeroing any of them. The caller is the terminal owner per D-09. |

### Plan 05 — Scope Predicate + Barrel

| Threat ID | Category | Severity | Disposition | Status | Evidence |
|-----------|----------|----------|-------------|--------|----------|
| T-63-17 | Elevation of Privilege | high | mitigate | CLOSED | `scope.ts` L98-112: `hasCoveringGrant` checks BOTH `activeGrantRootIpnsNames` (relay-supplied completeness aid) AND `localGrantRecord.rootIpnsName` (client-authoritative anti-malicious-relay cross-check) for each ancestor. Either one matching returns true; a relay omitting a grant root is defeated by the local record. |
| T-63-18 | Denial of Service | medium | mitigate | CLOSED | `scope.ts` L149-153: `maybeRotateOnScopeExit` returns `'no-rotation'` WITHOUT calling `deps.rotate` when `!hasCoveringGrant`. The zero-rotation invariant is hard-tested by a `vi.fn()` spy in `scope.test.ts` asserting 0 invocations for a private (no-covering-grant) mutation. |
| T-63-19 | Elevation of Privilege | medium | transfer | CLOSED | Transfer to Phase 68/69 (web/FUSE host). Transfer documentation: `63-CONTEXT.md` D-08 explicitly transfers the "defer rather than skip when the tree cannot be reconciled" policy to the host; `scope.ts` Plan-05 context states this is the caller's responsibility. The engine never assumes a reconciled tree. |
| T-63-20 | Tampering | low | accept | CLOSED | Accepted risk — see Accepted Risks section. |

### Plan 06 — Fan-Out Deletion

| Threat ID | Category | Severity | Disposition | Status | Evidence |
|-----------|----------|----------|-------------|--------|----------|
| T-63-21 | Information Disclosure | high | mitigate | CLOSED | `packages/sdk/src/share/index.ts`: 0 matches for `reWrapForRecipients`. `packages/sdk/src/client.ts`: 0 matches for `reWrapForRecipients` or `reWrapNewItems`. Add-item path delegates to `addFilePointerToFolder` at client.ts L730 and L971. |
| T-63-22 | Tampering | medium | mitigate | CLOSED | SDK typecheck gate passed per VERIFICATION.md; `enumerate-shared-subtree.test.ts` skip removed and passing per 63-06-SUMMARY.md. |
| T-63-23 | Elevation of Privilege | low | mitigate | CLOSED | `packages/sdk/src/types.ts`: 3 matches for `addShareKeys` (callback type, documentation, wiring). Phase-68 layering boundary preserved per D-03. |

### Plan 07 — SDK E2E Round-Trip

| Threat ID | Category | Severity | Disposition | Status | Evidence |
|-----------|----------|----------|-------------|--------|----------|
| T-63-24 | Elevation of Privilege | high | mitigate | CLOSED | `read-chain-navigation.test.ts` is not skipped and asserts post-rotation `navigateReadChain` returns `'behind-retry'` (NOT `'ok'`). Per 63-07-SUMMARY.md: "post-rotation `navigateReadChain` returns `'behind-retry'` (root generation 0→1 > rootExpectedGeneration 0)." Infra override applied (live stack verified by executor). |
| T-63-25 | Tampering | high | mitigate | CLOSED | `read-chain-navigation.test.ts` exercises real IPNS publish/resolve through the live local API (seq 1n first-publish constraint, CAS 1n→2n, rotation CAS 2n→3n). Infra override applied per project convention. |
| T-63-26 | Denial of Service | low | mitigate | CLOSED | Test file runs only `read-chain-navigation.test.ts`, not the full sdk-e2e suite. |

---

## Accepted Risks

| Threat ID | Category | Severity | Rationale |
|-----------|----------|----------|-----------|
| T-63-04 | Denial of Service | low | A malicious relay withholding an IPNS record maps to `{ status: 'revoked' }` (fail-closed). Liveness on rotation is recovered by the caller retrying on `'behind-retry'`. The typed union forces the caller to branch explicitly; there is no ambiguous boolean/null path. Accepted per plan design §4.6. |
| T-63-06 | Spoofing | medium | A replayed ephemeral invite link re-wraps the same root readKey per claimer. Revocation is via rotation (Phase 63/64), not link invalidation. This is the honest threat-model stance per ADR 0002: read-revocation protects future content only, not already-distributed content or previously claimed invite keys. Accepted per §3.11. |
| T-63-08 | Tampering | low | The `readDescriptorRef` is ECIES ciphertext. Tampering by an attacker produces an undecryptable grant; the fail-closed unseal in `navigateReadChain` surfaces a throw (or `'revoked'` if wrapped). No silent success path exists. Accepted per plan. |
| T-63-20 | Tampering | low | Export-only barrels (`share/index.ts`, `rotation/index.ts`, `sdk-core/src/index.ts`) carry no logic. Symbol reachability is gated by the `pnpm --filter @cipherbox/sdk-core typecheck && build` CI check. Accepted per plan. |
| T-63-SC | Tampering | n/a | No external npm/pip/cargo packages were installed during Phase 63 (RESEARCH Package Legitimacy Audit: zero new external dependencies). No supply-chain risk introduced. Accepted per plan. |

---

## Transfer Documentation

| Threat ID | Category | Severity | Transferred To | Documentation |
|-----------|----------|----------|----------------|---------------|
| T-63-11 | Tampering | high | Phase 64 (ROT-05/HIGH-4) | `engine.ts` `mergeConcurrentChildren` seam at L226 throws "not implemented — phase 64 (ROT-05/HIGH-4 concurrent-add merge)"; `63-CONTEXT.md` D-01 explicitly names this seam and its owning phase. |
| T-63-19 | Elevation of Privilege | medium | Phase 68 (web host) / Phase 69 (FUSE host) | `63-CONTEXT.md` D-08: "the 'defer rather than skip when the tree cannot be reconciled' policy is enforced by the CALLER (web Phase 68 / FUSE Phase 69)." The engine accepts reconciliation as a host responsibility and does not assume a reconciled tree. |

---

## Unregistered Flags

New attack surface observed during implementation review that has no threat ID mapping. These are
observations only; none are blocking.

### FLAG-63-U1 — PLACEHOLDER_WRITE_KEY in rotateOne (engine.ts)

**File:** `packages/sdk-core/src/rotation/engine.ts` L329-330

`rotateOne` passes `new Uint8Array(32)` (all-zeros) as the `writeKey` parameter to `sealNode`. This
is safe in Phase 63 because:

1. `unsealNode` is called WITHOUT a `writeKey` (Phase 63 is read-chain only).
2. The resulting unsealed node has no `writeBody` field.
3. `sealNode` (seal.ts L118) only seals a write body when `node.writeBody` is set; with it absent,
   the placeholder `writeKey` is never used.

**Latent risk for Phase 65+:** When `rotateOne` is extended to supply a real `writeKey` (Phase 65),
the placeholder must be replaced. If the code were called on a node with a `writeBody` before Phase
65 wires the real key, that write body would be silently resealed under an all-zeros key. The comment
at engine.ts L324-328 documents this Phase-65 seam explicitly.

**Classification:** Unregistered — informational, no current vulnerability given Phase 63 read-chain scope.

### FLAG-63-U2 — moveItem preserves SealedChildRef sealed under source parent readKey

**File:** `packages/sdk-core/src/folder/metadata-ops.ts` L132-143

`moveItem` moves a `SealedChildRef` from source to destination unchanged. The `readKeySealed`
field was created by `sealChildReadKey(childReadKey, sourceParentReadKey, ...)`. After moving, a
grantee navigating via the destination path would call
`unsealChildReadKey(childRef.readKeySealed, destParentReadKey, ...)`, which fails GCM authentication
because the destination parent's readKey differs from the source parent's readKey.

This is the declared READ-04 "zero re-encryption" design choice for within-scope moves. The design
requires either:
(a) The owner explicitly reseals the SealedChildRef for the new parent after a move (not done in
    Phase 63), or
(b) Moves are restricted to within the same readKey scope (e.g., same grant subtree with a shared
    parent readKey).

**Classification:** Unregistered — correctness/design concern, not a key-material leakage. Flagged
for Phase 64/68 attention. Does not block Phase 63 which covers the read-chain skeleton only.

---

## Audit Notes

### T-63-05 Comment Accuracy (non-blocking observation)

The `@security` JSDoc in `grant.ts` L157 states `reWrapKey` "zeroes the intermediate in a `finally`
block." The actual implementation in `rewrap.ts` uses a try/catch pattern, not try/finally. The
security outcome is identical: `plainKey.fill(0)` is executed on both the success path (L43) and
the failure path (catch L48), with no reachable path that exits without zeroing. The comment
inaccuracy is documentation-only and does not represent a security gap.

### ADR-0002 Honesty (verified)

Rotation protects future navigation and filename visibility. No code in Phase 63 overclaims that
rotation protects already-distributed content or prior IPFS CIDs. `claimInviteReadKey`'s JSDoc
(grant.ts L144) explicitly cites ADR 0002's accepted stance on invite replay.

### ADR-0003 Codec Integrity (verified)

No Phase-63 file reimplements the frozen AAD byte encoding. Every sealed/unsealed operation composes
the `@cipherbox/core` primitives (`sealNode`, `unsealNode`, `sealChildReadKey`, `unsealChildReadKey`,
`sealContent`, `unsealContent`). The grep for `sealAesGcmAad` / `buildNodeAad` in all seven Phase-63
source files returns 0 matches.

---

*Phase: 63-read-chain-navigation-and-rotation-core*
*Audit completed: 2026-06-29*
