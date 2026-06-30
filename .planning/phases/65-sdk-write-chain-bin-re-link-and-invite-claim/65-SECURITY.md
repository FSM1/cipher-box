---
phase: 65
slug: sdk-write-chain-bin-re-link-and-invite-claim
asvs_level: 1
block_on: high
threats_total: 29
threats_closed: 29
threats_open: 0
status: SECURED
audited: 2026-06-30
---

# Phase 65 — Security Audit

**Phase:** 65 — SDK Write-Chain, Bin Re-link, and Invite Claim
**Requirements:** WRITE-01, WRITE-02, WRITE-03, WRITE-04
**ASVS Level:** 1 (grep-level presence checks; no explicit config block in plan files — defaulted)
**Block-on threshold:** high (default)

## Verdict: SECURED

All 29 threats CLOSED. `threats_open = 0`.

---

## Threat Verification

| Threat ID | Plan | Category | Severity | Disposition | Status | Evidence |
|-----------|------|----------|----------|-------------|--------|----------|
| T-65-01 | 01 | Elevation of Privilege | high | mitigate | CLOSED | `sealChildWriteKey` exports `buildNodeAad(... 0x04)` — seal.ts:250 |
| T-65-02 | 01 | Tampering | high | mitigate | CLOSED | Role byte `0x04` at seal.ts:250,276; cross-role rejection test in `seal-write-chain.test.ts` |
| T-65-03 | 01 | Tampering | medium | mitigate | CLOSED | `buildNodeAad(childId, kb, childGeneration, 0x04)` at seal.ts:250 — AAD binds exact child identity |
| T-65-04 | 01 | Denial of Service | medium | mitigate | CLOSED | "Do NOT zero childWriteKey: caller is terminal owner (D-09)" at seal.ts:252 |
| T-65-05 | 02 | Information Disclosure | high | mitigate | CLOSED | `nodeReadKey` on `BinEntry` (bin/types.ts:72); `encryptBinMetadata` seals blob at bin/index.ts:95 |
| T-65-06 | 02 | Tampering | medium | mitigate | CLOSED | `sealChildReadKey(entry.nodeReadKey, targetFolder.folderKey, ...)` at bin/index.ts:436 |
| T-65-07 | 02 | Elevation of Privilege | medium | **accept** | CLOSED | Accepted residual — see Accepted Risks below |
| T-65-08 | 02 | Denial of Service | medium | mitigate | CLOSED | `folderState.folderKey` (caller-owned) never zeroed in bin/index.ts; D-09 rule honored |
| T-65-09 | 03 | Information Disclosure | high | **accept** | CLOSED | Accepted by design — see Accepted Risks below |
| T-65-10 | 03 | Spoofing | medium | mitigate | CLOSED | `claimInvite` calls `claimInviteReadKey` re-wrapping the same readKey; no link-invalidation path (grant.ts:302-306) |
| T-65-11 | 03 | Information Disclosure | medium | mitigate | CLOSED | "ephemeralPrivateKey and claimerPublicKey are NEVER zeroed here (D-09)" at grant.ts:189; `reWrapKey` zeros the intermediate |
| T-65-12 | 03 | Tampering | low | mitigate | CLOSED (below threshold) | Grep gate clean: zero `encryptedChildKeys` in non-test sdk-core/sdk source |
| T-65-13 | 04 | Elevation of Privilege | **critical** | mitigate | CLOSED | `unsealNode(published, readKey)` → `writeBody undefined` asserted at shared-write.test.ts:161; write-body reachable only with writeKey (test line 165) |
| T-65-14 | 04 | Tampering | high | mitigate | CLOSED | `SealedChildRef` type has no `writeKeySealed` field (types.ts:83-104); `shared-write.ts:351,490` comment "no write field — NODE-03" |
| T-65-15 | 04 | Tampering | high | mitigate | CLOSED | `CannotWriteUntilRefetchError` exported at shared-write.ts:136; thrown at lines 238, 348, 487 on `{ tombstoned: true }` |
| T-65-16 | 04 | Information Disclosure | medium | mitigate | CLOSED | Minted `childReadKey`/`childWriteKey` zeroed in `catch` blocks at shared-write.ts:390 |
| T-65-17 | 05 | Tampering | high | mitigate | CLOSED | `PLACEHOLDER_WRITE_KEY` has 0 occurrences in engine.ts; fail-closed guard at engine.ts:590-598 |
| T-65-18 | 05 | Tampering | high | mitigate | CLOSED | `unsealNode(published, parentReadKey, nodeWriteKey)` at engine.ts:563; write-body-reseal.test.ts asserts ipnsPrivateKey preserved |
| T-65-19 | 05 | Spoofing | high | mitigate | CLOSED | "no valid IPNS private key for" guard retained at engine.ts:582 |
| T-65-20 | 05 | Denial of Service | medium | mitigate | CLOSED | "NEVER zeroed by rotateOne — caller is terminal owner (D-09)" at engine.ts:212,259 |
| T-65-21 | 06 | Tampering | **critical** | mitigate | CLOSED | `generateEd25519Keypair()` per node at engine.ts:1298; `teeUnenrollFn(oldIpnsName)` at engine.ts:1374 |
| T-65-22 | 06 | Elevation of Privilege | high | mitigate | CLOSED | `deleteWriteGrantFn(grant.shareId)` for revoked at engine.ts:1444; only survivors get `wrapKey(newWriteKey)` at engine.ts:1449 |
| T-65-23 | 06 | Tampering | high | mitigate | CLOSED | "Process write children recursively FIRST (child-first / bottom-up)" at engine.ts:1221; child published before parent re-points |
| T-65-24 | 06 | Spoofing | high | mitigate | CLOSED | `sequenceNumber: 1n` in `createAndPublishIpnsRecord` call at engine.ts:1367 |
| T-65-25 | 06 | Information Disclosure | medium | mitigate | CLOSED | `newWriteKey.fill(0)` at engine.ts:1389; `newKeypair.privateKey.fill(0)` at engine.ts:1390 in catch block |
| T-65-26 | 06 | Tampering | medium | mitigate | CLOSED | No readKey minted in `rotateWriteFromNode`/`rotateWriteSubtree`; read-plane invariance asserted in write-revocation.test.ts |
| T-65-27 | 07 | Tampering | high | mitigate | CLOSED | `write-chain-rotation.test.ts` exists; `rotateWriteFromNode` called at line 334 against live API fixture |
| T-65-28 | 07 | Spoofing | medium | mitigate | CLOSED | `sequenceNumber: 1n` in `publishWriteCapableNode` helper; live API would reject otherwise |
| T-65-29 | 07 | Elevation of Privilege | medium | mitigate | CLOSED | No references to apps/api, apps/web, crates/fuse in write-chain-rotation.test.ts; files_modified confirmed to one suite file + sdk-core barrel export |

---

## Accepted Risks

### T-65-07 — Q3 Cross-principal Sub-share Exposure Window

- **Category:** Elevation of Privilege
- **Severity:** medium
- **Disposition:** accept
- **Decision ref:** D-01 (CONTEXT.md §Q3), Plan 02 threat model

When write-recipient C deletes or bins a node that the owner independently sub-shared to a third party D, C unlinks immediately (holds folder write keys) but cannot cryptographically revoke D — only the owner holds rotation authority. D retains read access to the now-binned snapshot until the owner's next online reconcile. `addToBin` performs no cross-principal revoke attempt and adds no new schema marker per D-01.

**Bound:** the marginal exposure is the navigation/future-write window. The binned content is already irreducibly readable via IPFS (per ADR 0002); the window closes on the owner's reconcile-rotation (Phases 66/68). Accepted as a documented residual — adding a cross-principal revoke would leak share-existence to a delegate (rejected option (b)) or require new signed-request plumbing (deferred to future phase).

### T-65-09 — Invite Link Carries Root readKey by Design

- **Category:** Information Disclosure
- **Severity:** high
- **Disposition:** accept
- **Decision ref:** §3.11, ADR 0002, Plan 03 threat model

A v3 invite link conveys the share-root readKey in the URL fragment (ECIES-wrapped to an ephemeral keypair). Anyone who obtains the link can claim the subtree-root readKey. This is the intended design — the link is the credential. The exposure is bounded to the granted subtree. Revocation is achieved by rotating the readKey (`rotateWriteFromNode` / Plan 06), which cuts the link and all claimers simultaneously. No link-invalidation mechanism is implemented or planned (ADR 0002).

---

## Unregistered Threat Flags

None. All seven SUMMARY.md `## Threat Flags` / `## Threat Surface Scan` sections explicitly report no new attack surface beyond the registered threat register. No unregistered flags.

---

## Key Security Invariants Verified

### WRITE-01: Read/Write Key Separation

`unsealNode(publishedNode, readKey)` (no writeKey) returns a node whose `writeBody` is `undefined`. Ed25519 signing material (`writeBody.ipnsPrivateKey`) is unreachable to a read-only holder. Proven by real crypto test at `packages/sdk/src/__tests__/shared-write.test.ts:161`.

The write link (`WriteChildRef.writeKeySealed`) is sealed with role `0x04` under the parent `writeKey`, separate from the role `0x02` read link sealed under the parent `readKey`. `SealedChildRef` has no write fields (types.ts:83-104).

### D-06: Independent Read/Write Planes

Read-rotation (`rotateReadFromNode`) re-seals write-body under the **same** `writeKey` (no write-plane rotation). Write-rotation (`rotateWriteFromNode`) mints new `writeKey'/k51` but never touches `readKey` or `generation`. The two planes are mechanically independent. Verified by `write-body-reseal.test.ts` (read-rotation preserves write plane) and `write-revocation.test.ts` (write-rotation leaves read plane unchanged).

### D-09: Terminal-Owner Zeroization

Callee functions never zero caller-supplied key buffers. Only minted intermediate/child keys are zeroed in `catch` blocks on failure paths. Documented in code comments across seal.ts, engine.ts, grant.ts, shared-write.ts, and bin/index.ts.

### WRITE-02/03/04: rotateWriteFromNode Correctness

Per node: new Ed25519 keypair + new k51 name + new 32-byte writeKey minted. Child-first cascade ensures parent re-points reference already-published child names. First-publish at `sequenceNumber: 1n` (strict IPNS gate). `teeUnenrollFn` fires per old name (tombstone-intent). Revoked grant is dropped via `deleteWriteGrantFn`; survivors receive `wrapKey(newWriteKey, recipientPublicKey)` into a fresh `writeDescriptorRef`. All of this is asserted by the D-04 live-API round-trip at `tests/sdk-e2e/src/suites/write-chain-rotation.test.ts`.
