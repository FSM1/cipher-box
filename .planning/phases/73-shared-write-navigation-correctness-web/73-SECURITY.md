---
phase: 73-shared-write-navigation-correctness-web
status: secured
asvs_level: 1
block_on: high
threats_total: 17
threats_closed: 17
threats_open: 0
audited: 2026-07-10
verdict: SECURED
---

# Phase 73 Security Audit: Shared-Write Navigation Correctness (Web)

## Summary

All 17 threats across plans 73-01 through 73-09 are CLOSED. Verdict: SECURED.

- 12 `mitigate` threats verified present in the implemented code (grep + L2 boundary
  check of the cited files).
- 5 `accept` threats have documented rationale and their code behavior confirms the
  accept is legitimate (no latent data-plane surface).
- `threats_open` = 0. No open threat at or above the `block_on: high` threshold.

Every one of the four security properties named in the audit brief is confirmed:

1. ROT-07 anti-rollback floor is enforced on all three non-listing read facades
   (`resolveFileMetadata`, `downloadFromIpns`, `resolveNodeIdentity`) — each now routes
   through `gatedResolveChild`, which fails closed on `!signatureVerified` before any
   floor mutation and gates via `RotationHighWater.enforceResolved`.
2. The sdk-core 410 catch maps ONLY `status === 410` to `tombstoned: true`; every other
   status/error `throw`s unchanged — no silent swallow of publish failures.
3. No key material is logged or persisted insecurely — the two new/adjacent `logger.error`
   sites emit the caught `Error` object, never a key buffer.
4. The caller-owns-key zeroization convention (D-05 / D-09) is respected: the new sdk-core
   try/catch adds zero key-zeroing, and every web write/nav key buffer is zeroed on every
   exit path, with clones used at each transfer to avoid use-after-free.

## Configuration

- ASVS level: 1 (project default; grep-level presence, with L2 boundary checks applied to
  the high-severity gate and zeroization threats).
- `block_on`: high (default). Only OPEN threats with severity high or critical count toward
  `threats_open`. There are none.

## Threat Verification

| Threat ID | Category | Severity | Disposition | Status | Evidence |
|-----------|----------|----------|-------------|--------|----------|
| T-73-01-01 | Repudiation | low | accept | CLOSED | Test-only fixme scaffolds (tests/web-e2e/*.spec.ts); security-relevant assertions enforced by impl plans' own verify. Accepted risk logged below. |
| T-73-02-01 | Tampering | medium | mitigate | CLOSED | packages/sdk-core/src/ipns/index.ts:110-122 — only `status === 410` returns `{tombstoned:true}`; `throw error` for all else. |
| T-73-02-02 | Information Disclosure | high | mitigate | CLOSED | packages/sdk-core/src/ipns/index.ts:53-64 callee-owns-key contract preserved verbatim; new catch (110-122) adds no `.fill(0)` on `ipnsPrivateKey`. |
| T-73-03-01 | Tampering | low | accept | CLOSED | SharedFolderRow.tsx:116-133 drag `type` classification is a UI/DnD hint; drop handler does not act on `DragItem.type`. Accepted risk logged below. |
| T-73-04-01 | Tampering | high | mitigate | CLOSED | packages/sdk/src/client.ts:1325, 4225, 4288 — all three facades route through `gatedResolveChild` (860-889: fail-closed on `!signatureVerified` then `enforceResolved`). |
| T-73-04-02 | Spoofing | medium | mitigate | CLOSED | client.ts:1322-1327 — `nodeId`/`kind` read from `gatedResolveChild(childRef).published`, not a raw resolve; caller threads full `SealedChildRef` (useSharedWriteOps.ts:38). |
| T-73-05-01 | Tampering | medium | mitigate | CLOSED | client.ts:5184-5188 — `tombstoned` returned only when `pubResult.tombstoned === true`; `if (!pubResult.success) throw` for generic failures. |
| T-73-05-02 | Tampering | high | mitigate | CLOSED | client.ts:5647 monotonicity guard (`state.sequenceNumber >= result.sequenceNumber` → early return) gates the new `resolvePublishedNode` (5674) + `publishedParent` adopt (5676-5680). |
| T-73-06-01 | Information Disclosure | medium | mitigate | CLOSED | useSharedNavigationActions.ts folderKey `.fill(0)` sites preserved across the restore consolidation (495-499 root; 546-551 restore/discard). |
| T-73-06-02 | Tampering | low | accept | CLOSED | Dead `getShareKeys`/`ShareKeyCache` folder-ipns path removed (useSharedNavigation.ts); path always yielded a zero buffer, changing no authorization outcome. Accepted risk logged below. |
| T-73-07-01 | Information Disclosure | high | mitigate | CLOSED | zeroWriteKey on new-share entry (useSharedNavigationActions.ts:302), navigate-to-root loop (496-501), restore discard loop (547-551); unmount cleanup (useSharedNavigation.ts:308-315). Clones at transfer avoid use-after-free (445, 823, 836-838). |
| T-73-07-02 | Tampering | medium | mitigate | CLOSED | writeKey captured from existing helpers `resolveSharedSubfolderWriteKey` (438) / `resolveSharedRootWriteKey` (289, 819); restore TRANSFERS `target.writeKey` (564), never re-invents. |
| T-73-07-03 | Elevation of Privilege | low | accept | CLOSED | useSharedNavigationActions.ts:287-303 — read-only grants keep `writeKey = null`; write gating unchanged. Accepted risk logged below. |
| T-73-08-01 | Denial of Service | medium | mitigate | CLOSED | useMutationFailureUx.ts:193 `_afterRefresh` guard bounds refresh to one automatic retry (retry sets `_afterRefresh:true` at 224); Phase 73 only supplies the supplier (useSharedWriteOps.ts), file unchanged. |
| T-73-08-02 | Repudiation | low | mitigate | CLOSED | useSharedWriteOps.ts — `runWithFailureUx({refreshWriteAccess})` wired into `runWrite`, `updateSharedFile`, `moveInSharedFolder`; classifier reachable from real failures. |
| T-73-09-01 | Tampering | high | mitigate | CLOSED | Same guard as T-73-05-02 (client.ts:5647); refresh-after-restore relies on the unchanged sequenceNumber monotonicity guard (useSharedNavigationActions.ts:594-608 doc). |
| T-73-09-02 | Denial of Service | low | accept | CLOSED | One extra IPNS resolve per up/breadcrumb restore; guard no-ops cheaply. Flagged-not-blocking (Assumption A1). Accepted risk logged below. |

## Accepted Risks Log

| Threat ID | Risk | Rationale (L1 accept) |
|-----------|------|-----------------------|
| T-73-01-01 | e2e regression cases are fixme placeholders in the scaffold plan | Security-relevant assertions (SC1 write-key retention, SC4 classifier reachability) are enforced by the impl plans' own verify (73-07/73-08/73-09), not the scaffold. No package installs; supply-chain checkpoint N/A. |
| T-73-03-01 | Drag-payload `type` (file/folder) is a client-side DnD hint | The shared drop handler does not read `DragItem.type` for any data-plane action; a wrong kind is a display-only defect with no crypto/authz surface. Fix (`isFileRefResolved`) corrects the latent display bug. |
| T-73-06-02 | Removal of the dead `getShareKeys`/`ShareKeyCache` folder-ipns path | The removed path always yielded a zero buffer (the `fetchShareKeys` stub returns `[]` for folder-ipns lookups); real write signing keys come from the SDK write-body, so removal changes no authorization outcome. |
| T-73-07-03 | Read-only grants keep a null writeKey in the nav stack | Read-only grants carry no `encryptedWriteKey` to unwrap, so `currentWriteKeyRef` stays `null`; UI write gating (`permission==='write'`) is unchanged, so no read-only depth gains write. |
| T-73-09-02 | One additional IPNS resolve per up/breadcrumb navigation | Latency-only concern (Assumption A1); the monotonicity guard no-ops cheaply when nothing changed. Flagged for revisit if resolve latency proves costly — non-blocking. |

## Unregistered Flags

None. No `## Threat Flags` section is present in any 73-0*-SUMMARY.md (this project does not
use that summary convention), so there is no unmapped new attack surface to log. All
security-relevant deltas are covered by registered threats above.

## Auditor Observations (non-blocking, no disposition change)

These do not open any threat; they are noted for the record because the FORCE stance
requires surfacing anything that touches a trust boundary.

- `refreshSharedFolder`'s new `publishedParent` resolve (client.ts:5674) uses a raw
  `resolvePublishedNode`, not `gatedResolveChild`. This is consistent with the declared
  mitigation (T-73-05-02 gates on the sequence-number monotonicity guard, not on signature
  re-verification of the parent envelope), and any subsequent shared write CAS-protects at
  publish time via `expectedSequenceNumber`. The listing state it feeds is already
  protected by the 5647 guard. No action required at L1; a future hardening could route the
  parent re-resolve through the gate for defense-in-depth.
- `gatedResolveChild`'s fail-closed signature check is contingent on
  `this.config.rotationHighWater` being configured (client.ts:866). This matches every
  other listing gate in the file (dfsFindFolder et al.) and is the established codebase
  pattern; the web app configures `rotationHighWater`, so the three facades inherit the
  same fail-closed guarantee as listing. No divergence introduced by Phase 73.

## Verdict

SECURED. 17/17 threats CLOSED, 0 open at or above the `block_on: high` threshold. Phase 73
may ship on security grounds.
