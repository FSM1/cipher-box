---
phase: 79
slug: web-kind-discrimination-completion-and-deferred-test-revival
status: verified
# threats_open = count of OPEN threats at or above workflow.security_block_on severity (the blocking gate)
threats_open: 0
asvs_level: 1
created: 2026-07-12
---

# Phase 79 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| SDK-unsealed Node → ResolvedChild projection | `resolveChildren()` already unseals an access-controlled Node for kind/modifiedAt/size; the phase surfaces one more already-decrypted field (`createdAt`) off the same object | Already-decrypted, already-access-controlled Node metadata |
| SDK ResolvedChild map → web dialog/label/sort/drag UI | The web reads a pre-resolved kind projection; it makes no independent classification and crosses no new untrusted boundary | Read-only `kind` / `createdAt` projection |
| useFolderStore tree → recursive folder-delete cleanup | Local in-memory store mutation walking `parentId` links | Local store entries, no network/authorization surface |
| Test harness → sdk-core/core/web hook logic under test | Unit tests exercise already-shipped contracts against mocked clients | No runtime/attacker surface |

---

## Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation | Status |
|-----------|----------|-----------|----------|-------------|------------|--------|
| T-79-01 | Information Disclosure | `createdAt` projection on ResolvedChild | low | accept | Field is already-decrypted, already-access-controlled Node data; surfacing it adds no new disclosure surface | closed |
| T-79-02 | Tampering | folder-identity re-key temptation (useFolderNavigation) | medium | mitigate | Delete-not-act the `Node.id` TODO; identity stays `ipnsName`-keyed; NON-CHANGE recorded in 79-02-SUMMARY and code doc-comment | closed |
| T-79-03 | Repudiation | updateFileMetadata rollback-guard coverage | low | mitigate | Legacy CAS suite retired with rationale; equivalent CURRENT-contract coverage exists at `file/file-node.test.ts:317` | closed |
| T-79-04 | Tampering | drop-target gating (file accepted as a container) | low | mitigate | `onDrop`/`onExternalFileDrop` gated on `isFileRefResolved`; map-miss defaults folder-safe; upload rows short-circuit to file | closed |
| T-79-05 | Tampering | SharedMoveDialog move cycle-guard (file wrongly disabling destinations) | low | mitigate | Guard set filtered to folder-kind items via `isFileRefResolved` (`SharedMoveDialog.tsx:107-108`) | closed |
| T-79-06 | Tampering | MoveDialog move cycle-guard (file wrongly disabling destinations) | low | mitigate | Guard set filtered to folder-kind items (`MoveDialog.tsx:61-64`) | closed |
| T-79-07 | Information Disclosure | dialog label mislabels kind | low | accept | Cosmetic only; share/permission authorization is unchanged | closed |
| T-79-08 | Information Disclosure | stale descendant FolderNode after parent delete | low | mitigate | `collectDescendantFolderIds` BFS recursively purges descendant store entries by `parentId` (`useFolderMutations.ts:83`) so no stale entry survives the `isLoaded` fast path | closed |
| T-79-09 | Tampering | folder-identity re-key temptation in mutation recursion | medium | mitigate | Recursion walks `parentId` only; store entries stay keyed by `result.ipnsName`; explicitly no `Node.id` re-key | closed |
| T-79-10 | Repudiation | shared-move handler coverage | low | mitigate | `moveItemHandler`/`batchMoveItemsHandler` suites un-skipped; assert `client.moveInSharedFolder` argument contract (15 tests pass) | closed |
| T-79-SC | Tampering | npm/pip/cargo installs | low | accept | No package installs this phase; no supply-chain checkpoint required | closed |

*Status: open · closed · open — below high threshold (non-blocking)*
*Severity: critical > high > medium > low — only open threats at or above workflow.security_block_on (high) count toward threats_open*
*Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| AR-79-01 | T-79-01 | `createdAt` is already-decrypted, already-access-controlled Node data; no new disclosure surface | gsd-secure-phase | 2026-07-12 |
| AR-79-02 | T-79-07 | Dialog kind label is cosmetic; share/permission authorization logic is untouched | gsd-secure-phase | 2026-07-12 |
| AR-79-03 | T-79-SC | No dependencies added/changed this phase; supply-chain checkpoint N/A | gsd-secure-phase | 2026-07-12 |

*Accepted risks do not resurface in future audit runs.*

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-07-12 | 11 | 11 | 0 | gsd-secure-phase (ASVS L1, short-circuit: register authored at plan time, no open threats at/above block threshold) |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-07-12
