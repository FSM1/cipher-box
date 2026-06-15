---
phase: 47
slug: sdk-folder-state-publish-consolidation
status: verified
threats_open: 0
asvs_level: 1
created: 2026-06-15
---

# Phase 47 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
| -------- | ----------- | ------------- |
| sdk-core ↔ in-memory key material | `fileIpnsPrivateKey` passed as `Uint8Array`; must be zeroed after use | Ed25519 IPNS private key (plaintext, in-memory only) |
| sdk-core ↔ CipherBox IPNS publish API | CAS publish crosses to the server with `expectedSequenceNumber` (optimistic concurrency) | IPNS record + expected sequence number |
| share recipient ↔ CipherBox unpin API (DELETE /api/ipfs/:cid) | A recipient may attempt to unpin a CID it does not own; the Phase-42 server guards refcount + ownership | CID identifier (no key material) |
| CipherBoxClient `folderTree` ↔ Zustand store | The client is the single source of truth; `folder:updated` emission drives the store projection | Folder children + `sequenceNumber` |

---

## Threat Register

| Threat ID | Category | Component | Disposition | Mitigation | Status |
| --------- | -------- | --------- | ----------- | ---------- | ------ |
| T-47-01 | Information Disclosure | `updateFileMetadata` key zeroing + new client methods + web hooks | mitigate | `params.fileIpnsPrivateKey.fill(0)` in a `finally` wrapping the `publishWithCas` call in `updateFileMetadata` (`packages/sdk-core/src/file/index.ts:368-372`) runs on all exit paths; `publishWithCas` never zeroes keys (`packages/sdk-core/src/cas.ts:8-9`); new client methods delegate zeroing to `updateFileMetadata`; web hooks zero their own copy in `finally` (`useFileOperations.ts:436-438`, `useFileVersions.ts:110-112`, `:211-213`) | closed |
| T-47-02 | Tampering | CAS sequence handling via `publishWithCas` | mitigate | Loop re-resolves the authoritative `currentSeq` from `resolveIpnsRecord` on each 409; every publish uses `expectedSequenceNumber: currentSeq.toString()`; throws `ConflictError(ipnsName, maxAttempts=4)` on exhaustion (`packages/sdk-core/src/cas.ts:68-123`) | closed |
| T-47-04 | Elevation of Privilege | `updateSharedFile` unpin of `prunedCids` by a share recipient | mitigate | Fire-and-forget `unpinFromIpfs(ctx, cid).catch(...)` loop (no await); the Phase-42 server-side guarded-unpin blocks any cross-user unpin (403 caught and logged, never propagated) (`packages/sdk/src/share/shared-write.ts:461-487`) | closed |
| T-47-05 | Tampering | shared-write callers consuming stale `updatedChildren` | mitigate | `updatedChildren` removed from all four shared-write return objects (lines 227, 328, 366, 397); only `publishedChildren` remains; sdk + web TypeScript compile confirms the sole consumer reads `publishedChildren` | closed |
| T-47-06 | Tampering | folder-state drift between client `folderTree` and the Zustand store | mitigate | New client methods set `folderTree` synchronously after the awaited publish, then emit `folder:updated`; `reconcileFolderState` deleted (repo-wide grep === 0); `ensureFolderRegistered` early-returns; store is projection-only (`packages/sdk/src/client.ts` replaceFile/restoreFileVersion/deleteFileVersion, `apps/web/src/lib/sdk-provider.ts:102-103`) | closed |
| T-47-SC | Tampering | npm/pip/cargo installs (supply chain) | accept | No new packages installed this phase; no install task exists (verified against all five PLAN files and the committed diff) | closed |

_Status: open · closed_
_Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)_

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
| ------- | ---------- | --------- | ----------- | ---- |
| AR-47-SC | T-47-SC | Phase 47 is a pure refactor (CAS unification, folder-state ownership consolidation, pin-leak fix). No new npm/pip/cargo dependencies were added and no install task ran, so the supply-chain attack surface is unchanged from the prior baseline. | gsd-secure-phase (Opus 4.8) | 2026-06-15 |

_Accepted risks do not resurface in future audit runs._

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
| ---------- | ------------- | ------ | ---- | ------ |
| 2026-06-15 | 6 | 6 | 0 | gsd-security-auditor (sonnet) |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-06-15
