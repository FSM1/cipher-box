---
phase: 44
slug: ipns-conflict-handling
status: verified
threats_open: 0
asvs_level: 1
created: 2026-06-14
---

# Phase 44 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
| -------- | ----------- | ------------- |
| decrypted metadata → merge functions | Two writers' decrypted `FolderChild[]` / `FileMetadata` cross into the pure `mergeChildren` / file-merge logic; malformed/missing fields must not crash or silently drop entries | Plaintext child/file metadata (high) |
| client → CipherBox IPNS publish API (folder + file) | CAS (`expectedSequenceNumber`) is the only server-side lost-update guard; server self-increments seq and does not verify IPNS signatures | Encrypted metadata CID + sequence number |
| remote writer's metadata → local conflict merge | Concurrent writer's decrypted metadata is re-fetched on 409 and merged before republish (never republish stale CID) | Plaintext `FolderChild[]` / `FileMetadata` (high) |
| write-share recipient → owner's folder IPNS | Multiple writers mutate one folder; `baseChildren` drives three-way merge so deletes are honored instead of resurrected | Plaintext `FolderChild[]` + base snapshot |
| sdk-core public API → sdk + web consumers | Return-shape widening (`publishedChildren`); consumers must adopt it or the lost-update fix is inert | Merged child set (in-memory contract) |
| ConflictError → web conflict UX | Unresolved conflicts must reach the user (sync banner), not vanish into a swallowed catch | Conflict signal (`ipnsName` / `attempts` / `seq` only — no plaintext) |
| updateFileMetadata return → web unpin loop | `prunedCids` returned by sdk-core are unconditionally unpinned by web hooks; any still-referenced CID in that list is destructive | CID list (pin references) |

---

## Threat Register

| Threat ID | Category | Component | Disposition | Mitigation | Status |
| --------- | -------- | --------- | ----------- | ---------- | ------ |
| T-44-01 | Information Disclosure | ConflictError shape | mitigate | `packages/sdk-core/src/errors.ts:8-22` — carries only `ipnsName`/`attempts`/`lastRemoteSeq`, no child data; test `folder-merge.test.ts:47-53` | closed |
| T-44-02 | Tampering (data loss) | mergeChildren branch logic | mitigate | `packages/sdk-core/src/folder/merge.ts:38-61` — all branch permutations; matrix test `folder-merge.test.ts:74-174` | closed |
| T-44-03 | Denial of Service | mergeChildren malformed input | mitigate | `packages/sdk-core/src/folder/merge.ts:46,49,59` — `?? 0` default on `modifiedAt`; total function; test `folder-merge.test.ts:138-148` | closed |
| T-44-04 | Tampering (data loss) | updateFolderMetadataAndPublish 409 path | mitigate | `packages/sdk-core/src/folder/index.ts:235-252` — re-resolve + `mergeChildren` before republish; test `folder.test.ts:231-280` | closed |
| T-44-05 | Denial of Service (livelock) | folder retry loop | mitigate | `packages/sdk-core/src/folder/index.ts:205` cap 4; `:41-43` exp backoff + ±50% jitter; test `folder.test.ts:315-343` | closed |
| T-44-06 | Repudiation / replay | folder sequence number | accept | Server self-increments DB seq (known protocol divergence `ipns.service.ts:543`); re-resolve + re-sign each attempt; protocol fix out of scope | closed |
| T-44-07 | Tampering (wrong key) | re-encrypt merged folder metadata | mitigate | `packages/sdk-core/src/folder/index.ts:211` — `encryptFolderMetadata(metadata, params.folderKey)` inside retry loop on every attempt | closed |
| T-44-08 | Information Disclosure | ConflictError on exhaustion | mitigate | `packages/sdk-core/src/folder/index.ts:237,265,274` — all throw sites pass only safe fields | closed |
| T-44-09 | Tampering (TOCTOU / data loss) | updateFileMetadata CAS | mitigate | `packages/sdk-core/src/file/index.ts:292-298` — `expectedSequenceNumber` CAS; loser→VersionEntry `:332-342`; both dirs tested `file.test.ts:237-336` | closed |
| T-44-10 | Denial of Service (version bloat) | versions[] growth | mitigate | `packages/sdk-core/src/file/index.ts:29,242,344` — `maxVersionsPerFile` cap; overflow → `prunedCids`; test `file.test.ts:129-148` | closed |
| T-44-11 | Tampering (replay) | file sequence number | accept | Same server self-increment divergence as folders; re-resolve + re-sign; protocol fix out of scope | closed |
| T-44-12 | Tampering (wrong key) | re-encrypt merged file metadata | mitigate | `packages/sdk-core/src/file/index.ts:368` — `encryptAndUpload(mergedMetadata, params.folderKey, ...)` before second publish | closed |
| T-44-13 | Denial of Service (livelock) | file conflict retry | mitigate | `packages/sdk-core/src/file/index.ts:386-391` — bounded to 2 attempts then ConflictError; test `file.test.ts:444-474` | closed |
| T-44-14 | Tampering (data loss) | shared-write union fallback | mitigate | `packages/sdk/src/share/shared-write.ts:202-210,299-307,358-367,390-399` — all four mutators pass `baseChildren: swCtx.children` (D-08) | closed |
| T-44-15 | Information Disclosure / leak | shared-write prunedCids drop | accept | Pre-existing Phase-42 deferred leak (`shared-write.ts:updateSharedFile`); not regressed; full fix out of scope | closed |
| T-44-16 | Denial of Service | unhandled ConflictError | accept | Intentionally propagates to web conflict surfaces (D-05); not swallowed in `useSharedWriteOps.ts` | closed |
| T-44-17a | Tampering (data loss) | web folder re-publish union fallback | mitigate | `apps/web/src/hooks/useFileOperations.ts:458-466` — `baseChildren: parentFolder.children` switches 409 path to three-way merge | closed |
| T-44-18a | Information Disclosure | ConflictError in web logs | mitigate | `apps/web/src/hooks/useFileOperations.ts:472-479` — `isConflictExhausted`-gated logging, safe fields only; double-publish removed | closed |
| T-44-19a | Tampering (version cap bypass) | web maxVersionsPerFile | mitigate | `apps/web/src/hooks/useFileOperations.ts:429` — sources `maxVersionsPerFile` from vault settings store, not sdk-core default | closed |
| T-44-17b | Tampering (silent data loss) | updateFolderMetadataAndPublish return contract | mitigate | `packages/sdk-core/src/folder/index.ts:197,230` returns `publishedChildren`; adopted at `client.ts:429,519,582-586,644,793,1055`; test `folder.test.ts:365-410` (CR-01) | closed |
| T-44-18b | Tampering (data loss) | folder:updated event children field | mitigate | `packages/sdk/src/events.ts:30-35` — event carries `children`; all emit sites pass merged `publishedChildren` | closed |
| T-44-19b | Repudiation / silent failure | ConflictError swallowed by new caller wiring | accept | No new try/catch swallows ConflictError; exhaustion still surfaces to caller (D-05) | closed |
| T-44-20 | Tampering (data destruction) | prunedCids accumulation in file 409 path | mitigate | `packages/sdk-core/src/file/index.ts:361-365` — filter `prunedCids` against referenced-CID Set (cid + versions[].cid) before return (CR-02) | closed |
| T-44-21 | Information Disclosure (test blind spot) | shallow conflict tests | mitigate | `packages/sdk-core/src/__tests__/file.test.ts:338-442` — asserts loser cid preserved + `prunedCids ∩ refs = ∅` (WR-08) | closed |
| T-44-SC(06) | Tampering (supply chain) | package installs (plan 06) | accept | No new package installs (pure source edits); package legitimacy gate N/A | closed |
| T-44-SC(07) | Tampering (supply chain) | package installs (plan 07) | accept | No new package installs (pure source + test edits); package legitimacy gate N/A | closed |

_Status: open · closed_
_Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)_
_Note: plans 05 and 06 independently reused IDs T-44-17/18/19; disambiguated here as `a` (plan 05) and `b` (plan 06)._

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
| ------- | ---------- | --------- | ----------- | ---- |
| AR-44-01 | T-44-06 | Server self-increments IPNS seq in DB (protocol divergence `ipns.service.ts:543`); mitigated operationally by re-resolving authoritatively and re-signing each attempt. Correcting the protocol is the hardening thread (CONTEXT line 16), out of scope. | phase-44 plan author | 2026-06-14 |
| AR-44-02 | T-44-11 | Same server self-increment divergence for per-file IPNS records; same operational mitigation and out-of-scope rationale as AR-44-01. | phase-44 plan author | 2026-06-14 |
| AR-44-03 | T-44-15 | Pre-existing Phase-42 deferred `prunedCids` leak in shared-write update path; this phase must not regress it (verified not regressed). Full fix deferred. | phase-44 plan author | 2026-06-14 |
| AR-44-04 | T-44-16 | ConflictError intentionally propagates to web conflict surfaces (sync banner) rather than being swallowed — surfacing over silent failure is the desired behavior (D-05). | phase-44 plan author | 2026-06-14 |
| AR-44-05 | T-44-19b | New caller wiring adds no try/catch that swallows ConflictError; exhaustion still surfaces via existing conflict UX (D-05). | phase-44 plan author | 2026-06-14 |
| AR-44-06 | T-44-SC(06) | Plan 06 introduced zero new package installs (pure source edits within existing deps); no new supply-chain surface. | phase-44 plan author | 2026-06-14 |
| AR-44-07 | T-44-SC(07) | Plan 07 introduced zero new package installs (pure source + test edits within existing deps); no new supply-chain surface. | phase-44 plan author | 2026-06-14 |

_Accepted risks do not resurface in future audit runs._

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
| ---------- | ------------- | ------ | ---- | ------ |
| 2026-06-14 | 26 | 26 | 0 | gsd-security-auditor (sonnet) |
| 2026-06-14 | 1 (post-audit) | 1 | 0 | CodeRabbit CLI re-review → fix `9f3c56181` |

Breakdown: 19 `mitigate` verified present in implementation (file:line evidence above) + 7 `accept` documented in the Accepted Risks Log. Auditor verdict: SECURED. No unregistered threat flags; all SUMMARY.md threat flags map to registered IDs.

### Post-Audit Findings (CodeRabbit CLI, 2026-06-14)

A CodeRabbit CLI review of the phase-44 diff, run **after** the SECURED verdict above, surfaced one critical data-loss bug the gsd-security-auditor missed:

- **Critical — local version history lost when the remote wins a file conflict.** `updateFileMetadata`'s 409 merge passed `remoteMeta.versions` (not `loser.versions`) as the second `mergeVersions` argument. When latest-wins selects the remote, the loser is the _local_ metadata, so the local writer's prior version history was silently dropped.
- **Why the audit missed it:** **T-44-09**'s "both directions tested" evidence over-trusted the remote-wins test, which used empty version arrays and never actually drove the remote-wins merge branch — `updateFileMetadata` stamps `updatedMetadata.modifiedAt = Date.now()`, so local wins unless the remote timestamp is future-dated. This is precisely the **T-44-21** "shallow conflict tests" class.
- **Resolution (commit `9f3c56181`):** second arg corrected to `loser.versions`; added a remote-wins history-preservation regression test (forces the branch with a far-future remote `modifiedAt`); also exported `is409` from the sdk-core barrel and added `is409` unit tests. Full sdk-core suite 196/196 green.

With the fix, **T-44-09** and **T-44-21** mitigations are now genuinely backed by tests. `threats_open` remains **0** (finding found _and_ fixed).

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-06-14
