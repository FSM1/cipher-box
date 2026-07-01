---
phase: 68
slug: web-integration-rotation-ux-and-durable-client-state
status: verified
threats_open: 0
asvs_level: 1
created: 2026-07-02
block_on: high
---

# Phase 68 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.
>
> Audit method: every threat below was verified by reading the actual implementation
> file(s) cited in its plan's mitigation and confirming the mitigation pattern exists
> at the correct call site — not by trusting SUMMARY.md prose. `mitigate` threats were
> grep/read-confirmed in the cited files; `accept` threats were checked for a
> documented rationale and are logged in the Accepted Risks Log below. Threat flags
> from SUMMARY.md `## Threat Flags` were cross-checked against this register — all
> three map to an existing threat ID (none unregistered).

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|----------------|
| Relay / delegated-routing → web client | A potentially colluding or lagging relay serves signed IPNS records; the client must reject a rolled-back generation/sequence rather than trust the wire | seq, generation, signed IPNS record bytes |
| Injected `HighWaterStore` → SDK state machine | Durable anti-rollback floors read from browser storage must be treated as untrusted-on-read | numeric floor values (generation, seq) |
| IndexedDB persistence (`cipherbox-rotation-state`, `cipherbox-rotation-jobs`) | Durable anti-rollback state and job checkpoints must survive reload and never leak key material | floors (numbers), job metadata (ids/status strings) — never key bytes |
| Authenticated web client → shares API (`PATCH /shares/:shareId/grant`) | Owner submits a rotated grant descriptor for server-side persistence (zero-knowledge, ciphertext-as-is) | hex ciphertext descriptor, numeric-string generation |
| Owner client → shares API (owner-reconcile) | Owner re-mints/deletes grant rows for a subtree a write-recipient destroyed | recipientPublicKey (from server-held grant rows), ECIES-wrapped descriptor |
| Multi-tab (same origin) | Concurrent browser tabs racing the tail walk or the high-water checkpoint | in-process only (Web Locks coordination), no network crossing |
| SDK/resolve fail-closed errors → user | Every fail-closed rejection must reach the user as visible, non-silent UX | error class → toast copy/action (no key material) |
| Relay (mock-ipns-routing, web-e2e) → web resolve (durability spec) | The durability spec drives a genuinely regressed record across the fail-closed gate to prove observable, real rejection | captured/replayed signed IPNS record bytes |

---

## Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation | Status |
|-----------|----------|-----------|----------|-------------|------------|--------|
| T-68-11 | Spoofing/Tampering | `rotation-high-water.ts` — colluding relay stale/replayed record | critical | mitigate | Durable `{nodeId→highestGeneration}` floor; `enforceResolved` throws `GenerationRegressionError` on regression | closed |
| T-68-12 | Tampering | `rotation-high-water.ts` — within-generation stale-seq | high | mitigate | Durable `{nodeId→highestSeq}` floor; `enforceResolved` throws `SequenceRegressionError` | closed |
| T-68-13 | Tampering | `rotation-high-water.ts` — cold-device/first-contact rollback | high | mitigate | `versionFloor` gate applied when no local seq floor exists yet | closed |
| T-68-14 | Tampering | `rotation-high-water.ts` — malformed stored high-water value | medium | mitigate | V5 validation (`isValidFloorValue`): non-integer/negative/NaN treated as absent | closed |
| T-68-15 | Cryptography | `rotation-high-water.ts` — high-water value misused as unseal AAD | high | mitigate | `enforceResolved` returns `Promise<void>` — pure pass/throw, never emits an AAD/unseal parameter | closed |
| T-68-21 | Tampering | `share.service.ts` — `rootGeneration` parse in fetch reshape | high | mitigate | `parseRootGeneration` uses `Number.isFinite` guard; non-numeric/absent → `undefined`, never `NaN`/`0` | closed |
| T-68-22 | Elevation of privilege | `share.service.ts`/`useAuth.ts`/`useSharedNavigation.ts` — leftover `addShareKeys`/`reWrapForRecipients` fan-out | medium | mitigate | Full deletion confirmed; repo-wide grep for both symbols in `apps/web/src` returns empty | closed |
| T-68-23 | Repudiation | `rotation-driver.service.ts` — `localGrantRecord` cross-check source | medium | mitigate | `getLocalGrantRecord` reads real `useShareStore().sentShares` (populated by 68-02's live API fetch), not a stub | closed |
| T-68-31 | Elevation of privilege | `shares.controller.ts`/`shares.service.ts` — `PATCH :shareId/grant` | high | mitigate | Owner-only check (`share.sharerId !== sharerId` → 403); `ParseUUIDPipe` on `shareId` | closed |
| T-68-32 | Tampering | `update-grant.dto.ts` — body tampering | medium | mitigate | `@Matches` hex + `@MaxLength(2500)` on descriptor; `@IsNumberString` + custom bigint-range validator on `rootGeneration` | closed |
| T-68-33 | Information disclosure | `shares.service.ts` — grant row leakage to non-owner | medium | mitigate | 404 for unknown share (checked first), 403 for non-owner — no distinguishing disclosure | closed |
| T-68-41 | Information disclosure | `RotationStatusBadge.tsx` — badge timing/labels | low | mitigate | `aria-live="polite"`, non-interactive (no `onClick`), coarse phase labels only, no per-node counts | closed |
| T-68-42 | Tampering | `NotificationToast.tsx` — notification `action.onClick` | low | accept | See Accepted Risks Log AR-1 | closed |
| T-68-51 | Repudiation/Elevation of privilege | `client.ts` — scope-exit coverage detection | high | mitigate | `performScopeExitRotation` passes `localGrantRecord` (from `getLocalGrantRecord`) into `maybeRotateOnScopeExit`; no inline `hasCoveringGrant` duplication | closed |
| T-68-52 | Tampering/DoS-of-guarantee | `client.ts` — reconcile-before-publish | high | mitigate | `reconcileFolderSequence` throws `ReconcileStaleError` on ANY seq mismatch, before any publish | closed |
| T-68-53 | Tampering | `client.ts` — key-buffer handling in rotation wrapper | high | mitigate | No `.fill(0)` on `rootReadKey`/caller-owned buffers (grep-confirmed: only `oldFolderKey`/locally-minted keys are zeroed); no high-water→AAD conflation | closed |
| T-68-54 | DoS-of-guarantee | `client.ts` — `moveItem` crash between publishes | medium | mitigate | Destination published before source (dest-before-source); `enumerateMoveDescendantsFireAndForget` enumerates unreadable descendants (bounded `MAX_NODES=2000`) | closed |
| T-68-61 | Spoofing/Tampering | `rotation-state.service.ts` — colluding relay stale/replayed record | critical | mitigate | IndexedDB `generation-high-water` store feeds SDK `enforceResolved`; regression → `GenerationRegressionError` | closed |
| T-68-62 | Tampering | `rotation-state.service.ts` — within-generation stale-seq | high | mitigate | IndexedDB `seq-high-water` store; SDK throws `SequenceRegressionError` | closed |
| T-68-63 | Tampering | `ipns.service.ts` — cold-device/first-contact rollback | high | mitigate | `versionFloor` passed via `ResolveRotationContext` into `enforceResolved` on first contact | closed |
| T-68-64 | Tampering | `rotation-state.service.ts` — malformed/absent stored value | medium | mitigate | `isValidFloorValue` at the storage boundary (defense-in-depth alongside the SDK's own guard) | closed |
| T-68-65 | Cryptography | `ipns.service.ts` — high-water misused as unseal AAD | high | mitigate | Grep-confirmed: zero references to `unsealChildReadKey` in `ipns.service.ts`; pre-unseal gate strictly separated | closed |
| T-68-71 | Elevation of privilege | `owner-reconcile.ts`/`engine.ts` — re-minting a revoked recipient's grant | high | mitigate | `reMintGrantsRootedAt`: `isRevoked` branch calls `deleteGrantFn` only, never `updateGrantFn` (source-confirmed in sdk-core) | closed |
| T-68-72 | Information disclosure | Owner-reconcile — dangling grant window after C's unlink+bin | medium | accept | See Accepted Risks Log AR-2 | closed |
| T-68-73 | Tampering | `owner-reconcile.service.ts` — wrong `recipientPublicKey` for re-wrap | high | mitigate | `recipientPublicKey` decoded from the owner's own server-held sent-grant rows; `wrapKey` (vetted `@cipherbox/crypto` ECIES) used inside the engine | closed |
| T-68-81 | Tampering/race | `multi-tab-lock.ts` — multi-tab concurrent tail walk | medium | mitigate | `navigator.locks.request(..., { mode: 'exclusive' }, fn)` leader election; documented-safe fallback (`fn()` direct call) when Web Locks is absent — idempotent walk + CAS-409 re-merge makes double-run safe | closed |
| T-68-82 | Tampering | `rotation-high-water.ts`/`rotation-state.service.ts` — multi-tab high-water checkpoint write | medium | mitigate | `bumpFloor` is read-then-compare-then-conditional-put (monotonic-max); order-independent across tabs | closed |
| T-68-83 | Tampering | `rotation-driver.service.ts` — key-buffer handling in `persistJob` | high | mitigate | `DurableJobCheckpoint` type carries `rootNodeId`/`status`/`completedNodeIds`/`frontierIpnsNames`/`updatedAt` only — no `Uint8Array` field; zero `.fill(0)` calls in the file | closed |
| T-68-84 | Information disclosure | `RotationStatusBadge.tsx` — badge exposes subtree progress | low | mitigate | Coarse phase labels only (verified alongside T-68-41); no per-node counts | closed |
| T-68-91 | DoS-of-guarantee | `useMutationFailureUx.ts` — silent swallow of a defer/regression error | high | mitigate | Every classified branch (`ReconcileStaleError` exhaustion, `Sequence/GenerationRegressionError`, stale-write) dispatches a visible toast before rethrowing; no catch-and-ignore | closed |
| T-68-92 | Elevation of privilege | `useMutationFailureUx.ts` — unbounded retry masking persistent stale state | medium | mitigate | Bounded backoff `RECONCILE_RETRY_DELAYS_MS = [2000,4000,8000,16000]` (5 total attempts, 30s) then terminal fail-closed; no durable/cross-reload queue | closed |
| T-68-93 | Spoofing | `useMutationFailureUx.ts` — 'Refresh access' re-resolve on a revoked co-writer | medium | mitigate | `dispatchWriteDescriptorStale`: post-refresh failure dispatches `'Write access revoked.'` with **no** action object | closed |
| T-68-101 | Tampering | `rotation-durability.spec.ts` — colluding relay stale/replayed record | critical | mitigate | Spec captures real signed IPNS bytes, republishes a genuinely higher sequence via real UI mutation, replays stale bytes, asserts fail-closed rejection | closed |
| T-68-102 | DoS-of-guarantee | `rotation-durability.spec.ts` — in-memory-only durability claim | high | mitigate | Persistence read via `page.evaluate` opening real `cipherbox-rotation-state` IndexedDB, strictly after `page.reload()` | closed |
| T-68-103 | Repudiation | `rotation-durability.spec.ts` — silent acceptance of a rolled-back record | high | mitigate | Spec asserts `[role="alert"]` with `'Stale data from server rejected.'` AND that the durable seq floor is unregressed after rejection | closed |
| T-68-11-01 | Tampering | `client.ts` — `reconcileFolderSequence` resolve (gap closure) | critical | mitigate | Routed through `this.config.rotationHighWater?.enforceResolved(...)` before the `ReconcileStaleError` check; injected live via `useAuth.ts` | closed |
| T-68-11-02 | Elevation of privilege | `client.ts` — revoked reader retains read access (gap closure) | high | mitigate | A rolled-back record is rejected, not applied, during a live mutation (same call site as T-68-11-01) | closed |
| T-68-11-03 | Repudiation | `client.ts`/`useMutationFailureUx.ts` — silent acceptance (gap closure) | medium | mitigate | `enforceResolved` call sits lexically OUTSIDE the resolve try/catch — regression errors propagate to the D-05 classifier, not swallowed by the network-error catch | closed |
| T-68-12-01 | Tampering | `client.ts` — mutation published against stale post-rotation folderKey | high | mitigate | `performScopeExitRotation` captures `RotateReadResult` and refreshes `folderTree` (folderKey/generation/sequenceNumber) immediately after a successful rotation | closed |
| T-68-12-02 | Information disclosure | `client.ts` — zeroization of shared/caller-owned buffer during folderTree swap | medium | mitigate | Only the OLD, folderTree-terminally-owned `folderKey` is zeroed, post-swap; `rootReadKey` and `rotationResult.readKey` are never zeroed | closed |
| T-68-12-03 | Denial of service | `client.ts` — unrecoverable defer loop forcing a full reload | medium | mitigate | Same-session second mutation reconciles against the refreshed sequence instead of throwing `ReconcileStaleError` (self-heals) | closed |

*Status: open · closed · open — below high threshold (non-blocking)*
*Severity: critical > high > medium > low — only open threats at or above `high` (workflow.security_block_on) count toward `threats_open`*
*Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)*

**Totals:** 41 threats registered (39 `mitigate`, 2 `accept`) — 41/41 closed, 0 open.

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| AR-1 | T-68-42 | `Notification.action.onClick` is a client-supplied closure dispatched by trusted app code (`useMutationFailureUx.ts` / `rotation-driver.service.ts`), never user-controlled or server-controlled input. No privilege boundary is crossed in the toast layer — the closure re-invokes the same mutation or refresh path the user already had permission to call. | 68-04 plan author (accepted at plan time) | 2026-07-01 |
| AR-2 | T-68-72 | Dangling-grant exposure window after a write-recipient (C) independently unlinks+bins a node the owner had sub-shared to D: the owner's eager reconcile (D-11, on login/app-open + opportunistic post-mutation) minimizes the window but cannot close it to zero without a push mechanism the project does not have. Per ADR 0002 (documented in `.planning/design/2026-06-26-sharing-read-keychaining-design.md` §4.1/§4.7 and `.planning/REQUIREMENTS.md`), the project's honest threat-model stance is that read-revocation protects future navigation/content, not already-distributed state — the residual exposure here is consistent with, and bounded by, that existing accepted architectural stance. No advisory is sent to D by design (no share-existence leak to a delegate). | 68-07 plan author (accepted at plan time, per pre-existing ADR 0002) | 2026-07-01 |

*Accepted risks do not resurface in future audit runs.*

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-07-02 | 41 | 41 | 0 | gsd-security-auditor |

**Verification method:** Read the full threat_model block of all 12 plans (68-01..68-12, including the two gap-closure plans 68-11/68-12) and the `## Threat Flags` sections of 68-05/68-08 SUMMARYs. For each `mitigate` threat, read the cited implementation file(s) directly (not the SUMMARY prose) and confirmed the specific mitigation pattern — error class thrown, validation guard, grep-negative for a deleted symbol, call-site ordering — at the correct location. Cross-checked against the pre-existing `.planning/phases/68-.../68-VERIFICATION.md` re-verification report (independently produced by a different agent after the 68-11/68-12 gap closures), which corroborates the same 24/24, 38/38, 20/20, 4/4 passing unit-test counts and the same source-line evidence for the two gap closures. No implementation file was modified during this audit.

**Notable finding (not a gap):** Plans 68-01 through 68-10 built the ROT-07 fail-closed mechanism but left it unreachable from any live UI code path (`68-10-SUMMARY.md` explicitly documents this as a discovered gap, corroborated by `68-VERIFICATION.md`'s prior "gaps_found" pass). Gap-closure plans 68-11 (BLOCKER — wires `enforceResolved` into `client.ts#reconcileFolderSequence`, the real chokepoint invoked by every mutation, plus `useFileBrowserActions.ts#handleSync`) and 68-12 (should-fix — `folderTree` refresh after rotation so a same-session retry self-heals) close this. All threats in this register that reference "live"/"reachable" wiring (T-68-11-01/02/03, T-68-12-01/02/03, and by extension T-68-61/62/63/65 and T-68-101/102/103) were verified against the POST-gap-closure code, not the pre-closure state.

**Deferred, non-blocking, out of phase scope:** `CannotWriteUntilRefetchError` (WRITE-03/D-01 co-writer stale-write escalation) has a fully-correct classifier (`useMutationFailureUx.ts` — verified above) but no live production trigger yet; `buildSharedWriteContextFromState`'s `publishNodeFn` never returns `{tombstoned: true}`. This is a pre-existing Phase 65/66 gap (not introduced by Phase 68, not touched by 68-11/68-12) and does not weaken any threat mitigation in this register — the escalation logic is correct and will activate once a future phase wires the trigger. Tracked informationally, not as an open threat (no Phase-68 threat ID depends on this trigger existing today).

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-07-02
