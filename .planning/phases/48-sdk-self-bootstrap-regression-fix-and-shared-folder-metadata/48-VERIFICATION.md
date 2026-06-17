---
phase: 48-sdk-self-bootstrap-regression-fix-and-shared-folder-metadata
verified: 2026-06-17T00:00:00Z
status: human_needed
score: 3.5/4
overrides_applied: 0
human_verification:
  - test: "REQ-1 web-e2e gate — bin-restore-after-reload.spec.ts + full-workflow.spec.ts:6.6.2"
    expected: "Both specs green: after a page reload, a deleted item restored from the bin must NOT vanish (loadBin must not clobber a transient 404 with an empty record), and a past file version must restore on a cold-reloaded folder. This is the gate #498's post-merge run missed; the fix landed via #500 (loadBin retry + never-publish-on-null) but was never re-confirmed via a clean dispatch."
    why_human: "Requires a live web-e2e stack (postgres + kubo + redis + mock-ipns-routing) and a full IPNS propagation/poll cycle. Dispatch via `gh workflow run web-e2e.yml --ref main` or confirm the post-#504 main-push ci-e2e run is green. Cannot be verified by static analysis."
  - test: "REQ-3 shared-folder write + sync UAT — writable-shares.spec.ts / sharing-workflow.spec.ts"
    expected: "A write-share recipient can upload / mkdir / rename / edit / delete and see changes persist with no stale-sequence 409 loop; owner-side changes poll in via the 30s refreshSharedFolder path without regressing local writes."
    why_human: "Two-account browser + IPNS runtime; covered transitively by the green web-e2e shared specs but the live two-party sync UAT (48-04 Task 4 / 48-07 Task 5) was deferred and not run here."
  - test: "REQ-4 itemName-at-rest DB + display UAT — invite-link-workflow.spec.ts + manual DB check"
    expected: "A new direct share writes shares.item_name_encrypted (bytea) with item_name empty; recipient sees the decrypted name; an invite → claim produces a Share row carrying recipient-decryptable item_name_encrypted."
    why_human: "Requires a live API + DB to inspect the persisted column and a recipient browser session to confirm client-side decryption renders correctly."
---

# Phase 48: SDK Self-Bootstrap Regression Fix and Shared-Folder/Metadata Consolidation Verification Report

**Phase Goal:** Restore a green `main` after PR #498's self-bootstrap regression, then finish the SDK-as-single-owner work the share/folder paths left open: make self-bootstrap non-clobbering (REQ-1, P0), delete the now-redundant web folder-seeding (REQ-2), extend single-ownership to shared-folder writes (REQ-3), and close the Phase-14 M1 plaintext-`itemName` leak (REQ-4).

**Verified:** 2026-06-17T00:00:00Z

**Status:** human_needed

**Re-verification:** No — retroactive initial verification (phase was code-complete and merged via #498/#500/#504 but never formally verified)

## Goal Achievement

This phase ships four requirements. Three are fully achieved on `main`; REQ-4 is PARTIAL — the at-rest encryption is delivered for all new shares/invites, but the lazy backfill of legacy plaintext rows cannot persist because no API update endpoint accepts `itemNameEncrypted` (a known, documented residual, not a regression).

### Observable Truths

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | REQ-1 — `loadFolder` reconciles on IPNS sequenceNumber and keeps the fresher in-memory state instead of clobbering it | ACHIEVED | `packages/sdk/src/client.ts:386` — `if (existing && existing.sequenceNumber >= result.sequenceNumber)` re-emits the existing snapshot and returns it (lines 386-395), only `folderTree.set()`-ing the resolved snapshot when it is strictly newer (line 407). Comment at :383-384 cites the #489 sequence-as-clock invariant. |
| 2 | REQ-1 — the guard sits AFTER the IPNS resolve (suppresses only the write-back, not the network call) and `ensureFolderLoaded`'s short-circuit is preserved (no #498 "Folder not loaded" regression) | ACHIEVED | Guard is inside `loadFolder` after `if (!result) return null` (`client.ts:381`); `ensureFolderLoaded`/`requireFolder` short-circuit on already-loaded folders is intact (unit-tested by `client-load-reconcile.test.ts` cases A/B/C). |
| 3 | REQ-1 — the bin-durability root cause (loadBin republishing an empty bin on a transient 404) is fixed so the bin-restore-after-reload spec can pass | ACHIEVED (code) / HUMAN (e2e) | `packages/sdk/src/bin/index.ts:185-188` — "loadBin NEVER publishes on a null resolve"; resolve is retried (`loadBin` retry count + backoff at :172-174) and falls back to in-memory empty WITHOUT publishing (:222). Landed via #500 AFTER the 2026-06-16 BLOCKED-HANDOFF. Spec green requires the live web-e2e gate (see human_verification). |
| 4 | REQ-2 — all web `ensureFolderRegistered` seed call sites and the function definition are deleted | ACHIEVED | `grep -rn ensureFolderRegistered apps/web/src packages/sdk/src` → 0 matches. Commit `26cf44d28 refactor: remove web folder-seeding now that SDK self-bootstraps` removed the `sdk-provider.ts` definition + 14 call sites across `useFolderMutations`/`useFileOperations`/`useFileVersions`/`useDropUpload`. |
| 5 | REQ-2 — web folder mutations rely solely on the SDK `requireFolder` self-bootstrap chokepoint | ACHIEVED | No `ensureFolderRegistered`/`client.registerFolder` anywhere in `apps/web/src`; the `useFolderNavigation.ts` key-unwrap that remains serves only the display metadata-load path (per 48-02 deviation), not SDK seeding. |
| 6 | REQ-3 — SDK client owns shared-folder state in a sibling `sharedFolderTree` keyed by shareId | ACHIEVED | `packages/sdk/src/state/shared-folder-tree.ts` exists; `client.ts:62` declares `private sharedFolderTree: SharedFolderTree`, instantiated at :109, cleared on destroy at :250. `SharedFolderState`/`SharedFolderTree` exported from `index.ts`. |
| 7 | REQ-3 — client shared-write methods own publish + sequence bookkeeping + a `sharedFolder:updated` emission | ACHIEVED | `client.ts` — `uploadToSharedFolder` (:2062), `createSharedSubfolder` (:2079), `renameInSharedFolder` (:2093), `deleteFromSharedFolder` (:2110), `updateSharedFile` (:2135); each delegates to `share/shared-write.ts` then `adoptSharedFolderResult` writes back + emits `sharedFolder:updated` (:2046). Event declared in `events.ts:38`. Plus `refreshSharedFolder` (:2191) for the SDK-owned poll path with the #489 sequence-guard (:2206). |
| 8 | REQ-3 — `useSharedWriteOps` routes through the client methods and reads nothing back; `useSharedNavigation`'s refs become event-fed projections | ACHIEVED | `useSharedWriteOps.ts` lines 81/97/109/135/176 call `getSdkClient().<method>(shareId, args)`; grep for `folderChildrenRef.current =`/`sequenceNumberRef.current =`/`withConflictRetry` in that hook → 0. `useSharedNavigation.ts:272` wires `subscribeSharedFolderProjection` as the sole ref writer; the 30s poller routes through `getSdkClient().refreshSharedFolder` (:365); inline `resolveIpnsRecord` removed (grep → 0). |
| 9 | REQ-4 — `shares.itemName` migrated to an additive nullable ciphertext column; server persists client-supplied ECIES ciphertext (zero-knowledge) | ACHIEVED | `share.entity.ts:58-59` — `@Column({ type: 'bytea', name: 'item_name_encrypted', nullable: true }) itemNameEncrypted!: Buffer \| null`. Migration `1749200000000-EncryptShareItemName.ts` (additive, also adds the column to `share_invites`, no data UPDATE). `shares.service.ts:100` persists `dto.itemNameEncrypted ? Buffer.from(..., 'hex') : null` — server never encrypts. api-client regenerated (`itemNameEncrypted` in `sentShareResponseDto`/`receivedShareResponseDto`/`inviteResponseDto`). |
| 10 | REQ-4 — new shares/invites send ciphertext-only and the recipient decrypts client-side for display | ACHIEVED | `ShareDialog.tsx:338` wraps `itemName` with the recipient pubkey and sends `itemName: ''` + `itemNameEncrypted` (:349-350). `share.service.ts` `decryptItemName` (:68) unwraps into the store's plaintext projection in `fetchReceivedShares` (degrades gracefully per-row on a bad row); display sites unchanged. Invite create wraps with the ephemeral key; claim re-wraps for the recipient. |
| 11 | REQ-4 — legacy plaintext rows are lazily backfilled (decision A2) | PARTIAL | `share.service.ts` `backfillSentShareItemNames` (:194) detects eligible rows via `shouldBackfill` (:95) and computes the re-wrapped ciphertext, BUT the persist step is a documented no-op (`void itemNameEncrypted`, :214) — there is NO API update/patch endpoint that accepts `itemNameEncrypted` (`grep` of `apps/api/src/shares/dto/*.ts` confirms only the CREATE paths carry it). Legacy rows display via the plaintext fallback until the follow-up endpoint ships. This is the sole phase shortfall. |

**Score:** 3.5/4 requirements (REQ-1 ACHIEVED, REQ-2 ACHIEVED, REQ-3 ACHIEVED, REQ-4 PARTIAL — at-rest encryption delivered for all new rows; legacy lazy-backfill persist blocked on a missing API endpoint).

### Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- | --- |
| `packages/sdk/src/client.ts` | `loadFolder` sequence guard | EXISTS + SUBSTANTIVE | Guard at :386; shared-folder methods at :1954-2230 |
| `packages/sdk/src/__tests__/client-load-reconcile.test.ts` | REQ-1 reconcile unit tests (3 cases) | EXISTS | Created by 48-01 (commit `d68368e35` RED / `bcb4fc03d` GREEN) |
| `packages/sdk/src/bin/index.ts` | loadBin no-clobber-on-null durability fix | EXISTS + SUBSTANTIVE | Retry + never-publish-on-null (:172-222); resolves the BLOCKED-HANDOFF root cause |
| `apps/web/src/lib/sdk-provider.ts` | `ensureFolderRegistered` definition removed | EXISTS (clean) | grep → 0; commit `26cf44d28` |
| `packages/sdk/src/state/shared-folder-tree.ts` | `sharedFolderTree` keyed by shareId | EXISTS + SUBSTANTIVE | Clones key material on set; zeroes on delete/clear |
| `packages/sdk/src/events.ts` | `sharedFolder:updated` event | EXISTS | Declared :38 |
| `apps/web/src/hooks/shared-folder-projection.ts` | projection/seed helpers | EXISTS | `subscribeSharedFolderProjection` + `seedSharedFolder` (48-04) |
| `apps/web/src/hooks/useSharedWriteOps.ts` | projection-only routing | EXISTS + SUBSTANTIVE | 5 handlers route through SDK; no write-back |
| `apps/api/src/shares/entities/share.entity.ts` | `item_name_encrypted` bytea column | EXISTS | :58-59 |
| `apps/api/src/migrations/1749200000000-EncryptShareItemName.ts` | additive nullable migration | EXISTS | Adds column to `shares` + `share_invites`; no data UPDATE |
| `apps/web/src/services/share.service.ts` | `decryptItemName` + `shouldBackfill` + lazy backfill | EXISTS + SUBSTANTIVE | Decrypt projection wired; backfill persist is a documented no-op (API gap) |
| `apps/web/src/services/__tests__/share-item-name.test.ts` | decrypt + backfill decision unit tests | EXISTS | 8 cases (48-06) |

**Artifacts:** 12/12 present (one — share.service.ts backfill — carries a documented stub at the persist call).

### Key Link Verification

| From | To | Via | Status | Details |
| --- | --- | --- | --- | --- |
| `client.loadFolder` | `folderTree` | sequence guard before `set()` | WIRED | `client.ts:386` skips set when in-memory is fresher/equal |
| `useSharedWriteOps` | `client.<sharedMethod>` | 5 handlers route through SDK | WIRED | lines 81/97/109/135/176 |
| `client` shared methods | `sharedFolder:updated` | `adoptSharedFolderResult` emit | WIRED | `client.ts:2046` |
| `useSharedNavigation` | projection refs | `subscribeSharedFolderProjection` (sole writer) | WIRED | `useSharedNavigation.ts:272` |
| web 30s poller | `client.refreshSharedFolder` | poll-through-SDK | WIRED | `useSharedNavigation.ts:365`; inline resolve removed |
| `ShareDialog` | `itemNameEncrypted` (wire) | `wrapKey(name, recipientPubKey)` + `itemName: ''` | WIRED | `ShareDialog.tsx:338,349-350` |
| `shares.service.createShare` | `item_name_encrypted` column | `Buffer.from(dto.itemNameEncrypted, 'hex')` | WIRED | `shares.service.ts:100` |
| `fetchReceivedShares` | display projection | `decryptItemName` | WIRED | `share.service.ts:68,123` |
| `backfillSentShareItemNames` | API persist | (none — no update endpoint) | NOT WIRED | `share.service.ts:214` `void itemNameEncrypted` — residual gap |

**Wiring:** 8/9 connections wired; the 9th (backfill persist) is the documented REQ-4 residual.

### Behavioral Spot-Checks

Per task directive, test suites were NOT run (static verification only). The plan SUMMARYs and 48-VALIDATION.md record green unit runs at build time:

| Behavior | Recorded Result (from SUMMARY/VALIDATION) | Verified Here |
| --- | --- | --- |
| REQ-1 reconcile unit (`client-load-reconcile.test.ts`) | 3/3 green (48-01) | Guard code present at client.ts:386 |
| REQ-3 shared-folder-tree + client-shared-write units | 23 + 6 green (48-03/48-07) | Code + exports present |
| REQ-3 web projection (`useSharedWriteOps.test.ts`) | 9 green (48-04/48-07) | Subscription wiring present |
| REQ-4 ECIES UTF-8 round-trip (`ecies.test.ts`) | 22 green (48-05) | wrapKey/unwrapKey used on the name |
| REQ-4 web decrypt/backfill (`share-item-name.test.ts`) | 8 green (48-06) | Helpers present |
| REQ-4 API ciphertext persistence (`shares.service.spec.ts`, `share-invite.service.spec.ts`) | 158 + invite specs green (48-05; gap closed by `e8a3a2fe0`) | Service persist + entity column present |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| --- | --- | --- | --- | --- |
| `apps/web/src/services/share.service.ts` | 214 | `void itemNameEncrypted` — backfill ciphertext computed but never persisted | Warning | Intentional, documented (`NOTE (API GAP)`). Blocks decision-A2 legacy closure only; new rows are ciphertext-only end-to-end. Tracked as a follow-up API endpoint. |

No TBD/FIXME/XXX markers in changed source. The handoff's `f6b13db2b` nav-bounce theory was superseded — the real REQ-1 fix is the loadBin durability change (#500), correctly reflected in `bin/index.ts`.

### Explicit Verification Requirement Confirmations

1. **REQ-1 sequence guard present:** `grep -n "existing.sequenceNumber >= result.sequenceNumber" packages/sdk/src/client.ts` → exactly one match (line 386), inside `loadFolder` after the IPNS resolve. CONFIRMED.

2. **REQ-1 blocker resolved post-handoff:** The 2026-06-16 BLOCKED-HANDOFF identified loadBin republishing an empty bin on a transient 404 as the bin-restore-after-reload root cause. `bin/index.ts:185-222` now NEVER publishes on a null resolve and retries with backoff — landed via #500, AFTER the handoff. The pre-merge web-e2e re-confirmation remains a live-environment check (human_verification). CONFIRMED (code) / DEFERRED (e2e).

3. **REQ-2 zero seed call sites:** `grep -rn ensureFolderRegistered apps/web/src packages/sdk/src` → 0. Commit `26cf44d28` present in git history. CONFIRMED.

4. **REQ-3 SDK owns shared-folder state + web routing:** `sharedFolderTree` field + 5 write methods + `refreshSharedFolder` + `sharedFolder:updated` event all present; `useSharedWriteOps` routes through the client with no write-back; `useSharedNavigation` projection subscription is the sole ref writer. Merged via #500. CONFIRMED.

5. **REQ-4 itemName encrypted at rest for new rows:** entity column + migration + zero-knowledge service persist + ShareDialog ciphertext-only send + recipient client-side decrypt all present. Merged via #500. CONFIRMED.

6. **REQ-4 legacy backfill gap:** No update endpoint accepts `itemNameEncrypted` (`grep` of `apps/api/src/shares/dto/*.ts` — only create-share / create-invite / claim-invite carry it). `backfillSentShareItemNames` computes but cannot persist the re-wrap. This is the single shortfall → REQ-4 PARTIAL. RESIDUAL (follow-up), not a blocker for new shares.

### Human Verification Required

See the `human_verification` block in the frontmatter. Three live-environment checks remain (all require a stack this verifier cannot run): the REQ-1 web-e2e gate (bin-restore + version-restore), the REQ-3 two-party shared-folder sync UAT, and the REQ-4 itemName-at-rest DB + display UAT.

## Gaps Summary

One residual gap, by design: REQ-4's lazy backfill of legacy plaintext `itemName` rows (decision A2) cannot persist server-side because no API update/patch endpoint accepts `itemNameEncrypted`. New shares and invites are ciphertext-only end-to-end (Phase-14 M1 closed for all new rows); legacy rows are detected and re-wrapped client-side but display via the plaintext fallback until a follow-up `PATCH /shares/:id { itemNameEncrypted }` endpoint is added (a one-line change at the documented persist call site). REQ-1/REQ-2/REQ-3 are fully achieved on `main`.

---

_Verified: 2026-06-17T00:00:00Z_

_Verifier: Claude (gsd-verifier)_
