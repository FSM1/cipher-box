---
phase: 48-sdk-self-bootstrap-regression-fix-and-shared-folder-metadata
verified: 2026-06-18T00:00:00Z
status: passed
score: 4/4
uat_signoff: "2026-06-18 — UAT gates signed off green by maintainer. REQ-1 bin/version-restore covered by green CI E2E run 27766162738 (web-e2e incl. bin-restore-after-reload), now on main; REQ-3 write/sync + REQ-4 itemName-at-rest covered by writable-shares + share-itemname-backfill e2e; live two-party feel accepted."
overrides_applied: 0
re_verification:
  previous_status: human_needed
  previous_score: 3.5/4
  gaps_closed:
    - "REQ-4 lazy backfill persist — PATCH /shares/:shareId/item-name endpoint added via PR #505 (sharesControllerUpdateShareItemName); the prior `void itemNameEncrypted` no-op is removed and the web client now persists the re-wrapped ciphertext."
  gaps_remaining: []
  regressions: []
human_verification:
  - test: "REQ-1 web-e2e gate — bin-restore-after-reload.spec.ts + full-workflow.spec.ts:6.6.2 (Restore a past version)"
    expected: "After a page reload, a deleted item restored from the bin must NOT vanish (loadBin must not clobber a transient 404 with an empty record), and a past file version must restore on a cold-reloaded folder. Both specs green on a clean web-e2e dispatch."
    why_human: "Requires a live web-e2e stack (postgres + kubo + redis + mock-ipns-routing) and a full IPNS propagation/poll cycle. Verify via `gh workflow run web-e2e.yml --ref main` or confirm the post-#505 main-push ci-e2e run is green. Cannot be verified by static analysis (planner deferred this as 48-01 Task 3 checkpoint:human-verify)."
  - test: "REQ-3 shared-folder write UAT — all five write ops as a write-share recipient (48-04 Task 4)"
    expected: "A write-share recipient can upload / mkdir / rename / edit / delete and each change reflects immediately and persists with no stale-sequence 409 loop."
    why_human: "Two-account browser session + IPNS runtime; deferred as 48-04 Task 4 checkpoint:human-verify. Not reproducible by static analysis."
  - test: "REQ-3 shared-folder sync UAT — poll + write, no inline resolve (48-07 Task 5)"
    expected: "Owner-side changes poll in via the 30s refreshSharedFolder path within ~30s without regressing the recipient's local writes; the projection subscription is the sole ref writer for both write and poll."
    why_human: "Live two-party IPNS sync over a 30s poll cycle; deferred as 48-07 Task 5 checkpoint:human-verify."
  - test: "REQ-4 itemName-at-rest UAT — server-side ciphertext + recipient display (48-06 Task 3)"
    expected: "A new direct share writes shares.item_name_encrypted (bytea) with item_name empty; the recipient sees the decrypted name; an invite -> claim produces a Share row carrying recipient-decryptable item_name_encrypted; a legacy plaintext row is backfilled to ciphertext on next sent-share list load (PATCH /shares/:id/item-name)."
    why_human: "Requires a live API + DB to inspect the persisted column and a recipient browser session to confirm client-side decryption renders correctly; deferred as 48-06 Task 3 checkpoint:human-verify."
---

# Phase 48: SDK Self-Bootstrap Regression Fix and Shared-Folder/Metadata Consolidation Verification Report

**Phase Goal:** Restore a green `main` after PR #498's self-bootstrap regression, then finish the SDK-as-single-owner work the share/folder paths left open: make self-bootstrap non-clobbering (REQ-1, P0), delete the now-redundant web folder-seeding (REQ-2), extend single-ownership to shared-folder writes (REQ-3), and close the Phase-14 M1 plaintext-`itemName` leak (REQ-4).

**Verified:** 2026-06-18T00:00:00Z

**Status:** human_needed

**Re-verification:** Yes — phase now fully merged into `main` (PRs #498/#500/#504/#505). The single residual gap from the prior (2026-06-17) verification — REQ-4's lazy-backfill persist — is now CLOSED by the `PATCH /shares/:shareId/item-name` endpoint (PR #505). Remaining items are live-environment UAT gates only.

## Goal Achievement

All four requirements are achieved at the code level on `main`. REQ-4, previously PARTIAL because no API endpoint accepted `itemNameEncrypted`, is now fully achieved: PR #505 added the sharer-authorized `PATCH /shares/:shareId/item-name` endpoint, and the web `backfillSentShareItemNames` persists the re-wrapped ciphertext through it. Four blocking UAT/e2e items were deliberately deferred by the planner to end-of-phase live verification.

### Observable Truths

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | REQ-1 — `loadFolder` reconciles on IPNS `sequenceNumber` and keeps the fresher in-memory state instead of clobbering it | VERIFIED | `packages/sdk/src/client.ts:386-396` — `if (existing && existing.sequenceNumber >= result.sequenceNumber)` re-emits the existing snapshot and returns it; only `folderTree.set()`-es the resolved snapshot when strictly newer (`:408`). #489 invariant comment at :384-385. Unit-covered by `client-load-reconcile.test.ts` cases A/B/C (3 strong tests, 13 assertions). |
| 2 | REQ-1 — the guard sits AFTER the IPNS resolve and `ensureFolderLoaded`/`requireFolder` short-circuit is preserved (no #498 "Folder not loaded" regression) | VERIFIED | Guard is inside `loadFolder` after `if (!result) return null` (`client.ts:382`). `ensureFolderLoaded` (`:444`) + `requireFolder` (`:527-528`) short-circuit on already-loaded folders intact; test case B asserts a genuinely-absent folder is still resolved + set. |
| 3 | REQ-1 — the bin-durability root cause (loadBin republishing an empty bin on a transient 404) is fixed | VERIFIED (code) / HUMAN (e2e) | `packages/sdk/src/bin/index.ts:186-224` — "loadBin NEVER publishes on a null resolve"; bounded retry with backoff (`:200-202`) then falls back to in-memory empty WITHOUT publishing (`:222-224`). Spec-green confirmation requires the live web-e2e gate (human_verification #1). |
| 4 | REQ-2 — all web `ensureFolderRegistered` seed call sites and the function definition are deleted | VERIFIED | `grep -rn ensureFolderRegistered apps/web/src packages/sdk/src` -> 0 matches; `apps/web/src/lib/sdk-provider.ts` has no `ensureFolderRegistered`/`registerFolder`. Commit `26cf44d28`. |
| 5 | REQ-2 — web folder mutations rely solely on the SDK `requireFolder` self-bootstrap chokepoint; the duplicate `useFolderNavigation` pre-seed is removed | VERIFIED | `requireFolder` (`client.ts:527-528`) resolves via `ensureFolderLoaded` self-bootstrap. `grep` for `registerFolder`/`folderTree`/`ensureFolderRegistered`/`unwrapKey`-pre-seed in `apps/web/src/hooks/useFolderNavigation.ts` -> 0. |
| 6 | REQ-3 — SDK client owns shared-folder state in a sibling `sharedFolderTree` keyed by shareId; isolated per share (no cross-share key/context bleed) | VERIFIED | `packages/sdk/src/state/shared-folder-tree.ts` keys by `shareId` (Map), `set()` clones key buffers, `delete()/clear()` zero `folderKey`+`ipnsPrivateKey` (`:41-77`). `client.ts:63` declares `private sharedFolderTree`, instantiated `:110`, cleared on destroy `:251`. |
| 7 | REQ-3 — client shared-write methods own publish + sequence bookkeeping + a `sharedFolder:updated` emission, routed through `publishWithCas` (no second retry loop) | VERIFIED | `uploadToSharedFolder` (`client.ts:2110`), `createSharedSubfolder` (`:2127`), `renameInSharedFolder` (`:2141`), `deleteFromSharedFolder` (`:2158`), `updateSharedFile` (`:2183`); each delegates to `share/shared-write.ts` then `adoptSharedFolderResult` writes back + emits `sharedFolder:updated` (`:2092-2098`). Event declared `events.ts:38`. `moveInSharedFolder` (`:2386`) adopts source only. |
| 8 | REQ-3 — `useSharedWriteOps` routes through the client methods and reads nothing back; `useSharedNavigation` refs become event-fed projections | VERIFIED | `useSharedWriteOps.ts` lines 83/99/111/137/178/199/234 call `getSdkClient().<method>(shareId, ...)`; no `folderChildrenRef.current =`/`sequenceNumberRef.current =`/`withConflictRetry` in that hook. `useSharedNavigation.ts:281-286` writes refs ONLY inside `subscribeSharedFolderProjection`. |
| 9 | REQ-3 — SDK owns shared-folder REFRESH; the web 30s poller routes through `client.refreshSharedFolder` with the #489 sequence-guard; inline IPNS/IPFS/decrypt removed | VERIFIED | `refreshSharedFolder` (`client.ts:2239-2275`) re-resolves via `sdkCore.loadFolderMetadata` (`:2243`), applies the `state.sequenceNumber >= result.sequenceNumber` guard (`:2254`), adopts + emits. `useSharedNavigation.ts:374` poller calls `getSdkClient().refreshSharedFolder`; `grep resolveIpnsRecord` in that hook -> 0. |
| 10 | REQ-4 — `shares.itemName` migrated to an additive nullable ciphertext column; server persists client-supplied ECIES ciphertext (zero-knowledge) for shares AND invites | VERIFIED | `share.entity.ts:58-59` — `@Column({ type: 'bytea', name: 'item_name_encrypted', nullable: true })`. Migration `1749200000000-EncryptShareItemName.ts` `ADD COLUMN IF NOT EXISTS` on `shares` + `share_invites`, no data UPDATE. `shares.service.ts:100` and `share-invite.service.ts:47,200` persist `Buffer.from(dto.itemNameEncrypted, 'hex')` only — server never encrypts. api-client regenerated. |
| 11 | REQ-4 — new shares/invites send ciphertext-only; recipient decrypts client-side for display; plaintext display sites unchanged | VERIFIED | `ShareDialog.tsx:339` wraps name with recipient pubkey (`wrapKey`) and sends `itemName: ''` + `itemNameEncrypted` (`:350`). `share.service.ts` `decryptItemName` (`:69`) unwraps with the vault key in `fetchReceivedShares`, degrading per-row on a bad row (`:118-124`). Unit-covered by `share-item-name.test.ts` (8 assertions). |
| 12 | REQ-4 — legacy plaintext rows are lazily backfilled and re-persisted (decision A2) | VERIFIED | `share.service.ts` `backfillSentShareItemNames` (`:188`) detects eligible rows via `shouldBackfill` (`:96`), re-wraps, and PERSISTS via `sharesControllerUpdateShareItemName(share.shareId, { itemNameEncrypted })` (`:212`). API endpoint `PATCH :shareId/item-name` (`shares.controller.ts:341-359`) -> `shares.service.ts:373 updateShareItemName` enforces sharer-only (`ForbiddenException` if `sharerId` mismatch) and stores ciphertext as-is. DTO `update-item-name.dto.ts` validates even-length hex. Added by PR #505 — closes the prior PARTIAL. |

**Score:** 4/4 requirements (REQ-1 VERIFIED, REQ-2 VERIFIED, REQ-3 VERIFIED, REQ-4 VERIFIED — at-rest encryption + lazy backfill persist both delivered).

### Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- | --- |
| `packages/sdk/src/client.ts` | loadFolder sequence guard + shared methods + refreshSharedFolder | VERIFIED | Guard `:386`; shared methods `:2110-2386`; refresh `:2239` |
| `packages/sdk/src/__tests__/client-load-reconcile.test.ts` | REQ-1 reconcile unit tests | VERIFIED | 3 cases A/B/C, 13 assertions, no skips |
| `packages/sdk/src/bin/index.ts` | loadBin no-clobber-on-null durability fix | VERIFIED | Retry + never-publish-on-null `:186-224` |
| `apps/web/src/lib/sdk-provider.ts` | `ensureFolderRegistered` definition removed | VERIFIED | grep -> 0 |
| `packages/sdk/src/state/shared-folder-tree.ts` | `sharedFolderTree` keyed by shareId, key-zeroing | VERIFIED | 83 lines; clones on set, zeroes on delete/clear |
| `packages/sdk/src/events.ts` | `sharedFolder:updated` event | VERIFIED | Declared `:38` |
| `apps/web/src/hooks/useSharedWriteOps.ts` | projection-only routing | VERIFIED | 7 SDK calls, no write-back |
| `apps/web/src/hooks/useSharedNavigation.ts` | event-fed projection + poll-through-SDK | VERIFIED | projection sole ref writer `:281-286`; poller `:374` |
| `apps/api/src/shares/entities/share.entity.ts` | `item_name_encrypted` bytea column | VERIFIED | `:58-59` |
| `apps/api/src/migrations/1749200000000-EncryptShareItemName.ts` | additive nullable migration | VERIFIED | `shares` + `share_invites`, no data UPDATE |
| `apps/api/src/shares/dto/update-item-name.dto.ts` | backfill DTO (hex-validated) | VERIFIED | even-length hex `Matches`, `MaxLength(2500)` |
| `apps/web/src/components/file-browser/ShareDialog.tsx` | ECIES wrap + ciphertext-only send | VERIFIED | `:339,350` |
| `apps/web/src/services/share.service.ts` | decrypt + shouldBackfill + backfill persist | VERIFIED | decrypt `:69`, backfill `:188-212` (persist wired) |
| `apps/web/src/services/__tests__/share-item-name.test.ts` | decrypt + backfill decision unit tests | VERIFIED | 8 assertions, no skips |

**Artifacts:** 14/14 VERIFIED. No stubs remain (the prior `void itemNameEncrypted` no-op is removed).

### Key Link Verification

| From | To | Via | Status | Details |
| --- | --- | --- | --- | --- |
| `client.loadFolder` | `folderTree` | sequence guard before `set()` | WIRED | `client.ts:386` (verified manually; the `gsd-tools verify.key-links` "Source file not found" result is a frontmatter-parse artifact of the multi-line `from:` value, not a real gap) |
| web hooks | SDK `requireFolder` | self-bootstrap chokepoint | WIRED | `client.ts:527-528`; 0 web seed call sites |
| `useSharedWriteOps` | `client.<sharedMethod>` | 7 handlers route through SDK | WIRED | `useSharedWriteOps.ts:83/99/111/137/178/199/234` |
| client shared methods | `sharedFolder:updated` | `adoptSharedFolderResult` emit | WIRED | `client.ts:2092-2098` |
| `useSharedNavigation` | projection refs | `subscribeSharedFolderProjection` (sole writer) | WIRED | `useSharedNavigation.ts:281-286` |
| web 30s poller | `client.refreshSharedFolder` | poll-through-SDK | WIRED | `useSharedNavigation.ts:374`; inline resolve removed |
| `client.refreshSharedFolder` | `sdkCore.loadFolderMetadata` | re-resolve + sequence-guard | WIRED | `client.ts:2243,2254` (manual; verifier parse-artifact) |
| `ShareDialog` | `itemNameEncrypted` (wire) | `wrapKey(name, recipientPubKey)` + `itemName: ''` | WIRED | `ShareDialog.tsx:339,350` |
| `shares.service.createShare` / invite path | `item_name_encrypted` column | `Buffer.from(dto.itemNameEncrypted, 'hex')` | WIRED | `shares.service.ts:100`; `share-invite.service.ts:47,200` |
| `fetchReceivedShares` | display projection | `decryptItemName` | WIRED | `share.service.ts:69,124` |
| `backfillSentShareItemNames` | API persist | `sharesControllerUpdateShareItemName` -> `PATCH :shareId/item-name` | WIRED | `share.service.ts:212` -> `shares.controller.ts:354` -> `shares.service.ts:373` (sharer-authorized) |

**Wiring:** 11/11 connections WIRED. The previously NOT-WIRED backfill persist is now connected end-to-end.

### Behavioral Spot-Checks

Per task directive, no test suites were run (static verification only; central behavioral evidence not supplied). Artifact/key-link verifiers and targeted greps were used. Plan SUMMARYs and 48-VALIDATION.md record green unit runs at build time:

| Behavior | Recorded Result (SUMMARY/VALIDATION) | Verified Here |
| --- | --- | --- |
| REQ-1 reconcile unit (`client-load-reconcile.test.ts`) | 3/3 green | Guard code present `client.ts:386`; 3 cases + 13 assertions present, no skips |
| REQ-3 shared-folder-tree + client-shared-write units | green | Code + exports present; isolation/key-zeroing in `shared-folder-tree.ts` |
| REQ-3 web projection (`useSharedWriteOps.test.ts`) | green | Subscription wiring present |
| REQ-4 web decrypt/backfill (`share-item-name.test.ts`) | 8 green | Helpers + persist call present |
| REQ-4 API ciphertext persistence (`shares.service.spec.ts`) | green | Service persist + entity column + backfill endpoint present |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| --- | --- | --- | --- | --- |
| (none) | — | — | — | No TBD/FIXME/XXX/HACK/PLACEHOLDER/"not implemented" markers in any phase-modified file. The prior `void itemNameEncrypted` backfill no-op is removed (PR #505). |

### Test-Quality Audit (static)

- No `.skip` / `.todo` / `xit` / `describe.skip` in the phase test files.
- `client-load-reconcile.test.ts`: strong assertions — exact `sequenceNumber` equality, `children` deep-equality, and a call-count check proving the network read is not suppressed (only the write-back). No circular fixtures (canned `loadFolderMetadata` mock).
- `share-item-name.test.ts`: strong boolean truth-table coverage of `shouldBackfill` (encrypted/plaintext x key-holder/non-holder x empty name) and exact-name round-trip assertions for `decryptItemName`.

### CONTEXT.md Decision Coverage (non-blocking)

48-CONTEXT.md decisions are reflected in code: A4 (sibling `sharedFolderTree`, not extending `folderTree`) — confirmed; A3 (invite flow carries `itemNameEncrypted`) — confirmed (`create-invite`/`claim-invite` DTOs + service); A2 (lazy backfill) — now fully delivered (persist endpoint shipped). Zero-knowledge persist (server never encrypts) — confirmed for all create + backfill paths.

### Human Verification Required

Four live-environment UAT/e2e gates were deferred by the planner as `checkpoint:human-verify` tasks (48-01 Task 3, 48-04 Task 4, 48-06 Task 3, 48-07 Task 5). All require a stack this verifier cannot run. See the `human_verification` frontmatter block. The phase is fully merged into `main` (PRs #498/#500/#504/#505); confirming the post-#505 main-push e2e run is green satisfies REQ-1's gate.

**✅ Signed off 2026-06-18 (maintainer).** REQ-1's gate is satisfied by green CI E2E run `27766162738` (web-e2e incl. `bin-restore-after-reload.spec.ts`), merged to `main`. The shared-write/sync and itemName-at-rest gates are covered by the green `writable-shares` and `share-itemname-backfill` e2e specs; remaining live two-party feel is accepted by the maintainer. Status set to `passed`.

## Gaps Summary

No code-level gaps. All four requirements are achieved on `main`. The prior verification's single shortfall — REQ-4's lazy-backfill persist blocked on a missing API endpoint — is CLOSED by PR #505 (`PATCH /shares/:shareId/item-name`, sharer-authorized, zero-knowledge). The only remaining work is human/live-environment UAT confirmation of behaviors that cannot be exercised by static analysis (bin/version restore after reload, two-party shared-folder write + 30s poll sync, and itemName-at-rest DB + recipient-display round-trip).

---

_Verified: 2026-06-18T00:00:00Z_

_Verifier: Claude (gsd-verifier)_
