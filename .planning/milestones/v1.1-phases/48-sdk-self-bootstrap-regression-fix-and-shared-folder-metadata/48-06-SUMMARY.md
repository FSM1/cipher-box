---
phase: 48-sdk-self-bootstrap-regression-fix-and-shared-folder-metadata
plan: 06
subsystem: web
tags: [web, crypto, shares, security, ecies, backfill, invite]

# Dependency graph
requires:
  - phase: 48
    plan: 05
    provides: "Regenerated @cipherbox/api-client carrying itemNameEncrypted on create-share / create-invite / claim-invite DTOs + responses; nullable item_name_encrypted column on shares + share_invites"
  - phase: 14
    provides: "Plaintext-itemName-at-rest finding M1 (the threat this plan closes on the web side)"
provides:
  - "ShareDialog ECIES-wraps itemName with the recipient pubkey on create and sends ciphertext-only (empty plaintext)"
  - "Invite create wraps itemName with the ephemeral pubkey; claim re-wraps for the recipient (decision A3)"
  - "Recipient clients decrypt itemNameEncrypted into the store's plaintext display projection on received-share load; display sites unchanged"
  - "decryptItemName + shouldBackfill pure helpers and a best-effort lazy-backfill pass (decision A2)"
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "ECIES itemName at rest: wrapKey(utf8(name), recipientPubKey) on create, unwrapKey(hex, vaultPrivKey) on display — mirrors the existing encryptedKey flow"
    - "Decrypt-on-load projection: recipient decrypts into the store's plaintext itemName so all display sites stay unchanged"
    - "Zero-knowledge asymmetry: owner cannot decrypt a name wrapped for the recipient — sent-share list uses plaintext fallback (T-48-18 accept)"

key-files:
  created:
    - apps/web/src/services/__tests__/share-item-name.test.ts
  modified:
    - apps/web/src/services/share.service.ts
    - apps/web/src/services/invite.service.ts
    - apps/web/src/stores/share.store.ts
    - apps/web/src/components/file-browser/ShareDialog.tsx

key-decisions:
  - "Stop sending plaintext itemName for new shares/invites: itemName is a required DTO string, so send '' alongside itemNameEncrypted (server stores empty plaintext + bytea ciphertext)"
  - "Recipient-only decryption: the owner cannot decrypt a name wrapped for the recipient, so the sent-share list keeps the in-memory plaintext (live session) and falls back to server plaintext otherwise"
  - "Lazy backfill (A2) is detection + re-wrap only — the API has no update endpoint that accepts itemNameEncrypted, so the persist step is blocked (see deviation)"

requirements-completed: [REQ-4]

# Metrics
duration: 18min
completed: 2026-06-16
---

# Phase 48 Plan 06: Encrypt share itemName at rest (web) Summary

**ECIES-wrap the share/invite display name with the recipient (or ephemeral) pubkey on create so only ciphertext leaves the browser, decrypt itemNameEncrypted into the store's plaintext projection on received-share load (display sites unchanged), and add the lazy-backfill decision logic for legacy plaintext rows — completing REQ-4 / Phase-14 M1 on the web.**

## Performance

- **Duration:** ~18 min
- **Tasks:** 3 (2 auto/tdd complete + 1 human-verify checkpoint deferred to orchestrator)
- **Files modified:** 5 (4 source + 1 new test)

## Accomplishments

- ShareDialog ECIES-wraps `item.name` with the recipient's secp256k1 pubkey (mirrors the existing `encryptedKey` wrap in the same flow) and sends `itemNameEncrypted` with `itemName: ''` — no plaintext display name leaves the browser for new direct shares.
- Invite create (`invite.service.ts`) wraps `item.name` with the ephemeral pubkey and sends ciphertext-only; the claim path unwraps with the ephemeral key and re-wraps with the recipient's vault pubkey so the resulting Share row carries recipient-decryptable ciphertext (decision A3).
- `fetchReceivedShares` decrypts `itemNameEncrypted` with the recipient's vault private key into the store's plaintext `itemName` projection, falling back to legacy plaintext when ciphertext is absent. SharedListRow / breadcrumbs / SharedFileBrowser read the projection and are UNCHANGED.
- Added pure helpers `decryptItemName(row, vaultPrivateKey)` and `shouldBackfill(row, hasRecipientPubKey)` with a RED→GREEN unit test (8 cases: decrypt ciphertext + multibyte + 2 fallback paths; shouldBackfill 4-row truth table).
- Lazy-backfill pass (`backfillSentShareItemNames`) detects legacy plaintext sent rows on the owner's share-list load, re-wraps for the recipient, and is idempotent (skips ciphertext-bearing rows). Best-effort and non-blocking.
- Transient unwrapped name bytes are zeroed after decode (CLAUDE.md rule 9); itemName/itemNameEncrypted are never logged.

## Task Commits

1. **Task 1: RED — itemName decrypt + backfill helper test** — `8edc0b0ed` (test) — RED confirmed (helpers not exported).
2. **Task 2: GREEN — encrypt on create, decrypt for display, lazy backfill** — `e1589c0d3` (feat) — 8/8 tests GREEN, typecheck + lint + full web unit suite (45) green.
3. **Task 3: itemName-at-rest UAT** — `checkpoint:human-verify`, DEFERRED to the orchestrator's end-of-phase web-e2e + DB check (see Checkpoint below).

## Files Created/Modified

- `apps/web/src/services/share.service.ts` — `decryptItemName` + `shouldBackfill` helpers; `fetchReceivedShares` decrypts into the plaintext projection; `fetchSentShares` carries `itemNameEncrypted`; `backfillSentShareItemNames` lazy pass wired into `fetchAllSentShares`; service `createShare` sends ciphertext-only when `itemNameEncrypted` present.
- `apps/web/src/services/invite.service.ts` — wrap itemName with ephemeral pubkey on create; re-wrap for recipient on claim; ciphertext-only on the wire.
- `apps/web/src/stores/share.store.ts` — added `itemNameEncrypted?: string | null` to `ReceivedShare` + `SentShare`; `itemName` documented as the decrypted plaintext projection.
- `apps/web/src/components/file-browser/ShareDialog.tsx` — ECIES-wrap `item.name` before `sharesControllerCreateShare`; send `itemName: ''` + `itemNameEncrypted`; local store-add keeps in-memory plaintext + marks ciphertext present.
- `apps/web/src/services/__tests__/share-item-name.test.ts` — new unit test (decrypt + backfill decision).

## Decisions Made

- **Ciphertext-only on the wire for new rows:** `itemName` is a required DTO string, so new shares/invites send `itemName: ''` together with `itemNameEncrypted`. The server stores empty plaintext + the bytea ciphertext — no plaintext display name at rest for new rows.
- **Recipient-only decryption (zero-knowledge asymmetry):** the name is wrapped for the recipient, so only the recipient can decrypt for display. The owner's sent-share list keeps the in-memory plaintext from create time during the live session and otherwise falls back to whatever plaintext the server holds (empty for new ciphertext-only rows). This matches threat-register T-48-18 (accept) and the sent-list display shows the recipient pubkey + permission, not the name.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] @noble/secp256k1 v3 API in the web test**

- **Found during:** Task 1 (RED→GREEN test run)
- **Issue:** The plan's analog test (`packages/crypto`) uses `secp256k1.utils.randomPrivateKey()`, but `apps/web` resolves `@noble/secp256k1@3.0.0`, where that was renamed to `utils.randomSecretKey()`. The test threw `randomPrivateKey is not a function`.
- **Fix:** Used `secp256k1.utils.randomSecretKey()` in the test keypair helper.
- **Files modified:** `apps/web/src/services/__tests__/share-item-name.test.ts`
- **Verification:** 8/8 tests GREEN.
- **Committed in:** `e1589c0d3` (the test helper was committed RED in `8edc0b0ed` and corrected in GREEN; the helper fix is purely test-fixture infrastructure).

### Blocked / Partial — API gap (raised, not auto-fixed)

**2. [Rule 4 boundary - API endpoint missing] Lazy backfill persist cannot land server-side**

- **Found during:** Task 2 (lazy backfill, decision A2)
- **Issue:** The plan instructs the lazy backfill to "re-persist via the existing share update endpoint." The 48-05 API only plumbed `itemNameEncrypted` on the CREATE paths (`createShare`, `createInvite`, `claim-invite`). There is **no** update/patch endpoint that accepts `itemNameEncrypted` for an existing share — `sharesControllerUpdateShareEncryptedKey` takes only `encryptedKey`, and `sharesControllerUpdatePermission` takes only permission/IPNS key. Routing the backfill ciphertext through either would corrupt the wrong column.
- **Decision:** Did NOT call a wrong endpoint (would be a correctness bug). Implemented the full backfill detection + re-wrap (`backfillSentShareItemNames` using `shouldBackfill` + `wrapKey`) and structured the function so wiring a future `PATCH /shares/:id { itemNameEncrypted }` is a one-line change at the documented persist call site. Until that endpoint exists, the re-wrap is computed but not persisted; legacy rows display via the plaintext fallback (transitional T-48-18 accept).
- **Action required (follow-up):** Add an API endpoint (e.g. extend `UpdateEncryptedKeyDto` or a dedicated `PATCH itemNameEncrypted` route) + regenerate the api-client, then enable the persist call in `backfillSentShareItemNames`. This is API-side scope, outside this web-only plan.
- **Files:** `apps/web/src/services/share.service.ts` (`backfillSentShareItemNames`, with a `NOTE (API GAP)` doc block).

---

**Total deviations:** 1 auto-fixed (test fixture), 1 raised API gap (backfill persist blocked on a missing endpoint).
**Impact:** New shares/invites are ciphertext-only end-to-end (M1 closed for new rows). Legacy plaintext rows are detected and re-wrapped client-side but cannot be re-persisted until the API gains an `itemNameEncrypted` update endpoint — full legacy closure (A2) is pending that follow-up.

## Threat Surface

- T-48-15 (itemName in transit/at rest): mitigated for new direct shares — ciphertext-only on the wire (ShareDialog).
- T-48-16 (legacy plaintext rows): detection + re-wrap implemented; persist blocked on the API gap above — partial until the follow-up endpoint.
- T-48-17 (unwrapped name in memory): mitigated — transient unwrapped bytes zeroed after decode; no logging of name/ciphertext.
- T-48-18 (display fallback): accepted as the transitional state for owner sent-list + un-backfilled legacy rows.

## Known Stubs

- `backfillSentShareItemNames` computes the re-wrapped ciphertext but the persist call is a documented no-op (`void itemNameEncrypted`) pending a server endpoint that accepts `itemNameEncrypted` on update (see Deviation 2). Intentional — resolved by a follow-up API plan, not by this web plan.

## Checkpoint — DEFERRED to orchestrator (Task 3: itemName-at-rest UAT)

Task 3 is a `checkpoint:human-verify` (gate=blocking). Per execution policy the autonomous code + TDD + automated verifies are done; the UAT is deferred to the end-of-phase web-e2e + a DB check:

1. New direct share of a named item → DB `shares` row has `item_name_encrypted` populated (bytea) and `item_name` empty for the new row.
2. Recipient opens Shared → display name renders correctly (decrypted client-side).
3. New invite → claim → resulting Share row carries recipient-decryptable `item_name_encrypted`.
4. Legacy plaintext row backfill is currently re-wrap-only (persist blocked on the API gap) — verify no NEW plaintext itemName is persisted; legacy closure is pending the follow-up endpoint.

## Verification

- `pnpm --filter @cipherbox/web test share-item-name` — 8/8 GREEN.
- `apps/web` full unit suite — 45/45 GREEN.
- `tsc -b` (web typecheck) — clean (crypto + api-client dist rebuilt first).
- `eslint` on all 5 changed files — clean.

## Self-Check: PASSED

- New test file exists; both task commits (`8edc0b0ed`, `e1589c0d3`) present in git log.
- `itemNameEncrypted` wired on create (ShareDialog + invite) + decrypt projection (fetchReceivedShares) + send paths.
- Display sites (SharedListRow / breadcrumbs / SharedFileBrowser) unchanged — read the store projection.

---

_Phase: 48-sdk-self-bootstrap-regression-fix-and-shared-folder-metadata_
_Completed: 2026-06-16_
