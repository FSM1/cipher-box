# v2 sharing flow: blueprint and code (branch `main`, HEAD `d30509e48`)

Two paths lead from "owner O shares folder F with person P" to "P reads F". Both start from the same share dialog. The web UI offers sharing only on folders.

- Path A, contact-code grant: O and P exchange contact codes, then O grants F directly.
- Path B, invite link: O mints a bearer link, P claims it, then O converts the claim into a grant.

## 1. Actors and artifacts

Actors: O's engine (WASM worker in `apps/web`), P's engine, the API (NestJS), the IPFS record plane.

Artifacts that cross a boundary:

- Contact code. Det-CBOR `{identityPk, encSubkey, bindingSig}`, shown as hex, moved out-of-band (paste or QR scan). Created at `crates/engine/src/session.rs:133-135`. Import verifies the binding signature fail-closed (`crates/engine/src/grants/contact.rs:70-72`). Cap 1024 bytes (`facade.rs:7644-7648`).
- Invite link. `${origin}/invite#<fragment>` (`apps/web/src/sharing/inviteLink.ts:12-14`). Fragment: base64url det-CBOR `{inviteSecret (32 bytes), ownerContactCode, scopeRootName}`, at most 2048 bytes (`crates/engine/src/grants/invite.rs:380-470`). The invite secret is the whole bearer capability; it derives an ephemeral secp256k1 identity and an X25519 subkey (`invite.rs:81-86`).
- Invite claim. `InviteClaim {claimId (16 bytes), scopeRootName, contactCode}` where `contactCode` is the claimant's own (`invite.rs:537-600`). Sealed to O's encryption subkey, signed by the ephemeral identity, posted to O's mailbox (`invite.rs:613-634`).
- Share pointer. `SharePointer {scopeRootName, sharerIdentityPk, displayName, permission}` (`crates/engine/src/grants/accept.rs:43-53`). Name and permission are courtesy; the owner-signed commitment is the authority.
- Mailbox item (wire). HPKE-sealed blob, at most 8 KiB, sealed to the recipient X25519 subkey, posted to the recipient identity public key with a random idempotency key; sender signature inside the seal (`crates/engine/src/mailbox/mod.rs:65-99`). Routes `POST/GET/DELETE /mailbox/messages` (`apps/api/src/mailbox/mailbox.controller.ts:38-84`). The API sees `{sender account, recipient, time}`.
- Scope root record. IPNS record whose envelope carries the grant section: grant blobs keyed by blinded tag, the owner-signed grant-set commitment (masked recipients, `cutEpoch`), the owner blob, the ascent link, structure signatures; the sealed write-body carries the grant ledger. The API registers the name first (`apps/api/src/registry/registry.controller.ts:45`).
- Grant blob. Scope seeds and `pointerReadKey` sealed to the recipient encryption subkey; a write grant also carries the write seed; keyed by the blinded tag from ECDH(owner enc, recipient enc) and the scope root name (`crates/engine/src/grants/ledger.rs:56`, `:174`).
- Scope pointer record. Owner-identity-signed re-point object sealed under `pointerReadKey` at an IPNS name from `ownerPointerSeed`; vouched at the mint (`crates/engine/src/grants/create.rs:1122-1133`).
- Device-local state: the contact book on each side; O's `RecordedInvite` and `ConvertedClaimRecord` (`invite.rs:316-331`, `:512-530`); P's received-share bookmark `{name, sharerPub, displayName, permission, pointerReadKey}` (`accept.rs:139`).

## 2. Happy path

### Path A: contact-code grant

| # | Who | Action and material | Code |
|---|---|---|---|
| A0 | API | P must already have an account; the mailbox rejects an unknown recipient with 404. | `apps/api/src/mailbox/services/mailbox.service.ts:107-111` |
| A1 [HUMAN] | O | Clicks "share..." on F; the dialog reads `sharing(F)`: grants, refusals, O's own code. | `apps/web/src/components/file-browser/FileBrowserActions.tsx:147-148`; `crates/engine/src/facade.rs:10676-10716` |
| A2 [HUMAN] | O | Clicks "import contact...", copies own hex code, sends it to P out-of-band. | `apps/web/src/components/sharing/ContactImportForm.tsx:99-107` |
| A3 [HUMAN] | P | Same on P's side; P needs a folder of P's own to open the dialog. | `tests/web-e2e/sharing.ts:16-17`, `:122-127` |
| A4 [HUMAN] | O | Pastes or scans P's code, clicks "import"; `ImportContact` verifies the binding and stores the contact in the sealed book. | `apps/web/src/sharing/contactCode.ts:22-36`; `facade.rs:7643-7659`; `crates/engine/src/grants/contact_store.rs:445` |
| A5 [HUMAN] | P | Imports O's code; A9 needs it; may happen after A6 because the pointer waits in the mailbox. | `crates/engine/src/grants/inbox.rs:126` |
| A6 [HUMAN] | O | Selects P and a permission, clicks "grant": `grant` → `recipient_contact` (book only) → `share_scope`. | `ShareDialog.tsx:69-74`; `facade.rs:8410-8421`, `:8049-8063`, `:8451` |
| A6a | O | Refuses the vault root and any folder that already names a scope. | `facade.rs:8462`, `:8483`, `:8519` |
| A6b | O | `create_grant` mints the row: tag from O's enc secret and P's enc pk; masks the commitment entry under `pointerReadKey`; signs the ledger row with O's identity key. | `create.rs:741-789`; `ledger.rs:174` |
| A6c | O → IPFS | Converges the subtree; mints the scope at epoch 1 with a fresh seed; signs the commitment; seals P's blob; vouches the scope pointer; publishes root first, re-seals the interior, republishes the parent child-scope index. | `create.rs:905`, `:1020-1160`, `:1247` |
| A6d | O | Write grant only: name wave. | `facade.rs:8698`, `:8885` |
| A6e | O → API | Seals a `SharePointer` to P's subkey, signs with O's identity key, posts to P's inbox. | `create.rs:791-835`; `facade.rs:8703` |
| A7 | API | Stores the blob; idempotency dedup; pending cap (409); 90-day retention. | `mailbox.service.ts:97-215`, `:30` |
| A8 | P (tick) | `ShareInbox.pull` polls, opens each item, verifies the sender, keeps only pointers from senders in P's book, resolves the root. | `facade.rs:7320-7331`; `inbox.rs:84-181`; `mailbox/mod.rs:103-120` |
| A9 | P | `accept_share` binds the sender to the contact; self-locates the blob with P's enc secret and O's verified enc pk; checks the tag is committed; opens the blob; runs the adoption gate against O's contact-anchored identity; persists the bookmark and `pointerReadKey`; acks. | `accept.rs:858-1010` |
| A10 | P | `ReceivedShareStatus.refresh` resolves again, re-opens the blob, deposits the read seed, classifies as "granted". | `facade.rs:7332+`; `received_status.rs:312`, `:638-760` |
| A11 [HUMAN] | P | Opens `/shared`, clicks "open". | `apps/web/src/routes/SharedPage.tsx:86-93` |

### Path B: invite link

| # | Who | Action and material | Code |
|---|---|---|---|
| B1 [HUMAN] | O | Clicks "share..." on F, picks permission and lifetime (default 7 days), clicks "mint invite link". | `ShareDialog.tsx:76-87`; `InviteLinkPanel.tsx:71-99` |
| B2 | O → IPFS | `share_scope(InviteLink)` → `mint_invite_link`: random invitee secret; row minted to the ephemeral identity via `mint_grant_row` with the deadline in the ledger row; converge; `RecordedInvite` persisted before publish; same scope mint as A6c; write link also runs the name wave; no mailbox item. | `facade.rs:8427-8436`, `:8633-8672`; `invite_mint.rs:163-230`; `invite.rs:353-397`, `:15-17` |
| B3 [HUMAN] | O | The fragment is sealed; the dialog shows the URL once; O copies and sends it out-of-band. | `invite_mint.rs:89-98`; `ShareDialog.tsx:206-213` |
| B4 [HUMAN] | P | Opens the link; if signed out, signs in in a new tab and reloads the link tab. | `InvitePage.tsx:68-88` |
| B5 [HUMAN] | P | Clicks "claim this invite"; the page strips the fragment and calls `claimInviteLink`. | `InvitePage.tsx:42-57`, `:89-101` |
| B6 | P → API | `claim_invite_link` decodes the fragment, derives the ephemeral identity, imports O's code from the fragment, builds an `InviteClaim` with P's own code, seals to O's subkey, signs with the ephemeral key, posts to O's inbox, records O in P's book. | `facade.rs:9131-9186`; `invite.rs:613-634` |
| B7 [HUMAN, implied] | P → O | P tells O out-of-band that P claimed; no code tells O. | — |
| B8 [HUMAN] | O | Opens the share dialog on F again, clicks "convert claims". | `InviteLinkPanel.tsx:44-58` |
| B9 | O → IPFS, API | `convert_invite_claims` polls the mailbox, checks owner authority and the committed ledger; per item `convert_invite_claim` checks scope name, sender against the recorded link identity, expiry, claim-id reuse; imports P's code; mints P's personal row (the link row stays); records P in O's book; re-signs the commitment; publishes the root once; per item records the grant floor, posts a `SharePointer` to P, persists the spent-claim record, acks. | `facade.rs:9190-9450`, `:9454`; `invite.rs:784-930` |
| B10–B12 | P | Same as A8–A11; the tick accepts because B6 put O in P's book. | as above |

## 3. Why each human step exists

- Out-of-band contact exchange (A2–A5, B3): no directory. `blueprint/api.md:293-294`: "Identity keys therefore only ever arrive out-of-band — there is no in-band lookup for a directory substitution attack to poison." `CONTEXT.md:99`: the contact code "Replaces any people directory."
- O imports P's code before a grant (A4): `facade.rs:8045-8048`: "The recipient's encryption subkey is only usable because a verified binding signature tied it to this identity key at import — a key taken from the command instead would let a host wrap a grant to anyone."
- P imports O's code before accept (A5): `CONTEXT.md:100`: "Every payload is sender-identity-signed inside the seal, verified against the contact-code-anchored key; unauthenticated items are dropped." `inbox.rs:13-15`: "the contact book is the accept's only trust anchor".
- The claim needs a click (B5): `InvitePage.tsx:19-23`: "A mount-time claim would let any page that can navigate a signed-in tab here — an `iframe`, a `window.open`, a mailed link — spend an attacker's link under the member's identity".
- P claims before O grants (B5 before B8): the claim carries P's code. `blueprint/engine.md:1020-1021`: "claim = a sealed, ephemeral-key-signed mailbox request the owner converts to a personal grant". `invite.rs:768-770`: "re-anchoring is the whole point of conversion".
- O converts (B8): `blueprint/engine.md:989-990`: "sharing, revoking, and every commitment change are owner-only." `invite.rs:763-766`: deciding from the record "would let any committed grantee … drive the owner into signing a grant for an identity the owner never approved." No blueprint sentence asks for a manual press; the UI says the grant "is theirs to complete" (`InvitePage.tsx:115-116`).

## 4. Counts before P can read F

Path A: one out-of-band round trip (both codes), then one automatic in-band message O → P. O about 4 actions, P about 4.

Path B: 1.5 round trips (link O→P out-of-band, claim P→O in-band, pointer O→P in-band), plus an implied out-of-band nudge P→O, so 2. O 3 actions (mint, send, convert); P 3 or 4 plus the nudge. Each automatic hop waits one mailbox poll (30 s cadence per `blueprint/api.md`).

## 5. Revocation

O clicks "revoke" (`ShareDialog.tsx:141-149`) → `revoke_grant` → `cut_recipient` (`facade.rs:8164-8240`); the tag derives from O's own secret. `cut_and_rotate` (`facade.rs:8249-8313`) builds a cut set with the next `cutEpoch` (`rotation/trigger.rs:473`, `:519`); `drive_cut` → `rotate_on_cut` (`trigger.rs:795`) republishes the scope root and every descendant scope root under a fresh seed, re-seals blobs for survivors only, bumps `minReadEpoch`; a write revoke runs the name wave. O raises its cut-epoch floor; O's book forgets a contact that only a link claim added. P gets no message; P's tick finds a fresh owner-signed record with no blob at P's tag → "revocation-signal" (`grants/revocation.rs:83-96`); `/shared` shows "the owner removed you from this folder" (`apps/web/src/sharing/receivedShares.ts:28`). "Revoke link" cuts only the link row (`facade.rs:9018-9055`); grants from its claims stay.

## 6. Gaps: built but not wired, or likely broken

1. O gets no signal that a claim waits. The tick skips claim items (`inbox.rs:11-15`); conversion runs only on the button in that folder's dialog; no event or badge.
2. The contact exchange UI lives only inside the share dialog of a folder the user owns; a new recipient must create a folder to see codes (`FileBrowserActions.tsx:147`; `tests/web-e2e/sharing.ts:16`).
3. QR scan exists (`contactScanner.ts`); QR display does not; own code is hex only (`ContactImportForm.tsx:103-106`).
4. Each folder takes one share. A second direct grant → `grant-target-already-names-a-scope`; a link on a directly granted folder → `invite-target-already-names-a-scope` (`facade.rs:3589-3611`, `apps/web/src/sharing/shareRefusals.ts`). Only `convert_invite_claims` appends a row.
5. A read grant has no re-send after a failed pointer post. `create.rs:397-401` says "A retry posts a fresh item", but `share_scope` resumes only a write share (`facade.rs:8494-8519`); a read retry hits `AlreadyAScope`. A 404 or 409 leaves the scope minted with no way to tell P. No test.
6. For read access, conversion is not a cryptographic gate: the fragment secret alone opens the link's blob (test `invite.rs:1285-1345`). The engine only does not offer that read path.
7. The web UI shares folders only; the blueprint makes files first-class targets (`blueprint/engine.md:1027`).
8. Stale docs: `grants/mod.rs:9-10` ("Write grants are not implemented here"), `create.rs:29-32` (invites listed as not implemented), `docs/SHARING.md` describes v1.
9. Accepted residuals in code: the fragment's `ownerContactCode` is unsigned (`facade.rs:9124-9129`); a claim post shows the claimant→owner edge to the API (`invite.rs:607-610`).
10. Tests: `tests/web-e2e/tests/contact-grant.spec.ts`, `tests/web-e2e/tests/invite.spec.ts`, `tests/web-e2e/staging/invite.spec.ts`. Only the staging spec drives the claimant to opening the share.
