# v1 sharing flow (frozen `v1` branch)

All paths are v1 paths, read with `git show v1:<path>`. Line numbers come from `cat -n`.

Summary: v1 does user-to-user sharing through the API database. It uses the recipient's raw secp256k1 public key, which P gets to the owner outside the app. On v1, revoking a share does not rotate any key. The rotation code exists but nothing calls it.

## 1. Actors and artifacts

Actors: the owner device (web app), the recipient device (web app), the API (NestJS and PostgreSQL), IPFS/IPNS through the API relay (`apps/web/src/lib/api/ipfs.ts:60-64`, `GET /ipns/resolve`).

Artifacts that cross a boundary:

- User public key (identity record). Uncompressed secp256k1, the Web3Auth-derived vault key (`docs/AUTHENTICATION_ARCHITECTURE.md:20,40,73`). Stored in `users.publicKey`, `unique: true` (`apps/api/src/auth/entities/user.entity.ts:17-18`). Shown in Settings (`apps/web/src/routes/SettingsPage.tsx:51,205-216`).
- Public key as a message. P sends the `0x04…` hex string to the owner outside CipherBox. The owner pastes it into the share dialog (`ShareDialog.tsx:555-575`).
- Share record. A row in `shares` (`docs/SHARING.md:60-80`): `sharer_id`, `recipient_id`, `item_type`, `ipns_name`, `item_name`, `item_name_encrypted`, `encrypted_key`, `permission`, `encrypted_ipns_key`, `hidden_by_recipient`, `revoked_at`, timestamps.
- Wrapped root key (`encryptedKey`). ECIES ciphertext of the folder `folderKey` for P's public key. Stored in `shares.encrypted_key` (`ShareDialog.tsx:244-245,289-290`).
- Wrapped child keys. ECIES ciphertexts of each descendant folder and file key, plus `folder-ipns` and `file-ipns` keys for write shares. Stored in `share_keys` (`docs/SHARING.md:82-95`, `apps/web/src/lib/crypto/key-wrapping.ts:38-164`).
- Wrapped IPNS private key (`encryptedIpnsKey`), write shares only (`ShareDialog.tsx:248-259`).
- Encrypted item name (`itemNameEncrypted`). New shares send `itemName: ''` (`ShareDialog.tsx:333-351`). `docs/SHARING.md:73` is out of date for new shares.
- Sent share list. `GET /shares/sent` returns rows with `recipientPublicKey` (`shares.controller.ts:147-180`); cached 30 s in `useShareStore` (`apps/web/src/services/share.service.ts:372-381`).
- Received share list. `GET /shares/received` returns rows with `sharerPublicKey`, `encryptedKey`, `encryptedIpnsKey` (`shares.controller.ts:110-145`).
- Folder and file metadata: encrypted JSON on IPFS behind IPNS names. v1 puts no sharing data in the metadata (`14-CONTEXT.md:84-88`).

## 2. Happy path (direct public-key share, read)

1. [HUMAN] P has an account. Else the lookup fails with `'user not found'` (`web/src/components/file-browser/ShareDialog.tsx:213-218`).
2. [HUMAN] P copies the key in Settings (`web/src/routes/SettingsPage.tsx:51-60,214`).
3. [HUMAN] P sends the key to the owner outside the app (`.planning/milestones/m2/phases/14-user-to-user-sharing/14-CONTEXT.md:18-19`).
4. [HUMAN] The owner opens Share on F. The dialog pages `GET /shares/sent` and filters by `ipnsName` (`ShareDialog.tsx:105-172`).
5. [HUMAN] The owner pastes P's key, picks `[ READ-ONLY ]` or `[ READ-WRITE ]`, clicks `--share` (`ShareDialog.tsx:555-620`). Client format check `0x04` + 128 hex (lines 48-54,181-184); self-share blocked (197-207).
6. Owner device calls `GET /shares/lookup?publicKey=…` → `{ exists }` (`api/src/shares/shares.controller.ts:182-204`, `shares.service.ts:357-366`).
7. Owner device unwraps F's key with the owner vault private key (`ShareDialog.tsx:237-240`).
8. Owner device wraps F's key for P: `wrapKey(itemFolderKey, recipientPubKeyBytes)` (`ShareDialog.tsx:244-245`); eciesjs ECIES with an ephemeral sender key (`packages/crypto/src/ecies/encrypt.ts:26-60`).
9. Owner device walks the tree: resolves F, fetches metadata (`ShareDialog.tsx:262-267`), `collectChildKeys` (`271-278`) recurses; each child key is unwrapped with the owner key and wrapped for P (`key-wrapping.ts:172-179`). Errors per child are logged and skipped (86-89, 156-159), so a share can be incomplete.
10. Owner device wraps the display name for P (`ShareDialog.tsx:336-342`).
11. Owner device sends `POST /shares` with `recipientPublicKey`, `itemType`, `ipnsName`, `itemName: ''`, `itemNameEncrypted`, `encryptedKey`, `permission`, `encryptedIpnsKey`, `childKeys` (`ShareDialog.tsx:346-356`).
12. The API finds P by `users.publicKey`, rejects self and duplicates, inserts `shares` and `share_keys` (`api/src/shares/shares.service.ts:34-135`). No notification. "Instant share — no accept/decline flow" (`14-CONTEXT.md:21`).
13. [HUMAN] P opens `~/shared`; device pages `GET /shares/received` (`web/src/hooks/useSharedNavigation.ts:213-253`); decrypts `itemNameEncrypted` with P's private key (`share.service.ts:69-83,121-128`).
14. [HUMAN] P clicks F; device unwraps `share.encryptedKey` with P's vault private key (`useSharedNavigationActions.ts:105-108`), resolves, fetches, decrypts (113-119).
15. [HUMAN] P opens a subfolder or file; `GET /shares/:shareId/keys` (`useSharedNavigationActions.ts:232,514`; API `shares.controller.ts:240-265`); cached 60 s. File download unwraps the file key with P's private key (530-539).

Later changes to F: the owner device calls `reWrapForRecipients` for each covering share's `recipientPublicKey` from the server's sent list, then `POST /shares/:shareId/keys` (`share.service.ts:469-525`).

## 3. How the owner found P's key

Out-of-band only. "No email/username lookup — recipient's pubkey obtained out-of-band (copy from Settings, send via chat, etc.)" (`14-CONTEXT.md:19`). A directory was deferred (`14-CONTEXT.md:148`). The API has only `GET /shares/lookup?publicKey=0x04... → { exists }` (`shares.controller.ts:182-204`).

## 4. Counts (direct path)

- One one-way human message minimum (P → owner); in practice one round trip.
- Zero device round trips between owner and P.
- P: 4-5 human actions. Owner: 3-4.

## 5. Revocation and rotation

`--revoke` → `DELETE /shares/:shareId` → API sets `revokedAt` only (`shares.service.ts:258-271`). `executeLazyRotation` (`share.service.ts:602-663`) has no caller; its old caller was deleted in `96455b3be8` (#422). So the `folderKey` never changes after a revoke. Gaps: `getShareKeys` does not check `revokedAt` (`shares.service.ts:186-201`); `GET /ipns/resolve` has no ownership check (`apps/api/src/ipns/ipns.controller.ts:157-192`). Write→read downgrade deletes the IPNS key rows but rotates nothing. "Cryptographic revocation (re-keying on revoke) is not implemented in either approach" (`14-CONTEXT.md:115`).

## 6. What v1 gave up

1. The server knows the social graph (`14-CONTEXT.md:88`; `.planning/seeds/blind-share-social-graph.md:13-18`).
2. The recipient key is a global identifier (`docs/AUTHENTICATION_ARCHITECTURE.md:40,73`; `user.entity.ts:17`).
3. The public key is not authenticated beyond `{ exists }`; 8-hex truncation in the UI (`ShareDialog.tsx:59-63`).
4. Later wraps trust keys from the server (`share.service.ts:492-505,626-632`; `ShareDialog.tsx:423-445`).
5. The sender is not authenticated (ECIES ephemeral sender key; `sharerPublicKey` is what the server says).
6. Any user can test whether a key belongs to an account (`GET /shares/lookup`).
7. Key and target are co-stored (`blind-share-social-graph.md:60-61`).
8. Access patterns are visible to the API (`blind-share-social-graph.md:53-55`; `ipfs.ts:60-64`).
9. Revocation is not cryptographic; write delegation hands out a raw Ed25519 IPNS key.
10. No consent, no notification; hide only, no un-hide (`docs/SHARING.md:257`).
11. Shares can be incomplete without warning (`key-wrapping.ts:86-89,156-159`).

## 7. The invite-link path

Key material:

- Ephemeral secp256k1 keypair per link, `secp256k1.keygen()` (`apps/web/src/services/invite.service.ts:56-67`). The public half wraps F's keys and is forgotten; the private half goes into the URL fragment only: `${base}#/invite/${token}?key=${ephemeralPrivKeyHex}` (`invite.service.ts:82-85`). `HashRouter` keeps the token in the fragment too (`apps/web/src/routes/index.tsx:1,11,14`). The owner device zeroes its copy (`invite.service.ts:213-216`).
- The API stores one `share_invites` row: `token` (`randomBytes(16)` base64url), `sharer_id`, `item_type`, `ipns_name`, `item_name_encrypted`, `encrypted_key`, `encrypted_child_keys`, `status`, `max_claims=1`, `claim_count`, `claimed_by`, `expires_at` (7 days) (`apps/api/src/shares/share-invite.service.ts:17-18,34-57`).

Happy path:

1. [HUMAN] Owner opens Share on F, selects the `INVITE LINK` tab (`ShareDialog.tsx:528-547,774-782`); the tab loads `GET /shares/invites?ipnsName=` (`InviteLinkTab.tsx:43-73`).
2. [HUMAN] Owner clicks `--create invite link` (`InviteLinkTab.tsx:161-169`).
3. Owner device makes the ephemeral keypair (`invite.service.ts:110`).
4. Owner device wraps F's keys for the ephemeral public key; read-only always ("Invite links are read-only — never distribute IPNS signing keys.", `invite.service.ts:151-152`); walks the tree (139-154); wraps the name (191-197).
5. Owner device `POST /shares/invites` (`invite.service.ts:200-207`; API `share-invites.controller.ts:38-68`). Returns `token`.
6. Owner device builds the URL with the private key in the fragment (210), zeroes the key (213-216), copies the URL (`InviteLinkTab.tsx:88-95`). Copy is possible only at this time.
7. [HUMAN] Owner sends the URL outside CipherBox.
8. [HUMAN] P opens the URL. `InvitePage` reads `key` from the fragment into a ref (`InvitePage.tsx:62`) and replaces the URL (74-78).
9. P's device `GET /invites/:token` (no auth) → `{ status }` or 404 (`invites.controller.ts:39-62`). Page shows "someone shared a file with you" (281-286).
10. [HUMAN] P logs in or signs up on the same page (Google, email OTP, wallet; `InvitePage.tsx:287-298`).
11. P's device claims automatically once `isAuthenticated` (`InvitePage.tsx:120-154`): `GET /invites/:token/data` (JWT), unwraps with the ephemeral private key, re-wraps for P's vault public key (`invite.service.ts:252-300`), `POST /invites/:token/claim` (303-307), zeroes the key.
12. The API converts atomically: `UPDATE … SET status='claimed' … WHERE status='active' AND claim_count < max_claims AND expires_at > NOW()` (`share-invite.service.ts:140-158`); creates the `shares` row read-only and the `share_keys` rows (194-221); self-claim 409 (134-136).
13. P's device redirects to `/shared` (`InvitePage.tsx:130-137`). [HUMAN] P clicks F and a file.

Answers: the owner never comes back; the server finishes the claim. A P with no account signs up on the page ("Serves as user acquisition funnel", `15-CONTEXT.md:24`). Caveat, not tested: an MFA `REQUIRED_SHARE` login state navigates to `/files` (`useAuth.ts:474`) and can leave the page before the claim effect runs.

Counts: owner 4 actions (open Share, select tab, create, send); P 3 with a session, 4+ without. One message, owner → P. Zero device round trips.

What the link path gave up: silent reading while active (`GET /invites/:token/data` gives ciphertext to any authenticated user without a claim); first claim wins and a thief is invisible; URL persists in clipboard and chat 7 days (`.planning/security/REVIEW-phase15-link-sharing.md:103-124`); the server plus the URL can decrypt F; after the claim the server records `claimed_by` and the normal graph edge; revoking an invite only blocks new claims (`15-CONTEXT.md:59`); no write access by link.
