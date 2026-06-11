<!-- generated-by: gsd-doc-writer -->

# CipherBox Sharing Specification

This document specifies the implemented file and folder sharing feature in CipherBox: user-to-user direct sharing and link-based sharing (invite links). Both flows are zero-knowledge — the server stores only ECIES-wrapped ciphertext and never sees a plaintext key.

Sharing is a v1.0 feature (read and write permission levels are both supported).

## Related documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — system overview and encryption primitives
- [AUTHENTICATION_ARCHITECTURE.md](AUTHENTICATION_ARCHITECTURE.md) — vault keypair derivation (secp256k1)
- [FILESYSTEM_SPECIFICATION.md](FILESYSTEM_SPECIFICATION.md) — folder/file metadata schema
- [DATABASE_EVOLUTION_PROTOCOL.md](DATABASE_EVOLUTION_PROTOCOL.md) — migration discipline

---

## Design principles

1. **Zero-knowledge server.** The CipherBox API stores only ECIES ciphertext. It has no ability to decrypt a shared key, read a shared file, or observe the plaintext name of a shared item beyond the `itemName` stored for UX display.
2. **Client-side re-wrapping.** All sharing operations begin with the sharer decrypting a key on their device and re-encrypting it for the recipient's public key. The server receives only the output ciphertext.
3. **IPNS as share boundary.** A share record is anchored to a single `ipnsName`. Sharing a folder shares the folder's IPNS root; subfolders and files within it have their own keys propagated as child keys.
4. **Lazy key rotation on revocation.** Revoking a share is a soft-delete. The sharer's key is not rotated immediately; rotation happens the next time the sharer modifies the shared folder (`executeLazyRotation` in `apps/web/src/services/share.service.ts`).

---

## Cryptographic primitives

All key wrapping uses ECIES over secp256k1 (package `@cipherbox/crypto`, source at `packages/crypto/src/ecies/`).

| Operation                       | Function                                               | File                                   |
| ------------------------------- | ------------------------------------------------------ | -------------------------------------- |
| Wrap a key for a public key     | `wrapKey(plainKey, publicKey)`                         | `packages/crypto/src/ecies/encrypt.ts` |
| Unwrap a key with a private key | `unwrapKey(ciphertext, privateKey)`                    | `packages/crypto/src/ecies/decrypt.ts` |
| Unwrap then re-wrap in one call | `reWrapKey(ciphertext, ownerPrivKey, recipientPubKey)` | `packages/crypto/src/ecies/rewrap.ts`  |

`reWrapKey` zeros the intermediate plaintext key via `fill(0)` before returning or on any error path, preventing key material from lingering in memory.

---

## Share key types

Defined in `apps/api/src/shares/types.ts`:

| Type           | Value           | Meaning                                                        |
| -------------- | --------------- | -------------------------------------------------------------- |
| `ChildKeyType` | `'file'`        | `fileKey` for a specific file                                  |
| `ChildKeyType` | `'folder'`      | `folderKey` for a subfolder                                    |
| `ChildKeyType` | `'file-ipns'`   | IPNS private key for a file's metadata IPNS name               |
| `ShareKeyType` | `'folder-ipns'` | IPNS private key for a subfolder IPNS name (write shares only) |

`ShareKeyType` is the superset: `['file', 'folder', 'file-ipns', 'folder-ipns']`. `ChildKeyType` excludes `'folder-ipns'` because that key type is only stored after a share is created (it is added when a subfolder's write access is granted, not during initial share creation).

---

## Data model

Three database tables back the sharing feature.

### `shares`

Source: `apps/api/src/shares/entities/share.entity.ts`

Primary sharing record. A unique partial index (`WHERE revoked_at IS NULL`) on `(sharer_id, recipient_id, ipns_name)` prevents duplicate active shares for the same triple while allowing revoked historical records to coexist (`apps/api/src/migrations/1740300000000-SharesPartialUniqueIndex.ts`).

| Column                | Type           | Description                                                                                             |
| --------------------- | -------------- | ------------------------------------------------------------------------------------------------------- |
| `id`                  | `uuid`         | Primary key                                                                                             |
| `sharer_id`           | `uuid`         | FK to `users.id` (CASCADE delete)                                                                       |
| `recipient_id`        | `uuid`         | FK to `users.id` (CASCADE delete)                                                                       |
| `item_type`           | `varchar(10)`  | `'folder'` or `'file'`                                                                                  |
| `ipns_name`           | `varchar(255)` | IPNS name of the shared item (e.g., `k51...`)                                                           |
| `item_name`           | `varchar(255)` | Plaintext display name (minimal privacy impact — server already knows involved user IDs)                |
| `encrypted_key`       | `bytea`        | `folderKey` (for folder shares) or parent `folderKey` (for file shares) wrapped via ECIES for recipient |
| `permission`          | `varchar(10)`  | `'read'` (default) or `'write'`                                                                         |
| `encrypted_ipns_key`  | `bytea`        | IPNS private key wrapped via ECIES for recipient; `NULL` for read-only shares                           |
| `hidden_by_recipient` | `boolean`      | Recipient has dismissed this share from their view                                                      |
| `revoked_at`          | `timestamp`    | `NULL` = active; set = soft-deleted pending key rotation                                                |
| `created_at`          | `timestamp`    | —                                                                                                       |
| `updated_at`          | `timestamp`    | —                                                                                                       |

### `share_keys`

Source: `apps/api/src/shares/entities/share-key.entity.ts`

Stores individual child keys (file keys, subfolder keys, IPNS keys) for a share. A unique constraint on `(share_id, key_type, item_id)` prevents duplicate entries.

| Column          | Type           | Description                                           |
| --------------- | -------------- | ----------------------------------------------------- |
| `id`            | `uuid`         | Primary key                                           |
| `share_id`      | `uuid`         | FK to `shares.id` (CASCADE delete)                    |
| `key_type`      | `varchar(12)`  | One of the four `ShareKeyType` values                 |
| `item_id`       | `varchar(255)` | UUID of the file or subfolder this key belongs to     |
| `encrypted_key` | `bytea`        | ECIES ciphertext of the key wrapped for the recipient |
| `created_at`    | `timestamp`    | —                                                     |

The `key_type` column was widened from `varchar(10)` to `varchar(12)` in migration `1743100000000-WidenShareKeyType.ts` to accommodate `'folder-ipns'` (11 characters).

### `share_invites`

Source: `apps/api/src/shares/entities/share-invite.entity.ts`

Short-lived records backing link-based sharing. The token is a 22-character URL-safe base64 string (`randomBytes(16).toString('base64url')`). The default TTL is 7 days. Expired invites are hard-deleted on access.

| Column                 | Type           | Description                                                                                                                   |
| ---------------------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `id`                   | `uuid`         | Primary key                                                                                                                   |
| `token`                | `varchar(44)`  | Unique URL-safe base64 token                                                                                                  |
| `sharer_id`            | `uuid`         | FK to `users.id` (CASCADE delete)                                                                                             |
| `item_type`            | `varchar(10)`  | `'folder'` or `'file'`                                                                                                        |
| `ipns_name`            | `varchar(255)` | IPNS name of the shared item                                                                                                  |
| `item_name`            | `varchar(255)` | Plaintext display name                                                                                                        |
| `encrypted_key`        | `bytea`        | Item key wrapped with the ephemeral public key                                                                                |
| `encrypted_child_keys` | `jsonb`        | Array of `{keyType, itemId, encryptedKey}` wrapped with ephemeral public key; `NULL` for single-file invites with no children |
| `status`               | `varchar(20)`  | `'active'`, `'claimed'`, or `'revoked'`                                                                                       |
| `max_claims`           | `integer`      | Maximum number of times this invite can be claimed (default `1`)                                                              |
| `claim_count`          | `integer`      | Number of times the invite has been claimed                                                                                   |
| `claimed_by`           | `uuid`         | User ID of the claimer (set on claim)                                                                                         |
| `expires_at`           | `timestamp`    | Expiry timestamp                                                                                                              |
| `created_at`           | `timestamp`    | —                                                                                                                             |

---

## User-to-user sharing flow

### Overview

The sharer looks up the recipient's `publicKey` via the API, re-wraps keys on their device, and POSTs the ciphertext to the server. The recipient retrieves the wrapped keys at login and decrypts them locally.

### Step-by-step

1. **Recipient lookup.** The sharer calls `GET /shares/lookup?publicKey=0x04...` to verify the recipient is a registered CipherBox user. The endpoint validates the uncompressed secp256k1 format (`0x04` + 128 hex characters). Source: `apps/api/src/shares/shares.controller.ts` → `lookupUser`.

2. **Key collection.** The sharer's client traverses the item's metadata tree and re-wraps every key for the recipient's `publicKey`:
   - For a folder: unwrap `folderKeyEncrypted` → `reWrapKey(ciphertext, ownerPrivKey, recipientPubKey)` for the root folder, plus all descendant subfolder keys and file keys via `collectChildKeys` (`apps/web/src/lib/crypto/key-wrapping.ts`).
   - For a file: re-wrap the parent `folderKey` (recipient needs it to decrypt file metadata) and the `fileKey` as a `'file'` child key.
   - For write permission: additionally re-wrap the IPNS private key of the shared item so the recipient can publish to that IPNS name.

3. **Create share.** The sharer POSTs to `POST /shares` with `CreateShareDto`:

   ```json
   {
     "recipientPublicKey": "04abc...",
     "itemType": "folder",
     "ipnsName": "k51...",
     "itemName": "Project Files",
     "encryptedKey": "<hex ECIES ciphertext>",
     "permission": "read",
     "childKeys": [
       { "keyType": "folder", "itemId": "<uuid>", "encryptedKey": "<hex>" },
       { "keyType": "file", "itemId": "<uuid>", "encryptedKey": "<hex>" },
       { "keyType": "file-ipns", "itemId": "<uuid>", "encryptedKey": "<hex>" }
     ]
   }
   ```

   Source: `apps/api/src/shares/dto/create-share.dto.ts`. For write permission, include `"permission": "write"` and the `"encryptedIpnsKey"` field. Omitting `encryptedIpnsKey` with `"permission": "write"` returns HTTP 400; including it with `"permission": "read"` also returns HTTP 400.

4. **Server stores share and child keys.** `SharesService.createShare` (`apps/api/src/shares/shares.service.ts`) validates the recipient exists, checks for duplicate active shares, creates the `shares` row, and bulk-inserts `share_keys` rows for the provided `childKeys`.

5. **Recipient access.** On the recipient's device, `GET /shares/received` returns active non-hidden shares with `sharerPublicKey`, `encryptedKey`, `permission`, and `encryptedIpnsKey`. The recipient decrypts `encryptedKey` with their own `privateKey` to obtain the `folderKey` for the shared item, then fetches child keys via `GET /shares/:shareId/keys`.

### Post-upload key propagation

When a sharer adds files or subfolders inside an already-shared folder, the new keys must be distributed to existing recipients. The function `reWrapForRecipients` in `apps/web/src/services/share.service.ts` handles this as a fire-and-forget operation after each upload or subfolder creation:

1. `findCoveringShares` walks the folder ancestor chain to find shares that cover the modified folder (the share may be on a parent folder, not the immediate folder).
2. For each covering share recipient, `wrapKey(plaintextKey, recipientPubKey)` produces the wrapped key.
3. `POST /shares/:shareId/keys` adds the new `ShareKey` rows.

---

## Link sharing flow (invite links)

Link sharing does not require the sharer to know the recipient's `publicKey` upfront. Instead, an ephemeral secp256k1 keypair acts as a cryptographic bridge.

### Security model

The ephemeral private key is placed in the URL hash fragment (`#/invite/:token?key=<hex>`). Hash fragments are never sent to the server by browsers, ensuring the server has no ability to decrypt the ciphertext stored in `share_invites.encrypted_key`. Source: `apps/web/src/services/invite.service.ts` → `buildInviteUrl`.

### Invite creation

Source: `apps/web/src/services/invite.service.ts` → `createInviteLink`

1. Generate ephemeral secp256k1 keypair via `secp256k1.keygen()`.
2. Unwrap the item's key using the sharer's `privateKey`.
3. Wrap the plaintext key with the ephemeral `publicKey` via `wrapKey`.
4. For folders: traverse children with `collectChildKeys`, wrapping each descendant key with the ephemeral `publicKey`.
5. For files: wrap the parent `folderKey` as the root `encryptedKey` and the `fileKey` as a `'file'` child key.
6. POST to `POST /shares/invites` (`CreateInviteDto`): server stores the invite with a 7-day expiry.
7. Build URL: `${origin}${pathname}#/invite/${token}?key=${ephemeralPrivKeyHex}`.
8. Zero the ephemeral private key from memory (`fill(0)`) in a `finally` block.

### Recipient claim flow

Source: `apps/web/src/routes/InvitePage.tsx` and `apps/web/src/services/invite.service.ts` → `claimInvite`

1. The recipient opens the URL; `InvitePage` reads the ephemeral private key from the hash fragment into a `ref` and immediately replaces the URL to remove the key from the address bar.
2. `GET /invites/:token` (unauthenticated) checks whether the invite is active. The server returns only `{ status: 'active' }` or HTTP 404 — no file name or sharer identity is revealed before authentication (prevents token-existence oracle attacks).
3. If valid, the page presents a login CTA. After the recipient authenticates, auto-claim begins.
4. `GET /invites/:token/data` (authenticated) returns `encryptedKey`, `encryptedChildKeys`, `itemType`, `ipnsName`, `itemName`.
5. Client unwraps `encryptedKey` with the ephemeral private key, then re-wraps with the recipient's own `publicKey`.
6. All `encryptedChildKeys` are unwrapped and re-wrapped in the same pass.
7. `POST /invites/:token/claim` sends the re-wrapped keys. The server atomically increments `claim_count` (`UPDATE ... WHERE status = 'active' AND claim_count < max_claims`) to enforce single-claim. A `Share` record and `ShareKey` rows are created inside a database transaction.
8. On success, the recipient is redirected to `/shared`.

The ephemeral private key is zeroed in a `finally` block after the claim call (`ephemeralPrivKey.fill(0)`).

### Public endpoint design

`GET /invites/:token` intentionally leaks no information beyond whether the token is active. Expired, claimed, and revoked states all produce HTTP 404 from the server. Error reason discrimination (`'expired'` vs `'claimed'`) comes only from the HTTP 409 response of the claim endpoint, not the status check.

---

## Permission levels

| Permission | folderKey | encryptedIpnsKey | Can read files | Can write (add/modify) files |
| ---------- | --------- | ---------------- | -------------- | ---------------------------- |
| `'read'`   | Provided  | `NULL`           | Yes            | No                           |
| `'write'`  | Provided  | Provided         | Yes            | Yes                          |

For write permission, the `encryptedIpnsKey` column stores the IPNS private key for the shared item's IPNS name, wrapped with the recipient's `publicKey`. This allows the recipient to publish updated metadata to the IPNS name.

The permission level can be changed by the sharer after the share is created via `PATCH /shares/:shareId/permission` (`UpdatePermissionDto`). Upgrading to write requires supplying `encryptedIpnsKey`; the API returns HTTP 400 if it is absent. Downgrading to read clears `encryptedIpnsKey` on the server.

---

## Revocation and lazy key rotation

### Revocation (soft-delete)

`DELETE /shares/:shareId` sets `revoked_at` to the current timestamp. The share record remains in the database. The recipient continues to see their cached copy of the data until the sharer performs a key rotation.

### Lazy rotation protocol

Key rotation is deferred to the sharer's next folder modification. Before any write to a shared folder, the client checks `GET /shares/pending-rotations`. If any revoked shares exist for that folder, `executeLazyRotation` (`apps/web/src/services/share.service.ts`) runs:

1. Generate a new random 32-byte `folderKey`.
2. Fetch the revoked share IDs for the folder and the currently active shares.
3. For each **remaining** (non-revoked) share recipient, re-wrap the new `folderKey` with their `publicKey` via `wrapKey` and call `PATCH /shares/:shareId/encrypted-key`.
4. If any re-wrap fails, abort the rotation (throw) to prevent inconsistent state — the new `folderKey` is zeroed.
5. Hard-delete revoked share records via `DELETE /shares/:shareId/complete-rotation`.
6. Invalidate the sent shares cache so the next check fetches fresh state.

The actual folder metadata re-encryption (decrypt with old key, re-encrypt with new key, publish IPNS) is performed by the caller (`folder.service.ts`) which holds the IPNS private key.

### Complete rotation API

`DELETE /shares/:shareId/complete-rotation` hard-deletes a revoked share row. It requires `revokedAt` to be non-null (HTTP 409 if the share has not been revoked first). Only the sharer can call this endpoint.

---

## Recipient-side actions

### Hide a share

Recipients can dismiss a share from their view without revoking it: `PATCH /shares/:shareId/hide` sets `hidden_by_recipient = true`. Hidden shares are excluded from `GET /shares/received`. Only the recipient can hide a share (HTTP 403 if the caller is the sharer). There is no unhide endpoint — the share remains accessible via direct API call with the `shareId`.

---

## API surface

All sharing endpoints require JWT authentication unless noted.

### `SharesController` — `/shares`

Source: `apps/api/src/shares/shares.controller.ts`

| Method   | Path                                 | Description                                          |
| -------- | ------------------------------------ | ---------------------------------------------------- |
| `POST`   | `/shares`                            | Create a user-to-user share                          |
| `GET`    | `/shares/received`                   | Paginated list of active, non-hidden received shares |
| `GET`    | `/shares/sent`                       | Paginated list of active sent shares                 |
| `GET`    | `/shares/lookup?publicKey=`          | Verify a user exists by their `publicKey`            |
| `GET`    | `/shares/pending-rotations`          | Revoked shares awaiting key rotation (sharer only)   |
| `GET`    | `/shares/:shareId/keys`              | Child key list (accessible by sharer or recipient)   |
| `POST`   | `/shares/:shareId/keys`              | Add child keys to an existing share                  |
| `PATCH`  | `/shares/:shareId/permission`        | Change permission level (sharer only)                |
| `DELETE` | `/shares/:shareId`                   | Soft-delete (revoke) a share (sharer only)           |
| `PATCH`  | `/shares/:shareId/hide`              | Hide a share from recipient's view (recipient only)  |
| `PATCH`  | `/shares/:shareId/encrypted-key`     | Update wrapped key after lazy rotation (sharer only) |
| `DELETE` | `/shares/:shareId/complete-rotation` | Hard-delete after key rotation (sharer only)         |

Pagination query parameters: `limit` (max 100) and `offset`.

### `ShareInvitesController` — `/shares/invites`

Source: `apps/api/src/shares/share-invites.controller.ts`

Authenticated management of invite links owned by the current user.

| Method   | Path                        | Description                     |
| -------- | --------------------------- | ------------------------------- |
| `POST`   | `/shares/invites`           | Create an invite link           |
| `GET`    | `/shares/invites?ipnsName=` | List active invites for an item |
| `DELETE` | `/shares/invites/:inviteId` | Revoke an active invite link    |

### `InvitesController` — `/invites`

Source: `apps/api/src/shares/invites.controller.ts`

Public-facing endpoints for the invite claim flow. Individual endpoints opt in to authentication.

| Method | Path                    | Auth | Description                                               |
| ------ | ----------------------- | ---- | --------------------------------------------------------- |
| `GET`  | `/invites/:token`       | None | Status check — returns `{ status: 'active' }` or HTTP 404 |
| `GET`  | `/invites/:token/data`  | JWT  | Full invite data for the claim flow                       |
| `POST` | `/invites/:token/claim` | JWT  | Claim the invite with re-wrapped keys                     |

---

## Web UI entry points

| Component           | Path                                                         | Purpose                                                     |
| ------------------- | ------------------------------------------------------------ | ----------------------------------------------------------- |
| `ShareDialog`       | `apps/web/src/components/file-browser/ShareDialog.tsx`       | Direct share creation UI (user lookup + key wrapping)       |
| `InviteLinkTab`     | `apps/web/src/components/file-browser/InviteLinkTab.tsx`     | Invite link creation and management within the share dialog |
| `SharedFileBrowser` | `apps/web/src/components/file-browser/SharedFileBrowser.tsx` | "Shared with me" view at `/shared` route                    |
| `InvitePage`        | `apps/web/src/routes/InvitePage.tsx`                         | Invite landing page at `#/invite/:token`                    |
| `SharedPage`        | `apps/web/src/routes/SharedPage.tsx`                         | Route wrapper for `SharedFileBrowser`                       |

---

## Database migrations

| Migration                  | Timestamp       | Description                                                                         |
| -------------------------- | --------------- | ----------------------------------------------------------------------------------- |
| `AddSharesTables`          | `1740250000000` | Create `shares` and `share_keys` tables                                             |
| `SharesPartialUniqueIndex` | `1740300000000` | Replace absolute unique index with partial index `WHERE revoked_at IS NULL`         |
| `AddShareInvites`          | `1740400000000` | Create `share_invites` table                                                        |
| `AddWritableShares`        | `1743000000000` | Add `permission` and `encrypted_ipns_key` columns to `shares`                       |
| `WidenShareKeyType`        | `1743100000000` | Widen `share_keys.key_type` from `varchar(10)` to `varchar(12)` for `'folder-ipns'` |
