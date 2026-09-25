# CipherBox Sharing

This document describes sharing in CipherBox v2 as the engine on `main` builds it. The invite link is the primary sharing path. A contact-code grant is the advanced path. There is no approve step: any owner device converts a claim by itself.

The normative source is [`blueprint/engine.md`](../blueprint/engine.md) "Grants and ledger" and "Mailbox logic". The terms come from [`CONTEXT.md`](../CONTEXT.md) "Envelope and grants" and "Sharing". When this document and the blueprint disagree, the blueprint is correct.

## Decisions

| ADR                                                                                                                                                   | Subject                                                    |
| ----------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| [0023](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0023-the-invite-link-is-the-primary-sharing-path-and-conversion-runs-by-itself.md) | The link is the primary path; conversion runs by itself    |
| [0024](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0024-a-link-holder-reads-at-once-from-the-link-blob.md)                            | A link holder reads at once from the link blob             |
| [0025](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0025-revocation-under-the-link-first-model.md)                                     | Revocation under the link-first model                      |
| [0026](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0026-a-scope-root-takes-many-grants.md)                                            | A scope root takes many grants                             |
| [0027](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0027-a-grantee-name-is-not-an-identity.md)                                         | A grantee name is not an identity                          |
| [0028](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0028-the-invite-page-previews-before-join.md)                                      | The invite page previews the share before the person joins |

This document cites a decision as "ADR 0023 D3" (decision) or "ADR 0023 E2" (residual).

## Where the grant lives

A grant lives in the published record of the shared folder, not on the server. Sharing a folder makes it a scope root. The scope root carries:

- one grant blob per recipient, keyed by a blinded tag;
- the grant ledger, sealed in the write-body;
- the owner-signed grant-set commitment.

Each commitment entry has a kind: `personal` or `link`. A link entry also carries the owner-signed deadline, the conversion permission and the admission cap (ADR 0023 D2, D9, ADR 0024 D4). Each ledger row carries an owner signature over its keys and tag, plus the via-link reference, the grantee name and the name source flag when they are present (ADR 0027 D3).

The API holds no grant and no key. It carries the mailbox only: share pointers, claims, and nothing that safety depends on. Every owner act reads the record. The owner's contact book is no trust input for conversion or revoke (ADR 0025 D3).

## A scope root takes many grants

A grant or a link on a folder that is not a scope root yet is a **fresh mint**. The engine converges the subtree, mints a scope with a fresh seed at epoch 1, re-seals the interior into it, and updates the parent's direct-child-scope index. The grantee reads from that first epoch.

A grant or a link on a scope root is an **append** (ADR 0026 D1). The engine adds one row and one grant blob, re-signs the commitment, and publishes the root once at the current epoch. There is no new seed, no re-seal and no converge step. Links and direct grants coexist, and a folder takes any number of live links (D2, D3).

A new grantee on an append reads the whole history of the scope, because the history links walk the current seed back to every earlier epoch (D6).

A direct grant to an identity that already holds a row is a permission change when the permission differs. When the permission is the same, the engine posts the share pointer again and changes nothing (D4).

## Invite links

### Mint

`Command::CreateInviteLink { node, permission, expires_at, owner_name }` mints a link.

- The link is a grant blob wrapped to an ephemeral identity that derives from one random invite secret. Its ledger row has the shape of a personal row.
- The link entry and its row are committed at `read`, whatever `permission` is. `permission` is the conversion permission. So a write link runs no write-scope cut and no name wave at mint, and its blob holds no write seed (ADR 0024 D4).
- Every link has a deadline. With no `expires_at`, the deadline is `DEFAULT_LINK_LIFETIME` (7 days) from the injected `now`.
- The mint sets the admission cap to `DEFAULT_ADMISSION_CAP` (25).
- No owner device stores the invite secret or a record of the link. The link lives in the owner-signed record alone. The fragment shows only once, at the mint (ADR 0023 D2).
- The engine returns the fragment once the scope root that commits the link has landed. A later handover failure does not discard the only copy of the invite secret.

### The fragment

The URL fragment is the whole bearer capability. It is one det-CBOR blob with a 2048-byte bound (`MAX_INVITE_FRAGMENT_BYTES`). It carries:

- the invite secret;
- the owner contact code;
- the scope id, the scope pointer name and the scope's stable `pointerReadKey`;
- the owner name and the folder name, under an owner identity signature over `{scopePointerName, ownerName, folderName}` (ADR 0027 D5).

A host moves the fragment between a URL and a command, and never parses it. A bad names signature gives no names, and the link still works. The fragment carries no MAC, so its other fields fail closed on their own: a changed pointer name or read key opens no re-point object under the owner code.

Anyone who holds the URL can unmask every committed recipient key with `pointerReadKey` (ADR 0024 E4).

### Preview before join

`Engine::preview_invite_link(fragment)` reads a link before the person joins (ADR 0028 D2, D3, D5). It runs in the signed-in session engine, in preview mode:

- It runs the checks of the join up to the open, and opens the scope root once through the link's grant blob under the adoption gate.
- It checks against the floors the session already holds, and raises none. It posts no claim, persists nothing and deposits no seed.
- It returns the names (only when the names signature verifies), the conversion permission, the state (`live`, `expired`, `revoked` or `unresolvable`), whether this account already joined, and the names and kinds of the direct children of the scope root. It returns no sizes, no counts and no deeper level.
- A refused re-point object, or a scope root that the gate refuses, is a trust violation.

### Join and the link-held read

`Command::ClaimInviteLink { fragment, name }` joins (ADR 0024 D1, D5). The link path runs these checks in order:

1. The fragment decodes inside its bound.
2. The owner contact code passes its binding verify.
3. The engine resolves the scope pointer, opens the re-point object under `pointerReadKey`, and verifies its owner-identity signature against the fragment's owner code. The record at `currentRootName` must verify at that name.
4. The record is not this vault's own root scope.
5. A blob sits at the link tag, which the holder derives again at each `currentRootName`.
6. The owner-signed commitment names that tag as a link entry, with a deadline later than `now`. The holder reads at `read`.
7. The blob opens under the ephemeral subkey.
8. The full adoption gate runs against the fragment owner's identity.
9. The bookmark persists before the floor advance commits.

A refused read, an expired link (`link-expired`) and a revoked link (`link-not-committed`) post no claim and record nothing. A pointer that does not answer still posts the claim and writes the bookmark, and the tick reads again. The join records the owner contact code in the claimant's contact book.

The received-share bookmark holds the link hold in four optional keys: `linkSecret`, `scopePointerName`, `linkDeadline` and `claim`. The list stays at version 2. ADR 0024 D1 names one key; the build uses four.

Each refresh pass reads the personal tag first. It reads the link tag only while no personal blob opens and `linkSecret` is held. The persist that records the first personal open drops the link hold, and the link holder is then a grantee (ADR 0024 D2). A link-held read also checks the deadline of the link entry, and stops at it.

### The claim

The claim is a sealed mailbox item to the owner, signed by the link's ephemeral identity. Its payload is `{claimId, scopePointerName, contactCode, name}`. `name` is the grantee name the claimant suggests, and it may be empty (ADR 0027 D1).

The claimant device keeps the claim and its idempotency key in the link hold. The tick posts it again under the same key while no personal blob lands. The first wait is 10 minutes, and each wait doubles up to 24 hours. The posts stop at the deadline, or after 40 posts (ADR 0023 D6). A second claim of the same link posts nothing.

## Conversion

Conversion mints a claimant a personal row. There is no click and no approve step (ADR 0023 D1).

### Trigger

Any owner device runs the conversion pass on every tick, over every folder. `Command::ConvertInviteClaims { node }` runs the same pass for one folder, for a host to issue when the share dialog opens (ADR 0023 D4). Each folder publishes its root once per pass.

### Ack first

For a claim item, the engine acks first and converts only when the ack answers that this call removed the item (ADR 0023 D5). The `Mailbox` seam `ack` returns `true` only then. So two owner devices never both convert one claim on an honest ack.

The acked claim is held in the conversion record: a sealed owner-local record (`PendingConversions`, kind `0x07`). The engine writes each claim in the `acking` state before the delete runs, and writes it again as pending after the delete removed it. An entry is `acking`, pending, pointer-due or refused. A conversion that fails on availability stays pending, and a later pass runs it again, checks included (ADR 0023 D6). A record that does not open is set aside, the record starts empty, and the engine emits `Event::ConversionRecordUnreadable`; the claimant re-post recovers the claims.

### The checks

The pass converts a claim only when every check passes (ADR 0023 D3):

1. The claim opens, and its sender signature verifies.
2. The claim's scope pointer name is the pointer name of a scope root this owner holds, and the record there passes the adoption gate.
3. The sender is the owner-attested `recipientIdentityPk` of a ledger row whose commitment entry is a link entry.
4. The deadline of that entry is later than the ack time. The verdict uses the stored ack time, so a retry does not judge it again against a later `now`.
5. The claimant contact code passes its binding verify.
6. The attested rows whose via-link reference names this link are below its admission cap (ADR 0023 D9).

A claimant identity that already holds a row makes the conversion a no-op. Conversion never changes an existing row (ADR 0026 consequence 5).

### What conversion mints

The pass appends a personal row at the conversion permission, with the via-link reference and the claimant's name as the grantee name under the flag `claimant`. It re-signs the commitment, publishes the root, raises the grant floor, and posts the share pointer to the claimant's contact. An entry settles when its pointer lands, or when the post still fails `POINTER_RETRY_WINDOW` after the conversion.

A write claim that passes every check, on a folder that is not a write scope yet, runs one write-scope cut first (ADR 0024 D4). The tick holds the same cut authority as the command.

The converting device records the claimant in its contact book and emits `Event::GranteeJoined { scope_root, name, fingerprint }`, a transient notice (ADR 0023 D7). The other owner devices see the new row in the record.

### Refusals and the per-link contact share

These refusals keep the entry as refused. The sharing read counts them per link (`refusedClaims`), and they never block the pending entries:

| Check                         | Why                                                                                                           |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `link-admission-cap-reached`  | The link reached its admission cap. A revoke frees a slot.                                                    |
| `grant-set-full`              | The scope root holds 1024 rows (ADR 0026 E1).                                                                 |
| `contact-book-full`           | The contact book cannot record the claimant: the link's share, the contact's scope bound or the book is full. |
| `claim-recipient-key-changed` | A known identity claims under another encryption subkey. The owner revokes and grants again.                  |

The per-link contact share bounds the claimants one link can record in the owner's contact book (`MAX_LINK_CONTACTS`, 128). One leaked link therefore takes only its own share, and it does not deny other links or a hand import. A fresh copy of a refused claim is pending again. `Command::DismissRefusedClaims { node }` clears the refused entries, and the cut of a link retires the claims it refused. The record keeps at most 64 refused entries, and `Event::RefusedClaimDropped` reports the oldest one when it goes.

### Two owner devices

The ack lock decides which device converts one claim. When two devices publish one scope root in one window, a publish that finds another record at its sequence or above is a lost race. The device that loses retries on a later pass, and signs above the sequence it observed.

## Grantee names and fingerprints

A grantee name is the owner-signed name on a grantee's ledger row. It is not an identity (ADR 0027 D3, D6).

- A claim suggests a name, and conversion copies it with the flag `claimant`.
- `Command::Grant { grantee_name, .. }` names a contact-code grantee with the flag `owner` (D2).
- `Command::RenameGrantee { node, recipient_identity_public_key, name }` re-signs the row with the flag `owner` and publishes the root once. The owner's edit wins.
- A name is not empty, is at most 255 bytes, and has no control characters.
- Every owner act binds to the identity key of the owner-signed row, never to a name.
- Core's `identity_fingerprint` gives an 80-bit fingerprint of an identity key, in five groups of four hex digits. A host shows it next to the name (D7).
- The grantee name cache (`GranteeNames`, kind `0x08`) keeps the last name this device saw for each identity. It pre-fills a name on another folder, it is never synced, and it is no authority (D4).

Every co-writer of the folder reads the grantee names, because the ledger is in the write-body (ADR 0027 consequence 2).

## Permission changes

`Command::ChangePermission { node, recipient_identity_public_key, permission }` changes a grantee's permission from the owner-attested row, so any owner device runs it (ADR 0025 D6).

- An upgrade mints write material, after a write-scope cut when the folder is not a write scope yet.
- A downgrade is a write revoke: a write rotation renames the subtree, and the grantee keeps a read row at the new name.
- The engine refuses a link row, the owner, a stranger, a row that is not owner-attested, and a grantee that holds more than one attested row.

A link's permission is fixed at creation. To change it, the owner revokes the link and mints a new one (ADR 0025 D7).

## Revocation

Revocation is discovered, not delivered. A fresh owner-signed record with no blob at a reader's tag is the revocation signal. The removed side keeps what it already saw, and loses everything new (ADR 0025 E2, ADR 0024 E5).

### One revoke is one cut

Every row one revoke removes leaves in one cut set, with one cut-epoch step, one re-sign and one rotation (ADR 0025 D4). The read plane always rotates. The write plane rotates only when a cut row is a write row, so a link revoke runs no name wave. The rotation re-keys the scope root and every descendant scope root.

### Revoke a person

`Command::Revoke { node, recipient_identity_public_key }` finds the grantee on the owner-attested ledger rows, so any owner device revokes, including one that never saw the person (ADR 0025 D3). A row whose writer broke the owner signature is found through the committed `recipientEncPk` of the one contact on this device that holds that key.

The cut also takes each committed link that the via-link reference of an attested row names (ADR 0024 D3). When a link admitted the grantee, the engine first converts the claims waiting at the folder. It then refuses with `link-has-a-pending-conversion` while a conversion through an admitting link is pending, and with `mailbox-unavailable` when it cannot poll the inbox. The revoke of a direct grantee does not wait for a conversion.

### Revoke a link

`Command::RevokeInviteLink { node, link_tag, remove_grantees }` cuts the link row, and every link holder of that link loses access at once (ADR 0025 D1).

- `link_tag` names the link. With no tag, the engine cuts the only link, and refuses with `link-ambiguous` when the folder carries more than one.
- With `remove_grantees`, the same cut also takes every committed personal row whose via-link reference names the link. The grantees who joined through the link keep access otherwise.
- The engine runs a conversion pass first, and never cuts a link while a conversion entry for it is pending (ADR 0023 D4).

### The revocation floor and the D3 clear

A cut records a per-recipient revocation floor on this device, so a later owner re-key withholds that recipient's blob. The cut also records the cut epoch of the set that removed the recipient, after the publish lands.

When another owner device commits the recipient again, an owner-signed commitment at a cut epoch not below the recorded one clears this device's cut for that recipient (ADR 0025 D3). The clear raises a separate floor, so the grant floor does not change. A set below the recorded cut epoch clears nothing.

### The expired-link sweep

The owner tick runs the sweep on `SyncTimingProfile::link_sweep_cadence` (600 s in production), after the conversion pass and under the same lock (ADR 0025 D2).

- It walks `directChildScopeIndex` from the vault root, with one resolve and one unseal per scope root. A scope root counts as visited only after the gate passes it.
- It cuts every link entry whose deadline the injected `now` has reached, less every link with a pending conversion entry.
- Each folder takes one cut for all its expired links. The engine resolves the scope root again right before it signs, so a link that another owner device already cut costs nothing.
- One sweep lands at most eight cuts, deepest first. A failed cut does not count. When the sweep stops at the cap, the next tick sweeps again.

A link holder's own engine stops at the deadline before the sweep runs (ADR 0024 D5). A hostile holder can read past the deadline until the sweep cuts the link (ADR 0025 E1).

### What the removed side sees

The received-share refresh reports one class per bookmark (ADR 0025 D5):

| Class                                 | Host message          |
| ------------------------------------- | --------------------- |
| `revocation-signal` on a personal tag | The owner removed you |
| `expired`                             | The link expired      |
| `revocation-signal` with `via_link`   | The link was revoked  |

`unresolvable` and `epoch-lag` are not revocations.

## Command surface

| Command or read          | Who         | Decision        |
| ------------------------ | ----------- | --------------- |
| `CreateInviteLink`       | owner       | ADR 0023, 0024  |
| `preview_invite_link`    | link holder | ADR 0028        |
| `ClaimInviteLink`        | link holder | ADR 0023, 0024  |
| `ConvertInviteClaims`    | owner       | ADR 0023 D4     |
| `DismissRefusedClaims`   | owner       | ADR 0023 D9     |
| `ImportContact`, `Grant` | owner       | ADR 0026, 0027  |
| `ChangePermission`       | owner       | ADR 0025 D6     |
| `RenameGrantee`          | owner       | ADR 0027 D3     |
| `Revoke`                 | owner       | ADR 0025 D3, D4 |
| `RevokeInviteLink`       | owner       | ADR 0025 D1, D4 |

## Known windows

These gaps are in the code on `main`. Each one is a single sentence.

- The web host does not show the link-first share dialog yet: it shows one live link and a control that runs a conversion pass at once, and it has no people-list names, rename, permission control, `remove_grantees` checkbox, joined notice or refused count.
- The web invite page runs no preview, and it sends an empty claimant name and an empty owner name.
- The owner cannot set the admission cap yet, so every link carries the default of 25.
- Only a command pass (`ConvertInviteClaims` or `RevokeInviteLink`) repairs a parent index that a failed re-point left stale, because the tick converts only at scope roots its own walk proved.
- A downgrade over a stalled write scope runs two name waves: the owed wave, then the cut.
- After a write wave, the contact route of `remove_grantees` does not find a row whose writer stripped its via-link reference, so the owner must revoke that person directly.
- When two contacts on one device share one encryption subkey, a person revoke on that device cannot reach an unattested row for that subkey, and answers `rot-revoke-not-granted`.
- A cut floor that a build before the D3 clear recorded carries no recorded cut epoch, so a re-commit never clears it on that device, and the device keeps the recipient withheld.

## Accepted residuals

The residuals of ADRs 0023 to 0028 are listed once, in [`blueprint/engine.md`](../blueprint/engine.md) "Sharing residuals".
