# Can any owner device recover a pending link from the published record?

Research for [sharing: can any owner device recover a pending link from the published record (#1946)](https://github.com/FSM1/cipher-box/issues/1946), under the map [wayfinder: sharing as a link-first flow with no approve step (#1945)](https://github.com/FSM1/cipher-box/issues/1945).

Sources: code on `main` at `ee147eac9`, `CONTEXT.md`, `blueprint/engine.md`, and [ADR 0006](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0006-owner-local-sealed-store.md). Line numbers are from that commit.

## Short answer

No. The published record does not let a second owner device convert a claim safely.

- The record carries every public key of the link in owner-signed form. The ledger row signature binds the ephemeral identity to the ephemeral encryption key, the tag and the scope root name.
- The record does not say which rows are links. A personal grant row has the same shape and the same owner signature. So a rule "convert a claim whose sender is the identity of an owner-attested row" lets every committed grantee re-share the folder.
- The record does not carry the deadline in signed form, the spent claim ids, or which link produced which grant. Without the last two, a redelivered or fresh claim puts back a person the owner revoked.

Recommendation: keep the link records and the spent-claim records as owner-only state, but move them from device-local storage to a vault-synced structure. Keep the record as the authority for permission and liveness, as conversion does today.

## 1. Field table

"Row signature" is the owner ECDSA signature over `{ipnsName, recipientEncPk, recipientIdentityPk, tag}` (`crates/core/src/seal/write_body.rs:202-255`). It excludes `permission` and `expiresAt` (`write_body.rs:205-211`). "Commitment" is the owner-signed grant-set commitment (`crates/core/src/seal/grant.rs:927-949`, `:1036-1060`).

| Value                                       | What conversion does with it                                                                                                                                                                  | In the record?                                                                        | Owner-signed?                                              | Where                                                                                                                                                         |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scopeId`                                   | Filters links to this scope (`crates/engine/src/grants/invite.rs:925-927`); binds the writer pseudonym in the new row (`crates/engine/src/grants/ledger.rs:174-190`).                         | No. "No field of the commitment carries a scope id" (`invite.rs:656-659`).            | Not applicable.                                            | Any owner device reads it from the gated scope reference in its own vault tree (`invite.rs:671-691`).                                                         |
| Scope root `ipnsName`                       | Must equal `claim.scope_root_name` (`invite.rs:922-924`); input to every tag.                                                                                                                 | Yes.                                                                                  | Yes, commitment and row signature.                         | `GrantSetCommitment.ipns_name`; row signature preimage.                                                                                                       |
| `ephemeralIdentityPk`                       | Must equal the claim's verified sender (`invite.rs:925-931`).                                                                                                                                 | Yes, as the link row's `recipientIdentityPk`.                                         | Yes, row signature only. The commitment does not carry it. | Ledger row in the sealed write-body. Owner and committed writers read it.                                                                                     |
| `ephemeralEncPk`                            | Derives the link's current tag (`invite.rs:981-989`); refuses a claimant who is the ephemeral half (`invite.rs:822-827`).                                                                     | Yes.                                                                                  | Yes, twice.                                                | Commitment entry `maskedRecipientEncPk`, unmasked with `pointerReadKey` (`grant.rs:856-858`); ledger row `recipientEncPk` under the row signature.            |
| Link tag, current                           | Finds the committed entry and its permission (`invite.rs:800-811`).                                                                                                                           | Yes.                                                                                  | Yes.                                                       | Commitment entry `tag`; row `tag`; grant blob key.                                                                                                            |
| Link tag at mint (`RecordedInvite.tag`)     | Key for `ConvertedClaimRecord.link_tag` (`invite.rs:512-530`) and for the contact-book charge (`crates/engine/src/facade.rs:9353-9355`).                                                      | Only until the first write wave re-mints the row at a new name (`invite.rs:975-980`). | Not applicable.                                            | A local key, not a trust input.                                                                                                                               |
| Permission                                  | Grant permission for the claimant (`invite.rs:802-811`).                                                                                                                                      | Yes.                                                                                  | Yes, commitment only.                                      | Commitment entry `permission`.                                                                                                                                |
| Deadline                                    | Recorded copy is the authority (`invite.rs:932-934`); published copy can only shorten (`invite.rs:812-820`).                                                                                  | Yes, as `expiresAt`.                                                                  | **No.**                                                    | Ledger row. A committed write grantee can change or remove it (`write_body.rs:74-88`). A write wave keeps it (`crates/engine/src/net/rotation.rs:4320-4327`). |
| "This row is a link"                        | Today, the existence of a `RecordedInvite` decides it.                                                                                                                                        | **No.**                                                                               | Not applicable.                                            | A link row is byte-shaped like a personal row (`invite.rs:9-17`, `:307-313`).                                                                                 |
| Spent claim ids                             | Refuses a redelivered claim (`invite.rs:938-940`).                                                                                                                                            | **No.**                                                                               | Not applicable.                                            | The mailbox chooses what to redeliver, so "only the owner can remember what it already converted" (`crates/engine/src/grants/invite_store.rs:9-12`).          |
| Converted pairs `(link tag, grantee tag)`   | `GrantWasCut`: refuses any new claim through this link for a grantee the owner cut (`invite.rs:846-855`).                                                                                     | **No.**                                                                               | Not applicable.                                            | The record shows only that the grantee tag is absent. It does not show which link made the grant.                                                             |
| Owner identity signer and encryption secret | Authorises against the commitment; derives tags; signs the new set.                                                                                                                           | No, by design.                                                                        | Not applicable.                                            | Every owner device derives both from the session.                                                                                                             |
| `pointerReadKey`                            | Unmasks the commitment; masks the new entry (`ledger.rs:174-218`).                                                                                                                            | Yes, sealed.                                                                          | Not applicable.                                            | The owner device reads it from the resolved scope root (`facade.rs:9294`).                                                                                    |
| Invite secret                               | **Not used by conversion.**                                                                                                                                                                   | Never.                                                                                | Not applicable.                                            | The URL fragment only, "in a URL and nowhere durable" (`crates/engine/src/grants/invite_mint.rs:105-108`).                                                    |
| Claimant contact code                       | Taken from the claim; recorded in the contact book before publish (`facade.rs:9344-9359`). A later revoke finds the recipient in the contact book only (`facade.rs:8079-8093`, `:8223-8233`). | No.                                                                                   | Not applicable.                                            | The contact book is device-local (`facade.rs:8063-8071`).                                                                                                     |

### What conversion needs the invite secret for

Nothing. `convert_invite_claim` (`invite.rs:784-902`) reads only the public halves: the ephemeral identity key to match the sender, and the ephemeral encryption key to derive the tag. The secret derives both halves (`invite.rs:273-280`), so a device without the secret cannot re-derive the ephemeral identity. It does not need to, because the ledger row carries the public key under the row signature.

The secret is needed in three other places:

- The claimant signs the claim with it (`invite.rs:613-634`).
- A link holder opens the link's grant blob with it.
- The owner shows or copies the link again. A second owner device cannot do this. The fragment is not stored anywhere (`invite_mint.rs:105-108`).

## 2. Can a second owner device verify a claim's sender against the record alone?

### What the second device can trust

After the adoption gate adopts the scope root and `authorise` passes (`invite.rs:694-704`), the device knows these facts:

1. The owner signed the commitment. So every committed tag, its permission and its masked encryption key are the owner's (`grant.rs:1043-1060`).
2. For each row whose row signature verifies (`ledger.rs:84-90`), the owner bound that `recipientIdentityPk` to that `recipientEncPk` and tag at this scope root name. A write wave copies the identity only from an attested row and writes `UNATTESTED_IDENTITY_PK` otherwise (`rotation.rs:4284-4299`).
3. The ledger matches the commitment in `(tag, permission)` (`ledger.rs:263`). So a writer cannot add a row, drop a row, or restore a row the owner cut. The cut epoch stops a replay of a pre-cut set (`CONTEXT.md:41`).

So the attack that ADR 0006 describes against the local store does not work against the record. In that attack, a party pairs a real link's `ephemeralEncPk` with an identity key that it holds. The row signature landed after ADR 0006 (commit `4b4c99807`, "put grant-ledger recipient keys under owner authority"). A row that pairs a different identity with that encryption key fails the row signature.

### What the second device cannot trust or cannot see

1. **Which rows are links.** Nothing marks a row as an invite (`invite.rs:307-313`). A link row and a personal row both carry an owner-attested `recipientIdentityPk`.
2. **The deadline.** `expiresAt` is outside both owner signatures (`write_body.rs:74-88`).
3. **The spent claim ids and the converted pairs.** Neither is in the record.

### What a committed grantee could do against a record-only rule

Assume the rule "convert a claim if its sender is the `recipientIdentityPk` of an owner-attested, committed row".

- **Re-share by any committed grantee (the concern at `invite.rs:763-770`).** A personal grantee G holds the private key of the identity in G's own attested row. G posts a claim to the owner's mailbox, signed with G's real identity key. The claim carries the contact code of a third party X. The rule matches the sender to G's row. The owner device signs a grant for X at G's permission. The owner never approved X. A read grantee re-shares read. A write grantee re-shares write. This breaks the owner-only grant authority (cipher-box-next#25 D7). No record-only check stops it. The device cannot tell an ephemeral key from a real identity key. A contact-book check does not help: the book is device-local, and G may have been imported on another device.
- **Extend a link past its deadline.** A committed write grantee removes `expiresAt` from the link row. The row signature still verifies, because the preimage excludes `expiresAt`. The second device then treats the link as live with no deadline. The write grantee can also shorten or remove the deadline to deny service, but it can do that today too.

### What the API or a revoked person could do without the spent state

- **Undo a revocation by redelivery.** The owner revokes P. The API re-serves P's old claim. A device with no spent-claim ids converts it again. P gets a new grant. The owner signs a set that undoes its own cut (`invite.rs:28-34`).
- **Re-enter through the same link.** P still holds the link fragment. P posts a fresh claim with a new claim id. Today `GrantWasCut` refuses it, because the owner recorded that this link produced P's grant and the grant is now absent (`invite.rs:846-855`). A device with no converted pairs cannot make that refusal. Under the map's "revoke per person", this refusal is the only thing that keeps a revoked person out while the link stays live.

### What a committed grantee could not do

- Forge a link. It cannot produce a row signature.
- Restore a cut link row. The ledger would diverge from the commitment.
- Change the permission. The commitment carries it.
- Read the invite secret from the record. The secret is never in the record.

### Verdict

The record authenticates the link's keys. It does not authenticate the link's role, its deadline, or its history. The role is the part that decides authority, so a record-only conversion lets any committed grantee drive the owner into a grant for an identity the owner never approved.

A record-only design becomes safe only with two changes:

1. Put a link marker and the deadline under the row signature. This is a `crates/core` wire and KAT change, so it needs an ADR.
2. Keep the spent claim ids and the converted pairs in owner-only state anyway.

## 3. The smallest vault-synced structure that closes the gap

### Today's state

`CONTEXT.md:18` places the owner seed cache "in the owner's own vault share list". The code does not build that list as vault-synced state yet:

- `OwnerSeedCache` is an in-memory map with no caller outside its module (`crates/engine/src/grants/owner_entry.rs:39-67`).
- The received shares, the contact book and the invite records all use the device-local `StagingStore` (ADR 0006 consequence 5; `facade.rs:8063-8071`, `:9546-9554`).

So "next to the owner seed cache" means a new owner-only structure in the owner's vault. It does not mean an addition to an existing one.

### Proposed payload

Keep the current invite-records body (`invite_store.rs`, kind `invite-records`), and add one field:

| Field                          | Content                                                                                                                                                                         | Why                                                                                                                                                |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `links`                        | `RecordedInvite` as today: `scopeId`, `tag`, `ephemeralIdentityPk`, `ephemeralEncPk`, `expiresAt` (`invite.rs:316-331`). About 130 bytes each; cap 1024 (`invite_store.rs:80`). | Decides which rows are links, and holds the authoritative deadline.                                                                                |
| `claims`                       | `ConvertedClaimRecord` as today: `claimId`, `linkTag`, `tag` (`invite.rs:512-530`). 80 bytes each; cap 4096 (`invite_store.rs:85`).                                             | Keeps a claim single-use. Keeps a revoked person out of a live link (`GrantWasCut`).                                                               |
| `claimantCode` per claim (new) | The claimant's contact code, which conversion already writes to the contact book (`facade.rs:9353-9355`).                                                                       | A revoke on another device must find the recipient (`facade.rs:8079-8093`). Without it, a device can convert a person that it cannot later revoke. |

The invite secret stays out. The payload holds no secret material, so a leak of the structure gives no bearer capability.

### Carrier requirements

- **Owner-only to write.** A committed grantee must not be able to author it. ADR 0006 explains why: an authored link record mints a genuine grant. A structure in the vault root scope meets this rule, because the engine refuses a grant or link at the vault root (`facade.rs:8490-8496`).
- **Owner-only to read.** The spent pairs and the claimant codes are the owner's contact graph.
- **Monotone.** Today a host that restores an old sealed blob un-spends claims, and "closing them needs a monotone generation held where the host cannot roll it back" (`invite_store.rs:26-37`). A record in the owner's vault gets the IPNS sequence and the adoption gate floors. So the vault carrier also closes this residual.
- **Mergeable across devices.** Two owner devices can convert at the same time. `links` and `claims` merge as a set union. Conversion is idempotent per grantee, because the tag derives from the owner secret and the claimant key. Removal stays the existing prune: a record is dropped only when an owner-signed commitment no longer carries its link (`invite.rs:1015-1062`).
- **Write order.** Keep ack-after-durable (`facade.rs:9209-9215`): the synced write lands before the mailbox ack. A revoke on any device reads the synced `claims` before it publishes the cut.

A carrier inside the vault root's existing sealed body needs no new KDF edge. A separate IPNS name would need a new edge in the frozen catalog. Either choice changes `blueprint/engine.md`, so it needs an ADR in cipher-box-next.

## 4. Recommendation: vault-synced

Use the vault-synced structure as the authority for which links exist, their deadlines and the spent claims. Keep the record in its current role: conversion reads the permission from the commitment and treats an absent entry as revocation (`invite.rs:800-811`).

Add one cheap cross-check: before conversion, verify that the synced `ephemeralIdentityPk` is the `recipientIdentityPk` of an owner-attested row at the link's current tag. This check uses the row signature that is already in the record, and it needs no wire change.

Do not choose the record-derived design:

- It needs a `crates/core` wire change (a link marker and the deadline under the row signature) and new KATs.
- It still needs owner-only state for the spent claims and the converted pairs.
- Both designs therefore need the synced structure, and the wire change adds nothing that the structure does not already give.

### Questions for the map

- **Re-show a link on another device.** The secret is stored nowhere, so only the minting browser can copy a link again. To sync the secret, the design must reverse the rule "in a URL and nowhere durable" (`invite_mint.rs:107`). This is a separate decision.
- **Scope of the contact-book sync.** The `claimantCode` field covers link claimants only. Hand-imported contacts stay device-local, so a direct grant made on device A cannot be revoked on device B. The people list has the same gap. The map can widen this structure to the whole contact book.
