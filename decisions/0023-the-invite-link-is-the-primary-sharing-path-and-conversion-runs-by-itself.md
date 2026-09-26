# ADR 0023 — The invite link is the primary sharing path, and conversion runs by itself

- **Status:** Accepted on 2026-09-25; the `blueprint/*.md` and `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-25
- **Supersedes:** the "owner converts" part of
  [Design: sharing and grant delivery architecture (#25)](https://github.com/FSM1/cipher-box-next/issues/25)
  D6, and the invite-record store of
  [ADR 0006](./0006-owner-local-sealed-store.md)
- **Relates to:**
  [wayfinder: sharing as a link-first flow with no approve step (#1945)](https://github.com/FSM1/cipher-box/issues/1945),
  [sharing: conversion on the owner tick on any owner device (#1950)](https://github.com/FSM1/cipher-box/issues/1950),
  [sharing: can any owner device recover a pending link from the published record (#1946)](https://github.com/FSM1/cipher-box/issues/1946),
  [Design: API residual role and surface (#34)](https://github.com/FSM1/cipher-box-next/issues/34)
  D6 (no people directory, unchanged),
  [Design: sharing and grant delivery architecture (#25)](https://github.com/FSM1/cipher-box-next/issues/25)
  D6 (links were already multi-claim) and D7 (stands: the owner key still signs every row),
  ADRs 0024 to 0027, the `blueprint/engine.md` "Grants and
  ledger" and "Mailbox logic" sections, the `blueprint/api.md` "Mailbox" section, the
  `blueprint/web-client.md` "Composition (apps/web)" section, and the `CONTEXT.md` "Grant-set
  commitment", "Grant ledger" and "Mailbox" terms

## Context

Today the owner converts a claim by a press on "convert claims" in the share dialog
(`apps/web/src/components/sharing/InviteLinkPanel.tsx:44-58`, `crates/engine/src/facade.rs:9190-9450`).
The tick leaves claim items alone (`crates/engine/src/grants/inbox.rs:11-15`). Only the minting
browser can convert, because the link records and the spent claim ids are device-local
(`crates/engine/src/grants/invite.rs:316-331`, `:512-530`). The record cannot say which rows are
links, so the code refuses to decide from it (`invite.rs:760-766`).

The research ticket
[sharing: can any owner device recover a pending link from the published record (#1946)](https://github.com/FSM1/cipher-box/issues/1946)
found gaps in the record. A link row has the shape of a personal row. The deadline `expiresAt` is
outside both owner signatures, so a committed write grantee can change it
(`crates/core/src/seal/write_body.rs:74-88`, `:202-255`). The spent claim ids and the link-to-grant
pairs are owner-local. It recommended a new vault-synced owner structure. The charting of the map
then decided that there is no approve step.

File and line citations come from the research reports (`main` at `d30509e48` or `ee147eac9`).

## Decision

**D1 — There is no approve step.** Every claim that passes D3 converts. The owner removes a
person later (ADR 0025). The contact code stays as an advanced path. There is no people directory,
and the decision #34 D6 stays.

**D2 — Conversion state lives in the record, under owner signatures.**

- The grant-set commitment entry gains a kind, `personal` or `link`, and a deadline for a `link`
  entry. The deadline is the time by which the owner must convert a claim. The commitment
  signature covers both. The codec refuses a deadline on a `personal` entry, on decode and on
  encode.
- The ledger row `expiresAt` retires. The commitment entry holds the one deadline.
- A grantee's ledger row gains a via-link reference: the tag of the link row that admitted the
  grantee. The field joins the row signature preimage when it is present (Consequence 1). A write
  wave re-mints every row at a new tag, so it re-maps the reference in the same pass.
- The fragment carries the scope pointer name and the scope's stable `pointerReadKey`, beside the
  invite secret and the owner contact code. The claim carries the scope pointer name in place of
  the scope root name.
- No vault-synced owner structure is introduced. The invite-record store kind retires.
- The invite secret is never stored on an owner device. A link shows only at its creation.

**D3 — The conversion rule.** An owner device converts a claim only when each check passes:

1. The claim opens, and its sender signature verifies, as today.
2. The claim names the scope pointer of a scope that this owner holds. Conversion matches the
   claim to the scope by the `scopeId` of the re-point object, and the record at
   `currentRootName` passes the adoption gate. A write-scope cut moves the scope root (name wave),
   but the scope pointer name does not move. Today the claim names the root, and conversion
   refuses a name mismatch and never acks, so every live link minted before the cut strands with
   no signal. The link tag is re-derived at each wave, like every grant tag. The link holder side
   of this path is ADR 0024 D5.
3. The sender is the owner-attested `recipientIdentityPk` of a ledger row whose commitment entry
   has the kind `link`.
4. The deadline of that entry is later than the injected `now`. The engine runs this check once,
   at the ack (D5), and stores the verdict in the op entry. A retry does not check it again.
5. The claimant contact code passes its binding verify at import.
6. The link has a free admission slot (D9).

When a row for the claimant identity already exists in the scope, conversion is a no-op. Otherwise
the device mints a personal row at the conversion permission of the link entry (ADR 0024 D4),
with the via-link reference and, for a write link, the write material, re-signs the commitment,
publishes the root, and posts the share pointer.

**D4 — The trigger.** Any owner device converts on every tick, with one root publish per folder
per tick, and when the owner opens the share dialog of a folder. The engine converts pending
claims before its sweep cuts expired links (ADR 0025 D2). It never cuts a link while an op entry
for that link is pending, because the cut removes the link row that D3 item 3 reads.

**D5 — Ack first, convert second.** The mailbox delete answers whether this call removed the item.
The engine converts only on "removed". Today the delete always answers success
(`apps/api/src/mailbox/services/mailbox.service.ts:237-252`), and the engine accepts any 2xx
(`crates/engine/src/api/client.rs:647-655`). The order is: ack, write a durable op-queue entry that
holds the claim, convert, publish. For claim items this replaces "ack after the fact is durable".
The ack lock stops two owner devices from converting one item and racing on the root publish. It
also stops a redelivery from admitting again a person whom the owner cut between the conversion and
the ack. The no-op on a known identity (D3) stays the duplicate guard. A claim is lost when the
engine stops between the ack and the durable op write; the claimant re-post (D6) covers that
window.

**D6 — Retry on both sides.** After a failed conversion, the owner engine retries the op-queue
entry on later ticks. The retry covers the whole conversion, the D3 checks and the publish. The
checks run after the ack, so a temporary failure, such as an unreachable record, would otherwise
lose the claim. The claimant engine posts its claim again when no personal blob lands inside a
window, and reads as a link holder meanwhile (ADR 0024). Every re-post of one claim reuses the
idempotency key of its first post, so the mailbox keeps one live item for it. The re-posts back
off exponentially and stop at the deadline.
Amended by
[ADR 0048](./0048-the-mailbox-ack-says-whether-this-call-removed-the-item.md)
D1 and D3 on 2026-09-26: the re-posts share one key, so the mailbox holds at most one live item for
the claim at a time. After an ack removes that item, the next re-post under the same key creates a
new item.

**D7 — The owner signal.** The people list updates from the record on every owner device. The
device that converted shows one transient notice, "X joined <folder>". Nothing persists.

**D8 — A revoked person may join again through another live link.** It is a fresh admission. The
contact book does not sync, and conversion and revoke do not read it.

**D9 — A link carries an owner-signed admission cap.** The link's commitment entry holds the cap
beside the deadline, under the commitment signature. Conversion refuses a claim when the number of
live ledger rows that carry this link's via-link reference has reached the cap. A revoke frees a
slot. The share dialog sets the cap, and the build chooses a small default. The claim carries no
proof that the claimant holds the contact code it names: the seal is HPKE base mode, and the only
signature is the link's ephemeral key. So without a cap, one URL holder can enrol many self-made
identities, up to the 1024-row cap, each one a writer on a write link.

### Why this reverses the recommendation of the research ticket

| Gap that the research found                  | What closes it                                         |
| -------------------------------------------- | ------------------------------------------------------ |
| A link row looks like a personal row         | The owner-signed entry kind (D2), checked by D3 item 3 |
| The deadline is outside the owner signatures | The owner-signed deadline on the entry (D2)            |
| Spent claim ids are owner-local              | The ack lock (D5) and the no-op on a known identity    |
| Link-to-grant pairs are owner-local          | The via-link reference, and ADR 0024 D3                |
| A later revoke needs the claimant key        | The owner-signed ledger row (ADR 0025 D3)              |

The re-share attack of `invite.rs:763-770` fails at D3 item 3, because a personal entry never has
the kind `link`. No owner device can show a link again. This is not a new loss: today the minting
device holds no secret either.

## Alternatives considered

**(a) An owner-only vault-synced structure, as the research ticket recommended.** Rejected. The
table above closes every gap with owner-signed fields. The structure adds a second authority beside the
record, and it needs a carrier, merge rules and a monotone generation.

**(b) An approve step.** Rejected at the charting. A per-link "ask me first" switch, off by
default, stays on the map as an item that is not yet specified.

**(c) Conversion on the minting device only.** Rejected. The owner may not open it again.

**(d) Sync the invite secret, so that any owner device shows a link again.** Rejected. A stored
secret is a bearer capability.

## Consequences

1. **`crates/core` wire formats change.** The commitment entry gains the kind, the deadline, the
   admission cap (D9) and the conversion permission (ADR 0024 D4) as optional fields. An absent
   kind means `personal`. The existing KAT vectors stay valid, and new vectors pin the new fields.
   The ledger row gains the via-link reference and loses `expiresAt`. The row signature preimage
   includes the via-link reference and the grantee name (ADR 0027 D3) only when they are present.
   So a row from before this change keeps the same bytes and its signature, and a removed field
   still fails the verify. Each decode refusal has a release-active encode check (AGENTS.md
   rule 8). The fragment gains the scope pointer name and `pointerReadKey`, and the claim carries
   the scope pointer name in place of the scope root name (D2).
2. **Links minted before this change stop working.** They carry no kind, so they cannot be claimed
   or converted. This loss is accepted: v2 runs on staging only, and there is no migration. Store
   kind `0x03`, the retired invite-record store, stays reserved for ever.
3. **A public observer sees which commitment entries are links, and when each ends.** A mask
   under `pointerReadKey` needs a new edge in the frozen KDF catalog, and the entry already shows
   its permission in the clear.
4. **The blueprint changes.** `blueprint/engine.md` "Grants and ledger": the "Invites" bullet
   states D2 to D9, and "Authority" states that the owner engine converts with no click.
   `blueprint/engine.md` "Mailbox logic": "Lifecycle" states D5 for claim items.
   `blueprint/api.md` "Mailbox": the ack answers whether the call removed the item.
   `blueprint/web-client.md` "Composition (apps/web)": the "convert claims" control goes, and the
   notice of D7 comes.
5. **`CONTEXT.md` changes.** New terms: **claim** (the grantee side of a link: the sealed,
   ephemeral-key-signed mailbox request that carries the claimant contact code), **conversion**
   (the owner side: the owner engine mints the claimant a personal grant, on the tick, with no
   click), and **invite link**. "Grant-set commitment" gains the kind, the deadline and the
   admission cap, "Grant ledger" gains the via-link reference, and "Mailbox" gains the ack answer.
   **Cut** stays the engine word for a revoke, and **adoption** stays with the record gate only.
6. **ADR 0006 keeps its structure** for received shares and the contact book. **The pending
   conversion is a new op record,** and ADR 0020 applies to it.

## Residuals

**E1 — A lying API can report "removed" to two owner devices.** Both mint the same row, because the
tag derives from the owner secret and the claimant key. No extra grant results.

**E2 — The API can replay an acked claim through a live link.** It re-admits a person who once
claimed through that link and who can rejoin through it anyway. The owner can cut the link.

**E3 — A URL holder can enrol a third-party identity without its consent.** The claim carries no
proof that the claimant holds the contact code it names. The admission cap (D9) bounds the count,
not the consent.

**E4 — An owner who stays offline past the deadline loses the claims.** Every claim that no owner
device acked before the deadline fails D3 item 4. The person sees "The link expired".

**E5 — A cut person who holds the URL of another live link on the scope rejoins with no owner
step.** The person reads at once as a link holder, is converted on the next tick, and reads the
whole history of the scope (ADR 0026 D6). A person revoke is complete only when every live link
that the person may hold is cut; the people list shows the person again, with no persistent notice.

**E6 — Many pending claimants can fill the owner's mailbox.** More than 1000 distinct pending
claimants reach the mailbox pending cap and block other mail to the owner until the owner converts.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
