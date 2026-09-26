# ADR 0048 — The mailbox ack says whether this call removed the item

- **Status:** Accepted on 2026-09-26 — retroactive; the rule shipped in FSM1/cipher-box#668 and
  FSM1/cipher-box#1981, and the blueprint carries it since FSM1/cipher-box#1962 and
  FSM1/cipher-box#1981; the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-26
- **Amends:**
  [ADR 0023](./0023-the-invite-link-is-the-primary-sharing-path-and-conversion-runs-by-itself.md)
  D6 (the sentence "so the mailbox keeps one live item for it")
- **Relates to:**
  [ADR 0023](./0023-the-invite-link-is-the-primary-sharing-path-and-conversion-runs-by-itself.md)
  D3 (the no-op on a known identity), D5 (ack first, convert second), E2 and E6,
  [ADR 0001](./0001-mailbox-recipient-binding.md)
  (the recipient-bound sender signature),
  [#34](https://github.com/FSM1/cipher-box-next/issues/34) D5 (the bounded until-acked mailbox,
  the pending cap and reject-new),
  [#25](https://github.com/FSM1/cipher-box-next/issues/25) D2 (retained until acked, then deleted),
  the `blueprint/api.md` "Mailbox" section, the `blueprint/engine.md` "Mailbox logic" and
  "Grants and ledger" sections, and the `CONTEXT.md` "Mailbox" and "Claim" terms
- **Implemented by:** FSM1/cipher-box#668 (the replay path and the hard-delete ack) and
  FSM1/cipher-box#1981 (the ack answer, the TTL bound on a replay, the tests and the blueprint
  text)

## Context

The mailbox is the API's integrity-untrusted transport for sealed pointers
(`apps/api/src/mailbox/services/mailbox.service.ts`). A sender posts a sealed blob with an
idempotency key. The API keeps `sha256(senderPublicKey : idempotencyKey)` as the row's
idempotency scope, under a unique index on the recipient and the scope. The ack is a hard delete
by id. The sender is not stored in a column (FSM1/cipher-box#668).

The build of the mailbox did not record two facts about the idempotency key:

- **What a key means after the ack.** The ack deletes the row, and the row is the only place
  where the key lives. So a later post under the same key finds no row and creates a new item.
  FSM1/cipher-box#668 shipped this behaviour without a test. ADR 0023 D6 then said that every
  claimant re-post reuses the key of the first post, "so the mailbox keeps one live item for it".
  Read literally, that sentence says one item for the whole life of the claim. The engine seam
  says the same thing in other words: "re-posting with an already-seen idempotency key for the
  same recipient creates no second item" (`crates/engine/src/seams/mailbox.rs`).
- **What a replay gets when the mailbox is full.** The pending cap refuses a new item when the
  recipient holds 1000 pending items (#34 D5, ADR 0023 E6). The post path checks for a live
  replay before it counts, first without a lock and again under the per-recipient advisory lock
  (`post` and `enforceCapAndInsert`). So a replay answers with the id of its live item even at
  the cap. FSM1/cipher-box#668 shipped this with a unit test, but no blueprint text.

ADR 0023 D5 made the first fact load-bearing. The owner engine acks a claim first and converts
only on "removed". A claim is lost when the engine stops between the ack and the durable op
write, and ADR 0023 D5 says that the claimant re-post covers that window. The re-post can cover
it only if the key of an acked item creates a new item. Under the literal ADR 0023 D6 reading,
the re-post returns nothing, because no live item exists, and the claim is gone.

The build slice FSM1/cipher-box#1976 stated the first fact and asked for text on the pending cap.
FSM1/cipher-box#1962 put the after-ack sentence into `blueprint/api.md`, and FSM1/cipher-box#1981
added the replay at the cap to that section, bounded a replay by the 90-day TTL, and tested both.
The rules are in the `blueprint/api.md` "Mailbox" section, on the "Post" and "Ack" bullets.

Other ADRs already decide two rules on the same bullets, and this ADR does not restate them: a
missing, foreign or malformed id answers "not removed" (ADR 0023 D5), and the pending cap is 1000
items by default (ADR 0023 E6).

## Decision

**D1 — The idempotency key lives as long as its item.** A post whose sender, recipient and
idempotency key match a live item returns the id of that item. It stores nothing, and the blob of
the first post stays. A live item is a pending item that no ack removed and that is inside the
90-day unacked TTL. When the ack removes the item, or the TTL expires it, the key is free: the
next post under the same key creates a new item with a new id. The API keeps no record of a key
after its item is gone. The rule landed with FSM1/cipher-box#668, and FSM1/cipher-box#1981 bounded
the replay by the TTL; FSM1/cipher-box#1962 and FSM1/cipher-box#1981 wrote it into the blueprint;
this ADR records it.

**D2 — A replay of a live item answers at the pending cap.** The API checks for a live replay
before it applies the pending cap. When the recipient's mailbox is full, a post that D1 answers
with a live item still gets that id, and only a post that would create a new item is refused
(reject-new). The replay adds no row, so the count of pending items does not change. The check
runs on both the unlocked fast path and under the per-recipient lock. The rule landed with
FSM1/cipher-box#668; FSM1/cipher-box#1981 wrote it into the blueprint; this ADR records it.

**D3 — ADR 0023 D6 reads under D1.** A claimant engine re-posts one claim under the key of its
first post. So the mailbox holds at most one live item for a claim at any time. After an owner
device acks that item, the next re-post creates a new item. The owner device acks the new item
and converts it; when the claimant already holds a row, the conversion is the no-op on a known
identity (ADR 0023 D3). This is the path by which the re-post covers a stop between the ack and
the op write (ADR 0023 D5).

## Rationale

- **A replay is the same request, so it gets the same answer.** A sender that lost the answer to
  a post and posts again must learn the id of the item it created. A "mailbox full" answer at
  the cap would report a failure for an item that is pending, and the engine surfaces a
  reject-new as a sender-visible failure (`blueprint/engine.md` "Mailbox logic").
- **D2 does not weaken the cap.** The cap is a DoS control on stored rows (#34 D5). A replay
  stores no row, so the bound on pending items is the same with or without D2.
- **D2 adds no lock contention at the cap.** The first replay check takes no lock, so a sender
  that retries against a full mailbox does not contend on the per-recipient lock.
- **D1 keeps no state past the ack.** The ack is a hard delete, and #25 D2 says "retained until
  acked, then deleted". A key that outlives its item needs a row or a tombstone per acked item.
  That is durable per-sender state on the server, which the one-way idempotency scope of
  FSM1/cipher-box#668 exists to avoid.
- **D1 is what makes ADR 0023 D5 recoverable.** The ack-first order accepts a window in which a
  claim is acked and not yet durable. The next re-post puts the claim back in the mailbox only
  because the acked key is free.
- **The extra item that D1 allows is harmless for a claim.** The owner engine converts a claim
  for a known identity as a no-op (ADR 0023 D3), so a second item adds one ack and no grant.
  The claim is the one payload that re-posts under a held key; a grant delivery draws a fresh key
  for each post (`crates/engine/src/grants/create.rs`).

## Alternatives rejected

**(a) Apply the pending cap before the replay check.** Every post to a full mailbox gets 409,
replays included. The sender of a pending item then sees "mailbox full" for an item that the
recipient will receive, and each retry takes the per-recipient lock to write nothing.

**(b) Keep a key for ever, which is the literal reading of ADR 0023 D6.** The API would keep a
tombstone per acked item, against hard-delete retention (#25 D2). The claimant re-post could not
put a lost claim back after the ack, so the recovery that ADR 0023 D5 names would not exist.

## Consequences

1. **`blueprint/api.md` already carries D1 and D2.** The "Mailbox" section, "Post" bullet: "A
   post that reuses a key returns the live item; after the ack, the same key creates a new item".
   The "Ack" bullet: "reject-new when full; a replay of a pending item still answers". No text
   change is needed.
2. **`blueprint/engine.md` already carries D3.** "Grants and ledger", the "Claim" bullet: every
   re-post reuses the key of the first post. "Mailbox logic", "Lifecycle": "The claimant's re-post
   covers a stop between the ack and the op write." No text change is needed.
3. **`CONTEXT.md` needs no change.** The "Mailbox" term carries the ack answer (ADR 0023 D5). D1
   and D2 are transport detail of the API and belong in `blueprint/api.md`, not in a glossary
   term.
4. **ADR 0023 D6 now reads under this ADR.** Its sentence "Every re-post of one claim reuses the
   idempotency key of its first post, so the mailbox keeps one live item for it" reads as "so the
   mailbox holds at most one live item for it at a time; after an ack removes that item, the next
   re-post under the same key creates a new item (ADR 0048 D1, D3)".
5. **`blueprint/api.md` section "Mailbox" gains the citation (ADR 0048)** on the "Post" bullet,
   where the after-ack sentence now cites ADR 0023 D5 and D6, and on the "Ack" bullet after "a
   replay of a pending item still answers".
6. **No wire format, no KDF edge, and no op queue record changes.**

## Residuals

**E1 — A replay cannot replace the blob of a live item.** The API keeps the first blob and drops
the blob of a replay. Each claimant re-post seals the same claim again, so nothing is lost for a
claim. A sender that must change a pending payload has to use a new key.

**E2 — One claim can produce more than one item over its life.** Each item after the first costs
the owner one pending slot until the ack, one ack, and one no-op conversion. The claimant's post
bound (`CLAIM_MAX_POSTS` in `crates/engine/src/grants/accept.rs`) and the link deadline bound the
count. This is separate from an API replay of an acked claim (ADR 0023 E2).

**E3 — The engine seam text and the conformance kit disagree with D1.** The `Mailbox` trait doc
in `crates/engine/src/seams/mailbox.rs` and the comment in
`crates/engine/src/testkit/conformance/mailbox.rs` say that an "already-seen" key creates no
second item. Under D1 a key seen before an ack creates a new item after it. This ADR records the
blueprint (D1). The in-memory fake follows D1 (`remove` in
`crates/engine/src/testkit/fakes/mailbox.rs` frees the key). The kit does not assert the
after-ack case, so a `Mailbox` implementation that never frees a key passes it.

**E4 — The in-memory fake does not model D2.** The fake has no pending cap, and it keys a replay
on the recipient and the key, not on the sender, the recipient and the key. No engine test
exercises a replay at the cap. D2 is proved at the API only.

**E5 — `blueprint/testing.md` claims contract coverage that does not exist.** The "contract
suite" paragraph lists "pending-cap reject-new" in the mailbox lifecycle.
`crates/contract/tests/contract.rs` has no pending-cap test. The API unit suite tests the cap and
D2. The real-Postgres HTTP integration suite (`mailbox.http.itest.ts`) and the real-Postgres
service integration suite (`mailbox.service.itest.ts`, the cap under concurrent posts) also test
reject-new.

**E6 — The engine writes the conversion entry before the ack, not after it.** ADR 0023 D5 and
`blueprint/engine.md` "Mailbox logic" give the order "ack, write the durable op entry, convert,
publish", and name a stop between the ack and the op write as the window that the re-post
covers. The engine writes the entry before the delete runs (the module header of
`crates/engine/src/grants/conversion.rs`, and the engine test
`a_crash_between_the_ack_and_the_record_write_keeps_the_claim` in
`crates/engine/tests/owner_actions.rs`), so in the code that window does not open. An entry
written before the delete also converts when the answer of its delete is lost
(`EntryState::Acking` and `Hold::Resumed` in `crates/engine/src/grants/conversion.rs`), so the
code does not convert only on "removed" either. This ADR records the blueprint text for D3. D1
still decides what every claimant re-post after an ack does, whichever order the owner engine
uses. The order itself is the rule of ADR 0023 D5, not of this ADR.

## Gate

- **D1, the key replays while the item is live.** API unit suite
  (`apps/api/src/mailbox/services/mailbox.service.test.ts`): `is idempotent per sender: a replay
returns the original id without a duplicate row`. API integration suite
  (`apps/api/src/mailbox/mailbox.http.itest.ts`, real Postgres): `replays idempotently: the same
key returns the original id, no duplicate`. Contract suite
  (`crates/contract/tests/contract.rs`): `mailbox_ack_reports_removal_and_releases_the_idempotency_key`.
- **D1, the key is free after the ack.** API unit suite: `frees the idempotency key: a post
after the ack creates a new item`. API integration suite: `returns the live item to a reused
key, and a new item after the ack`. Contract suite:
  `mailbox_ack_reports_removal_and_releases_the_idempotency_key`. The engine fake has its own
  test, `a_key_replays_while_its_item_is_pending_and_posts_anew_after_the_ack`; it proves the fake,
  not the API.
- **D1, the key is free after the TTL.** API unit suite: `never replays a row past the 90-day TTL
that the purge has not removed yet`. No real-Postgres or contract test covers it.
- **D2.** API unit suite: `lets an idempotent replay through even when the mailbox is full`, on
  the fake repository with a cap of 3. It exercises the unlocked fast path only. No test covers
  the replay check under the lock at the cap, and neither the integration suite nor the contract
  suite covers a replay at the cap. This is a finding.
- **D3.** Engine tests: `a_held_claim_posts_again_under_its_first_key_with_exponential_backoff`
  (`crates/engine/src/grants/link_read.rs`) proves that every re-post uses the first key, and
  `a_link_holders_tick_posts_the_claim_again_under_one_key` (`crates/engine/tests/owner_actions.rs`)
  proves that the owner holds one item while it is live.
  `a_second_claim_by_one_identity_appends_no_row` (`crates/engine/tests/owner_actions.rs`) proves
  the no-op conversion of a second claim item, posted under another key. No engine test runs the
  after-ack path: an owner ack, a re-post that creates a new item, and a no-op conversion of that
  item. This is a finding.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
