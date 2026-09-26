# ADR 0024 — A link holder reads at once from the link blob

- **Status:** Accepted on 2026-09-25; the `blueprint/*.md` and `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-25
- **Relates to:**
  [wayfinder: sharing as a link-first flow with no approve step (#1945)](https://github.com/FSM1/cipher-box/issues/1945),
  [sharing: the engine cost of instant read from the link blob (#1947)](https://github.com/FSM1/cipher-box/issues/1947),
  [sharing: what revocation means under the link-first model (#1949)](https://github.com/FSM1/cipher-box/issues/1949)
  (write links),
  [Design: sharing and grant delivery architecture (#25)](https://github.com/FSM1/cipher-box-next/issues/25)
  D6 (bearer links), ADR 0020 D3 (the new build reads the previous release), ADR 0023
  (conversion), ADR 0025 (revocation), the `blueprint/engine.md`
  "Grants and ledger" section ("Accept flow" and "Invites"), the `blueprint/web-client.md`
  "Composition (apps/web)" section, and the `CONTEXT.md` terms **link holder**, **grantee** and
  **invite link**

## Context

The invite secret in the fragment opens the link's grant blob today
(`crates/engine/src/grants/invite.rs:1285-1345`, a test). The engine offers no read path for it,
so a claimant reads nothing until the owner converts the claim. The mint keeps the secret "in a
URL and nowhere durable" (`crates/engine/src/grants/invite_mint.rs:105-108`).

The prototype on branch `prototype/link-blob-instant-read` (commit `0c6ad04f2`) adds the read:
about 290 engine lines, one optional field on the received-share bookmark, no new seam, no new
store kind, and no KAT. Line numbers below that name `link_read.rs` are on that branch. The
others come from the research reports (`main` at `d30509e48` or `ee147eac9`).

Words: a **link holder** reads through the link keys and is not converted yet. A **grantee** is a
converted person with a personal blob.

## Decision

**D1 — A link holder reads at once.** When the person joins, the engine posts the claim, then
reads the scope through the link's grant blob. The fragment carries the scope pointer name and the
stable `pointerReadKey` beside the invite secret and the owner contact code (ADR 0023 D2). The read
is best-effort, and the tick retries a
failed read. The received-share bookmark gains one optional field, `linkSecret`, that holds the
invite secret. The field lives in the received-shares list, sealed under its owner-local kind
(ADR 0006). This reverses "nowhere durable" on the grantee side only.

**D2 — The grantee drops the link keys when the personal blob lands.** The refresh pass prefers the
personal tag. It reads the link tag only while no personal blob opens and `linkSecret` is held.
The persist that records the first personal open also deletes `linkSecret`. The person is then a
grantee.

**D3 — A revoke of a person also cuts the link that admitted the person.** The owner finds that
link through the via-link reference (ADR 0023 D2). Until the person's engine sees the personal
blob, it still holds the link keys, and the person may still hold the URL. A cut of the personal
row alone leaves the person reading through the link. ADR 0025 D4 puts both rows in one cut.

**D4 — A link is committed at `read`, whatever the permission it grants.** The link's commitment
entry and its ledger row carry the permission `read`. The permission that conversion grants is a
separate owner-signed field on the commitment entry, beside the kind and the deadline. The
committed permission alone selects the blob material, at the mint and at every re-seal, by the
owner or by any co-writer on any release. A build that ignores the kind still seals by that
permission, so a link entry committed at `write` would hand the write seed to every link holder.

A write-link holder reads through the link blob and cannot write, and holds no writer pseudonym
authority. At conversion the owner engine mints the personal row at the conversion permission,
with the write material and a write-scope cut when the folder has none yet (ADR 0025 D6). The
grantee then writes under its own writer pseudonym. Creating a write link runs no write-scope cut
and no name wave. An older owner build that ignores the new field converts at `read`, which fails
safe.

**D5 — The link path runs these trust checks.** At the join, in this order:

1. The fragment decodes inside its 2048-byte bound (`invite.rs:462`).
2. The owner contact code in the fragment passes its binding verify
   (`crates/engine/src/grants/contact.rs:70`).
3. The link path resolves the scope pointer that the fragment names (ADR 0023 D2). It opens the
   re-point object under the fragment's `pointerReadKey` and verifies the owner-identity signature
   against the fragment's owner contact code. The record at `currentRootName` verifies at that
   name, and the resolved name is that name. The old-name tombstone and the mailbox mirror stay
   accelerators only (`CONTEXT.md` "Re-point object").
4. The record does not name this vault's own root scope (`link_read.rs:43`).
5. A blob sits at the link tag, which derives from the ephemeral encryption key, the owner
   encryption key and the current scope root name. The holder derives the tag again at each new
   `currentRootName`.
6. The owner-signed commitment names that tag with the kind `link`, and its deadline is later
   than the injected `now` (ADR 0023 D2). The holder reads at the committed permission, `read`
   (D4).
7. The blob opens under the ephemeral subkey, with the AAD bound to version, id, scope and epoch.
8. The adoption gate runs in full against the fragment owner's identity, with floors keyed under
   the owner's contact label. The personal path uses the same namespace, so the switch in D2
   moves no floor.
9. The bookmark persists before the floor advance commits.

Each refresh pass runs the checks of a personal share with the ephemeral subkey: the sequence
floor, `verify_commitment_in_force` against the owner identity and the cut-epoch floor, the
cut-epoch raise, and the open with the id and scope bound to the bookmark
(`crates/engine/src/grants/received_status.rs:607-869`, on the prototype branch). It also checks
the deadline of the link entry. A second join on one device copies the equal-floor short-circuit
of the personal accept (`crates/engine/src/grants/accept.rs:982-1004`).

**D6 — Three checks of the personal path do not all carry over.**

- **Sender binding to an out-of-band contact.** The link path cannot run it. The personal path
  binds the mailbox sender to an imported contact (`accept.rs:904`, `:907`). The link path has no
  mailbox item. Its owner anchor is the fragment's owner contact code, which nothing signs
  (`crates/engine/src/facade.rs:9124-9129`).
- **A per-person binding.** The link path cannot run it. Every holder of one link shares one key.
- **The deadline.** The link path runs it now. The prototype ticket
  [sharing: the engine cost of instant read from the link blob (#1947)](https://github.com/FSM1/cipher-box/issues/1947)
  listed it as a check the link path could not run, because the deadline was in the sealed
  ledger. ADR 0023 D2 moves it onto the commitment.

## Alternatives considered

**(a) Conversion on the tick only, with no read before it.** Rejected. The person waits for the
owner's device to be online, which can take days.

**(b) Keep the two derived keys in the bookmark instead of the secret.** Rejected. The secret
re-derives both halves, and the claimant needs the ephemeral identity key to post a claim again
(ADR 0023 D6).

**(c) A separate owner-local kind for the secret.** Rejected. It adds a `crates/core` kind and a KAT
entry, and the received-shares seal already protects the bookmark.

**(d) Commit a write link at `write`, and keep its blob read-only by the kind.** Rejected by D4.
Every re-sealer selects the blob material by the committed permission.

## Consequences

1. **The received-shares stored list keeps version 2.** `linkSecret` is an optional bookmark key
   with no version bump, because ADR 0020 D3 requires the new build to read the previous
   release's list. Received-share bookmarks without the key stay valid.
2. **`blueprint/engine.md` changes.** In "Grants and ledger", "Accept flow" gains the link-held
   arm of D1, D2 and D5, and "Invites" states D3 and D4.
3. **`blueprint/web-client.md` changes.** "Composition (apps/web)" gains the `/shared` row state
   of a link-held share.
4. **`CONTEXT.md` changes.** It adds **link holder** and **grantee**, and it defines **invite
   link** as a bearer link that reads at once and writes after conversion. The "Grant-set
   commitment" sentence names the conversion permission field of D4.
5. **No seam, no KDF edge and no op record changes.** A write-link mint costs the same as a
   read-link mint, because the write material is minted at conversion (D4).

## Residuals

**E1 — The invite secret rests on the grantee device until conversion.** A thief of the
received-shares list can read through the link and can post claims through it, until the owner
cuts the link. D2 bounds the window to the time before the personal blob lands. When conversion
refuses the claim, no personal blob lands, and the real bound is the link lifetime.

**E2 — The owner identity on the link path comes from the unsigned fragment code.** The read
anchors to whoever minted the link. A forged fragment can name the forger's scope and the forger's
code, and its content renders at the join. Before this ADR the forger had to convert the claim
first. The forger's power is the same, and one step is gone.

**E3 — One key per link.** The owner and the record plane cannot tell one holder from another. The
owner cannot cut one unconverted holder alone: a link cut ends every unconverted holder at once.
A leak of one holder's bookmark leaks the link.

**E4 — A link holder can unmask every committed recipient key.** The holder gets the scope
`pointerReadKey`, and a recipient key is a global identifier. Any grantee can do this today; the
link only widens who holds the key. The fragment carries `pointerReadKey`, so the URL alone
unmasks the committed recipients with no blob open: the same bound, reached one step earlier.
The owner accepted this leak as a residual on 2026-09-25, in place of a link-only mask key that
would need a new commitment format.

**E5 — A revoked or expired link still opens what the holder already has.** Every record that the
holder cached or fetched while the link was live stays open to it. The content key rule
(`CONTEXT.md` "Content key") never re-encrypts content bytes, so a cut protects the next version
only, the same bound as a person revoke.

**E6 — A write-link preview says "can edit" before the holder can write.** The holder writes only
after an owner device converts the claim, and that can take days.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.

## Amendment 2026-09-25

This amendment replaces the bookmark sentence of D1. The received-share bookmark gains three
optional keys. `linkSecret` holds the invite secret. `scopePointerName` holds the scope pointer
name from the fragment. `linkDeadline` holds the deadline of the link entry that the holder last
verified. The holder cannot derive the scope pointer name from the secret, because the owner
selects that routing name and the fragment carries it. The "expired" removal state needs the
stored deadline, so that a link cut at its deadline reads "expired" and not "revoked". The three
keys come as one set, and the D2 persist deletes all three. Consequence 1 holds for all three
keys: the stored list keeps version 2, and a bookmark without them loads unchanged.
