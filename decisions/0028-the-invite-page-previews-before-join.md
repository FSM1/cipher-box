# ADR 0028 — The invite page previews the share before the person joins

- **Status:** Accepted on 2026-09-25; the `blueprint/*.md` and `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-25
- **Relates to:**
  [wayfinder: sharing as a link-first flow with no approve step (#1945)](https://github.com/FSM1/cipher-box/issues/1945),
  [sharing: preview the shared content on the invite page before joining (#1954)](https://github.com/FSM1/cipher-box/issues/1954),
  [sharing: prototype the invite flow from arrival to the shared folder (#1961)](https://github.com/FSM1/cipher-box/issues/1961),
  [web: let a signed-out user sign in on the invite page and claim without a reload (#1943)](https://github.com/FSM1/cipher-box/issues/1943)
  (the invite page), ADR 0024 (the link read), ADR 0027 (the names in the fragment and in the
  claim), the `blueprint/engine.md` "Grants and ledger" ("Invites") and "Facade" sections, the
  `blueprint/web-client.md` "Engine hosting and tab leadership" and "Composition (apps/web)"
  sections, and the `CONTEXT.md` "Adoption gate" and "Floor law" terms

## Context

The invite page signs a person in on the page, since
[web: let a signed-out user sign in on the invite page and claim without a reload (#1943)](https://github.com/FSM1/cipher-box/issues/1943).
The claim then needs a press. A claim at page mount would let any page that can navigate a
signed-in tab spend an attacker's link under the grantee's identity
(`apps/web/src/routes/InvitePage.tsx:19-23`). The person
presses "join" with no view of what the link shares.

The link read of ADR 0024 can show the content first. The folder's own name is not reachable
through the link: it lives in the parent's listing (`crates/core/src/seal/body.rs:78-84`), and the
parent is outside the scope.

A preview before sign-in meets four blocks. Every engine read passes the session gate. The floor
store binds only at `start` (`crates/engine/src/facade.rs:5355`,
`crates/engine/src/seams/floor_store.rs:200-213`). No production in-memory floor store exists. The
web build has no public content gateway (`apps/web/src/engine/config.ts:131-136`). File and line
citations come from the research reports and from the preview ticket.

## Decision

**D1 — The order is sign-in, then preview, then join.** Sign-in comes first, always. Sign-in never
spends a link. "Join" is its own action, and it needs a press.

**D2 — The preview shows four things.** It shows the folder name, the owner, the permission that
the link gives, and a one-level listing of the folder's direct children with names and kinds, from
one read of the scope root. It shows no sizes and no counts. Each needs one resolve per child, and
each resolve links to the session pseudonym before the person consents. The person cannot browse
into a subfolder before joining.

**D3 — The preview is a read-only mode of the link read.** It runs on the signed-in person's own
engine. It runs every trust check of ADR 0024 D5 up to the open: it resolves the scope pointer
first, then the root at `currentRootName`. The adoption gate checks against the floors that the
session already holds. In this mode the engine:

- posts no claim and no mailbox item;
- persists nothing: no bookmark, no floor, no contact;
- deposits no seed into the session;
- drops the preview state when the page navigates away.

Because the preview spends and stores nothing, it may run with no press.

**D4 — The folder name and the owner name come from the fragment.** ADR 0027 D5 puts both there
under an owner signature. The names show only when that signature verifies. The preview and the
link-holder bookmark use them until the share pointer arrives at conversion.

**D5 — A dead link shows its state after sign-in.** The preview reads the link, so it reports an
expired link (the deadline of ADR 0023 D2), a revoked link (no blob at the link tag), and a link
that this account already joined (a bookmark this account still holds: a committed Personal entry
with a blob at its tag, or a claim this account already posted through this link). An already
joined link shows "open folder" and no "join". A person revoke leaves the bookmark at rest, so a
bookmark alone does not prove a join: ADR 0025 E4 lets a cut person who holds another live link
rejoin with no owner step. The preview and the join follow the scope pointer path of ADR 0024 D5, so a moved
scope root does not read as a revoked link.

**D6 — "Join" posts the claim and starts the link read.** The claim carries the grantee name of
ADR 0027 D1. The engine then records the bookmark and reads as a link holder (ADR 0024 D1).

**D7 — A preview before sign-in is deferred.** It needs a throwaway engine mode with an in-memory
floor store, public routing and a public content gateway. The four blocks in the context stand
until that mode exists. The map keeps it as an item that is not yet specified.

## Alternatives considered

**(a) Sign-in as the join gesture.** Rejected. A page can drive a sign-in, and a spend at sign-in
repeats the mount-time attack of `InvitePage.tsx:19-23`.

**(b) A preview before sign-in in this version.** Deferred by D7.

**(c) The name and the owner only, with no listing.** Rejected. The person decides on the content,
and a listing of the names and kinds of direct children costs one read of the scope root.

**(d) A browsable read-only view.** Rejected. Each subfolder costs one more read before the person
consents, and the joined folder gives the same view one press later.

## Consequences

1. **The page layout follows from D1 to D6.** The owner chose variant A of the invite-flow
   prototype: one stacked card after sign-in, led by "<owner name> shared <folder> with you",
   then the permission badge, the one-level listing, the name field and "join". The joined state opens the shared folder. This is
   a consequence of the decisions above, not a decision of its own.
2. **`blueprint/engine.md` changes.** In "Grants and ledger", "Invites" states the preview mode of
   D3. "Facade" gains the preview command, which returns the four items of D2.
3. **`blueprint/web-client.md` changes.** "Composition (apps/web)" states the invite route of D1,
   D5 and D6. "Engine hosting and tab leadership" states that the preview runs in the session
   engine and holds no state across navigation.
4. **`CONTEXT.md` changes.** "Adoption gate" states that a preview checks against the held floors
   and raises none. "Floor law" does not change, because the preview advances no floor.
5. **A preview tells CipherBox infrastructure one fact.** The session resolves the scope root
   through its routing under the per-session accelerator pseudonym, so the operator learns that a
   pseudonymous session read that name, not which account read it. The join discloses the same
   fact a moment later.
6. **A hidden page can make a signed-in tab show an attacker's preview.** Nothing is spent. The
   names show only under a verified owner signature (ADR 0027 D5).

## Residuals

**E1 — A write-link preview says "can edit" before the holder can write.** ADR 0024 E6 states the
bound.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
