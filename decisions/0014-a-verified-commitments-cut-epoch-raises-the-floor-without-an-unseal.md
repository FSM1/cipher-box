# ADR 0014 — A verified commitment's cut epoch raises the cut-epoch floor without an unseal

- **Status:** Accepted — implemented in FSM1/cipher-box#1737 (merged)
- **Date:** 2026-09-03
- **Relates to:** the floor law of
  [#39](https://github.com/FSM1/cipher-box-next/issues/39) D4, which supersedes
  [#26](https://github.com/FSM1/cipher-box-next/issues/26) D4's blob-seeded floors, the adoption
  gate that [#33](https://github.com/FSM1/cipher-box-next/issues/33) D7 runs on every resolve,
  the grant-set commitment of [#34](https://github.com/FSM1/cipher-box-next/issues/34) D6, and
  [FSM1/cipher-box#1698](https://github.com/FSM1/cipher-box/pull/1698), which closed this replay
  for a recipient the owner did not cut
- **Implemented by:** [FSM1/cipher-box#1737](https://github.com/FSM1/cipher-box/pull/1737), which closed
  [FSM1/cipher-box#1697](https://github.com/FSM1/cipher-box/issues/1697)

## Context

The floor law admits a durable floor advance from the record plane only after a body unsealed
under an AAD that confirms the epoch, plus the cold seed from the owner-signed re-point object.
`blueprint/engine.md` states it under "Adoption gate and floors", and the module header of
`crates/engine/src/gate/floor.rs` lists the admitted advances. The rule holds a floor to a field
the record proved, never to a field the record claimed.

The cut-epoch floor is the bar that stage 2 of the adoption gate holds a grant-set commitment
to. A commitment carries no read epoch, so a pre-cut set the owner really did sign verifies for
ever, and any surviving committed write grantee can republish a scope root that carries it. The
cut epoch this device already adopted is what tells the replay apart from the set in force.

On a recipient device the cut-epoch floor rises in one place: the commit of a pending adoption,
which runs after a full gate pass and an unseal. A recipient the owner **cut** holds no grant
blob in the post-cut set. It therefore never adopts the post-cut record, so its cut-epoch floor
stays at the value it last adopted, usually zero.

A surviving committed write grantee can then republish the pre-cut scope root at the cut
recipient's bookmarked name. The record carries an authentic owner signature that is bound to
that name, the recipient's blinded tag is still committed in the pre-cut set, and the
recipient's cut-epoch floor is below the record's cut epoch. The `/shared` row moves from
`revocation-signal` back to `granted`, and it stays there while the replay is served.

The exposure is the label alone. A `granted` verdict makes no durable write, unseals nothing,
and grafts nothing. Every unseal, the seed deposit, and the snapshot merge sit behind the open
path, which runs the gate, so the cut recipient still reaches no content.

The repair is to raise the cut-epoch floor from the commitment that stage 2 just verified. That
advance sits outside the floor law, because the classification path unseals nothing by design.
The floor law is therefore amended first, and the code follows.

## Decision

**D1 — The cut epoch of a grant-set commitment that passed `verify_commitment_in_force` raises
the device's cut-epoch floor for that scope, with no unseal.** This is one exception to the
floor law, added beside the AAD-confirmed unseal and the cold seed from the re-point object.

**D2 — The exception covers one field, and the list is closed.** The cut epoch of a verified
commitment is the only field that may move a durable floor without an unseal. No other field of
the commitment, of the envelope, or of any grant blob gains such a path. A grant blob's epoch
field stays an advisory routing hint with no advancement path.

**D3 — The pre-condition is the whole of gate stage 2, and nothing less.** The commitment
verifies under the contact-code-anchored sharer identity, the scope root name it is presented
under is inside the signed preimage, and its cut epoch is not below the floor this device holds.
The name binding is what makes the value a statement of the owner about this scope root, rather
than a claim the network authored.

**D4 — The raise is written under the sharer-scoped floor key.** The sharer authors its own
scope id, so the floor is keyed by the contact label of the granting identity together with the
scope id. A cut by one sharer therefore refuses that sharer's scope alone, and leaves another
sharer's scope of the same id granted.

**D5 — The raise is monotone.** It is a maximum against the stored floor, like every other
floor advance. A commitment that carries a lower cut epoch than the stored floor moves nothing,
and no path lowers this floor.

**D6 — A later rejection of the same record does not undo the raise, and the raise never makes
a plane unreadable.** The cut-epoch floor is read at stage 2 and refuses commitments only; it is
never read against a body, a sequence, or a read epoch. A floor raised from a record the gate
then rejects at a later stage leaves every readable plane readable.

**D7 — The raise reaches the device that the unseal path cannot.** A recipient the owner cut
records the cut epoch on the resolve that classifies the row, without holding a grant blob and
without an unseal. A recipient that is not cut keeps raising the same floor through the adoption
commit, so the two paths agree on one bar.

## Alternatives rejected

**Raise the floor only on an AAD-confirmed unseal, which is the rule as it stands.** A cut
recipient holds no blob in the post-cut set, so it unseals nothing and its floor never moves.
The replay of the pre-cut set therefore stays open on that device for good. The status quo
closes the exposure for every recipient except the one the cut was made against. Rejected.

**Have the owner publish a revocation record that the cut recipient adopts.** The recipient
holds no key in the post-cut set, so no body of that record unseals for it, and the floor law
would still admit no advance. Delivering a value the recipient can open needs a new record kind
that is sealed to a party the owner has just cut, which is a wire-format change and a new
grant of readability to a revoked recipient. Rejected.

**Treat the classification verdict as durable state, with no floor.** The path would remember
that it once saw a `revocation-signal` for the row, and would refuse to return to `granted`. A
verdict is a rendering of the newest record, not a bar a record is held to, and the adoption
gate does not read it. The gate and the row would therefore drift apart again, which is the
defect FSM1/cipher-box#1698 removed. Rejected.

## Consequences

1. **`blueprint/engine.md` changes when this ADR is accepted.** The floor law paragraph under
   "Adoption gate and floors" lists the admitted advances; it gains this exception and the bound
   on it. The stage 2 text in the same section states where the raise is made.

2. **`CONTEXT.md` "Floor law" gains a clause.** The entry today names the AAD-confirmed unseal
   and the cold seed alone. "Cut epoch", "Revocation floor" and "Grant-set commitment" need no
   new term: the exception is a new advancement path for a field they already define.

3. **The module header of `crates/engine/src/gate/floor.rs` gains the same item**, because it
   enumerates the record-plane advances the law admits.

4. **Three tests from the acceptance list of FSM1/cipher-box#1697 follow.** A cut recipient that
   resolves a post-cut record, classifies `revocation-signal`, and then refuses a replayed
   pre-cut record served at the same name at a higher sequence. A cut under one sharer that
   leaves another sharer's scope of the same id granted. A floor raised from a commitment that
   the gate then rejects for another reason that leaves the plane readable.

## Residuals

**E1 — A device that resolves no post-cut record at all learns no cut.** The raise needs a
commitment to verify, so a cut recipient that is offline, or that is served the pre-cut record
only, holds its old floor and shows `granted`. The exposure stays the label alone, and the first
post-cut record it resolves closes it.

**E2 — The cut-epoch floor still has no cold-seed anchor.** No owner-signed anchor carries it,
so a fresh install of a cut recipient starts at zero and takes the first commitment served. This
is the residual that `CONTEXT.md` already records at "Revocation floor"; this ADR narrows it to
a device with no floor, rather than a device that can never raise one.

**E3 — A partial or reordered set of unseal-free advances is moot under D2.** The exception has
one member, so there is no set to reorder and no half-applied set to leave a plane unreadable. A
second member would reopen the question, which is why D2 states the list as closed.

## Gate

- A cut recipient that resolves a post-cut record whose commitment passes
  `verify_commitment_in_force` holds a cut-epoch floor at that record's cut epoch, with no
  unseal and with no grant blob of its own.
- The same recipient refuses a replayed pre-cut record served at the same name at a higher
  sequence, and the `/shared` row does not return to `granted`.
- A cut by one sharer leaves another sharer's scope of the same id granted.
- A commitment that carries a cut epoch below the stored floor moves the floor nowhere.
- A record whose commitment passes stage 2 and that the gate then rejects at a later stage
  leaves every plane this device could read readable.
- No field other than the cut epoch of a verified commitment moves a durable floor without an
  unseal.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
