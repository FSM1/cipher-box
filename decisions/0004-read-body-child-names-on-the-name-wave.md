# ADR 0004 — Read-body child names are rewritten by the write-plane name wave

- **Status:** Accepted — implemented in FSM1/cipher-box#1101 (merged)
- **Date:** 2026-08-05
- **Amends:** [#26](https://github.com/FSM1/cipher-box-next/issues/26) decision D3
  ("Write plane: parallel flat write-seed tree; write rotation = override + child-first
  name wave") — makes concrete what "read-only survivors follow republished mirrors"
  requires, a clause the v2 blueprint dropped
- **Relates to:** [#38](https://github.com/FSM1/cipher-box-next/issues/38) decision D3
  (the re-point object supplies `currentRootName` only) and
  [#27](https://github.com/FSM1/cipher-box-next/issues/27) (the child-ref wire format)
- **Implemented by:** [FSM1/cipher-box#1026](https://github.com/FSM1/cipher-box/issues/1026)

## Context

`rotateScopeWrite` mints a fresh write override seed and republishes the scope's whole
subtree under freshly derived names. Every per-node write artefact — `writeSeed`,
`writeKey`, and the Ed25519 IPNS keypair that _is_ the `ipnsName` — derives from
`KDF(writeScopeSeed, node.id)`, so a fresh scope seed moves every node in the subtree to
a new name.

D3 of #26 states how each class of party keeps up: "surviving write-grantees derive every
new name locally (zero re-discovery), read-only survivors follow **republished mirrors**
plus the mailbox re-point for the root". #38 D3 later replaced the mailbox with the
owner-signed scope pointer as canonical for the root. The "republished mirrors" half was
never elaborated, and in the v2 blueprint's `### rotateScopeWrite` section it is gone
entirely — the text now reads "read-only survivors follow the owner-signed re-point
object", which covers the root and nothing below it.

That leaves a real hole. A read-only grantee **cannot derive interior names**: the grant
blob carries the write scope seed only for write grants, so a read-only holder has no
`writeScopeSeed` and no way to compute `KDF(writeScopeSeed, node.id)`. The re-point object
carries `currentRootName` and no other name. The only remaining route from the root to a
child is the parent's read-body child list — and `ChildRef` carries an `ipnsName` per
child (#27's wire format). After a name wave those entries name nodes that have moved;
once interior old names batch-retire, they name nothing.

So the wave as specified strands every read-only survivor one level below the root. This
is not an under-implementation of a charted mechanism: no mechanism was ever charted.
The engine's own module text asserts the opposite invariant — "The read plane is
untouched" — which is true of override seeds, read keys and `minReadEpoch`, but not of
read-body _bytes_.

## Decision

**The name wave rewrites read-body child names.** When the wave republishes a node, it
rewrites each `ChildRef.ipnsName` in that node's read body to the child's freshly derived
name and re-seals the read body under the node's unchanged read key at the unchanged read
epoch. The existing child-first ordering already makes every child's new name known
before its parent publishes, so no second pass is needed.

Three consequences follow and are accepted as part of this decision:

1. **The republish is not byte-stable.** The read body changes, so the record cannot be
   reproduced verbatim from its predecessor. Any "carry the read body verbatim" language
   in the blueprint or in `rotateScopeWrite`'s contract is withdrawn.
2. **The publisher needs read-plane material** — the node's read key, and a nonce from
   the entropy seam for the re-seal. The write rotation therefore touches read-plane
   bytes while leaving read-plane _keys and epochs_ untouched; the blueprint must say
   the narrower thing rather than "the read plane is untouched".
3. **The read epoch does not move.** A rewrite at the same epoch is not a read rotation
   and must not raise any read-epoch floor; `minReadEpoch` still carries unchanged, per
   #38 D1's rule that each plane's clock is authored by its own authority.

### Rejected alternatives

**Resolve children by node id through a write-plane index**, removing names from the read
body. Correct in the abstract — location-independent ids are what the write plane already
uses — but it is a `crates/core` wire-format change to #27's `ChildRef`, and it would
leave a read-only grantee needing a name lookup they still cannot perform. Rejected as
out of scope and insufficient on its own.

**Tombstone every migrated interior name** and let readers chase `movedTo`, instead of
rewriting anything. Rejected: #33's chase is depth-guarded, so a subtree deeper than the
guard breaks outright; and old names lapse at the 90-day EOL, so the approach defers the
break rather than removing it. It also multiplies the wave's publish count by keeping a
live tombstone per interior node, against #34 D4's retirement path.

## Consequences

- Read-only survivors traverse the subtree normally after a wave, which is what #26 D3
  intended and what its "republished mirrors" clause was pointing at.
- `rotateScopeWrite` is no longer describable as write-plane-only. The blueprint entry and
  the engine module header both need correcting; the honest statement is that the wave
  rewrites read-plane _metadata_ while never re-keying it.
- Content bytes are still never re-encrypted (#26 D6). Only the child-name field of a
  folder's read body changes.
- The wave's cost per node rises by one read-body re-seal. It stays O(subtree) and stays
  background and parallel, so the shape of the cost is unchanged.
- A resumed wave is unaffected: `isRepublished` still answers from published state alone,
  and a node whose record already sits at the new name is skipped before any re-seal.

## Gate

- After a wave, a read-only holder starting from the re-pointed `currentRootName`
  resolves every node in the subtree — asserted at a depth greater than one, so a
  root-only pass cannot satisfy it.
- Every republished parent's `ChildRef.ipnsName` set equals the derived new names of its
  children, and no retired name survives anywhere in the subtree's read bodies.
- The read epoch and every read-epoch floor are unchanged across the wave, while the
  write epoch advances — the two planes' clocks stay independently authored.
- A resumed wave that skips already-republished nodes still leaves no stale child name
  behind.
