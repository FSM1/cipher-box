# ADR 0082: A grantee cannot move a node across the edge of a received share

- **Status:** Proposed
- **Date:** 2026-10-28
- **Relates to:** [FSM1/cipher-box#1910](https://github.com/FSM1/cipher-box/pull/1910) (the
  refusal shipped), [FSM1/cipher-box#2494](https://github.com/FSM1/cipher-box/issues/2494) (the
  grantee arm of the ADR 0080 fix),
  [ADR 0080](./0080-a-flat-cut-re-seals-the-ascent-links-of-nested-scope-roots.md),
  [ADR 0074](./0074-a-personal-grantee-takes-the-scope-pointer-name-from-the-owner-signed-share-pointer.md)
  (a grantee follows a cut of the owner)
- **Implemented by:** the refusal in FSM1/cipher-box#1910; the deletion of the grantee
  scope-exit arm (PR to follow)
- **Amends:** FSM1/cipher-box-next#26 D1 for grantees (frozen corpus, cited only),
  [ADR 0032](./0032-the-owner-signs-each-grant-row-and-the-commitment-names-every-recipient.md)
  D6, ADR 0080 Residuals,
  [ADR 0081](./0081-a-rotation-root-publish-holds-its-signed-sequence-as-a-durable-mark.md) D1

## Context

The frozen corpus (FSM1/cipher-box-next#26 D1) made a cross-scope move out of a granted source
scope a scope-exit trigger. When a grantee made the move, the grantee device ran a flat
`rotateScope` of the source. The engine did not build that path. FSM1/cipher-box#1910 refuses
the move in the facade, and it recorded no owner decision. `GranteeRotationNet` in
`net::rotation` stays, but only its tests build it. The blueprint and `CONTEXT.md` still describe
a grantee cut.

## Decision

**D1 — A grantee cannot move or relink a node across the edge of a received share, and only the
sharer makes that move.** The engine refuses with `ScopeExitRefused` each relocation where one
end is in a received share and the source scope and the destination scope are different. This
covers a move into a received share, out of it, between two received shares, and across a scope
root nested in one share. `Engine::relocation_anchors` sends each relocation with an end in a
graft to `grafted_relocation`, which refuses with "a move out of or into a received share is the
sharer's to make". The free function `write_home` refuses a grafted root as the node of an op
(`TargetRole::Node`): a grantee cannot move, rename or delete the grafted root. Thus no grantee
device cuts a scope that it does not own. There is no grantee-triggered scope-exit rotation. A
scope exit is an owner trigger, and the owner device runs it as a flat cut (ADR 0080).

## Alternatives considered

- **Permit the move, and the grantee device runs a flat cut of the source (the frozen design).**
  Rejected. It needs the grantee arm built and wired. The cut must also re-seal the ascent link
  of each nested scope root (ADR 0080, FSM1/cipher-box#2494). A grantee can lack the authority for
  that re-seal, so the cut leaves owed work for an owner device. A device that does not own a
  scope then cuts it, and the owner device must finish the cut.
- **Permit the move, and leave owed work so that an owner device runs the cut.** Rejected. The
  source scope stays uncut until an owner device runs. A new owed record kind and a new sync path
  must carry the work to the owner. That is more complexity for one move that the sharer can
  make.

The cost of D1 is grantee UX. A grantee asks the sharer to make the move, or copies the node
out.

## Consequences

- The dead grantee arm is deleted in a code PR: `GranteeRotationNet` and the grantee-only parts
  of `net::rotation`, with their tests.
- `blueprint/engine.md` "Triggers": the scope-exit row is an owner trigger, and a grantee move
  across the edge of a received share is refused.
- `blueprint/engine.md` eager set law: the "Grantee scope-exit rotations" bullet becomes the
  flat-cut bullet (`RotateNow`, an owned scope exit).
- `blueprint/engine.md` "Cold start": the residual names flat-cut epochs, not grantee-triggered
  epochs.
- `blueprint/core.md` "Structure signatures" and `CONTEXT.md` "Grant-set commitment": the
  commitment still carries no read epoch, and the grantee-rotation reason for it is retired.
- `CONTEXT.md` "Eager set": the grantee scope-exit sentence goes.
- ADR 0032 D6 carries an "Amended by" sentence. The commitment format does not change.
- ADR 0080 Residuals carries an "Amended by" sentence that closes the grantee-arm residual.
- ADR 0081 D1 carries an "Amended by" sentence: the grantee scope-root publish goes with the arm.
