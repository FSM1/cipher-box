# ADR 0081: A rotation root publish holds its signed sequence as a durable mark

- **Status:** Proposed
- **Date:** 2026-10-27
- **Relates to:** [#2499](https://github.com/FSM1/cipher-box/issues/2499),
  [ADR 0076](./0076-a-put-that-no-endpoint-acknowledged-holds-its-signed-sequence-as-a-second-mark.md)
  (the unacknowledged mark of a drain node),
  [ADR 0066](./0066-a-different-record-at-the-sequence-floor-is-a-fork-not-a-trust-violation.md)
  (a same-sequence fork),
  [ADR 0077](./0077-a-scope-root-stops-being-one-by-a-re-seal-into-new-node-ids.md) (the relink
  mark), [ADR 0071](./0071-a-below-floor-record-while-an-endpoint-fails-is-unavailable-not-a-trust-violation.md)
  D1, [ADR 0080](./0080-a-flat-cut-re-seals-the-ascent-links-of-nested-scope-roots.md) (the child
  ascent re-seal), [ADR 0020](./0020-the-durable-op-queue-reads-the-previous-release.md) (a durable
  record reads the previous release)
- **Implemented by:** not landed
- **Amends:** —

## Context

A rotation publish signs a scope root, or an interior node that the sweep or a grant move
re-seals, at the next sequence of its name. A PUT that does not confirm can still land at one
endpoint. A later read of a stale endpoint then gives the old sequence, and the engine signs other
bytes at the same sequence. Two valid records at one sequence are a fork (ADR 0066), and a reader
can pick the record whose seed the re-sealed children do not use. Today only
`OwnerRotationNet::publish_scope_root` keeps the sequence it signed, in the session map
`SessionState.spent_sequences`, in memory. Each attempt of the cut loops of `OwnerCutNet` gets a
new map. `promote_scope_root`, `publish_interior_head` and the grantee scope-root publish keep
nothing. The second mark of ADR 0076 covers drain nodes only.

## Decision

**D1 — Each rotation publish raises a durable mark at its name to its signed sequence, before the
PUT.** The key is `rotation-signed/ | name`, in the sequence namespace of the floor store, in the
style of the relink mark key `dissolve-relink-parent/ | name` (`floor::relink_parent_mark_key`).
The raise is `PutMark::SignedDurable`. When the floor store does not take the raise, the publish
refuses before the PUT (`PublishError::MarkUnrecorded`). Two arms raise the mark: the scope-root
publish arm `RootPublish::run` and `publish_interior_head`. Thus each of these publishes raises it:
the cut root and each descendant root of an owner cut, in each attempt of the bounded loops of
`OwnerCutNet`; the root of a flat cut (`flat_root_cut`); the child ascent re-seal
(`reseal_root_in_place`) and the index repair of the sweep; `promote_scope_root`; the grantee
scope-root publish, under the floors of its granting identity; and the interior re-seals of the
sweep (`publish_node`) and of a grant move (`reseal_interior_node`). The mark only rises, and
nothing clears it. A PUT that fails leaves a gap in the sequences of the name, and a gap is
harmless. The mark is not a floor: no gate, no resolve and no settle reads it.

**D2 — Every signature at the name reads the mark and signs strictly above it.**
`SignatureGate::read` and `SignatureGate::read_for_renewal` read the mark as they read the relink
mark. `sign_above` signs above the highest of the sequence floor, the relink mark, this mark, the
observed sequence and the held sequence. Thus the drain, the renewal walk and each later rotation
sign above the mark, in this session and in each later one. This is not the rule of ADR 0076 D2,
where the drain does not read the unacknowledged mark, so that a retry signs at the same sequence.
A scope root name is also a drain and a renewal target, and a drain signature at the sequence of a
rotation PUT signs other bytes there. A mark that does not read refuses the signature, as the floor
law of `blueprint/engine.md` requires for each floor read. It never reads as "no mark", and the
signature does not go above a bound as in ADR 0076 D2.

## Alternatives considered

- **The second mark of ADR 0076 (D1).** Rejected: it is a key for each node in the retire ledger,
  with settle semantics, and a confirmed publish above it clears it. A write cut moves a root to a
  new name, so a mark for each node holds a sequence of a name that the root left.
- **The session map alone, with an accepted residual (D1).** Rejected: a new session or a new cut
  net can sign other bytes at a sequence that landed. A reader then picks one record by the order of
  ADR 0066 D2, which can be the record whose seed the re-sealed children do not use.
- **Raise the real sequence floor to the signed sequence (D1).** Rejected: the device then reads
  the served record below its own floor. That record is unavailable under ADR 0071 D1 while an
  endpoint fails, and a rollback when every endpoint answers, until a newer record lands.
- **Raise the relink mark key (D1).** Rejected: the dissolve fence
  (`sync::drain::dissolve::proof`) waits until each relink parent name serves a record above its
  relink marks. A rotation publish at a relink parent name then holds a dissolve Retire back.
- **Only the rotation nets read the mark (D2).** Rejected: the drain and the renewal walk sign at
  the same names, and either can sign other bytes at a marked sequence.

## Consequences

- `SessionState.spent_sequences`, `GatedRoots::sharing` and the signed map of `GatedRoots` retire:
  the mark bounds each signature that the map bounded, and three more paths. The parked map of one
  pass stays, because `put_back_unmoved` reads it.
- A rotation publish whose mark the floor store does not take now refuses. Today it proceeds.
- The cut root PUT keeps the `Sent` note of its root fallback and also raises the mark.
- No floor-store GC touches the key: the `FloorStore` seam has no delete for one key, and neither
  host scans a prefix. A host `clear()` of the whole store drops the mark with every floor.
- The previous release reads only exact keys, so it ignores this key (ADR 0020). After a downgrade,
  the gap of FSM1/cipher-box#2499 is open again until the upgrade.
- `blueprint/engine.md` "Rotation primitives" states D1, and the "Publish" bullet of
  "Resolve/publish pipeline" states D2.
- `blueprint/testing.md` names the tests in the code PR: a rotation PUT that does not confirm,
  then a new session, a cut retry, a promote, an interior re-seal and a grantee cut, each above the
  mark; a drain publish and a walk renewal above the mark; a mark that does not read refuses; a
  raise that the store does not take sends no PUT.

## Residuals

- The name wave (`publish_moved`, over `Observed::unread` at a new name) and the pointer plane do
  not raise the mark. A wave PUT that does not confirm has the same window at its new name. Does
  the wave need the mark too?
