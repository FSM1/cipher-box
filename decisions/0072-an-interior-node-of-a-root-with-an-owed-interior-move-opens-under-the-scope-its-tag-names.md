# ADR 0072 — An interior node of a root with an owed interior move opens under the scope its tag names

- **Status:** Accepted on 2026-10-03
- **Date:** 2026-10-03
- **Relates to:** FSM1/cipher-box#2248 (the tick focus leg reports an interior node of a grant
  with an owed interior move as abuse),
  [ADR 0017](./0017-the-epoch-tag-is-a-key-selection-label-not-an-attestation.md) (the epoch
  tag is a key-selection label),
  [ADR 0021](./0021-a-read-opens-an-epoch-lagged-interior-record.md) D2,
  [ADR 0063](./0063-a-rotation-step-that-stops-leaves-a-durable-owed-record-that-the-sync-pass-finishes.md),
  [ADR 0064](./0064-the-name-wave-reads-a-lagging-interior-node.md) D1,
  [ADR 0065](./0065-the-name-wave-drops-a-node-that-it-cannot-move-and-an-owed-cut-ends-within-a-bound.md),
  AGENTS.md rule 6, and the `blueprint/engine.md` "Adoption gate and floors" and "Grants and
  ledger" sections
- **Implemented by:** —
- **Amends:** —

## Context

A grant hands its folder over in three steps after the root publish: the reseal of the interior,
the re-key of the descendants, and the publish of the parent index. A stop at any step leaves one
owed step, the interior move with the scope that the folder left (ADR 0063 D1). The entry does
not record where the handover stopped. A stop at the reseal leaves the interior under the scope
that the folder left. A stop at the parent index leaves it under the new scope. A partial reseal
leaves a mix. A read leg groups an interior node by one scope and opens it under that scope's
seed, so either grouping refuses an honest record in one of these states. The child gate then
reports `seal-open-failed`, and the engine sends a false abuse event. The re-drive of the move
already tells the two cases apart by the scope in the record's epoch tag
(`resolve_moving_child` in `net::rotation`).

## Decision

**D1 — While an owed entry holds the interior move of a scope root, a gated read of an interior
node of that root opens the record under the seed of the scope that its epoch tag names.** The
tag must name one of the two scopes that the entry binds: the scope root of the entry, or the
scope that the folder left. A tag that names any other scope is refused at the unseal stage,
as today. The read opens the record one time, under the seed and the floors of the named scope.
The seal's AAD binds the scope, so a record whose tag names the wrong scope does not open under
the seed that it names, and a hostile record stays exactly one trust violation. The rule applies
to every read leg that picks the read seed of an interior node by its scope, with one shared
rule: the tick focus leg, the navigation leg, and the file legs that they run. When no owed
entry holds the interior move, the read takes the scope root of the node as before. The entry is
durable, so the rule also holds after a restart, and it covers a partial reseal. No durable
shape changes.

## Alternatives considered

- **Open under both seeds (the two-open form of this rule).** The leg opens under the grouped
  scope, and after a `seal-open-failed` it opens again under the other scope. It covers the same
  states, but each refused record costs two opens, and a second read path follows a refusal at
  the gate. The tag already names the one seed that can open the record.
- **Record the handover stage in the owed entry.** Split the interior move into the reseal step
  and the parent index step, and group by the new scope after the reseal lands. This changes the
  durable shape of kind `0x0a`, needs the two-release landing of ADR 0020 and new KAT rows, and a
  partial reseal still gives a false abuse event.
- **Keep a session-only mark of a reseal that landed.** No durable change, but a restart in the
  state after the reseal and a partial reseal still give a false abuse event, and three sites must
  set the mark in step.
- **Report `seal-open-failed` as unavailable while a move is owed.** This hides a hostile record
  at an interior node for the whole owed window, against AGENTS.md rule 6.

## Consequences

1. `blueprint/engine.md` "Adoption gate and floors" states D1 at the child unseal stage. The read
   runs at the floors of the named scope, so the count of sanctioned readers below the read-epoch
   floor stays four.
2. `blueprint/engine.md` "Grants and ledger" states that a read of the interior of a root with an
   owed interior move follows D1.
3. `CONTEXT.md` "Owed rotation work" adds one sentence: while the interior move is owed, a read
   of an interior node opens it under the scope that its epoch tag names, one of the two scopes
   that the entry binds.
4. `blueprint/testing.md` names the tests: a stop at the reseal, a stop at the parent index, a
   partial reseal and a restart each give no abuse event at the tick focus leg and at the
   navigation leg; a record whose tag names a bound scope that does not open it, and a record
   whose tag names a third scope, each give exactly one trust violation.
5. When the owed record does not read, the leg cannot tell that an interior move is owed. The
   leg then groups by the proved scope roots, as before this ADR, and a false abuse event is
   accepted in that state. The leg does not report the interior as unavailable, because that
   hides a hostile record (AGENTS.md rule 6).
6. Only the device that holds the entry applies D1 (ADR 0063 consequence 6). A second owner
   device or a grantee that reads the interior during the owed window can still report a false
   abuse event. This residual is accepted. It ends when the owed move lands.

## Residuals

None.
