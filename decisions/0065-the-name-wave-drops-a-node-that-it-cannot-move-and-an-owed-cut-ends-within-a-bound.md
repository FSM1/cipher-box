# ADR 0065 — The name wave drops a node that it cannot move, and an owed cut ends within a bound

- **Status:** Accepted on 2026-10-02
- **Date:** 2026-10-02
- **Relates to:** FSM1/cipher-box#2157 (the revokee can block its own revocation),
  [ADR 0020](./0020-the-durable-op-queue-reads-the-previous-release.md) D2,
  [ADR 0060](./0060-a-stated-refusal-from-every-endpoint-supersedes-the-bin-index-mint-mark.md),
  [ADR 0061](./0061-a-renewal-walk-over-every-owned-scope-renews-each-name-through-the-adoption-gate.md) D4,
  [ADR 0063](./0063-a-rotation-step-that-stops-leaves-a-durable-owed-record-that-the-sync-pass-finishes.md)
  D1, D3 and D4, [ADR 0064](./0064-the-name-wave-reads-a-lagging-interior-node.md),
  `blueprint/engine.md` "rotateScopeWrite"
- **Implemented by:** FSM1/cipher-box#2188
- **Amends:** ADR 0063 D4 (the names the renewal walk skips), ADR 0064 Residuals

## Context

The name wave of `rotateScopeWrite` reads the whole subtree before it moves a node
(`collect_subtree`). The first node that `resolve_node` does not resolve stops the wave, and the
owed entry of ADR 0063 stays. A revoked writer holds the old write seed, so it can plant a record
at an interior name that the wave cannot move. Each re-drive then stops at the same node, the
renewal walk skips the scope (ADR 0063 D4), the scope lapses at EOL, and the revokee keeps write
access. A writer can always break or delete data before the revoke, so a drop of a node that the
revokee planted gives the revokee no new power.

## Decision

**D1 — The name wave drops an interior node that it refuses for a cause in the record bytes.**
The causes are: the adoption gate refuses the record, except a sequence below the floor and a
head block that does not match its CID; an epoch that no held history link reaches (ADR 0064
consequence 8); and a malformed child ref in the body, which drops the parent. The wave removes
the ref from the moved parent, does not walk below the node, retires the old name, moves the
other nodes, re-points the root, and finishes the cut. The wave never adopts or carries a refused
record.

**D2 — Of two refs to one node id at different names, the wave keeps the ref at the name that
the scope's old write seed derives for that id, and drops the other ref.** Today this conflict
(`ConflictingChildLabel` in `record_children`) stops the wave.

**D3 — A stop that an endpoint can cause drops only after a bound.** The causes are: no record at
the name, no endpoint that answers for the name, no endpoint that serves the head block, a record
below the sequence floor, and a record at an epoch above the gated root's, which a read rotation on
another owner device can publish. The owed entry keeps the time of its first stop. A re-drive
retries such a node. When the entry has stopped for longer than the bound, and that node has
stopped the wave over a minimum count of passes, the next re-drive drops the node as D1 does. No
drop rests on one answer from the endpoint set.

**D4 — After the time of the bound of D3, the renewal walk renews in an owed scope each name
that the scope root's current write seed derives.** The count of passes does not apply here.
Before that time, ADR 0063 D4 stays. Such a renewal signs no
name under a seed that does not derive it (ADR 0061 D4), and gives the revokee no new access. Thus
a stop at the scope root also does not lapse the scope.

## Alternatives considered

- **Stop and re-drive with no limit (today).** The revokee keeps write access for ever, and the
  scope lapses at EOL.
- **Drop by class at once, with no bound (option 1).** A record whose head block no endpoint
  serves still stops the wave for ever. A drop of an absent record rests on one answer from the
  endpoint set, so an endpoint set that states "absent" in error makes the owner drop a real node.
- **Cut first and move the refused nodes later (option 3).** It keeps the most data. It needs a
  new `OwedStep` variant, which the previous release cannot decode, so it lands over two releases
  (ADR 0020), as the time of the first stop of D3 does. A parent ref points at a name with no
  record until the move. Until the bound, the revokee can write at the old name, and the late
  move takes that record into the new tree.
- **Stop and ask the owner (option 4).** The revokee keeps write access until the owner acts,
  with no limit. The owner sees only a node id and a class, which is not sufficient for a good
  decision. It needs a new command, a new event and host UI on web and desktop.
- **Carry the refused record to its new name without opening it.** The name is not in the AAD,
  so the bytes are valid there. But the owner then signs a parent that names bytes that it did
  not verify, the wave cannot learn the children of the node, and an absent record has no bytes
  to carry.

## Consequences

1. `blueprint/engine.md` "rotateScopeWrite" states D1 to D3. "Rotation primitives" states the
   bound of D3 as T = 7 days and K = 3 passes, and D4. "Residuals" states the data loss: the
   subtree under a dropped node leaves the tree and lapses at EOL.
2. `blueprint/engine.md` "Rotation primitives" states the event that each drop sends: the scope
   root, the node id and the cause. The command or the re-drive that drops a node returns `Ok`
   (ADR 0063 D5). `packages/client` adds the event type.
3. `blueprint/core.md` "Structure-tag registry", the `owner-local` structure: the `owed-rotation` (`0x0a`) body adds the
   time of the first stop to each entry. A body that the previous release wrote decodes to "no
   stop recorded", so the next stop sets the time (ADR 0020 D2). The `owner_local_accept` KAT
   body changes, and a test decodes the old shape (ADR 0020 D5).
4. `CONTEXT.md` adds the term "Dropped node". "Forgery window" ends at the bound of D3 for a node
   stop, and "Owed rotation work" states the bound.
5. `blueprint/testing.md` "crates/engine — seam fakes and the simulation harness": the rotation
   matrix adds the five ways to plant a stop (a record that does not unseal, an epoch that no
   held link reaches, a ref to an id with no record, a record with no head block, a second ref
   to one id), and each finishes the revoke within the bound.
6. ADR 0063 D4 and ADR 0064 Residuals carry an "Amended by ADR 0065" sentence.

## Residuals

- A planted record at the scope root name is not covered. The revokee derives the root name, and
  the wave cannot drop the root (FSM1/cipher-box#2176).
