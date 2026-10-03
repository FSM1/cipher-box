# ADR 0069 — A writer applies again a write that a name wave did not carry

- **Status:** Accepted on 2026-10-03
- **Date:** 2026-10-02
- **Relates to:** FSM1/cipher-box#2220 (the name wave loses a write into the old tree),
  [ADR 0020](./0020-the-durable-op-queue-reads-the-previous-release.md) D2 and D3,
  [ADR 0065](./0065-the-name-wave-drops-a-node-that-it-cannot-move-and-an-owed-cut-ends-within-a-bound.md)
  D3, FSM1/cipher-box#2188, `blueprint/engine.md` "rotateScopeWrite" and "Sync core"
- **Implemented by:** FSM1/cipher-box#2220
- **Amends:** none

## Context

The name wave reads each interior node one time, and each republish seals the record that the
walk gated (`blueprint/engine.md` "rotateScopeWrite"). A writer that holds the old write seed can
publish a new record at an old interior name after the walk and before the pointer flip. The moved
node does not name that write, and no current seed derives its old name, so the write is not in the
live tree after the flip. Three parties can write into the old tree in this window: another device
of the owner, a write grantee that survives the cut, and the party that the cut revokes or
downgrades. A re-read in the wave lets a committed writer stop the wave or drop a node, so
FSM1/cipher-box#2188 pinned the gated reads on purpose.

## Decision

**D1 — The writer carries into the new tree a write that the wave did not carry. The wave does not
read an old name again.** The gated reads of "rotateScopeWrite" stay as they are. The writer is the
party that knows what it wrote, and the new write seed is the proof that it can still write. The
wave gets no re-read, no re-walk and no new bound, so a revokee gets no new way to hold the cut.

**D2 — A published op stays in the durable op queue until it is visible from the live root of its
write scope.** The live root is the scope root that the scope pointer names, at the current write
epoch. The confirm of the last record of the op's plan (`Drain::mark_published`) does not remove
the op. The op leaves the queue (`Drain::drain_queue`) only when a pass shows its effect from the
live root. Until then its staged blocks stay pinned, and the pending-op overlay shows the op as the
state law of "Sync core" states. Thus the write of an honest writer is not lost, at any time before
or after the flip. Amended on 2026-10-03: D7 replaces the overlay clause.

**D3 — When a pass sees a new write epoch on the op's write scope, the writer reads the new tree
and, if it holds the new write seed, applies the op again under that seed.** An owner device gets
the seed from the owner write blob, and a surviving write grantee gets it from its grant blob. The
op applies again through the standard rebase of "Sync core", in FIFO order before the later queued
ops, and the per-op rebase rules apply unchanged. A revoked or downgraded party holds no new write
seed, so its op does not apply again and takes the dead-letter path of "Sync core".

Amended on 2026-10-03: the owner ruled the three Residuals. D4 to D6 record the rulings, and D7
follows from them.

**D4 — A kept op is an op at or below the published-op mark that stays queued, and its note is a
separate clear record.** The drain writes one note for each kept op in one bookkeeping record of
the identity (`sync::kept_op`): the write epoch of the op's scope and the time of the publish.
The note holds an op id, an epoch and a time, so it stays clear, as the op-id marks do. The
previous release removes a queued op at or below the published-op mark as published, and its
orphan sweep deletes the note record. Thus a downgrade drops a kept op as that release did, and
no migration step is necessary (ADR 0020 D3).

**D5 — A kept op waits at its write epoch for T = 7 days, the bound of ADR 0065 D3.** The live
write epoch is the write-epoch floor of the op's scope on this device. While the floor equals the
epoch of the note, the op stays, and after T it leaves the queue and its staged blocks release. A
higher floor sends the op to D3 at any time. Time enters through the clock seam.

**D6 — The test "visible from the live root" is the standard rebase onto the live tree.** An op
that the rebase reads as already satisfied leaves the queue, and an edit whose own version is the
head of its file is already satisfied. The check runs only when the base read the folder that the
op writes under at its name of the new write seed. A kept op with no note gets a note at write
epoch 0 when the drain first sees it, so it gets one check, and T runs from that sight.

**D7 — A kept op is not pending.** The pending-op overlay, the pending flags, the staged-content
read and the second-end choice of a pass skip an op at or below the published-op mark, because its
version is live. Only the drain reads a kept op again, and the cancel command refuses it.

## Alternatives considered

- **Check every old name before the flip, and walk again (option A).** After the interior
  republishes, the wave reads each old name again, and a newer record starts the walk again from
  the root, within the bound of ADR 0065 D3. A write after the last check and before the flip is
  still lost. A revokee can hold the cut until the bound. Each pass costs one more read for each
  interior node, and a resume must compare a moved copy with the gated read.
- **Carry only the changed nodes before the flip (option B).** As option A, but the wave gates
  the new record of a changed node, publishes it again and walks only its new children. It reads
  less than option A on a large tree, and it has the same window and the same revokee bound. It
  adds more code to the wave and to `rotate_write`.
- **Accept the loss as a residual (option D).** No code. An honest writer loses a write with no
  notice, which the dead-letter law of "Sync core" forbids.

## Consequences

1. `blueprint/engine.md` "Sync core", the "Ops" bullet, states D2 to D7: the kept op, the
   check at a new write epoch, and the second apply through the rebase.
2. `blueprint/engine.md` "rotateScopeWrite" adds one sentence after the gated-read sentence:
   the writer carries such a write (D1). "Residuals" states that the late write of a revoked
   writer dead-letters on its own device, and that a kept op whose folder the writer does not
   read at its new name within T leaves at T.
3. `CONTEXT.md` "Op queue" states that a published op stays until it is visible from the live
   root, and "Name wave" states that the writer carries a write that lands after the walk.
4. `blueprint/testing.md` "crates/engine — seam fakes and the simulation harness" adds the
   probe: the wave reads the old record, and after the writer's next passes the new tree names
   the new child at its new name and the child opens there. Amended on 2026-10-03: the probe
   serves the walk the record from before the write, and the bound of D5 and the check of D6
   each have a test.
