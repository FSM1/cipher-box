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
epoch. The confirm of the last record of the op's plan (`Drain::mark_published`) does not remove the
op. The op leaves the queue (`Drain::drain_queue`) only when a pass shows its effect from the live
root. Until then its staged blocks stay pinned, and the pending-op overlay shows the op as the state
law of "Sync core" states. Thus the write of an honest writer is not lost, at any time before or
after the flip. Amended on 2026-10-03: D7 replaces the overlay clause. Amended on 2026-10-03: only a
create, a delete and a content edit (`Create`, `Delete`, `UpdateContent`) stay in the queue. Every
other kind leaves the queue at its publish, as before this ADR: the live tree cannot show if a later
writer overtook it, so a second apply could undo the later write (FSM1/cipher-box#2285).
Amended on 2026-10-06 (owner ruling on FSM1/cipher-box#2285, option B): a rename, a move inside one
scope and a version restore also stay kept ops. The note records the result of each: the name
before and after, the parent and name before and after, or the head content CID before and the
restored one. After a flip, a live node that shows the result or another value ends the op with no
apply, and one that shows the value before applies the op again. A move that re-seals into another
scope still leaves at its publish.

**D3 — When a pass sees a new write epoch on the op's write scope, the writer reads the new tree
and, if it holds the new write seed, applies the op again under that seed.** An owner device gets
the seed from the owner write blob, and a surviving write grantee gets it from its grant blob. The
op applies again through the standard rebase of "Sync core", in FIFO order before the later queued
ops, and the per-op rebase rules apply unchanged. A revoked or downgraded party holds no new write
seed, so its op does not apply again and takes the dead-letter path of "Sync core". Amended on
2026-10-03: that dead letter is not landed. Its kept op reads the old tree and leaves with no notice
(FSM1/cipher-box#2272). Amended on 2026-10-05: the dead letter landed.
Amended on 2026-10-08: when the bookmark holds the scope pointer name, the drain first reads the moved tree under the pointer read key, and a kept op whose own result the tree shows, or a kept delete whose node the tree lacks, leaves with no notice.

Amended on 2026-10-03: the owner ruled the three Residuals: the kept op, T = 7 days, and an
amendment of this ADR in place. D4 to D7 record the rulings. Each sentence that starts with
"Proposed" is not a ruling and waits for the owner.

**D4 — A kept op stays queued after its publish, and a note records it.** The drain writes the note
before the published-op mark rises (`Drain::keep_published`), into one bookkeeping record of the
identity (`sync::kept_op`). The note holds the write epoch of the op's write scope and the time of
the publish. Proposed: the note also holds the scope root, so the record seals as the owner-local
`kept-ops` kind, and an op with a note and no mark is a kept op, so a crash between the two writes
keeps the op. The previous release removes a queued op at or below the mark as published, and its
orphan sweep deletes the note record. Thus a downgrade drops a kept op as that release did, and no
migration step is necessary (ADR 0020 D3). Amended on 2026-10-06 (owner ruling on
FSM1/cipher-box#2285, option B): the note is format version 2. It also holds the folder the op
wrote under and, for a kind whose live node alone cannot show that it landed, the value before and
after the op. A version 1 note reads with neither. A release that reads only version 1 reads a
version 2 note as no notes, so each of its kept ops gets one check (D6).

**D5 — A kept op waits at its write epoch for T = 7 days, the bound of ADR 0065 D3.** The live
write epoch is the write-epoch floor of the op's scope on this device. While the floor equals the
epoch of the note, the op stays, and after T it leaves the queue and its staged blocks release. A
higher floor sends the op to D3 at any time, and a kept delete to the read of its folder (D6).
Time enters through the clock seam. Proposed: a
note time later than the clock reads as the clock. A nearest scope root other than the note's is
also a flip, and a flip waits for its check with no limit, as a flip at T would lose the write.

**D6 — The test "visible from the live root" is the standard rebase onto the live tree.** An op that
the rebase reads as already satisfied leaves the queue. A kept op with no note gets a note at write
epoch 0 when the drain first sees it, so it gets one check, and T runs from that sight. Consequences
of this test, not rulings: the check runs only when the base read the node that the op writes under
at its name of the live write seed, because a stale base shows the old tree and the op as satisfied.
A content edit landed when its file's live history names its version, because a later edit moves the
head. A kept delete whose node the base does not hold leaves at T. Amended on 2026-10-06 (owner
ruling on FSM1/cipher-box#2336, option 3): at a flip, a kept delete whose note names its folder
waits for one read of that folder at its live name, which the drain makes itself. A live node
applies the delete again, and a node that is gone ends the op with no notice. A folder that its old
parent no longer names took the node with it, so the op ends too, at once when a read of this
session at the live parent name shows the old parent no longer names the folder. A base that does not hold the folder shows
nothing, so with no such read the op waits for a pass that reads the folder, or leaves at T. A kept
delete under a scope that this device can no longer write leaves with no notice when the pointer read of D3 shows its node gone, and otherwise takes the keyless charge of D3 and
dead-letters with a notice, as a kept create and a kept edit do, also when the base does not hold
its folder. Proposed: a kept
op that this device edits again leaves with no check, because the later op sets what the node shows. Amended on 2026-10-07: a later delete of this device expires every earlier op on its node once a flip shows, a later bin restore cancels that delete so the earlier ops stay, and no other later op expires an earlier op. A second
apply that cannot land leaves with no retire and no notice, because its version landed once.

**D7 — A kept op is not pending.** The pending-op overlay, the pending flags, the staged-content
read, the cold-start data path and the second-end choice of a pass skip a kept op, because its
version is live. A kept op that crosses a scope and waits for its check still holds the second end.
Only the drain reads a kept op again, and the cancel command refuses it.

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

1. `blueprint/engine.md` "Sync core", the "Ops" bullet, states D2 to D7: the kept kinds, the
   check at a new write epoch, and the second apply through the rebase.
2. `blueprint/engine.md` "rotateScopeWrite" adds one sentence after the gated-read sentence:
   the writer carries such a write (D1). "Residuals" states that the late write of a revoked
   writer dead-letters on its own device. Amended on 2026-10-03: until that dead letter lands
   (FSM1/cipher-box#2272), "Residuals" states that the kept op of a revoked writer leaves its
   queue with no notice. Amended on 2026-10-05: the dead letter landed.
3. `CONTEXT.md` "Op queue" states that a published op stays until it is visible from the live
   root, and "Name wave" states that the writer carries a write that lands after the walk.
   Amended on 2026-10-03: "Op queue" names the kept kinds, and "Pending-op overlay" states that
   a kept op is not pending (D7).
4. `blueprint/testing.md` "crates/engine — seam fakes and the simulation harness" adds the
   probe of `InMemoryRecordStore::seed_record_after_put`: after the writer's next pass, the new
   tree names the new child at its new name and the child opens there, and the op of a revoked
   writer dead-letters. Amended on 2026-10-03: the probe serves the walk the record from before
   the write, for each kept kind. The revoked-writer half waits for that dead letter
   (FSM1/cipher-box#2272). Amended on 2026-10-05: the dead letter landed. D5 and D6 each have a
   test, and each kind that is not kept has a test that a later writer's change stays.
5. `blueprint/core.md` "Owner-local seals" adds the `kept-ops` kind (D4).
