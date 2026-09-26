# ADR 0045 — A queued op journals its crossing as a plan, and the drain decides

- **Status:** Accepted on 2026-09-26 — retroactive; the rule shipped in FSM1/cipher-box#878,
  FSM1/cipher-box#897, FSM1/cipher-box#1123, FSM1/cipher-box#1679, FSM1/cipher-box#1747,
  FSM1/cipher-box#1765, FSM1/cipher-box#1828 and FSM1/cipher-box#2002, and the blueprint
  carries it, except D5 and D6, where this ADR corrects the blueprint text; the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-26
- **Relates to:**
  [#33](https://github.com/FSM1/cipher-box-next/issues/33) D5 (merge is op-rebase; the per-op
  rules), D6 (offline is the same machinery, durable; the dead letter) and D7 (replay rebases
  only onto gate-passing state), which this ADR extends,
  [#26](https://github.com/FSM1/cipher-box-next/issues/26) D1 and D7 (a cross-scope relink
  re-seals at the destination epoch; a scope exit cuts the source),
  [ADR 0020](./0020-the-durable-op-queue-reads-the-previous-release.md)
  (the durable op queue reads the previous release; Consequence 4, the retained record),
  [ADR 0019](./0019-file-version-retention-is-count-based-keep-latest-n.md)
  (count-based version retention, which moves a version count backwards),
  the resolutions of FSM1/cipher-box#830 and FSM1/cipher-box#832 on the write-plane map
  FSM1/cipher-box#813, the owner decision of 2026-09-18 on FSM1/cipher-box#1735, the
  `blueprint/engine.md` "Sync core" section (the state law, the "Ops" bullet, the per-op rebase
  table and the dead-letter paragraph), the `blueprint/desktop.md` "Reads, writes, and the
  never-block law" section, and the `CONTEXT.md` "Cross-scope move", "Pending-op overlay",
  "Op queue", "Op record", "Owner tag", "Retained record" and "Dead-letter" terms
- **Implemented by:** FSM1/cipher-box#878 (the owner-tagged op record, `authored_at`, the
  retained class; D3, D4, D5), FSM1/cipher-box#897 (the `move` op; D6),
  FSM1/cipher-box#1123 (the conditional edit; D7), FSM1/cipher-box#1679 (journal-time
  classification, the three-scope dead letter and the drain's crossing arm; D1, D2),
  FSM1/cipher-box#1747 (the dead-letter notice; D8), FSM1/cipher-box#1765 (the two-leg
  relocation between two interior scopes; D6), FSM1/cipher-box#1828 (the crossing-plan
  sentence in `blueprint/engine.md` and its test; D1) and FSM1/cipher-box#2002 (the
  crossing-plan sentence in `CONTEXT.md`; D1).

## Context

Thread `#33` fixed the sync model in two decisions. D5 makes every mutation an intent op that
carries its base sequence, and a lost CAS race re-applies the op onto fresh remote state. D6
makes the op queue durable on both platforms and covers every mutation; an op that cannot
rebase dead-letters with its staged bytes preserved. The thread named five op kinds and one
rebase rule per race. It did not say what one durable queue entry holds, who may read it, what
the overlay shows before the entry publishes, or which part of an entry the drain trusts.

The build answered those questions one slice at a time.

**The queue is shared with other identities.** The staging store is named per origin, not per
account, so two accounts on one browser profile share one queue. Before FSM1/cipher-box#832,
the queue was plaintext JSON with no owner, and the root node id was the same constant for
every account. A second account's first login could therefore replay the first account's
"new file in my root" into its own vault. The cold-start path also removed every record it
could not decode, which FSM1/cipher-box#768 had asked for so that a corrupt entry is not
re-emitted at each boot. A seal alone makes a foreign record fail to open, so a seal checked
before the owner would make the second login delete the first account's whole queue.
FSM1/cipher-box#878 landed the resolution: an owner tag in a clear header, a sealed body, and
a tag check before any open.

**The overlay had nothing to show for a pending write.** An `UpdateContent` op carried no size
and no time. A file the member just uploaded rendered with no size until something downloaded
it. FSM1/cipher-box#830 put `authored_at` on the op envelope, for publish determinism first: an
`Unconfirmed` publish retries at the same sequence, and a clock read at publish would author
different bytes at one sequence.

**One kernel rename was three ops.** The FUSE operation core spelled a replacing rename as
`Delete` the destination, `Relink`, then `Rename`, with a fallible journal step between each.
A failure after the `Delete` left the destination gone and the source not moved, while the
caller was told that nothing happened (FSM1/cipher-box#884). FSM1/cipher-box#897 added one
combined `move` op.

**An edit could supersede a version it never saw.** Two devices that edited one file each
published a new head, and no read path reaches a non-head version. The loser's bytes became
unreachable with no notice. FSM1/cipher-box#1123 added the edit-vs-edit row.

**A crossing classified at journal time can be wrong.** `classify_crossing`
(`crates/engine/src/facade.rs`) resolves both ends of a relocation against the scope roots the
session has proved. That set is in memory and is empty until the first boundary walk returns.
Before then every relocation classifies as intra-scope, and the overlay can place a queued
create under a granted scope root (FSM1/cipher-box#1735). FSM1/cipher-box#1679 and
FSM1/cipher-box#1672 already made the drain derive the crossing from the two planes its own
pass proved (`publish_ref_move` in `crates/engine/src/sync/drain.rs`), re-seal through
`reseal_into`, and owe the source cut from the same pair (`commit_crossing`).
FSM1/cipher-box#1755 made the owed cut durable across a restart. So the published result is
correct either way, and the journaled crossing field can name a boundary that the journaling
session had not proved. The owner chose on 2026-09-18 to record that shape as the rule.

**The preserved set evicts oldest-first.** A dead letter that staged a version keeps its op
record in the preserved set, because that record holds the only copy of the version's content
key. A dead letter that staged nothing took a slot too, or left nothing a restart could read
(FSM1/cipher-box#1747).

The blueprint carries every rule below in `blueprint/engine.md` "Sync core" and the rename law
in `blueprint/desktop.md` "Reads, writes, and the never-block law". Two properties of the
queue are already decided elsewhere and are not restated here: the queue is per device and is
shared with whatever build wrote it, and a record at a format version or an intent grammar this
build does not implement is retained
([ADR 0020](./0020-the-durable-op-queue-reads-the-previous-release.md)
Consequence 4).

## Decision

**D1 — The journaled crossing is a plan, and the drain is the authority.** The crossing field
of a queued relocation records what the journaling session knew. The drain does not read it to
decide what to publish. The drain re-derives the crossing from the two planes that its own pass
proved, and it owes the source cut from that pair. The drain reads the field only to refuse: a
relocation journaled as a crossing does not publish as a plain relink when the pass holds no
second end or when the two proved planes are one scope (`publish_ref_move` in
`crates/engine/src/sync/drain.rs`). So a boundary that the journaling session
had not yet proved still re-seals the moved subtree at the destination scope's epoch and cuts
the scope it left. Durable proved scope roots per account are not kept. The owner decided this
rule on 2026-09-18 in FSM1/cipher-box#1735 (option A). FSM1/cipher-box#1828 wrote it into
`blueprint/engine.md` and the `classify_crossing` doc, and FSM1/cipher-box#2002 wrote it into
the `CONTEXT.md` "Cross-scope move" entry.

**D2 — A crossing is classified once, at journal time, and replay dead-letters a relocation
that now names three scopes.** When the command journals a `relink` or a `move`, the engine
classifies the crossing once, from both ends, against the boundaries the session has proved.
An intra-scope `relink` is a pure relink. A cross-scope `relink` re-seals the moved subtree at
the destination scope's epoch, and one that leaves a granted source scope is a scope-exit
rotation trigger for the source (`#26` D1 and D7). At replay, the engine re-derives both ends
against the boundaries the session has proved. One drain pass anchors on one scope and carries
one interior end, so it cannot author a relocation that now names three scopes. Replay
dead-letters such a relocation. The rule landed with FSM1/cipher-box#1679; this ADR records
it.

**D3 — A record that bears another identity's owner tag is retained, and the tag check runs
before the decode.** Each op record carries the owner tag in a clear header. The tag is the
owner's `enc-subkey` public half, verbatim. The engine compares it byte for byte with the live
session's tag before it opens or decodes the body. A record with another identity's tag is
retained: never replayed, never surfaced, never removed, and its staged bytes stay pinned. A
check after the decode is forbidden, because the decode failure path removes the record. The
owner decided this on 2026-07-28 in the resolution of FSM1/cipher-box#832, a map
FSM1/cipher-box#813 ticket, and FSM1/cipher-box#878 landed it.

**D4 — Only a record that fails to decode at all is dead-lettered and removed.** A record whose
header does not read, whose tag is this session's but whose seal does not open, or whose clear
content root disagrees with the root in its opened body, is undecodable
(`RecordReader::classify` in `crates/engine/src/sync/record.rs`). The engine surfaces it as a dead letter with the reason `Undecodable` and removes
it from the durable queue, so the next boot does not surface it again. An undecodable record
never authorizes the deletion of the blocks its clear header names. The rule landed with
FSM1/cipher-box#878, after FSM1/cipher-box#768 asked for it; this ADR records it.

**D5 — The overlay stamps `mtime = authored_at` on exactly the nodes whose records the drain
publishes, and a content op also stamps its plaintext size.** Each op carries `authored_at`,
the time the engine read from its injected clock when it journaled the op. The pending-op
overlay writes `authored_at` onto the `mtime` of exactly the set of nodes whose records the
drain will publish for that op:

- `create` stamps the new node and its parent.
- `rename` and `delete` stamp the parent. The child's own record does not change; only its
  child ref does.
- `relink` stamps both parents.
- `updateContent` stamps the node alone.

The stamp overwrites the projected time; it does not fill only an absent value. A content op
also stamps the plaintext size of its version. One function gives the authored-node set, and
both the overlay and the drain's publish plan call it, so a rendered node and the record that
publishes it agree. This is the set that the owner decided on 2026-07-28 in section 3 of the
resolution of FSM1/cipher-box#830, a map FSM1/cipher-box#813 ticket.

The blueprint states a different set today: "Every op but a delete authors its target's next
record, so the overlay stamps `mtime = authored_at`" (`blueprint/engine.md` "Sync core", the
state-law bullet). That target-only form first appeared in the body of FSM1/cipher-box#878,
which an agent wrote, and no owner decision stands behind it. It contradicts the resolution of
FSM1/cipher-box#830. This ADR proposes the FSM1/cipher-box#830 set as the rule, for the owner
to accept. The code does not meet it yet (E3).

**D6 — A `move` is a relink and a rename in one entry, and one kernel rename is one
command.** The intent op list of `#33` D5 gains `move`. A `move` carries the relink, the rename
and, optionally, the node already at the destination name that it vacates. At rebase, the move
vacates the destination node only while that node still holds the contested name. One kernel
rename is one command. A relocation between two interior scopes journals as a parking leg and
an arriving leg, and both legs are journaled or neither is. The parking leg is a `relink` out of
the source scope into the vault-root scope; it leaves the granted source, so it carries the cut
that the whole relocation owes. The arriving leg is the op the caller asked for, from the vault
root into the destination scope, and it re-seals the subtree and cuts nothing. Every other
relocation journals as one entry. A replace is never observable half-done.

The single `move` landed with FSM1/cipher-box#897. The two-leg plan landed with
FSM1/cipher-box#1765, which an agent wrote and which says that no blueprint sentence changes.
No owner decision exists for either. The blueprint says "one POSIX rename is exactly one
`move`" (`blueprint/engine.md` "Ops") and "exactly one facade intent op" (`blueprint/desktop.md`
"Reads, writes, and the never-block law"), which the two-leg plan does not meet. The owner
accepts the rule above with this ADR.

**D7 — A conditional edit anchors on the head version and dead-letters on a mismatch.** The
intent op list of `#33` D5 gains an edit-vs-edit rule. An edit names the head version it was
formed against. The engine takes that version when the write handle opens, not at the commit.
If the head is not that version at rebase time or at publish time, another writer published
it, so the edit dead-letters with its staged version preserved. It does not supersede the other
version. The anchor is an identity, never a count, because a queued predecessor and a
concurrent writer advance a count alike. A device that holds no head for the target resolves
one at `beginWrite` and does not write unanchored. The rule landed with FSM1/cipher-box#1123;
this ADR records it.

**D8 — The dead-letter notice and the custody of a content key use separate carriers.** The
preserved set evicts oldest-first. An op that staged a version parks its op record in the
preserved set, because that record carries the version's content key. An op that staged no
version takes a per-owner notice of its id and its reason. The notice costs no preserved slot
and holds no record bytes. A cold start reads both carriers back, so every dead letter is
nameable and discardable after a restart. `#33` D6 decides that a dead letter keeps its staged
bytes and a visible notice; the carrier split landed with FSM1/cipher-box#1747, and this ADR
records it.

## Rationale

- **The drain proves what it publishes.** D1 puts the crossing decision where the planes are
  proved: in the pass that seals under them. A journaled field is what the member's session
  knew when it acted. The session can know less than the network, but the drain's pass reads
  the network. So a crossing that the journaling session missed still re-seals and still cuts.
- **A crossing that the journaling session missed has no observable effect.** No member and no
  attacker can see the difference between a correct journaled crossing and one that the
  session classified as intra-scope before it proved the boundary, because the drain publishes
  the same records either way. D1 costs nothing today.
- **A debt follows the publish, not the queue.** Deriving the owed cut from the journaled field
  would cut a source scope for an op that the FIFO never reached, once per tick while the head
  stalls (FSM1/cipher-box#1679).
- **A three-scope relocation fails early and visibly.** No later tick makes such a relocation
  authorable, so D2 charges it and dead-letters it at replay. It does not hold the FIFO head.
- **"Is this mine?" and "can I open this?" are one question.** The owner tag of D3 names the key
  that opens the body. Checking it first makes a foreign record invisible, and it keeps the
  removal path of D4 for this identity's records only.
- **Retention protects offline work.** A second account's login, or a newer build, must not
  destroy an unpublished queue. The only records the engine removes are ones it can prove are
  its own and unreadable.
- **An undecodable record does not return at each boot.** D4 removes it once and names it once.
  A planted record that bears the owner's public tag cannot delete a real version's blocks.
- **A time on the op makes publish deterministic.** A retried publish at the same sequence
  authors the same bytes. The overlay shows the time and size that the record will carry, so
  the view does not jump at publish (D5).
- **The stamped set follows the records, and it is the POSIX set.** A rename changes the mtime
  of the directory, not of the file. The FSM1/cipher-box#830 set stamps the parent folders that
  the drain republishes, so a folder's mtime does not jump at publish for a reason the view never
  showed (D5).
- **One command per rename removes the loss window.** D6 makes the kernel ack mean that the
  whole rename is journaled. There is no state in which the destination is gone and the source
  did not move.
- **Two legs are the only shape one pass can publish.** One pass carries one interior end beside
  its vault-root anchor. Each leg of D6 has the vault root at one end, so each leg is an existing,
  charged, fail-closed crossing. The source is cut exactly once, by the leg that left it. Parking
  in the vault-root scope narrows and never widens: that scope is the owner's alone
  (FSM1/cipher-box#1765).
- **The loser of an edit race stops, and nothing is lost.** No read path reaches a non-head
  version, so "last writer wins" destroys the loser. D7 keeps the loser's version preserved
  and visible as a dead letter.
- **A notice does not evict a key.** D8 keeps the preserved set for records that carry the only
  copy of a content key, so a burst of versionless dead letters cannot evict a parked write.

## Alternatives rejected

**(a) Durable proved scope roots per account (option 1 of FSM1/cipher-box#1735).** A session
would start with the boundaries the last session proved, which narrows the misclassification
window to a first run on a device. It adds durable per-account state that a second device must
read, and a stale entry becomes a boundary that a session believes without proof. It is only
worth its cost if a later change makes the journaled crossing authoritative somewhere. Rejected
by the owner on 2026-09-18.

**(b) Refuse a relocation until the first boundary walk returns.** Named as an option on
FSM1/cipher-box#1735 in the body check of 2026-09-05. It refuses honest moves during every cold
start, and D1 already publishes the correct result without it.

**(c) Derive the scope-exit debt from the journaled crossing.** Rejected in
FSM1/cipher-box#1679: a stalled head would owe a cut at each tick for an op the FIFO never
reached.

**(d) A per-account store namespace instead of an owner tag.** Rejected in
FSM1/cipher-box#832. The discipline would live in each host, outside the conformance kit, and a
host that passed a stale prefix would mix two queues with no signal.

**(e) Check the tag after the decode, or dead-letter a foreign record.** Rejected in
FSM1/cipher-box#832. The first makes a second login delete the first account's queue. The
second shows a member a permanent error about files that member never touched.

**(f) Keep an undecodable record in the queue.** The record would surface again at each boot
(FSM1/cipher-box#768), and no build can act on it.

**(g) Read the clock at publish, or fill the overlay's size and time only where the base has
none.** Rejected in FSM1/cipher-box#830. A clock read at publish forks a retried publish at one
sequence. A fill-only overlay shows the old size of a file the member just replaced.

**(h) Fold the written size and time into the base snapshot at `commitWrite`.** Rejected in
FSM1/cipher-box#830. It writes unpublished intent into gate-passing state, and the base cannot
remove it if the op later dead-letters.

**(i) Keep three ops per rename, or reorder them.** Rejected in FSM1/cipher-box#884. Three ops
keep the loss window. `Relink` and `Rename` before `Delete` lands an auto-suffixed name on the
success path, because the rebase suffixes a name collision.

**(j) Anchor an edit on the version count.** Rejected in FSM1/cipher-box#1123. A queued
predecessor and a concurrent writer advance a count alike, so a second queued edit passes the
guard. Count-based retention
([ADR 0019](./0019-file-version-retention-is-count-based-keep-latest-n.md))
also moves a count backwards.

**(k) Park every dead letter in the preserved set.** Rejected in FSM1/cipher-box#1747. A
versionless op would take a slot and could evict a record that holds a content key.

**(l) A pass that resolves three ends.** Shape 2 of FSM1/cipher-box#1765. It would publish a
relocation between two interior scopes as one op. It needs a new pass shape that carries two
interior ends, while the two legs of D6 reuse crossings the drain already authors and charges.
Its gain is that the subtree publishes once, not twice.

## Consequences

1. **`blueprint/engine.md` already carries D1 to D4, D7 and D8.** The "Ops" bullet carries D1,
   D2, D3 and D4. The per-op rebase table's "Edit vs edit" row carries D7. The dead-letter
   paragraph after the table carries D8. No text change is needed for these.

2. **`blueprint/engine.md` "Sync core" changes for D5 when this ADR is accepted.** The
   state-law sentence "Every op but a delete authors its target's next record, so the overlay
   stamps `mtime = authored_at`" is reworded to the FSM1/cipher-box#830 set of D5: `create`
   stamps the new node and its parent, `rename` and `delete` stamp the parent, `relink` stamps
   both parents, and `updateContent` stamps the node alone, through one function that the
   overlay and the drain's publish plan both call.

3. **`blueprint/engine.md` "Ops" and `blueprint/desktop.md` change for D6 when this ADR is
   accepted.** The "Ops" sentence "one POSIX rename is exactly one `move`, so the whole
   operation is journaled or none of it is" is reworded to: one kernel rename is one command; a
   relocation between two interior scopes journals as a parking leg and an arriving leg, and both
   legs are journaled or neither is. `blueprint/desktop.md` "Reads, writes, and the never-block
   law", lines 185 to 188 ("becomes exactly one facade intent op" and "A kernel rename is one
   `move`"), takes the same reword.

4. **`CONTEXT.md` already carries D1, D3 and D4.** The "Cross-scope move" entry carries D1 and
   the journal-time classification of D2 (FSM1/cipher-box#2002). The "Op record", "Owner tag"
   and "Retained record" entries carry D3 and D4. No text change is needed.

5. **`#33` D5 and D6 now read with this ADR.** The D5 op list reads `create`, `delete`,
   `rename`, `relink`, `move`, `updateContent`, and its per-op rules gain the conditional edit
   of D7. The D6 dead letter keeps its staged bytes and its visible notice through the two
   carriers of D8. The state law of D6 and the replay rule of D7 do not change.

6. **ADR 0020 does not change.** Its Consequence 4 still governs a record at a format version or
   an intent grammar this build does not implement. D3 adds the foreign-tag case beside it, from
   its own source.

7. **Citations the blueprint gains.** `blueprint/engine.md` section "Sync core" gains the
   citation (ADR 0045) on the state-law bullet, on the "Ops" bullet after the sentence "The
   journaled crossing is a plan, never the authority", on the "Edit vs edit" row, and on the
   dead-letter paragraph. `blueprint/desktop.md` section "Reads, writes, and the never-block
   law" gains the citation (ADR 0045) on the rename sentence. `CONTEXT.md` gains the citation
   (ADR 0045) on the "Cross-scope move" and "Retained record" entries.

8. **The code must follow the reworded blueprint.** FSM1/cipher-box#2013 tracks moving the
   overlay and the drain onto the one authored-node set of D5 (E3). FSM1/cipher-box#2014 tracks
   journaling the two legs of D6 in one atomic write (E2).

9. **No wire format, no KDF edge and no op record format changes.**

## Residuals

**E1 — The journaled crossing can name a boundary the session had not proved.** Before the
first boundary walk returns, every relocation classifies as intra-scope, and the overlay can
place a queued create under a granted scope root. D1 makes the published result correct, and
no member and no attacker can observe the field. While the walk is still dark, the drain maps
the failed unseal to an uncharged halt, and the op waits at the queue head until the walk
proves the boundary. That is an availability cost, not a trust cost.

**E2 — The two legs of D6 are not journaled atomically.** `stage_legs_and_notify`
(`crates/engine/src/facade.rs`) journals the parking leg and the arriving leg in two
`enqueue_op` calls. If the arriving leg fails to journal, the command removes the parking leg
on a best-effort basis (`let _ = self.dequeue_op(op_id)`). That removal cannot undo a parking
leg that a tick already drained, and the code comment allows that case. The source is then cut,
the subtree sits in the vault-root scope, and the caller hears that the command failed. That is
a false failure that performed a scope exit, which D6 forbids. The fix is one atomic journal
write for both legs, which needs a multi-entry enqueue on the `StagingStore` seam, and a test
that fails the arriving leg's journal. FSM1/cipher-box#2014 tracks it.

**E3 — The overlay and the drain stamp different node sets.** D5 requires one authored-node
set that both call. In the code only the overlay calls `Op::stamp_authored`
(`crates/engine/src/sync/op.rs`), and it stamps the op's target alone. The drain reads
`applied.op.authored_at` at each authoring site in `crates/engine/src/sync/drain.rs` and in
`crates/engine/src/net/author.rs`. The two sets differ:

- For `rename`, `relink` and `move`, the overlay's `relocate` (`crates/engine/src/sync/overlay.rs`)
  stamps the renamed or relinked node. The drain's `publish_ref_move` never republishes that
  node's record; it publishes only the parent folders, with `modified_at = authored_at`. So the
  overlay stamps a node that the drain does not author, and it does not stamp the parents that
  the drain does author.
- For `create`, the drain's `publish_create` stamps the child and the parent, and the overlay
  stamps the child only. For `delete`, the drain republishes each parent at `authored_at`, and
  the overlay stamps nothing.

A folder's mtime therefore jumps at publish, which is what section 3 of the resolution of
FSM1/cipher-box#830 exists to prevent. FSM1/cipher-box#2013 tracks the fix. Also, the overlay does not stamp a `prune`, a
`restoreVersion` or a `deleteVersion`, although each authors its target's next record. The
drain keeps the existing `modified_at` for those three kinds (`publish_prune`,
`publish_restore_version` and `publish_delete_version` in `crates/engine/src/sync/drain.rs`), so
the overlay and the drain agree there. Those kinds are outside the six-op list of the
blueprint, and only its sentence "every op but a delete authors its target's next record"
reaches them.

**E4 — `authored_at` is a client-authored time.** A skewed or lying client publishes a skewed
`modified_at`, and no gate check catches it. The only reader is the owner's own view, so this
is not a trust boundary (FSM1/cipher-box#830).

**E5 — Ownership is in the clear, and a retained record can stay forever.** The owner tag tells
anyone with disk access that a given X25519 public key used this device. A corrupted tag is
byte-identical to another identity's tag, so a damaged record of this identity is retained, not
dead-lettered. A co-tenant of the store can copy, delete or reorder whole records; the seal
authenticates the author only. Retained records and their staged bytes stay until their own
identity drains them or a build that reads them runs.

**E6 — An undecodable record loses its write.** The content key of a staged version is inside
the sealed body. A record whose body no longer opens cannot park its version, so D4 names the
op and removes it, and the version is lost. A co-tenant who plants a record with this owner's
public tag causes one `Undecodable` dead letter and nothing more.

**E7 — A grant minted after a move was queued can dead-letter it.** D2 re-derives both ends at
replay. A move that was authorable when the member made it dead-letters if a later grant makes
it name three scopes. The member must do the move again.

**E8 — Another device can see a two-leg relocation parked.** The drain publishes one leg of D6
per tick. The member's own view applies both legs from the moment they are journaled, but
another device that polls between the two ticks sees the subtree in the vault-root scope. The
parked state is in the owner's own scope, so no grantee reads more than before, and it lasts
until the arriving leg publishes. FSM1/cipher-box#1765 names this cost on purpose.

## Gate

- **D1:** `a_move_journaled_before_any_walk_verdict_re_seals_and_cuts_at_the_drain`
  (`crates/engine/tests/owner_actions.rs`) journals a move out of a granted root as intra-scope
  in a session with no walk verdict, then proves that the drain re-seals at the destination and
  cuts the source.
- **D2:** `a_move_out_of_a_granted_folder_journals_the_crossing_it_makes`
  (`crates/engine/tests/owner_actions.rs`),
  `a_relocation_that_crosses_a_scope_boundary_is_classified_from_either_side`
  (`crates/engine/src/facade.rs`) and
  `a_relocation_the_grants_moved_onto_three_scopes_dead_letters`
  (`crates/engine/src/sync/rebase.rs`).
- **D3:** `a_foreign_record_is_retained_rather_than_undecodable`
  (`crates/engine/src/sync/record.rs`), `decode_queue_leaves_another_accounts_records_invisible`
  (`crates/engine/src/sync/rebase.rs`),
  `another_accounts_queued_record_is_invisible_and_survives_cold_start` and
  `a_foreign_queue_entry_is_invisible_but_counted` (`crates/engine/src/facade.rs`), and
  `a_foreign_records_whole_block_set_is_never_collected` (`crates/engine/src/sync/staging.rs`).
- **D4:** `undecodable_queue_entry_surfaces_as_dead_letter_on_cold_start`
  (`crates/engine/src/facade.rs`), `garbage_bytes_are_undecodable_not_foreign` and
  `a_record_bearing_our_tag_but_a_tampered_body_is_undecodable`
  (`crates/engine/src/sync/record.rs`), `decode_queue_dead_letters_corrupt_entries`
  (`crates/engine/src/sync/rebase.rs`), and
  `an_undecodable_record_never_authorizes_deleting_the_blocks_its_header_names`
  (`crates/engine/tests/write_plane.rs`).
- **D5:** `a_content_op_stamps_its_authored_time_and_plaintext_size` and
  `a_metadata_op_stamps_time_over_a_projection_and_leaves_size_alone`
  (`crates/engine/src/sync/op.rs`), and `a_new_child_stamps_the_journaled_time_not_a_clock`
  (`crates/engine/src/net/author.rs`) cover the stamp on one node. **Finding:** no test proves
  that the overlay and the drain's publish plan stamp the same set of nodes, and no test
  enumerates the op kinds, which the resolution of FSM1/cipher-box#830 asked for. The code does
  not meet the D5 set today (E3, FSM1/cipher-box#2013).
- **D6:** `a_durable_queue_outage_never_destroys_the_destination_a_rename_did_not_replace` and
  `replacing_a_junk_holding_folder_keeps_the_destination_entry_when_the_queue_fails`
  (`crates/fuse/tests/fuse_op_core.rs`), `overlay_move_relinks_renames_and_replaces_in_one_step`
  (`crates/engine/src/sync/overlay.rs`), `a_move_that_replaces_lands_under_the_entered_name`
  (`crates/engine/src/sync/rebase.rs`), and
  `a_replacing_rename_lands_the_vacated_and_moved_refs_in_one_record`
  (`crates/engine/tests/write_plane.rs`) cover the single `move`.
  `a_relocation_between_two_shared_folders_is_staged_through_the_vault_root`
  (`crates/engine/src/facade.rs`), and
  `a_move_between_two_granted_folders_re_seals_into_the_destination_scope`,
  `a_restart_between_the_legs_of_a_staged_move_cuts_the_source_once` and
  `the_passes_that_cannot_author_a_staged_move_do_not_spend_it`
  (`crates/engine/tests/owner_actions.rs`) cover the two legs. **Finding:** no test covers a
  two-leg relocation whose arriving leg fails to journal (E2, FSM1/cipher-box#2014).
- **D7:** `conditional_edit_dead_letters_when_another_writer_took_the_head` and
  `a_second_queued_edit_dead_letters_behind_a_superseded_first`
  (`crates/engine/src/sync/rebase.rs`), and
  `a_second_queued_edit_does_not_slip_past_the_writer_that_beat_the_first`,
  `an_edit_anchors_on_the_version_its_handle_opened_on` and
  `an_edit_from_a_device_that_never_read_the_file_resolves_its_anchor`
  (`crates/engine/tests/write_plane.rs`).
- **D8:** `a_versionless_dead_letter_takes_a_notice_and_no_preserved_slot` and
  `notices_never_evict_a_record_that_carries_a_content_key`
  (`crates/engine/src/sync/staging.rs`), and
  `a_versionless_dead_letter_is_named_again_after_a_cold_start` and
  `discarding_a_noticed_dead_letter_clears_it_across_the_next_restart`
  (`crates/engine/tests/write_plane.rs`).

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
