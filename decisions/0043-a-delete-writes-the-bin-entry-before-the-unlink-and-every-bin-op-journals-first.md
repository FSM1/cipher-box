# ADR 0043 — A delete writes the bin entry before the unlink, and every bin op journals first

- **Status:** Accepted on 2026-09-26 — retroactive; the rule shipped in FSM1/cipher-box#1618,
  FSM1/cipher-box#1621, FSM1/cipher-box#1623, FSM1/cipher-box#1658 and FSM1/cipher-box#1747, and
  the blueprint carries it; the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-26
- **Relates to:**
  [ADR 0010](./0010-recycle-bin-is-an-owner-sealed-index.md)
  items 2 to 7, of which this ADR amends item 3 (which soft deletes re-key) and item 4 (the key a
  restore uses),
  [ADR 0031](./0031-the-bin-index-seals-symmetrically-under-a-login-secret-key-and-exists-from-genesis.md)
  D4 (the bin-held key), D8 (only an established index feeds a rewrite), D9 (a charged verdict
  against an uncharged hold) and D10 (`StrandedMint`), which this ADR cites and does not restate,
  [ADR 0013](./0013-a-lapsed-bin-index-record-is-rewritten-not-refused.md)
  (a lapsed bin index record establishes the index),
  [ADR 0011](./0011-quarantine-release-rests-on-the-doomed-manifest.md)
  D5 (a proof that does not hold costs a leak, never a loss),
  [ADR 0012](./0012-the-drain-carries-the-write-wave-forward.md)
  D6 (a strict-FIFO stall with no dead letter is a liveness defect),
  [ADR 0019](./0019-file-version-retention-is-count-based-keep-latest-n.md)
  consequence 4 (a destructive retention acts only on a member choice),
  [ADR 0034](./0034-a-degraded-settings-load-falls-back-to-the-last-verified-copy-and-never-widens-placement.md)
  D2 (a degraded settings load prefers the verified last-known-good copy),
  [#33](https://github.com/FSM1/cipher-box-next/issues/33) D5 (every mutation is an intent op with
  a base sequence, and a delete is conditional) and D6 (the durable op queue, replayed FIFO), the
  `blueprint/engine.md` sections "Bin index record", "Delete branch", "Re-key into the bin",
  "Owner capture" and "Restore, purge, and expiry", the `blueprint/core.md` section "Bin index",
  and the `CONTEXT.md` terms "Soft delete", "Bin entry", "Bin-held key", "Restore", "Purge", "Bin
  expiry" and "Owner capture"
- **Implemented by:** FSM1/cipher-box#1618 (the delete branch, the journaled verdict, the entry
  order, the degraded-load branch and the scope-root rule), FSM1/cipher-box#1621 (the re-key into
  the bin and owner capture), FSM1/cipher-box#1623 (restore, purge and expiry),
  FSM1/cipher-box#1658 (the unlink of every link, the exits of the bin plane and the one load per
  pass) and FSM1/cipher-box#1747 (the unlink across scopes and `targetLinkedAcrossScopes`)

## Context

ADR 0010 decided what the recycle bin is: one owner-sealed, vault-level index, a `Delete` command
that branches on the owner's retention setting, a re-key that cuts access, owner capture of a
grantee's unlink, expiry on the poll tick, and a purge that owes its roots to the retire ledger.
It did not decide the order of the steps, what a partial pass leaves, or how each step fails.
ADR 0031 decided the bytes of the bin index record and how a load establishes it. The five PRs
that built the flow under FSM1/cipher-box#1399 made each of the remaining choices. Most of them
answer one question: what does a pass leave when it stops part-way?

**A delete is three publishes, not one.** A soft delete writes a bin entry, re-seals the doomed
subtree, and republishes every parent that names the node. Each is a separate record on the
network. The drain is strict FIFO and retries the op whole, so every order leaves some residue
when a pass stops between two steps. FSM1/cipher-box#1618 compared the two residues. A node that
is binned and still linked is visible, and the retry settles it. A node that no folder names and
no bin entry finds is lost: the entry's `ipnsName` is the only route back to it.

**ADR 0010 item 3 let an unshared scope skip the re-key.** FSM1/cipher-box#1621 found that the
drain cannot apply that rule. The drain carries the read and write seeds of a scope, not its grant
ledger, so it cannot tell a scope with live or historical grants from one without. A wrong
"unshared" verdict leaves a node open to a revoked grantee permanently, because key regression hands
that grantee every older epoch, and a binned node takes no ordinary write, so no lazy wave ever
reaches it.

**ADR 0010 item 4 gave an unshared restore a fresh key.** FSM1/cipher-box#1623 runs the re-key in
reverse through the same walk as the delete. The destination scope's current epoch key is already
a key the bin-held key does not derive, so a second mechanism would only be a second place for
the two paths to drift.

**A node can have more than one link.** Before FSM1/cipher-box#1658, the delete took the winning
link only. A second folder then named a record that its readers could no longer open, and a later
purge retired the name and unpinned the content behind a link the member still saw. Expiry queues
that purge with no owner command. FSM1/cipher-box#1747 extended the fix to a link in the second
end of a pass.

**The bin plane can hold the queue head.** A soft delete that cannot establish the bin index holds
the head of the whole op queue. Before FSM1/cipher-box#1658, a withheld record stalled the queue
in silence, and a full bin spent its attempt budget on a codec error that named no cause
(FSM1/cipher-box#1616). A binned subtree joins no eager set, so a rotation can leave it sealed at
an epoch the adoption gate refuses permanently, and a restore or purge that reads it would
retry with no end (FSM1/cipher-box#1623).

**A purge destroys, and expiry runs with no owner command.** An entry alone does not prove that
the node is unlinked: a soft delete whose parent publish spends its attempt budget leaves the
entry standing for a node the member still sees. A settings load that carries no member choice
takes the documented default retention, which is the right default for binning and the wrong
one for destroying.

`blueprint/engine.md` carries every rule below today, in the sections "Delete branch", "Re-key
into the bin", "Owner capture" and "Restore, purge, and expiry", and in the last three bullets of
"Bin index record". No owner decision records any of them. ADR 0010, ADR 0011 D5, ADR 0012 D6
and ADR 0019 give the principles only.

## Decision

**D1 — One `Delete` command branches on `binRetentionDays`, and the op journals the verdict.** The
facade reads the retention that this session's settings load gave, and it journals the branch on
the op as `to_bin`. A settings save between the queue and the drain therefore cannot change what
an already-queued delete does. Retention `0` keeps the hard delete, with the doomed manifest, the
quarantine and the reclamation. Retention above `0` makes the delete soft: the drain adds one bin
entry, re-keys the subtree (D5) and unlinks the node. It enumerates and journals no doomed manifest,
and it retires and unpins nothing, so the node's record still resolves and its content stays
pinned. The entry's `deletedAt` is the op's `authoredAt`, the one clock read the facade takes for
the command, so every replay of the op writes the same value. A grantee's delete only unlinks;
the owner's engine bins the node by owner capture (D6). The branch itself is ADR 0010 item 2; the
journaled verdict landed with FSM1/cipher-box#1618, and this ADR records it.

**D2 — The bin entry lands before the unlink.** On an authored soft delete the order is: the bin
entry, then the re-key, then the unlink of every parent. A pass that stops between the entry and
the unlink leaves a node that is both binned and still linked, and the retry settles it. The
reverse order leaves a node that no folder names and no bin entry finds. The retry is idempotent.
An encode refuses a duplicate node id, so an entry that already landed publishes nothing, and the
retry reads the standing entry's own `deletedAt`, so the re-key reaches the same bin-held key
(ADR 0031 D4). The rule landed with FSM1/cipher-box#1618 and FSM1/cipher-box#1621; this ADR
records it.

**D3 — A settings load that carries no member choice takes the soft branch.** When the session has
no settings summary, or its load fell to the documented defaults, the delete takes the default
retention, which is above `0`. A last-known-good copy (ADR 0034 D2) is still the member's choice,
and it still decides the branch. The two errors are not equal: a soft delete reclaims nothing and
stays reversible, and a hard delete that the owner did not ask for destroys the node. The rule
landed with FSM1/cipher-box#1618; this ADR records it.

**D4 — A child that is a scope root stays a hard delete.** Such a child publishes under a name
that the source scope's write seed does not derive. Its subtree is sealed under the seed of its
own scope, which a grantee of that scope holds. A bin entry and a re-key cannot cut that grantee;
a rotation of that scope does. The drain therefore takes the hard branch for it, whatever the
journaled verdict. The rule landed with FSM1/cipher-box#1618; this ADR records it.

**D5 — Every soft delete re-keys the whole subtree into the bin before the unlink, shared scope or
not.** Every node of the doomed subtree is re-sealed under the bin-held key before the unlink
publishes. This re-key is the access cut: key regression gives a current or revoked grantee every
older epoch of the scope seed, so only a key outside the scope's derivation stops them.

- Names, signers and the scope id that the AAD binds do not move. Only the read key moves, so the
  entry's `ipnsName` stays the route back and the write plane does not change.
- The whole subtree re-keys in the pass that bins it. A binned node takes no ordinary write, so no
  lazy wave would carry it.
- A descendant scope root is a boundary of the walk, not a member of it.
- A re-key that does not land leaves the node linked. The unlink publishes after the re-key, so
  the delete retries whole.

The drain carries no grant ledger, so it re-keys every soft delete. This replaces the ADR 0010
item 3 rule that an unshared scope skips the re-key. The rule landed with FSM1/cipher-box#1621;
its PR body gives the reason, and no owner decision records the change. This ADR records it, and
the owner accepts the amendment by accepting this ADR.

**D6 — Owner capture re-keys first, holds its captures in the session, and is bounded.** The
owner's engine adopts an unlink that it observes on the poll leg and did not author (ADR 0010
item 5). The poll leg's folder merge reports the children a folder stopped naming, and the drain
re-keys each node and writes one bin entry for it.

- The re-key runs before the entry. This is the opposite of D2, for the opposite reason: the
  unlink has already published, so nothing waits on the entry, and an entry ahead of the re-key
  would claim a cut that may never run.
- The session holds the captures it has not settled, and clears one only when its entry lands.
  The merge that saw the departure has already dropped the node from the base, so the next pass
  would see nothing. Each capture carries the `deletedAt` that the merge stamped, so a retry
  re-keys under the key its entry will name.
- A node that the base still links is no capture: a move and a dual-link loser leave one parent
  and stay named by another. A child whose name the scope's write seed does not derive is a scope
  root and is no capture, for the reason of D4.
- One entry per node, however many ticks observe the unlink. The index refuses a duplicate node
  id, and a later pass re-keys under the standing entry's own `deletedAt` rather than minting a
  second key.
- Capture runs after the queue. A peer chooses the trigger and the count, so one pass adopts a
  bounded share of the captures on one index load and one index publish, and the owner's own ops
  drain first.
- A vault at retention `0` captures nothing. The owner turned the bin off, and an adoption carries
  no owner command that could overrule that.

The capture itself is ADR 0010 item 5; the order, the session hold, the bound and the retention
`0` rule landed with FSM1/cipher-box#1621, and this ADR records them.

**D7 — A node that the base links more than once unlinks from every folder that links it, in
either end of the pass.** The delete removes the child reference from every folder the base links
the node under, and republishes each folder under its own plane. A folder in the second end's
scope is this pass's to unlink. One bin entry covers them all. Its `originParent` names the
highest-ranked link, which is the folder a reader resolves the node under and so the folder a
restore returns it to. Its `scopeId` names the scope that link resolved onto. A folder that the
pass cannot load holds the op, so the pass never publishes a partial unlink. The soft branch
re-keys the node out of the scope, so a link left standing would name a record its own folder's
readers cannot open; the hard branch's reclamation already assumes that no link survives. The
rule landed with FSM1/cipher-box#1658 (the links in one scope) and FSM1/cipher-box#1747 (the
links in the second end); this ADR records it.

**D8 — A link that the pass cannot author refuses the delete; the pass never drops it.** A pass
anchors on one scope and carries one interior end beside it. A queue that holds only deletes
supplies its own second end: the boundary under which a link of the first such op sits is the end
that the tick resolves. What the pass still cannot reach takes one of three exits:

- A link under a boundary for which this tick proved no material is **charged**. The op spends
  its attempt budget and dead-letters where the member sees it.
- A target whose links name two interior scopes, or three scopes in all, has no pass that carries
  every end. The replay dead-letters it as `targetLinkedAcrossScopes` before any record is
  authored.
- A target whose every link sits under one scope root other than this pass's own is that scope's
  own pass to take, and it waits for that pass.

The rule landed with FSM1/cipher-box#1747; this ADR records it.

**D9 — Every op that takes a node out of the bin is a journaled intent op, and a restore re-keys in
reverse, relinks, then drops the entry.** Restore, purge and expiry each stage an op on the
durable queue (#33 D5, D6), so a replay of the queue reproduces the same bin and the same
reclamation. A restore runs in this order:

- It re-seals every node of the subtree at the destination scope's current epoch, through the same
  walk as D5 run in reverse. The destination's grantees read the node again by scope membership,
  and the bin-held key stops opening it. An unshared destination gets the same operation: the
  scope key it re-seals under is the fresh key such a restore needs.
- It relinks the node in the destination folder.
- It drops the bin entry last. The entry drop, not the relink, completes the op. A pass that stops
  between the relink and the drop leaves a node that is both linked and binned, and the retry
  settles it. A rebase that finds the node already linked applies the op rather than dropping it,
  because an entry left standing for a linked node is the entry that a later delete of that node
  would inherit, already past its retention.

The facade resolves the destination at command time, from the caller's choice or from the entry's
`originParent`, and journals it on the op. A destination that the vault no longer holds is its own
refusal at the command, so a host can offer another folder. A destination lost between the queue
and the drain is the `destinationGone` dead letter that a move gets. The journaled ops are ADR
0010 items 4 and 6; the key a restore uses replaces the ADR 0010 item 4 rule that an individual
restore mints a fresh key. That replacement, the order, the command-time destination and the
rebase rule landed with FSM1/cipher-box#1623; this ADR records them. No owner decision records
the replacement, and the owner accepts the amendment by accepting this ADR.

**D10 — A purge proves the node unlinked, is conditional on `deletedAt`, stops at a scope root,
and journals before it drops the entry.**

- The bin entry alone is not the proof. Two halves refuse the purge: gate-passing state that still
  holds the node, and the entry's own `originParent` record, which the pass reads rather than
  looks up in the base. The focus window fills the base, so absence from the base says only that
  this session never rendered the folder.
- The purge is conditional on the `deletedAt` it was formed against. That value is the
  per-delete input of the bin-held key, so an entry stamped otherwise is one this op never saw,
  and its subtree is sealed under another key.
- The purge walk runs under the bin-held key and stops at a scope root, which the bin never
  re-keyed (D4, D5).
- The reclamation is the hard delete's: the doomed manifest, the journal, the target's own debt
  and the descendant quarantine. The journal entry also carries the entry's `deletedAt`, so a
  later pass can derive the held key and resolve a quarantined descendant.
- The journal lands before the entry drop, and a journal that does not land refuses the purge.
  Nothing is reclaimed at that point, so the entry is still the whole retry. The entry drop
  completes the op, and the settle replays off the journal on any later pass.

The reclamation is ADR 0010 item 7; the proof, the condition, the boundary and the journal order
landed with FSM1/cipher-box#1623, and this ADR records them.

**D11 — A bin read that the pass cannot establish is charged.** A restore or a purge that cannot
read a record of the binned subtree spends the op's attempt budget and dead-letters. A binned
subtree joins no eager set, so a rotation can leave it at an epoch the adoption gate refuses
permanently. Uncharged, such a read would hold the strict-FIFO head for every later pass, and expiry
queues these ops with no owner command. The dead letter keeps the entry and its content: a leak,
never a loss (ADR 0011 D5). The rule landed with FSM1/cipher-box#1623; this ADR records it.

**D12 — Expiry runs on the poll tick against the journaled `deletedAt`, queues a bounded share, and
reads the cached index.** The poll tick compares each entry's `deletedAt` against the injected
clock and queues a purge for each entry past the owner's retention. One tick queues a bounded
share of purges across all the scopes it drains, and it skips an entry that the queue already
names. The sweep reads this device's cached index, so a tick costs no record resolve; a device
with no cached copy loads one. The sweep decides nothing by itself: the purge re-reads the
resolved index and refuses an entry stamped otherwise (D10). The sweep queues nothing for an
entry that the purge would refuse permanently: an entry that names another scope, an entry whose
`ipnsName` this scope's write seed does not derive, an entry whose node this device still
renders, and an entry whose own purge already dead-lettered. Expiry is what enforces retention,
and it is the only thing that frees room under the frozen ceiling of the bin index body. Expiry on
the tick is ADR 0010 item 6; the share, the cached read and the skip rules landed with
FSM1/cipher-box#1623, and this ADR records them.

**D13 — Only a retention the owner chose expires anything; retention `0` expires nothing; the
sweep waits when it cannot read the queue.** A settings load that carried no member choice
disables expiry. This is the reverse of D3, because expiry destroys: an owner who set ten years,
and whose settings record will not resolve on one device, must not have a month applied to the
bin. Retention `0` means that the bin takes no new node, not that the entries already in it are
destroyed. The sweep stages ops, and a queue that it could not read cannot say which purges it
already holds, so the sweep waits. The member-choice rule is the one ADR 0019 consequence 4
names; the rest landed with FSM1/cipher-box#1623, and this ADR records it.

**D14 — The queue head never waits on the bin plane in silence.** Every state that a bin index load
can leave the head in has an exit and a reported cause. The split between a charged verdict and an
uncharged hold is ADR 0031 D9, and the `StrandedMint` dead letter is ADR 0031 D10. A charged
verdict exits at the dead letter when the op's attempt budget is spent. Every outcome that is
neither a verdict nor a stranded mint takes a reported hold, which the host reads beside the quota
and settings holds, and the hold clears when the record resolves. A body that no bin rung admits
dead-letters under its own reason, `BinIndexFull`, not as a codec fault, because no retry shrinks
it. ADR 0012 D6 gives the principle; the reported hold and the full-bin reason landed with
FSM1/cipher-box#1658, and this ADR records them.

**D15 — One bin load serves the additions of a pass; a removal resolves again.** The index that a
pass establishes (ADR 0031 D8), by a resolve or by its own confirmed publish, carries across the
entries that the pass adds, so a bulk soft delete costs one resolve, not one per node. A rewrite
that removes an entry — the drop of a restore or a purge — runs after a re-key and several folder
publishes, so it resolves the index again: the index is rewritten whole, and a copy read before
those publishes would drop every entry that another device added since. The publish stays one per
op either way, which keeps each entry ahead of its own unlink (D2). The rule landed with
FSM1/cipher-box#1658; this ADR records it.

## Rationale

- **No pass leaves a node that nothing can find.** D2 puts the entry ahead of the unlink, D9 puts
  the relink ahead of the entry drop, and D10 puts the journal ahead of the entry drop. Each
  residue that a stopped pass leaves is a node that is findable twice, which the retry settles.
- **A retry reaches the same key.** The bin-held key derives from the node id and `deletedAt`
  (ADR 0031 D4). D1 fixes `deletedAt` at authoring, D2 reads it back from a standing entry, and D6
  carries it with a capture, so a retry never seals under a key that no entry names.
- **The cut does not depend on a verdict the drain cannot make.** D5 re-keys every soft delete,
  so no wrong "unshared" reading can leave a binned node open to a revoked grantee.
- **Restore has one mechanism.** D9 runs the D5 walk in reverse for every destination, so a shared
  and an unshared restore cannot drift apart.
- **No link survives that its readers cannot open.** D7 unlinks every link, and D8 refuses a
  delete rather than drop a link that no pass can author.
- **A degraded device errs on the reversible side.** D3 bins when the member's choice is unknown,
  and D13 destroys nothing when it is unknown. Both follow from the fact that a soft delete can be
  undone and a purge cannot.
- **A purge destroys only what it proved.** D10 reads the origin record, checks `deletedAt`, and
  stops at a scope root, so a purge never reclaims a live node or a subtree under another key.
- **The queue head always moves or says why.** D11 and D14 give every bin-plane state a charge, a
  dead letter or a reported hold (ADR 0012 D6). D12 keeps a refused entry off the sweep, so it
  cannot become an endless stream of dead letters.
- **A peer cannot spend the owner's tick.** D6 bounds the captures one pass adopts and puts them
  after the owner's own ops; D12 bounds the purges one tick queues.
- **A bulk delete stays cheap, and a removal stays safe.** D15 carries the index only across
  additions, which cannot drop another device's entries, and resolves it again before a removal.

## Alternatives rejected

**(a) Write the bin entry after the unlink.** A pass that stops between the two leaves a node that
no folder names and no bin entry finds. FSM1/cipher-box#1618 rejected it.

**(b) Skip the re-key for an unshared scope, as ADR 0010 item 3 read.** The drain cannot tell a
scope with grants from one without, and a wrong "unshared" verdict is a fail-open disclosure that
no later pass repairs. The cost of the re-key is the same order as the hard branch's own subtree
walk. FSM1/cipher-box#1621 rejected it.

**(c) Write a capture's entry ahead of its re-key.** The unlink has already published, so the
entry would claim a cut that may never run. FSM1/cipher-box#1621 rejected it.

**(d) Mint a fresh key for an unshared restore, as ADR 0010 item 4 read.** The destination scope
key is already a fresh key with respect to the bin-held key, and a second mechanism is a second
place to drift. FSM1/cipher-box#1623 rejected it.

**(e) Unlink the winning link only, or only the links in the pass's anchor scope.** This was the
behaviour before FSM1/cipher-box#1658 and FSM1/cipher-box#1747. A second folder kept a link to a
record that its readers could not open, and a later purge retired content behind a live link.

**(f) Make a delete wait for a folder outside the pass's scopes.** FSM1/cipher-box#1658 review
finding 2 found that this held the queue head with no exit. D8 charges it, dead-letters it at the
replay, or leaves it to the pass that owns it.

**(g) Treat a bin entry as proof that its node is unlinked.** A soft delete whose parent publish
spent its budget leaves an entry for a node the member still sees. FSM1/cipher-box#1623 rejected
it.

**(h) Leave a bin read that cannot be established uncharged.** A binned subtree that a rotation
left behind would hold the strict-FIFO head permanently, on ops that expiry queues with no owner
command. FSM1/cipher-box#1623 rejected it.

**(i) Expire under the default retention on a degraded load.** An owner who chose a longer
retention would lose entries on the one device that cannot read the settings record.
FSM1/cipher-box#1623 rejected it.

**(j) Wait on a withheld bin index in silence, and report a full bin as a codec fault.** This was
the behaviour before FSM1/cipher-box#1658 (FSM1/cipher-box#1616). The member saw a stalled queue
with no cause, and a full bin spent its budget on a retry that could not succeed.

**(k) Carry the pass's index across every rewrite.** FSM1/cipher-box#1658 review finding 1 found
that a removal built on the carried copy drops every entry that another device added since. D15
carries it across additions only.

## Consequences

1. **`blueprint/engine.md` already carries D1 to D15.** "Delete branch" states D1, D2, D3, D4, D7
   and D8. "Re-key into the bin" states D5. "Owner capture" states D6. "Restore, purge, and
   expiry" states D9 to D13. The bullets "The queue head never waits on the bin plane in silence"
   and "One load serves a pass of soft deletes; every other rewrite resolves" of "Bin index
   record" state D14 and D15. No text change is needed.

2. **`blueprint/core.md` already carries the D5 consequence for the entry.** The "Bin index"
   section says "Every soft delete re-keys, so every entry this build writes carries one". No text
   change is needed.

3. **`CONTEXT.md` already carries the terms.** "Soft delete" (D1), "Bin-held key" (D5),
   "Restore" (D9), "Purge" (D10), "Bin expiry" (D12) and "Owner capture" (D6) state the rules at
   the depth of a glossary. No text change is needed.

4. **ADR 0010 item 3 now reads:** every soft delete, from a shared or an unshared scope, re-keys
   the whole doomed subtree under the bin-held key before the unlink (D5). The sentence "Unshared
   scopes skip the re-key and keep the cheap unlink" no longer applies. The key itself is ADR 0031
   D4. ADR 0010's first consequence now reads "a soft delete costs one re-seal and republish per
   node of the subtree", with no restriction to a shared scope.

5. **ADR 0010 item 4 now reads:** a restore into a destination in the entry's own scope re-seals
   the subtree at that scope's current epoch, whether the scope is shared or not (D9). The
   sentence "An individual restore mints a fresh key and is shared manually" no longer applies. A
   destination in another scope is not covered: the code dead-letters it, and E2 leaves the rule
   for that case to the owner.

6. **ADR 0010 items 2, 5, 6 and 7 stand.** D1 extends item 2, D6 extends item 5, D12 and D13
   extend item 6, and D10 extends item 7. Each adds the order and the failure rules, and none
   changes what the item says.

7. **ADR 0031 consequences 5 and 11 name this ADR.** It is the separate ADR on the soft-delete and
   restore flow. D14 cites ADR 0031 D9 for the split between a charged verdict and an uncharged
   hold, and D14 records the dead-letter exit that ADR 0031 E7 left to this ADR.

8. **`blueprint/engine.md` section "Delete branch" gains the citation (ADR 0043)** in its opening
   paragraph.

9. **`blueprint/engine.md` section "Re-key into the bin" changes its citation** from "ADR 0010
   item 3" to "ADR 0010 item 3, as ADR 0043 amends it", at the bullet "Every soft delete re-keys,
   shared scope or not".

10. **`blueprint/engine.md` section "Owner capture" gains the citation (ADR 0043)** beside its
    ADR 0010 item 5 citation.

11. **`blueprint/engine.md` section "Restore, purge, and expiry" gains the citation (ADR 0043)**
    beside its ADR 0010 items 4, 6 and 7 citation, and at the bullet "A restore re-keys in
    reverse, then relinks, then drops the entry".

12. **`blueprint/engine.md` section "Bin index record" gains the citation (ADR 0031, ADR 0043)** at
    the bullet "The queue head never waits on the bin plane in silence", and (ADR 0043) at the
    bullet "One load serves a pass of soft deletes; every other rewrite resolves".

13. **`blueprint/core.md` section "Bin index" gains the citation (ADR 0043)** at the sentence
    "Every soft delete re-keys, so every entry this build writes carries one".

14. **No wire format, no KDF edge and no KAT vector changes.** The op record already carries the
    `to_bin` verdict and the purge's `deletedAt`, and the doomed journal already carries the
    entry's `deletedAt`; each shipped with the PRs above.

## Residuals

**E1 — Owner capture re-keys under the capture's own stamp, and this can lose a node. The code
and the blueprint disagree, and FSM1/cipher-box#2019 tracks the defect.** D6 records the blueprint
rule: a later pass re-keys under the standing entry's own `deletedAt`. The code does not. Line
numbers below are at `origin/main` `c86137502`; `drain.rs` is `crates/engine/src/sync/drain.rs`.

1. The authored soft delete follows the rule. `publish_delete` stamps the entry with the op's
   `authoredAt` (`drain.rs:2867`), calls `record_bin_entry` (`drain.rs:2869`-`2871`), and re-keys
   under the stamp it returns (`drain.rs:2872`). `record_bin_entry` returns a standing entry's own
   `deletedAt` (`drain.rs:3450`-`3457`).
2. A capture carries a different clock read. `FolderMerge::observed_unlinks` stamps each departure
   with the value its caller passes (`crates/engine/src/sync/project.rs:116`-`133`): the focus leg
   passes `observed_at` (`crates/engine/src/net/focus.rs:167`-`171`), and the root leg passes
   `now` (`crates/engine/src/facade.rs:7281`). It is never the authored op's `authoredAt`.
3. `adopt_observed_unlinks` ignores the standing entry's stamp. It computes `standing`
   (`drain.rs:3514`-`3517`) and calls `rekey_into_bin` with the capture's own `deletedAt` whatever
   `standing` says (`drain.rs:3518`-`3526`). With an entry standing, it drops the capture on
   success and writes no entry (`drain.rs:3534`-`3536`), and it drops the capture on failure
   (`drain.rs:3528`-`3532`).
4. The key derives from the stamp (`drain.rs:3803`). `load_doomed` opens each node under the
   source key, else under the target key (`drain.rs:3897`-`3915`).
5. The authored op ends with no re-key by one of two routes. `run_queue` drains the queue before
   capture (`drain.rs:1658`-`1659`). When the merge has dropped the node from the base,
   `rebase_delete` drops the op as already satisfied (`crates/engine/src/sync/rebase.rs:710`-`712`).
   When the base still holds the node, `publish_delete` reads each parent again, finds no link,
   and returns `Ok(())` before `record_bin_entry` (`drain.rs:2827`-`2844`).
6. Restore and purge open under the entry's stamp (`drain.rs:2979`, `drain.rs:3050`,
   `drain.rs:3059`). An unopenable read goes through `charge_bin_read` (`drain.rs:767`-`772`), so
   both dead-letter, and the expiry sweep then skips the entry permanently (`drain.rs:3600`).

The loss needs all of these: a retention above `0`; a node N that is not a scope root; an authored
soft delete of N whose entry landed at stamp T1 and whose re-key did not re-seal N's root record,
so N stays linked (the residue of D2); a write grantee of N's scope that unlinks N itself, and not
an ancestor, before a retry finishes the re-key; and an owner device that captures the departure
at stamp T2, resolves the index with N's T1 entry, and completes the re-key under T2. An unlink of
an ancestor re-keys N under the ancestor's key instead, and a restore of the ancestor brings N
back.

The outcome is a loss. Every node of N's subtree is sealed under the key of T2. Only the dropped
session capture held T2, so no entry, journal or log holds it. The standing entry names the key of
T1. No folder links N. Restore and purge both dead-letter, expiry skips the entry, and the content
stays pinned. No code path recovers N, so the owner loses N and pays for its content with no end.

A partial variant loses nothing but leaves the cut incomplete. When the authored walk re-sealed
N's root under T1 and then stopped, the capture's re-key fails at the root and the capture is
dropped. The authored op is also dropped by one of the two routes of step 5, so the descendants
that the walk did not reach stay under the scope key. A grantee of the source scope still reads
those descendants. A restore still works, because `load_doomed` treats them as already moved. A
purge dead-letters on the first of them (`drain.rs:3413`-`3423`).

This ADR records the blueprint rule. The fix direction: when an entry stands,
`adopt_observed_unlinks` re-keys under that entry's `deletedAt`, as `record_bin_entry` already does
for the authored path. `load_doomed` reads both keys, so the same fix also completes the partial
variant. No test covers either window.

**E2 — A restore into a folder of another scope dead-letters. The code and the blueprint disagree,
and FSM1/cipher-box#2020 tracks the defect.** D9, the "Restore, purge, and expiry" section of
`blueprint/engine.md` and ADR 0010 item 4 all say that a restore re-seals the subtree at the
destination scope's current epoch, so that the destination's grantees read it by scope membership.
The code refuses every destination in another scope. `publish_restore` returns
`Halt::Permanent(CrossingUnauthorable)` when the destination's scope is not the scope the entry
names (`drain.rs:2973`-`2978`), because the restore re-keys in place and no pass authors a re-seal
across scopes. The facade does not refuse such a destination at command time
(`crates/engine/src/facade.rs:8084`-`8093` checks only that the vault holds the folder and that
the folder has room), so the member gets a dead letter, not the `RestoreTargetGone` refusal. A
node deleted from an unshared scope therefore cannot be restored into a shared folder, which is
the case ADR 0010 item 4 names. A default restore can meet the same refusal: when the owner shares
the `originParent` folder after the delete, that folder becomes a scope root of its own, and the
default destination may then sit in another scope.

This ADR records the blueprint rule. The choice of fix is the owner's: a cross-scope restore in
the drain, or a reword of the rule to "a restore lands in the entry's own scope" together with a
refusal at command time.

**E3 — A focus refresh can meet a node between its re-key and its unlink.** The node is sealed
under the bin-held key and still named by its parent for one pass on the authoring device, so a
refresh in that window reports an unseal rejection. FSM1/cipher-box#1621 named this residual. The
folder leg merges root-ward, so a peer refreshes the parent before the child.

**E4 — Capture sees only a departure from a folder this device has rendered.** The merge compares a
fresh listing with the base, and the focus window fills the base. A grantee's unlink from a folder
that no owner device refreshes after the unlink is never captured, and the grantee keeps the read
key of that node. The session holds the unsettled captures, so a session that ends before a
capture settles also loses it: the base no longer names the node.

**E5 — A scope-root child is destroyed even at a retention above `0`.** D4 takes the hard branch,
so the member gets no bin entry and no restore for such a child. The blueprint states the rule; no
host text is required to warn the member.

**E6 — A withheld bin index holds the head without a bound.** D14 reports the hold, and the web
client shows it beside the quota and settings holds. Only the record resolving clears it. This is
the uncharged arm of ADR 0012 D6, and the blueprint accepts it.

**E7 — A dead-lettered purge keeps its entry until the member acts.** D11 keeps the entry and its
content, and D12 then keeps the entry off the sweep permanently. The bin index body has a frozen
ceiling, so such entries use room that expiry never frees.

**E8 — A device that never writes the bin can expire late.** D12 reads the cached index, and only a
bin operation refreshes it. Any device of the account expires an entry, and the entry stands until
one does. The blueprint accepts this.

## Gate

The engine tests run in the `Engine simulation tests` job, inside the **Rust** area of the PR
gate. Unless a path is given, the tests below are in `crates/engine/tests/write_plane.rs`.

- **D1:** `the_loaded_bin_retention_decides_the_journaled_delete_branch` (retention `0` journals
  the hard branch, the default journals the soft one), `a_soft_delete_bins_the_node_and_reclaims_nothing`
  (no retire and no unpin, and a `deletedAt` that the injected clock did not produce at publish
  time), `a_write_grantees_delete_only_unlinks_the_node` (`crates/engine/src/facade.rs`) and
  `a_write_grantees_delete_reaches_the_owners_bin_by_owner_capture`
  (`crates/engine/tests/owner_actions.rs`). No test saves settings between the queue and the drain;
  the journaled verdict is proven, its effect on a later save is not.
- **D2:** `a_purge_refuses_a_node_a_live_parent_still_names` (the entry landed and the parent
  still names the node after a refused parent publish), `a_re_key_that_cannot_publish_leaves_the_node_linked`,
  and `a_body_naming_one_node_twice_is_never_published` (`crates/engine/tests/bin_index.rs`). No
  test drives an authored retry over a standing entry to completion.
- **D3:** no test. No test deletes on a session whose settings load fell to the defaults, or that
  holds no settings summary.
- **D4:** no test. FSM1/cipher-box#1618 stated that the harness cannot plant a child with a
  foreign `ipnsName` cheaply.
- **D5:** `a_soft_delete_re_keys_the_whole_doomed_subtree_out_of_the_scope` (the vault in the test
  has no grant, so it also proves that an unshared scope re-keys) and
  `a_re_key_that_cannot_publish_leaves_the_node_linked`. No test proves that the walk stops at a
  descendant scope root.
- **D6:** `an_unlink_this_device_did_not_author_is_adopted_into_the_bin_once`,
  `a_child_another_parent_still_names_is_never_captured`,
  `a_capture_that_cannot_settle_is_adopted_by_a_later_pass`,
  `a_vault_at_retention_zero_captures_no_unlink`, and
  `a_grafted_pass_bins_no_capture_and_starves_no_set` (`crates/engine/src/sync/drain.rs`). No test
  proves the per-pass bound, the session bound, or the re-key under a standing entry's `deletedAt`
  (E1).
- **D7:** `a_soft_delete_unlinks_a_dual_linked_node_from_every_folder`,
  `a_restore_returns_a_dual_linked_node_to_its_origin_parent_alone`,
  `a_purge_after_a_dual_link_soft_delete_finds_no_link_to_refuse_it`, and
  `a_delete_unlinks_a_node_from_a_folder_in_each_end_of_the_pass` and
  `a_delete_inside_the_second_end_files_its_bin_entry_under_that_scope`
  (`crates/engine/tests/owner_actions.rs`). No test proves that a folder the pass cannot load holds
  the op.
- **D8:** `a_delete_charges_a_link_under_a_boundary_no_pass_can_seal` and
  `a_delete_wholly_inside_a_dark_grant_waits_rather_than_charging`
  (`crates/engine/tests/owner_actions.rs`); `a_delete_linked_from_two_granted_scopes_dead_letters`,
  `a_delete_linked_from_three_scopes_dead_letters`,
  `a_delete_linked_from_the_anchor_and_one_granted_scope_reaches_the_drain` and
  `a_delete_linked_only_inside_one_granted_scope_reaches_the_drain`
  (`crates/engine/src/sync/rebase.rs`); and
  `a_delete_names_the_one_granted_scope_its_target_is_linked_from`,
  `a_delete_linked_from_two_granted_scopes_names_no_second_end` and
  `a_delete_linked_outside_every_granted_scope_names_no_second_end`
  (`crates/engine/src/facade.rs`).
- **D9:** `a_restore_with_no_destination_returns_the_node_to_the_folder_its_entry_names` (an
  unshared destination; the scope key opens the node and the bin-held key does not),
  `a_restore_into_a_chosen_folder_places_the_node_there_and_drops_its_entry`,
  `a_restore_whose_destination_is_gone_reports_its_own_outcome`,
  `a_restore_whose_entry_drop_does_not_land_finishes_on_the_retry`,
  `a_restore_retried_over_a_destination_that_already_names_it_publishes_one_ref`,
  `a_purge_charges_the_doomed_roots_and_drops_the_entry` and
  `an_entry_past_the_retention_is_purged_on_a_poll_tick` (journaled ops), and
  `a_restore_lands_at_its_destination_and_auto_suffixes_a_taken_name` and
  `a_restore_into_a_destination_the_vault_lost_dead_letters` (`crates/engine/src/sync/rebase.rs`).
- **D10:** `a_purge_charges_the_doomed_roots_and_drops_the_entry`,
  `a_purge_refuses_a_node_a_live_parent_still_names` (the command-time refusal),
  `a_purge_refuses_a_node_gate_passing_state_still_holds` and
  `a_purge_of_an_unlinked_node_reaches_the_drain` (`crates/engine/src/sync/rebase.rs`), and
  `a_purge_entry_round_trips_the_stamp_its_held_key_derives_from`
  (`crates/engine/src/sync/doomed.rs`). No test drives the drain's read of the `originParent`
  record, a `deletedAt` mismatch, the stop at a scope root, or a journal that does not land.
- **D11:** `a_bin_paths_epoch_lag_is_charged_because_no_wave_reaches_a_binned_subtree`
  (`crates/engine/src/sync/drain.rs`). It proves the charge mapping; no integration test drives a
  restore or a purge to the dead letter.
- **D12:** `an_entry_past_the_retention_is_purged_on_a_poll_tick`, and
  `a_tick_shares_its_bin_expiries_across_the_scopes_it_drains` and
  `a_grafted_pass_stages_no_bin_expiry` (`crates/engine/src/sync/drain.rs`). No test proves the
  skip rules, the skip of an entry the queue already names, or the cached read.
- **D13:** `only_an_elapsed_retention_the_owner_chose_expires_a_bin_entry`
  (`crates/engine/src/sync/drain.rs`) and `a_settings_load_with_no_member_choice_expires_nothing`.
  No test proves that the sweep waits on an unreadable queue.
- **D14:** `a_withheld_bin_index_reports_a_named_hold_that_clears_when_it_resolves`;
  `a_later_pass_of_the_same_tick_does_not_drop_another_pass_bin_index_hold`,
  `a_bin_index_at_its_ceiling_dead_letters_under_its_own_reason` and
  `a_bin_index_publish_charges_only_what_this_build_authored` (`crates/engine/src/sync/drain.rs`);
  and `a_bin_past_the_top_rung_is_refused_as_a_full_bin_and_not_as_a_codec_fault`
  (`crates/engine/tests/bin_index.rs`). The verdict charge and the stranded mint are ADR 0031's
  gate.
- **D15:** `a_bulk_soft_delete_resolves_the_bin_index_once_for_the_whole_pass` and
  `a_restore_resolves_the_bin_index_rather_than_the_copy_the_pass_carried`.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
