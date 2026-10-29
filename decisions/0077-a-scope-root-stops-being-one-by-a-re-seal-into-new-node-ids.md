# ADR 0077: A scope root stops being one by a re-seal into new node ids

- **Status:** Accepted on 2026-10-17
- **Date:** 2026-10-17
- **Relates to:** [#2298](https://github.com/FSM1/cipher-box/issues/2298), [#2241](https://github.com/FSM1/cipher-box/issues/2241), [ADR 0012](./0012-the-drain-carries-the-write-wave-forward.md), [ADR 0020](./0020-the-durable-op-queue-reads-the-previous-release.md), [ADR 0041](./0041-a-rotation-reads-every-floor-again-before-it-seals.md), [ADR 0063](./0063-a-rotation-step-that-stops-leaves-a-durable-owed-record-that-the-sync-pass-finishes.md)
- **Implemented by:** [#2476](https://github.com/FSM1/cipher-box/pull/2476) (the D3 kind and its readers), [#2483](https://github.com/FSM1/cipher-box/pull/2483) (the D3 journal grammar and store), [#2484](https://github.com/FSM1/cipher-box/pull/2484) (the D1 cut and final records), [#2490](https://github.com/FSM1/cipher-box/pull/2490) (the D3 walk and id map), [#2491](https://github.com/FSM1/cipher-box/pull/2491) and [#2497](https://github.com/FSM1/cipher-box/pull/2497) (the D1 re-seal and the D4 rules). The relink, the cleanup, the D2 command and the restore across scopes are not landed.
- **Amends:** ADR 0012 D2 (the count of sanctioned readers below the read-epoch floor)

## Context

A folder stays a scope root after the owner revokes its last grant, and the delete refuses a known
scope root, so the owner can never delete a folder that was shared one time. The root keeps a
scope seed that the parent plane cannot derive, and the parent's `directChildScopeIndex` keeps its
entry. A restore into a folder of another scope also needs a subtree that re-seals under another
scope. The owner ruled on 2026-10-13 and on 2026-10-17.

## Decision

**D1 — A scope root stops being one by a re-seal of its subtree into new node ids.** The dissolve
authors each node of the subtree again as a new node of the parent scope: a fresh node id, the name
that the write scope seed of the parent folder derives for that id, the parent scope id in the AAD,
and the parent's current epoch. Each nested scope root in the subtree is cut and re-sealed the same
way, so the new folder holds no scope root. The parent folder then names the new plain folder in
place of the old root, and the old scopes retire. Each dissolved scope keeps its pointer, its final
post-cut root name and its final head block for one more EOL term. The root gate does not
change: a plain record at a scope root's id stays a `MissingGrantSection` refusal, and new ids make
it unnecessary to tell an owner dissolve from a forged downgrade.

**D2 — A separate owner command dissolves a scope root, and the delete, bin, restore and purge
paths do not change.** The command cuts the scope, re-seals it under D1, and stops; alone, it is
"stop sharing". To delete a shared folder, the host sends the dissolve, then the ordinary delete on
the new folder, under one confirmation. No drain path bins or hard-deletes a scope root.

**D3 — One subtree re-seal serves the dissolve and the restore across scopes, and one owner-local
journal entry carries it.** The re-seal walks a subtree from a source plane to a destination plane
and seals each node at the destination's current epoch, child first. It opens a lagging source node
as the drain's re-author does (ADR 0012), under the same four conditions. The dissolve gives each
node a new id, random from the injected entropy, so no KDF edge is new, and sheds every carried
field. The restore of FSM1/cipher-box#2241 keeps each id and every carried field (`blueprint/core.md`
"Carried unknown fields"), and refuses by name a structure that is not safe across a scope change.
The walk maps no node outside the source subtree: a child that opens under another scope starts
the walk again, and a gate refusal is a trust violation. Before the cut, the
engine writes one entry under a new owner-local kind: the source scope, the destination read scope
and the destination write scope bound separately, their epochs, the step still owed, and the map
from old to new ids. The dissolve fills the map after the cut, durably before the first re-seal
publish; it stays empty when the ids stay. The entry holds no seed and no key, and carries every
step after the cut. Only the device with the entry resumes it, with the same id map, so a retry
mints no second copy.

**D4 — Before the relink, only an owner read cut restarts the full re-seal, and a destination
write cut restarts the names.** Each publish and irreversible step obeys ADR 0041. Each check reads
the floor of the scope that supplies its seed: the destination read scope for a seal, the
destination write scope for a name. The pass writes a new epoch to the entry before it seals at
that epoch. A rise that an owner cut of the read scope causes (`minReadEpoch` or the cut epoch
rises) re-seals each published node again, because key regression gives a cut grantee every epoch
below the cut, and the lazy wave reaches no node that the destination does not link. Another rise
seals only the remaining nodes at the new epoch, so a grantee rotation cannot restart the pass
(Amended by ADR 0082 D1 on 2026-10-28: the engine starts no cut of a received scope on the grantee device; a read-epoch rise without a
`minReadEpoch` or cut-epoch rise, as in an owner flat cut, still does not restart the pass). A
write cut of the destination write scope derives each name again under the new write scope seed,
publishes each node again and retires the vacated names; as ADR 0063 D1 refuses a resume at another
write epoch, no publish lands at a name of an old write scope seed. A grant on an ancestor of the
relink parent changes the destination scope: the dissolve binds the new read and write scopes,
re-seals every node and restarts the names. After the relink, the lazy wave and the name wave
carry a rise.

## Alternatives considered

- **In-place demotion (D1).** Keep the node ids, and add a root gate rule that accepts a scope root
  that becomes a plain folder. Rejected: the rule must tell an owner dissolve from a forged
  downgrade, and after a write grant the boundary walk still reads the root name as a scope root.
- **A scope-aware delete (D2).** Rejected: the soft delete, hard delete, restore and purge each read
  under the parent plane (`rekey_subtree`, `enumerate_doomed`, `publish_restore`), so all four
  change, and a restore gives back a scope root whose grants are cut.
- **Revoke every grant and keep the root (D2).** Rejected: the delete refusal stays, and the stale
  `directChildScopeIndex` entry stops each later ancestor rotation in `enumerate_eager_set`.
- **Two re-seal mechanisms, one for each caller (D3).** Rejected: two journal shapes, two test sets.
- **No journal, a retry re-seals from the start (D3).** Rejected: a dissolve retry mints new ids
  again, so each stopped pass leaves a full copy that no folder names.
- **Any epoch rise re-seals every node again (D4).** Rejected: a write grantee of the destination
  can rotate at will, and so restart an O(subtree) pass again and again. ADR 0083 D1 closes this:
  the gate refuses a scope-root section that a grantee signs.

## Consequences

- `CONTEXT.md` gains "Scope dissolution". `blueprint/core.md` registers the D3 owner-local kind.
- `blueprint/engine.md` "Delete branch" names the dissolve as the path to a delete. "Restore,
  purge, and expiry": a restore of a dissolved, then deleted folder gives back a plain folder.
- FSM1/cipher-box#2241, in its own PR on D3, removes the `RestoreCrossesScope` refusal and the
  interim sentences in `blueprint/engine.md`, `CONTEXT.md` "Restore", ADR 0010 item 4, ADR 0043 E2.
- `blueprint/engine.md` "Grants and ledger": the confirmation lists each nested shared folder and
  says that the write grantees of the parent scope can write the folder after the dissolve. The
  dissolve runs online only; a link claim that waits for conversion delays the cut.
- "Grants and ledger": the dissolve cuts every scope root in the subtree, each with every grant,
  write grant and invite link in one cut. Each cut, name wave and re-point lands before the first
  re-seal publish, and the walk reads only names that the post-cut write scope seed derives.
- Per-op rebase rules: a concurrent grant refuses the dissolve before the copy starts, which the
  seal marks before its first re-seal publish. After it and before the relink, the D3 entry cuts
  and re-seals a new root as well (D1), and cuts again a scope that it cut when a new grant or cut
  lands there; a cut that left no row raises the held cut epoch and publishes the final records
  again. The host reports each.
- "Rotation primitives": the order is cut, re-seal, relink, index removal, retirement. The
  `owed-rotation` entry carries the cut alone (ADR 0063 D1). The dissolve files no sweep of the
  scopes it cuts: the name wave and the re-point land in the cut, and the walk opens a lagging
  interior node as the re-author does. No durable signal for that sweep exists. An op or owed
  step under a scope root that its parent no longer names dead-letters.
- "Rotation primitives": before the relink, another owner device can start a separate dissolve.
  The parent CAS admits one replacement, and a loser never replaces the winner. A loser retires
  its own copy only when its entry proves that it sent no relink. Else a gated link proof of the
  parent scope decides, and only a proof that the old root is still linked lets it retire the
  copy. An optimistic confirm does not prove a loss. The loser also keeps its copy until the
  served parent passes every relink sequence that its relink marks in the floor store hold. The
  marks stay after the entry goes.
- `blueprint/api.md` "Pin/name registry": after the gated parent root shows the index removal, the
  dissolve retires every name of the old subtree except the D1 final records.
- Accepted residuals: the uploads of a write grantee stay in the new folder. Content keys are re-wrapped and content bytes are not encrypted again, so a cut grantee keeps each version it opened. The publish of N new names and the retire of N old names show the dissolve and its size to the server, as a bin re-key does (`blueprint/core.md` "Bin index"). The server also links old and new file records through unchanged content CIDs. The journal's explicit id map stays local.
- `blueprint/desktop.md` "Conflicts, dead letters, and rotation": a delete of a shared folder is a dissolve, then a delete; the tray reports a refused dissolve.
- `blueprint/testing.md`: crash and replay at each stop point; for the D3 kind, the previous-release read, the cross-kind KAT pair, and a release-active encode and decode refusal of a duplicate id in the map; a mid-pass read-epoch rise and write-epoch rise.
- `blueprint/engine.md` "Rotation primitives": the cut's name wave and the re-seal each walk the
  source. The double walk is accepted: a dissolve is rare.
- `blueprint/engine.md` "sweep" and "Adoption gate and floors", and `CONTEXT.md` "Adoption gate":
  the count of sanctioned lagging readers becomes five; the fifth is the D3 re-seal's read.
- `blueprint/api.md` "Pin/name registry" and `blueprint/engine.md` "Revocation is discovered, not
  delivered": the D1 final records stay for one more EOL term, under owner-signed EOLs that cover
  it, so a grantee shows "this share ended" as after a revoke. At term end, the engine retires them.
