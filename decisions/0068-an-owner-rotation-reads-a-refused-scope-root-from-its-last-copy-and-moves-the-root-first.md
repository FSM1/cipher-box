# ADR 0068 — An owner rotation reads a refused scope root from its last copy, and moves the root first

- **Status:** Accepted on 2026-10-03
- **Date:** 2026-10-02
- **Relates to:** FSM1/cipher-box#2176 (a planted record at the scope root name blocks the name
  wave), [ADR 0020](./0020-the-durable-op-queue-reads-the-previous-release.md) D2,
  [ADR 0061](./0061-a-renewal-walk-over-every-owned-scope-renews-each-name-through-the-adoption-gate.md)
  D3 and D4,
  [ADR 0063](./0063-a-rotation-step-that-stops-leaves-a-durable-owed-record-that-the-sync-pass-finishes.md)
  D2, D4 and D5, [ADR 0064](./0064-the-name-wave-reads-a-lagging-interior-node.md),
  [ADR 0065](./0065-the-name-wave-drops-a-node-that-it-cannot-move-and-an-owed-cut-ends-within-a-bound.md)
  D1, D3 and D4, `blueprint/engine.md` "rotateScopeWrite" and "Adoption gate and floors"
- **Implemented by:** FSM1/cipher-box#2270 (D1 to D4, and the amendment of 2026-10-03)
- **Amends:** ADR 0065 D4 (a stop at the scope root does not lapse the scope), ADR 0065 Residuals

## Context

A revoked writer derives the scope root name from the old write seed. It plants a record there at
a higher sequence, so every endpoint serves the plant and not the honest root. The gate refuses the
plant. The name wave cannot drop the root (ADR 0065 D1), the renewal walk cannot admit it
(`admit_owned_scope_root`), the scope lapses at EOL, and the revokee keeps write access. A plant at
sequence `u64::MAX` also blocks each later publish at the old name, which the read cut and
`publish_cut_set` need. A plant before the command stops the command before its owed entry. After
the plant, the only source of the honest root is a copy on an owner device.

## Decision

**D1 — An owner rotation read of a scope root that the gate refuses for a cause in the record
bytes runs on the last copy of that root that passed the gate on this device.** This extends the
rule that `last_known_good_root` applies today to a root that is not resealable. It applies to the
command read, `publish_cut_set`, the read cascade root read, the name wave's `root_source`, and
the check of the re-drive that the cut set landed. The copy runs the full gate again. A head block
that no endpoint serves falls back only past the bound of ADR 0065 D3. Each fallback sends one
trust event with the scope root and the refused sequence. Readers that are not an owner rotation
do not change.

Amended on 2026-10-03: the bound applies to the re-drive only. The reads of an owner command fall
back at once also for a cause that an endpoint can give: a head block that no endpoint serves or
that does not match its CID, and a record below the sequence floor. A root that leaves no room for
its re-seal also falls back at once.

**D2 — A confirmed scope root publish by the owner is a last-known-good copy.** Thus a plant after
the cut set lands finds the cut-set root in the cache.

**D3 — A rotation whose root read fell back does not publish at the old root name.** A cut that
moves the write plane runs its name wave first. The root republish at the new name re-mints the
grant section from the cut set, never from the copy, so a pre-cut copy gives the revokee no new
seed. The read cut then runs at the new root name. A cut that does not move the write plane keeps
the stop: a current writer planted the root, and the trust event names it.

**D4 — A re-drive takes the cut set from the owner's own published root (D2).** The owed entry
does not carry the cut set. When no copy carries it, the re-drive finds the cut as never landed,
drops the entry with `rotationWorkAbandoned`, and the owner runs the command again. After a
fallback, the cut-epoch floor rises only when the cut set lands.

Amended on 2026-10-03: an entry whose cut never landed stays with its first stop. A run of the
command again replaces its steps and its cut epoch, and keeps its first stop. The re-drive drops
the entry only when the owner runs no command again within the bound. The bound for a scope starts
at the first stop of an owner rotation on that scope and survives an abandon and a run again. Each
sync pass that re-drives the entry counts as a pass: the pass places an owed scope whose refused
root was the one failure of its boundary walk. The durable `owed-rotation` body does not change.

## Alternatives considered

- **Keep the stop (today).** The revokee keeps write access for ever, and the scope lapses at EOL.
- **D1 without D3 (option 1).** A plant at `u64::MAX`, or a new plant after each owner publish,
  holds the read cut at the old name for ever. The wave re-mints from the copy, so the copy must
  carry the entry's cut epoch, and a plant before the command stays open.
- **The owed entry carries the cut set (option 2b).** A re-drive then finishes a cut whose first
  wave stopped after a plant before the command. But the `owed-rotation` body changes, so it lands
  over two releases (ADR 0020 D2). A command that the owner runs again gives the same result.
- **Re-mint the scope root when no copy passes the gate (option 3).** It also covers a device with
  no copy. But every member loses the whole subtree, the step needs a new `OwedStep` variant over
  two releases, and the hosts need new text.
- **Correct the documents only (option 4).** The revokee keeps write access for ever.
- **Read the honest root from the API republisher.** The API never serves records.
- **Take the highest record on the network that passes the gate.** Each endpoint keeps only the
  record with the higher sequence, so the honest root is not on the network.

## Consequences

1. `blueprint/engine.md` "rotateScopeWrite" replaces "a stop at the scope root still stops the
   wave" with D1 and D3. "Owed rotation work" states D4. "Residuals" replaces "a planted record at
   the scope root name is not covered" with the data loss: what a writer published after the copy
   goes, surfaced by the trust event. "Triggers" states the order of D3: the read plane goes
   first, except after a fallback.
2. `blueprint/engine.md` "Adoption gate and floors" names the owner rotation fallback of D1 beside
   the gate's fail-closed rule.
3. `CONTEXT.md` "Forgery window" ends at the wave for a planted root when a copy passes the gate.
   "Owed rotation work" states D4.
4. `blueprint/testing.md` "crates/engine — seam fakes and the simulation harness": the rotation
   matrix adds the root plants (a refused record, a pre-cut replay, a head block that no endpoint
   serves, a plant at `u64::MAX`, a plant before the command). Each ends the revoke in one pass
   with a copy, and a wave on a pre-cut copy re-mints no grant for the revokee.
5. ADR 0065 D4 and ADR 0065 Residuals carry an "Amended by ADR 0068" sentence.

## Residuals

- Honest lag (amended on 2026-10-03): when another owner device published the root and no endpoint
  serves its head block yet, a command runs on the older copy, and what that device published goes,
  surfaced by the trust event.

- A device with no copy that passes the gate keeps the stop, and the scope lapses. Does option 3
  follow, or does the owner accept this?
- A `directChildScopeIndex` entry that a committed writer put in the root body before the cut
  stops the wave in `record_scope_boundary`, also on the copy. Does it get its own rule?
