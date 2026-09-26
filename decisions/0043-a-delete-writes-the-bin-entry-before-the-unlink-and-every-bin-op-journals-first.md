# ADR 0043 — A delete writes the bin entry before the unlink, and every bin op journals first

- **Status:** Accepted on 2026-09-26 — retroactive; the rule shipped in FSM1/cipher-box#1618,
  FSM1/cipher-box#1621, FSM1/cipher-box#1623, FSM1/cipher-box#1658 and FSM1/cipher-box#1747, and
  the blueprint carries it; the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows; trimmed on 2026-09-26 to the items that pass
  the three ADR hurdles — the removed items live in the blueprint
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

ADR 0010 decided what the recycle bin is. It did not decide the order of the steps, or what a
partial pass leaves. A soft delete is three separate publishes: a bin entry, a re-seal of the
doomed subtree, and a republish of every parent that names the node. The drain is strict FIFO and
retries the op whole, so every order leaves some residue when a pass stops between two steps. A
node that no folder names and no bin entry finds is lost, because the entry's `ipnsName` is the
only route back to it. ADR 0010 item 3 let an unshared scope skip the re-key, but the drain
carries the seeds of a scope and not its grant ledger, so it cannot apply that rule. A wrong
"unshared" verdict leaves a binned node open to a revoked grantee permanently, because key
regression hands that grantee every older epoch and no lazy wave reaches a binned node. ADR 0010
item 4 gave an unshared restore a fresh key, but the destination scope's current epoch key is
already a key that the bin-held key does not derive.

## Decision

**D2 — The bin entry lands before the unlink.** On an authored soft delete the order is: the bin
entry, then the re-key, then the unlink of every parent. A pass that stops between the entry and
the unlink leaves a node that is both binned and still linked, and the retry settles it. The
reverse order leaves a node that no folder names and no bin entry finds. The retry is idempotent.
An encode refuses a duplicate node id, so an entry that already landed publishes nothing, and the
retry reads the standing entry's own `deletedAt`, so the re-key reaches the same bin-held key
(ADR 0031 D4).

**D5 — Every soft delete re-keys the whole subtree into the bin before the unlink, shared scope or
not.** Every node of the doomed subtree is re-sealed under the bin-held key before the unlink
publishes. This re-key is the access cut: key regression gives a current or revoked grantee every
older epoch of the scope seed, so only a key outside the scope's derivation stops them. Names,
signers and the AAD-bound scope id do not move, so the entry's `ipnsName` stays the route back.
The whole subtree re-keys in the pass that bins it, because a binned node takes no ordinary write
and no lazy wave would carry it. The drain carries no grant ledger, so it re-keys every soft
delete. This replaces the ADR 0010 item 3 rule that an unshared scope skips the re-key. No owner
decision records the change. This ADR records it, and the owner accepted the amendment on
2026-09-26.

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
  settles it.

This replaces the ADR 0010 item 4 rule that an individual restore mints a fresh key. No owner
decision records the replacement, and the owner accepted the amendment on 2026-09-26.

Items D1, D3, D4, D7 and D8 moved to `blueprint/engine.md` "Delete branch", D6 to "Owner capture",
D10 to D13 to "Restore, purge, and expiry", and D14 and D15 to "Bin index record", on 2026-09-26.

## Alternatives rejected

- **(a) Write the bin entry after the unlink.** A pass that stops between the two leaves a node
  that no folder names and no bin entry finds.
- **(b) Skip the re-key for an unshared scope, as ADR 0010 item 3 read.** The drain cannot tell a
  scope with grants from one without, and a wrong "unshared" verdict is a fail-open disclosure
  that no later pass repairs. The re-key costs the same order as the hard branch's subtree walk.
- **(d) Mint a fresh key for an unshared restore, as ADR 0010 item 4 read.** The destination scope
  key is already fresh with respect to the bin-held key, and a second mechanism can drift.

## Rationale

- **D2:** each residue of a stopped pass is a node that is findable twice, never a lost node.
- **D5:** the cut does not depend on an "unshared" verdict that the drain cannot make.
- **D9:** one re-key walk serves every restore, and the last entry drop keeps the D2 residue.

## Consequences

1. `blueprint/engine.md` carries every item, kept and moved, and `blueprint/core.md` "Bin index"
   carries the D5 consequence for the entry.
2. `CONTEXT.md` carries the bin terms at the depth of a glossary.
3. ADR 0010 items 3 and 4 carry the D5 and D9 amendments; items 2, 5, 6 and 7 stand.
4. ADR 0031 consequences 5 and 11 name this ADR as the ADR on the soft-delete and restore flow.

The `Engine simulation tests` job in the **Rust** area of the PR gate blocks the merge.

## Residuals

**E2 — A restore into a folder of another scope dead-letters. The code and the blueprint disagree,
and FSM1/cipher-box#2020 tracks the defect.** D9 and ADR 0010 item 4 say that a restore re-seals
the subtree at the destination scope's current epoch. The code refuses every destination in
another scope with `Halt::Permanent(CrossingUnauthorable)`, and the facade does not refuse it at
command time. A node deleted from an unshared scope therefore cannot be restored into a shared
folder, which is the case ADR 0010 item 4 names. The choice of fix is the owner's: a cross-scope
restore in the drain, or the rule "a restore lands in the entry's own scope" with a refusal at
command time.

**E4 — Owner capture sees only a departure from a folder that this device has rendered.** A
grantee's unlink from a folder that no owner device refreshes after the unlink is never captured,
and the grantee keeps the read key of that node.
