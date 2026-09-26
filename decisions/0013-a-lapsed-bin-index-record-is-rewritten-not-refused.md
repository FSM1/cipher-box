# ADR 0013 — A lapsed bin index record is rewritten, not refused

- **Status:** Accepted — the rule is in the code, from
  [FSM1/cipher-box#1658](https://github.com/FSM1/cipher-box/pull/1658)
- **Date:** 2026-09-02
- **Relates to:**
  [ADR 0010](./0010-recycle-bin-is-an-owner-sealed-index.md)
  item 1 (the bin index is published and CAS-guarded like the vault settings record) and item 3
  (a soft delete re-keys the subtree under a key held only in the index),
  [ADR 0011](./0011-quarantine-release-rests-on-the-doomed-manifest.md)
  (the purge that a bin entry feeds),
  [ADR 0012](./0012-the-drain-carries-the-write-wave-forward.md)
  D6 (a strict-FIFO stall with no dead letter is a liveness defect), and
  [#24](https://github.com/FSM1/cipher-box-next/issues/24) lapse semantics (an EOL lapse is an
  availability event, never loss) with its D2/D5 renewal loop
- **Implemented by:** [FSM1/cipher-box#1658](https://github.com/FSM1/cipher-box/pull/1658)

## Context

The bin index record plane is the vault settings record plane. `blueprint/engine.md` says so
under "Bin index record", and ADR 0010 item 1 decided it. The blueprint therefore gave the bin
index every settings rule, and one of those rules was a carve-out: refuse a record past its
end-of-life, because the reader of that record is always its signer.

On the settings plane the carve-out costs nothing and buys something. It strands nobody, because
the session that holds the login secret republishes the record on the spot. It also bounds a
replay on a device that holds no sequence floor to compare against, and the record it would
otherwise adopt carries a bearer credential — a bring-your-own access token that the engine then
presents to a third party.
Amended by
[ADR 0034](./0034-a-degraded-settings-load-falls-back-to-the-last-verified-copy-and-never-widens-placement.md)
D9 on 2026-09-26: "republishes the record on the spot" now reads "the renewal set keeps a live
account's settings record inside its EOL".

On the bin plane the same rule is a permanent stall. Nothing on this plane re-signs the record
except the rewrite that a refusal blocks. The keyless re-PUT of the API carries the record's own
validity, so it extends nothing. The sub-EOL renewal loop walks the records below about 30 days
of remaining life, so it passes over a record that is already past its end-of-life. The drain is
strict FIFO. A refusal therefore holds the head of the whole operation queue for good, and the
trigger is an ordinary one: a vault that soft-deleted nothing for ninety days. ADR 0012 D6
already states that such a stall is a liveness defect.

A bin index carries no bearer credential. It carries entries that the owner sealed for the
owner. The trade that justifies the settings carve-out therefore reads differently here.

### The rule the code implements

- The load admits a record that is past its end-of-life. The record establishes the index, and
  the rewrite that the index feeds stamps a fresh end-of-life.
- Every other stage of the floor law is unchanged. The sequence floor, the mint-versus-adopt
  revision pair, and the three-rung degradation ladder all hold.
  Amended by
  [ADR 0034](./0034-a-degraded-settings-load-falls-back-to-the-last-verified-copy-and-never-widens-placement.md)
  D2, D5 and D6 on 2026-09-26: the mint-versus-adopt revision pair is ADR 0034 D6, and the
  three-rung degradation ladder is ADR 0034 D2 and D5.
- The load enrols the record it read in the session's renewal set. A live account therefore never
  reaches the lapse, because the session keeps the name alive without publishing anything.
- The load enrols only a record that cleared the whole floor law, and only a record for a name
  that this device already holds a sequence floor for. The renewal re-signs at `floor + 1`, so it
  promotes whatever it is given.
- The settings plane keeps its refusal. The carve-out now covers one record, and the blueprint
  states the reason at that record.

## Decision

**D1 — A lapsed bin index record establishes the index; it does not refuse the rewrite.** The
load reads it, the pass builds on it, and the rewrite that follows publishes a record with a
fresh end-of-life. The lapse is an availability event on this plane, as it is on every plane but
the settings plane.

**D2 — The settings carve-out does not carry over to the bin index.** The reason for that
carve-out is the bearer credential in the record that the settings load would adopt. A bin index
holds no such credential, so the reason does not apply. The blueprint states the carve-out at the
settings record alone.

**D3 — The load enrols the record in the session's renewal set.** This is the first bound on the
residual. An account that opens a session inside the ninety-day window never lapses, whether or
not it publishes.
Amended by
[ADR 0034](./0034-a-degraded-settings-load-falls-back-to-the-last-verified-copy-and-never-widens-placement.md)
D9 on 2026-09-26: this rule applies to both owner record planes, the settings record and the bin
index.

**D4 — The renewal set takes only a floor-passing record for a name this device already holds a
floor for.** This is the second bound. The renewal re-signs at `floor + 1` and promotes what it
is given, so it must never receive bytes that no load gated.
Amended by
[ADR 0034](./0034-a-degraded-settings-load-falls-back-to-the-last-verified-copy-and-never-widens-placement.md)
D9 on 2026-09-26: this rule applies to both owner record planes, the settings record and the bin
index.

**D5 — The end-of-life on a self-signed record is a liveness signal, not a trust signal.** What
bounds a replay on this plane is the per-name sequence floor. The floor is monotone, so a record
at or above it is the freshest record this device ever accepted, or a newer one.

## Alternatives rejected

**Keep the refusal, and give the renewal loop an arm for a lapsed record.** The loop would
resolve the name, find the record past its end-of-life, and re-sign it to restore the plane. The
loop re-signs at `floor + 1` on whatever the network serves. No load passes the floor law over
those bytes first, so the arm promotes a record that the adoption gate never admitted, and it
signs that record with the owner's own key. This moves a trust decision into a background job.
Rejected.

**Keep the refusal, and rebuild the index from nothing at a lapse.** A lapsed record would be
discarded, and the pass would publish a fresh empty index. The index is rewritten whole, so the
rebuild drops every entry that another device added. Each dropped entry holds the only key to a
re-keyed subtree (ADR 0010 item 3), so the drop is not a lost listing; it is a permanent loss of
the owner's soft-deleted data. Rejected.

## Consequences

1. **`blueprint/engine.md` changes when this ADR is accepted.** The "Bin index record" section
   listed the lapsed-EOL carve-out among the settings rules that carry over. It now states the
   opposite rule and its rationale. PR FSM1/cipher-box#1658 makes that edit already.

2. **The settings carve-out narrows to one record.** The blueprint sentence "A lapsed EOL is
   refused here, and only here" is now exact rather than approximate.

3. **A dormant vault drains.** A first soft delete after ninety days of no bin activity
   establishes the index and publishes, rather than holding the queue head with no dead letter
   and no reported cause.

4. **`CONTEXT.md` needs no new term.** The glossary already defines the bin index, the floor law,
   and the sequence floor. This ADR changes which of the settings rules the bin index inherits.

## Residuals

**E1 — Nothing on this plane bounds a record's age.** The per-name sequence floor bounds a
replay, and it admits any record at or above the floor however old that record is. The two
bounds of D3 and D4 hold this down: a live account never reaches the lapse, and no record that
the gate did not admit is ever promoted. The trust reading is that the floor is monotone, so an
admitted record is the freshest one this device ever accepted, or newer.

**E2 — A device that holds no floor for the name takes what the network serves.** This is the
case that the settings carve-out named, and it is now open on the bin plane. A fresh install that
resolves an owner-signed but stale index sees a short bin listing. D4 keeps that record out of
the renewal set, so nothing re-signs it, and the next resolve above the floor supersedes it. The
exposure is an incomplete restore list, not a disclosure and not a purge.

## Gate

- A load of a record past its end-of-life establishes the index, and the rewrite it feeds
  publishes.
- The published rewrite carries a fresh end-of-life.
- A soft delete on a vault that has been dormant for more than ninety days drains, rather than
  holding the head of the operation queue.
- A record below the sequence floor is refused, and it is never enrolled in the renewal set.
- A record for a name this device holds no sequence floor for is not enrolled in the renewal set.
- A settings record past its end-of-life is still refused.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
