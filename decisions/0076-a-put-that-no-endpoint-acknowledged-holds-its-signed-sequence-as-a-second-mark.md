# ADR 0076: A PUT that no endpoint acknowledged holds its signed sequence as a second mark

- **Status:** Proposed
- **Date:** 2026-10-15
- **Relates to:** [#2430](https://github.com/FSM1/cipher-box/issues/2430),
  [ADR 0054](./0054-a-dropped-versions-debt-carries-its-target-set-and-settles-above-the-acknowledged-sequence.md)
  D2 (the acknowledged mark),
  [ADR 0061](./0061-a-renewal-walk-over-every-owned-scope-renews-each-name-through-the-adoption-gate.md)
  D3 (the walk signs at `S + 1`),
  [ADR 0020](./0020-the-durable-op-queue-reads-the-previous-release.md) (a durable record reads
  the previous release), ADR 0062 D3 (the revival signs through the walk's path)
- **Implemented by:** not landed
- **Amends:** ADR 0054 D2, ADR 0061 D3 step 6

## Context

A record PUT that no endpoint acknowledges (`PublishError::AllEndpointsFailed`) writes no mark
under ADR 0054 D2, yet its bytes can land. When the dead letter's version is then dropped, the
settle retires content that the record at that name names once the endpoint serves it: a loss.
A mark held at the signed sequence of each outage pass climbs one sequence per pass, and every
outage dead letter then leaves a mark above the served sequence, which stops the renewal walk
and the revival of that name.

## Decision

**D1 — A PUT that no endpoint acknowledged holds its signed sequence as the node's
unacknowledged mark, under a second key.** The key is the acknowledged mark key with one suffix
byte: `cbx/ra/ | ownerTagLen(1) | ownerTag | node(16) | 'u'`. The value is the acknowledged
mark's sealed body (`ACKED_V1 | node | sequence | name`) under the `retire-ledger` kind. A hold
keeps the higher of the held and the new sequence. The encode refuses a sequence of zero or a
name that is not an IPNS name, and the decode reads such a body as unreadable (AGENTS.md rule
8). The previous release reads only the exact acknowledged key, so it does not see this one,
and its orphan GC spares the whole `cbx/ra/` prefix.

**D2 — The settle reads the unacknowledged mark, and the signature does not.** The settle of a
dropped version (`OwingRecord::Unconfirmed`) waits while the gated record is at or below the
higher of the two marks. The drain's signature clears only the acknowledged mark, so a retry
after an outage signs at the same sequence and nothing climbs. A mark that does not read moves
the signature: it stands for the sequence floor plus the attempt budget plus one, the highest
value either mark can hold.

**D3 — The renewal walk and the revival sign above the higher held mark, and do not refuse.**
With no mark, the walk signs at `S + 1`. With a mark above `S`, it signs one above the mark,
for example at `S + 2` when the mark is at `S + 1`. A mark that does not read stands for the
sequence floor plus the attempt budget plus one. The floor check of ADR 0061 D3 step 5 stays on
the admitted `S`. A write that another device signs at `S + 1` at the same time then loses to
the renewal and rebases. The revival takes the same rule.

**D4 — Only a confirmed publish above the unacknowledged mark clears it.** A publish that
confirms at exactly the mark's sequence ties the bytes that the mark stands for, so the mark
stays and a dropped version's debt keeps waiting. The next record above the mark, a later edit
or the walk renewal of D3, clears it. A mark that does not read clears on any confirmed
publish, which D2 signs above its bound.

**D5 — A dropped create settles once its name holds no record, whatever mark is held.** The
drain publishes a child before its parent and stops at the first failure, so no folder links a
create that dead-lettered, and bytes that surface later at its name are not reachable. The
vacancy rule of ADR 0054 D2 (every endpoint answers that it holds no record, and this device
holds no sequence floor for the name) applies with no mark condition.

## Alternatives considered

- **One mark, held at the signed sequence of each unacknowledged pass (D1, D2).** No new key.
  Rejected: the mark climbs up to the unattributed budget. Bytes that landed at the top of the
  climb hide up to 119 newer records of other devices when the endpoint heals, which is a loss,
  and a bound on the climb needs per-op state.
- **Carry the signed sequence on the debt, with no node mark (D1, D2).** The preserved dead
  letter and a version 4 ledger entry record the highest sequence the op signed. Rejected: three
  durable shapes change (the drain charges, the dead-letter name value, the ledger entry), and
  the debt waits for a second renewal, because the walk signs at that same sequence.
- **The walk keeps refusing above a mark (D3).** No change to ADR 0061 D3. Rejected: the settle
  waits for a record above the mark, and only the walk publishes one when the member does not
  edit again, so the record lapses at its EOL.
- **Clear the unacknowledged mark on any confirmed publish (D4).** Fewer waits. Rejected: a
  confirm at the mark's sequence can tie the dropped bytes, and a reader that reaches only the
  endpoint that holds them reads content that the settle retired.
- **Keep the vacancy wait for an acknowledged create (D5).** Rejected: no publish ever comes at
  the name of a dropped create, so its debt waits for ever.

## Consequences

- ADR 0054 D2 reads "no mark is held at that name" for the vacancy rule, which is what the code
  did, and carries an "Amended by" sentence for D2, D4 and D5.
- ADR 0061 D3 step 6 carries an "Amended by" sentence for D3.
- `blueprint/engine.md` "Liveness" and "Retirement" state the second mark, the walk rule and the
  vacancy rule, in the code PR.
- `blueprint/testing.md` names the tests for each item, the previous-release read and the encode
  refusal, in the code PR.
- A discarded outage dead letter's debt waits for the next record above the mark: the next edit,
  or the walk renewal inside its window.

## Residuals

None.
