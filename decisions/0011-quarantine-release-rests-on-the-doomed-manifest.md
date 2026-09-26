# ADR 0011 — A quarantine release rests on the owner's doomed manifest, not on a live-namer proof

- **Status:** Accepted — the rule is in the code, from
  [FSM1/cipher-box#1570](https://github.com/FSM1/cipher-box/pull/1570) (merged, `cf6ca85ee`)
- **Date:** 2026-08-31
- **Relates to:** ADR 0010 item 7 (the hard-delete reclamation lands first and standalone),
  [FSM1/cipher-box#1434](https://github.com/FSM1/cipher-box/issues/1434) (delete reclaims
  nothing), and the reclamation-quarantine decision of 2026-08-26
- **Narrowed by:** [FSM1/cipher-box#1589](https://github.com/FSM1/cipher-box/issues/1589)
  (milestone v2.0.0)

## Context

A delete detaches a subtree. The decision of 2026-08-26 split what the delete may reclaim at
once from what it must hold. The target reclaims at once, because the shortened parent is a
record the delete pass itself resolved and republished. Every descendant waits.

The reason for the wait is the authorship of the evidence. A descendant is reached through a
`ChildRef`, and any holder of the scope's write seed authors a `ChildRef`. So the doomed walk
proves nothing about a descendant on its own. The delete therefore writes an owner-authored
**doomed manifest**: the version roots the owner's own device quoted for each descendant at
delete time (`crates/engine/src/sync/doomed.rs`, `Reclamation` and `Quarantined`). The owner
seals it, so no other writer redirects a debt into it after the fact.

`crates/engine/src/sync/drain.rs` then decides each quarantined descendant. The delete's own
pass never decides (`Settle::Hold`), because the snapshot it just repainted is this device's
own work. A later converged poll tick decides (`Settle::Decide`), under a per-pass proof budget
and a per-entry attempt ceiling.

### The rule the code implements

`prove_quarantine` reads the base snapshot first.

- The base **contains** the node: the verdict is `Retry`. The node waits, and no resolve is
  spent.
- The base does **not** contain the node: `decide_quarantined` runs. It resolves the node's own
  record with no cache and compares the version roots to the manifest. An exact match is
  `Release`: the name retires and the content unpins. A record that resolves and disagrees is
  `Refuse`, for good. A record this pass cannot establish is `Retry`.

So absence from the converged base snapshot **enables** a release. It never holds one. The base
is populated by the focus window rather than by a whole-vault walk, so that absence is not
complete evidence of unreachability.

The `blueprint/engine.md` "Retirement" text in `FSM1/cipher-box` states the opposite. It calls
the first half "a refusal and never an entitlement". The code contradicts that wording.

A review exchange on PR #1570 established the correct reading after the merge (discussion
`r3895741977` on that pull request, and the maintainer reply on it). The reviewer asked for
complete authenticated reachability evidence before any release. The maintainer accepted the
description of the mechanism, and kept the trade. This ADR records both halves, because the
trade is a decision and the wording was wrong.

## Decision

**D1 — The release proof is the owner's manifest plus local absence. No live namer is
consulted.** The engine asks no other party whether a link to the descendant still exists. The
two halves are the base snapshot and the descendant's own freshly resolved record.

**D2 — Absence from the converged base enables a release; presence holds one.** This is the
rule as implemented, and it is the rule as intended. The blueprint wording that calls the
snapshot half a refusal alone is wrong and is corrected.

**D3 — The folder case is accepted as stated.** A folder quotes no version root, so the
manifest half is vacuous for a folder and always holds. A folder release therefore rests on
absence from the base alone, and what it costs is a name retire. A folder owns no pins, so it
costs no unpin.

**D4 — The accepted bound is evidence this session established.** A release may rest only on an
absence that some poll of this session established. It may not rest on a base that no poll ever
painted. `FSM1/cipher-box#1589` carries that narrowing, its test cases, and the blueprint
wording fix. The bound restricts the first half; it adds no live-namer consultation, so it
returns no veto to a co-writer.

**D5 — A proof that does not hold costs a leak, never a loss.** A refused descendant keeps its
name registered and its content pinned. A descendant that no pass can establish drops unspent
after a bounded number of attempts, with the same cost. This is the behaviour the delete path
had before the proof existed.

## Alternatives rejected

**Require complete authenticated reachability evidence before a release.** The reviewer asked
for a live-namer traversal, and a retained quarantine whenever coverage is incomplete. This
hands an admitted co-writer a veto over the owner's own reclamation. A co-writer keeps one
`ChildRef` under a parent, and the owner never reclaims the descendant. The owner's ability to
reclaim their own storage must not depend on the co-operation of a party the owner is often
removing. Rejected for that reason.

**Hold the quarantine open until coverage is complete.** This is the same veto in a softer
form, plus an unbounded journal entry. An unlinked node joins no eager set, so a rotation
leaves it sealed at an epoch the gate refuses for good. Such an entry would never settle, and
it would starve the entries behind it.

**Reclaim nothing for a descendant.** This is the state before PR #1570: the descendant's name
retired while a live parent could still resolve it, and its content stayed pinned forever
(FSM1/cipher-box#1434). It trades a bounded availability risk for a permanent leak and a
permanent inconsistency. Rejected.

**Retire the name but keep the pins.** A half measure. It keeps the storage cost, and it still
breaks the reader who resolves through a live parent, because the record no longer resolves.
The two legs stand or fall together.

## Consequences

1. **An availability risk is accepted, and it is now written down.** A descendant whose record
   is unchanged, and which a live parent outside the focus window still names, can lose its pins
   and its registry rows.
2. **The folder form of that risk retires a name on the snapshot half alone**, because the
   record half is vacuous for a folder.
3. **`FSM1/cipher-box#1589` narrows the rule and closes the worst form of it.** A restarted
   session whose root resolves `Current` leaves the base unprojected, so today a pass can decide
   against an empty base. Under D4 that pass must hold.
4. **`blueprint/engine.md` "Retirement" changes when this ADR is accepted.** The pull request
   that closes `FSM1/cipher-box#1589` makes the edit. The text must say that absence enables a
   release, and it must state the accepted residual.
5. **Two test cases are owed**, and `FSM1/cipher-box#1589` carries them: a descendant that a
   live parent below an unfocused parent still names, and the folder form of the same case.
6. **The reviewer's finding stands as an accepted residual, not as a defect.** A future report
   of this path is answered by this ADR and by the bound in D4.

## Gate

- A quarantined descendant that the converged base still reaches is not released, and the pass
  spends no resolve on it.
- A quarantined descendant absent from the base, whose freshly resolved record matches the
  doomed manifest exactly, is released: its name retires and its content unpins.
- A descendant whose record resolves and disagrees with the manifest is refused for good.
- A pass whose base no poll of this session painted decides no quarantined descendant.
- A delete journals its quarantine, the process restarts, a second device re-links the
  descendant, and no pass unpins that descendant's content.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
