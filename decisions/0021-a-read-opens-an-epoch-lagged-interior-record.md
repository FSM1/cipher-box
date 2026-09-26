# ADR 0021 — A read opens an epoch-lagged interior record, and is the third sanctioned reader below the read-epoch floor

- **Status:** Accepted — `blueprint/engine.md` and `CONTEXT.md` reworded in FSM1/cipher-box#1915 (merged)
- **Date:** 2026-09-19
- **Relates to:**
  [FSM1/cipher-box#1911](https://github.com/FSM1/cipher-box/issues/1911) (an epoch-lagged file
  does not read after a cut),
  [ADR 0012](./0012-the-drain-carries-the-write-wave-forward.md)
  D2 (the two sanctioned readers below the read-epoch floor, and "a third path needs its own
  decision"),
  [ADR 0003](./0003-sweep-population-and-below-floor-scope-roots.md)
  (a scope root below its own floor stays unreachable),
  [ADR 0017](./0017-the-epoch-tag-is-a-key-selection-label-not-an-attestation.md)
  (the epoch tag is a key-selection label), the `blueprint/engine.md` "Adoption gate and floors"
  and "sweep" sections, and the `CONTEXT.md` "Epoch lag" and "Adoption gate" terms
- **Implemented by:** the fix for FSM1/cipher-box#1911, after acceptance.

## Context

A read rotation cuts the scope root and raises the scope's read-epoch floor at once
(`rotate_scope` in `crates/engine/src/rotation/rotate.rs`). The lazy wave then re-seals the
interior. Every interior node that no write has re-sealed is below the floor by construction
(`blueprint/engine.md` "sweep").

A read of such a file fails. The content read resolves the file through `resolve_child` with a
`ChildAdopter` (`crates/engine/src/facade.rs`, `crates/engine/src/net/child.rs`). The adopter
runs `floor::check` at `StrictlyNewer`, then at `AtFloor`. Both calls apply gate stage 5, and
stage 5 refuses the record with `EpochBelowFloor` (`crates/engine/src/gate/floor.rs`).
`EngineError::from_gate` maps every gate rejection to `TrustViolation`. The member sees a trust
violation on a file that is the member's own and that is not damaged.

The documents disagree about this read:

- `CONTEXT.md` "Epoch lag" says that a lagging node is "readable via history links".
- `CONTEXT.md` "Adoption gate" and `blueprint/engine.md` stage 5 apply the epoch floor to every
  resolved record, and the "sweep" section names exactly two readers that may skip it.

No text says that a lagging file must stay refused. No text lets a read admit one. ADR 0012 D2
requires a decision for a third reader. This ADR is that decision.

The sweep carries the wave, but it does not converge a scope in time for a read. The facade
runs `run_sweep` one time for each cut, with a bound of three passes. The idle-cadence job
`run_sweep_job` that the blueprint names has no production caller
(`crates/engine/src/rotation/sweep.rs`). That gap is a code defect against the current
blueprint text, and its fix needs no ADR. It is context here and not part of this decision.

## Decision

**D1 — The child resolve opens an interior record below the read-epoch floor.** When the child
gate refuses a record with `EpochBelowFloor`, the resolve does not fail. It anchors on the
scope root that this device gated at or above the floor, and takes that root's epoch and its
history links. It walks the seed back to the record's epoch with `seed_at_epoch`
(`crates/engine/src/rotation/reseal.rs`). It opens the record with
`ChildAdopter::open_interior_under`. The arm lives in `resolve_child`, so the content read and
the focus-window folder refresh get the same arm.

**D2 — The read is the third sanctioned reader below the read-epoch floor.** It holds the same
four conditions as the sweep and the drain:

1. The record carries no grant section. `ChildAdopter::assemble_envelope` refuses a grant
   section before any floor stage runs, so a scope root never reaches this arm.
2. The read moves no read-epoch floor.
3. The sequence bar is the replay bar, `Strictness::AtOrAboveFloor`.
4. The epoch is one that the ratchet of the gated scope root reaches, and it is not above that
   root's epoch.

**D3 — One seed walk serves the drain and the read.** The drain's `seed_for_lagging`
(`crates/engine/src/sync/drain.rs`) moves to a shared place, and both paths call it. Each path
maps its failure to its own error type. ADR 0012 names a second copy of a trust check as the
defect to avoid.

**D4 — The arm raises the per-name sequence floor after an unseal.** The raise comes only
after the AAD-confirmed unseal, it is monotonic-max, and it is deferred until the accepted
record is durable, as on the ordinary child adopt path. The reasons:

- The ordinary child adopt path and the sweep's interior read already raise it after an unseal
  (`floor::advance_sequence_on_unseal` in `crates/engine/src/net/rotation.rs`). A read that does
  not raise it keeps a rollback window open for the node for as long as no other path touches
  it.
- The raise cannot lock the member out. The floor rests on a record that exists and that
  opened. Every lagging reader takes the replay bar, which admits the record at the floor.
- The raise does not relax any stage. It only makes the replay bar of the next read stricter.

The drain does not raise the sequence floor on its re-open, because its publish moves the node forward
in the same pass. The read publishes nothing, so the read must raise the floor itself.

**D5 — The error class follows the cause.**

| Outcome                                                                        | Error class          |
| ------------------------------------------------------------------------------ | -------------------- |
| The record epoch is above the anchor epoch                                     | `ContentUnavailable` |
| No held history link reaches the record epoch                                  | `ContentUnavailable` |
| The device holds no gated anchor or no read seed for the scope                 | `ContentUnavailable` |
| The record carries a grant section                                             | `TrustViolation`     |
| The sequence is below the replay bar                                           | `TrustViolation`     |
| The record does not open under the seed that the ratchet reached (AAD or AEAD) | `TrustViolation`     |
| The envelope id or scope is not the expected node and scope (transplant)       | `TrustViolation`     |

An epoch above the anchor is an honest race with a fresher root. An epoch that no link reaches
can come from a link set that a committed writer shaped (ADR 0012 D4), and the blueprint already
reports a node that the retained window does not reach as unreachable, not as a trust
violation. Neither case is a verdict on the trust of the record, so `ContentUnavailable` is
correct for both.

## Trust argument

- **A scope root never reaches the arm.** Condition 1 holds on every path before any floor
  stage runs. The pre-cut root, which carries the old override seed, stays refused (ADR 0003).
- **The arm gives no key to a party that does not already hold it.** The seed comes only from
  the root that this device gated. A current member already holds every earlier epoch's seed
  through key regression. A revokee does not hold the current seed, so it cannot walk the
  ratchet. An interior record carries no seed, no grant blob and no commitment.
- **A relabelled record opens under no seed.** The read-body AAD binds the record's own epoch
  (ADR 0017), so the seed that the ratchet reaches for the claimed epoch does not open a body
  that was sealed at a different epoch. A body that a revoked writer seals fresh at the old
  epoch, with the old seed, is not relabelled and does open; that is residual E2.
- **A replay stays barred.** The replay bar applies (condition 3), and D4 raises it after each
  unseal.
- **The revocation boundary does not move.** The arm does not raise or lower the scope's read-epoch
  floor.

## Alternatives rejected

**(a) The parent names the child's epoch.** `ChildRef` has no epoch field
(`crates/core/src/seal/body.rs`). This needs a wire-format change and a parent rewrite for each
child re-seal. The ratchet already gives the same seed without it.

**(b) Reads wait for the sweep.** A read then has no time bound. A read-only member cannot carry
the wave, because the sweep needs write capability. An owner who stays offline, or a node that
leaves the retained window, makes a lagging file unreadable for good. The durable sweep is
still necessary as the write-side convergence path, but it is not a read fix.

**(d) Report `ContentUnavailable` and change nothing more.** This corrects the error class
only. The file stays unreadable until a write or a sweep reaches it.

## Consequences

1. **`blueprint/engine.md` changes when this ADR is accepted.** In the "sweep" section, the
   text

   > Reading one is one of exactly **two** paths that run the sequence floor without the
   > read-epoch floor. The other is the drain's re-author of a lagging interior node, which
   > carries the same wave for an ordinary write (ADR 0012).

   becomes

   > Reading one is one of exactly **three** paths that run the sequence floor without the
   > read-epoch floor. The second is the drain's re-author of a lagging interior node, which
   > carries the same wave for an ordinary write (ADR 0012). The third is the child resolve's
   > read of a lagging interior node, which serves a member read before the wave arrives
   > (ADR 0021).

   In the same section, "Both paths hold the same conditions: the record carries no grant
   section, the read moves no floor, and the epoch is one the scope root's own ratchet reaches."
   becomes "All three paths hold the same conditions: the record carries no grant section, the
   read moves no read-epoch floor, the sequence bar is the replay bar, and the epoch is one the
   scope root's own ratchet reaches."

   In the "Adoption gate and floors" section, stage 5 gains the sentence "An interior record below the
   floor is opened only by the three readers that the 'sweep' section names."

2. **`CONTEXT.md` changes when this ADR is accepted.** In "Adoption gate", "epoch at or above
   the scope floor" becomes "epoch at or above the scope floor, except for an interior record
   that one of the three sanctioned lagging readers opens under the scope root's ratchet". The
   "Epoch lag" entry needs no change: it already says "readable via history links".

3. **The `Strictness::AtOrAboveFloor` doc names three takers**
   (`crates/engine/src/gate/floor.rs`): the sweep's interior read, the drain's re-author, and
   the child resolve's lagging read.

4. **The fourth condition of ADR 0012 D2 is stated precisely.** ADR 0012 D2 and the blueprint
   say "the read moves no floor". The sweep's interior read already raises the per-name
   sequence floor after an unseal. The condition that protects revocation is the read-epoch
   floor, and this ADR states it in that form.

5. **A share recipient gets the same arm when shared reads land.** Today the content read
   resolves only the owner's vault root scope. A recipient holds the current seed and the
   gated root's history links, which is all the arm needs.

6. **No wire format and no op queue record changes.**

## Residuals

**E1 — A first read on a device with no sequence floor for the name admits an older pre-cut
record.** A server can serve any earlier record of the node that the replay bar admits. The
sweep reads under the same bar and then publishes that record forward, so the read adds no
exposure. D4 closes the window for every later read on that device. This is the same
trust-on-first-use bound as the ordinary child adopt on a new device.

**E2 — The forgery window now reaches readers.** During the name wave a revoked writer still
holds the old seed for an old name that the wave does not yet rotate, and the writer can seal a
plausible record at the old key-regression epoch there (`CONTEXT.md` "Forgery window", an
accepted residual). The epoch tag attests nothing about who sealed the body (ADR 0017). Before
this ADR, the adoption gate refused every record below the read-epoch floor at the reader, so a
forged old-epoch record did not render, and only the sweep and the drain opened such a record.
After this ADR, the lagging read opens a forged record on the same path that opens an honest
lagging record. The forged bytes can therefore render as file content on a reader's device
inside the window.

What holds with it:

- No new seed reaches the revoked writer. The arm walks backward from a scope root that the
  device gated.
- A scope root never reaches the arm. A record that carries a grant section is refused first,
  as a trust violation.
- The per-name sequence floor still bars a replay. D4 raises that floor after an AAD-confirmed
  unseal.
- The read moves no read-epoch floor.
- The window closes when the name wave reaches the node and re-seals it at the new epoch under
  a new name. FSM1/cipher-box#1923 is the open dependency of that bound.

## Gate

- A cut, then a read of a file that no write has re-sealed, returns the pre-cut bytes through
  the content read, the version list and the version content read. The test does not drive the
  sweep.
- The read does not move the scope's read-epoch floor, and it raises the per-name sequence
  floor to the record's sequence.
- A record below the floor that carries a grant section is refused as `TrustViolation`.
- A record below the replay bar is refused as `TrustViolation`.
- A record above the anchor epoch is `ContentUnavailable`.
- A record whose epoch no held history link reaches is `ContentUnavailable`.
- A record sealed at an epoch other than its tag opens under no seed and is `TrustViolation`.
- The drain and the read call one seed-walk function.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
