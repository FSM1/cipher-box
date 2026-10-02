# ADR 0064 — The name wave reads a lagging interior node

- **Status:** Accepted on 2026-10-01
- **Date:** 2026-10-01
- **Relates to:** FSM1/cipher-box#2123 (a write revoke on a folder with any child fails),
  FSM1/cipher-box#2153, FSM1/cipher-box#2157 (the revokee can block its own revocation),
  [ADR 0012](./0012-the-drain-carries-the-write-wave-forward.md) D2,
  [ADR 0021](./0021-a-read-opens-an-epoch-lagged-interior-record.md) D2 and D5,
  [ADR 0041](./0041-a-rotation-reads-every-floor-again-before-it-seals.md),
  [ADR 0063](./0063-a-rotation-step-that-stops-leaves-a-durable-owed-record-that-the-sync-pass-finishes.md),
  `blueprint/engine.md` "sweep" and "rotateScopeWrite"
- **Implemented by:** FSM1/cipher-box#2153
- **Amends:** ADR 0012 D2 (the count of sanctioned readers below the read-epoch floor)

## Context

A write revoke cuts the read plane first and the write plane second (`rotate_on_cut`). After the
read cut, every interior node lags the new read epoch until the lazy wave reaches it. The name wave
of `rotateScopeWrite` gates each interior node at the read-epoch floor, so the first lagging child
stops the wave. The revoke fails, and the revoked writer keeps a write seed that derives every live
name (FSM1/cipher-box#2123). A write grant or a downgrade just after a read rotation fails the same
way. ADR 0012 D2 states that each new reader below the read-epoch floor needs its own decision.

## Decision

**D1 — The name wave opens an interior node below the read-epoch floor, and is the fourth
sanctioned reader below that floor.** The arm runs only when the gate refuses the node with
`EpochBelowFloor`. It anchors on the scope root that this wave passed through the full root gate,
and takes that root's epoch and history links. It opens the node through the child resolve's
`open_under_anchor` (one seed walk, ADR 0021 D3). It holds the four conditions of ADR 0021 D2: the
record carries no grant section, the read moves no read-epoch floor, the sequence bar is the replay
bar, and the epoch is one that the anchor's ratchet reaches and is below the anchor's epoch. Every
other refusal still stops the wave.

## Alternatives considered

- **Sweep the scope to convergence before the write cut.** Each node then publishes twice, once
  for the sweep and once for the wave. The sweep isolates a node that it cannot reach and goes on,
  so it does not prove convergence, and a node that lags again between the two passes still stops
  the wave.
- **Cut the write plane before the read plane in `rotate_on_cut`.** Then no child lags during a
  revoke. But a write grant or a downgrade after a read rotation still meets lagging nodes, so
  this fixes only part of the problem.

## Consequences

1. `blueprint/engine.md` "sweep": "exactly three" paths become "exactly four"; the fourth is the
   name wave's read of a lagging interior node (D1), and "All three paths" becomes "All four paths".
2. `blueprint/engine.md` "Adoption gate and floors" stage 5: "the three readers" becomes "the four
   readers".
3. `blueprint/engine.md` "rotateScopeWrite": the wave re-seals a lagging node at the root's epoch
   under the current read key, because the publish path refuses a seal below the read-epoch floor
   (ADR 0041). A node that does not lag keeps its epoch and its read key. The read override seed
   and `minReadEpoch` carry verbatim, and the read-epoch floor does not move.
4. `CONTEXT.md` "Adoption gate": "one of the three sanctioned lagging readers" becomes "one of the
   four".
5. `blueprint/testing.md` rotation matrix: a write revoke over a nested subtree, a downgrade just
   after a manual read rotation, and a write grant just after a read revoke move each lagging
   node; a lagging grandchild that does not open under the ratchet's seed is a trust violation;
   a child whose epoch no held link reaches is reported unreachable, not as a trust violation.
6. The `Strictness::AtOrAboveFloor` doc (`gate/floor.rs`) names four takers; FSM1/cipher-box#2153
   makes that edit.
7. ADR 0012 D2 carries an "Amended by ADR 0064 D1" sentence.
8. An epoch that no held history link reaches takes the unreachable class of ADR 0021 D5: it is
   not a trust verdict, and a retry does not clear it. The wave cannot move such a node, so the
   wave stops. The owed record of ADR 0063 finishes the rotation when that record lands.
9. Accepted residual: a revokee who holds an older epoch seed can seal a lagging record that the
   wave opens and moves into the new tree under the new key. The sweep and the drain (ADR 0012 E1,
   ADR 0021 E2) and the name wave over a current-epoch record already give that exposure.
   `CONTEXT.md` "Forgery window" bounds it.

## Residuals

- Which rule the name wave takes for an interior node that it cannot open or cannot reach: today
  the wave stops, and a re-drive meets the same node (FSM1/cipher-box#2157). That rule needs its
  own ADR. Amended by ADR 0065 D1 to D3 on 2026-10-02: the wave drops a node that it refuses
  for a cause in the record bytes at once, and a node that an endpoint can block after a bound.
