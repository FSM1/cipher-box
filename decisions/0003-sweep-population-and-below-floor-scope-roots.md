# ADR 0003 — Sweep population, and the below-floor descendant scope root

- **Status:** Accepted — implemented in FSM1/cipher-box#1200 (merged)
- **Date:** 2026-08-05
- **Amends:** [#38](https://github.com/FSM1/cipher-box-next/issues/38) decision D4
  ("Consult discipline: polled, not fallback") — extends the pointer consult to a
  descendant scope root reached through a stale `directChildScopeIndex` name
- **Restates:** [#26](https://github.com/FSM1/cipher-box-next/issues/26) decision D2
  ("Cascade scope: root cut + background sweep") — the sweep's population is _interior
  nodes_, which the v2 blueprint's `### sweep` section lost; no change to the decision
  itself
- **Relates to:** [#38](https://github.com/FSM1/cipher-box-next/issues/38) decision D6
  (the direct-child-scope index and its self-heal)
- **Implemented by:** [FSM1/cipher-box#1025](https://github.com/FSM1/cipher-box/issues/1025)

## Context

`SweepResolver` is the last read-plane rotation seam without a production
implementation. #1014 landed the other two and stopped short of this one, because the
sweep as built cannot obtain its own work-list.

The epoch-lag predicate in `sweep_pass` selects a node whose published record epoch is
below its scope's durable read-epoch floor. The adoption gate's stage 5 rejects exactly
those records (`floor::check`, `RejectionReason::EpochBelowFloor`). So a resolver built
the way `OwnerRotationNet::gated_root` is built refuses every node the sweep exists to
repair. The original framing of #1025 asked what should _authenticate_ a below-floor
record so the owner can repair it. Two findings say that question has no good answer.

**Finding 1 — the sweep is walking the wrong population.** D2 of #26 splits the tree in
two: the **eager set** (the rotated scope root plus, as amended by #38 D5, every
transitively-reachable descendant scope root) is rotated _synchronously_ by the cascade;
**interior nodes** "ride a background sweep re-sealing epoch-lagged nodes". `CONTEXT.md`
agrees — epoch lag is "a node whose envelope epoch is behind **its scope's** current
epoch; readable via history links". The implementation inverted this: `sweep_pass`
enumerates the eager set and applies the epoch-lag predicate to descendant scope roots,
the population the cascade already handles eagerly. The blueprint's `### sweep` section
is where the drift entered — it kept "the work-list is the epoch-lag predicate" from #26
D8 but dropped D2's statement of _what_ lags.

**Finding 2 — a scope root cannot lag its own floor.** A scope root defines its scope's
epoch, and every floor advance is bounded by a record that already exists:

- `rotate_scope` and `cascade` both **publish first and raise the floor second**, so a
  crash between the two "never demands an unpublished epoch (no lockout)";
- `floor::advance_on_unseal` sets the floor _equal_ to the adopted record's epoch;
- `cold_seed`'s `minReadEpoch` is owner-authored and, per #38 D3, bumps only on
  owner-triggered read rotations — which publish first.

So `recordEpoch < floor` on a scope root never means "this node lags and needs
re-sealing". It means **the record we fetched is not the current one**. The most common
non-adversarial cause is a stale name: the parent's `directChildScopeIndex` still names
the child scope at a name a `rotateScopeWrite` has since moved.

Two consequences of the drift are worth recording. The index self-heal (#38 D6: "a scope
root encountered but missing from its parent's index is repaired and flagged") is
implemented as canonicalisation performed _during_ a lag re-seal, so it is unreachable
whenever the predicate is vacuous — and it is a different repair from the one D6
specifies. And `sweep_pass`'s only production caller is grant creation's convergence
gate (#26 D2: "Grant creation converges its subtree first"), whose `SubtreeNotConverged`
verdict therefore cannot fire: the gate passes vacuously, so "a new grantee cannot
regress through an ancestor scope's history" is currently unenforced.

## Decision

**D1 — the sweep's population is interior nodes.** Re-target the work-list at nodes
_within_ a scope whose envelope epoch is behind the scope's current epoch, per #26 D2.
Descendant scope roots are eager-set members and are not swept. The blueprint's
`### sweep` section is corrected to say so.

**D2 — a below-floor scope root is a name-staleness signal, handled by a pointer
consult.** When a scope root's record is refused at gate stage 5, the resolver returns a
distinct _superseded_ verdict — neither `Rejected` (a trust violation the caller must
not retry) nor `Unavailable` (a transport stall). The handler consults that scope's
pointer per #38 D4, re-resolves at the re-pointed `currentRootName`, and fails closed
only if the fresh record is still below the floor. This extends D4's consult discipline
from the cold-start/focus-tick root to any descendant scope root reached through a
possibly-stale index entry.

**D3 — the index self-heal is decoupled from any epoch comparison.** The D6 repair — a
scope root encountered during enumeration but missing from its parent's index — is
detectable from the walk alone. It runs on the enumeration result and is flagged there,
independent of whether any node is being re-sealed.
Amended by ADR 0041 D5 on 2026-09-26: the self-heal is a walk-time repair, and it writes only a name
that the walk resolved current.

### Rejected alternatives

**A repair-role gate variant** that keeps stages 1–3 and 6 and substitutes an owner-held
committed set for the record's. Rejected on security, not just on need. The sweep reuses
the scope's **existing override seed verbatim** — it mints none. Admitting a below-floor
record would therefore republish the _old seed_ at the current epoch, handing every
revoked reader who cached that seed a record that passes the gate. That is a full
revocation bypass, strictly worse than the stale-grant-set hole the variant was proposed
to close. The grant-set commitment is owner-signed and epoch-free by design, so it
carries no freshness of its own and cannot distinguish a replayed pre-rotation section;
the floor stages are the only thing that can.

**Re-sealing from owner-held state** rather than from the lagging record. Rejected on
architecture: the material a re-seal needs (each descendant's commitment, ledger, child
index, carried history links) would have to be mirrored locally, and #26 D8 fixes
"published records are the sole source of truth — no job records, no checkpoints".

## Consequences

- `SweepResolver` becomes implementable: its work-list is drawn from records the
  adoption gate _accepts_, so it composes with `OwnerRotationNet::gated_root` unchanged.
- The gate keeps its fail-closed posture at stage 5. Nothing is admitted below a floor;
  the below-floor case gains a _route_ (consult and re-resolve), not an exemption. AGENTS
  rule 6 is preserved as written.
- Grant creation's convergence gate becomes able to fire. This is a behaviour change at a
  security-relevant gate that has been silently passing, and it needs its own coverage —
  tracked separately from the sweep re-targeting.
- A stale `directChildScopeIndex` entry stops being an unexplained hard rejection and
  becomes a self-correcting consult, which also narrows #38 D6's poisoning surface: a
  wrong name now costs a pointer round-trip instead of a fail-closed stall.
- The self-heal starts running, so `flaggedIndexes` becomes non-vacuous for the first
  time; hosts that surface it should expect real traffic.

## Gate

- A below-floor descendant scope root whose pointer re-points to a fresh record is
  converged after the consult; one whose fresh record is _still_ below the floor is
  refused fail-closed. Distinct, asserted outcomes.
- A forged below-floor record is refused, and no consult path admits it.
- An interior node behind its scope's epoch is re-sealed to the current epoch;
  re-running the pass is a no-op (idempotence) and concurrent sweepers are safe under
  CAS.
- A scope root encountered but absent from its parent's index is repaired and flagged
  with no node re-sealed in the same pass — proving the self-heal no longer rides the
  epoch comparison.
