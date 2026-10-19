# ADR 0080: A flat cut re-seals the ascent links of nested scope roots

- **Status:** Proposed
- **Date:** 2026-10-19
- **Relates to:** [FSM1/cipher-box#2492](https://github.com/FSM1/cipher-box/issues/2492),
  [ADR 0003](./0003-sweep-population-and-below-floor-scope-roots.md),
  [ADR 0063](./0063-a-rotation-step-that-stops-leaves-a-durable-owed-record-that-the-sync-pass-finishes.md)
- **Implemented by:** [FSM1/cipher-box#2493](https://github.com/FSM1/cipher-box/pull/2493)
- **Amends:** ADR 0003 D1

## Context

A flat cut of a scope P is a manual `RotateNow` or an owned scope exit. It mints a new override
seed for P and keeps the `directChildScopeIndex` of P. The ascent link of each nested scope root C
is sealed to a keypair that `nodeSeed(P override seed, C)` derives. The flat cut did not re-seal
these links, and the sweep stops at each scope root. After the cut, the boundary walk could not
prove C, and the writes of the owner under C stalled.

## Decision

**D1 — A flat cut of P owes a same-epoch, metadata-only re-seal of the ascent link of each child
scope root that P indexes.** The re-seal seals the ascent link of C under the new seed of P. C
keeps its override seed and its read epoch: `prev` is none, and the re-seal adds no history link.
Only the ascent link of C and its record sequence change. This is not the revoke cascade: C gets
no fresh seed, and no row leaves a grant set. The flat scope-exit rule ("rotateScope") does not
change.

**D2 — The cut and the full sweep pass of P both run the re-seal, from published records alone.**
The cut runs it after its publish lands. Once P reaches read epoch 64, every flat cut also runs it
before its publish (D4). A full sweep pass of P runs it again. To re-seal C, the owner gates C
under each earlier seed of P that the authenticated history-link ratchet of P reaches, newest
first. Each try runs the full adoption gate, and the floors of C do not change. An ascent-link
mismatch (a public-half mismatch) has its own gate verdict. Only that verdict makes the owner try
the next older seed. Each other availability verdict gives a retry. At the first seed that opens
C, the owner re-seals the ascent link under the current seed of P. The sweep still does not rotate
or sweep a descendant scope root. It only re-seals the ascent link of an indexed one, as the index
self-heal already republishes metadata. These are trust violations: a child record whose head the
read refuses, a gate or floor rejection, a refused head block, and a record-byte refusal under the
seed whose public half matched (`OwnerSeedRefused`: a read body or blob that does not open, or an
ascent payload that does not cross-check). A re-seal error that no retry clears, for example a
write body that does not unseal, is also a trust violation. The engine emits one event for each
child and record sequence in a session. The key is the verified record sequence, or 0 when the
record itself does not verify. A rejected pointer consult emits one event for each child and
pointer. A pointer that the on-access consult already rejected and reported gets no second event.
A superseded child name takes the pointer consult of ADR 0003 D2. A child that no seed in the
retained window opens is a settled residual.

Item D3 moved to Consequences on 2026-10-19.

**D4 — A flat cut refuses as retryable only when it would drop a history link that an owed child
still needs.** A flat cut (`RotateNow` and an owned scope exit) adds one history link to P. The 64
retained links (`MAX_RETAINED_HISTORY_LINKS`) after a cut from epoch E reach back to epoch E-63.
Every flat cut runs the check once P reaches read epoch 64 (`E + 1 > 64`). A served child C has a
retryable owed re-seal that needs the seed of epoch O of P. The cut refuses only when
`E + 1 - O > 64`. The refusal is `RotateError::NestedRootOwed`. The cut publishes over the base of
its own first read of P. If the pre-cut re-seal read adopts a later record of P (another device cut
P in between), the cut returns a retryable lost race and publishes nothing. The host sees the check string
`rot-read-nested-root-owed:<scope hex of C>`: `RotateNow` gives it as ContentUnavailable, and the
scope-exit debt gives it as the detail of the owed cut. The refusal holds until the re-seal of C
lands. The vouch-completion branch of the cut adds no link and does not run the check.

## Alternatives considered

- **The full revoke cascade on a flat cut (D1).** Rejected: the flat scope-exit rule holds, each
  old-seed holder stays a grantee, and the cascade mints a fresh seed for each nested root.
- **A drain retry through a new `OwedStep` variant (D2).** Rejected: it changes the durable shape
  of ADR 0063, and the published records already carry each fact that the re-seal needs.
- **No repair.** Rejected: nested scope roots stay unprovable until a revoke, as in
  FSM1/cipher-box#2492.
- **Proceed with the cut and lose C (D4).** Rejected: the cut drops the last seed that opens C, and
  C stays unprovable with no repair path.
- **Keep the needed link past 64, up to the 256-link decode bound (D4).** Rejected: it changes the
  retention rule of `blueprint/core.md`.
- **Exempt the scope exit from the refusal (D4).** Rejected: a scope exit strands C the same way,
  and the scope-exit debt already retries an owed cut.

## Consequences

- `blueprint/engine.md` "rotateScope": a flat cut also re-seals the ascent link of each indexed
  child scope root under the new seed of the scope.
- `blueprint/engine.md` "rotateScope": a flat cut that would drop a history link that an owed child
  needs refuses as retryable (D4).
- `blueprint/engine.md` "sweep": a full pass also re-seals the ascent link of each indexed child
  scope root that opens only under an earlier seed of the scope.
- ADR 0003 D1 carries an "Amended by" sentence for D2.
- ADR 0063 does not change: the re-seal keeps no durable state, and after a crash the idle sweep
  repeats D2.

## Residuals

- The grantee scope-exit arm (`GranteeRotationNet`) calls `rotate_scope` directly and has the same
  gap. Does a grantee re-seal the ascent links of the nested roots too?
- A nested scope root that the index of P omits has no repair path under this ADR. Do we accept
  this gap?
- A child whose GET fails at the pre-cut check does not hold the cut. A parent probe that fails does not
  hold the cut. The seed of that child can then drop from the window. Do we accept this?
- The refusal of D4 does not protect a superseded child, because the cut net refuses the pointer
  consult. Do we accept this?
