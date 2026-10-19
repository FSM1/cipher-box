# ADR 0080: A flat cut re-seals the ascent links of nested scope roots

- **Status:** Accepted on 2026-10-19
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
write body that does not unseal, is also a trust violation. A superseded child name takes the
pointer consult of ADR 0003 D2.

Item D3 moved to Consequences on 2026-10-19.

**D4 — A flat cut checks the history window before it drops a seed.** A flat cut (`RotateNow`
and an owned scope exit) adds one history link to P. The 64 retained links
(`MAX_RETAINED_HISTORY_LINKS`) after a cut from epoch E reach back to epoch E-63. Every flat cut
runs the check once P reaches read epoch 64 (`E + 1 > 64`). The check re-reads P and probes each
child that P indexes. If a child C has a retryable owed re-seal that needs the seed of epoch O of
P, the cut refuses when `E + 1 - O > 64`. In that epoch range, the cut also refuses when a child
probe returns `AscentResidual::Retry`, because the seed that opens that child is unknown. Each
refusal is the retryable `RotateError::NestedRootOwed`. The cut publishes over the base of its own
first read of P. The cut returns a retryable lost race and publishes no record of P if the pre-cut
re-read adopts a later record of P (another device cut P in between), or if a park of this pass at
the name of P is above that base. After the lost-race check, a pre-cut re-read of P that does not
finish stops the cut. That failure keeps its class: an availability failure stays retryable, a
rejection keeps its trust verdict, and an unreadable record or a version skew is not retryable.
The host sees the check string `rot-read-nested-root-owed:<scope hex of C>`: `RotateNow` gives it
as ContentUnavailable, and the scope-exit debt gives it as the detail of the owed cut. Each
refusal holds until a later check finds no such child. The vouch-completion branch of the cut
adds no link and does not run the check.

## Alternatives considered

- **The full revoke cascade on a flat cut (D1).** Rejected: the flat scope-exit rule holds, each
  old-seed holder stays a grantee, and the cascade mints a fresh seed for each nested root.
- **A drain retry through a new `OwedStep` variant (D2).** Rejected: it changes the durable shape
  of ADR 0063, and the published records already carry each fact that the re-seal needs.
- **Proceed with the cut and lose C (D4).** Rejected: the cut drops the last seed that opens C, and
  C stays unprovable with no repair path.
- **Keep the needed link past 64, up to the 256-link decode bound (D4).** Rejected: it changes the
  retention rule of `blueprint/core.md`.
- **Exempt the scope exit from the refusal (D4).** Rejected: a scope exit strands C the same way,
  and the scope-exit debt already retries an owed cut.

## Consequences

- `blueprint/engine.md` "rotateScope": an owner flat cut (`RotateNow`, an owned scope exit) also
  re-seals the ascent link of each indexed child scope root under the new seed of the scope.
- `blueprint/engine.md` "rotateScope": from read epoch 64, a flat cut refuses as retryable when it
  would drop a history link that an owed child needs or when a child probe does not finish, and a
  pre-cut re-read of the scope that does not finish stops the cut with the class of its failure
  (D4).
- `blueprint/engine.md` "sweep": a full pass also re-seals the ascent link of each indexed child
  scope root that opens only under an earlier seed of the scope, and the re-seal emits one event
  for each child and verified record sequence and at most one ascent pointer event for each child
  in a session.
- ADR 0003 D1 carries an "Amended by" sentence for D2.
- ADR 0063 does not change: the re-seal keeps no durable state, and after a crash the idle sweep
  repeats D2.

## Residuals

- The grantee scope-exit arm (`GranteeRotationNet`) calls `rotate_scope` directly and has the same
  gap. Does a grantee re-seal the ascent links of the nested roots too?
- A nested scope root that the index of P omits has no repair path under this ADR. Do we accept
  this gap?
- The refusal of D4 does not protect a superseded child, because the cut net refuses the pointer
  consult. Do we accept this?
- A child that returns `Retry` holds every flat cut of P at read epoch 64 and above, with no time
  limit. A child that no endpoint ever serves thus blocks the cut. Does the cut hold on every
  `Retry` (the code now), or only on a child that an endpoint served?
- A background read can adopt a cut of another device after the cut restores its held base and
  before the cut signs. The cut can then still sign above that base. Main has the same window on
  every flat cut, and FSM1/cipher-box#2496 tracks it. Do you accept that this ADR leaves that
  window to that issue?
