# ADR 0078: An absent head block is unavailable on every reader route

- **Status:** Proposed
- **Date:** 2026-10-18
- **Relates to:** [#2448](https://github.com/FSM1/cipher-box/issues/2448),
  [ADR 0029](./0029-a-record-head-block-follows-placement-and-the-hosted-leg-alone-can-fail-an-op.md)
  D1 (a head block under `External` goes to the member's own node only),
  [ADR 0062](./0062-a-lapsed-name-revives-only-through-the-read-that-its-plane-runs.md) D1 (a body
  that is not available is an availability failure),
  [ADR 0065](./0065-the-name-wave-drops-a-node-that-it-cannot-move-and-an-owed-cut-ends-within-a-bound.md)
  D3 (a stop that an endpoint can cause),
  [ADR 0068](./0068-an-owner-rotation-reads-a-refused-scope-root-from-its-last-copy-and-moves-the-root-first.md)
  D1 and consequence 6 (honest lag),
  [ADR 0071](./0071-a-below-floor-record-while-an-endpoint-fails-is-unavailable-not-a-trust-violation.md)
  D1, AGENTS.md rule 6
- **Implemented by:** [#2474](https://github.com/FSM1/cipher-box/issues/2474)
- **Amends:** ADR 0068 D1 ("Readers that are not an owner rotation do not change")

## Context

A head block is absent when every block source answers 404 or 410 for the CID that a verified
record names (`HeadBlockAbsent`). The record passed only its signature check and the CID decode;
no stage of the adoption gate ran. When every record endpoint answered, the boundary walk, the
renewal walk root admit, the grantee rotation root read and the write wave scope boundary read
this as a trust violation. The vault root resolve, the child resolve, the inbox, the drain and
the revival read it as unavailable. ADR 0068 D1 settles only the owner rotation. The owner ruled
on 2026-10-18.

## Decision

**D1 — Every reader that is not an owner rotation reads an absent head block as unavailable,
whether or not an endpoint failed.** It adopts nothing, raises no floor, keeps last-known-good,
sends no trust event, and reads again later. A boundary walk that meets it is unavailable, not
rejected, and a rejection of another scope root in the same walk still holds. The renewal walk
reports the scope root as a failed renewal, not as a rejection.

**D2 — The root gate keeps `HeadBlockAbsent` as its own verdict, and each reader folds it.** The
owner rotation reads it as ADR 0068 D1 states: a fallback at once on a command, past the bound of
ADR 0065 D3 in a sync pass re-drive, with one trust event for each refused record. Every other
reader folds it to unavailable under D1. An absent head block met while a record endpoint failed
stays unavailable on every route, the owner rotation included (ADR 0071 D1).

## Alternatives considered

- **Rule R: an absent head block is a trust violation on every route.** Under `External`
  placement the head block is only on the member's own node (ADR 0029 D1), and the read sources
  are the accelerator and the public gateways. When that node is offline, each source can answer
  404, so an honest record gives a trust event and the revival refuses it. This contradicts ADR
  0062 D1, ADR 0065 D3 and ADR 0068 consequence 6. Also, a source is untrusted infrastructure:
  a 404 from every source then raises `AttributableAbuse` on every route.
- **The split rule: a trust violation for a scope root, unavailable for a child.** No reason
  supports the split. Before the head block, a root and a child pass the same check, the record
  signature. The owner commitment and the ascent link are inside the block. A writer who holds the
  write scope seed can sign, at either name, a record whose block no source holds. Thus the root
  and the child have the same exposure.
- **Collapse `HeadBlockAbsent` into `Unavailable` at the gate.** Then the owner rotation cannot
  fall back on a planted root whose block no source holds, and the ADR 0068 problem returns.

## Consequences

1. ADR 0068 D1 carries an "Amended by ADR 0078 D1" sentence.
2. `blueprint/engine.md` "rotateScopeWrite" states D1 beside the owner rotation rule.
3. The renewal walk reports an absent head block of a scope root with a failed report and the
   detail `NO_HEAD_BLOCK`, as it reports `NO_RECORD` for a name with no record. The host then
   gets `renewalFailed`, so a grant does not lapse with no signal.
4. A boundary walk that meets an absent head block sends no trust event, and the session does not
   refuse moves and restores for good. They wait until a walk names the whole boundary set.
5. The grantee rotation root read and the write wave scope boundary read stop as unavailable, and
   a later pass reads again.
6. `blueprint/testing.md` names the tests of #2474 for each changed route.
7. `decisions/README.md` lists this ADR.

## Residuals

- The renewal walk keeps back a child whose head block no source holds, with no report. Does
  it report the child with `NO_HEAD_BLOCK` too?
