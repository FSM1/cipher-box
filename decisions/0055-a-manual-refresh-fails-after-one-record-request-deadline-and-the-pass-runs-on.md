# ADR 0055 — A manual refresh fails after one record-request deadline, and the pass runs on

- **Status:** Proposed
- **Date:** 2026-09-27
- **Relates to:**
  [ADR 0044](./0044-the-engine-owns-refresh-forcing-mailbox-transport-and-the-staging-budget.md)
  D1 (every forced pass goes through `Command::ManualRefresh`) and D2 (a refresh it could not land
  is a failure, not a repaint), [#33](https://github.com/FSM1/cipher-box-next/issues/33) D3
  (nocache) and D4 (the staleness ladder), the `blueprint/engine.md` "Sync core" section
  ("Staleness ladder" bullet), and the `CONTEXT.md` "Sync pass" and "Manual refresh" terms
- **Implemented by:** FSM1/cipher-box#2060 (closes FSM1/cipher-box#1956)
- **Amends:** ADR 0044 D2

## Context

ADR 0044 D2 names two ends for a manual refresh: what it landed, or a failure. A pass that stalls
on the record plane had a third: no end. `manual_refresh` awaited the pass with no bound, and the
`Reconciling` rung held while the pass ran. Staging run 35938670706 showed the owner's indicator on
`reconciling` for five minutes after a write grantee built inside a shared folder. The pass had in
fact reconciled the grantee's writes. A rung the host read during the pass was never replaced,
because the engine sent a rung change only against the last event it sent, not against the last
rung the host read. Both the refresh and the rung needed a bound. The open questions were which
clock measures it, and what happens to the pass at the bound.

## Decision

**D1 — The waiting refresh and the `Reconciling` rung are bounded by one host record-request
deadline, timed from the pass start, and the pass is not cancelled.**
`SyncTimingProfile::refresh_deadline` equals one record GET or PUT deadline, which neither profile
compresses: a pass that waits on more than one record request has stalled, not reconciled slowly.
At the deadline the tick loop answers every request waiting on the pass, and every request filed
until the tick ends, with `RefreshVerdict::Overdue`, which the host receives as
`EngineError::RefreshFailed`. The ladder stops reading `Reconciling` at the same instant and reads
from the last success. The pass runs to its own end: a pass cut mid-drain would strand what it had
half published, and a later refresh may still land.

## Alternatives considered

- **A clock per request, from its filing time.** A request filed late in a stalled pass would
  wait one full deadline more than the indicator, and the refresh and the rung would leave
  `Reconciling` at different moments. One bound would need three clocks.
- **Cancel the pass at the deadline.** The drain publishes in steps, and a cancelled pass strands
  what it had half published.
- **Several deadlines before the failure.** One record request is the unit the host already
  bounds. A pass that waits on a second one is stalled, and a stall reported after several
  deadlines is a `reconciling` state that lasts minutes.
- **Bound the wait in the host.** The host cannot tell a slow pass from a stalled one, and the
  engine owns refresh forcing (ADR 0044 D1).

## Consequences

1. `blueprint/engine.md` "Staleness ladder" says that `reconciling` lasts at most one
   record-request deadline from the pass start, and that the pass runs on.
2. `CONTEXT.md` "Manual refresh" names the overdue failure as the third way a refresh ends.
3. ADR 0044 D2 reads with D1 here: a pass past the deadline answers `RefreshFailed` too.
4. A rung the host reads counts as reported, so the pass that ends it sends the next rung, and the
   host's own dedup drops a repeat.
5. The tick loop wakes at each rung boundary while a pass runs, so the stale threshold is also
   reported during a long pass.
6. A cold cache stays `Reconciling` past the deadline. The ladder has no other rung without a
   last success, and the refresh itself fails at the deadline.
7. The web scheduler seam has no cancel, so a per-pass deadline timer outlives a short pass on
   web. About two such timers are alive at once at the poll cadence.

## Residuals

**E1 — Should the host pass its record deadline into the profile?** `refresh_deadline` and the
host record timeout are two values of 30 s that name each other in comments. A host that tunes
one must tune the other. The owner decides whether the host supplies the value.
