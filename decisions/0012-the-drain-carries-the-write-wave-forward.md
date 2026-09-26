# ADR 0012 — The drain carries the write wave forward, and is the second sanctioned reader below the read-epoch floor

- **Status:** Accepted — the rule is in the code, from
  [FSM1/cipher-box#1641](https://github.com/FSM1/cipher-box/pull/1641)
- **Date:** 2026-09-01
- **Relates to:**
  [ADR 0003](./0003-sweep-population-and-below-floor-scope-roots.md)
  (the sweep's interior read, and the scope root that stays unreachable below its own floor),
  the lazy wave of [#26](https://github.com/FSM1/cipher-box-next/issues/26) D2, and
  [FSM1/cipher-box#1638](https://github.com/FSM1/cipher-box/issues/1638) (a mount write into a
  just-cut scope is refused as a trust violation)
- **Implemented by:** [FSM1/cipher-box#1641](https://github.com/FSM1/cipher-box/pull/1641)

## Context

A read rotation cuts the scope root and raises the scope's read-epoch floor at once. The lazy
wave re-seals the interior behind that cut. Every interior node the wave has not yet reached is
therefore below the floor **by construction**. `CONTEXT.md` defines the lazy wave as re-sealing
that ordinary writes and a background sweep carry. Only the sweep carried it. The drain refused.

The defect is FSM1/cipher-box#1638, and the cross-client suite reproduces it on a clean stack. A
member cuts a scope from one client. The member then writes a file at the mount inside that
scope. The next drain pass loads the target's record, and the adoption gate rejects it at the
epoch stage. The drain classified that rejection as an unclassified halt, which charges nothing
and retries for ever. The durable op queue is strict FIFO, so the op held the head of the queue
permanently. There was no dead letter, no event, and no progress. The class was also wrong: a
stale local write is not a trust violation, and the record the gate refused is the member's own.

A drain publish is an ordinary write. So the drain must carry the wave.

### The rule the code implements

- A drain pass anchors on the scope root: the epoch every record of the pass is sealed at, and
  the read-plane **history links** that root carries. Those links are the backward key-regression
  ratchet.
- A record the epoch stage rejects is re-read under the scope read seed of the epoch the record
  was actually sealed at, through `ChildAdopter::open_interior_under`
  (`crates/engine/src/net/child.rs`). The publish path then re-seals the body at the pass epoch,
  which carries the wave one node further.
- Only the **epoch** stage relaxes. It relaxes downward alone, and only to an epoch the ratchet
  derives from the scope root that this same pass already gated.
- The sequence bar drops to the replay bar, `Strictness::AtOrAboveFloor`
  (`crates/engine/src/gate/floor.rs`). That is the bar the sweep takes, and it is never weaker
  than the bar the record already passed.
- The read serves an **interior** node alone. `ChildAdopter::assemble_envelope` refuses any
  record that carries a grant section, on every path and before any floor stage runs, so a scope
  root below its own read-epoch floor stays unreachable (ADR 0003).
- The re-open moves no floor. The envelope id and scope transplant checks are unchanged. A record
  above the pass epoch is an honest race and is refused. The sealed body's AAD binds the record's
  own epoch, so a relabelled epoch opens under no seed the ratchet yields.

## Decision

**D1 — A member write into a scope below the read-epoch floor is served, not refused.** The
drain opens the target at the epoch the record was sealed at, and re-seals it forward at the
pass epoch. The op drains. The node leaves the sweep work-list.

**D2 — The drain is the second sanctioned reader below the read-epoch floor.** The number of
paths that bypass that floor is a security-relevant invariant, so it is stated here and named in
the code. There are two paths, and only two: the sweep's interior read, and the drain's
re-author of one. Each path holds the same four conditions. The record carries no grant section.
The read moves no floor. The sequence bar is the replay bar. The epoch is one the scope root's
own ratchet reaches. A third path needs its own decision.

**D3 — The relaxation is the epoch stage alone, and it relaxes downward alone.** No other gate
stage is weakened for this read, and a record above the pass epoch is refused.

**D4 — An epoch that the ratchet cannot reach is charged against the attempt budget, and is
bounded.** It is not a permanent refusal. The adoption gate authenticates the signature of each
history link and nothing about the order or the walkability of the chain, so the input is shaped
by whoever publishes the root. The pass also anchors on a cached root that a later pass may
supersede, so this pass cannot prove that a later pass fails too. A permanent dead letter
releases the staged blocks; the charged verdict preserves the staged version. A pass that holds
no history links at all holds no ratchet, and takes an uncharged hold that a later pass clears.

**D5 — Scope roots keep the rule of ADR 0003.** A scope root below its own read-epoch floor is
still not readable on this path. Admitting one would republish the scope's existing override
seed at the current epoch, which is a revocation bypass.

**D6 — A strict-FIFO stall with no dead letter is a liveness defect, never an accepted
outcome.** Every halt the drain takes either retries with no charge, or spends a bounded attempt
budget and ends in a dead letter that preserves the staged version.

## Alternatives rejected

**Refuse the op as a trust violation.** This is the behaviour FSM1/cipher-box#1638 reports. A
trust violation means a record failed to prove its authorship or its freshness. Here the record
is authentic, it belongs to the member's own scope, and the only stale thing is the local view.
The refusal also fails closed against the owner's own data, and no retry clears it. Rejected.

**Wait for the sweep to reach the node.** The sweep is an idle-cadence job. It carries no
guarantee that it runs before the next drain pass, so it gives the queued op no bound. The whole
queue waits behind the head op while the member writes more. The sweep also performs the same
read under the same relaxation, so deferring to it buys no safety at all. It buys only delay.

**Re-key the write at the mount against the new epoch.** This asks the mount to hold current
scope state at write time. The mount holds the pre-cut state for at least one pass by design,
because reads are cache-first. It also moves a trust decision to a layer that runs no gate.

**Dead-letter the op permanently when the ratchet cannot reach the epoch.** The generic
permanent arm releases the staged blocks, so this destroys the member's staged version. It also
rests on data an attacker shapes, as D4 states. One publish by a committed writer could then
abandon the queued write of another device. Rejected in review on PR #1641 and replaced by D4.

**Give the drain its own copy of the sweep's gated descent.** A second copy of a trust check is
the mistake that produced v1's revocation bypass. The descent stays in one place.

## Consequences

1. **`blueprint/engine.md` changes when this ADR is accepted.** The "sweep" section states:

   > Reading one is the single path that runs the sequence floor without the read-epoch floor —
   > a lagging node sits below that floor by construction, and carries no seed, grant blob or
   > commitment for the stage to protect; its body opens under the seed the scope's history-link
   > ratchet walks back to.

   The replacement wording is:

   > Reading one is one of exactly **two** paths that run the sequence floor without the
   > read-epoch floor. The other is the drain's re-author of a lagging interior node, which
   > carries the same wave for an ordinary write (ADR 0012). A lagging node sits below that floor
   > by construction, and carries no seed, grant blob or commitment for the stage to protect; its
   > body opens under the seed the scope's history-link ratchet walks back to. Both paths hold
   > the same conditions: the record carries no grant section, the read moves no floor, and the
   > epoch is one the scope root's own ratchet reaches.

   The sentence two lines later, "Runnable by any write-capable client; ordinary writes advance
   it for free", already predicted the drain. The two sentences disagree today, and the
   replacement removes the disagreement.

2. **The `Strictness::AtOrAboveFloor` doc names both takers.** PR #1641 made that edit already.
   The count is the invariant, so the doc states it rather than naming one example.

3. **A scope with active writers converges after a cut without any sweep.** Every ordinary write
   into the scope advances the wave by one node. The sweep remains the path for an idle scope.

4. **The drain load path costs one extra open for each lagging node it re-authors.** The
   assembled head is reused, so the extra open fetches no additional block.

5. **`CONTEXT.md` needs no new term.** The "Lazy wave" entry already names ordinary writes as a
   carrier. This ADR makes the drain match the definition that entry already gives.

6. **Two capabilities stay open, and this ADR closes neither.** The owner's own device still
   reaches a folder inside its own nested scope root on no plane, for read and for write. PR
   #1641 keeps both scenarios as ignored cases in `crates/engine/tests/mount_convergence.rs`.

## Residuals

**E1 — The accepted write-plane forgery window gains a cheaper trigger, and no new capability.**
A party who holds an old-epoch read seed and still holds a node write key can author a record at
an old epoch. That capability exists today, and `CONTEXT.md` "Forgery window" records it as an
accepted residual that `rotateScopeWrite` closes. Before this change, only the idle-cadence
sweep re-sealed such a record forward into the current epoch. An ordinary member write now does
the same. The capability does not widen, the bound does not move, and the eager set is
untouched. What changes is the cost of the trigger: it is cheaper and more frequent. Accepted on
that basis.

**E2 — A lagging node that no history link reaches costs one op its attempt budget.** The op
ends in a dead letter with its staged version preserved, which is the documented terminal state
for an op that cannot rebase. This replaces a silent permanent stall of the whole queue.

## Gate

- A cut, then a member write at the mount inside that scope, converges on the next drain pass.
- The re-authored record is sealed at the pass epoch, and the node leaves the sweep work-list.
- A record that carries a grant section is refused on this path, before any floor stage runs.
- A record whose sequence is below the replay bar is refused.
- A record whose epoch is above the pass epoch is refused.
- A record sealed at an epoch other than the one the caller ratcheted to opens under no seed.
- A re-open moves neither the sequence floor nor the read-epoch floor.
- A record whose epoch no held history link reaches spends the attempt budget, does not
  dead-letter on the first attempt, and keeps its staged version.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
