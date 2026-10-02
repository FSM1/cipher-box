# ADR 0066 — A different record at the sequence floor is a fork, not a trust violation

- **Status:** Proposed
- **Date:** 2026-10-02
- **Relates to:** FSM1/cipher-box#1984 (a record at the floor replaces another with no evidence),
  [ADR 0016](./0016-a-durable-sequence-floor-key-is-a-name-label-not-the-name.md),
  [ADR 0021](./0021-a-read-opens-an-epoch-lagged-interior-record.md) E2,
  [ADR 0031](./0031-the-bin-index-seals-symmetrically-under-a-login-secret-key-and-exists-from-genesis.md),
  [ADR 0034](./0034-a-degraded-settings-load-falls-back-to-the-last-verified-copy-and-never-widens-placement.md) D6,
  [ADR 0061](./0061-a-renewal-walk-over-every-owned-scope-renews-each-name-through-the-adoption-gate.md) D3,
  `blueprint/engine.md` "Resolve/publish pipeline"
- **Implemented by:** not yet implemented
- **Amends:** ADR 0061 D3 (steps 2 and 7)

## Context

Two holders of one write seed can each sign a record at one sequence. `fanout::scan` picks one
record at the top sequence and returns the others as `tied`. `resolve_gated` returns `tied`, but
only the drain reads it (`scope_root_candidates`, `resolved_bytes`); the tick root leg, the cold
start and `resolve_child_record` ignore it. At the floor, the resolve admits any record that
passes the gate again, and `keep_newest_last_known_good` keeps the record with the later EOL. So
a record that replaces another at one sequence leaves no evidence, the signer picks the winner
through the EOL, and the renewal walk then signs `S + 1` over one side. No signer gets a power
from a fork that a record at `S + 1` does not give. Most forks are honest races between two
devices of the owner, and the drain rebase heals them.

## Decision

**D1 — At the sequence floor, a different record is a same-sequence fork, and the resolve reports
it as its own outcome.** A fork is one of two things: a non-empty `tied` set from the fan-out, or a
fetched record whose bytes differ from the bytes that the snapshot cache holds for that name at
that sequence. Each record that `resolve_gated` resolves takes this rule: the vault root, each
scope root, and each node that `resolve_child_record` resolves. The settings record and the bin
index do not take it. They resolve through the record plane, and their sealed body revision keeps
its own rule (ADR 0034 D6, ADR 0031).

**D2 — A fork is not a trust violation.** The gate still runs on each record. The reader picks
one gate-passing record by a fixed total order, paints it as it paints a `Current` record, and
sends one event for each name and sequence in a session. The drain reads the other records from
the fork outcome, and its rebase heals the fork as it does today.

**D3 — The renewal walk does not renew a name that resolved as a fork in this cycle.** A renewal
at `S + 1` buries the record that the order did not pick, on each reader. The keyless re-PUT of
the republisher holds the pick alive. A later cycle renews the name when the fork has gone.

## Alternatives considered

- **Pin a fingerprint of the floor record beside the sequence floor (option A).** It detects a
  fork also after a loss of the snapshot cache. But the `FloorStore` seam holds only monotonic
  `u64` values, so a pin needs a new seam method with replace semantics on both hosts and in each
  test fake. A plain record hash at rest links the blind name label to a public record (ADR 0016),
  so the pin needs a keyed value and a KDF catalog decision. The cache already holds the bytes
  that the pin would hold.
- **Refuse a fork as a trust violation (option B).** Each honest race between two devices of the
  owner then raises `AttributableAbuse` against the owner's own device. `resolved_bytes` turns the
  verdict into `Halt::RecordRefused`, so the drain stops at the fork that its rebase must heal.
- **A total order alone, with no detection (option C alone).** Each reader converges on one
  record, but nothing records the fork, and the renewal walk still buries one side.
- **A fingerprint key in the sequence namespace, as `mint_revision` uses.** The floor store only
  raises a value to the maximum, so it cannot keep the first fingerprint. Each sequence also
  adds a key that nothing removes.
- **A sealed body revision, as the settings record has.** It orders the retries of one writer,
  not two writers: two devices mint separate counters, so the lower one reads as a violation. It
  also changes the wire format.

## Consequences

1. `CONTEXT.md` "Adoption gate": a different record at the floor is a same-sequence fork, not a
   failure (D1, D2). `CONTEXT.md` adds the term "Same-sequence fork" with the scope of D1.
2. `blueprint/engine.md` "Resolve/publish pipeline" states the total order of D2: the later EOL
   wins, then the lower record bytes in byte order. It replaces two different tie rules:
   `fanout::scan` takes the first endpoint at one EOL, and `keep_newest_last_known_good` keeps the
   held copy at one EOL. The Liveness bullet states D3.
3. `blueprint/engine.md` "Facade" adds the fork event. It carries the routing key alone. The
   event crosses the WASM seam, and `packages/client` adds its type.
4. `blueprint/testing.md` adds four tests: a fork through `tied`, a fork through the cache, one
   event for two resolves of one fork, and a walk that does not renew a forked name.
5. Accepted residual: a device with a cold or cleared snapshot cache sees a fork only through
   `tied`. When the endpoints serve one record, that device keeps the present rule.
6. ADR 0061 D3 steps 2 and 7 carry an "Amended by ADR 0066" sentence.
