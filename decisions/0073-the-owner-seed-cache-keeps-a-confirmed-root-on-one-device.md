# ADR 0073: The owner seed cache keeps a confirmed root on one device

- **Status:** Proposed
- **Date:** 2026-10-03
- **Relates to:** [#2139](https://github.com/FSM1/cipher-box/issues/2139),
  FSM1/cipher-box-next#39 D6, ADR 0002, ADR 0006, ADR 0068
- **Implemented by:** [#2292](https://github.com/FSM1/cipher-box/pull/2292)
- **Amends:** —

## Context

A writer can publish an owner blob that the owner cannot open. The random scope
seed cannot be derived from the login secret. A session-only cache loses the last
confirmed seed on restart. The planned vault share list has no durable record or
merge rule. Its design is too large for this cache repair.

## Decision

**D1 — Keep a sealed recovery entry per scope and name in the device's
`StagingStore`.** Use HPKE auth mode to self under owner-local kind `0x0b`,
`owner-seed-cache`. Use the existing name-label edge for opaque lookup keys.
The core codec stores the confirmed seed and epoch, signed IPNS record,
encrypted root block, and parent node seed when required. The block keeps
recovery independent of gateway retention and the disposable snapshot cache.
Each completed owner read saves its entry before floors advance. A probe or
refused read saves nothing. Updates cannot lower the saved epoch or sequence.
The store's failure-atomic replacement keeps the previous entry on write failure.

A failed current owner blob remains a trust violation and raises attributable
abuse. The engine gates the separate confirmed copy at the current floors.
It can read that copy and cut above the refused record's sequence. It does not
adopt or renew the refused record. This protects one device that retains its
store. [#2296](https://github.com/FSM1/cipher-box/issues/2296) extends the store to
an owner-authored vault record for all devices; it is natively blocked by #2139.

## Alternatives considered

- **A vault record first.** It protects all owner devices, but needs a record
  shape, merge rules, freshness rules, and retention rules. The local store
  supplies restart recovery while that work is designed.
- **A seed without a root copy.** The old seed does not open a rogue new epoch.
  Recovery would still depend on the network retaining the confirmed block.
- **Use the snapshot cache alone.** That cache is disposable and has no sealed
  seed. Clearing it would remove the recovery source.

## Consequences

- `CONTEXT.md` defines the owner seed cache as a device-local recovery source.
- `blueprint/engine.md` states the refresh points, recovery path, and coverage.
- `blueprint/core.md` specifies the body, bounds, kind, and KAT families.
- `blueprint/testing.md` names the behavior tests and their required CI gates.
- The old `cross_check` and its test-only `owner_entry` KAT family add no
  invariant: the root gate checks the ascent link and opens the body with the
  owner blob's seed. A different seed fails with `seal-open-failed`.
- Entries count toward the staging budget and remain until the device is forgotten.
- The sent-index stays unchanged. Its decision moves to the web UI wave in
  [#2297](https://github.com/FSM1/cipher-box/issues/2297).
- A current floor can bar an old copy. Local-store loss and content sealed only
  under a withheld epoch remain outside recovery. The latter needs a valid-seed
  holder. Sequence exhaustion and repeated writer races need the root-first
  name move in ADR 0068. This change supplies no such move.

## Residuals

None.
