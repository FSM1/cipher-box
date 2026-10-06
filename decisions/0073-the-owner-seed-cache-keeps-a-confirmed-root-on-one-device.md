# ADR 0073: The owner seed cache keeps a confirmed root on one device

- **Status:** Implemented
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

**D1 — Keep one sealed recovery entry per scope in the device's `StagingStore`.**
Use HPKE auth mode to self under owner-local kind `0x0c`, `owner-seed-cache`.
Use the existing name-label edge on the prefix and scope id for the lookup key.
The core codec stores the confirmed epoch and write epoch, signed IPNS record,
fetched root block, and parent node seed when required. It stores no scope
seed: recovery opens the owner blob in the block again. The block permits
recovery when neither a gateway nor the snapshot cache holds it.
Each completed owner read tries to save its entry before floors advance. A
failed cache write does not stop the read or floor advance. A probe or refused
read saves nothing. At one name, only a greater sequence replaces the entry;
the gate holds the epoch floors, so a keyless root also replaces it. A
confirmed read at a new name replaces the old name's entry unless its
owner-signed cut epoch is lower. A keyless read has no write epoch, and the
gate binds the owner-signed grant set to the name, so only a name the owner
chose can enter. A corrupt entry is absent and can be replaced; a local failure
cannot accuse a writer, and the network record keeps its trust verdict.

**D2 — Use the confirmed copy as the durable source for recovery and ADR 0068.**
A failed current owner blob stays a trust violation and raises attributable
abuse. The engine gates the separate confirmed copy at the current floors.
The owner rotation uses `RootFallback::last_copy`: it moves the root first,
publishes nothing at the old name, and keeps no grant row (ADR 0068 D3 and D5).
It does not adopt or renew the refused record. This protects one device that
retains its store. The vault record for all owner devices is not landed.
Amended on 2026-10-06 by FSM1/cipher-box#2344: a cold start whose root resolve
adopts nothing also opens the cached copy, at the current floors.

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
  owner blob's seed. A different seed fails with `ascent-link-mismatch` or
  `seal-open-failed`.
- Entries do not count toward the upload budget. A scope delete removes the
  entries before the publish that completes it, as a best effort. Each scope
  has at most one entry, bounded by the core codec.
- Sign-out keeps the sealed entries for the next session of that account.
  Account switch keeps them under separate account labels and sealing keys.
  Forget-device removes them with the staging store.
- The sent-index stays unchanged. Its decision moves to the web UI wave in
  [#2297](https://github.com/FSM1/cipher-box/issues/2297).
- A current floor can bar an old copy. Local-store loss and content sealed only
  under a withheld epoch remain outside recovery. The latter needs a valid-seed
  holder. The root-first name move follows ADR 0068, also at sequence exhaustion.
- A keyless entry has no write seed and no owner-write blob. It recovers reads,
  but the cut from that device waits for a copy with the write seed or for
  another owner device.

## Residuals

None.
