# ADR 0062 — A lapsed name revives only through the read that its plane runs

- **Status:** Accepted on 2026-09-30
- **Date:** 2026-09-30
- **Relates to:** `blueprint/engine.md` "Resolve/publish pipeline" (Revival), "Pointer planes" and
  "Vault settings load", `blueprint/api.md` "Republisher module and recovery", the `CONTEXT.md`
  terms "Recovery endpoint", "Vault pointer" and "Adoption gate",
  [ADR 0013](./0013-a-lapsed-bin-index-record-is-rewritten-not-refused.md) (no background job
  promotes a record that no gate admitted),
  [ADR 0034](./0034-a-degraded-settings-load-falls-back-to-the-last-verified-copy-and-never-widens-placement.md)
  (the settings ladder), and
  [ADR 0061](./0061-a-renewal-walk-over-every-owned-scope-renews-each-name-through-the-adoption-gate.md)
  (the renewal walk)
- **Implemented by:** FSM1/cipher-box#2337, FSM1/cipher-box#2338, FSM1/cipher-box#2339 and
  FSM1/cipher-box#2340, the four parts of FSM1/cipher-box#2108
- **Amends:** none

## Context

A vault whose owner is offline for more than 90 days lapses whole. Nothing revives a lapsed name
today. `eol_republish` and `eol_republish_inline` return `Ok(None)` for a lapsed record.
`net::revival::revive` has no production caller, checks only the signature and the floor, and takes
only an `/ipfs/` value, so a pointer record, whose value is an inline sealed block, cannot revive.
The vault pointer is in no renewal set. So after more than 90 days offline, a new device cannot
find the vault root, and it does not start.

## Decision

**D1 — A revival re-signs only a value that the read of its own plane admits, in its own steps.**

1. Fetch the last record from the recovery endpoint. A 429 answer retries later and fails nothing.
2. Corroborate it with the fan-out: each endpoint that answers reads `Absent` or serves a record
   at or below the recovered sequence. No answer refuses the revival, and a record below the
   durable floor is refused.
3. Give the record to the read of its plane: the root adopt (`gate::adopt`) for a scope root, the
   gated child resolve for another node, `open_repoint` and the pointer bar for a pointer record,
   and the bin index load for the bin index. The settings load refuses a lapsed EOL
   (`EolRule::RefuseAt`), so D4 gives the settings record its own rule.
4. Register the name, in batches of up to `REGISTRY_BATCH_MAX` names.
5. After the registration, the fan-out still reads `Absent`, or serves exactly the admitted record.
6. After the adopt commits, read the durable floor with no await before the signature. The floor
   must be at or below the admitted sequence S. Sign at S + 1 with the EOL `eol_from(now)` minus
   one day, as a renewal does (ADR 0061 D3 step 6), so a revival never wins a tie against a real
   record at the same sequence.

A refusal in step 3 of bytes that the plane served is a `TrustViolation`. A body that is not
available is an availability failure, not a `TrustViolation`.

**D2 — A revival re-signs the value unchanged, whatever its shape.** A head record re-signs its
`/ipfs/` value, and a pointer record re-signs its inline sealed block. A revival never re-seals a
body and never re-points a name.

**D3 — A name that no parent body names renews or revives at session start, before the first
tick.** These names are the vault pointer chain, the vault root, the settings record, the bin index
and the owned scope pointers. The vault pointer is an indexed chain: the engine revives indices 0
to k from the recovery endpoint, with the same probe one index past the last, before
`resolve_vault_pointer` runs. Thus a new device does not read a first run or an older root. The
engine loads settings again after a revival, because the settings load comes first (ADR 0034 D1).
The renewal walk of ADR 0061 revives each lapsed name that a parent body names, and it revives a
lapsed folder before it descends into it.

**D4 — The settings record revives only at exactly the floor.** The settings record carries a
bearer credential. A device revives it only when its floor equals the recovered sequence
(`Strictness::AtFloor`), and the load then sets the EOL rule aside for that one record. Any other
device takes the ADR 0034 ladder. Its first settings save with no floor takes the sequence of the
verified recovery record as its `Observed` sequence, so the save does not publish at sequence 1 and
an older device does not report `RolledBack` for good. The same rule holds when the load reports
`Expired` or `Unreadable` for a served record that verified under the account's own settings key:
the save signs above the sequence of that record, and the floor rises only on a confirm. When a
newer release wrote the body, the load holds nothing and the save is refused, so an older client
does not overwrite that body. For a lapsed record, the load fetches the head only to learn its
release and never adopts the record; an unknown release refuses the save as a newer one does.

**D5 — A device with no floor revives a name from the corroborated recovery record, and the user
sees it.** The shell shows a "restored from the server copy" state for such a vault. When another
owner device later reads a revived record below its own floor, or at a lower read epoch, its gate
reports a `TrustViolation`.

## Alternatives considered

- **Revive after the signature and the floor check only**, as `revive` does now. ADR 0013 rejected
  this shape: a background job would sign bytes that no gate admitted.
- **Reuse the renewal steps of ADR 0061 D3.** A lapsed name reads `Absent`, and a pointer adopt
  raises no floor, so no revival could sign.
- **No automatic revival: the owner starts it by hand.** A new device cannot start, so the owner
  cannot reach the command.
- **Rebuild a lapsed pointer from the root that the walk holds.** A new device holds no root yet.
- **Revive the settings record on each device.** A device with no floor can then re-sign an old
  record whose credential the owner replaced.
- **Refuse a revival on each device with no floor.** An owner who lost each device and was offline
  for 90 days can then never open the vault.

## Consequences

1. `blueprint/engine.md` "Resolve/publish pipeline", the Revival bullet, states D1, D2, D4 and D5.
   The Liveness bullet names the session-start check of D3 in this order: the vault pointer chain,
   the vault root, the settings record, the bin index, then each owned scope pointer when the walk
   proves its scope. A read that opens a lapsed folder moves that folder to the front of the
   revival order.
2. `blueprint/engine.md` states the pace: at most 25 recovery fetches a minute for each session,
   below the `recovery` throttle of 30 a minute for each account. A revival cycle runs its visits at
   that pace, not at the per-pass budget of ADR 0061. The anchor names revive in the first minute,
   so a new device starts at once. A vault of 10 000 names that lapsed whole needs about 400
   minutes of session time, which is 6 hours and 40 minutes.
3. `blueprint/web-client.md` and `blueprint/desktop.md` name the "restored from the server copy"
   state (D5).
4. `CONTEXT.md` adds the term "Revival" and extends "Recovery endpoint" with the D1 steps.
5. `blueprint/testing.md` adds two virtual-clock tests: a lapsed file record revives through the
   gate, and a device that starts after 100 days offline finds its vault root.
6. Accepted residual: a bad recovery server can give a new device an old copy of a record while
   the network has no copy. The device then restores that old copy and signs it again. For a vault
   pointer or a scope pointer from before a rotation, the old copy sets an old read epoch on the
   device. The device can then write new files under a key that a removed grantee still holds, so
   that grantee can read them. The user sees "restored from the server copy". Another owner device
   reports a trust violation only when the copy is below its floor or at a lower read epoch. A
   copy exactly one sequence behind is signed one above it, so it lands at that device's floor,
   and that device takes it with no signal. The owner accepted it on 2026-09-30.
