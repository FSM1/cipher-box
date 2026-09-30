# ADR 0062 — A lapsed name revives only through the read that its plane runs

- **Status:** Proposed
- **Date:** 2026-09-30
- **Relates to:** `blueprint/engine.md` "Resolve/publish pipeline" (Revival), "Pointer planes" and
  "Vault settings load", `blueprint/api.md` "Republisher module and recovery", the `CONTEXT.md`
  terms "Recovery endpoint", "Vault pointer" and "Adoption gate",
  [ADR 0013](./0013-a-lapsed-bin-index-record-is-rewritten-not-refused.md) (no background job
  promotes a record that no gate admitted),
  [ADR 0034](./0034-a-degraded-settings-load-falls-back-to-the-last-verified-copy-and-never-widens-placement.md)
  D2 and D5 (the settings ladder), and ADR 0061 (the renewal walk and its signature rules)
- **Implemented by:** not landed; FSM1/cipher-box#2108 tracks the change
- **Amends:** none

## Context

A name lapses when no session renews it for 90 days. The renewal walk of ADR 0061 keeps an active
vault alive, but a vault whose owner is offline for more than 90 days lapses whole. Today nothing
revives a lapsed name. `eol_republish` and `eol_republish_inline` return `Ok(None)` for a lapsed
record. `net::revival::revive` has no production caller, it checks only the signature and the
floor, and it takes only an `/ipfs/` value (`head_cid_from_value`), so a pointer record, whose value
is an inline sealed block, cannot revive. The vault pointer is also in no renewal set. So after
more than 90 days offline, a new device cannot find the vault root, and the device does not start.

## Decision

**D1 — A revival re-signs only a value that the read of its own plane admits.** The order is:

1. Fetch the last record from the recovery endpoint.
2. Corroborate it with the fan-out, as `revive` does: the routing set takes the tie, a routing set
   that does not answer refuses the revival, and a record below the durable floor is refused.
3. Give the record to the read that its plane runs. A node record goes through the gated child
   resolve or the root adopt. A pointer record goes through `open_repoint` and the pointer bar.
   The bin index goes through the bin index load. The gate does not refuse a record for its EOL.
4. Sign the admitted value at one above the higher of the floor and the recovered sequence, under
   the signature rules of ADR 0061 D3 steps 2 to 6.

A record that any step refuses is not revived, and the refusal of step 3 is a `TrustViolation`.

**D2 — A revival re-signs the value unchanged, whatever its shape.** A head record re-signs its
`/ipfs/` value, and a pointer record re-signs its inline sealed block. A revival never re-seals a
body and never re-points a name.

**D3 — At session start, the engine checks each name that no parent body names, in anchor order,
before the first tick.** The order is: the vault pointer, the vault root, the settings record, the
bin index, and then each owned scope pointer when the walk proves its scope. A name inside the
renewal window renews, and a lapsed name revives under D1. The vault pointer thus also gets its
renewal. The renewal walk of ADR 0061 revives each lapsed name that a parent body names, and it
revives a lapsed folder before it descends into it.

**D4 — The settings record revives only on a device that holds its sequence floor.** The settings
record carries a bearer credential, and the settings load refuses a lapsed record for that reason.
A device with no floor cannot tell a replay from the last record, so it does not revive the
record. It takes the ADR 0034 ladder, and its next settings save publishes a new record. Every
other name revives on a device with no floor for it, from the corroborated recovery record.

## Alternatives considered

- **Revive after the signature and the floor check only**, as `revive` does now. ADR 0013 rejected
  this shape: a background job would sign bytes that no gate admitted.
- **No automatic revival: the owner starts it by hand.** A new device cannot start, so the owner
  cannot reach the command that starts it.
- **Rebuild a lapsed pointer from the root that the walk holds.** A lapsed vault pointer is the
  only way to the root on a new device, so no root is held yet.
- **Revive the settings record on each device.** The recovery endpoint is not trusted, so a device
  with no floor can then re-sign an old record whose credential the owner replaced.
- **Refuse a revival on each device with no floor.** An owner who lost each device and was offline
  for 90 days can then never open the vault.

## Consequences

1. `blueprint/engine.md` "Resolve/publish pipeline", the Revival bullet, states D1, D2 and D4, and
   the Liveness bullet names the session-start check of D3.
2. `blueprint/engine.md` states the pace: at most 25 recovery fetches a minute for each session,
   below the `recovery` throttle of 30 a minute for each account. A revival cycle runs its visits at
   that pace, not at the per-pass budget of ADR 0061. The anchor names of D3 revive in the first
   minute, so a new device starts at once. A vault of 10 000 names that is lapsed whole needs about
   400 minutes of session time, which is 6 hours and 40 minutes.
3. `net::revival::revive` gets an inline arm and a caller, and the `ReviveError` set gains the
   refusal of step 3 as a `TrustViolation`.
4. `blueprint/testing.md` adds two virtual-clock tests: a file record that lapsed revives through
   the gate, and a device that starts after 100 days offline finds its vault root.

## Residuals

- A device with no floor for a name takes the recovery record that the routing set does not
  contradict. A recovery endpoint that serves an older owner-signed record, while the routing set
  has nothing, then rolls that name back, and the revival makes the rollback permanent. Does the
  owner accept this for a device with no floor?
- A user can open a lapsed folder before the walk reaches it. Must a read move that folder to the
  front of the revival order?
