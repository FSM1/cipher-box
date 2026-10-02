# ADR 0067 — The floor law admits a closed list of raises, and the cold-start guard reads a vouched floor

- **Status:** Accepted on 2026-10-02
- **Date:** 2026-10-02
- **Relates to:** FSM1/cipher-box#2119 (the floor-law list in `CONTEXT.md` under-states the
  raises), FSM1/cipher-box#1920 (a one-device owner is locked out after a cut of the vault root),
  [ADR 0007](./0007-derived-idempotent-first-run-mint.md),
  [ADR 0014](./0014-a-verified-commitments-cut-epoch-raises-the-floor-without-an-unseal.md),
  [ADR 0016](./0016-a-durable-sequence-floor-key-is-a-name-label-not-the-name.md) D1,
  [ADR 0020](./0020-the-durable-op-queue-reads-the-previous-release.md),
  [ADR 0021](./0021-a-read-opens-an-epoch-lagged-interior-record.md) D2,
  [ADR 0025](./0025-revocation-under-the-link-first-model.md) D3,
  [ADR 0041](./0041-a-rotation-reads-every-floor-again-before-it-seals.md),
  [ADR 0063](./0063-a-rotation-step-that-stops-leaves-a-durable-owed-record-that-the-sync-pass-finishes.md),
  `blueprint/engine.md` "Adoption gate and floors"
- **Implemented by:** FSM1/cipher-box#2212 (D1 to D4)
- **Amends:** ADR 0014 D2 and E3 (the closed list of raises with no unseal)

## Context

The floor law says that a floor moves only on an AAD-confirmed unseal or a cold seed, with one
exception (ADR 0014). But the engine raises floors with no unseal at more sites, and the
blueprint sanctions some of them: an owner cut raises the read-epoch floor, and a pointer
`writeEpoch` raises the write-epoch floor on sight. The text does not tell a sanctioned raise
from a new one. Separately, a session that adopts a vault-root record above the epoch that the
vault pointer vouches raises its read-epoch floor. If the vouch never lands, `repoint_regression`
(`gate/floor.rs`) refuses the next cold start, and a one-device owner stays locked out.

## Decision

**D1 — A floor rises with no unseal only from one of three sources.** (a) An owner-signed field
whose signed preimage binds the scope, verified before the raise: the re-point object at a cold
seed, a pointer `writeEpoch` on sight, and the cut epoch of ADR 0014. (b) A value that this
owner device authored, after the publish that carries it lands. A raise before the publish is
admitted only when it makes the device more restrictive. (c) An epoch that a device holds by
construction when it mints a scope root. Each raise is a maximum. A field that the network
authors, or a grant blob carries, raises no floor. A local write clock (a revision mint counter,
a mint mark, the vault-pointer index mark) is not an adoption bar, and the law does not cover it.

**D2 — The list of raises is closed.** `blueprint/engine.md` names each raise that D1 admits. A
new raise enters the list only through an ADR or an amendment, also when it fits D1.

**D3 — The cold-start guard at the vault anchor reads a vouched floor.** The vouched floor is the
highest `minReadEpoch` that a vault pointer vouched to this device. It is a floor-store key in
the epoch namespace, the root scope id with its own suffix, the same shape as the vault-pointer
index mark. It rises in `cold_seed`, when the vouch of a vault-root cut lands, when
`catch_up_vault_pointer` lands its vouch, and when `vouch_over` reads a standing pointer that
already vouches the epoch. The read-epoch stage of `repoint_regression` compares
the vouched `minReadEpoch` with this key. A device without the key compares with the read-epoch
floor, as on main. The gated adopt still raises the read-epoch floor, so the gate still refuses
a pre-cut vault root in the session.

**D4 — The produce side keeps the read-epoch floor.** `check_repoint_publishable` and
`vouch_over` refuse a vault-pointer re-point whose `minReadEpoch` is below the read-epoch floor.
Each raise of the vouched floor also raises the read-epoch floor to at least the same value, so
the produce bar is never below the consume bar, and security rule 8 holds.

The rollback argument for D3. Only a holder of the login secret can sign a vault-root record:
the name key derives from the vault-root write seed (ADR 0007), the writer pseudonym from
`owner-pseudonym-seed`, and the override seed opens from the owner blob. The vault root takes no
grant and no link, so no grantee and no link holder can sign one. A holder of the login secret
can also sign a vouch and a new root, so D3 gives it no new power. A pointer below the highest
epoch that a pointer vouched to this device is still refused at cold start. The guard no longer
refuses a pointer that only lags a root that this device adopted but did not vouch.

## Alternatives considered

- **Keep "one exception" and treat the other raises as rotation detail.** The glossary then
  under-states the law, and a review cannot tell a sanctioned raise from a new one.
- **Raise every floor through an unseal of the published record.** Each raise then needs one more
  resolve, and an endpoint that withholds the record blocks it. A raise before the publish (the
  revocation floor) and the promotion seed have no record to unseal.
- **The rule of D1 with no closed list.** Each publish author then decides by itself. That is the
  defect class of FSM1/cipher-box#2119.
- **Lockout option A: the cut owes the vouch as owed rotation work.** It adds an `OwedStep` tag
  that the previous release cannot decode, so it lands over two releases (ADR 0020). It adds a
  cold-start exception keyed by local evidence. A vault-root entry that stays open stops the renewal of
  the vault-root names (ADR 0063 D4).
- **Lockout option B: at the vault root, the read-epoch floor follows the vault pointer.** A test
  failed: an owner device with a stale view signs an epoch-N root above the sequence of the
  epoch-N+1 root, and this device adopts it. The folder list goes from `["reports"]` to `[]`. B
  removes an in-session guard that main has.
- **Lockout option C: repair at cold start with no local evidence.** The vault pointer has no
  sequence floor, so the repair cannot tell its own cut from a replay. It can re-sign pointer
  fields that an attacker chose.
- **Lockout option D: a vouch catch-up in the tick.** The window gets smaller, but a vouch
  that fails until the session ends still locks out the device. The tick also holds the owner
  signature key.

## Consequences

1. `CONTEXT.md` "Floor law": "One exception, and the list of them is closed" becomes the three
   sources of D1 and the closed list of D2.
2. `blueprint/engine.md` "Adoption gate and floors" names each raise by its D1 source. The
   cold-start paragraph states D3 and D4.
3. `blueprint/core.md`: no change. The new key takes the `name-label` of ADR 0016 D1 like every
   floor-store key.
4. `blueprint/testing.md` floor-law matrix: a one-device owner restarts after a vouch that ran
   out and a tick, and after an unconfirmed root that landed and a tick; a session refuses a
   pre-cut root above the sequence of the cut root; a pointer below the vouched floor is refused.
5. The floor-store seam on web (IndexedDB) and desktop (the fsync journal) stores opaque keys,
   so neither host changes.
6. The key needs no release in two steps (ADR 0020). An older release never reads or raises the key. After a
   rollback, it compares with the read-epoch floor, and the lockout of FSM1/cipher-box#1920 can occur again.
   After the roll forward, the key does not hold a vouch that the older release saw, so the
   guard rests on the last value that this release wrote.
7. A device that is locked out at the upgrade has no key, so it stays locked out until a vouch
   lands.
8. The `gate/floor.rs` module doc lists the raises of D1 and cites this ADR.
9. ADR 0014 D2 and E3 carry an "Amended by ADR 0067 D1" sentence.

## Residuals

- None.
