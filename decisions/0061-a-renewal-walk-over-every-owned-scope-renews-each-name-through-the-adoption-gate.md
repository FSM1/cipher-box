# ADR 0061 — A renewal walk over every owned scope renews each name through the adoption gate

- **Status:** Proposed
- **Date:** 2026-09-30
- **Relates to:** `blueprint/engine.md` "Resolve/publish pipeline" (Liveness) and "sweep",
  `blueprint/api.md` "Republisher module and recovery", the `CONTEXT.md` terms "Write seed",
  "History link" and "Name wave", [ADR 0006](./0006-owner-local-sealed-store.md) and ADR 0030 D11
  (the owner-local structure), [ADR 0010](./0010-recycle-bin-is-an-owner-sealed-index.md) (the
  bin), [ADR 0013](./0013-a-lapsed-bin-index-record-is-rewritten-not-refused.md) (no background
  job promotes a record that no gate admitted),
  [ADR 0020](./0020-the-durable-op-queue-reads-the-previous-release.md),
  [ADR 0033](./0033-every-attacker-sized-field-has-one-canonical-form-and-a-symmetric-fail-closed-bound.md),
  and ADR 0062 (the revival of a lapsed name)
- **Implemented by:** not landed; FSM1/cipher-box#2108 tracks the change
- **Amends:** [ADR 0057](./0057-an-observer-outside-a-session-reads-a-verified-record-and-adopts-nothing.md)
  Context (the republisher extends no validity)

## Context

A record lapses 90 days after its signature. The engine re-signs a record only for a name in the
session's renewal set (`net::liveness`, `HeldRecords`): the vault root, the records that this
session published, the owned scope pointers, the settings record and the bin index. A read holds
nothing. The API republisher re-PUTs the same bytes, so it extends no validity. Thus a file or
folder record that no session publishes lapses at 90 days, even when the owner opens it each day,
and a lapsed folder hides its subtree. v1 re-signed each name in a TEE; v2 has none.

## Decision

**D1 — A renewal walk renews each name of the vault, and a read renews nothing.** The liveness
pass runs a bounded part of the walk after the sub-EOL renewal of the renewal set, and the first
pass of a session runs it too. The roots of the walk are the vault root scope, then each other
owned scope in scope-id order, then each bin index entry until its purge, because a binned
subtree is named only in the bin index. The walk stops at a scope-root boundary and walks that
scope as its own. A visit renews a name whose EOL is inside the walk window.

**D2 — The walk is depth-first in node-id order, and its cursor is the path of node ids from the
root.** The cursor holds a version byte, the start instant of the cycle, the current root, the
folder node ids on the path, and the last child visited at the deepest level. It holds no name: a
resume re-reads each folder on the path from its parent's current body, and continues at the
deepest folder that is still on the path. It seals on the owner-local structure under the new
kind `renewal-cursor` (discriminator `0x09`). This is not a KDF edge: the seal is HPKE auth mode to
the owner's own enc subkey, and the kind is a discriminator in the AAD and the `info`. The body is
padded to the path-length cap, so the sealed length does not show the depth. The decode and the
encode enforce the cap with a release-active `Err`. A release reads the cursor version that the
previous release wrote. A cursor that does not open or decode, or a replayed older cursor, costs
only work: the walk starts a new cycle or visits names again.

**D3 — The walk signs only the record that the adoption gate admitted in this visit, at
`floor + 1`, and only when no other write can come between.** The order for each renewal:

1. The gated child resolve adopts the record, or re-opens it at the floor (`open_at_floor`) when
   this device already adopted it. The admitted sequence is S.
2. The walk reads the doomed journal and the retire ledger, and re-reads the parent. A name that a
   delete doomed, that a ledger owes a retire, or that the parent no longer names, is not renewed.
3. Registration goes in batches of up to `REGISTRY_BATCH_MAX` names.
4. After the registration, the walk reads the name through the fan-out again. If the freshest
   record is not the admitted record, the walk does not sign.
5. The walk reads the durable sequence floor, with no await between that read and the signature.
   If the floor is not S, the walk does not sign. A drain publish, a sweep re-seal or a bin re-key
   on this device can raise the floor while the registration is in flight.
6. The walk signs at S + 1 with the EOL `eol_from(now)` minus one day. At one sequence an endpoint
   keeps the later EOL, so a write that another device signs at S + 1 at the same time always wins
   the tie, while that device's clock is less than one day behind.

A `LostRace` ends the renewal of that name for this cycle, with no retry.

**D4 — A node that a stopped name wave did not reach renews at its old name.** When the parent
names a name that the current write seed does not derive, the owner's walk derives the older write
seed through the write-plane history link. It renews the node under that seed only if the derived
name is the name that the parent names. The wave, when it resumes, then reads a live record. D3
step 2 stops the walk at each old name that the wave retired.

## Alternatives considered

- **Renew on read.** A name that no session reads still lapses, and each held name joins the
  hourly keyless re-PUT.
- **Renew on read and the walk.** The walk alone meets the bound, and a second producer of renewal
  publishes adds paths that can race a write.
- **Walk the whole vault on each pass, with no cursor.** A short session ends before the walk does,
  and the next one starts again at the root, so a far subtree is never reached.
- **A breadth-first frontier of names as the cursor.** A flat folder makes it as large as the
  vault, and a write rotation makes each stored name stale.
- **A cursor that a new release discards.** Releases ship every few days, so a walk that needs
  weeks restarts at each one.
- **Re-sign at the same sequence.** The engine reads two different records at one sequence as a
  fork (`fanout_get_tied`), and each renewal then confirms as a `LostRace`.
- **The name wave owns the liveness of its old names.** A wave stopped for longer than the EOL
  then reads `Absent` at each old name, and each node needs a revival (ADR 0062).
- **A keyed re-signer on the API**, as v1 had. The zero-knowledge server must hold no signing key.

## Consequences

1. `blueprint/engine.md` "Resolve/publish pipeline", the Liveness bullet, replaces "the names it
   holds keys for" with the renewal set plus the walk (D1, D3, D4). It adds: a session renews only
   a name whose signer derives from a write seed that it holds; a read grantee signs nothing; and a
   write grantee renews only its renewal set.
2. `blueprint/engine.md` states the numbers: at most 500 visits for each pass, a walk window of
   60 days of EOL left, and a new cycle no sooner than 7 days after the previous one began. Two
   visits of one name are at most `max(2T, 7 days + T)` apart, where T is the longest time that the
   owner takes to run `ceil(N / 500)` passes. The window holds when T is below 29 days. For
   N = 10 000, that is 20 passes in each 29 days. A name visited with 60.1 days left is not renewed,
   and the next visit comes at most 58 days later, before the EOL.
3. `blueprint/engine.md` "Host seams" names `renewal-cursor` on the `StagingStore` seam, and
   `blueprint/core.md` adds it to the owner-local kind registry and the KAT set: one populated
   accept body, and a cross-kind reject for each ordered pair with every other kind.
4. `blueprint/api.md` states the two throttles that bound the walk: `registry` at 120 calls a
   minute and `recovery` at 30 calls a minute, each for one account.
5. `blueprint/testing.md` adds a virtual-clock test: a file that no session opens or publishes for
   65 days is at S + 1 with a fresh validity after the passes that consequence 2 names.
6. The `HeldRecords` doc in `net::liveness` says that the walk renews the names outside the set.
7. ADR 0057 carries an "Amended by" sentence at the false line of its Context.

## Residuals

- A shared folder lapses for its grantees when the owner runs no session for about two months.
  Must a write grantee also walk the scopes that it can write? That walk can come later with no
  migration.
