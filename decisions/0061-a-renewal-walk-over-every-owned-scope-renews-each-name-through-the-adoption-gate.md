# ADR 0061 — A renewal walk over every owned scope renews each name through the adoption gate

- **Status:** Accepted on 2026-09-30
- **Date:** 2026-09-30
- **Relates to:** `blueprint/engine.md` "Resolve/publish pipeline" (Liveness) and "sweep",
  `blueprint/api.md` "Republisher module and recovery", the `CONTEXT.md` terms "Write seed",
  "History link" and "Name wave", [ADR 0006](./0006-owner-local-sealed-store.md) and ADR 0030 D11
  (the owner-local structure), [ADR 0010](./0010-recycle-bin-is-an-owner-sealed-index.md),
  [ADR 0013](./0013-a-lapsed-bin-index-record-is-rewritten-not-refused.md),
  [ADR 0020](./0020-the-durable-op-queue-reads-the-previous-release.md),
  [ADR 0033](./0033-every-attacker-sized-field-has-one-canonical-form-and-a-symmetric-fail-closed-bound.md),
  and ADR 0062 (the revival of a lapsed name)
- **Implemented by:** FSM1/cipher-box#2112 (D1 to D4)
- **Amends:** [ADR 0057](./0057-an-observer-outside-a-session-reads-a-verified-record-and-adopts-nothing.md) Context

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
pass of a session runs it too. The roots of the walk are the vault root scope, each other owned
scope in scope-id order, each bin index entry until its purge (the bin index alone names a binned
subtree), and each deferred root of D2. The walk stops at a scope-root boundary and walks that
scope as its own. A visit renews a name whose EOL is inside the walk window.

**D2 — The walk is depth-first in node-id order, and its cursor is the path of node ids from the
root.** The cursor holds a version byte, the cycle start, the time the cycle first kept the cursor
back after a transient failure (or none), the current root, the folder node ids on
the path (64 at most), the last child visited at the deepest level, and the deferred roots (256 at
most, each a scope id, a node id and a name). A resume re-reads each folder on the path from its
parent's current body, and continues at the deepest folder still on the path. The walk
does not descend below a folder at depth 64: it adds that folder as a deferred root and walks it
later with a new path. A deferred name that went stale fails the signer bind, and the next cycle
finds that folder again. When the set is full, the walk descends below depth 64 in memory and
finishes that subtree in the same pass, with no per-pass budget. The cursor stays at the depth-64
folder, so the encode never fails, and a pass that ends inside the subtree starts it again. Until
one day after the cycle's first keep-back time, a pass that meets a transient failure stores the
cursor it began from. After that day, or when that time is ahead of the clock, each pass of the
cycle stores where it stopped, and a new cycle clears the time. The cursor seals on the owner-local structure under the new kind
`renewal-cursor` (discriminator `0x09`). This is not a KDF edge: the seal is HPKE auth mode to the
owner's own enc subkey, and the kind is a discriminator in the AAD and the `info`. The body is
padded to the caps, so the sealed length shows nothing. The decode and the encode enforce both
caps with a release-active `Err`. A release reads the cursor that the previous release wrote. A
cursor that does not open or decode, or a replayed older one, costs only work.

**D3 — The walk signs only the record that the adoption gate admitted in this visit, at
`floor + 1`, and only when no other write can come between.** The order for each renewal:

1. The gate admits the record: the root adopt (`gate::adopt`) for a scope root, or the gated child
   resolve for any other node. Each adopts, or re-opens at the floor (`open_at_floor`) a record
   that this device already adopted. The admitted sequence is S.
2. The walk skips a name that a delete doomed, that the retire ledger owes a retire, that the
   parent no longer names, or that the drain has a publish of in flight.
3. Registration goes in batches of up to `REGISTRY_BATCH_MAX` names.
4. After the registration, the walk reads the name through the fan-out again. If the freshest
   record is not the admitted record, the walk does not sign.
5. The walk reads the durable sequence floor, with no await between that read and the signature.
   If the floor is not S, the walk does not sign.
6. The walk signs at S + 1 with the EOL `eol_from(now)` minus one day, so a write that another
   device signs at S + 1 at the same time has the later EOL, while that device's clock is less
   than one day behind.
7. Every reader sides with the endpoints: at one sequence, the fan-out resolve (`fanout::scan`)
   and the last-known-good keeper (`keep_newest_last_known_good`) take the record with the later
   EOL. Today both keep the first record that they hold, so a device that adopted a renewal can
   refuse the real write as `SequenceNotNewer`, or start from a cache that does not show it.

A `LostRace` ends the renewal of that name for this cycle, with no retry.

**D4 — The walk renews a node only under the write seed that derives its scope root's name.** It
renews no name under a superseded seed.

## Alternatives considered

- **Renew on read, alone or with the walk.** A name that no session reads still lapses, and a
  second producer of renewal publishes adds paths that can race a write.
- **No cursor, or a cursor that a new release discards.** A short session, or a release every few
  days, restarts a long walk at the root.
- **A breadth-first frontier of names as the cursor.** A flat folder makes it as large as the vault.
- **Re-sign at the same sequence.** Each renewal then confirms as a `LostRace` against itself.
- **Renew a node at its old name under a superseded seed**, derived through the write-plane
  history link. The walk then signs under a seed that does not derive its scope root's name.
- **A keyed re-signer on the API**, as v1 had. The zero-knowledge server must hold no signing key.

## Consequences

1. `blueprint/engine.md` "Resolve/publish pipeline": the Liveness bullet replaces "the names it
   holds keys for" with the renewal set plus the walk (D1 to D4). A session renews only a name
   whose signer derives from a write seed that it holds; a read grantee signs nothing; a write
   grantee renews only its renewal set. The Resolve bullet states D3 step 7.
2. `blueprint/engine.md` states the numbers: at most 500 visits for each pass, a walk window of
   60 days of EOL left, and a new cycle no sooner than 7 days after the previous one began. A move
   can put a subtree behind the cursor for one cycle, so two visits of one name are at most
   `2 max(T, 7 days) + T` apart, where T is the longest time that the owner takes to run
   `ceil(N / 500)` passes, plus at most 1 day for which the cycle keeps the cursor back (D2). The
   window holds when T is at most 19 days, so the passes take at most 18 days. For N = 10 000, that
   is 20 passes in each 18 days. A name visited with 60.1 days left is not renewed, and the next
   visit comes at most 57 days later, with at least 3 days of EOL left.
3. `blueprint/engine.md` "Host seams" names `renewal-cursor` on the `StagingStore` seam, and
   `blueprint/core.md` adds it to the owner-local kind registry and the KAT set: one populated
   accept body, and a cross-kind reject for each ordered pair with every other kind.
4. `blueprint/api.md` states the two throttles that bound the walk: `registry` at 120 calls a
   minute and `recovery` at 30 calls a minute, each for one account.
5. `blueprint/testing.md` adds a virtual-clock test: a file that no session opens or publishes for
   65 days is at S + 1 with a fresh validity after the passes that consequence 2 names.
6. `CONTEXT.md` adds the term "Renewal walk".
7. ADR 0057 carries an "Amended by" sentence at the false line of its Context.
8. Accepted residual: a grantee runs no walk, so a shared folder lapses for its grantees when the
   owner starts no session for about two months. The owner accepted it on 2026-09-30; the research
   for a grantee walk is FSM1/cipher-box#2111.
9. Under D4, a node that a stopped name wave left at an older name lapses, and ADR 0062 revives it.
