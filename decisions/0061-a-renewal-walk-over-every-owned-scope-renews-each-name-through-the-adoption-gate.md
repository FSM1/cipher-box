# ADR 0061 — A renewal walk over every owned scope renews each name through the adoption gate

- **Status:** Proposed
- **Date:** 2026-09-30
- **Relates to:** the `blueprint/engine.md` sections "Resolve/publish pipeline" (Liveness,
  Revival) and "sweep", `blueprint/api.md` "Republisher module and recovery", the `CONTEXT.md`
  terms "Write seed", "Adoption gate" and "Recovery endpoint",
  [ADR 0013](./0013-a-lapsed-bin-index-record-is-rewritten-not-refused.md) (a background job
  must not promote a record that no gate admitted), [ADR 0006](./0006-owner-local-sealed-store.md)
  and ADR 0030 D11 (the owner-local sealed structure),
  [ADR 0020](./0020-the-durable-op-queue-reads-the-previous-release.md) (a build reads the
  durable state that the previous release wrote),
  [ADR 0033](./0033-every-attacker-sized-field-has-one-canonical-form-and-a-symmetric-fail-closed-bound.md)
  (a symmetric bound on each decoded field), and
  [ADR 0057](./0057-an-observer-outside-a-session-reads-a-verified-record-and-adopts-nothing.md)
- **Implemented by:** not landed; FSM1/cipher-box#2108 tracks the change
- **Amends:** none

## Context

A record lapses 90 days after its signature. The engine re-signs a record only for a name in the
session's renewal set (`net::liveness`, `HeldRecords`). The set holds the vault root, the records
that this session published, the owned scope pointers, the settings record and the bin index. A read
holds nothing: the child resolve, the focus window, the scope walk and the FUSE listing add no name.
The API republisher re-PUTs the same bytes, so it extends no validity. `revive` has no production
caller. Thus a file or folder record that no session publishes lapses at 90 days, even when the
owner opens it each day, and a lapsed folder hides its subtree. v1 re-signed in a TEE; v2 has none.

## Decision

**D1 — A renewal walk over every owned scope renews each name, and a read renews nothing.** The
liveness pass runs a bounded part of the walk after the sub-EOL renewal of the renewal set, and the
first pass of a session runs it too. The walk visits every node of each scope that the vault owns
(`owned_sweep_targets`): the vault root scope first, then the other owned scopes in scope-id order.
It stops at a scope-root boundary, and it walks that scope as its own. A visit resolves the name
and renews it when its EOL is inside the walk threshold. The walk finishes a cycle over many
sessions, so a vault stays alive when its owner runs enough passes (Consequences 3).

**D2 — The walk is depth-first in node-id order, and its cursor is the path of node ids from the
scope root.** The cursor holds a version byte, the start instant of the cycle, the scope id of the
current scope, the node ids of the folders on the path, and the node id of the last child visited
at the deepest level. It holds no name: a resume re-reads each folder on the path from its parent's
current body, then continues after the stored child id. A folder that left the path ends the
descent there, and the walk continues at the deepest folder that is still on the path. The cursor
seals on the owner-local structure under a kind of its own, and the host holds only the sealed
bytes. The decode and the encode enforce one path-length cap with a release-active `Err`
(ADR 0033, security rule 8). A release reads the cursor version that the previous release wrote,
as ADR 0020 requires of the op queue. A cursor that does not open or decode starts a new cycle.

**D3 — The walk renews only a record that the adoption gate admitted in this visit, and it signs
the admitted value at `floor + 1` only while the network still serves that value.** Each visit runs
the gated child resolve (`net::child`), which advances the sequence floor to the admitted record. Immediately before the signature, the walk reads the name through the fan-out
again. If the freshest record is not the admitted record, the walk does not sign. A `LostRace`
from the publish confirm ends the renewal of that name for this cycle, with no retry.

**D4 — The walk revives a lapsed name, and the revival also goes through the adoption gate.** When
the fan-out finds no record for a name that the parent body names, the walk fetches the record
from the recovery endpoint, corroborates it as `net::revival::revive` does, and gives it to the
same gated child resolve. The gate does not refuse a record for its EOL, so a lapsed record can
pass. The walk then signs the admitted value at one above the higher of the floor and the
recovered sequence. A lapsed folder is revived before the walk descends into it, because its body
names the subtree. A revival that the gate or the corroboration refuses renews nothing.

**D5 — A session renews only a name whose signer it derives from a write seed that it holds.** The
signer is `write_name_signer(writeScopeSeed, nodeId)` of the scope at its current write epoch. If
the derived name is not the name that the parent names, the walk skips the node. The owner's walk
covers each owned scope, and a shared scope is one of them. A grantee runs no walk: a read grantee
can sign nothing, and a write grantee renews only its renewal set.

## Alternatives considered

- **Renew on read: hold each name that a read resolves and the gate admits.** A name that no
  session reads still lapses, and most of a large vault is not read in 90 days. Each held name
  also joins the hourly keyless re-PUT, so the set grows with the reads.
- **Both renew on read and the walk.** The walk alone meets the bound. A second producer of
  renewal publishes doubles the paths that can race a write, and it adds no name that the walk
  does not visit.
- **Walk the whole vault on each pass, with no cursor.** A vault of 10 000 nodes costs 10 000
  fan-out reads per pass. A short session ends before the walk does, and the next session starts
  again at the root, so a far subtree is never reached.
- **A breadth-first frontier of names as the cursor.** A flat folder makes it as large as the
  vault, and a write rotation makes each stored name stale.
- **A cursor that a new release discards.** Releases ship every few days. A walk that needs weeks
  then restarts at each release, and a far subtree lapses.
- **Re-sign at the same sequence with a fresh EOL.** A newer write always wins over it, so it
  cannot roll a write back. But the engine reads two different records at one sequence as a fork
  (`net::fanout::fanout_get_tied`), the publish confirm then reports each renewal as a
  `LostRace`, and the behavior of every routing endpoint for this case is not proved.
- **Revive from the recovery record after the signature and the floor check only**, as `revive`
  does now. ADR 0013 rejected the same shape: a background job would sign bytes that no gate
  admitted.
- **A keyed re-signer on the API**, as v1 had. The server then holds a signing key for each name,
  which the zero-knowledge server must not hold.

## Consequences

1. `blueprint/engine.md` "Resolve/publish pipeline", the Liveness bullet, replaces "the names it
   holds keys for" with the renewal set plus the renewal walk (D1, D3, D5), and the Revival bullet
   says that the walk revives through the gate (D4).
2. `blueprint/engine.md` "Host seams" names the renewal cursor as an owner-local kind on the
   `StagingStore` seam (D2). The new kind is a `crates/core` change with a KAT manifest entry.
3. `blueprint/engine.md` states the numbers: at most 500 visits for each pass, a walk threshold
   of 60 days of EOL left, a new cycle no sooner than 7 days after the previous cycle began, and a
   path cap of 256 folders. A vault of N names stays alive when its owner runs `ceil(N / 500)`
   passes in each 60 days: one pass for a vault below 500 names, and 20 passes for 10 000.
4. The `HeldRecords` doc in `net::liveness` says that the walk renews the names outside the set.
5. ADR 0057 gets this sentence at its Context when this ADR is accepted: "Amended by ADR 0061 on
   <date>: the republisher re-PUTs the same bytes and extends no validity; the engine's renewal
   gives a record a fresh validity."
6. Two devices of one owner can renew one name at once. Both sign one value at one sequence, so
   the fork carries one value. A node that the name wave did not reach yet waits for the wave.

## Residuals

- A shared folder lapses for its grantees when the owner runs no session for 90 days. Does a
  write grantee also walk the scopes that it can write?
- D3 leaves a short window between the read before the signature and the PUT. A write that lands
  in it at the same sequence can lose to the renewal, which has the later EOL. Does the owner
  accept the window, or prove same-sequence renewal on each routing endpoint first?
