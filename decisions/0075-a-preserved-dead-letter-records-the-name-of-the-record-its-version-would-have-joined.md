# ADR 0075: A preserved dead letter records the name of the record its version would have joined

- **Status:** Proposed
- **Date:** 2026-10-14
- **Relates to:** [#2283](https://github.com/FSM1/cipher-box/issues/2283),
  [ADR 0070](./0070-a-retire-ledger-entry-records-the-name-of-the-record-that-owes-it.md) D1
  and D2 (the version 3 entry),
  [ADR 0020](./0020-the-durable-op-queue-reads-the-previous-release.md) D1 and D6 (a durable
  record reads the previous release),
  [ADR 0030](./0030-a-record-the-owner-alone-authors-and-that-seals-hpke-to-the-owner-seals-in-auth-mode.md)
  D11 (a per-owner staging surface seals under its own kind), ADR 0047 (a dropped version
  journals its debt)
- **Implemented by:** not landed
- **Amends:** ADR 0070 D1, as the amendment of 2026-10-03 states it

## Context

ADR 0070 D1 journals each new retire-ledger debt at version 3, with the name of the record that
owes it. Two sites still journal version 2: `Engine::discard_dead_letter`, and the preserved-set
trim in `reconcile_staging_over`. A third site, the count cap in `preserve_dead_letter`, evicts
an entry and journals no debt at all. At these sites no write seed of the op scope is in hand, and
the preserved entry does not hold the name. When the node moved to another scope after the drain
parked the op, the settle derives the name of the new place. The debt then retires under that
name, or it waits, and the rows of the old record stay charged.

## Decision

**D1 — The drain records the name when it parks the version.** When the drain preserves a dead
letter that staged a version, it records the `ipnsName` of the record that the version would
have joined. The name is the write name of the end that the drain derives for the op target at
that tick, the same name that `release_unpreserved` journals for a version that it does not
preserve. When the drain derives no end, it records no name. A discard, a trim and an eviction
past the count cap journal a version 3 entry with the recorded name. With no recorded name,
they journal a version 2 entry, as before.

**D2 — The name has its own sealed staging key, and the preserved set keeps its format.** The
key is `cbx/dn/ | ownerTagLen(1) | ownerTag | opId(8, big-endian)`. The value seals under a new
owner-local kind, `dead-letter-names` (`0x0d`), per ADR 0030 D11. The sealed body is
`version(1) = 1 | opId(8) | rootCid | nameLen(1) | name`, where `rootCid` is the binary content
CID of the parked version. A body whose op id or root CID is not the one of its key and its
preserved entry reads as no name. The encode refuses a name that is not a well-formed IPNS name,
and the decode reads such bytes as no name (AGENTS.md rule 8). The name key is written before
the preserved set, so the set write commits both. Orphan GC keeps a name key while the preserved
set or the op queue holds its op id, and collects it after that. The queue clause covers the
time between the name write and the set write. When the drain derives no end for a version, it
removes any name key of that op before the set write, so a name from an earlier tick does not
stay. A name key that the discard or the trim cannot read keeps that one preserved entry in
place for the pass, and the pass does not journal its debt. An entry that the cap evicts and
that this session opens journals its debt under its recorded name after the set write, and then
its name key goes. An evicted entry whose name does not read stays in the set past the cap, and
the trim handles it later. While name reads fail and name writes succeed, the set keeps one
more entry past the cap for each such dead letter, and no ceiling holds that growth.

## Alternatives considered

- **A new preserved-set format that carries the name in each entry.** One write, one key.
  Rejected: the previous release reads the whole set as unreadable. On a device that goes back
  one release, every new dead letter is then refused and its version released, orphan GC stops,
  and no parked write can be discarded or recovered.
- **The name in the clear in the preserved set.** No new kind. Rejected: ADR 0030 D11 keeps
  clear only values that associate no two identifiers, and this value ties an op to a record
  name.
- **Seal under the `retire-ledger` kind.** No new kind and no KAT change. Rejected: ADR 0030 D11
  gives each new staging surface its own kind, and the kind is the domain separation that makes
  a value moved between stores fail to open.
- **Derive the name from the cached write seed at discard.** No new durable state. Rejected: a
  write rotation changes the write seed of a scope, so a cached seed can be newer than the op,
  and the derived name is not the name that the version charged.
- **Journal the debt when the drain parks the version.** The name is in hand there. Rejected: the
  settle then retires the rows of a version that a recover can re-queue, which is a loss.
- **Keep version 2 at the two sites.** No change. The debt of a moved node keeps the derived name
  and the wait rule, which is a leak for the life of the node.

## Consequences

- The new build reads a preserved set that the previous release wrote. Its entries have no name
  key, so their debts journal at version 2 (ADR 0020 D5 test).
- The previous release reads the preserved set as it is. Its orphan GC collects the name keys,
  so a debt that it or a later build journals for those entries is version 2: a leak, not a
  loss.
- ADR 0070 D1 carries an "Amended by" sentence for the two sites and the cap
  eviction.
- `blueprint/core.md` names the `dead-letter-names` kind and the KAT manifest adds it, in the
  code PR.
- `blueprint/engine.md` "Retirement" says that a discard, a trim and a cap eviction use the recorded
  name, in
  the code PR.
- `blueprint/testing.md` names the tests for each site, the previous-release read, the
  round-trip, and the encode refusal, in the code PR.

## Residuals

- An op that exhausts its attempts records the end of its final tick. If the node moved between
  two attempts, the name is the one of the last attempt. Is that the record that the version
  charged, or must the drain record the name at the first attempt?
