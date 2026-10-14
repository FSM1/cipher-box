# ADR 0070 — A retire-ledger entry records the name of the record that owes it

- **Status:** Accepted on 2026-10-03
- **Date:** 2026-10-03
- **Relates to:** FSM1/cipher-box#2237 (the entry does not record the name),
  FSM1/cipher-box#2191 (a purge can drop references that a live copy needs),
  [ADR 0020](./0020-the-durable-op-queue-reads-the-previous-release.md) (a durable record reads
  the previous release),
  [ADR 0030](./0030-a-record-the-owner-alone-authors-and-that-seals-hpke-to-the-owner-seals-in-auth-mode.md)
  (j) (the ledger keys stay clear),
  [ADR 0046](./0046-the-registry-counts-references-per-record-and-caps-every-batch-at-1000.md) D1
  (a retire drops one record's references),
  [ADR 0054](./0054-a-dropped-versions-debt-carries-its-target-set-and-settles-above-the-acknowledged-sequence.md)
  D1 (the versioned entry), and the `blueprint/engine.md` "Resolve/publish pipeline" section
  ("Retirement" bullet)
- **Implemented by:** `net::retire` (`encode_entry`, `decode_entry`, `drain_owed_retires`),
  `sync::drain` (`live_owing_record`, the journal sites), `sync::staging` (`DroppedVersionDebts`)
- **Amends:** ADR 0054 D1

## Context

A retire-ledger entry records the owing node and the target CID, but not the name of the record
that owes the debt. The settle derives the name from where the base places the node at settle
time, and the registry drops the references of the record at that name (ADR 0046 D1). When the
node moves to another scope before the settle, the derived name can be the name of the live copy,
and the retire drops references that the live copy needs. The wait rule of FSM1/cipher-box#2191
holds such a debt while the base links the node. That rule prevents the loss, but the old
record's references then stay charged for as long as the node lives.

## Decision

**D1 — A new entry version records the name.** An entry at version 3 carries, after the CID, the
`ipnsName` of the record that owes the debt, as one length byte and the name bytes. The target
set of a dropped version follows the name, as in ADR 0054 D1. The journal writes version 3 for
each new debt, with the name of the record whose history dropped the target. The encode refuses
a name that is not a well-formed IPNS name, and the decode reads such bytes as unwritten
(AGENTS.md rule 8). Amended on 2026-10-03: the discard of a preserved dead letter and the
preserved-set trim write a version 2 entry with no name, because no write seed of the op scope
is in hand there; such a debt keeps the derived name and the wait rule.

**D2 — The settle retires under the recorded name.** For a version 3 entry, the settle uses the
recorded name for the retire and for the live-record read, and it does not derive a name from the
base. An entry at version 2, or with no version, has no name. It keeps the derived name and the
wait rule of FSM1/cipher-box#2191 for a node that the base links. Amended on 2026-10-03: a
version 3 entry of a retired node that the base links again is read as published when the end
of the scope that its links prove derives the recorded name, so the retire spares the CIDs that
the live record names; with no record to read, or when its links prove no held scope, the entry
waits. Amended on 2026-10-14 (FSM1/cipher-box#2259, owner option 1): the base is local to the
device, so before it settles a retired node that the base links nowhere, the settle reads the
folder records of each held scope whose write seed derives the name (a read grant keeps its
parent's seed) from the scope root, live and not from the cache. It settles only when no folder
links the node. A folder that links the node counts as a base link. A per-tick read cap bounds
the read, which continues on the next tick, and the debts of one tick in that scope share it. A
read that spans ticks proves nothing until a second sweep reads each folder to the same record.
The entry waits while a folder does not answer, while the gate refuses a folder, and for the
session once a scope passes the node bound of the read. A name that no held end derives, as
after a write cut, settles with no live record only when the tick reached every scope and no
rotation work is owed; otherwise the entry waits.
Amended on 2026-10-14 (FSM1/cipher-box#2280, owner option a):
a write grant re-seals the record at the recorded name under the new scope root. When the scope
binding refuses that record, the settle reads it again at the same name under the held end whose
root the record's tag names, as ADR 0072 D1 does. The retire stays under the recorded name.

**D3 — One release carries the change.** The new release reads all three shapes. Corrected on
2026-10-14: the previous release, v2.13.1, also reads a version 3 entry, so its `owe` keeps a held
version 3 entry and does not overwrite it with a version 2 entry.

## Alternatives considered

- **Record the name in the staging key, not the sealed value.** No value-format change. Rejected:
  ADR 0030 (j) keeps the ledger keys clear, so the key would show a name-to-node relation on the
  device.
- **Accept the leak.** Keep the wait rule as the final state. No format change, but a debt of a
  moved node stays charged for the life of the node.
- **Two releases: read version 3 first, write it in the next release.** No version 3 entry waits
  on a device that goes back one release. Rejected: such an entry waits and loses nothing, and
  the extra release delays the fix.

## Consequences

- ADR 0054 D1 carries an "Amended by" sentence for the version 3 entry.
- `blueprint/engine.md` "Retirement" says that a retire uses the name that the entry records.
- `blueprint/testing.md` names the test that decodes a version 2 entry with the new build
  (ADR 0020 D5), and the round-trip and refusal tests of the version 3 entry.
- The ledger key holds the content id and not the name, so two debts for one content id under two
  record names share one ledger slot, and the references of the second record stay charged (a
  leak, not a loss).

## Residuals

None.
