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
waits.

**D3 — One release carries the change.** The new release reads all three shapes. A
previous-release build reads a version 3 entry as unwritten, and its `owe` can overwrite the entry
with a version 2 entry for the same content id; the debt then settles under the derived name with
the wait rule.

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
