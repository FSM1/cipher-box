# ADR 0054 — A dropped version's debt carries its target set and settles above the acknowledged sequence

- **Status:** Accepted on 2026-09-27
- **Date:** 2026-09-27
- **Relates to:**
  [ADR 0047](./0047-a-failed-or-abandoned-publish-retires-exactly-what-it-charged.md) D2 (an
  acknowledged PUT retires nothing), D5 (a dropped version's debt is journaled first) and E4 (an
  acknowledged PUT that never becomes live leaks everything it charged),
  [ADR 0046](./0046-the-registry-counts-references-per-record-and-caps-every-batch-at-1000.md) D1
  (the registry deletes a pin row only for a CID the batch names),
  [ADR 0020](./0020-the-durable-op-queue-reads-the-previous-release.md) (the durable op queue reads
  the previous release),
  [ADR 0045](./0045-a-queued-op-journals-its-crossing-as-a-plan-and-the-drain-decides.md) (a dead
  letter parks its op record in the preserved set), the decision of 2026-08-20 on
  FSM1/cipher-box#1226 (a spent attempt budget keeps the bytes), the `blueprint/engine.md`
  "Resolve/publish pipeline" section ("Retirement" bullet) and "Content plane" section ("Referenced
  equals kept" bullet), and the `CONTEXT.md` "Dead-letter" term
- **Implemented by:** FSM1/cipher-box#2063 (closes FSM1/cipher-box#2021)
- **Amends:** ADR 0047 D2

## Context

A dead letter that keeps its rows — a spent attempt budget, `BaseSuperseded`, `AlreadyPublished`,
a spent unattributed budget — holds a staged version whose registry rows stay charged. Three paths
later drop that version: the member discards the dead letter, the drain's valve refuses or loses
the preserved entry, and the preserved-set trim evicts it. Before FSM1/cipher-box#2063 each of
them released the staged blocks and sent no retire, so the rows leaked with no bound (ADR 0047
E4). The staged root is the only manifest that lists those rows, and it may never have reached a
gateway, so the retire ledger's prune shape — the root alone, leaves fetched at settle time —
cannot carry the debt. ADR 0047 D2 still holds: an acknowledged PUT may be resolvable at its name,
and a later record at the same sequence can lose a tie to it. So the debt may settle only once no
endpoint can still serve the dropped version as the node's live record.

## Decision

**D1 — A dropped version's debt carries its whole target set, in a versioned ledger entry.** The
retire-ledger entry gains a version byte and an origin. A prune debt keeps the root-only shape. A
dropped-version debt lists every leaf and then the root, each with its pinned bytes, so the settle
expands it with no gateway read. Encode refuses a set that is empty, does not end at the root, or
does not sum to the total, and decode reads the same bytes as unwritten (AGENTS.md rule 8). The
unversioned entry the previous release wrote still decodes, as a prune debt. The previous release
reads a versioned entry as unwritten, and the ledger never discards, so such an entry waits for
this release. Amended by
[ADR 0059](./0059-a-dropped-version-whose-staged-root-does-not-read-journals-its-root-alone.md)
D1 on 2026-09-29: a drop whose staged root does not give a target set journals a root-only debt,
and the settle fetches the root.

**D2 — The drain holds the acknowledged sequence of a PUT that did not confirm, signs above it,
and settles nothing at or below it.** A publish whose PUT was acknowledged but not confirmed, or
that lost a tie at its own sequence, records that sequence for the node under a sealed owner-local
key. The next publish at that name signs strictly above the mark. The settle of a dropped-version
debt reads the node's live record under a new class, `OwingRecord::Unconfirmed`: it waits while the
gated record is at or below the mark, while the endpoints serve other bytes at the same sequence,
or while a mark exists that will not read. A confirmed publish above the mark removes it. A mark
that will not read stands for any sequence, so the publish signs above the sequence floor plus the
attempt budget. For a dropped create, the settle treats the name as holding nothing only when
every endpoint answers that it holds no record, this device holds no sequence floor for the name,
and no mark exists for the node; any other read waits.

## Alternatives considered

- **Retire inline in the drain pass, with no ledger entry (D1).** The discard and the trim run
  outside a pass, and a retire needs the live record's CID set, which only a gated read gives. The
  ledger is the crash-safe carrier the prune already uses.
- **Store the root block in the entry (D1).** Every settle page would unseal roots of up to the
  record ceiling, and the ledger would grow with dead-letter roots. The target set is bounded by
  the manifest.
- **Compare the settle's head against the dropped edit's base (D2).** A later record at the same
  sequence hides the dropped one, and a prune or a restore that makes the head equal the base
  again stalls the debt for good. The sequence mark does not depend on the base.
- **Journal the rows when they are charged, at upload (D1, D2).** It gives the content-gone case
  its rows back, at one ledger write per version upload. Deferred; FSM1/cipher-box#2065 holds it.

## Consequences

1. `blueprint/engine.md` "Retirement" carries the carve-out on the acknowledged-PUT rule: a
   dropped dead-letter version journals its rows and settles above the acknowledged sequence.
2. `blueprint/engine.md` "Referenced equals kept" says that a dropped version's debt carries its
   target set.
3. ADR 0047 D2 reads with D2 here as its limit, and ADR 0047 E4 narrows to the content-gone case.
4. One new owner-local key prefix, `cbx/ra/`, sealed under the retire-ledger kind. The key names
   the owner tag and the node, as the tombstone key does, and the value is sealed.
5. A mark outlives a rotation. It is read against the current write name, so a mark held for an
   old name reads as nothing and stays as one key per node until a confirmed publish removes it.
6. A rotation re-seal or a liveness re-sign does not read the mark and can tie the dropped
   record. The settle sees the tie and waits, so the exposure is a delay, not a loss.

## Residuals

**E1 — Should a version's rows be journaled when they are charged?**
`Preservation::ContentGone` has no manifest to read, so its rows stay charged. FSM1/cipher-box#2065
names the charge-time journal, at one ledger write per version upload, as the candidate. The
owner decides whether it lands.
