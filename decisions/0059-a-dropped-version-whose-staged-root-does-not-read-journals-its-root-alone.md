# ADR 0059 — A dropped version whose staged root does not read journals its root alone

- **Status:** Accepted on 2026-09-29
- **Date:** 2026-09-29
- **Relates to:**
  [ADR 0054](./0054-a-dropped-versions-debt-carries-its-target-set-and-settles-above-the-acknowledged-sequence.md)
  D1 (a dropped version's debt carries its target set), D2 (the settle reads the owing node under
  `OwingRecord::Unconfirmed`) and E1 (should a version's rows be journaled when they are charged),
  [ADR 0047](./0047-a-failed-or-abandoned-publish-retires-exactly-what-it-charged.md) D2 (an
  acknowledged PUT retires nothing) and E4 (an acknowledged PUT that never becomes live leaks what
  it charged), [ADR 0020](./0020-the-durable-op-queue-reads-the-previous-release.md) (durable
  staging state reads the previous release), the `blueprint/engine.md` "Resolve/publish pipeline"
  section ("Retirement" bullet) and "Content plane" section ("Referenced equals kept" bullet)
- **Implemented by:** FSM1/cipher-box#2105
- **Amends:** ADR 0054 D1

## Context

A dead letter that keeps its rows drops its staged version later, and the drop journals the target
set that the staged root lists (ADR 0054 D1). When the preservation outcome is `ContentGone`
because the staged root is gone or fails its own CID, no local manifest lists the rows, so the drop
journals nothing. The rows stay charged, the pending-reclaim figure does not show them, and no
later pass can find them. The drain keeps the root staged until the publish confirms, so the root
goes only when the store loses or damages that key. The same gap applies to a root that this build
cannot decode. The op record still names the root CID. For a PUT that was acknowledged, the root
uploaded before the PUT, so an endpoint can serve it.

## Decision

**D1 — A drop whose staged root does not give a target set journals a root-only debt of a third
origin, and the settle fetches the root.** When the staged root is gone, fails its own CID, or
does not decode, the drop takes the root CID from the op record. It journals a versioned ledger
entry with the origin "dropped root", which carries no target set. The owed figure is the size
that the op record carries. The settle fetches the root over the gateway ladder and expands it, as
for a prune debt. It reads the owing node under `OwingRecord::Unconfirmed`, as for a dropped
version. A root that no source serves keeps the entry, as a `TargetUnexpandable` stall with its
figure in the pending-reclaim figure. Encode refuses a dropped-root entry with a target tail, and
decode reads such bytes as unwritten (AGENTS.md rule 8). The upload path writes nothing new.

This release reads every entry the previous release wrote with no change. The previous release
reads a dropped-root entry as unwritten, and the ledger never discards, so the entry waits for
this release. Its orphan GC keeps the entry, because the entry is under the ledger prefix.

## Alternatives considered

- **A charge-time journal (D1).** When the upload charges a version's first block, a sealed
  owner-local entry keeps the target set, and the drop reads it when the root is gone. The entry
  clears when the publish confirms or when the drop journals its debt. It closes every sub-case,
  also a root lost before its own upload. But it costs one sealed write of the whole target set and
  one removal for each version upload, about as large as the root block. It is also in the same
  store as the root that it protects. It needs a new key prefix, which the previous release's
  orphan GC does not know and deletes on a rollback. The only loss that it covers is a single key
  that the store loses while a dead letter holds the version.
- **Put the leaf list in the upload mark (D1).** The drain writes the mark again after each leaf,
  so a list in the mark costs bytes in proportion to the square of the leaf count.
- **Keep the root block in the op record (D1).** The op record is the durable queue that the
  previous release must read (ADR 0020), and each queued content op grows by the size of its
  manifest.
- **Leave the case as an accepted leak.** The rows stay invisible to the pending-reclaim figure
  and to every later pass, which is the fault this ADR removes.

## Consequences

1. `blueprint/engine.md` "Referenced equals kept" says that a dropped version whose staged root
   does not read journals its root alone, and the settle fetches the root.
2. `blueprint/engine.md` "Retirement" says that the drop journals a debt also when the staged root
   is gone, and cites this ADR next to ADR 0054.
3. ADR 0054 D1 reads with D1 here as its fallback. ADR 0054 E1 closes on item 6.
4. ADR 0047 E4 narrows to a version whose root no source serves.
5. The retire-ledger entry gains the origin byte for "dropped root" under the existing version
   byte. No key prefix is new.
6. Accepted residual: a root that the store loses before its own upload leaks the leaves that
   uploaded before it, and so does a `ContentUnrecoverable` abandon whose root is gone. The leak
   is bounded to one version and shows in the pending-reclaim figure. The owner accepted it on
   2026-09-29, so the charge-time journal is not adopted.
7. Accepted residual: a dropped version whose PUT never reached the transport waits behind the
   per-node acknowledged mark (ADR 0054 D2) until the node moves past that mark. This is a delay,
   not a loss. The owner accepted it on 2026-09-29, with no per-version record.
