# ADR 0019 — File version retention is count-based keep-latest-N

- **Status:** Accepted — `blueprint/engine.md` reworded in FSM1/cipher-box#1862 (merged)
- **Date:** 2026-09-15
- **Relates to:**
  [FSM1/cipher-box#1094](https://github.com/FSM1/cipher-box/issues/1094) (the engine half of
  version history, and the comment of 2026-08-20 that took this decision),
  [FSM1/cipher-box#1095](https://github.com/FSM1/cipher-box/issues/1095) (the web half, which
  renders what this rule retains),
  `blueprint/engine.md` "Chunking and retention" (the line this ADR replaces: "Retention
  default: keep all versions within quota, with an explicit user-initiated prune op."),
  the `CONTEXT.md` "Version history" term, and
  [ADR 0012](./0012-the-drain-carries-the-write-wave-forward.md)
  (the op queue that must replay deterministically)
- **Implemented by:** [FSM1/cipher-box#1862](https://github.com/FSM1/cipher-box/pull/1862),
  which landed the engine rule, the restore and delete commands, and the blueprint reword. It
  merged on 2026-09-16 as commit `63cb731da`.

## Context

A file's sealed read-body carries a `versions` list. Each version holds its own `contentCid`,
its size, its modification time, and its own content key. A version is fresh-keyed: the key is
random per version and rides inside that one read-body. A prior version therefore opens only
while its entry stays in the list.

Orphan GC reclaims a staged root that nothing refers to. A superseded content root has no
referent after the node moves forward. Prior versions are thus not only unshown to the member —
they are collectable. Retention is a reference decision in the engine, not a rendering gap.

The blueprint states a different rule. Its "Chunking and retention" paragraph says the default
is to keep all versions within quota, with an explicit user-initiated prune op. Three facts at
`main` show that the rule is not the one the engine can hold:

- `RetentionPolicy` defaults to `KeepAll`, and no path applies it. A file's history grows
  without a bound.
- `OpKind::Prune` and `publish_prune` are complete, but no `Command` variant stages a prune.
  Only tests reach it, so a host cannot start the explicit op the blueprint names.
- The vault settings record already carries `keepLatestVersions`. The engine stores the number
  and never acts on it.

A quota-shaped rule also needs a size the engine does not have at the moment it seals a write.
The member's quota lives at the API. Retention runs in the write path, which must decide from
the record in hand.

CipherBox v1 answers the same question with a count. `maxVersionsPerFile` defaults to 10. The
owner decision of 2026-09-14 on FSM1/cipher-box#1094 says that v2 file versions behave as v1
file versions do.

### Why no clock enters the rule

Every op replays from the durable op queue. A rule that reads a clock gives a different plan on
each replay, because the time moves between the stage and the drain. The plan would then retire
bytes that the first pass kept, or keep bytes that the first pass retired. Determinism is
injected in this codebase: time enters as a parameter, never as a call. An age rule puts a clock
where no seam carries one.

## Decision

**D1 — Retention is count-based keep-latest-N.** A file keeps its N most recent prior versions,
newest first. The current version is not in the list.

**D2 — N is the existing `keepLatestVersions` vault setting.** The default before the member
chooses is 10, which is the v1 `maxVersionsPerFile` default. No new setting is added, and no
wire format changes.

**D3 — A retained version stays referenced by its own entry.** The version's content root rides
the node's live read-body versions list. Orphan GC keeps its one rule, referenced-equals-kept,
and needs no new machinery, no reference count, and no retention-aware pass.
Amended by
[ADR 0047](./0047-a-failed-or-abandoned-publish-retires-exactly-what-it-charged.md)
D5 on 2026-09-26: "no new machinery" means no machinery beyond the re-registration that the publish
path already runs, and ADR 0047 D5 is its mechanism.

**D4 — A delete of a version removes its entry and makes its root collectable.** The current
version is untouched, the record republishes, and the dropped blocks go to the retire ledger.
The current version cannot be deleted: the list holds prior versions only, and the engine
refuses the command and refuses it again at the drain.

**D5 — No clock enters retention.** The rule reads a count and nothing else, so the decision
replays deterministically in the op queue.

**D6 — A restore publishes a new version through the normal write path.** The restored entry
leaves the list, and the outgoing current version becomes the newest entry. History keeps its
length, and no byte moves. A restore is a write, not an edit of history.

**D7 — A delete is final.** Each version is fresh-keyed and its key rides inside the entry.
When the entry goes, the bytes stay addressed but no key opens them.

**D8 — There is no version cooldown.** v1 had a `versionCooldownMinutes` window, default 15, in
which a new upload replaced the content and made no version. Such a window needs a clock, which
D5 refuses. Every content write in v2 makes a version.

## Alternatives rejected

**Keep all versions within quota, with an explicit user-initiated prune op.** This is the
blueprint line. It is rejected for three reasons. The quota is an API fact, and the write path
that must decide does not hold it. The prune op has no command, so the member cannot start it,
and a history grows without a bound until someone does. And a rule that keeps everything until a
member acts makes the first prune retire a large set of blocks at one time, which is the pause
the count rule spreads across the writes.

**An age-based rule, such as "keep every version younger than 30 days".** Rejected for
replay determinism (D5). The rule reads a clock, so the plan the stage makes and the plan the
drain replays differ. The op queue cannot hold a decision that changes under it.

**A hybrid rule, such as "keep the latest N, and keep any version younger than T".** Rejected
for the same reason as the age rule: the age half carries the clock, and one clock is enough to
break the replay. The hybrid also makes the retained set hard for a member to predict, because
two rules decide it.

**A reference count on a content root, so a retained root is kept outside the versions list.**
Rejected. It adds durable state that the read-body already holds, and it gives orphan GC a
second rule. The entry is the reference (D3).

**Keep `0` as a representable N, as v1 did.** v1 allowed `maxVersionsPerFile: 0` to turn
versioning off. `RetentionPolicy::KeepLatest` takes a non-zero count, because a zero would plan
the retire of the live version with its history. A member who wants no history deletes the
versions.

## Consequences

1. **`blueprint/engine.md` changes when this ADR is accepted.** The "Chunking and retention"
   paragraph loses the "keep all versions within quota, with an explicit user-initiated prune
   op" sentence. It gains the count rule, the `keepLatestVersions` source of N, the
   referenced-equals-kept interaction with orphan GC, and the restore-is-a-write law.

2. **`CONTEXT.md` gains the "Version history" term**, so the list, the entry and the current
   version have one name each.

3. **Retention runs where history grows.** The write path shortens the list it is about to
   seal, so a vault never carries a version past the rule, not even between a write and a
   prune. The prune op stays, and goes through the same helper.

4. **A device that cannot read the settings record keeps every version.** Shortening a history
   retires bytes and cannot be undone, so the drain acts only on a settings load that carried a
   member choice. This is the rule the recycle bin's expiry sweep already follows.

5. **A version is named by its `contentCid`.** An entry has no other identifier, and an index
   into the list moves under a concurrent write.

6. **FSM1/cipher-box#1094 closes at the merge of FSM1/cipher-box#1862.**
   FSM1/cipher-box#1095 renders the history the rule retains.

## Residuals

**E1 — A member cannot keep an old version past the rule.** The count is per vault, not per
file and not per version. A member who must keep an old state makes a copy of it.

**E2 — Every content write makes a version.** With no cooldown (D8), a host that writes often
pushes the oldest entries out fast. A host that saves on each keystroke would empty a history in
seconds. The write path, not retention, must batch such writes.

**E3 — A history whose `contentCid` repeats cannot be shortened safely by position.** A version
list is authored by any party that holds the scope's write seed, so a co-writer can park a
repeated CID in it. Such a history publishes whole rather than taking a permanent refusal.

**E4 — N applies from the next write.** Lowering `keepLatestVersions` does not retire the
excess entries at once. Each file meets the new count when it is next written, or when a member
deletes the versions.

## Gate

- `blueprint/engine.md` "Chunking and retention" states the count rule, names
  `keepLatestVersions` as N, states the referenced-equals-kept interaction with orphan GC, and
  no longer carries the quota-and-prune sentence.
- `CONTEXT.md` carries the "Version history" term.
- The tests of FSM1/cipher-box#1862 stay green, and each one fails on the unfixed code:
  a superseded root inside the rule is retained and the write that pushes it outside the rule
  retires it; a write with no member retention choice keeps every version; a restore publishes
  the named version as the new head and keeps the history length; a delete makes the version
  unresolvable and retires its blocks; a delete of the current version is refused; a version
  retained across a key-regression epoch still opens.
- No path in `crates/engine` reads a clock to plan retention, a restore or a delete.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
