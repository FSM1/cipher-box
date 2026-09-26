# ADR 0020 — The durable op queue reads the previous release

- **Status:** Accepted — `blueprint/engine.md` reworded in FSM1/cipher-box#1915 (merged)
- **Date:** 2026-09-19
- **Relates to:**
  [#6](https://github.com/FSM1/cipher-box-next/issues/6) (the clean break, which covered the
  v1 → v2 cutover and which this ADR bounds after it),
  [FSM1/cipher-box#1900](https://github.com/FSM1/cipher-box/pull/1900) (the change that added
  `StagedContent.scope` as a required field),
  [FSM1/cipher-box#1905](https://github.com/FSM1/cipher-box/pull/1905) (the fix: an absent
  `scope` decodes as the vault root),
  `blueprint/engine.md` "Host seams" (the `StagingStore` and `FloorStore` contracts) and
  "Sync core" (the op queue, the retained record, the dead letter),
  `blueprint/deploy.md` "Release management" and "Cutover",
  the `CONTEXT.md` "Op queue", "Op record" and "Retained record" terms,
  [ADR 0006](./0006-owner-local-sealed-store.md)
  (the owner-local sealed stores), and
  [ADR 0016](./0016-a-durable-sequence-floor-key-is-a-name-label-not-the-name.md)
  (a floor-key change that re-seeds from the network)
- **Implemented by:** [FSM1/cipher-box#1905](https://github.com/FSM1/cipher-box/pull/1905)
  for the first case, and the `blueprint/engine.md` sentence below after acceptance.

## Context

The v2 build started as greenfield. The clean break of #6 removed every data-continuity
obligation from v1 to v2, so a v2 change could reshape any durable record with no migration.
That rule was correct for the cutover. The cutover is done: v2.0.0 went to staging on
2026-09-13, and the train then shipped eight more releases in six days, up to v2.3.0 on
2026-09-19. Each staging deploy now lands a new build on devices that hold durable state from
the build before it.

The op queue is the place where this matters first. It is per device, it holds every mutation
that did not publish yet, and it is shared with whatever build wrote it. A queued op is a
member's write that the network does not have. If the new build cannot use the record, the
write does not reach the network.

The engine already has a rule for a record it cannot read (`blueprint/engine.md` "Sync core").
A record at another header version, or a record whose seal opens but whose intent body the
build does not parse, is **retained**: never replayed, never surfaced, never removed, and its
staged bytes stay pinned. That rule protects a newer build's records from an older build. It
does not make a newer build drain an older build's records. A retained op is safe from
deletion, but the member's write stays unpublished.

### The case that showed the gap

FSM1/cipher-box#1900 bound the content key blob AAD to the scope that the write target sits
in. It added `StagedContent.scope` to the content op as a required field, with no decode
default and no header version bump. v2.2.0 wrote content ops with no `scope`. v2.3.0 shipped
with the required field. An upgraded device therefore decodes each queued v2.2.0 content op as
`Retained(UnsupportedBody)`. The write leaves the pending view, never drains, and its staged
blocks stay pinned.

Greptile found this after the merge. FSM1/cipher-box#1905 adds a serde default: an absent
`scope` decodes as `NodeId::VAULT_ROOT`. That is the value the older build used, because it
bound every content key blob to the vault root. The open still checks the value against the
blob AAD, so a wrong scope still fails closed. The test
`a_content_op_written_before_the_scope_field_decodes_at_the_vault_root` removes `scope` from a
current body and decodes it.

No test, no review gate and no blueprint rule asked for this. The owner decision of 2026-09-19
makes the rule explicit.

## Decision

**D1 — The durable op queue reads every op that the previous release wrote.** A build decodes,
opens and drains each queue record that the release before it wrote. This covers the op
record framing, the intent grammar of each op kind, and the seal envelope. "The previous
release" is the `vX.Y.Z` tag before the build on the release train of `blueprint/deploy.md`.

**D2 — A new field on a queued op takes a decode default equal to the value the older build
used.** The default is not a guess and not a "safe" value. It is the value that the previous
release acted on when it wrote the record without the field. When no single such value exists,
D3 applies.

**D3 — A change that cannot meet D2 needs a migration step or its own ADR.** A removed op kind,
a changed meaning of an existing field, or a new field with no single older value cannot take
a decode default. Such a change either adds a migration step that rewrites the old records and
runs before the first drain of the new build, or it carries its own ADR that accepts the loss.
A header version bump (`OP_RECORD_V`) is such a change: the new build must still read the
previous version, or the bump strands every queued record at the old version.

**D4 — A default feeds the same checks as a written value.** A default never skips a
fail-closed check. The decoded value goes through every check that a written value goes
through, in the same order. Example: the defaulted `scope` of D2 still feeds the content key
AAD check, and a blob bound to another scope still refuses to open. A record that fails a check
takes the existing dead-letter path.

**D5 — Every change to a durable queued record carries a test that decodes the old shape.**
The test builds the bytes that the previous release wrote, decodes them with the new build, and
asserts the value that the drain acts on. The test must fail when the default or the migration
step is removed. A round-trip test of the new shape does not meet this obligation.

**D6 — The rule covers one release, not all releases.** A build does not have to read a record
that a build two releases back wrote. A default can go when the release after the one that
added it ships.

### Scope

The rule applies to a durable client record when two things are true: a deploy can leave the
record on a device, and the new build cannot get the record again from the network. For such a
record, a refusal after a deploy loses a member's write or locks the member out of the state
the record holds. The scope is therefore the op queue, the records the drain needs to finish a
queued op, the owner-local stores that fail closed, and the value format of a floor. All but
the floors sit behind the `StagingStore` seam.

In scope:

- **The op queue** — the op record framing, the intent grammar and the seal envelope (D1–D6
  in full).
- **The records that the drain needs to finish a queued op** — the staged content blocks and
  their root format, the preserved dead-letter set (the only carrier of a dead-lettered
  version's content key), the dead-letter notices, the drained and published op marks, the op
  attempt counts, the upload progress marks, the retire ledger and its tombstones, the doomed
  name journal, and the scope-exit debt. A queued op that decodes is of no use if the record
  that finishes it does not.
- **The owner-local sealed stores of ADR 0006 that fail closed** — received-share bookmarks,
  the contact book, and invite records. Each one refuses an unreadable value rather than
  reading it as empty, so a format change with no default locks the member out of the store.
  The received-share bookmarks have no network source: the mailbox items that delivered them
  are already acknowledged and do not come back.
- **The value format of a `FloorStore` entry.** A floor is a security bar, and an unreadable
  floor fails closed. A change to how a floor value is encoded must read the previous encoding.

Out of scope:

- **A change to a `FloorStore` key.** ADR 0016 changed the key shape with no migration: an
  old floor reads as absent, and the device re-seeds it from the record plane. That reasoning
  stays valid. A key change keeps its own ADR, as ADR 0016 did.
- **The `SnapshotCache`.** The fetch runs first, and a cache entry that does not decode acts
  as a miss. The network rebuilds it.
- **The `CredentialStore` refresh token and the web sealed Core Kit store.** An unreadable
  value means a new login. No write and no trust state is lost.

The name of this ADR says "op queue" because the op queue is the case that failed and the case
the other records serve. The rule is the same for each record in scope.

## Alternatives rejected

**Keep "v2 is greenfield, no backward compatibility" after the cutover.** Rejected. It was an
answer to the cutover, and #6 states its reason: v1 was staging-only, and no member state had
to survive. After the cutover, staging holds v2 member state, and the train often ships more
than one release in a day. FSM1/cipher-box#1900 shows the cost: a routine engine change stranded
unpublished writes, and only an after-merge review found it.

**Read every older release, not only the previous one.** Rejected for now. Each default then
stays in the code with no end, and each test matrix grows with the release count. One release
covers the normal case of a device that takes each deploy. D6 states the residual.

**Bump `OP_RECORD_V` on each grammar change, and let the old records stay retained.**
Rejected. The retained rule keeps the bytes, but the member's write does not publish. A
retained record is safe storage, not a working queue.

**Drop an old record as undecodable.** Rejected. A dropped record is a lost write with no
notice, which the dead-letter law of `blueprint/engine.md` forbids.

**A default that picks a "safe" value, not the older value.** Rejected. A value that the older
build did not use makes the drain act on a record the member did not author. D2 and D4 keep the
default honest: it is the older value, and it passes the same checks.

## Consequences

1. **`blueprint/engine.md` changes when this ADR is accepted.** The "Sync core" ops paragraph
   gains the sentences in "Blueprint change" below.

2. **`blueprint/deploy.md` "Cutover" stays as it is.** Its "no data migration" statement
   describes the v1 → v2 cutover, which is done. This ADR applies to each release after it.

3. **Review gains one question for a diff that touches a durable record in scope:** what does a
   record that the previous release wrote decode to? The answer is a test (D5).

4. **A retained record keeps its meaning.** It remains the rule for a record that a newer build
   wrote and an older build reads, for example after a rollback. This ADR does not change it.

5. **FSM1/cipher-box#1905 is the first implementation.** It lands the default of D2 and the
   test of D5 for `StagedContent.scope`.

## Residuals

**E1 — A device that skips a release has no guarantee.** A desktop that stays offline across
two releases, or a web client that is not opened across two deploys, can hold records that the
new build retains. The retained rule keeps the bytes and their staged blocks. The write does not
publish until a build that reads it runs.

**E2 — No gate finds a missing default automatically.** D5 depends on the author and the
reviewer seeing that a change touches a durable record. A fixture corpus of queue records
written by each release would find a miss in CI, but no such corpus exists.

**E3 — v2.3.0 is in the field without the default.** A device that took v2.3.0 before
FSM1/cipher-box#1905 ships holds v2.2.0 content ops as retained. They drain when a build with
the default runs, because the retained rule did not remove them.

## Blueprint change

After acceptance, add these sentences to `blueprint/engine.md` "Sync core", at the end of the
"Ops" bullet, after "Replay is FIFO in performed order through the standard rebase, and rebases
only onto gate-passing state (FSM1/cipher-box-next#33 D5–D7).":

> A build decodes, opens and drains every queue record that the previous release wrote
> (FSM1/cipher-box-next ADR 0020). A new field on a queued op takes a decode default equal to
> the value the older build used, and that default passes every check a written value passes.
> A change that cannot take such a default — a removed op kind, a changed meaning, a header
> version bump that stops reading the previous version — needs a migration step that runs
> before the first drain, or its own ADR. The same rule holds for the staging-store records
> that finish a queued op, for the owner-local sealed stores that fail closed, and for the
> value format of a floor; caches and credentials stay out. Every change to such a record
> carries a test that decodes the previous release's bytes.

## Gate

- `blueprint/engine.md` "Sync core" carries the sentences above.
- FSM1/cipher-box#1905 is merged, and its test
  `a_content_op_written_before_the_scope_field_decodes_at_the_vault_root` fails when the serde
  default is removed.
- Each later change to a record in scope carries a test that decodes the previous release's
  shape (D5).

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
