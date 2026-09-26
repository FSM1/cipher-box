# ADR 0047 — A failed or abandoned publish retires exactly what it charged

- **Status:** Accepted on 2026-09-26 — retroactive; the rule shipped in FSM1/cipher-box#923,
  FSM1/cipher-box#944, FSM1/cipher-box#1046 and FSM1/cipher-box#1862, and the blueprint carries
  it; the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-26
- **Relates to:**
  [#34](https://github.com/FSM1/cipher-box-next/issues/34) D2 (register-first, fail-closed), D3
  (per-account rows, union liveness) and D4 (retire = remove my row; the timing is client
  policy), [#24](https://github.com/FSM1/cipher-box-next/issues/24) D6 (coverage is structural;
  retirement is inventory removal), [#33](https://github.com/FSM1/cipher-box-next/issues/33) D6
  (a dead letter keeps its staged bytes),
  [#26](https://github.com/FSM1/cipher-box-next/issues/26) D6 (a fresh random content key per
  version),
  [ADR 0007](./0007-derived-idempotent-first-run-mint.md)
  D4 (the accepted one-head-block crash leak),
  [ADR 0011](./0011-quarantine-release-rests-on-the-doomed-manifest.md)
  D4 and its Context (no pass that journals an entry may decide it),
  [ADR 0019](./0019-file-version-retention-is-count-based-keep-latest-n.md)
  D3 and D4 (a retained version stays referenced by its own entry),
  [ADR 0046](./0046-the-registry-counts-references-per-record-and-caps-every-batch-at-1000.md)
  D1, D2 and E4 (the per-record reference count, the two retire forms, and why these retires use
  the account-wide form), the decision of 2026-08-20
  on FSM1/cipher-box#1226 (a spent attempt budget keeps the bytes), the `blueprint/engine.md`
  "Resolve/publish pipeline" section ("Retirement" bullet), the "Content plane" section
  ("Referenced equals kept" bullet) and the "Sync core" dead-letter paragraph, the
  `blueprint/api.md` "Pin/name registry" section ("Batch bounds", "Register-first,
  fail-closed" and "Per-referencing-record refcount"), and the `CONTEXT.md` "Register-first",
  "Union liveness", "Dead-letter" and "Version history" terms
- **Implemented by:** FSM1/cipher-box#923 (the abandoned op retires every charged block, D1 and
  D2), FSM1/cipher-box#944 (the per-attempt orphaned-head retire, D3 and D4),
  FSM1/cipher-box#1046 (the same retire for the vault settings publish),
  FSM1/cipher-box#1762 (a name wave carries every version's root and leaves to the new name, D5)
  and FSM1/cipher-box#1862 (retained roots register again on each publish, D5).

## Context

Every block a publish uploads goes through `POST /content/upload`. The API writes one sized pin
row per block, `{ accountId, cid, size, advisory: false }`, and the quota gate
`sumHostedBytes` counts exactly those rows. A registration at publish time adds reference and
name rows, but the charged row is the upload's own. So each upload is its own accountable pin
row. A row that no record can ever reach again spends quota for as long as the account exists.

Before FSM1/cipher-box#923, an abandoned op retired its write name and its version root only.
A version with 40 leaves whose upload stopped at leaf 39 left 39 charged rows behind.
`release_staged_blocks` then dropped the staged copies, so the client lost the only list of
those CIDs. The rows were unrecoverable from the client side (FSM1/cipher-box#916).

The head block has the same shape. A record publish uploads its head through the same charged
ingress, and the drain draws a fresh seal nonce on each pass. So each retry authors a new head
under a new CID. Before FSM1/cipher-box#944, no path retired a head block for any op kind. An op
that spent its five attempts left five charged heads. An op that retried three times and then
succeeded leaked three, and no abandonment ever came to collect them (FSM1/cipher-box#921).

The retire itself is destructive. `RegistryService.retire` unpins a CID physically when its
global reference count reaches zero. So the question is never only "what did this op charge".
It is also "can a live record name it". Both review gates on FSM1/cipher-box#923 found the same
trap in the first cut: an op whose record PUT was acknowledged may already be resolvable at its
name, with a background re-PUT still running. To retire there turns a quota leak into content
loss. The security gate on FSM1/cipher-box#944 found the mirror trap: the first cut retired the
head when no endpoint acknowledged the PUT. No ack is not proof that no endpoint stored the
record.

File versions add one more case. A file keeps its newest `keepLatestVersions` prior versions
(ADR 0019). Orphan GC collects a root that nothing references, so a retained version must
stay referenced, and a version that falls outside the rule must give back what it holds. The
drop cannot be undone, so the debt must survive a crash between the publish and the retire.

The blueprint carries the rule today in the `blueprint/engine.md` "Resolve/publish pipeline"
section, "Retirement" bullet, and in the "Content plane" section, "Referenced equals kept"
bullet. `blueprint/api.md` "Pin/name registry" carries the batch cap and the retire forms. No
decision thread records the rule. This ADR records it.

## Decision

**D1 — An abandoned op retires the whole set its publish charged.** The set is the name the op
registered and every block it uploaded, root and leaves. The name is retired only when no
published record references it: an abandoned create hands back the child name it derived, and
an abandoned `updateContent` keeps the file's own live name. The engine reads the leaf CIDs from
the staged root manifest before it releases the staged blocks, because after the release the
list exists nowhere. It reads the manifest through a CID-verified reader
(`version_leaf_cids` in `crates/engine/src/sync/staging.rs`), so a staging-store co-tenant
cannot choose the leaf list that a destructive call names. The retire uses the account-wide form
(an entry with no `ipnsName`, `blueprint/api.md` "Per-referencing-record refcount"), and chunks to
the registry batch cap of 1000 targets (`retire` in `crates/engine/src/net/retire.rs`). Retire is
idempotent, so a target that never landed costs nothing. A failed chunk leaves the earlier chunks
retired and the op queued, and the next pass replays the whole batch. The op leaves the queue
only after the retire succeeds (`Drain::dead_letter` and `Drain::abandon` in
`crates/engine/src/sync/drain.rs`). The rule landed with FSM1/cipher-box#923; this ADR records
it.

**D2 — An op whose record PUT was acknowledged retires nothing.** The record may be resolvable at
its name. Unpinning content that a live record still references is loss, and leaving the rows
charged is only a leak. So a spent attempt budget on an acknowledged-but-unconfirmed publish
(`Halt::Attempt`) dead-letters the op and retires neither the name nor a block. The half of the
old attempt arm that fails before any PUT (an unattributable upload refusal) is a separate halt,
`Halt::UploadAttempt`, because nothing reached the transport there. The rule landed with
FSM1/cipher-box#923; this ADR records it.

**D3 — A publish that fails before its record reaches the transport retires its head block, on
each attempt.** Such a failure leaves a head block that is already uploaded and charged under its
own row, and no record can name it. The retry authors a new head under a fresh seal nonce, so the
old head is permanently unreachable. The qualifying failures are exactly those that
`orphaned_head` (`crates/engine/src/net/retire.rs`) names: a register-first refusal, a floor-read
failure, a head-CID echo mismatch, an epoch below the floor, a record over the size limit, an
exhausted sequence, and an upload whose answer never came back (a transport failure or an
unreadable 2xx). The predicate matches every publish error variant exhaustively, so a new publish
error variant does not compile until someone classifies it. The engine notes the head CID and
retires the pending set at the end of the pass that orphaned it, independent of the op's fate:
an op that later succeeds still retires what its failed attempts charged. The pending set
(`OrphanHeads`) is session-lived and capped at 1000 entries. A refused retire keeps the set for a
later pass. In the drain, a head that the live held set still names never enters it
(`Drain::record_orphan_head`). The vault settings publish and the bin index publish use the same
predicate and the same set, record the head without that check, and retire at the point of
failure (FSM1/cipher-box#1046; `crates/engine/src/settings.rs`, `crates/engine/src/bin_index.rs`).
The rule landed with FSM1/cipher-box#944; this ADR records it.

**D4 — A fan-out that acknowledged nothing does not qualify under D3.** `AllEndpointsFailed` says
that no endpoint acknowledged the PUT. It does not say that no endpoint stored the record. A lost
ack can leave a record resolvable at the name that points at this head, and D2's reason applies.
Two other failures do not qualify either, for a different reason: an upload that the server
refused with a status answer charged no row, and an empty head CID addressed nothing. The rule
landed with FSM1/cipher-box#944; this ADR records it.

**D5 — Each publish of a file registers every retained version's root again under the file's own
name, and a dropped version's debt is journaled before the shortened history publishes.** The
content publish registers the new head version's blocks plus the root of each prior version that
the retention rule keeps. A write-rotation name wave registers every version's root and leaves at
the node's new name before the record moves (FSM1/cipher-box#1762). A version that falls outside
the
rule loses that reference. What it owes the registry goes to the durable retire ledger first
(`Drain::shorten_history` and `Drain::journal_retire_debt`). A debt the ledger does not take
leaves the history it was read from standing, and the pass publishes no shortened history. The
ledger later retires the debt under the owning record, in the record-scoped form. This is the
mechanism behind ADR 0019 D3 ("a retained version stays referenced by its own entry"): the entry
is the reference, and the re-registration is how the registry learns it. The rule landed with
FSM1/cipher-box#1862; this ADR records it.

The delete path's quarantine is outside this ADR. "No pass that journals an entry may decide it"
is ADR 0011 D4 and its Context.

## Rationale

- **The charge is per upload, so the retire must be per upload.** The API charges a row at
  upload time, not at registration time. A retire that names the root only, or the name only,
  misses every other row the op charged.
- **The asymmetry of the two errors decides every edge.** A retire too few leaves a charged row:
  a bounded, visible leak. A retire too many unpins bytes that a live record names: loss that no
  later pass can undo. Where the engine cannot prove that no record names a CID (D2, D4), it
  keeps the row.
- **"Before the transport" is the proof D3 needs.** A failure raised before any PUT means that
  no record on the network names the head. The fresh nonce means that no later record of this op
  names it either. The two facts together make the head unreachable.
- **Per pass is stricter than per abandonment.** An op that retries and then succeeds never
  abandons. A per-abandonment retire would never collect its orphaned heads. The per-pass retire
  collects them and needs no new durable format, no staging key and no pruning pass.
- **The account-wide form is safe for these targets.** Each version draws a fresh random content
  key (#26 D6), and each head seals under a fresh 192-bit nonce. So an abandoned version's CIDs
  and an orphaned head's CID are unique to that op, and no other record of the account names
  them (ADR 0046 E4). In the drain, the live-set guard of D3 checks this for the head instead of
  trusting it.
- **Chunking at the client keeps one server bound.** The registry already refuses a batch over
  1000 fail-closed. `retire` is the one chokepoint every retire passes through, so the name wave
  and the sweeps get the same chunking.
- **Journal first makes the drop crash-safe.** A shortened history on the network with no
  journaled debt would leak the dropped version permanently, since no later pass can name it. A
  journaled debt with the old history still standing costs nothing: the next pass journals again
  and publishes.

## Alternatives rejected

**Route the whole attempt arm through the abandonment.** FSM1/cipher-box#916 asked for it. The
arm included the acknowledged-but-unconfirmed publish, so the change would unpin a version a
live record may name. Both review gates flagged it as the highest finding in FSM1/cipher-box#923.
The arm was split instead (D2).

**Give the retire endpoint a new batch limit.** FSM1/cipher-box#916 assumed the endpoint had no
cap. It had one: `BatchSizePipe` refuses a batch over 1000 before any database work. The fix
chunks at the client instead (D1).

**Keep a durable per-op list of every head the op minted, and retire it at abandonment.**
FSM1/cipher-box#921 proposed it. It misses an op that retries and then succeeds, and it needs a
new staging key, a format tag and a pruning pass. The per-pass retire covers strictly more (D3).

**Re-PUT the bytes of the earlier attempt instead of authoring a new head.**
FSM1/cipher-box#921 asked whether re-authoring per attempt is needed at all. Reuse needs the
authored record bytes made durable and the publish plan pinned across passes. The drain
re-derives its plan from the current gate-passing base on each pass, so this is a change to the
publish pipeline, not to retirement. It was not taken.

**Retire the head on `AllEndpointsFailed`.** The first cut of FSM1/cipher-box#944 did. A lost
ack leaves a resolvable record that names the head, so the retire would make that node
unreadable (D4).

**Keep a retained version by a separate reference count on its root.** ADR 0019 rejected this.
The version's entry in the read-body is the reference, and D5 registers it again on each
publish.

## Consequences

1. **`blueprint/engine.md` already carries D1 to D4.** The "Resolve/publish pipeline" section,
   "Retirement" bullet, states the whole-set retire, the chunking, the idempotence, the
   acknowledged-PUT rule, the per-attempt head retire with its four named failures, and the
   zero-ack exemption. No text change is needed.
2. **`blueprint/engine.md` already carries the same-name half of D5.** The "Content plane"
   section, "Referenced equals kept" bullet, states the re-registration under the file's own name
   and the journal-first order. `CONTEXT.md` "Version history" states that a retained version's
   root stays registered under the file's own name. No blueprint section carries the name-wave
   carry to the new name; item 7 adds it.
3. **`blueprint/api.md` already carries the registry side.** The "Pin/name registry" section,
   "Batch bounds" bullet, names "an abandoned version whose leaves all need retiring" as a bulk
   caller that chunks to the cap. The "Per-referencing-record refcount" bullet names the
   account-wide form as the path an orphaned head block needs. `CONTEXT.md` "Register-first" and
   "Union liveness" define the rows the retire removes. No text change is needed.
4. **ADR 0007 D4 reads more narrowly under this ADR.** D4 says that the crash leak of one head
   block is "handled by the existing orphan-head path". The path of D3 reaches a failure that a
   live pass observes. It does not reach a process that dies between the head upload and the
   record PUT, because the pending set is session-lived. The one-block crash leak that D4 accepts
   therefore stays leaked; no path retires it. D4's acceptance of the leak does not change.
5. **ADR 0019 D3 reads with D5 as its mechanism.** "No new machinery" means no machinery beyond
   the re-registration that the publish path already runs.
6. **`blueprint/engine.md` section "Resolve/publish pipeline", "Retirement" bullet, gains the
   citation (ADR 0047)** after the sentence that ends "no ack is not proof nothing stored".
7. **`blueprint/engine.md` section "Content plane", "Referenced equals kept" bullet, gains the
   citation (ADR 0047) and one sentence for the carry:** "A write-rotation name wave registers
   every version's root and leaves at the node's new name before the record moves (ADR 0047)."

## Residuals

**E1 — The blueprint does not say which exits are an abandonment.** In the code, two exits retire
the whole set under D1 (`Drain::abandon`): a permanent refusal (`Halt::Permanent`, except
`BaseSuperseded` and `AlreadyPublished`), and a terminally unrebasable op. The unrebasable exit
also preserves its staged bytes locally, and when the preserved set refuses them, it releases
them after the retire. A spent attempt budget on a failure before the transport
(`Halt::UploadAttempt`, `RecordRefused`, `HeadOversized`, `ScopeRootNotResealable`) is not one
of them. The decision of 2026-08-20 on FSM1/cipher-box#1226, shipped in FSM1/cipher-box#1343,
made it a dead letter that keeps its version and every row it charged, and hands back only the
name of an unreferenced create (`Drain::apply_valve`). A spent budget on `Halt::UnwritableScope`,
and a spent unattributed budget (`Halt::Unclassified`, `Halt::LostRace`,
`Drain::abandon_keeping_its_name`), keep the version, the name and every row. The "Retirement"
bullet does not carry these carve-outs; only the "Sync core" dead-letter paragraph implies them.
This ADR records the blueprint rule as written. It does not ratify or revert the
FSM1/cipher-box#1226 decision. The owner should decide whether the carve-outs join this ADR as a
Dn and the "Retirement" bullet.

**E2 — A released dead letter that kept its rows retires nothing.** Under E1, a dead letter that
keeps its version also keeps the rows its partial upload charged. Three paths release that
version's local blocks and send no retire:

- `Engine::discard_dead_letter` (`crates/engine/src/facade.rs`), when the member discards it;
- `trim_preserved` through `reconcile_preserved_dead_letters`
  (`crates/engine/src/sync/staging.rs`), when the preserved set evicts it by age, count or bytes;
- `Drain::release_if_refused` (`crates/engine/src/sync/drain.rs`), at once, when the preserved
  set refuses to hold it.

The charged rows then leak permanently, because the release drops the only manifest that lists
them. This is a leak, not a loss, but no path bounds it. FSM1/cipher-box#2021 carries the three
paths, the two retire-ledger gaps that the fix must close, and the custody rule for entries that
another session parked.

**E3 — The orphaned-head set does not survive the session.** A crash, a sign-out, or a session
whose retires keep failing loses the pending heads. The cap of 1000 bounds memory, not the leak:
past the cap, a new orphan is dropped unrecorded. ADR 0007 D4 accepts the crash form of this
leak.

**E4 — An acknowledged PUT that never becomes live leaks everything it charged.** D2 keeps the
name, the head and every content row of such an op. No later pass learns that the record never
landed. The cost is bounded by the attempt budget per op.

**E5 — A version whose root the name wave cannot fetch carries its root alone.** The wave
expands each version from its root to carry the leaves. When it cannot fetch a root, that version
registers its root at the new name and no leaf. Its leaves lose their reference edges when the old
name retires. They stay pinned only because the registry deletes a pin row only for a CID that the
batch names as a target, and a name retire names no leaf (`RegistryService.retire` in
`apps/api/src/registry/services/registry.service.ts`; ADR 0046 D1). If that registry behaviour
changes, this case turns from a lost edge into a lost pin.

## Gate

Engine tests run in the `Engine simulation tests` job of the `Rust` gate. Contract tests run in
the `Contract Suite` gate.

- **D1:** `an_abandoned_version_retires_every_block_it_uploaded_and_keeps_the_files_name`,
  `an_abandoned_create_retires_the_child_name_it_registered_exactly_once` and
  `a_refused_dead_letter_retires_its_blocks_before_it_releases_them` in
  `crates/engine/tests/write_plane.rs`; `an_oversize_batch_splits_into_chunks_the_server_accepts`
  in `crates/engine/src/net/retire.rs`;
  `an_abandoned_versions_whole_block_set_retires_back_to_the_pre_upload_figure`,
  `an_oversize_retire_batch_is_refused_fail_closed` and
  `batch_register_and_retire_are_idempotent` in `crates/contract/tests/contract.rs`.
- **D2:** `an_unconfirmed_publish_never_retires_the_version_it_may_already_name` and
  `a_publish_that_never_confirms_dead_letters_once_its_attempt_budget_runs_out` in
  `crates/engine/tests/write_plane.rs`.
- **D3:** `every_head_block_a_retrying_op_orphaned_leaves_the_inventory` in
  `crates/engine/tests/write_plane.rs`;
  `only_a_publish_that_never_reached_the_transport_orphans_its_head` in
  `crates/engine/src/sync/drain.rs`;
  `a_register_first_refusal_retires_the_settings_head_it_uploaded` in
  `crates/engine/tests/vault_settings.rs`;
  `every_head_block_a_retrying_publish_orphaned_retires_back_to_the_pre_upload_figure` in
  `crates/contract/tests/contract.rs`. No test proves the live-set guard: a head that the held
  set still names must not enter the pending set. That is a finding.
- **D4:** `a_publish_that_reached_the_transport_never_retires_its_head` in
  `crates/engine/tests/write_plane.rs`;
  `a_settings_publish_whose_fan_out_acked_nothing_retires_nothing` in
  `crates/engine/tests/vault_settings.rs`; the `AllEndpointsFailed`, status-refusal and
  `EmptyHeadCid` rows of `only_a_publish_that_never_reached_the_transport_orphans_its_head`.
- **D5:** the journal-first half is proved by
  `a_prune_whose_ledger_write_fails_leaves_the_history_standing_and_still_reclaims`,
  `a_content_write_retires_only_the_version_the_retention_rule_drops` and
  `a_prune_whose_retire_is_refused_keeps_the_debt_until_a_later_pass` in
  `crates/engine/tests/write_plane.rs`. The name wave's carry to the new name is proved by
  `a_moved_file_registers_the_content_its_record_names` and
  `a_moved_file_carries_every_version_it_names_to_the_new_name` in
  `crates/engine/src/net/rotation.rs`. No test asserts that a content publish registers every
  retained version's root again under the file's own name. That is a finding.
- **E1 carve-out (context, not a Dn):**
  `a_version_whose_upload_budget_runs_out_keeps_the_bytes_it_already_charged` and
  `a_spent_budget_keeps_its_version_across_the_cold_start_that_drops_its_op` in
  `crates/engine/tests/write_plane.rs`.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
