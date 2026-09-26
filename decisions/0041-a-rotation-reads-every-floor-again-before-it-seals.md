# ADR 0041 — A rotation reads every floor again before it seals

- **Status:** Accepted on 2026-09-26 — retroactive for D2 to D8, which shipped in FSM1/cipher-box#1177,
  FSM1/cipher-box#1200, FSM1/cipher-box#1285, FSM1/cipher-box#1307, FSM1/cipher-box#1542 and
  FSM1/cipher-box#1750; the blueprint carries D5 to D8 and a wider wording of D2. D1 is a new
  decision for the owner to accept: it extends D2 to D4 to the write-wave root arm, where no code
  and no blueprint text reads the cut-epoch floor today; the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-26
- **Relates to:**
  [#38](https://github.com/FSM1/cipher-box-next/issues/38) D2 (the scope pointer is the canonical
  re-point channel), D3 (one owner-signed re-point object on three channels, which this ADR
  amends), D4 (a pointer `writeEpoch` above the floor advances it) and D6 (the direct-child-scope
  index self-heal), [#26](https://github.com/FSM1/cipher-box-next/issues/26) D3 (the name wave)
  and D8 (published records are the sole source of truth),
  [#39](https://github.com/FSM1/cipher-box-next/issues/39) D4 (the floor law) and D5 (the indexed
  vault pointer), [#23](https://github.com/FSM1/cipher-box-next/issues/23) D4 (a lost race),
  [ADR 0003](./0003-sweep-population-and-below-floor-scope-roots.md)
  D2 and D3 (a below-floor scope root is superseded; the self-heal is a walk-time repair),
  [ADR 0012](./0012-the-drain-carries-the-write-wave-forward.md)
  and
  [ADR 0021](./0021-a-read-opens-an-epoch-lagged-interior-record.md)
  D2 (the lagging readers move no read-epoch floor),
  [ADR 0014](./0014-a-verified-commitments-cut-epoch-raises-the-floor-without-an-unseal.md)
  (the cut-epoch raise without an unseal),
  [ADR 0032](./0032-the-owner-signs-each-grant-row-and-the-commitment-names-every-recipient.md)
  D6 (the cut-epoch bar at stage 2) and E4 (which hands the cut-floor mirror to this ADR), the
  `blueprint/engine.md` sections "Adoption gate and floors", "Rotation primitives", "sweep",
  "rotateScopeWrite", "Pointer planes" and "Mailbox logic", and the `CONTEXT.md` terms "Floor
  law", "Cut epoch", "Name wave", "Re-point object", "Scope pointer", "Vault pointer" and
  "Forgery window"
- **Implemented by:** FSM1/cipher-box#1177 (D2, the write-epoch floor), FSM1/cipher-box#1285 (D2,
  the read-epoch floor), FSM1/cipher-box#1307 (D3), FSM1/cipher-box#1750 (D4),
  FSM1/cipher-box#1200 (D5, with the blueprint sentence from FSM1/cipher-box#1066) and
  FSM1/cipher-box#1542 (D6 to D8).

## Context

A published record cannot be unpublished. A rotation signs a record against floors it read
earlier, and between that read and the signature another leg of the engine can raise a floor. The
engine is a single writer per device, but it is not a single task: a focus-window tick, a
`/shared` pass and a pointer consult all raise durable floors while a rotation parks its re-seal.
When the signed record then sits below a floor, the gate of this device refuses it for ever, and so
does the gate of every reader that holds the same floor. The floors are monotonic, so no later pass
can lower the bar to meet the record.

Four defects showed the shape, one floor at a time:

- **The write-epoch floor, FSM1/cipher-box#1130.** `WriteWaveNet::publish_moved` checked the root
  republish against the floor snapshot that the enumeration took. The whole child-first interior
  wave runs between the two, and a pointer consult raises the floor on sight (#38 D4). The
  `ownerWriteBlob` AAD binds the write epoch and `open_write_body` unseals at the floor, so a root
  sealed at or below the live floor published a write plane that no later rotation could open.
  FSM1/cipher-box#1177 made the root arm re-read the floor.
- **The read-epoch floor, FSM1/cipher-box#1180.** The name wave re-seals every node at the
  envelope epoch the enumeration captured, because a name wave cuts no read key. A read rotation
  adopted mid-wave lifts the read-epoch floor above that epoch. Every record the wave then
  publishes fails gate stage 5 on every reader. Interior old names retire at completion, so the
  subtree ends up unreachable at both names. FSM1/cipher-box#1285 made every republish re-read the
  floor.
- **The retire and the re-point, FSM1/cipher-box#1293.** The two irreversible steps after the
  republishes read no floor. The retire tombstoned old names whose moved copies sat below a risen
  floor. The re-point could carry a `minReadEpoch` or a `writeEpoch` that this build's own cold
  seed refuses. FSM1/cipher-box#1307 added both checks.
- **The cut-epoch floor, FSM1/cipher-box#1750.** `RootPublish::check_publishable` mirrored the
  read-epoch and write-epoch floors, but not the cut-epoch floor that stage 2 holds every
  grant-set commitment to. A `/shared` pass raised that floor from the owner's fresh cut while a
  rotation parked its re-seal. The rotation then signed a root that its own stage 2 refuses, and
  overwrote the owner's post-cut record at a higher sequence: a revocation rollback made by an
  honest client.

Two neighbouring rules came out of the same work. The sweep's index self-heal must not write the
superseded name that caused the repair (FSM1/cipher-box#1066, FSM1/cipher-box#1200). And the
re-point channels had to match what the engine can publish: #38 D3 names three channels, but the
mailbox and the old-name tombstone had no wire shape and no consumer, and
`WriteWaveNet::publish_repoint` answered both with `NotLanded` for ever (FSM1/cipher-box#1137).
The same change gave the vault anchor a re-point, because the vault pointer was frozen at genesis
and a cold start after a root write rotation declined the write scope seed it had just recovered
(FSM1/cipher-box#1447). FSM1/cipher-box#1542 landed both, and it kept the vault pointer outside
the write-epoch bar, which FSM1/cipher-box#1447 had asked to remove.

`blueprint/engine.md` carries the name-wave re-read and the channels in "rotateScopeWrite", the
self-heal in "sweep", and the write-epoch bar in "Pointer planes". The pre-publish mirror of the
cut-epoch floor, and the checks on the retire and the re-point, are in the code only.

## Decision

**D1 — A rotation publish re-reads every floor the gate holds its record to, just before it
signs.** The read comes after the publish's own gated read of the record it replaces, because that
read can itself raise a floor. It comes before any signature, and before any irreversible step. It
compares strictly: a record at the floor publishes, a record below it is refused release-active
(AGENTS.md rule 8), and nothing is signed. A floor that cannot be read refuses the publish as a
retryable failure; it never reads as "no floor". The floors are the read-epoch floor (stage 5),
the write-epoch floor (the `ownerWriteBlob` AAD), and, for a record that seals a grant-set
commitment, the cut-epoch floor (stage 2). D2 to D4 are the instances in the code today; they
landed across FSM1/cipher-box#1177, FSM1/cipher-box#1285, FSM1/cipher-box#1307 and
FSM1/cipher-box#1750, and this ADR records them. D1 extends them to every publish that seals a
grant-set commitment, the write-wave root arm included. That extension is a new decision, and
the owner must accept it: the root arm reads no cut-epoch floor today (E1), and the blueprint
states no such rule.

**D2 — The name wave re-reads the read-epoch floor at every republish, and the write-epoch floor at
the root.** Every republish, interior and root, re-reads the scope's read-epoch floor and refuses
when the wave's carried epoch is below it (`WriteWaveNet::publish_moved` in
`crates/engine/src/net/rotation.rs`). The root arm is the only arm that re-seals a write plane. It
takes the write-epoch lease (`floor::WriteEpochLease`), then re-reads the write-epoch floor and
refuses when the floor has risen above the write epoch the enumeration opened the root at. The lease
holds the write-epoch floor still until the signature: a pointer sighting inside the window is
deferred, not applied. The rule landed with FSM1/cipher-box#1177 (the write-epoch floor) and
FSM1/cipher-box#1285 (the read-epoch floor, closing FSM1/cipher-box#1180); this ADR records it. It
is the publish-side mirror of gate stage 5. An interior republish re-reads no write-epoch floor,
because it re-seals no write plane. So D2 is narrower than the blueprint sentence "every republish
re-reads both durable floors", and consequence 6 corrects that sentence to the code.

**D3 — The wave's re-point and retire re-read the floors too.** Before the owner signs the
re-point object, `check_repoint_publishable` runs `floor::repoint_regression`, the same predicate
the cold seed runs on the consume side, at the scope-pointer bar (D8). So this build never signs a
re-point that a reader of either channel refuses. Before the interior old names retire,
`WriteWaveNet::retire` re-reads the read-epoch floor and refuses when the lowest read epoch the
wave gated is below it. With no gated read behind the batch, the retire refuses: that epoch is the
only evidence the step rests on. A refused retire leaves every old name live. The rule landed with
FSM1/cipher-box#1307; this ADR records it.

**D4 — The owner re-seal reads the cut-epoch floor under the write-epoch lease.**
`RootPublish::check_publishable` in `crates/engine/src/net/rotation.rs` reads the read-epoch, the
write-epoch and the cut-epoch floors while `RootPublish::run` holds the write-epoch lease, and
refuses release-active when `record.section.commitment.cut_epoch < cut_floor`, with the same strict
`<` as `refuse_stale_cut_epoch` in core. Every production `ScopeRootPublisher` reaches it: the owner
net, the grantee net, and the vault-root wrapper `VouchedRoot`, which delegates to one of them. So
the cascade, the grant mint, the grant edits (append, invite, permission change, rename and
conversion) and the index repair all publish through this check. The rule landed with
FSM1/cipher-box#1750 on 2026-09-05; this ADR records it.

**D5 — The index self-heal writes only a name that the walk resolved current.** A scope root that
the sweep meets below its own read-epoch floor is superseded (ADR 0003 D2). The walk consults the
scope pointer and re-resolves at `currentRootName` first (`resolve_scope_current` in
`crates/engine/src/rotation/sweep.rs`). Only the name that resolve gated current may enter a
repaired `directChildScopeIndex`. The repair never persists the superseded name that caused it.
The blueprint sentence landed with FSM1/cipher-box#1066 and the code with FSM1/cipher-box#1200;
this ADR records it. It adds a clause to ADR 0003 D3, which makes the self-heal a walk-time repair
but does not limit the name it writes.

**D6 — The re-point publishes on two channels, and the mailbox carries no re-point.** The channels
are the scope pointer record, and, when the rotated scope is the vault anchor, the indexed vault
pointer at the index this session adopted (`RepointChannel` in
`crates/engine/src/rotation/rotate_write.rs`). The anchor is structural: it is the scope whose id
is the session root scope id, never a scope that happens to have a signer. No old-name tombstone is
published, and no re-point item is posted to the mailbox. The mailbox carries share pointers,
claims and courtesy notifications alone. The channel count was decided on 2026-08-26 in
FSM1/cipher-box#1137; the comment of that date says "Decided", and the audit did not rate its
ownership. The rule landed with FSM1/cipher-box#1542.

**D7 — Each channel carries its own seal, in a fixed order, and neither is best-effort.** The
engine gates one owner-signed re-point object once, then seals it once per channel under
`pointerReadKey` with a fresh nonce. No two published blocks are byte-identical, so the
account-level vault-pointer name does not join to a scope-pointer name that every grantee of the
scope holds. The scope pointer flips first and the vault pointer second. A vault-pointer arm with
no signer, or for a scope other than the session root, refuses release-active rather than skipping
the plane. A wave that does not land both flips stays incomplete and resumable from the published
records, and it retires no interior old name. The rule landed with FSM1/cipher-box#1542; this ADR
records it.

**D8 — The write-epoch floor holds the scope pointer alone.** The two channels flip in sequence,
not atomically, so a wave that stops between them leaves the vault pointer one write epoch behind.
That lag is honest state. The consume side therefore never measures the vault pointer's
`writeEpoch` against the write-epoch floor (`PointerPlane::VaultPointer` in
`crates/engine/src/gate/floor.rs`); the cold seed still raises the floor from it, monotonic-max.
The scope pointer is the write-epoch clock, and a scope pointer below the floor is a fail-closed
trust violation at every scope. The produce side holds the one re-point object to the stricter
scope-pointer bar for both channels (D3). The rule landed with FSM1/cipher-box#1542, which kept the
narrowing that FSM1/cipher-box#1447 asked to remove; this ADR records it.

## Trust argument

- **A refused publish signs nothing, and the next pass rebases.** Every check in D1 to D4 runs
  before the signature and before any irreversible step. The floor only rises, so the refusal is
  the right answer for these bytes, and the next pass rebases on the record that raised the floor.
- **A record below the read-epoch floor would strand the subtree.** Stage 5 refuses it on every
  reader, this device included. The retire then removes the old names. D2 and D3 keep both names
  from dying at once.
- **A record below the write-epoch floor would lock the write plane.** The `ownerWriteBlob` AAD
  binds the write epoch, and the next rotation opens the write body at the floor. The lease keeps
  the floor still between the check and the signature, so the check stays true when it is spent.
- **A commitment below the cut-epoch floor would roll a revocation back.** The pre-cut set is
  authentic and verifies for ever, because it carries no read epoch. Signed at a higher sequence
  than the owner's post-cut record, it replaces that record for every reader that holds no floor.
  D4 stops an honest client from making that replay.
- **An unreadable floor never reads as zero.** A seam failure refuses the publish as retryable.
  Reading it as "no floor" would pass every bar.
- **The self-heal cannot re-poison the index.** The superseded name is the stale entry the repair
  exists to remove. The name D5 writes comes from the owner-signed scope pointer and a gated
  resolve.
- **The removed channels carried no safety.** #38 D2 already made the mailbox and the tombstone
  accelerators; the scope pointer is canonical, and the consult discipline of #38 D4 does not wait
  for either. Removing them costs discovery latency only, inside the pointer-consult bound that
  `blueprint/engine.md` "Residuals" already states for read-only survivors.
- **A fresh seal per channel keeps the planes unlinkable.** One block at two names is a
  zero-false-positive join between an account-level name and a name every grantee holds, and it
  outlives revocation.
- **The vault-pointer exemption does not open a rollback.** The vault plane stays guarded by the
  read-epoch stage at the anchor, the durable vault-pointer index floor, and the clock-checked
  scope-pointer consult. The produce side still refuses to sign a re-point that either plane's
  reader refuses.

## Alternatives rejected

**(a) Check against the floor snapshot that the enumeration or the gated read took.** This was the
code before FSM1/cipher-box#1130 and FSM1/cipher-box#1180. The wave runs a whole subtree between
the snapshot and the signature, and a pointer consult or a tick raises the floor in that time.
Rejected.

**(b) Re-read the floors at the republish only, and trust them for the re-point and the retire.**
The retire is the one irreversible step, and the re-point is a signed owner statement. A floor can
rise between the root republish and either step (FSM1/cipher-box#1293). Rejected.

**(c) Land the old-name tombstone as a record kind.** No `movedTo` record type, encoder or decoder
exists, and the migration-window closure signal is an open edge. Landing it means a new wire format
with no decision behind it. Rejected in FSM1/cipher-box#1137.

**(d) Land the mailbox re-point.** The payload was specified, but nothing polled it into
`open_repoint`. The post would burn the recipient's mailbox quota and emit owner-to-grantee
metadata at rotation time while it accelerated nothing. Rejected in FSM1/cipher-box#1137.

**(e) Keep three channels with two that report "not landed".** A specified channel that never
lands is a false promise in the spec. Rejected in FSM1/cipher-box#1542.

**(f) Seal the re-point once and publish the same block on both planes.** This joins the vault
pointer name to a scope-pointer name. Rejected in review on FSM1/cipher-box#1542.

**(g) Hold the vault pointer to the write-epoch floor.** FSM1/cipher-box#1447 proposed it once the
vault pointer tracks the root. A wave that stops between the two flips would then turn an honest,
resumable lag into a refused boot. Rejected in FSM1/cipher-box#1542.

**(h) Make the vault-pointer flip best-effort.** The cold start reads that plane first. A plane
left on a moved root makes the cold start decline the write scope seed it recovers
(FSM1/cipher-box#1447). Rejected.

**(i) Write the encountered name into the index, then consult.** The encountered name is the
superseded one. Writing it first re-poisons the entry the walk is healing. Rejected in review on
FSM1/cipher-box#1066.

## Consequences

1. **`blueprint/engine.md` already carries D5, D6, D7 and D8.** "rotateScopeWrite" carries the
   two channels with their seals, order and resumable wave. "sweep" carries the current-name rule
   of the self-heal. "Pointer planes" carries the vault-anchor re-point and the write-epoch clock
   of the scope pointer alone. "Mailbox logic" names no re-point item. No text change is needed
   for these rules. "rotateScopeWrite" carries D2 in a wider form than the code, and consequence
   6 corrects it.

2. **`CONTEXT.md` "Floor law", "Cut epoch", "Scope pointer" and "Vault pointer" need no change.**

3. **Texts still name the removed accelerators, and they lag D6.** No `movedTo` record exists
   (alternative (c)), so the old root name serves no tombstone. Each text below loses its mailbox
   or tombstone clause:
   - `CONTEXT.md` "Name wave": "mailbox and old-name tombstone as accelerators".
   - `CONTEXT.md` "Re-point object": "mirrored to the mailbox and the old name's tombstone as
     accelerators".
   - `CONTEXT.md` "Forgery window": "tombstones advisory only".
   - `blueprint/engine.md` "Link-held arm": "with the old-name tombstone and the mailbox mirror as
     accelerators only".
   - `blueprint/engine.md` "Revocation is discovered, not delivered" (line 1079): "tombstones
     advisory only".
   - `blueprint/engine.md` "Retirement" (line 142): "the old scope-root name lingers serving the
     tombstone until the migration window closes".
   - `blueprint/engine.md` "Open edges" (line 1460): "how long the old scope-root name lingers
     serving the tombstone before retire".
   - The module header of `crates/engine/src/grants/link_read.rs`, which names the tombstone and
     the mailbox mirror as accelerators.
   - The module header of `crates/engine/src/net/retire.rs` (line 6): "scope-root name lingers
     serving the tombstone until the migration window".
   - The comment on `WriteWaveNet::retire` in `crates/engine/src/net/rotation.rs` (line 4845): "the
     old root serves the tombstone every lagging reader chases".

   The old root name still lingers until the migration window closes. That is a retirement rule,
   not a re-point channel, and it does not change.

4. **#38 D3 reads as two channels.** Under D6 and D7, "one owner-signed re-point object, three
   channels" reads "one owner-signed re-point object, two channels, each sealed on its own: the
   scope pointer, and the vault pointer when the scope is the vault anchor". #38 D2 keeps the scope
   pointer as the canonical channel; its sentence "Both are kept as accelerators only" reads
   "Neither is published". The residual bound of #38 for read-only survivors does not change.

5. **ADR 0003 D3 gains a clause.** The self-heal is a walk-time repair, and it writes only a name
   the walk resolved current (D5). ADR 0003 does not otherwise change.

6. **`blueprint/engine.md` gains the rules it does not carry, with the citation (ADR 0041).**
   "Rotation primitives" gains D1 and D4: "Every rotation publish re-reads, after its own gated read
   and immediately before it signs, each durable floor the gate holds the record to — the
   read-epoch, the write-epoch and, for a scope root, the cut-epoch floor — and refuses below any of
   them (ADR 0041)." "rotateScopeWrite" gains D3 after the paragraph on the re-read: "The re-point
   is held to the scope-pointer bar before it is signed, and the retire re-reads the read-epoch
   floor and refuses on a rise (ADR 0041)." In "rotateScopeWrite", the sentence at lines 886 to 887,
   "every republish re-reads both durable floors immediately before it seals and refuses below
   either", becomes "every republish re-reads the read-epoch floor immediately before it seals, the
   root republish also re-reads the write-epoch floor, and each refuses below the floor it reads
   (ADR 0041)". The "sweep" self-heal sentence and the "Pointer planes" bullet on the write-epoch
   clock each gain the citation (ADR 0041).

7. **ADR 0032 E4 points here.** Its note that the grant edits read no cut-epoch floor holds for
   `grants/invite.rs::check_publishable`, which mirrors the decode-side structural rejects only.
   Their publish reaches the D4 check through the owner net. The gap that remains is the wave
   root arm, residual E1.

8. **No wire format, no KDF edge and no op queue record changes.**

## Residuals

**E1 — The name wave's root arm signs a commitment with no cut-epoch floor read.** The root arm of
`WriteWaveNet::publish_moved` re-reads the read-epoch and write-epoch floors only (D2), then
re-seals the grant section with `reseal_root` and signs the root. A cut-epoch raise that lands
during the wave, from a `/shared` pass or a gated adoption of the owner's cut made on another
device, is not seen. The wave can then sign a root at a cut epoch that its own stage 2 refuses, at
a higher sequence than the post-cut record: the defect FSM1/cipher-box#1750 closed on the owner
re-seal. D1 covers this arm, and the code lags it. No test covers it. FSM1/cipher-box#2016 tracks
the fix.

**E2 — The lease holds the write-epoch floor alone.** D4 reads the cut-epoch and read-epoch floors
under the write-epoch lease, but the lease does not stop a raise of either. The regression test
lands the cut raise inside the check's own reads. A raise that lands after the check and before the
transport publish is not seen by this publish. The publish-plane CAS and the next pass's gate are
then the only bar.

**E3 — The drain's scope-root republish has no cut-epoch check of its own.** A member write at a
scope root republishes the root with its gated grant section carried verbatim (`sync/drain.rs`
through `author_scope_root_envelope`). Its gated re-resolve (`reresolve_before_signing`, #23 D4,
ADR 0025 D2) reads the floor at stage 2, so its exposure is the E2 window. When the re-resolve is
served no record (`NoUpdate`), the drain signs on its pass-start read with no floor read. A
cut-epoch raise since the pass started is then not seen. FSM1/cipher-box#2016 tracks this case
with E1.

**E4 — Nothing in the type system routes a new scope-root publish through D4.** The check lives in
`RootPublish`, and every production `ScopeRootPublisher` uses it today. A future publisher that
signs a scope root on another path would not inherit it.

**E5 — A read-only survivor learns of a re-point only at its next pointer consult.** With the
accelerators gone, discovery waits for the consult of #38 D4. This is the bound the blueprint
already accepts.

**E6 — A wave that stops between the flips and never resumes leaves the vault pointer behind for
good.** D8 guards that plane by other stages, not by a bound on the lag. The focus tick reads the
anchor's scope pointer and corrects a running session; a cold start reads the trailing plane
until the wave resumes.

**E7 — A withheld scope pointer leaves an index unrepaired.** D5 needs the consult to answer. When
the pointer is unreachable the superseded root is unavailable, and the index keeps its stale
entry. The failure is availability; the index is never repaired with a wrong name.

## Gate

The tests below run in the Rust area of the PR gate (the workspace tests).

- **D1:** no single test states the law; D2 to D4 cover its instances. The interior re-seals of the
  grant mint and the sweep hold the read-epoch bar to the signature:
  `a_read_floor_rise_inside_the_mint_publish_window_refuses_the_re_seal` and
  `a_read_floor_rise_inside_the_sweep_publish_window_refuses_the_node` (`net/rotation.rs`).
- **D2:** `net/rotation.rs` `a_read_floor_rise_before_the_republish_refuses_the_record`,
  `a_republish_at_exactly_the_read_floor_still_lands`,
  `a_write_floor_rise_before_the_root_republish_refuses_the_seal`,
  `a_consult_inside_the_wave_publish_window_cannot_move_the_floor` and
  `the_read_epoch_floor_never_moves_across_a_republish`.
- **D3:** `net/rotation.rs` `a_read_floor_rise_before_the_retire_refuses_the_tombstones`,
  `a_retire_at_exactly_the_read_floor_still_runs`, `a_retire_behind_no_gated_read_is_refused`,
  `a_repoint_below_the_live_read_floor_is_refused_at_the_vault_anchor` and
  `a_repoint_below_the_live_write_epoch_floor_is_refused_at_every_scope`;
  `rotation/rotate_write/tests.rs` `a_refused_repoint_check_signs_and_publishes_nothing` and
  `a_wave_whose_retire_refused_on_a_floor_rise_converges_on_the_next_run`.
- **D4:** `net/rotation.rs` `a_cut_floor_rise_inside_the_owner_publish_window_refuses_the_re_seal`,
  which also passes under `cargo test --release`, and
  `a_consult_inside_the_owner_publish_window_cannot_move_the_floor`. No test drives a grant edit
  into the cut-floor refusal; the edits share the function. No test covers the wave root arm (E1).
- **D5:** `rotation/sweep/tests.rs`
  `an_encountered_scope_root_below_its_floor_is_repaired_at_the_repointed_name` and
  `an_omitted_scope_root_is_repaired_and_flagged_with_no_node_resealed`.
- **D6:** `rotation/rotate_write/tests.rs` `happy_path_child_first_root_last_repoint_then_retire`
  (both channels, scope pointer first, after every republish) and
  `a_scope_below_the_anchor_publishes_the_scope_pointer_alone`; `gate/floor.rs`
  `only_the_vault_pointer_channel_escapes_the_write_epoch_floor`, an exhaustive match over the two
  channels. No test asserts that the mailbox receives no re-point; the enum has no such variant.
- **D7:** `rotation/rotate_write/tests.rs` `an_unlanded_vault_pointer_flip_aborts_the_wave`,
  `a_refused_canonical_repoint_aborts_before_any_retire` and
  `mid_wave_crash_resumes_from_published_records_only`; `net/rotation.rs`
  `the_anchor_repoint_lands_at_the_adopted_vault_pointer_index`,
  `an_anchor_repoint_without_a_signer_refuses_rather_than_skipping` and
  `an_anchor_repoint_for_a_scope_below_the_root_refuses_release_active`. No test asserts that the
  two channels carry different blocks: the fake publisher in `rotate_write/tests.rs` drops the
  block. That is a finding.
- **D8:** `gate/floor.rs` `cold_seed_never_bars_the_vault_pointer_on_a_raised_write_floor`,
  `a_scope_pointer_below_its_own_write_floor_is_fail_closed` and
  `a_shared_scopes_pointer_is_held_to_the_same_write_bar`; `net/rotation.rs`
  `a_scope_pointer_below_the_write_epoch_floor_is_rejected` and
  `a_scope_pointer_exactly_at_the_write_epoch_floor_is_admitted`.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
