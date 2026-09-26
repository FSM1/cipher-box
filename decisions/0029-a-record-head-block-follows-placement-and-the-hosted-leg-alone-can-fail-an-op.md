# ADR 0029 — A record head block follows placement, and the hosted leg alone can fail an op

- **Status:** Accepted on 2026-09-26 — retroactive for D2 to D15, which shipped in FSM1/cipher-box#932,
  FSM1/cipher-box#1072, FSM1/cipher-box#1338 and FSM1/cipher-box#1585, and which the blueprint
  carries. D1 is an owner decision of 2026-09-26 that changes the shipped rule: the code and the
  blueprint lag it (E1, FSM1/cipher-box#2006); the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-26
- **Relates to:**
  [#34](https://github.com/FSM1/cipher-box-next/issues/34) D1 (the three modes, and registration
  on every mode) and D7 (the read path), [#24](https://github.com/FSM1/cipher-box-next/issues/24)
  D6 (register-first), the `blueprint/engine.md` "Content plane" section (pin-provider layer,
  dispatch, quota pre-flight, BYO endpoint policy, reads), "Vault settings load" section (the
  degraded-load policy) and "Sync core" section (the FIFO op queue), the `blueprint/api.md`
  "Content plane" and "Quota" bullets, AGENTS.md rules 6 and 8, and the `CONTEXT.md` "Vault
  settings record" and "Advisory pin row" terms
- **Implemented by:** FSM1/cipher-box#1072 (dispatch, dual, the upload mark, the publish
  refusal, the quota pre-flight, D1 to D11), FSM1/cipher-box#1338 (provenance of the reconcile,
  D12), FSM1/cipher-box#1585 (the in-session re-decide and the staging read leg, D13 and D14)
  and FSM1/cipher-box#932 (the BYO endpoint policy, D15). The decision source for D3, D9 and
  D11 is the resolution of FSM1/cipher-box#822 (2026-07-27).

## Context

A member chooses where the bytes of a content version go. The pin mode has three values:
`Hosted` (the CipherBox hosted store, the default), `External` (the member's own provider only)
and `Dual` (both). #34 D1 fixed the three modes and fixed one invariant: every mode's publish
still traverses registration. It decided nothing else about the byte path.

Until FSM1/cipher-box#1072, `PinMode` had no consumer on the byte path. Every block of every
version went to the hosted ingress, whatever the member chose. The quota pre-flight
short-circuited on the account-level `advisory` flag, so a dual write would have skipped the
fail-fast check while real hosted bytes moved (FSM1/cipher-box#705).

The resolution of FSM1/cipher-box#822 (2026-07-27) found one fact in the API that reframed the
problem. The hosted ingress refuses every upload from an account whose `users.byo` flag is set
(`apps/api/src/content/content.service.ts`, a 409 read under a row lock). `users.byo` has two
states and the pin mode has three. So `PinMode` is a client-side placement policy, and the
server flag means only "refuse hosted ingress and stamp rows advisory". The same resolution
settled the dual failure rule from the drain law: the drain is strict FIFO and stops at the
first failure (FSM1/cipher-box#819, `blueprint/engine.md` "Sync core"). A rule that both legs
must succeed lets an offline home node or a rate-limited pin service stall every later mutation
in the vault. The comment of 2026-07-28 on the same issue moved the provider config into the
vault settings record and kept every other ruling unchanged.

The provider kinds do not behave alike. Kubo takes bytes under an address the caller gives
(`block/put`). PSA and Pinata are pin-by-CID services: they fetch a block from the network, and
their own byte ingress re-chunks under a different multihash. Neither can hold a block under
the address a CipherBox record names.

Three later incidents shaped the rest:

- A crypto review on FSM1/cipher-box#1149 found that an assumed first-run placement reconciled
  the account flag. A fresh device, with the settings record withheld, cleared `byo` on an
  account it had authenticated nothing about. FSM1/cipher-box#1338 fixed it.
- The placement was decided once at `start`. A desktop mount runs for days, so a revoked
  provider credential kept receiving blocks until a restart. FSM1/cipher-box#1585 fixed it.
- A partial write over a staged, unpublished version was refused, which blocked an append to a
  file just written. FSM1/cipher-box#1585 made the staging store a read leg.

The BYO endpoint arrives from a member or from a resolved record, and the provider probe carries
the member's bearer. FSM1/cipher-box#905 asked for a stated transport and address-range policy;
FSM1/cipher-box#932 set it.

The `blueprint/engine.md` "Content plane" section carries every rule below today. Its "Dual runs
both legs" bullet cites #34 D1, which does not state the dual rules.

## Decision

**D1 — A record head block follows placement, the same as a content version.** Under `Hosted`
the head block goes to the hosted store. Under `Dual` it goes to both legs, and D3 applies.
Under `External` it goes to the member's own node only, and the API sees the registration and
nothing else. On every leg the record-plane publish compares the address the leg returns against
the head block's own address, and a mismatch publishes nothing. Placement decides where every
block of a record goes, head and content alike. The owner decided this on 2026-09-26 during the
review of this ADR. The shipped rule (FSM1/cipher-box#1072) sent every head block to the hosted
path in every mode, which under `External` makes CipherBox Kubo the only provider of the head:
a CipherBox outage then blocks every BYO write and darkens every BYO read that the local cache
does not hold, and the vault settings record stops being server-free (`CONTEXT.md` "Vault
settings record"). Under this rule a BYO read of a head depends on the member's node, as a BYO
read of content already does. The code lags this rule (E1).

**D2 — A pin-by-CID provider is only the second leg of a dual write.** The byte destinations a
mode names are exactly what the provider's API supports. Kubo takes bytes under the caller's
own address (`block/put` with the CID's multicodec and the frozen `blake3`/32 framing), and the
address it answers with must equal the one it was given. PSA and Pinata cannot preserve an
address, so they are only ever a dual write's second leg. External-only over a pin-by-CID
provider is a placement refusal: no leg would hold the block for the service to fetch, and the
published record would name bytes that exist nowhere. The rule landed with
FSM1/cipher-box#1072; this ADR records it.

**D3 — Dual runs both legs, and only the hosted leg can fail the op.** Both legs run, and both
retry inside the op. Only a hosted-leg failure can fail or dead-letter the op. The op completes
when the hosted leg succeeds and the external leg has either succeeded or used all its
attempts. The external outcome is reported once per op, never swallowed, and no retry is queued
for it. Under `External` the member's provider is the byte path, so its refusal is the op's.
Decided on 2026-07-27 in the resolution of FSM1/cipher-box#822, section 3. The per-op report,
the rule that no retry is queued, and the `External` clause landed with FSM1/cipher-box#1072.

**D4 — The external retry budget belongs to the op, not to each block.** A node that is down
refuses every block alike. When the op has spent the budget, the mirror is abandoned for that
version, and later blocks of the same version do not ask the provider again. The rule landed
with FSM1/cipher-box#1072; this ADR records it.

**D5 — A partial-success report waits for the publish.** The external-pin shortfall says that
the version published and its content is retrievable. The engine emits it after the record
lands, never at the end of the block upload. A pass that then fails to publish made no such
promise. The rule landed with FSM1/cipher-box#1072; this ADR records it.

**D6 — Durable upload progress is keyed by the destinations that took the bytes.** A resumed
version's confirmed prefix is no longer on the device. A session skips that prefix only where
the leg that can fail this op already holds it: the hosted store, or the member's provider under
external-only. The mark records what the legs took, not what the mode named. A dual write whose
mirror missed a block narrows its mark to the hosted leg, so a later external-only session
places the blocks again and does not publish content that the provider never received. The rule
landed with FSM1/cipher-box#1072; this ADR records it.

**D7 — The destination identity is the provider, not the credential.** The identity covers the
provider kind and the endpoint, and it excludes the bearer. A mark that stops matching is not
only ignored: the leaves it covered are already released. A key on a rotatable secret would make
a routine credential rotation leave the version unpublishable. The rule landed with
FSM1/cipher-box#1072; this ADR records it.

**D8 — A settings publish refuses settings under which no reader can place bytes.** The produce
path runs the consumer's own placement predicate, release-active (AGENTS.md rule 8). A settings
record that names a mode with no usable byte destination is never signed: an external leg with
no provider, or external-only over a pin-by-CID provider. Such a record would be a durable,
account-wide refusal of every content write, which only a new publish can recover. The rule
landed with FSM1/cipher-box#1072; this ADR records it.

**D9 — The quota pre-flight gates this write's byte path, not the account.** It runs at command
time, where the write already waits, before staging. It is sized in sealed bytes, because
sealed bytes are what the ingress charges. `Hosted` and `Dual` are checked; `External` is
skipped. The `advisory` field on the quota response is a display hint that lags the vaulted
mode, and it is never the decision input. The pre-flight is never authoritative: the API upload
endpoint stays the enforcement. Decided on 2026-07-27 in the resolution of FSM1/cipher-box#822,
sections 5 and 7.

**D10 — An unreachable API queues the write; an unauthenticated placement refuses it.** The
pre-flight is not a trust gate, so an unreachable or unconfigured API leaves the write to queue
offline like any other write. The placement decision is a trust gate, so a placement that the
engine cannot authenticate refuses the write. The rule landed with FSM1/cipher-box#1072; this
ADR records it.

**D11 — `users.byo` has two states, and `byo=true` means exactly `External`.** `Hosted` and
`Dual` both run `byo=false`; dual has no server representation. The vaulted mode is the source
of truth, and the engine reconciles the account flag against it. Decided on 2026-07-27 in the
resolution of FSM1/cipher-box#822, sections 1 and 7.

**D12 — Only a placement that the member's own record established reconciles the account
flag.** The placement decision carries its provenance: the member's record (published or
last-known-good) or an assumption. An assumed placement latches no account-scoped state. An
`advisory` that contradicts the hosted default an assumed placement took refuses the write. The
general rule that a server signal only restricts belongs to the "Vault settings load" policy.
The rule landed with FSM1/cipher-box#1338; this ADR records it.

**D13 — The placement is decided again while the session runs, and only on a resolved
record.** The resolve tick re-decides, paced by the profile constant
`settings_recheck_interval`, so a provider or credential revoked on another device stops
receiving blocks inside that window. A degraded re-load is no evidence that the member changed
anything, and the unproven-first-run default resolves to `Hosted`, so a re-decide on one would
widen a live `External` session. A re-decide that lands re-arms the account-flag reconcile, as
a save does. The rule landed with FSM1/cipher-box#1585; this ADR records it.

**D14 — The staging store is the local-first read leg, and it clears the gateway bars.** A read
consults the staging store ahead of every gateway. The staging key is the block's own
`contentCid`, so a local hit is byte-identical to what a gateway serves for that address, and a
half-uploaded version reads across both legs. A local block clears the bars a fetched block
clears, in the same order: the plane anchor, the block-size cap before any hash, then the CID
verify against the same binary anchor. A mismatch is the same terminal trust violation and never
rotates to the gateway. An over-cap value rotates, as an over-cap body does. The rule landed
with FSM1/cipher-box#1585; this ADR records it.

**D15 — One BYO endpoint policy gates the whole config.** The gate applies identically to a
config the member types and to one resolved from the network, and it is release-active on the
encode side, so nothing is published that the reader would refuse. The rules:

- The endpoint is an absolute `http(s)` URL whose authority is host-and-port bytes only.
- `https` is required unless the host is a loopback literal (`127.0.0.0/8`, `::1`) or
  `localhost`, because the probe carries the member's bearer.
- The cloud-metadata address (`169.254.169.254`, its IPv6 spellings, and `fd00:ec2::254`) is
  refused.
- A host that the gate would read as a name while the transport's URL parser would read it as an
  address (`0xa9fea9fe`, `2852039166`) is refused.
- Private and link-local ranges stay allowed; self-hosting on a LAN is the feature.
- The engine has no resolver and does not get one. The verdict comes from the literal, so the
  metadata refusal is a legibility rule, not an SSRF containment boundary.
- The access token is visible ASCII only.
- Each refusal is its own `ProviderError` verdict.
- The `Http` seam must not follow a redirect that downgrades `https` to `http`.

The rule landed with FSM1/cipher-box#932; this ADR records it.

## Trust argument

- **Every published record is backed by a pin on the leg its placement names.** D1 and D3 keep
  the record head and the content together: on the hosted store under `Hosted`, on both legs
  under `Dual`, on the member's node under `External`. Registration, quota and retire keep their
  hosted-mode meaning. The read accelerator serves a hosted block from the hosted store and
  fetches an `External` block from the network, head and content alike. A CipherBox outage does
  not stop a BYO member from reading a vault whose node is up.
- **A third party cannot stall the vault.** Under D3 an external refusal degrades one version's
  redundancy. It never holds the strict-FIFO drain, so no provider outside CipherBox can deny
  service to later mutations.
- **No record names bytes that exist nowhere.** D2 refuses the one mode in which no leg holds
  the block, and D8 refuses to sign a settings record that would put a reader in that mode.
  D6 stops a resume from publishing a version that its only leg never received.
- **The server flag cannot widen placement.** D9 gates on the local byte path, not on
  `advisory`. D12 lets `advisory` only restrict an assumed placement, and never latches the
  account flag from one. D13 re-decides only on a resolved record. So neither the API nor an
  adversary on the record plane can move an `External` member onto the hosted store.
- **A credential rotation does not strand a version.** D7 keys the mark on the provider, not on
  the bearer.
- **A nearer source is not a more trusted one.** D14 holds a staged block to the bars a fetched
  block clears, and a mismatch is terminal (AGENTS.md rule 6).
- **The bearer does not go to the wire in clear.** D15 requires `https` off loopback and forbids
  a downgrade redirect. The gate reads only literals, so it adds no resolver-based
  time-of-check to time-of-use gap.
- **Encode and decode agree.** D8 and D15 run the reader's own predicates on the produce path,
  release-active (AGENTS.md rule 8).

## Alternatives rejected

**(a) Both legs must succeed in a dual write.** Under the strict-FIFO drain an offline home node
or a rate-limited pin service stalls every later mutation in the vault. The resolution of
FSM1/cipher-box#822 rejected it.

**(b) Either leg is enough in a dual write.** An external-only success leaves the API with no
pin row for the CID, so quota accounting and retire go wrong, and reads depend on the member's
provider announcing to the DHT. The resolution of FSM1/cipher-box#822 rejected it.

**(c) Teach the server all three modes with a `pin_mode` column.** The engine already knows its
own mode. The column costs a migration and an edit to a live trust gate for no gain. The
resolution of FSM1/cipher-box#822 rejected it.

**(d) Derive the mode from `users.byo` and the presence of a provider config.** It makes the
desync between the two writers impossible, but it deletes a real state: turning dual off would
delete the provider config. The resolution of FSM1/cipher-box#822 rejected it for the D11
reconcile.

**(e) Send external-only writes to a pin-by-CID provider through the hosted relay, then
unpin.** v1 did this. It puts the member's bytes in the hosted store, which is what external-only
refuses, and it leaked quota when the unpin failed. FSM1/cipher-box#1072 rejected it for D2.

**(f) A `PinProvider` seam trait.** It is a seam over the `Http` seam, adds no nondeterminism
that `Http` does not already carry, and its fake can drift from the real provider dialects. The
resolution of FSM1/cipher-box#822 chose concrete dispatch over `Http`.

**(g) A drain-time quota pre-flight.** The file is sealed and staged before the drain runs, so a
drain-time check saves only upload bandwidth. A command-time check saves the member the whole
seal-and-stage wait. The resolution of FSM1/cipher-box#822 chose command time.

**(h) Resolve the endpoint host to classify it.** The engine has no resolver, and a resolved
verdict is a time-of-check to time-of-use gap. FSM1/cipher-box#932 chose the literal.

**(i) Keep every record head block on the hosted ingress, and exempt heads from the `byo`
refusal.** This is the shipped rule plus an API exemption. It puts CipherBox Kubo on the write
path and on the read path of a BYO vault: the head has no other provider, so a CipherBox outage
blocks every BYO write and every uncached BYO read, and the settings record is no longer
server-free. The ingress also cannot tell a record head from a DAG root by codec, so the
exemption needs a new signal on the wire. The owner rejected it on 2026-09-26 for D1.

## Consequences

1. **`blueprint/engine.md` "Content plane" is reworded for D1.** The bullet "Dispatch is
   concrete over the Http seam, and only content versions dispatch" now reads: dispatch is
   concrete over the Http seam, and every block of a record dispatches by placement, the head
   block the same as a content version; on every leg the record-plane publish compares the
   returned address against the head block's own. The clause "the republisher re-PUTs from the
   hosted store" goes: the republisher re-PUTs the signed record from its own cache
   (`apps/api/src/republisher/republisher.task.ts`) and never reads the head block.
2. **`blueprint/engine.md` already carries D2 to D14.** The "Content plane" section states them
   in the bullets "Dual runs both legs", "A partial-success report waits for the publish", "Durable
   upload progress is keyed by the destinations that took the bytes", "The destination identity
   is the provider, not the credential", "The placement is re-decided while the session runs",
   "A publish refuses settings no reader could place under", "The quota pre-flight gates this
   write's byte path, not the account", and "The staging store is the local-first leg". No text
   change is needed.
3. **`blueprint/engine.md` already carries D15** in the "BYO endpoint policy" bullet. No text
   change is needed.
4. **`blueprint/engine.md` "Vault settings load" already carries the policy D12 and D13 apply.** The
   bullets "A degraded load never widens placement" and "The one arm that still authorises a write
   is named for what it assumes" state the restricting-direction reading of `advisory`.
5. **`CONTEXT.md` needs no change.** The "Vault settings record" term ("it resolves at cold
   start with no CipherBox infrastructure") holds under D1, and "Advisory pin row" is consistent
   with D11.
6. **#34 D1 is confirmed, and this ADR cites it.** #34 D1 says "Hosted uploads ride the API
   (quota-gated, → Kubo); BYO bytes bypass it". Under D1 of this ADR that sentence covers the
   record head block too. The three modes and registration on every mode do not change.
7. **`blueprint/engine.md` section "Content plane" gains the citation (ADR 0029)** on the "Dual
   runs both legs" bullet, in place of the #34 D1 citation there, which does not state the dual
   rules. The "Pin-provider layer" bullet keeps its #34 D1 citation.
8. **`blueprint/engine.md` section "Content plane" gains the citation (ADR 0029)** on the "BYO
   endpoint policy" bullet, beside its cipher-box issue reference.

## Residuals

**E1 — The code lags D1, and under `External` the device is locked out of every publish.** The
shipped code sends every record head block to the hosted ingress in every mode
(`publish_record` in `crates/engine/src/net/record_publish.rs:233`). Every record publish takes
this path: the drain, the settings save, the bin index, rotation and provisioning. D11 sets
`byo=true` for an `External` account, and the engine's reconcile runs in the command-time pre-flight of a file
write, before the drain (`hosted_quota_pre_flight` in `crates/engine/src/facade.rs:10843`). The
hosted ingress refuses every upload from a `byo=true` account with a 409
(`apps/api/src/content/content.service.ts:245`), with no exemption. The member sees this, in
order:

1. The settings save that selects `External` succeeds, because `byo` is still false.
2. The first file write sets `byo=true` at command time. The drain places the version's blocks
   on the member's node, then gets a 409 on the file's record head block. The drain charges each
   409 as an attempt (`a_refusal_of_these_bytes_costs_an_attempt_and_never_dead_letters_on_sight`
   in `crates/engine/src/sync/drain.rs`), and the op dead-letters after `ATTEMPT_BUDGET`
   attempts. The file never publishes.
3. Under the strict-FIFO drain, every later op meets the same 409 and dead-letters in turn. Bin
   index and rotation publishes fail the same way.
4. A settings save is not a drain op. It fails at once with the seam error "the settings record
   did not reach the record plane". This includes a save that selects `Hosted` again.
5. The device cannot leave this state from the app. Only the pre-flight of a session whose
   placement has a hosted leg sets `byo=false`, and that placement needs a settings save, which
   gets the 409.

No suite catches this. The engine testkit's fake ingress does not model the 409
(`crates/engine/src/testkit/account.rs`), and the contract suite proves the 409 for a content
leaf only (`quota_is_hosted_authoritative_and_byo_advisory` in `crates/contract/tests/contract.rs`).

D1 resolves this: under `External` the head block goes to the member's node, and nothing from
that account reaches the hosted ingress. Only the Kubo dialect takes a raw block, and `External`
with a pin-by-CID provider is already refused (D2), so the rule needs no new dialect. The
resolution of FSM1/cipher-box#822, section 7, decided an order for mode changes: `byo` first
when the member leaves `External`, last when the member enters it. Neither the blueprint nor the
code carries that order. The fix is FSM1/cipher-box#2006.

**E2 — The code holds the mirror budget per drain pass, not across the op's passes.**
`upload_blocks` in `crates/engine/src/sync/drain.rs` builds a new `MirrorLeg` (three attempts,
`MIRROR_ATTEMPTS`) on each pass. When a hosted failure sends the op to a later pass, the mirror
gets a new budget; the durable mark's mirror gap carries the earlier miss forward. The hosted
leg has no leg-local retry loop: its retries are the op's attempt budget (`ATTEMPT_BUDGET`). A
config refusal that no retry can change also spends the mirror's attempts. D3 and D4 hold for
one pass. This ADR records the blueprint text.

**E3 — An assumed placement on a `Dual` account drops the mirror without a mirror signal.** D12
reads `advisory` in the restricting direction only. A `Dual` account runs `byo=false`, so on a fresh
device whose settings record is withheld, the assumed `Hosted` default does not contradict the flag,
and the session writes one copy while the member chose two. The host sees only a `Defaults` settings
summary (`SettingsOrigin::Defaults` in `crates/engine/src/settings.rs`); nothing says that a mirror
was dropped. The wider settings-load policy in `blueprint/engine.md` "Vault settings load" owns the
unproven first run; D12 narrows the `External` case only.

**E4 — Retire and prune do not reach the member's provider.** The resolution of
FSM1/cipher-box#822, section 6, decided that retire and prune unpin both legs, with the provider
unpin best effort. The comment of 2026-07-28 on the same issue kept this rule among the rulings
that survive, and handed it to FSM1/cipher-box#871. FSM1/cipher-box#1072 closed
FSM1/cipher-box#871 without it. The blueprint does not carry the rule, and the engine has no
provider unpin in any dialect. Bytes on the member's provider under `External` and `Dual` grow
without bound. This ADR does not record the section 6 rule. The gap is open as
FSM1/cipher-box#2007.

**E5 — A staged read can leak a `contentCid` to the accelerator.** A local miss on a staged
version asks the gateway for the address of ciphertext that no drain uploaded, so a version the
member later cancels can disclose a ciphertext hash, never bytes. Bounding the gateway leg by
the durable upload mark would close it. The blueprint states this and does not close it.

**E6 — Two accounts on one multi-tenant pin service share a destination identity.** D7 excludes
the bearer, so their tags are equal. The collision reaches only the best-effort mirror report.

**E7 — The metadata refusal is not SSRF containment.** D15 classifies the literal only. A DNS
name that resolves to the metadata address or to a private range passes the gate. The
contract-suite harness `ReqwestHttp` (`crates/contract/src/lib.rs`) keeps reqwest's default
redirect policy; it is test code, not a shipped `Http` seam, but it does not meet the D15 seam
obligation.

## Gate

The engine suites below run in the Rust area of the PR gate (the workspace tests). `wp` is
`crates/engine/tests/write_plane.rs` and `vs` is `crates/engine/tests/vault_settings.rs`.

- **D1:** `a_pin_store_that_reports_another_address_publishes_nothing`
  (`crates/engine/src/net/record_publish.rs`) proves the address compare on the hosted leg.
  `wp` `an_external_write_places_every_block_on_the_members_node_and_none_on_the_hosted_store`
  proves it for content only: the folder record head under `External` still takes the hosted
  ingress there. No test proves that a head block lands on the member's node under `External`,
  or on both legs under `Dual`, and no suite runs the head upload against the real ingress for a
  `byo=true` account (E1). This is a finding; FSM1/cipher-box#2006 adds the tests.
- **D2:** `kubo_puts_the_block_under_its_own_codec_and_the_frozen_hash`,
  `a_dag_root_is_put_under_the_dag_cbor_codec`,
  `a_kubo_node_that_stored_the_block_elsewhere_is_a_failure` and
  `a_pinning_service_is_asked_to_pin_the_address_it_fetches_itself`
  (`crates/engine/src/content/provider.rs`);
  `a_pin_by_cid_provider_cannot_be_the_only_byte_destination` (`crates/engine/src/settings.rs`).
- **D3:** `wp` `a_dual_write_publishes_and_reports_the_leg_the_members_node_did_not_take`,
  `a_dual_write_places_the_same_block_set_on_both_legs` and
  `a_mirror_refusal_the_op_retries_past_leaves_nothing_to_report`; `drain.rs`
  `only_an_answered_placement_charges_the_attempt_budget`. No test proves end to end that an
  `External` provider refusal fails the op, or that no retry is queued after a shortfall. This is
  a finding.
- **D4:** `wp` `a_dead_mirror_costs_the_op_a_bounded_number_of_attempts`.
- **D5:** `wp` `a_mirror_shortfall_is_reported_only_once_the_record_published`.
- **D6:** `wp` `a_dual_mark_names_the_mirror_only_where_the_mirror_took_the_bytes` and
  `a_placement_changed_mid_upload_resumes_only_where_the_bytes_already_are`; `settings.rs`
  `a_missed_mirror_narrows_the_mark_to_the_hosted_leg`;
  `crates/engine/src/sync/upload_mark.rs`
  `a_resumed_mark_covers_only_what_the_op_failing_leg_already_holds`.
- **D7:** `settings.rs` `a_rotated_bearer_is_the_same_destination` and
  `each_set_of_destinations_tags_itself_apart`.
- **D8:** `settings.rs` `publishing_settings_no_reader_could_place_under_is_refused`; `vs`
  `a_settings_save_naming_no_byte_destination_is_refused_as_a_placement`.
- **D9:** `wp` `a_hosted_write_over_quota_is_refused_at_command_time`;
  `crates/engine/src/content/retention.rs` `the_gate_follows_the_byte_path_not_the_advisory_flag`.
  No test separates sealed-byte sizing from plaintext sizing, and no test runs the `Dual` pre-flight
  end to end. This is a finding.
- **D10:** `wp` `a_withheld_settings_record_refuses_the_write_instead_of_widening_it` and
  `a_settings_save_that_never_landed_refuses_the_write_instead_of_widening_it` prove the refusal.
  No test proves that a write whose quota probe is unreachable queues; only tests that boot with
  no API configured cover it indirectly. This is a finding.
- **D11:** `wp` `the_session_reconciles_the_accounts_byo_flag_to_the_vaulted_mode` and
  `a_byo_reconcile_that_did_not_land_is_retried_by_the_next_write`; the contract suite
  (`Contract Suite Result`) `quota_is_hosted_authoritative_and_byo_advisory` proves the API side.
  No test proves that `Dual` reconciles to `byo=false`. This is a finding.
- **D12:** `vs` `an_assumed_first_run_never_clears_the_accounts_byo_flag` and
  `an_assumed_first_run_latches_nothing_when_the_flag_already_agrees`; `settings.rs`
  `an_assumed_default_is_never_reported_as_the_members_own_choice`.
- **D13:** `wp` `a_running_session_re_decides_its_placement_from_the_live_settings_record`
  (the reconcile re-arm included) and `a_settings_change_the_tick_adopts_is_reported_to_the_host`;
  `settings.rs` `only_a_resolved_record_re_decides_a_running_sessions_placement`.
- **D14:** `crates/engine/src/content/read.rs` `a_locally_held_block_is_served_without_a_fetch`,
  `a_block_the_local_store_lacks_falls_through_to_the_gateway`,
  `a_locally_held_block_that_does_not_address_is_a_terminal_trust_violation`,
  `an_over_cap_local_block_is_skipped_before_it_is_hashed` and
  `a_wrong_plane_codec_is_refused_before_the_local_store_is_consulted`; `wp`
  `both_readers_serve_the_staged_version_the_rendered_size_names`.
- **D15:** `provider.rs` `an_endpoint_outside_the_policy_is_rejected_before_any_request`,
  `a_local_http_kubo_endpoint_is_allowed`, `an_access_token_that_could_inject_a_header_is_refused`
  and `the_config_gate_and_the_header_splice_agree_on_every_token`; `settings.rs`
  `a_byo_config_the_seam_may_not_be_pointed_at_is_refused_on_both_sides`; the redirect rule by
  `reqwest_http_follows_no_redirect_and_does_not_replay_the_bearer`
  (`crates/desktop-seams/tests/conformance.rs`) and the "FetchHttp redirects" cases in
  `packages/client/src/seams/http.test.ts` (Web area, `packages/client` browser suite).

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
