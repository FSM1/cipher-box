# ADR 0034 — A degraded settings load falls back to the last verified copy and never widens placement

- **Status:** Accepted on 2026-09-26 — retroactive; the rule shipped in FSM1/cipher-box#903,
  FSM1/cipher-box#934, FSM1/cipher-box#1046, FSM1/cipher-box#1149, FSM1/cipher-box#1676 and
  FSM1/cipher-box#1939, and the blueprint carries it; the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-26
- **Amends:**
  [ADR 0013](./0013-a-lapsed-bin-index-record-is-rewritten-not-refused.md)
  D3 and D4 (the renewal enrolment on a load now covers the settings record too), and
  [ADR 0022](./0022-a-first-run-cold-start-tolerates-a-failed-public-routing-endpoint.md)
  D2 (the no-floor condition) and D3 (the answer is not stored)
- **Relates to:**
  [ADR 0007](./0007-derived-idempotent-first-run-mint.md)
  (the first-run mint and its vacancy probe),
  [#33](https://github.com/FSM1/cipher-box-next/issues/33) D4 (a trust violation keeps
  last-known-good), [#24](https://github.com/FSM1/cipher-box-next/issues/24) D3 (no client resolve
  path touches the API's record cache) and its lapse semantics,
  [#27](https://github.com/FSM1/cipher-box-next/issues/27) D10 (the 90-day client-signed EOL), the
  FSM1/cipher-box#813 map resolution FSM1/cipher-box#825 section 4 (settings move off the API), the
  `blueprint/engine.md` "Vault settings load", "Adoption gate and floors" (the paragraph "The
  first-run rule") and "Bin index record" sections, and the `CONTEXT.md` terms "Vault settings
  record", "Vault pointer", "Floor law", "Adoption gate" and "Sync timing profile"
- **Implemented by:** FSM1/cipher-box#934 (D2 to D4, D8), FSM1/cipher-box#1046 (D6, D7),
  FSM1/cipher-box#1149 (D5), FSM1/cipher-box#1676 (D9) and FSM1/cipher-box#1939 (D10, D11). D1
  shipped with FSM1/cipher-box#903 (the build slice FSM1/cipher-box#870) and
  FSM1/cipher-box#934.

## Context

The vault settings record holds the member's own client configuration: the pin mode, the
bring-your-own node endpoint and its bearer credential, and the retention policy. On
2026-07-28 the map resolution FSM1/cipher-box#825 section 4 moved it off the API. The record
publishes at a name derived from the login secret and seals HPKE-to-self under the encryption
subkey, so a cold start reads it before any other resolve. A self-hosting owner never needs
CipherBox to find the owner's own node. The build slice FSM1/cipher-box#870 took the v1
semantics: validate the body, degrade to the documented defaults on any failure, and bound the
load with a timeout.

Unlike every other resolve, the degraded outcome of this load applies a different policy. It
does not only show stale data. FSM1/cipher-box#928 found the effect: the defaults name
`PinMode::Hosted`. A member who chose `PinMode::External` ("never put my bytes in CipherBox's
store") went silently onto the hosted store whenever the record was withheld, timed out, or had
an unreadable head block. The engine already named each of these cases
(`DefaultsReason::{Suppressed, RolledBack, TimedOut, Unreadable, FloorUnreadable}`), but no code
acted on them. The party that gains from this reversion is the party that controls the record
plane. FSM1/cipher-box#934 added a verified last-known-good copy and wrote the placement policy
into `blueprint/engine.md`.

Three further gaps followed, each from a review of the previous fix:

- **A cold device and a same-sequence fork.** An unconfirmed publish followed by a retry mints
  two owner-signed records at one sequence. The load admitted any record at or above the floor,
  so a chosen-record adversary could select one of the two for every device, permanently. Every
  durable seam is device-local, so a fresh install has no anchor at all. FSM1/cipher-box#930
  asked for a cold-device anchor, and FSM1/cipher-box#1046 answered it and added the body
  revision.
- **The first-run carve-out.** A first run has no record, so the defaults must authorise a
  write there. Before FSM1/cipher-box#1149 the engine derived "first run" from the per-name
  sequence floor alone. A device that saved an `External` choice which never landed, or that
  lost its floor write after an adopt, read a withheld record as a first run and placed bytes
  on the hosted store. The same path also reconciled the account's BYO flag to `false` on an
  assumed placement.
- **The lapse.** The settings load refuses a lapsed EOL (ADR 0013 D2 keeps that carve-out at
  this record alone). Before FSM1/cipher-box#1676 only a publish enrolled the record in the
  sub-EOL renewal set. An account that nobody re-saved inside 90 days lapsed on its own, and
  the placement decision then failed closed because it had no copy it could authenticate.

The first-run registry query of ADR 0022 landed later, in FSM1/cipher-box#1939. That PR added
two conditions that ADR 0022 does not state. They belong to the same family as the settings
carve-out: a first-run rule applies only to a device that holds no durable mark of a record,
and it leaves no durable trace.

`blueprint/engine.md` states the settings rules under "Vault settings load" and the first-run
registry rule in the paragraph "The first-run rule" under "Adoption gate and floors". The code is
`crates/engine/src/settings.rs`, `crates/engine/src/record_plane.rs` (the ladder, shared with the
bin index) and `crates/engine/src/facade.rs` (`start`, `first_run_pointer_name`).

## Decision

**D1 — The settings record resolves first, never blocks, and degrades inside a budget.** The
vault settings record resolves at cold start, ahead of any vault resolve. It never blocks that
resolve: every failure degrades inside the settings budget of the sync timing profile
(`settings_load_budget`), and the budget is measured on the Scheduler seam. One budget covers
the whole load, the last-known-good cache read included. The order and the bounded degrade were
decided on 2026-07-28 in FSM1/cipher-box#825 section 4, an owner-approved FSM1/cipher-box#813
resolution. The Scheduler-measured budget landed with FSM1/cipher-box#903, and the one budget
over the cache read landed with FSM1/cipher-box#934.

**D2 — A degraded load prefers the verified last-known-good copy to the defaults, and reports
it stale.** The engine caches the head block of a settings record that cleared its sequence
floor and opened. It caches the ciphertext only, in `SnapshotCache`, never the opened body. A
degraded load prefers that copy to the built-in defaults, for every degraded reason, and reports
it as stale with the reason it degraded. The cache gives the bytes no trust: the copy must pass
the same seal open and the same body grammar as a freshly fetched head block, or the load
discards it. #33 D4 states the general law (a trust violation keeps last-known-good). The
settings rule landed with FSM1/cipher-box#934; this ADR records it.

**D3 — A degraded load never widens placement.** A withheld record, a spent budget, an
unreadable head block, or a floor read that fails must not move a member from `External` onto
the hosted store. A load that cannot authenticate the member's current choice must not invent
a wider one. The guarantee is relative to this device: the widest placement that a degraded
load can report is the one this device last authenticated, never the built-in default. A
rollback takes the same path, because pinning last-known-good is what the gate already owes a
rejected record. The rule landed with FSM1/cipher-box#934; this ADR records it.

**D4 — With no last-known-good copy, the placement decision refuses the hosted upload.** Under
every degraded reason except `UnprovenFirstRun` (D5), a load with no cached copy makes the
placement decision refuse the hosted upload. It does not resolve to `PinMode::Hosted`. The
engine tells the member that the settings are unavailable. A consumer that branches only on the
resolved case, and lets the degraded cases fall through to the defaults, brings back the
widening that D3 forbids. The rule landed with FSM1/cipher-box#934; this ADR records it.

**D5 — The one degraded arm that authorises a write is an unproven first run.** The built-in
defaults stand in for a first run, and the reason that carries them is `UnprovenFirstRun`. The
load reaches it only when no endpoint served a record and this device holds none of the three
durable marks that a settings record leaves: the per-name sequence floor, the adopted body
revision, and the publish mint counter. Any one mark refuses the placement. An unreadable mark
is never read as an absent one: the load reports `FloorUnreadable`, which refuses. Absence is a
verdict about this device only, so an assumed placement never latches account-scoped state. The
account's advisory BYO flag is read only in the restricting direction: `advisory` set means
never assume the default. The rule landed with FSM1/cipher-box#1149; this ADR records it.

**D6 — The sealed body carries a monotonic revision per publish attempt.** The engine mints the
revision for each publish attempt and advances it before the PUT. A reader refuses a revision
below the highest it has adopted at the same sequence. That refusal is a trust violation, not
staleness. A record at a strictly higher sequence won its own CAS and is never held to the
device-local revision, or the legitimate publish of a second device would be refused permanently.
The writer's mint counter and the reader's adopted high-water are separate durable values. An
attempt that never landed advances only the mint counter, so it never makes a device refuse the
live record it failed to replace. A confirmed publish raises the reader's bar and seeds
last-known-good with the record it published. A store that does not take the minted value
refuses the publish with a release-active error (`next_revision` in
`crates/engine/src/settings.rs`). The rule landed with FSM1/cipher-box#1046; this
ADR records it.

**D7 — The EOL is the only anchor on a cold device.** A fresh install holds neither a sequence
floor nor an adopted revision, so D6 protects a device with state and not a device without it.
The bound on a cold device is the 90-day EOL window of #24 D1, and it is stated, not closed.
Two anchors are refused. A settings head CID chained into the vault pointer would reverse the
purpose of the record, because a BYO member would have to reach the network configured in the
settings to read those settings. An API-held counter is refused because no client resolve path
touches the API's record cache (#24 D3). FSM1/cipher-box#930 put the three options, and the
FSM1/cipher-box#1046 body picked option (i). No owner decision records the choice. The rule
landed with FSM1/cipher-box#1046; this ADR records it.

**D8 — The cached copy has no freshness bound, and this ADR accepts that.** The seal alone binds
the copy to the account. It carries no sequence, no name and no time. A party that can write
this device's durable store can pin the device to any settings generation the account ever
published, because every historical head block is a public, content-addressed object. The
sequence floor and the adopted revision do not defend against that party, because both live in
the same device-local store. That party can also delete the entry and force the defaults path,
which is the behaviour before the cache. The anti-downgrade property of D3 therefore holds
against a record-plane adversary, not against an adversary inside the device's storage. A device
that stays degraded keeps its copy with no adversary too, a rotated BYO credential included, so
the load reports the reason and does not hide it. The residual landed with
FSM1/cipher-box#934; this ADR records it.

**D9 — A settings load enrols the record it read in the session's renewal set.** Every caller of
the settings load enrols, so a session that only reads keeps the name alive. The enrolment has
the two bars of ADR 0013 D4, because the renewal re-signs at `floor + 1` and so promotes what it
is given. The record must have cleared the whole floor law, the lapsed-EOL refusal included. This
device must already hold a sequence floor for the name. The enrolment also writes only while the
renewal slot still holds the record bytes it held when the load began, so a save that lands
across the load is never replaced by the older read (`SettingsRead::enrol` in
`crates/engine/src/settings.rs`, `hold_if_unchanged` in `crates/engine/src/net/liveness.rs`). The
rule landed with FSM1/cipher-box#1676;
this ADR records it.

**D10 — The registry is asked only on a device that holds no vault-pointer index floor.** This
amends ADR 0022 D2. Before the walk at index 0, on a device that holds no vault-pointer index
floor, the cold start asks the registry whether this account holds a registration for the
index-0 pointer name. A device that adopted a pointer holds a floor and does not ask, even when
it walks at index 0 again, so it keeps the unanimity rule. The engine reads an index floor that
the store cannot read as present (`first_run_pointer_name` in `crates/engine/src/facade.rs`), as
D5 reads an unreadable mark. The rule landed with FSM1/cipher-box#1939; this ADR records it.

**D11 — The registry answer is not stored.** This amends ADR 0022 D3. The answer permits
availability only: it never adopts a record or selects a root, and it is not stored. It lives
for the one start or the one in-session mint retry that asked for it. The in-session retry asks
again, and the re-walk after another device published uses the unanimity rule. The rule landed
with FSM1/cipher-box#1939; this ADR records it.

## Trust argument

- **The record-plane adversary gains no widening.** Withholding, delay, a broken head block and
  a replay all reach D2 or D4. D2 returns the member's own authenticated choice, and D4 refuses.
  Neither can produce `Hosted` for an `External` member.
- **The cache is storage, not a trust bypass.** Every use of the cached copy re-runs the seal
  open, which authenticates the owner, and the body grammar of this build (D2). A copy for
  another account, a tampered copy, or a copy from an unknown schema does not open.
- **The one permissive arm needs proof of absence on this device.** `UnprovenFirstRun` needs
  three independent marks absent and readable (D5). The mint counter rises before the PUT, so a
  choice that the member expressed but never landed still refuses. The adopted revision rises in
  a store write apart from the sequence floor, so it outlives a lost floor write.
- **A server-controlled signal only restricts.** The advisory flag can refuse an assumed default.
  It can never authorise one (D5).
- **A same-sequence fork is closed on a device with state.** The revision orders two records at
  one sequence (D6). The per-attempt mint gives the retry a new value, and the adopted high-water
  refuses the older generation.
- **The renewal promotes only admitted bytes.** D9 enrols only a record that cleared the whole
  floor law on a device that holds a floor, and it never replaces a newer save. A replay or a
  fork is never re-signed into winning the record selection.
- **The first-run registry rule cannot reach a device with a pointer.** D10 keeps a device that
  adopted a pointer on the unanimity rule, so residual E3 of ADR 0022 reaches only a device that
  never held a pointer. D11 keeps a stale "not registered" answer from outliving its start.

## Alternatives rejected

**(a) Degrade to the built-in defaults on any failure.** This was the v1 shape that
FSM1/cipher-box#870 took. The defaults name `Hosted`, so every degraded load of an `External`
member placed that member's bytes on the hosted store. FSM1/cipher-box#928 showed that the party
that gains is the one that controls the record plane.

**(b) Cache the decoded record, not the head block.** A withholding adversary breaks the load at
the head-block fetch, so a decoded cache would leave the hole open. It would also put the
member's BYO bearer in host storage as plaintext (FSM1/cipher-box#934).

**(c) Prefer the cached copy only on the four reasons that FSM1/cipher-box#928 listed.** The
argument does not change with the reason. `RolledBack` already owes last-known-good, and a
four-of-six rule is weaker code for more of it (FSM1/cipher-box#934).

**(d) Derive the first run from the sequence floor alone.** The floor rises only on a confirmed
adopt. A save that never landed, and an adopt whose floor write was lost, both read as a first
run and widen placement (FSM1/cipher-box#1149).

**(e) Refuse `UnprovenFirstRun` outright.** The absence of a settings record cannot be proved
cryptographically, and a first run has no record. The refusal would refuse every content write
on every account that never saved settings (FSM1/cipher-box#1149).

**(f) Chain the settings head CID into the vault pointer (FSM1/cipher-box#930 option ii).** It
gives a cold device an anchor, but it makes a BYO member reach the network configured in the
settings in order to read those settings, and it reverses the cold-start order (D7).

**(g) An API-held monotonic counter (FSM1/cipher-box#930 option iii).** No client resolve path
touches the API's record cache (#24 D3).

**(h) Derive the revision from the confirm-gated sequence floor.** The retry after an
unconfirmed publish re-mints the same value, so it separates nothing (FSM1/cipher-box#1046).

**(i) One revision counter for writer and reader.** An attempt that never landed would make the
device refuse the live record that it failed to replace (FSM1/cipher-box#1046).

**(j) Hold every record to the adopted revision, at every sequence.** The crypto review on
FSM1/cipher-box#1046 found that this refuses the legitimate higher-sequence record of a second
device permanently. The bar applies at the same sequence only.

**(k) Enrol the settings record on a publish only.** An account that nobody re-saved lapsed
inside 90 days, and the placement then failed closed (FSM1/cipher-box#1676).

**(l) Ask the registry before every walk at index 0.** This is ADR 0022 D2 as written. A device
that adopted index 0 would then reach the relaxed rule, and with it residual E3 of ADR 0022.

## Consequences

1. **`blueprint/engine.md` already carries D1 to D8.** The "Vault settings load" section states
   D1 in its opening paragraph and D2 to D8 in the bullets "Last-known-good before defaults",
   "A degraded load never widens placement", "No last-known-good copy fails the placement
   decision closed", "The one arm that still authorises a write is named for what it assumes",
   "The sealed body carries a monotonic revision", "The cold-device anchor is the EOL, and only
   the EOL" and "Residual: the cached copy has no freshness bound". No text change is needed.

2. **`blueprint/engine.md` already carries D10 and D11.** The paragraph "The first-run rule" in the
   "Adoption gate and floors" section states the no-floor condition and "it is not stored". No text
   change is needed.

3. **`CONTEXT.md` already carries the frame of D1.** The "Vault settings record" entry states
   that the record resolves at cold start with no CipherBox infrastructure. The "Vault pointer"
   entry carries ADR 0022 consequence 3 and needs no change for D10 or D11.

4. **`blueprint/engine.md` does not state D9 in positive form.** FSM1/cipher-box#1676 removed
   the lapse residual from "Vault settings load" and added no sentence in its place. The
   section gains one sentence: a settings load enrols the record it read in the session's
   renewal set, only when the record cleared the whole floor law and this device holds a
   sequence floor for the name (ADR 0034 D9).

5. **ADR 0013 is amended.** D3 ("The load enrols the record in the session's renewal set") and
   D4 (the two enrolment bars) now read as the rule of both owner record planes, the settings
   record and the bin index. D2 does not change: the lapsed-EOL refusal stays at the settings
   record alone, and D9 of this ADR enrols no lapsed settings record. The ADR 0013 Context
   sentence "the session that holds the login secret republishes the record on the spot" now
   reads with D9: the renewal set keeps a live account's settings record inside its EOL. The
   ADR 0013 Context phrase "the mint-versus-adopt revision pair, and the three-rung degradation
   ladder" refers to D6, D2 and D5 of this ADR.

6. **ADR 0022 is amended.** D2 now reads: "Before the pointer walk at index 0, on a device that
   holds no vault-pointer index floor, the cold start asks D1 for the derived vault-pointer
   name." D3 now reads: "It does not adopt a record, it does not select a root, it does not skip
   the verify or the adoption gate on a `Found`, and it is not stored."

7. **The lapsed-EOL refusal needs no encode-side guard.** This applies AGENTS.md rule 8 with the
   90-day EOL of #24 D1: the EOL is `now + 90 days` off the injected clock, so a publish cannot
   mint an expired record. It is not a rule of this ADR.

8. **`blueprint/engine.md` section "Vault settings load" gains the citation (ADR 0034).** The
   paragraph "The first-run rule" in "Adoption gate and floors" gains the citation (ADR 0022 as
   amended by ADR 0034).

9. **The engine doc comments cite headings that do not exist.** `crates/engine/src/settings.rs`,
   `crates/engine/src/facade.rs` and `crates/engine/tests/write_plane.rs` cite
   `blueprint/engine.md "Settings-load policy"`, and the settings load in `Engine::start`
   (`crates/engine/src/facade.rs`) cites `blueprint/engine.md "Vault settings record"`. The
   section is "Vault settings load".

10. **No wire format, no KDF edge, and no op queue record changes.**

## Residuals

**E1 — An adversary inside the device's storage can pin or reset the settings.** This is D8. The
bound is the seal: the adversary can choose only among generations that the account itself
published, or force the defaults path, which D4 and D5 then govern.

**E2 — A fresh install with no marks takes the assumed default.** A record-plane adversary that
withholds the settings record from a device that holds no mark reaches `UnprovenFirstRun`, and
that device places its first writes on the hosted store. The advisory flag closes the case for
an `External` account whose flag a member-established placement already reconciled, because a
set flag refuses the default. It does not close the case for a `Dual` account, which has no
server representation. A hostile API can clear the flag. It can also fail the quota read, and
the pre-flight check in `crates/engine/src/facade.rs` then does not read the flag. The exposure
ends at the first successful resolve on that device.

**E3 — A cold device admits any owner-signed record inside its EOL.** This is the bound of D7. A
replay inside the 90-day window reaches a fresh install, a record that names a BYO credential
the member has since rotated included. D6 cannot order a same-sequence fork on a device without
state.

**E4 — A dormant account still lapses.** D9 enrols only while a session runs on a device that
holds a floor. An account with no such session for 90 days lapses. The load then refuses the
record as `Expired`, falls back to last-known-good, and with no copy fails closed. Recovery needs
a publish from a session that holds the login secret.

**E5 — The first-run registry residuals of ADR 0022 remain.** D10 narrows ADR 0022 E3 to a
device that never held a pointer. It does not remove E1 or E3 of ADR 0022 for that device.

## Gate

The suite is `Engine Tests` (`cargo test -p cipherbox-engine`) for every item below.

- **D1:** `an_unresolvable_settings_name_does_not_block_cold_start_past_the_budget` and
  `a_snapshot_cache_that_never_answers_does_not_block_cold_start`
  (`crates/engine/tests/vault_settings.rs`) prove the budget on the Scheduler seam at the load.
  No test drives `Engine::start` through a timed-out settings load, and no test asserts that
  the settings load runs ahead of the vault resolve. That is a finding.
- **D2:** `a_load_that_runs_out_of_budget_prefers_the_cached_copy`,
  `a_record_this_build_cannot_read_prefers_the_cached_copy`,
  `a_floor_the_host_cannot_read_prefers_the_cached_copy`,
  `a_cached_copy_that_does_not_authenticate_is_not_used`,
  `the_cache_holds_the_sealed_block_never_the_opened_body`,
  `a_rolled_back_record_never_becomes_last_known_good` and
  `a_lapsed_eol_is_not_authoritative_and_degrades_to_last_known_good`
  (`crates/engine/tests/vault_settings.rs`); `a_stale_copy_decides_placement_like_a_resolved_record`
  (`crates/engine/src/settings.rs`).
- **D3:** `a_withheld_record_never_downgrades_external_to_hosted`
  (`crates/engine/tests/vault_settings.rs`).
- **D4:** `a_degraded_load_with_no_cached_copy_reports_defaults_not_stale`
  (`crates/engine/tests/vault_settings.rs`);
  `only_an_unproven_first_run_falls_back_to_the_hosted_default`
  (`crates/engine/src/settings.rs`);
  `a_withheld_settings_record_refuses_the_write_instead_of_widening_it`
  (`crates/engine/tests/write_plane.rs`).
- **D5:** `any_durable_mark_alone_refuses_a_withheld_record` (each mark alone, no mark, and an
  unreadable mark) and `an_assumed_default_is_never_reported_as_the_members_own_choice`
  (`crates/engine/src/settings.rs`);
  `a_settings_publish_that_never_confirmed_is_still_a_mark_of_a_choice`,
  `an_assumed_first_run_never_clears_the_accounts_byo_flag` and
  `an_assumed_first_run_latches_nothing_when_the_flag_already_agrees`
  (`crates/engine/tests/vault_settings.rs`);
  `a_settings_save_that_never_landed_refuses_the_write_instead_of_widening_it`
  (`crates/engine/tests/write_plane.rs`).
- **D6:** `a_body_revision_below_the_adopted_high_water_is_refused`,
  `a_retry_mints_a_revision_above_the_attempt_it_replaces`,
  `a_higher_sequence_record_is_admitted_whatever_revision_it_carries`,
  `an_unconfirmed_publish_leaves_the_live_record_still_admissible`,
  `a_confirmed_publish_raises_the_writers_own_adopted_revision`,
  `a_revision_rolled_back_record_never_becomes_last_known_good` and
  `a_mint_counter_that_does_not_advance_refuses_the_publish`
  (`crates/engine/tests/vault_settings.rs`). `a_rolled_back_settings_record_is_reported_at_start`
  (same file) proves the trust-violation event for a sequence rollback. No test proves the event for
  a revision rollback, which `report_settings_verdict` in `crates/engine/src/facade.rs` emits. That
  is a finding.
- **D7:** `a_lapsed_eol_on_a_cold_device_reports_expiry_rather_than_applying_the_record`
  (`crates/engine/tests/vault_settings.rs`) proves the EOL bound on a cold device. The two
  refused anchors are design choices and have no test.
- **D8:** an accepted residual has no test. The seal binding it rests on is proven by
  `a_cached_copy_that_does_not_authenticate_is_not_used` and
  `a_second_account_on_the_device_never_sees_the_first_accounts_cached_settings`.
- **D9:** `a_resolved_settings_record_is_offered_for_renewal_by_the_load_alone`,
  `a_session_that_only_loads_the_settings_record_keeps_it_alive`,
  `a_replayed_settings_record_is_never_offered_for_renewal`,
  `a_lapsed_settings_record_is_never_offered_for_renewal`,
  `a_device_that_has_never_adopted_the_settings_record_re_signs_nothing`,
  `an_enrolment_never_replaces_a_record_that_landed_across_its_load`,
  `the_settings_enrolment_captures_the_slot_ahead_of_its_load` and
  `a_renewal_never_re_signs_a_settings_record_a_second_device_superseded`
  (`crates/engine/tests/vault_settings.rs`).
- **D10:** `a_device_that_walked_the_chain_before_does_not_ask_the_registry`
  (`crates/engine/src/facade.rs`). No test proves that an index floor the store cannot read
  keeps the unanimity rule. That is a finding.
- **D11:** no test proves that the answer is not stored, for example that the in-session mint
  retry asks the registry again. That is a finding.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
