# ADR 0044 — The engine owns refresh forcing, mailbox transport and the staging budget

- **Status:** Accepted on 2026-09-26 — retroactive; the rule shipped in FSM1/cipher-box#878,
  FSM1/cipher-box#1212, FSM1/cipher-box#1409 and FSM1/cipher-box#1501, and the blueprint carries
  it except two sentences that still place the staging budget in the sync timing profile
  (consequence 8), the unconditional cache reservation (consequence 9) and the desktop TTL-check
  sentence (consequence 10); the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-26
- **Relates to:**
  [#33](https://github.com/FSM1/cipher-box-next/issues/33) D1 (the refresh hint source), D2
  (focus-window polling "30 s with jitter"), D3 (the sync timing profile holds the staging
  budget) and D6 (the "profile-scoped budget"), which this ADR supersedes where consequences 6
  and 7 say;
  [#26](https://github.com/FSM1/cipher-box-next/issues/26) D8 (floors store, publish transport and
  mailbox are mandatory constructor seams) and the
  [#44](https://github.com/FSM1/cipher-box-next/issues/44) resolution (nine constructor seams,
  `Mailbox` and `RefreshHintSource` among them), which this ADR supersedes where consequence 7
  says;
  [#25](https://github.com/FSM1/cipher-box-next/issues/25) D2 (a decentralized inbox stays
  swappable behind `Mailbox`), [#34](https://github.com/FSM1/cipher-box-next/issues/34) D5 (the
  mailbox poll rides the tick), [#28](https://github.com/FSM1/cipher-box-next/issues/28) D3 and
  D5 (the seam set; the single hand-written API client),
  [ADR 0023](./0023-the-invite-link-is-the-primary-sharing-path-and-conversion-runs-by-itself.md)
  D5 (the ack answer that the engine's mailbox carries), the `blueprint/engine.md` "Doctrine",
  "Module map", "Host seams", "Sync core" and "Open edges" sections, the `blueprint/web-client.md`
  "Browser seams", "UI state law" and "Open edges" sections, the `blueprint/desktop.md` "Engine
  wiring", "Freshness — the desktop trigger source", "Tauri shell" and "Open edges" sections, the
  `blueprint/testing.md` "crates/engine — seam fakes and the simulation harness" and "The DX
  hook" sections, and the `CONTEXT.md` "Manual refresh", "Sync timing profile", "Storage policy",
  "Focus window" and "Mailbox" terms
- **Implemented by:** FSM1/cipher-box#878 (the storage policy, D6 to D8, with the cache
  reservation of D7 made unconditional; the conditional form is not landed),
  FSM1/cipher-box#1212 (refresh forcing and the tick without jitter, D1 to D3),
  FSM1/cipher-box#1409 (the desktop headroom measurement, D7 and D8) and FSM1/cipher-box#1501
  (the mailbox transport and the harness, D4 and D5).

## Context

The sync model of `#33` and the engine blueprint of `#44` gave the engine nine constructor seams.
Two of them were never real host capabilities, and one sync constant was not a constant. Three
defects showed this.

**The refresh control did nothing.** `Command::ManualRefresh` reached the catch-all
`EngineError::Unimplemented` arm. The web chrome called it, swallowed the rejection, and repainted
from a purely local snapshot, so the control appeared to work and did nothing. A write waited up to
one full 30 s poll cadence to publish. The `RefreshHintSource` seam was dead on both sides: no host
implemented a producer, the desktop seam crate declined it, and the web built a queue that nothing
pushed to (FSM1/cipher-box#1210). FSM1/cipher-box#1212 implemented the command as a forced pass on
the tick loop and deleted the seam. The same PR found that the tick loop had never applied the
jitter that `#33` D2 names, and removed the word from the nine places that still stated it.

**The browser mailbox could not authenticate.** Every API mailbox route is guarded by
`JwtAuthGuard`, which reads the access token only from the `Authorization` header. The browser
`Mailbox` seam sent no bearer, so every post, poll and ack returned 401, and it had no refresh path.
The access token lives in the engine's session store, and the engine's `ApiClient` already had the
three mailbox calls with single-flight refresh and one retry on 401
(FSM1/cipher-box#953). The owner decided on 2026-08-25, in FSM1/cipher-box#953, that the engine
owns mailbox transport auth. FSM1/cipher-box#1501 removed `Mailbox` from `SeamTypes` and
`SeamSet`, deleted the TypeScript seam, its mock and the desktop `UnwiredMailbox` stub, and moved
the testkit mailbox hub behind the fake HTTP.

**The staging budget promised storage that nobody had measured.** Under the stage-then-commit
upload protocol, a whole sealed file sits in the staging store until the drain completes, so the
staging budget is the maximum file size. It was a 1 GiB placeholder in the sync timing profile.
The map `#813` research on FSM1/cipher-box#829 found that a Chrome origin set to "clear cookies
when all windows close" gets about 300 MB, and incognito less. A fixed 1 GiB budget admits the
write and then fails minutes later with `QuotaExceededError`. The same research found that
`navigator.storage.estimate()` is deliberately imprecise, so a budget taken wholly from it moves
between sessions. The resolution of FSM1/cipher-box#829 (2026-07-27) made the budget a platform
cap cut down by a measured fraction of headroom. The resolution of FSM1/cipher-box#844
(2026-07-28) gave the read cache a ceiling off headroom first, conditional on a read cache
existing, and moved the whole policy out of the timing profile. The owner ruled on 2026-09-26 that
a map `#813` resolution is an owner decision. FSM1/cipher-box#878 shipped the split and added one
state that neither resolution names: a host that cannot measure headroom. It also made the cache
subtraction unconditional, six hours after the FSM1/cipher-box#844 resolution, and gave no reason.

The rules live today in `blueprint/engine.md` "Host seams" and "Sync core",
`blueprint/web-client.md` "UI state law", `blueprint/desktop.md` "Freshness — the desktop
trigger source", `blueprint/testing.md` "crates/engine — seam fakes and the simulation
harness", and the `CONTEXT.md` terms "Manual refresh" and "Storage policy". No ADR states them.

## Decision

**D1 — Every forced pass goes through `Command::ManualRefresh`, and `RefreshHintSource` is not a
seam.** A host event that must bring a sync pass forward calls the facade command. It does not
push a hint into a seam. On web, the regain of the network, the regain of tab visibility and a
change in the focus that any tab reports each call the command. On desktop, the tray "Sync Now",
a network reconnect and a wake from sleep each call it. The FUSE-op TTL check is not a forced
pass: a stale hit puts the node in the focus window, and the next tick refreshes it, so no kernel
callback waits on the network (the never-block law of `blueprint/desktop.md`). A future push
overlay (API WebSocket hints, or desktop PubSub) is a handler that calls the same command. The
command files a request on the tick loop's second wake source and waits for the pass that answers
it. The tick loop is the only pass executor, so a forced pass never runs beside the poll leg; it
brings the next pass forward. Requests coalesce: every request outstanding when a pass starts, and
every request filed while a manual pass runs, is answered by that one pass. The drain rides the
same pass, so a queued op publishes in that pass. The rule landed with FSM1/cipher-box#1212; this
ADR records it.

**D2 — A manual refresh reports what it landed, and a refresh it could not land is a failure, not
a repaint.** The forced pass resolves nocache: it reads no snapshot cache, so its verdict is only
what the record plane served it (`#33` D3). The command settles on every read leg the pass forced,
the focus window included, and the worst leg wins. The pass that reconciled gate-passing state
answers success. A pass in which no endpoint served a record it could adopt answers
`EngineError::RefreshFailed`, a retryable availability failure. A pass in which the adoption gate
rejected a served record answers `EngineError::TrustViolation`, and a host never retries it
(AGENTS.md rule 6). A failed pass leaves the host's last-known-good view standing, and the host
renders the failure over that view. It does not render a success from cached bytes. The rule
landed with FSM1/cipher-box#1212; this ADR records it.

**D3 — The focus-window tick has no jitter.** The tick loop sleeps exactly the poll cadence after
each pass and wakes early only on a manual refresh. The production cadence is 30 s. The
`Scheduler` seam contract is timers, background task execution and wall clock; it has no jitter
term and takes no entropy. No earlier owner decision existed for this rule. The rule landed with
FSM1/cipher-box#1212, which removed a jitter helper that no live path used and left a return of
jitter to a later measured-constant change. The owner accepted the rule on 2026-09-26.

**D4 — `Mailbox` is not a host seam; the engine implements it over its own API client.** Every API
mailbox route is JWT-guarded, and the access bearer never leaves the engine. The engine therefore
implements the `Mailbox` trait itself over its `ApiClient` (`crates/engine/src/api/mailbox.rs`),
through the same token store, the same single-flight refresh and the same one retry on 401 as
every other authenticated call, on both platforms. `Mailbox` is not a member of `SeamTypes` or
`SeamSet`, and no host supplies an implementation. The trait stays, so a decentralized inbox stays
swappable behind it (`#25` D2), and its conformance kit runs against the API client. A host never
receives the bearer to attach it, and a host never refreshes it. Decided on 2026-08-25 in
FSM1/cipher-box#953.

**D5 — The simulation harness serves the mailbox through the fake HTTP.** The engine test kit has
no `Mailbox` seam fake in the seam set. A mailbox hub sits behind the fake HTTP, which answers the
API's mailbox routes from the hub. Engine instances in one simulation world share the hub, so
sealed blobs still cross from device to device, and the wire shape and the trait contract meet at
the same place they meet in production. Decided on 2026-08-25 in FSM1/cipher-box#953, which
accepted this test cost and allowed the hub behind the fake HTTP router or a test-support
injection hook; FSM1/cipher-box#1501 took the fake HTTP router.

**D6 — The staging budget lives in a device-scoped storage policy, not in the sync timing
profile.** The sync timing profile is a named, environment-scoped constant set. Its members
include record TTL, poll cadence, staleness thresholds, escalation window and the pointer-consult
interval. A measured per-device byte count has no name, so it is not a member. The storage
policy carries the staging budget and the read-cache ceiling. The host measures a headroom figure
once and injects the policy at engine construction. No staging read-modify-write queries the
host for space; the `StagingStore` seam has no headroom method. Decided on 2026-07-27 in
FSM1/cipher-box#829 and on 2026-07-28 in FSM1/cipher-box#844, map `#813` resolutions.

**D7 — The storage policy splits measured headroom, with no floor-up, and reserves the cache
ceiling off headroom only once a read cache exists.** The split is:

```text
cache_ceiling  = min(CACHE_CAP, CACHE_PERCENT × headroom)
reserved       = cache_ceiling  when a sealed-block read cache is built, else 0
staging_budget = min(STAGING_CAP, STAGING_PERCENT × (headroom − reserved))
```

The ceiling lands in the storage policy at once. Its subtraction from headroom is conditional on
the read cache being built; until then, headroom is unreduced. An unconditional reservation is
rejected: the staging budget is the maximum file size (FSM1/cipher-box#815), which
FSM1/cipher-box#820 made a product commitment, and a reservation taken now taxes that commitment
for a feature that does not exist, worst on a small device. The budget is a construction-time
value that is computed again at each session, so a read cache that lands changes what the next
construction computes, and it needs no migration.

On web, headroom is the Storage Standard estimate's quota minus its usage; the caps and fractions
are 1 GiB and 50 % for staging, 512 MiB and 10 % for the cache. On desktop, headroom is the free
bytes a non-privileged user has on the volume of the engine data directory; the values are 16 GiB
and 25 % for staging, 2 GiB and 10 % for the cache. The fractions are integer percents, so one
headroom figure gives one budget on every host. There is no floor-up: a small headroom gives a
small budget and an honest over-budget refusal. The op queue, the snapshot cache and the floors
are demand-driven, have no budget, and have first claim on what the fractions leave. The policy
carries the platform cap beside the budget, so a refusal can say whether the platform cap or this
device's headroom refused the write. Decided on 2026-07-27 in FSM1/cipher-box#829 and on
2026-07-28 in FSM1/cipher-box#844 (section 2 for the conditional reservation).
FSM1/cipher-box#878, merged six hours later, made the subtraction unconditional and gave no reason.
`blueprint/engine.md` "Storage policy", `CONTEXT.md` "Storage policy" and
`StoragePolicy::measured` lag this decision (consequence 9, E3). The code fix folds into the open
read-cache issue FSM1/cipher-box#831.

**D8 — A host that cannot measure headroom is unmeasurable, not full.** When the host has no
headroom figure, the policy is the unmeasured policy: zero budgets, because inventing a figure is
the floor-up that D7 rules out, and a separate state. The engine refuses every upload with the
unmeasurable cause, not with the device-full cause, and the host reports it as such. A partial
figure is not a measurement. On web, an estimate without both quota and usage, and a figure that
is not a whole, in-range byte count, are unmeasured. On desktop, a path the host cannot measure
is unmeasured. The host climbs to a parent directory only past a directory that does not exist
yet, never past a refusal. A measured zero stays measured and reads as a full device. Metadata ops
still queue unbounded (`#33` D6). No earlier owner decision existed for this rule. The rule landed
with FSM1/cipher-box#878. The owner accepted the rule on 2026-09-26.

## Rationale

- **One forcing path can report failure.** A hint pushed into a seam is fire-and-forget, so it
  cannot tell the host that the pass failed. A command returns a verdict, and it coalesces in one
  place for every host (D1, D2).
- **A repaint from cache is a false success.** The defect in FSM1/cipher-box#1210 was a control
  that looked like it worked. Nocache and a reported failure make the control mean what it says
  (D2).
- **A trust verdict is not an availability failure.** Keeping `Rejected` apart from `Unreachable`,
  worst leg first, stops a reconciled leg from hiding a gate rejection in a retry (D2).
- **Jitter protects against a lasting alignment that the tick does not have.** Each session starts
  its own loop, each pass has its own length, and each manual pass restarts the sleep. No
  fleet-wide clock aligns the ticks, so an alignment decays by itself (E7). Jitter would need
  entropy in the `Scheduler` seam, and it would make the virtual-clock tests inexact for no gain
  (D3).
- **The bearer stays in one place.** A token exported to a JavaScript seam lives in strings that
  cannot be wiped. A second refresher in the host races the engine's single-flight rotation. The
  engine already held the calls, the token and the retry (D4).
- **The harness tests what ships.** With the hub behind the fake HTTP, the simulation exercises
  the API client's mailbox path, the same path the contract suite runs against a real API (D5).
- **A budget is a promise about storage.** A promise the engine makes without a measurement fails
  in the middle of a write. A promise taken wholly from an imprecise estimate moves between
  sessions. A cap cut by a measured fraction is stable on a large device and honest on a small one
  (D6, D7).
- **The read cache is the one consumer that can grow without a limit.** Its loss costs nothing, and
  its growth can take the whole origin. Once a read cache exists, a ceiling off headroom first
  keeps the staging admission valid however large the cache grows. Before it exists, a
  reservation only makes the maximum file size smaller (D7).
- **Unknown must not read as full.** A user told "device full" frees disk space that does not help.
  A user told "storage unmeasurable" learns that the host is the cause (D8).

## Alternatives rejected

**(a) Wire `RefreshHintSource` to real producers.** FSM1/cipher-box#1210 allowed this. No host
had built a producer, the leader relay already routed the cross-tab focus signal through the
command, and a hint queue cannot report a failed pass.

**(b) Run a forced refresh beside the poll leg.** Two pass executors race on the same snapshot and
queue. Bringing the next pass forward keeps one executor.

**(c) Keep the jitter that `#33` D2 names.** The tick loop never applied it, and nothing depended
on it. It would add an entropy input to a seam that has none.

**(d) Attach the bearer in the host.** Rejected on FSM1/cipher-box#953: it moves a bearer secret
into JavaScript and adds a refresher that races the engine's rotation.

**(e) Make the mailbox routes auth-free.** Rejected on FSM1/cipher-box#953: a poll is
recipient-authenticated, and the throttle model keys on the account.

**(f) A fixed staging budget.** Rejected on FSM1/cipher-box#829: 1 GiB is too large for a Chrome
clear-on-close origin and too small for a desktop disk, where the budget is the `ENOSPC`
threshold.

**(g) A budget taken wholly from the estimate.** Rejected on FSM1/cipher-box#829: the estimate is
imprecise by design, so the maximum file size would change between sessions with no reason a user
can act on.

**(h) A fraction for every consumer of the origin.** Rejected on FSM1/cipher-box#844: a share for
the op queue, the snapshot cache or the floors can never be enforced, because enforcing it refuses a
mutation, breaks cold start or fails open on the floor law.

**(i) Keep the policy in the timing profile.** Rejected on FSM1/cipher-box#844: the profile is
selected by name, and a measured byte count per device has no name.

**(j) Report an unmeasurable host as a measured zero.** The two states admit the same uploads, but
only one is a full device. The user action differs.

**(k) Reserve the cache ceiling before a read cache exists.** Rejected on FSM1/cipher-box#844
section 2: the staging budget is the maximum file size, a product commitment, and the reservation
would reduce it for a consumer that has no implementation.

**(l) Make the TTL check a forced pass.** A forced pass waits on the network, and a kernel callback
must not. The tick already refreshes the focus window, and the stale hit adds the node to it.

## Consequences

1. **`blueprint/engine.md` already carries D1 to D4, D6 and D8.** The "Module map" states that
   the mailbox runs over the `Mailbox` the API client implements. The "Host seams" table has no
   `Mailbox` and no `RefreshHintSource` row, and its `Scheduler` row has no jitter; the note
   "`Mailbox` is not a host seam" states D4. The "Sync core" section states the 30 s tick,
   `Command::ManualRefresh`, the sync timing profile without the budget and the storage policy
   bullet with the unmeasurable state. The "Open edges" section routes the push overlay through
   the command. It does not carry D7: its "Storage policy" bullet reserves the cache ceiling
   unconditionally (consequence 9). The blueprint does not state the D7 formula, caps or
   fractions; they live in `crates/engine/src/storage_policy.rs` (`StoragePlatform::WEB`,
   `StoragePlatform::DESKTOP`, `StoragePolicy::measured`).

2. **`blueprint/web-client.md` already carries D1, D2 and D4.** The "Browser seams" table has no
   `Mailbox` and no `RefreshHintSource` row, and its `Scheduler` row says that every wake-relevant
   transition forces a pass. The "UI state law" section states D2. The "Open edges" section routes
   the push overlay through the command. Consequence 8 names the one row that lags.

3. **`blueprint/desktop.md` already carries D4 and most of D1.** The "Engine wiring" table has no
   `Mailbox` and no `RefreshHintSource` row. The "Freshness — the desktop trigger source" section
   routes reconnect, "Sync Now" and wake through the command. The "Tauri shell" section makes
   "Sync Now" a manual-refresh command with nocache semantics. The "Open edges" section routes
   desktop PubSub through the command. Consequence 10 names the TTL-check sentence that lags.

4. **`blueprint/testing.md` already carries D5.** The "crates/engine — seam fakes and the
   simulation harness" section names "a mailbox hub the fake HTTP serves the API's mailbox routes
   from". The "The DX hook" section keeps nocache manual refresh as the forcing path between
   clients. Consequence 8 names the one bullet that lags.

5. **`CONTEXT.md` already carries D2, D6 and D8.** The "Manual refresh" term states the forced
   nocache pass, the coalescing and the two failure verdicts. The "Sync timing profile" term
   excludes the measured byte count. The "Storage policy" term states the split and the
   unmeasured policy, but it reserves the cache ceiling unconditionally, so it does not carry D7
   (consequence 9).

6. **This ADR supersedes `#33` D1, D2 and D3 where they conflict, and the budget clause of D6.**
   D1 now reads: refresh is pull-only; a forced pass goes through `Command::ManualRefresh`, and a
   later push overlay is a handler that calls it. D2 now reads "focus-window polling, 30 s", with no
   jitter; the immediate ticks on navigation, tab-visibility regain and reconnect are manual
   refresh commands from the host. D3 now reads: the sync timing profile holds TTL, poll
   cadence, staleness thresholds and the escalation window, and the staging budget is in the
   storage policy. In D6,
   "behind a profile-scoped budget" now reads "behind the storage-policy staging budget". The
   other parts of D1 to D3 and D6 do not change.

7. **This ADR supersedes the mailbox clause of `#26` D8 and the `#44` seam list.** `#26` D8 now
   reads: the floors store and the publish transport are mandatory constructor seams, and the
   mailbox is mandatory engine behaviour that the engine implements itself over its API client, so
   no host can diverge on it. The `#44` list of nine constructor seams now reads seven:
   `FloorStore`, `RecordTransport`, `Http`, `Scheduler`, `StagingStore`, `SnapshotCache` and
   `CredentialStore`.

8. **Two blueprint sentences still place the budget in the profile and must change.** The
   `blueprint/web-client.md` "Browser seams" `StagingStore` row says "behind the
   sync-timing-profile budget"; it changes to "behind the storage-policy staging budget". The
   `blueprint/testing.md` "The DX hook" "CI profile" bullet lists "a small staging budget" as a
   member of the profile; the small budget moves to a sentence of its own that names the CI
   storage policy (`StoragePolicy::CI`), which the engine tests and the desktop shell pin in CI
   and the web host does not (E2).

9. **The cache reservation text changes to the conditional form of D7.** In `blueprint/engine.md`
   "Sync core", the "Storage policy" sentence "The cache ceiling comes off headroom before the
   staging fraction" becomes "The cache ceiling is part of the policy at once, and it comes off
   headroom before the staging fraction only once a sealed-block read cache is built; until then,
   headroom is unreduced (ADR 0044)". In `CONTEXT.md` "Storage policy", "the read-cache ceiling
   reserved off headroom before the staging fraction" becomes "the read-cache ceiling, reserved
   off headroom before the staging fraction once a read cache exists". The code fix in
   `StoragePolicy::measured` folds into the open read-cache issue FSM1/cipher-box#831.

10. **`blueprint/desktop.md` "Freshness — the desktop trigger source" changes for the TTL check.**
    "A stale hit forces a pass for that node" becomes "a stale hit puts the node in the focus
    window, and the next tick refreshes it, so no kernel callback waits on the network (ADR
    0044)". The sentence "Network reconnect, tray "Sync Now", and wake-from-sleep force one the
    same way, through `Command::ManualRefresh`" becomes "Network reconnect, tray "Sync Now", and
    wake-from-sleep force a pass through `Command::ManualRefresh`", because "the same way" no
    longer names a forced pass.

11. **`blueprint/engine.md` sections "Host seams" and "Sync core" gain the citation (ADR 0044).**
    "Host seams" gains it on the note "`Mailbox` is not a host seam" and on the `Scheduler` row.
    "Sync core" gains it on the "Focus-window tick" bullet, the "Sync timing profile" bullet and
    the "Storage policy" bullet. The "Doctrine" sentence "Hosts inject every capability as a
    constructor seam trait" and the "Open edges" push-overlay item gain it beside their `#26` D8
    and `#33` D1 citations.

12. **`blueprint/web-client.md` sections "UI state law" and "Open edges" gain the citation (ADR 0044)**, on the manual-refresh sentence and on the push-overlay item.

13. **`blueprint/desktop.md` sections "Freshness — the desktop trigger source" and "Open edges"
    gain the citation (ADR 0044)**, on the reworded TTL-check sentence, the forced-pass sentence
    and the PubSub item.

14. **`blueprint/testing.md` section "crates/engine — seam fakes and the simulation harness"
    gains the citation (ADR 0044)** on the mailbox hub.

15. **No wire format, no KDF edge and no op queue record changes.**

## Residuals

**E1 — No desktop code forces a pass on a network reconnect or a wake from sleep.** D1 and the
blueprint name both. At `origin/main`, only the tray "Sync Now"
(`apps/desktop/src-tauri/src/engine/mod.rs`, `Request::Refresh`) files a forced pass on desktop,
and no code in `apps/desktop/src-tauri/src` listens for a reconnect or a wake. The work is
FSM1/cipher-box#2017. On web, both triggers are wired (`useRefreshOnWake`). The TTL check is not
part of this gap: it puts a stale node in the focus window, and the tick refreshes it (`ttl_check`
in `crates/fuse/src/ops.rs`, over `Engine::note_focus_access`), which is the D1 rule.
`FuseOpCore::refresh_hint`, which records the stale node, is read only by tests.

**E2 — On web, the CI cadence does not pin a small staging budget.** The desktop shell pins
`StoragePolicy::CI` in the CI environment (`pinned_storage_policy` in
`apps/desktop/src-tauri/src/engine/config.rs`). The WASM host always builds the web policy from the
measured headroom, also on the CI cadence (`web_storage_policy` in `crates/wasm/src/host.rs`). So
the testing blueprint's claim that budget exhaustion is reachable in CI holds for the engine unit
tests and the desktop shell, not for a browser e2e run.

**E3 — The blueprint and the code lag the conditional cache reservation.** The FSM1/cipher-box#844
resolution lands the ceiling in the policy at once and subtracts it from headroom only once a read
cache exists. FSM1/cipher-box#878 made the subtraction unconditional six hours later and gave no
reason. `blueprint/engine.md` "Storage policy", `CONTEXT.md` "Storage policy" and
`StoragePolicy::measured` follow the code. No consumer reads `read_cache_ceiling_bytes` at
`origin/main`, and the read cache FSM1/cipher-box#831 is open. Until the fix lands, a full 1 GiB web
budget needs about 2.22 GiB of headroom, not 2 GiB, and every budget below the cap is about 10 %
smaller than D7 allows. Consequence 9 rewords the text; the code fix folds into
FSM1/cipher-box#831.

**E4 — The policy is fixed for the life of the engine.** The host measures once at construction.
Headroom that other applications consume during the session is not seen, and a staging write can
still meet a host quota refusal below the budget. The staging store surfaces that refusal; it does
not invent space. The next construction measures again. FSM1/cipher-box#829 deferred a
recomputation during the session on purpose.

**E5 — The caps and fractions wait for measurement.** The resolutions of FSM1/cipher-box#829 and
FSM1/cipher-box#844 give the values of D7 with the status "the measurement lands later". The
formula is decided; the numbers are not frozen.

**E6 — An unmeasurable host can never upload.** A browser or web view without the Storage
Standard estimate refuses every upload for that session. This is the cost of D8. Metadata ops
still queue and publish.

**E7 — Clients that start together tick together.** Without jitter, clients whose loops start at
one instant, for example on one network regain, poll at the same instants until their pass
lengths drift apart. The mailbox poll rides the tick, so the API sees the same step. The step
decays by itself, and the API rate limits bound it.

**E8 — A decentralized inbox is now an engine change, not a host change.** The trait stays, but
no host supplies it. Swapping the inbox means a second implementation inside the engine.

## Gate

- **D1:** `a_filed_manual_refresh_ticks_immediately_without_advancing_time` (two requests, one
  pass, no timer elapsed) in `crates/engine/src/sync/tick.rs`;
  `requests_before_a_pass_share_the_one_pass_that_starts` and
  `a_request_during_a_running_pass_joins_it_rather_than_queueing_another` in
  `crates/engine/src/sync/refresh.rs`;
  `a_manual_refresh_publishes_a_queued_op_without_waiting_out_the_cadence` in
  `crates/engine/tests/write_plane.rs` (Rust area, workspace tests); `useRefreshOnWake.test.tsx`
  "refreshes when the network comes back" and "refreshes when a backgrounded tab comes back on
  screen" (Web area, `apps/web` host suite); `broadcastTransport.test.ts` "collapses a burst of
  union changes onto one trailing pass" in `packages/client` (Web area). The absence of the
  seam is structural: `SeamTypes` in `crates/engine/src/seams/mod.rs` names seven types. No test
  proves a desktop reconnect or wake forced pass, because none is wired (E1). That is a finding.
- **D2:** `manual_refresh_is_nocache_and_a_poll_is_cache_first` in `crates/engine/src/sync/tick.rs`;
  `resolve_nocache_never_reads_the_cache_and_reports_no_last_known_good` in
  `crates/engine/tests/net.rs`; `a_manual_refresh_reports_an_unreachable_record_plane_as_a_failure`
  and `a_manual_refresh_reports_a_rejected_record_as_a_trust_violation` in
  `crates/engine/tests/write_plane.rs`;
  `a_filed_pass_reports_the_verdict_the_command_would_have` and
  `the_worst_leg_settles_the_pass` in `crates/engine/src/sync/refresh.rs`;
  `a_folder_under_a_scope_this_pass_cannot_read_fails_the_forced_refresh` in
  `crates/engine/src/facade.rs`; `a_manual_refresh_with_no_sync_loop_reports_a_failed_refresh`
  in `crates/engine/tests/facade.rs`; `availability_failures_stay_availability` in
  `crates/fuse/src/error.rs` (`FUSE Op Core`); `snapshotStore.test.ts` "reports a refused refresh
  over the listing it left standing" and "treats a failed refresh as recoverable" (Web area).
- **D3:** `the_poll_timer_ticks_on_the_cadence` in `crates/engine/src/sync/tick.rs` asserts that
  "each tick slept exactly the cadence" on the virtual clock.
- **D4:** `every_mailbox_seam_call_carries_the_session_bearer` and
  `a_mailbox_401_refreshes_once_and_retries` in `crates/engine/src/api/client.rs`; the contract
  suite (`Contract Suite Result`) runs `mailbox_post_poll_ack_round_trips`,
  `mailbox_ack_reports_removal_and_releases_the_idempotency_key` and
  `a_read_grant_delivers_its_share_pointer_through_the_live_mailbox` in
  `crates/contract/tests/contract.rs` against a real API. The removal from `SeamSet` is
  structural.
- **D5:** `the_api_client_passes_the_mailbox_kit` in `crates/engine/tests/conformance_fakes.rs`
  runs the mailbox conformance kit against the API client over the fake API's mailbox routes;
  `a_pointer_that_does_not_land_is_posted_again_until_it_does` in
  `crates/engine/tests/owner_actions.rs` has an engine post through its fake HTTP into the shared
  hub; `two_instance_share_accept_end_to_end` in `crates/engine/tests/grants_mailbox.rs` exchanges
  a sealed blob between two simulated devices through the shared hub, over the hub handles.
- **D6:** `ci_keeps_budget_exhaustion_reachable` in `crates/engine/src/storage_policy.rs`;
  `the_ci_environment_is_the_only_one_that_moves_off_production_timings` in
  `apps/desktop/src-tauri/src/engine/config.rs`. That no staging read-modify-write queries the
  host is structural: the policy is a constructor value and `StagingStore` has no headroom
  method. No behaviour test proves it.
- **D7:** `a_generous_headroom_lands_on_the_platform_cap`,
  `the_cache_reservation_comes_off_headroom_before_the_staging_fraction`,
  `a_tiny_headroom_yields_a_tiny_budget_and_never_floors_up`,
  `a_headroom_near_the_integer_ceiling_does_not_wrap` and
  `every_shipped_platform_splits_within_its_headroom` in `crates/engine/src/storage_policy.rs`;
  `the_three_staging_refusals_are_distinguishable` and
  `a_refusal_quotes_the_room_left_never_the_whole_budget` in
  `crates/engine/src/content/budget.rs`; `storageHeadroom.test.ts` "reports quota minus usage when
  the estimate is complete" in `packages/client` (Web area).
  `the_cache_reservation_comes_off_headroom_before_the_staging_fraction` proves the unconditional
  form that lags D7 (E3); after FSM1/cipher-box#831 it proves the state with a read cache. No test
  proves that headroom is unreduced while no read cache exists. That is a finding.
- **D8:** `an_unmeasurable_host_is_distinguishable_from_a_full_one` and
  `a_measured_zero_headroom_yields_no_budget_and_stays_measured` in
  `crates/engine/src/storage_policy.rs`; `an_unmeasurable_host_is_never_reported_as_a_full_one`
  in `crates/engine/src/content/budget.rs`; `only_a_whole_in_range_headroom_reads_as_measured` in
  `crates/wasm/src/host.rs`; `a_path_naming_no_volume_is_unmeasured_rather_than_full` in
  `crates/desktop-seams/src/storage_policy.rs`; `storageHeadroom.test.ts` "stays unmeasured when
  usage is missing rather than assuming an empty origin" and "distinguishes an unmeasurable
  origin from a measured zero".

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
