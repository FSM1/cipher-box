# Testing and verification strategy — v2 blueprint

Resolved by [Blueprint: testing and verification strategy](https://github.com/FSM1/cipher-box-next/issues/47).
Normative for the v2 build. Upstream inputs: the
[component decomposition](https://github.com/FSM1/cipher-box-next/issues/28)
(D6/D7), the
[sync/refresh/offline](https://github.com/FSM1/cipher-box-next/issues/33)
design (the timing profile), the KAT regime in
[`blueprint/core.md`](core.md), the seam contracts and facade law in
[`blueprint/engine.md`](engine.md), the testing hooks in
[`blueprint/web-client.md`](web-client.md) and
[`blueprint/desktop.md`](desktop.md), and the contract-and-clients section of
[`blueprint/api.md`](api.md). This doc fixes the suite map, the CI gates, and
the disposition of every v1 harness; per FSM1/cipher-box-next#28 D7, v2 rebuilds in the cipher-box
repo, so "ports" below means edited in place, in history.

## Doctrine

Verification follows the architecture. v2 concentrates all logic in two Rust
crates below a facade, so the test budget concentrates the same way:
correctness is proven **once**, in Rust, at the layer that owns it; hosts test
only hosting; e2e tests only flows. Three laws, each a v1 inversion:

1. **A suite that asserts the behavior of a change and does not block a merge
   does not exist.** v1's evidence: `apps/web` had a vitest config and no CI
   runner; `.spec.ts` files sat silently outside a `.test.ts` include; web and
   desktop e2e ran only post-merge, discovering regressions after they landed;
   an entire auth Playwright scaffold (`tests/e2e/`) was never even committed.
   Such a suite blocks a merge in the PR gate; where its full run does not
   fit, the PR gate runs a slice and the main gate runs the full set
   revert-first. A measurement harness (the load harness, `Perf Benches`) and a
   run against a deployed or long-horizon environment (the nightly tier,
   `Staging E2E`, `Staging Soak`) block no merge and live in the dispatch and
   scheduled tier;
   their code still compiles in the PR gate. The virtual-time liveness suite
   is a named exception: its PR slice is the republisher unit suite, and its
   full run is nightly (ADR 0050). Every v2 suite is wired into a named gate
   in this doc the day it lands, or it is deleted.
2. **Assert behavior, never source text.** v1 leaned on lexical gates — the
   SC#6/SC#2 source greps over `crates/fuse`, a vector-"parity" script that
   checked files exist and are valid JSON, grep-shaped acceptance criteria
   that forced a runtime-broken implementation past review while only a live
   suite caught it. v2 gates run code: the KAT manifest, simulation
   scenarios, live contract tests. Grep may serve as a hygiene lint; it is
   never the proof of an invariant — invariants live in structure and are
   exercised by tests.
3. **Determinism is injected, not hoped for.** Core takes entropy, time, and
   policy as parameters; the engine takes every capability as a seam trait;
   the sync timing profile is environment-scoped. Together these move race,
   rotation, and offline coverage from flaky wall-clock e2e (v1's only home
   for them) into deterministic in-process tests, and make the e2e that
   remains fast and sleep-free.

What dies relative to v1 — with what killed it:

| Gone                                                                                                       | Killed by                                                                                                                                                                            |
| ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Lockstep TS/Rust vector suites, `tests/vectors/` twin consumers, `check-vector-parity.sh`                  | FSM1/cipher-box-next#27 D2 — one implementation; the KAT manifest defends the frozen contract; the WASM CI run is the residual parity surface                                        |
| `apps/web` unit tests with no CI runner; the `.spec.ts`/`.test.ts` include trap                            | FSM1/cipher-box-next#28 D1 — vault logic leaves the web host; the merge-blocking browser suite moves to `packages/client`, and a thin `apps/web` host suite blocks merges (ADR 0049) |
| Post-merge-only web/desktop e2e (`ci-e2e.yml` on main push)                                                | the PR e2e gate below — a smoke slice blocks every PR, the full matrix blocks main                                                                                                   |
| SC#6/SC#2 grep gates standing in for resolve/rotation invariants                                           | engine structure — one gated resolve path exists at all (FSM1/cipher-box-next#33 D7); simulation scenarios exercise it                                                               |
| `check-api-client.sh`, `api:generate` drift job, generated-client compile checks as "contract enforcement" | FSM1/cipher-box-next#28 D6 — the live contract suite against a real API                                                                                                              |
| Mock-heavy Nest specs green while the runtime threw (the take-pagination class)                            | the contract suite runs the real app + Postgres on every PR                                                                                                                          |
| Serial single-worker e2e whose cascade aborts masked late specs                                            | per-test vault isolation via a fresh login secret → parallel workers (ADR 0049)                                                                                                      |
| The Windows twin operation tree "only CI can compile"                                                      | FSM1/cipher-box-next#32 — the vfs operation core is platform-neutral and tests anywhere; Windows CI checks a thin adapter                                                            |
| `tee-worker` boot + secrets in every e2e recipe; redis/BullMQ for the republish relay                      | FSM1/cipher-box-next#24 — TEE dropped; the republisher is an in-process API module under the contract suite                                                                          |
| Blanket line-coverage merge gates (sdk-core 80% breaking on barrel refactors; api-client's 0% theater)     | the coverage policy below — structural anti-vacuity gates, informational coverage                                                                                                    |

## Suite map

### crates/core — KATs and property tests

The KAT regime itself is fixed in core.md (manifest, accept+reject vectors,
separation KAT, anti-vacuity, committed generators). This doc owns its CI
wiring and adds the property layer:

- **Manifest job, merge-blocking**: `cargo test` runs the full KAT suite
  natively **and** as WASM (the residual parity surface — u64/BigInt,
  getrandom wiring). The manifest completeness check — every structure tag,
  KDF edge, and codec enumerated has vectors; counts hard-asserted — fails
  the job, not a warning. Vectors regenerate only through the committed
  generators; a vector diff without a generator diff fails review by
  convention and the anti-vacuity counts by construction.
- **Property tests** — a new discipline; v1 had zero proptest/fuzzing
  anywhere. proptest over: encode∘decode identity including unknown-field
  byte-stable round-trip, canonicality rejection (mutated encodings must
  reject), the strict name comparator (idempotence, symmetry, platform
  agreement), KDF-edge separation over random inputs, IPNS name codec
  round-trip. Failing seeds are committed as regression vectors. Case counts
  are bounded for CI speed (engineering judgment).

### crates/engine — seam fakes and the simulation harness

Every seam is a trait, so the engine test kit ships in-memory fakes: a
virtual-clock `Scheduler`, an in-memory `RecordTransport` (a fake
`/routing/v1` record store), `FloorStore`, `StagingStore`, a mailbox hub the
fake HTTP serves the API's mailbox routes from (ADR 0044), and seeded entropy.
No network, no docker, no wall clock — CAS races and multi-day EOL timelines
execute in milliseconds.

The **Engine simulation tests** PR gate also runs the engine unit tests,
`encode_refusals`, and `renewal_walk` in release mode. Together they exercise
the shared produce-side gate through root rotation, the name wave, the drain,
renewal, and revival, including floor changes before signing, foreign envelope
versions, and sequence exhaustion.

The **simulation harness** is this strategy's center of gravity: N engine
instances (owner, write-grantee, read-grantee, revokee, adversary) share one
fake record store and mailbox and are stepped deterministically on virtual
time. The scenario matrices are mandatory and mirror the design tables 1:1,
hard-asserted the same way the KAT manifest is (a table row without a
scenario fails the meta-test):

- the six adoption-gate stages — acceptance plus every reject class, each
  surfacing its named trust-violation error;
- the floor law — cold-seed from the re-point object, monotonic advance on
  AAD-confirmed unseals, regression rejection, pointer-driven advance; a
  one-device owner restarts after a vault-root vouch that ran out and a tick,
  and after an unconfirmed root that landed and a tick; a session refuses a
  pre-cut vault root above the cut root's sequence; a pointer below the vouched
  floor is refused; the first-run mint refuses a read-epoch floor above a
  lower vouched floor; a standing pointer that already vouches the epoch raises
  the vouched floor and publishes nothing; a vouch over a pointer below the
  vouched floor or below the published sequence publishes nothing (ADR 0067;
  `crates/engine/tests/mount_convergence.rs` and the `sync::provision` and
  `facade` unit tests);
- all five rebase races from the FSM1/cipher-box-next#33 D5 table (conditional delete,
  rename/rename, add/add auto-suffix, dest-first move, dual-link repair);
- the rotation trigger table and the eager-set law — owner cascade vs
  grantee flat, sweep idempotence, concurrent sweepers, resumed name waves
  via the history link; a write revoke over a nested subtree, a downgrade just
  after a manual read rotation, and a write grant just after a read revoke move
  each lagging node at the root's epoch (ADR 0064); the five ways a revokee
  plants a stop — a record that does not unseal, an epoch that no held link
  reaches, a ref to an id with no record, a record with no served head block,
  and a second ref to one id — each finish the revoke: the first two drop at
  once, the next two past the bound, and the second ref goes with no report.
  The bound holds before T, for each node until its own K passes, and over a
  restart, and an honest node new to a wave past T does not drop on its first
  stop; a new ref to nothing on each pass ends at the entry count, also
  beside a down endpoint and at a record that does not verify, an honest
  node that no endpoint answers waits past the entry count, command re-drives
  inside one pass count once, and a node that resolves starts its count again;
  past T the renewal walk renews an owed scope, and within T it does not
  (ADR 0065, `crates/engine/tests/owner_actions.rs`). The wave retires only a
  name the scope derives, waits for the bound on a wrong head block and on an
  endpoint that does not answer, and re-seals the record its walk gated, so a
  record written at an old name after the walk does not stop it, and the writer
  of that record applies it again under the new seed for a create, a delete
  and a content edit. A rename, a move and a version restore leave at publish,
  so a later writer's change stays. A kept op leaves after the bound of
  ADR 0069 D5, a kept op with no note leaves once the live tree shows it, and a
  second apply that a rebase or a permanent halt refuses leaves with no notice;
  a second apply that loses a tie once lands on a later pass, one under a
  refused parent dead-letters with a notice and keeps a file's bytes across a
  restart, a kept edit under a refused file record dead-letters with a notice
  and frees the queue, a kept create under a refused scope root waits uncharged after a
  restart and leaves at the bound, and one under a moved root the walk cannot
  prove waits past the bound and applies again once the walk proves it (ADR 0069,
  `crates/engine/tests/owner_actions.rs`); the kept op of a downgraded write
  grantee dead-letters on its device with a notice, also a late write that
  the wave did not carry (ADR 0069 D3,
  `crates/engine/tests/mount_convergence.rs`); a body of many
  outranking refs re-walks one time and reads nothing again, and a derived ref
  met after two others is kept, a re-walk keeps the first ref of its own
  walk, and a held node is read once across a re-walk
  (`crates/engine/src/net/rotation.rs`); the root plants — a record the gate
  refuses before the command, a pre-cut replay, a plant at `u64::MAX`, a plant
  at `u64::MAX` that leaves no room for a re-seal, a downgrade over a plant, and
  a plant after the cut set lands — each end the
  cut with a copy, the moved root gives the revokee no row
  and no blob, nothing more publishes at the old root name, a cut from the copy
  keeps no grant row of any recipient while a cut from a gated root keeps the
  other rows, a read revoke over a writer's plant cuts the writer too, a
  re-drive from the copy and a revoke over an owed wave keep no grant row, as
  does a re-drive after another owner device revoked a grantee and a downgrade
  with no owed entry, a re-drive that drops a new share tells the host once, a
  read revoke that stops at an absent root head block leaves nothing owed, a
  link expiry does not replace an owed wave whose cut landed, a read
  cut that stops at the moved root ends in the next re-drive,
  a root whose head block no block source holds ends the revoke in one pass,
  and so does a root below the sequence floor when every endpoint answered,
  while the same head block with a failed record endpoint, a head block the
  gateway times out on, and a cache write fault are unavailable with no
  fallback, a command over honest lag runs on the older copy, a first wave
  that stops leaves a cut the pass keeps within the bound and drops past it, a
  run again keeps the first stop so an unserved interior node drops past the
  bound, a command rerun over a plant after the cut stands ends in one pass, a
  different cut over a cut that never landed reports the replaced work, the
  link sweep cuts an expired link over such a cut, and a sync pass re-drives
  an owed cut, and two owed cuts, while their root plants stand
  (ADR 0068, `crates/engine/tests/owner_actions.rs`); in a sync pass re-drive a
  head block that no source holds, a wrong head block and a record below the
  sequence floor fall back only past the bound, and the first and the last
  never after a failed endpoint; a confirmed root publish is
  the last copy, and the driver runs the wave first after a fallback
  (`crates/engine/src/net/rotation.rs`, `crates/engine/src/rotation/trigger`);
- the keyless re-PUT adversary (FSM1/cipher-box-next#38) — forged old-epoch records at old
  names, re-point adoption, the pin-window bound;
- revocation classification (revocation-signal vs unresolvable vs epoch-lag)
  and the withheld-update escalation;
- the offline queue — FIFO replay through rebase, dead-letter on
  revoked-while-offline with staged bytes preserved, staging-budget
  fail-fast;
- the retire ledger (ADR 0070) — the new build decodes a version 2 entry and
  an unversioned entry (ADR 0020 D5), round-trips a version 3 entry of each
  origin, and reads a damaged name as unwritten (`net::retire`); `owe` refuses
  a name that is not an IPNS name (`tests/encode_refusals.rs`); a dropped
  version and a hard delete in a write-granted folder retire under the file's
  own name (`tests/owner_actions.rs`); a named debt of a deleted node that the
  base links again at that name, in the vault scope or below an interior
  scope, reads its live record and spares what it names, and waits when the
  record does not pass the gate (`sync::drain`);
- the renewal walk (ADR 0061, `crates/engine/tests/renewal_walk.rs`) — on the
  virtual clock, a file that no session opens or publishes for 65 days is at
  S + 1 with a fresh validity after the passes that ADR 0061 consequence 2
  names; a bin entry, a deferred depth-64 folder and a node that lags a cut
  renew; a pass that parks below an ancestor resumes at that ancestor's next
  sibling; a link cycle ends in the pass that meets it; an unavailable scope
  root or child, a 503 registration, a failed ledger read or a failed PUT
  keeps the cursor for the next pass, across sessions, for one day from the
  cycle's first keep-back at most; a scope root or child with no record and
  a 4xx registration or an acknowledged sequence that does not open move
  the cursor at once and emit `renewalFailed`; a 401 after the refresh keeps
  the cursor back; a doomed-name journal that does not list, or a cursor that
  does not read, renews and stores nothing and emits `renewalFailed`; a journal entry that does not read or
  open stops only its own scope root, and `tests/owner_actions.rs` shows that
  another owned scope still renews; unit tests in
  `net::renewal_walk` fix the window edge at exactly one day, a keep-back
  time ahead of the clock, and one window for each cycle; a publish during the
  registration wait makes the walk refuse; at one
  sequence the later EOL wins in the resolve and in the last-known-good
  keeper, and at one EOL the higher signed `data` wins (`net::eol`,
  `net::fanout`, `net::last_known_good`). A same-sequence fork (ADR 0066): a
  resolve at the floor reports a fork when the fan-out serves a second value
  that gates or the cache holds one, paints the served record, and reports
  no fork for a tie of one value, a copy with an unsigned field, or a tie that
  fails the gate; a record at the floor that fails the floor check stays a
  trust violation (`net::resolve`); the boundary walk marks a scope whose root
  is served or cached forked (`net::rotation`) and reports it once
  (`sync::pass`, `tests/owner_actions.rs`); the folder leg and the lagging arm
  report a forked child (`net::focus`, `net::child`); a device that reads a
  fork at the vault root on two ticks, or on a restart against its cached
  root, sends one fork event and no abuse event, and a walk whose second read
  shows another record starts again on either order of the two records
  (`tests/write_plane.rs`); the walk holds a served fork of a file or of the
  vault root back with 45 days left and reports it, renews over it with 25
  days left, and renews over a tie of one value, and the renewal set renews
  over a fork inside 30 days (`tests/renewal_walk.rs`, `net::liveness`).
  A child or a vault root at a foreign envelope version is not renewed by the
  walk or the renewal set, and the walk emits `renewalFailed` with a version
  detail; a scope floor raised during the registration makes the walk refuse
  (`tests/renewal_walk.rs`); the renewal set refuses a held node at a foreign
  version or below its scope bar (`net::liveness`).
  A lagging endpoint (ADR 0071): with two endpoints, where one lags one
  sequence and the other fails or answers 429, a revoke gets
  `EngineError::Seam`, a read
  sends no abuse event and moves no cache or floor, and a queued create stays
  queued and lands after the failed endpoint recovers; when the other
  endpoint serves the old record or answers 403, each stays a trust violation;
  the revoke finishes after the failed endpoint recovers
  (`tests/owner_actions.rs`); the root admit, the sweep read, the grantee root
  read, and the write cut's root, boundary, interior and `gated_root_at` reads
  give the same split, and a forged record stays a rejection
  (`net::rotation`); the vault pointer's standing read does too
  (`net::vault_pointer`); the bin index load reports `suppressed`, not
  `rolled-back` (`tests/bin_index.rs`
  `a_lagging_endpoint_while_another_fails_is_withheld_not_rolled_back`), the
  share inbox keeps the item unreported (`grants::inbox`
  `a_below_floor_record_while_an_endpoint_fails_is_kept_unreported`), the
  received-share status reports nothing (`grants::received_status`
  `a_record_below_the_sequence_floor_while_an_endpoint_fails_is_unreported`),
  and the link preview is unresolvable (`tests/owner_actions.rs`
  `a_preview_of_a_lagging_root_while_an_endpoint_fails_is_unresolvable`); a
  pre-cut set below both floors stays a trust violation while an endpoint
  fails (`grants::received_status`
  `a_pre_cut_set_below_the_sequence_floor_while_an_endpoint_fails_is_reported`),
  and a rollback of a joined root to a set from before the link is a trust
  violation, not a revoked link (`tests/owner_actions.rs`
  `a_rollback_to_a_root_from_before_the_link_is_no_revoked_link`); only no
  answer, a 5xx, a 408, a 429, a 3xx or a timeout is a failed endpoint, and a
  failed body cancellation keeps the known answer (`net::fanout`, the desktop
  record transport, the web `recordTransport`). The fix tests fail on the code
  before ADR 0071.
  The withheld-update escalation bounds that hold on a shared scope: a
  received share held withheld past the escalation window, while the vault
  root resolves, sends one escalation and no trust event, and a full outage
  sends none and does not count toward the window (`tests/owner_actions.rs`
  `a_shared_scope_withheld_past_the_window_sends_one_escalation`,
  `a_shared_scope_withheld_in_a_full_outage_sends_no_escalation`); a folder
  inside a shared scope that the focus leg reads as withheld does the same,
  a read of it that no endpoint answers sends none, and a read that reaches
  its record ends the hold (`tests/owner_actions.rs`
  `a_withheld_shared_child_sends_one_escalation_after_the_window`,
  `a_shared_child_no_endpoint_answers_sends_no_escalation`,
  `a_reached_shared_child_ends_the_hold`); a held bookmark's scope pointer
  that no endpoint answers past the window, while the vault root reconciles,
  sends one escalation, with the vault root down it sends none until one
  window after the root recovers, a pointer that every endpoint answers as
  absent sends none, and an answer ends the hold (`grants::received_status`
  `a_pointer_no_endpoint_answers_escalates_once_past_the_window`,
  `a_pointer_unanswered_in_a_full_outage_escalates_one_window_after_recovery`,
  `an_absent_pointer_never_escalates`, `a_pointer_answer_ends_the_hold`); a
  pass that reaches no record keeps the hold, and an owned scope never
  escalates (`grants::received_status`, `sync::staleness`).
  An owed interior move (ADR 0072): after a stop at the reseal, a partial
  reseal, or a stop at the parent index publish, the navigation leg and then
  the tick focus leg each adopt a changed interior folder with no abuse event;
  a restart over a move still owed gives no abuse event at either leg; a
  record whose epoch tag names a bound scope that does not open it, and a
  record whose tag names a third scope, each give exactly one trust violation
  (`tests/owner_actions.rs`); an unread owed record leaves the legs on the
  proved and minted scope roots, and a leg whose root holds no seed reads a
  record of the left scope and waits on a record of the root (`sync::pass`,
  `net::focus`).
  `tests/owner_actions.rs` covers a nested owned scope and a node a stopped
  wave left at its old name, which nothing renews; `tests/write_plane.rs`
  covers a renewal inside the drain's window, and a lost race on a scope root
  or an interior folder healed after a restart or a re-read.

Adversarial cases are first-class: the harness can replay, transplant, and
re-sign records with any key it holds; every crypto-review finding (FSM1/cipher-box-next#35)
gets a pinned regression scenario.

The engine also ships **its own KAT vectors**, under core's regime but for the
formats and predicates core cannot reach: the content-DAG root, the
retire-ledger entry, and the rotation and check-surface reject families. The stage-3 **one section, one
signer** vectors are core's, in the KAT `grant` family (ADR 0052 D4). The
engine vectors are written only by
`cargo run -p cipherbox-engine --example kat_gen`, and the **Engine simulation
tests** gate regenerates all of `crates/engine/kat` and diffs it before running
the suites, so a verdict change that is not a deliberate re-freeze fails there
(ADR 0049).

### The contract suite — the live API gate

The sdk-e2e descendant (FSM1/cipher-box-next#28 D6), and it inherits sdk-e2e's most valuable v1
property: it runs on **every PR**. A Rust integration-test crate constructs
real engines with production seam implementations pointed at the CI stack
(real NestJS app + Postgres + Kubo + the `/routing/v1` store), drives facade
commands, and asserts API-side effects. Contract drift between server
behavior and the hand-written client fails a test run, not a grep.

Coverage, mirroring api.md surface for surface: challenge-signature login,
refresh rotation, SIWE secondary; test-login environment gating asserted
(production mode must refuse); **register-first fail-closed** — publishing
an unregistered name is refused; batch register/retire idempotency, the batch
bounds and the record-scoped retire (ADR 0046); union liveness and refcounted
physical unpin; quota (hosted authoritative, BYO `advisory: true`); hosted
upload (ADR 0038) — including that the pinned address **equals** the
caller-computed one under both content-plane codecs, and that a declared
address the bytes do not hash to is refused and compensated;
the mailbox lifecycle (post/poll/ack, the ack's "removed" answer,
idempotency keys, unknown-recipient rejection);
the recovery endpoint (auth + rate limit); account hard-delete cascade;
the identity subject bind at the first login that presents a token, no rebind
on a conflict, and both registration refusals (ADR 0058);
the email link to the subject of the account, and its refusals (ADR 0039 D1);
the republisher module's inventory walk and resolve-failure alerting; and
**throttling asserted effective** — expect real 429s (v1's inert `@Throttle`
decorators are a named defect, api.md). The API's committed OpenAPI artifact
gets a freshness check (regenerate-and-diff) as documentation hygiene — it
is not the contract gate.

### Host suites

- **`packages/client` — the merge-blocking browser suite.** The structural
  answer to v1's least-verified-layer trap (web-client.md): leadership
  election and the single-writer invariant, leader failover with rehydration
  from durable seams (kill the leader, assert no accepted-op loss), both
  facade transports, and the Service Worker brokerage — in a real browser
  against real IndexedDB, OPFS, Web Locks, and BroadcastChannel, driven by
  Playwright. This suite blocks every PR.
- **`packages/client` — the Node suite.** The IPNS record KATs run through
  the record read outside a session (ADR 0057), in a WASM module built with
  the `observer` feature, under Node. It is the step `Client Node suite` in the job `Client Browser Suite`,
  reported through `Web Result`.
- **`packages/client` — the production module suite.** The module that
  `apps/web` `build:wasm` makes has no `readIpnsRecord` export, and
  `openIpnsRecordReader` refuses it (ADR 0057 D1). It is the step
  `Production engine module carries no record read` in the job `Web Bundle`,
  reported through `Web Result`. The staging deploy runs the same suite on the
  module that it builds, as the step
  `Engine WASM artifact carries no record read` in the job `build-web`.
- **Seam conformance kits.** The engine ships a reusable conformance suite
  per seam trait — FloorStore monotonicity and durability semantics,
  StagingStore ordering and orphan GC, SnapshotCache ciphertext-only-at-rest
  — that every real implementation must pass: browser implementations inside
  the browser suite, desktop implementations in cargo tests. One contract,
  every platform; the v1 per-platform store-drift class has no home.
- **`crates/fuse` operation core (`FUSE Op Core`).** vfs operations driven
  directly against a real engine on fake seams — no kernel, runs on any CI
  runner. Covers the never-block law (no operation may await network), name
  validation and platform-junk filtering, inode stability across renames, the
  ranged read path and its bounded plaintext chunk cache, and the
  errno/status mapping per adapter. The vendored fuser MSG_PEEK patch gets
  the regression test desktop.md commits to, and the same job asserts that no
  default `Filesystem` body writes a name to a log record (ADR 0040). Windows
  CI compiles and tests the thin WinFsp adapter and remains authoritative for
  it — but the operation core no longer lives there.
- **`apps/api` unit.** Nest specs where server logic actually lives (quota
  arithmetic, refcounting, retention caps, auth services) — the v1 jest
  setup ports. The contract suite, not spec mocks, is the correctness gate.
- **`apps/api` integration.** The `*.itest.ts` files over HTTP on a real
  Postgres, in the job `Integration tests (real Postgres)`, reported through
  `API Result`. The login bind and the registration rule (ADR 0058) are among them.
  `apps/api/src/auth/method-link.http.itest.ts` proves that a linked method opens
  the account it links to (ADR 0039 D1).
- **`apps/web` and `apps/desktop` shells.** Vault correctness is not tested
  here — it lives below the facade. What the web shell does own is the seam
  the facade does not: the `useSyncExternalStore` snapshot adapter, the
  failover re-export of the login secret, and UI-owned chrome state. Those
  get a thin unit suite, merge-blocking in the Web area as the job
  `Web host typecheck + tests`, reported through `Web Result`; rendering and
  flows stay Playwright's and the mounted e2e's (ADR 0049). The export,
  transfer and zeroization of the login secret live in `packages/login`, and
  its suite blocks merges in the same Web area
  (`Shared packages typecheck + tests`).

### E2E — flows over real stacks

- **Web Playwright** ports the v1 skeleton from `tests/web-e2e/`: the
  page-object model, fixtures, the wallet-mock SIWE login, and multi-account
  helpers — rewired to v2. The facade introspection hook (snapshot and
  event-stream taps, no key access) replaces v1's window-store poking as the
  e2e seam; deterministic waits poll it — never sleep. Tests run against the
  production build served statically (v1 tested the Vite dev server; the
  artifact that ships was never the artifact tested). Per-test vault isolation makes workers
  parallel; `retries: 0` ports as policy — a flaky test is a defect.
  The hook rides a dedicated build flag rather than `DEV`, precisely because
  the artifact under test is a production build; the suite builds that bundle
  a second time without the flag and asserts the shipping one exposes no hook.
  A `staging` or `production` build that sets `VITE_E2E_HOOK` fails at build
  time.
  Web isolation needs no test-login: challenge-signature login creates the
  account implicitly, so a fresh login secret per test is a fresh vault
  (ADR 0049). The page mints the login secret itself, so the secret never
  appears as an `evaluate` argument in an uploaded trace.
  The device-approval approver signs in with the token of a wallet exchange,
  so its login binds the account and its registration passes (ADR 0058 D3).
  The account-switch spec signs two owner accounts in on one browser profile.
  It checks through the UI and the origin's storage that a switch keeps the
  other account's staging and floors databases and its staged records, and
  that a forget erases only its own account.
- **Desktop mounted e2e** keeps the v1 shape that worked: dev-key headless
  entry, real mounts per platform (FUSE-T SMB, libfuse3, WinFsp), the
  orchestrator scripts and wait-for-mount pattern — scenarios rewritten onto
  the new facade: mount round-trip, conflict outcomes, cross-client sync,
  and the new offline-replay and rotation-under-mount flows (desktop.md).
- **Staging e2e** — the v1 usage profiles (`tests/web-e2e/staging`) against
  the deployed front, reached only when `E2E_BASE_URL` is set. It signs in
  through a shipped method, because a deployed bundle refuses the
  introspection hook, and it waits on what the chrome renders. It gates no
  merge: its verdict is on a deploy (ADR 0049).
- **Cross-client e2e** — the marquee v2 addition: web and desktop hosts (or
  two instances of one host) on a single vault, exercising share
  grant/accept, an invite-link join converted by an owner device other than
  the one that minted the link, the revocation immediate cut, write rotation
  with surviving grantees, offline/reconnect convergence, and leader failover
  mid-flow (web-client.md). Runnable at all only because of the DX hook below.

## CI gates

Path-filtered like v1 (the dorny pattern and reusable-workflow structure
port), reorganized into three tiers (ADR 0050):

| Tier                         | Trigger        | Contents                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ---------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **PR gate** — merge-blocking | every PR       | five areas, each one reusable workflow reported through a single stable result context — **Repo** (lint, the tracker-reference scan `Tracker Refs`); **API** (typecheck, the unit suite, the real-Postgres integration suite, DB migration drift, OpenAPI freshness); **Rust** (fmt + clippy, `Core KATs (native + WASM)`, the engine simulation, the fuse operation core `FUSE Op Core`, the workspace tests, and one adapter leg per shipped desktop platform — macOS and Windows each run a workspace check over all targets, the tests of the OS adapter crates, and the keyring conformance suite against the real OS backend, and neither runs the engine simulation, which is platform-neutral); **Web** (the shared packages, the `apps/web` host suite, the engine WASM artifact, the bundle, the `packages/client` browser suite); **Desktop** (the shell frontend suites and the unsigned shell build on all three platforms). Beside the areas stand the contract suite on the CI stack (`Contract Suite Result`) and an e2e **smoke slice** (`Web E2E Smoke`, reported through the stable `Web E2E Smoke Result` context) — a bounded-minutes budget of web login-and-CRUD plus one timing-profile cross-client scenario. Branch protection requires the area result contexts and these standalone contexts, never a job inside an area (ADR 0018)                                                                                                                                                                                                                                                     |
| **Main gate**                | push to main   | the full web-e2e suite, the desktop mounted matrix (macOS/Linux/Windows), the full cross-client matrix, and the updater-key drift check (`Updater Key`), which compares the committed updater pubkey against the release signing secret and therefore stays out of the pull-request path. The PR gate forwards no signing secret to any area, and a dispatch of `Updater Key` is guarded to `main`. Failure is treated revert-first, not fix-forward — this tier exists to bound the blast radius of what the smoke slice missed, never to be the first line                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| **Dispatch / scheduled**     | manual or cron | the load harness (`crates/load`, v1's `tests/load/` scenarios ported onto the v2 surface — it drives the engine's real API client, so it is Rust beside the contract suite rather than a TS package, ADR 0049; its target resolution is an allowlist: `local` reaches a loopback host only, `staging` reaches only an https URL from the approval-gated `staging` environment, and no production target exists); the nightly tier (`nightly.yml`) — long-horizon liveness (lease renewal at seq+1 and the republisher walk against a compressed-EOL profile) full-matrix flake surveillance (`ci-e2e.yml` re-run on `main` HEAD with the change filter forced open), and the Cloudflare Range Watch (ADR 0035 D9), each reporting a failure into one tracking issue; the **`Staging Soak`** (`staging-soak.yml`, ADR 0053), a nightly run from the newest `staging-*` tag against the deployed staging front as the two durable soak accounts, with three desktop legs, reporting a failure into its own tracking issue; staging release gates (mechanics → [FSM1/cipher-box-next#48](https://github.com/FSM1/cipher-box-next/issues/48)) — the **`Staging E2E`** job (`staging-e2e.yml`) drives the usage profiles through a real browser against the deployed front, dispatchable with a base URL and called by `tag-staging.yml` after the deploy job, so a red run is the verdict on that deploy; the per-stage profiling benches (`Perf Benches`, criterion over `crates/core` and `crates/engine` on the in-memory seam fakes and the virtual clock — shared-runner timings are too noisy to gate a merge on) |

The cargo test profile builds its dependencies optimized: the workspace
`Cargo.toml` sets `[profile.dev.package."*"] opt-level = 3`, and the workspace
crates stay at opt-level 0 and debuggable. The bound tests do one signature,
key derivation, or seal per item up to a ceiling, so the dependency graph, not
the code under test, sets their run time. Every cargo cache key hashes
`Cargo.toml` next to `Cargo.lock`, so a profile change invalidates the caches.
A run on `main` is the only writer of those caches; a pull-request run
restores one and never saves, because a cache a pull request writes is scoped
to that pull request alone and no other run can read it.

The CI stack: Postgres, Kubo, the API under test, and a local `/routing/v1`
record store — v1's `mock-ipns-routing` tool **promoted, not deleted**: a
dumb delegated-routing server is exactly the RecordTransport seam's shape,
so the hermetic CI store and production someguy are interchangeable behind
the same client code. someguy itself runs in staging, not CI (the real DHT
has no place in a hermetic gate). The v1 redis/tee-worker services leave the
stack; the local/CI redis port split (6380/6379) dies with them.

### Durable owner seed cache

The **Core KATs (native + WASM)** gate runs the owner seed record codec tests,
`owner_seed_cache_accept` and `owner_seed_cache_reject`, and the release
`encode_refusals` tests. They cover both parent-seed shapes, corrupt fields,
and encode/decode size symmetry (ADR 0073).

The **Engine simulation tests** PR gate runs the production `RootAdopter` and
rotation unit tests. They cover confirmed-read persistence, refusal without
refresh, interleaved reads, best-effort writes, corrupt entry replacement, and
recovery after a restart with no snapshot or gateway copy. The recovery test
retains the network trust violation and opens the confirmed body. The owner
command test moves the root, leaves the old name unchanged, and removes every
grant row, also at the sequence ceiling. It asserts the abuse event for a signed
owner blob with a different seed. The scope-walk test covers a refused
descendant with a healthy root. Cache tests cover name replacement,
equal-sequence forks, scope deletion, account isolation, and upload budget
exclusion. A keyless root at one name replaces the entry, so a later broken
owner blob still recovers after a restart. A keyless read at a moved name
replaces the entry at the old name. A local store fault keeps the trust verdict
of the network record, and a fault in one fallback source leaves the other
source. A store fault on the entry does not stop a scope delete, and the delete
removes the entry before its completing publish.

## The DX hook — the environment-scoped timing profile

The sync timing profile (FSM1/cipher-box-next#33 D3) is the single lever that makes v2's
cross-client flows testable at speed, and this doc is its consumer contract:

- **CI profile**: record TTL 1–5 s (small but nonzero — `0`/unset is how v1
  fell into a silent 5-minute default), compressed poll cadence, staleness
  thresholds, escalation window and pointer-consult interval. Production
  profile: TTL 1 minute, 30 s poll, per FSM1/cipher-box-next#33. The small
  staging budget that makes budget-exhaustion paths reachable is not a
  profile member: it is the CI storage policy (`StoragePolicy::CI`), which
  the engine tests and the desktop shell pin in CI and the web host does not
  (ADR 0044).
- **Nocache manual refresh** is the TTL-independent forcing path — the
  deterministic sync barrier between clients in every cross-client scenario.
- **No sleeps anywhere**: web polls the introspection hook, desktop polls
  the filesystem and tray state, both bounded by profile-derived timeouts.
- **The profile is where measured constants land.** The open-edge numbers
  the sibling docs handed here — the migration-window closure constant, the
  sweep cadence, kernel entry/attr TTLs per backend, chunk size and DAG
  shape — get their values from measurements this harness produces (the
  cross-client latency measurement job, the FUSE-T invalidation round-trip,
  ranged-fetch profiles). Each lands as a profile-constant change with its
  measurement linked. The process is fixed here; the values are build-time
  work.

## Hardware verification gates

The FSM1/cipher-box-next#32 pre-build checks, owned here as task-shaped verifications with
recorded results — they precede `crates/fuse` work, and they are not CI:

1. FUSE-T ≥ 1.2.7 SMB invalidation round-trip, with measured cross-client
   latency — feeds the kernel TTL constants above.
2. Replay of the v1 macOS cross-client flake scenario against the SMB
   backend.
3. Overwrite-rename atomicity under the SMB backend.
4. FUSE-T commercial license terms for bundling.
5. The FSKit spike against the macOS 27 beta
   (`mountSingleVolume`/`DataCacheHandler` behavior).

Results are recorded alongside the profile constants they feed; a failed
gate reopens the driver decision (FSM1/cipher-box-next#32), not this doc.

The #644 execution of these gates — harness, measurements, and per-gate
verdicts — is recorded in `tools/hw-gates/RESULTS.md`. Gates 1, 2, 3 and 5
passed, and gate 4 is CONDITIONAL: bundling FUSE-T needs a negotiated
commercial licence, and a member-installed FUSE-T is the free interim path
(ADR 0051). Gate 5 ran on macOS 27 beta hardware and confirmed FSKit's
`DataCacheHandler`/`setCacheStateForItem` push-invalidation
(`tools/hw-gates/fskit-spike/RESULTS.md`).

## Coverage policy

No blanket line-coverage thresholds as merge gates. v1's record: the
sdk-core 80% gate broke on barrel-file refactors while real gaps hid
elsewhere; api-client ran a 0% threshold with `passWithNoTests` — pure
theater. Codecov stays as informational reporting. The merge gates are
structural instead: KAT-manifest completeness, the simulation harness's
table-mirroring anti-vacuity assertions, seam conformance kits, and the
named CI jobs above — each asserts _presence of specific coverage_, which a
percentage never did.

## Disposition of the v1 inventory

| v1 artifact                                                                                             | Disposition                                                                                                                                                                               |
| ------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tests/web-e2e/` (Playwright skeleton, wallet-mock, page objects)                                       | **Ports** — rewired to the facade introspection hook and built-artifact serving; the test-login helpers do not port, because a fresh login secret per test isolates each vault (ADR 0049) |
| `POST /auth/test-login` (prod hard-block, `TEST_LOGIN_SECRET` timing-safe check, deterministic keypair) | **Ports** — same gating pattern; v2 derivation feeds `start(secret)`                                                                                                                      |
| `tests/sdk-e2e/`                                                                                        | **Succeeded** by the contract suite — keeps its PR-blocking slot and stack recipe                                                                                                         |
| `tests/desktop-e2e/` (run-all orchestrators, wait-for-mount, dev-key mode, `.mts`/tsx invocation)       | **Ports** — scenarios rewritten onto the facade                                                                                                                                           |
| `docker/docker-compose.yml` postgres/kubo services; GH service-container pattern                        | **Ports**                                                                                                                                                                                 |
| `tools/mock-ipns-routing`                                                                               | **Promoted** — the hermetic `/routing/v1` CI record store                                                                                                                                 |
| someguy service                                                                                         | staging/production accelerator only — leaves CI                                                                                                                                           |
| redis, tee-worker services and their secret plumbing                                                    | **Die** (FSM1/cipher-box-next#24)                                                                                                                                                         |
| `ci.yml` job skeleton, dorny path filters, reusable workflows, failure-artifact uploads                 | **Port** — refiltered for the v2 layout                                                                                                                                                   |
| Migration drift check                                                                                   | **Ports** if the API keeps TypeORM migrations                                                                                                                                             |
| `tests/load/` harness                                                                                   | **Ported** — `crates/load`, dispatch-gated                                                                                                                                                |
| `tests/vectors/` cross-language corpus + generators                                                     | **Dies** — vectors regenerate under the KAT-manifest regime (the formats they lock are gone anyway)                                                                                       |
| `check-vector-parity.sh`, `check-api-client.sh`, `api:generate` loop, SC#6/SC#2 grep gates              | **Die** — replaced by live gates per the doctrine                                                                                                                                         |
| `tests/e2e/` (uncommitted Web3Auth storage-state scaffold) + its planning dir                           | **Delete** — superseded twice over                                                                                                                                                        |
| `codecov.yml` targets, per-package vitest thresholds                                                    | **Demoted** to informational                                                                                                                                                              |

## Open edges

- **Smoke-slice composition** — which specs fill the PR e2e minutes budget;
  engineering judgment at build time, revisited as the suite grows.
- **Measured constants** — kernel TTLs, migration window, sweep cadence,
  chunk size/DAG shape: process fixed above, values land during build.
- **Web3Auth Core Kit interactive login** — wallet-mock covers SIWE in CI, and
  `Staging E2E` drives that same SIWE path with an injected test wallet against
  the deployed front. MFA enrollment and the Google and email-code methods stay
  uncovered by every automated suite: they need an interactive staging run, never
  a PR gate — an honest, inherited limitation (ADR 0049).
  **Device approval is not covered by that exemption** ([ADR 0009](../decisions/0009-device-approval-is-a-bound-rendezvous.md)): it is a
  rendezvous over our own API, and it needs a harness driving two sessions. v1
  skipped every cross-device case for want of a second device, which is how a
  desktop path that could never succeed reached a verified status.
- **Runner provisioning, staging deploy gates, release-tag e2e gating,
  nightly scheduling** →
  [deployment blueprint (FSM1/cipher-box-next#48)](https://github.com/FSM1/cipher-box-next/issues/48).
