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
the disposition of every v1 harness; per #28 D7, v2 rebuilds in the cipher-box
repo, so "ports" below means edited in place, in history.

## Doctrine

Verification follows the architecture. v2 concentrates all logic in two Rust
crates below a facade, so the test budget concentrates the same way:
correctness is proven **once**, in Rust, at the layer that owns it; hosts test
only hosting; e2e tests only flows. Three laws, each a v1 inversion:

1. **A suite that does not block a merge does not exist.** v1's evidence:
   `apps/web` had a vitest config and no CI runner; `.spec.ts` files sat
   silently outside a `.test.ts` include; web and desktop e2e ran only
   post-merge, discovering regressions after they landed; an entire auth
   Playwright scaffold (`tests/e2e/`) was never even committed. Every v2 suite
   is wired into a named gate in this doc the day it lands, or it is deleted.
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

| Gone                                                                                                       | Killed by                                                                                                                 |
| ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Lockstep TS/Rust vector suites, `tests/vectors/` twin consumers, `check-vector-parity.sh`                  | #27 D2 — one implementation; the KAT manifest defends the frozen contract; the WASM CI run is the residual parity surface |
| `apps/web` unit tests with no CI runner; the `.spec.ts`/`.test.ts` include trap                            | #28 D1 — web keeps no logic worth unit-testing; the merge-blocking browser suite moves to `packages/client`               |
| Post-merge-only web/desktop e2e (`ci-e2e.yml` on main push)                                                | the PR e2e gate below — a smoke slice blocks every PR, the full matrix blocks main                                        |
| SC#6/SC#2 grep gates standing in for resolve/rotation invariants                                           | engine structure — one gated resolve path exists at all (#33 D7); simulation scenarios exercise it                        |
| `check-api-client.sh`, `api:generate` drift job, generated-client compile checks as "contract enforcement" | #28 D6 — the live contract suite against a real API                                                                       |
| Mock-heavy Nest specs green while the runtime threw (the take-pagination class)                            | the contract suite runs the real app + Postgres on every PR                                                               |
| Serial single-worker e2e whose cascade aborts masked late specs                                            | per-test vault isolation via test-login → parallel workers                                                                |
| The Windows twin operation tree "only CI can compile"                                                      | #32 — the vfs operation core is platform-neutral and tests anywhere; Windows CI checks a thin adapter                     |
| `tee-worker` boot + secrets in every e2e recipe; redis/BullMQ for the republish relay                      | #24 — TEE dropped; the republisher is an in-process API module under the contract suite                                   |
| Blanket line-coverage merge gates (sdk-core 80% breaking on barrel refactors; api-client's 0% theater)     | the coverage policy below — structural anti-vacuity gates, informational coverage                                         |

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
`/routing/v1` record store), `FloorStore`, `StagingStore`, `Mailbox`, and
seeded entropy. No network, no docker, no wall clock — CAS races and
multi-day EOL timelines execute in milliseconds.

The **simulation harness** is this strategy's center of gravity: N engine
instances (owner, write-grantee, read-grantee, revokee, adversary) share one
fake record store and mailbox and are stepped deterministically on virtual
time. The scenario matrices are mandatory and mirror the design tables 1:1,
hard-asserted the same way the KAT manifest is (a table row without a
scenario fails the meta-test):

- the six adoption-gate stages — acceptance plus every reject class, each
  surfacing its named trust-violation error;
- the floor law — cold-seed from the re-point object, monotonic advance on
  AAD-confirmed unseals, regression rejection, pointer-driven advance;
- all five rebase races from the #33 D5 table (conditional delete,
  rename/rename, add/add auto-suffix, dest-first move, dual-link repair);
- the rotation trigger table and the eager-set law — owner cascade vs
  grantee flat, sweep idempotence, concurrent sweepers, resumed name waves
  via the history link;
- the keyless re-PUT adversary (#38) — forged old-epoch records at old
  names, re-point adoption, the pin-window bound;
- revocation classification (revocation-signal vs unresolvable vs epoch-lag)
  and the withheld-update escalation;
- the offline queue — FIFO replay through rebase, dead-letter on
  revoked-while-offline with staged bytes preserved, staging-budget
  fail-fast.

Adversarial cases are first-class: the harness can replay, transplant, and
re-sign records with any key it holds; every crypto-review finding (#35)
gets a pinned regression scenario.

### The contract suite — the live API gate

The sdk-e2e descendant (#28 D6), and it inherits sdk-e2e's most valuable v1
property: it runs on **every PR**. A Rust integration-test crate constructs
real engines with production seam implementations pointed at the CI stack
(real NestJS app + Postgres + Kubo + the `/routing/v1` store), drives facade
commands, and asserts API-side effects. Contract drift between server
behavior and the hand-written client fails a test run, not a grep.

Coverage, mirroring api.md surface for surface: challenge-signature login,
refresh rotation, SIWE secondary; test-login environment gating asserted
(production mode must refuse); **register-first fail-closed** — publishing
an unregistered name is refused; batch register/retire idempotency; union
liveness and refcounted physical unpin; quota (hosted authoritative, BYO
`advisory: true`); hosted upload; the mailbox lifecycle (post/poll/ack,
idempotency keys, pending-cap reject-new, unknown-recipient rejection);
the recovery endpoint (auth + rate limit); account hard-delete cascade;
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
- **Seam conformance kits.** The engine ships a reusable conformance suite
  per seam trait — FloorStore monotonicity and durability semantics,
  StagingStore ordering and orphan GC, SnapshotCache ciphertext-only-at-rest
  — that every real implementation must pass: browser implementations inside
  the browser suite, desktop implementations in cargo tests. One contract,
  every platform; the v1 per-platform store-drift class has no home.
- **`crates/fuse` operation core.** vfs operations driven directly against a
  real engine on fake seams — no kernel, runs on any CI runner. Covers the
  never-block law (no operation may await network), name validation and
  platform-junk filtering, inode stability across renames, and the
  errno/status mapping per adapter. The vendored fuser MSG_PEEK patch gets
  the regression test desktop.md commits to. Windows CI compiles and tests
  the thin WinFsp adapter and remains authoritative for it — but the
  operation core no longer lives there.
- **`apps/api` unit.** Nest specs where server logic actually lives (quota
  arithmetic, refcounting, retention caps, auth services) — the v1 jest
  setup ports. The contract suite, not spec mocks, is the correctness gate.
- **`apps/web` and `apps/desktop` shells.** Vault correctness is not tested
  here — it lives below the facade. What the web shell does own is the seam
  the facade does not: the `useSyncExternalStore` snapshot adapter, the
  login-secret handoff and its transfer/zeroization boundary, and UI-owned
  chrome state. Those get a thin merge-blocking unit suite, `Web Unit`;
  rendering and flows stay Playwright's and the mounted e2e's.

### E2E — flows over real stacks

- **Web Playwright** ports the v1 skeleton from `tests/web-e2e/`: the
  page-object model, fixtures, the wallet-mock SIWE login, multi-account
  helpers, and test-login API helpers — rewired to v2. The DEV-gated facade
  introspection hook (snapshot and event-stream taps, no key access)
  replaces v1's window-store poking as the e2e seam; deterministic waits
  poll it — never sleep. Tests run against the production build served
  statically (v1 tested the Vite dev server; the artifact that ships was
  never the artifact tested). Per-test vault isolation via test-login makes
  workers parallel; `retries: 0` ports as policy — a flaky test is a defect.
- **Desktop mounted e2e** keeps the v1 shape that worked: dev-key headless
  entry, real mounts per platform (FUSE-T SMB, libfuse3, WinFsp), the
  orchestrator scripts and wait-for-mount pattern — scenarios rewritten onto
  the new facade: mount round-trip, conflict outcomes, cross-client sync,
  and the new offline-replay and rotation-under-mount flows (desktop.md).
- **Cross-client e2e** — the marquee v2 addition: web and desktop hosts (or
  two instances of one host) on a single vault, exercising share
  grant/accept, the revocation immediate cut, write rotation with surviving
  grantees, offline/reconnect convergence, and leader failover mid-flow
  (web-client.md). Runnable at all only because of the DX hook below.

## CI gates

Path-filtered like v1 (the dorny pattern and reusable-workflow structure
port), reorganized into three tiers:

| Tier                         | Trigger        | Contents                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ---------------------------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **PR gate** — merge-blocking | every PR       | lint + typecheck; cargo workspace tests (core KATs + property layer, engine simulation, fuse op core); the WASM KAT run; the `packages/client` browser suite; the contract suite on the CI stack; Windows cargo check + adapter tests; DB migration drift check (ports as-is if the API keeps TypeORM); an e2e **smoke slice** — a bounded-minutes budget of web login-and-CRUD plus one timing-profile cross-client scenario |
| **Main gate**                | push to main   | the full web-e2e suite, the desktop mounted matrix (macOS/Linux/Windows), the full cross-client matrix. Failure is treated revert-first, not fix-forward — this tier exists to bound the blast radius of what the smoke slice missed, never to be the first line                                                                                                                                                              |
| **Dispatch / scheduled**     | manual or cron | the load harness (v1's k6 scenarios in `tests/load/` port); long-horizon liveness — lease renewal at seq+1 and the republisher walk against a compressed-EOL profile; staging release gates (mechanics → [#48](https://github.com/FSM1/cipher-box-next/issues/48))                                                                                                                                                            |

The CI stack: Postgres, Kubo, the API under test, and a local `/routing/v1`
record store — v1's `mock-ipns-routing` tool **promoted, not deleted**: a
dumb delegated-routing server is exactly the RecordTransport seam's shape,
so the hermetic CI store and production someguy are interchangeable behind
the same client code. someguy itself runs in staging, not CI (the real DHT
has no place in a hermetic gate). The v1 redis/tee-worker services leave the
stack; the local/CI redis port split (6380/6379) dies with them.

## The DX hook — the environment-scoped timing profile

The sync timing profile (#33 D3) is the single lever that makes v2's
cross-client flows testable at speed, and this doc is its consumer contract:

- **CI profile**: record TTL 1–5 s (small but nonzero — `0`/unset is how v1
  fell into a silent 5-minute default), compressed poll cadence, staleness
  thresholds, escalation window, pointer-consult interval, and a small
  staging budget so budget-exhaustion paths are reachable. Production
  profile: TTL 1 minute, 30 s poll, per #33.
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

The #32 pre-build checks, owned here as task-shaped verifications with
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
gate reopens the driver decision (#32), not this doc.

The #644 execution of these gates — harness, measurements, and per-gate
verdicts — is recorded in `tools/hw-gates/RESULTS.md`. All five passed:
gate 5 ran on macOS 27 beta hardware and confirmed FSKit's
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

| v1 artifact                                                                                             | Disposition                                                                                         |
| ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `tests/web-e2e/` (Playwright skeleton, wallet-mock, page objects, test-login helpers)                   | **Ports** — rewired to the facade introspection hook and built-artifact serving                     |
| `POST /auth/test-login` (prod hard-block, `TEST_LOGIN_SECRET` timing-safe check, deterministic keypair) | **Ports** — same gating pattern; v2 derivation feeds `start(secret)`                                |
| `tests/sdk-e2e/`                                                                                        | **Succeeded** by the contract suite — keeps its PR-blocking slot and stack recipe                   |
| `tests/desktop-e2e/` (run-all orchestrators, wait-for-mount, dev-key mode, `.mts`/tsx invocation)       | **Ports** — scenarios rewritten onto the facade                                                     |
| `docker/docker-compose.yml` postgres/kubo services; GH service-container pattern                        | **Ports**                                                                                           |
| `tools/mock-ipns-routing`                                                                               | **Promoted** — the hermetic `/routing/v1` CI record store                                           |
| someguy service                                                                                         | staging/production accelerator only — leaves CI                                                     |
| redis, tee-worker services and their secret plumbing                                                    | **Die** (#24)                                                                                       |
| `ci.yml` job skeleton, dorny path filters, reusable workflows, failure-artifact uploads                 | **Port** — refiltered for the v2 layout                                                             |
| Migration drift check                                                                                   | **Ports** if the API keeps TypeORM migrations                                                       |
| `tests/load/` k6 harness                                                                                | **Ports** — dispatch-gated                                                                          |
| `tests/vectors/` cross-language corpus + generators                                                     | **Dies** — vectors regenerate under the KAT-manifest regime (the formats they lock are gone anyway) |
| `check-vector-parity.sh`, `check-api-client.sh`, `api:generate` loop, SC#6/SC#2 grep gates              | **Die** — replaced by live gates per the doctrine                                                   |
| `tests/e2e/` (uncommitted Web3Auth storage-state scaffold) + its planning dir                           | **Delete** — superseded twice over                                                                  |
| `codecov.yml` targets, per-package vitest thresholds                                                    | **Demoted** to informational                                                                        |

## Open edges

- **Smoke-slice composition** — which specs fill the PR e2e minutes budget;
  engineering judgment at build time, revisited as the suite grows.
- **Measured constants** — kernel TTLs, migration window, sweep cadence,
  chunk size/DAG shape: process fixed above, values land during build.
- **Web3Auth Core Kit interactive login** — wallet-mock covers SIWE in CI;
  real Core Kit login (MFA, device approval) stays a staging-dispatch job
  with test credentials, never a PR gate — an honest, inherited limitation.
- **Runner provisioning, staging deploy gates, release-tag e2e gating,
  nightly scheduling** →
  [deployment blueprint (#48)](https://github.com/FSM1/cipher-box-next/issues/48).
