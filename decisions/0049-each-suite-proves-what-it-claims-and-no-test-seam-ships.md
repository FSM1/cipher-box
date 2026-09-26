# ADR 0049 — Each suite proves what it claims, and no test seam ships

- **Status:** Accepted on 2026-09-26 — retroactive; the rule shipped in FSM1/cipher-box#899,
  FSM1/cipher-box#960, FSM1/cipher-box#1078, FSM1/cipher-box#1120 and FSM1/cipher-box#1831, and
  the blueprint carries it; the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-26
- **Relates to:**
  [#47](https://github.com/FSM1/cipher-box-next/issues/47) (the testing blueprint: the three
  laws, the host-suite list, the v1 disposition table and the Core Kit open edge),
  [#48](https://github.com/FSM1/cipher-box-next/issues/48) (the deployment blueprint: "Load
  harness and real-Web3Auth login stay dispatch-only"),
  [#27](https://github.com/FSM1/cipher-box-next/issues/27) D2 (one implementation, and the KAT
  manifest defends the frozen contract),
  [ADR 0008](./0008-cipherbox-issues-the-identity-token.md)
  D1 and D2 (every method, the wallet included, ends in one Core Kit `loginWithJWT`),
  [ADR 0018](./0018-the-pr-gate-is-grouped-by-area-with-an-adapter-leg-per-desktop-platform.md)
  (the PR gate by area, and the `Web E2E Smoke Result` context),
  ADR 0038 D6 (the contract suite proves the declared-address binding), the
  `blueprint/testing.md` sections "crates/engine — seam fakes and the simulation harness", "The
  contract suite — the live API gate", "Host suites", "E2E — flows over real stacks", "CI gates"
  and "Open edges", the `blueprint/deploy.md` section "Scheduled tier", the `blueprint/core.md`
  section "KAT regime", and the `CONTEXT.md` terms "Adoption gate" and "Structure signature"
- **Implemented by:** FSM1/cipher-box#899 (the web host suite, D1), FSM1/cipher-box#1078 (the
  hook flag, the shipping-bundle assertion and the per-test secret, D2 to D4),
  FSM1/cipher-box#1120 (the engine KAT set, D5), FSM1/cipher-box#960 (the load harness and its
  BYO scope, D6 and D7) and FSM1/cipher-box#1831 (the staging sign-in path, D8).
  FSM1/cipher-box#2005 corrected the coverage text of D8 in `blueprint/testing.md` and
  `blueprint/deploy.md`.

## Context

The testing blueprint came out of #47 on 2026-07-19, before any v2 suite existed. Its three laws
invert v1 defects. Law 1: a suite that does not block a merge does not exist. Law 2: assert
behavior, never source text. Law 3: determinism is injected. The same resolution fixed a suite
inventory and a v1 disposition table. #48 fixed the deploy side on the same day. Five build PRs
then found that parts of that inventory could not hold, and each PR changed the blueprint in
place. This ADR records those changes as one rule: a suite must prove the claim it is named for,
on the artifact that ships, and no seam that exists for a test may reach a deployed artifact.

**The web host suite.** #47 said that `apps/web` and `apps/desktop` "get no unit suites by
design". The web shell then gained code that the facade does not own. FSM1/cipher-box#899 landed
the `useSyncExternalStore` snapshot adapter (`apps/web/src/engine/snapshotStore.ts`) and the Core
Kit login-secret handoff (`apps/web/src/engine/loginHandoff.ts`). The handoff moves the login
secret into the worker as a transferred `ArrayBuffer` and zeroes every copy that the transfer
does not detach. The review passes on that PR found two defects on the handoff path: a
`RegExp.test` that left the whole secret hex in the realm's legacy `RegExp` statics, and a failed
failover promotion that left the secret unscrubbed. Both fixes landed in `packages/client`. The
tracker slices for the web host (FSM1/cipher-box#803 and its siblings) already named a web unit
gate. FSM1/cipher-box#1276 later moved the export and the transfer into `@cipherbox/login`; the
web host keeps the failover re-export (`LoginSecretSource`).

**The introspection hook.** The web e2e suite needs to read engine state without sleeps, and it
needs to cold-start a vault without an interactive Core Kit login. The hook is
`window.__CIPHERBOX_ENGINE__` (`apps/web/src/engine/introspection.ts`). The suite drives the
production static build, because v1 tested the Vite dev server and never tested the artifact
that shipped. A hook gated on `import.meta.env.DEV` is absent from exactly the build under test.
A hook gated on any build flag is a seam that a deploy job can switch on by one variable, because
`loadEnv` reads `VITE_` variables from the process environment and from any `.env.<mode>` file.

**Test isolation.** #47 ported the v1 test-login pattern, and FSM1/cipher-box#809 asked to harvest
the v1 test-login helpers. FSM1/cipher-box#1078 found that the web path does not need them.
`login_identity` creates the account at the first challenge-signature login
(`crates/engine/src/api/client.rs`), so a fresh 32-byte login secret is a fresh vault with no
fixture. The smoke workflow then needs no secret at all.

**The engine KAT set.** `blueprint/core.md` "KAT regime" puts every frozen encoding in one core
manifest. Core cannot reach two things that the engine freezes. The content-DAG root is an engine
format: its chunk size is stamped in every published root. The adoption gate's stage-3 verdict
over a whole scope-root head block is an engine predicate. FSM1/cipher-box#1120 added the
**one section, one signer** rule at stage 3, because the old per-structure trial verify adopted a
structure spliced from another record and let a hostile commitment force about 1.3 million
signature checks. The PR froze the accept and reject verdicts as engine vectors. Both the
generator and the suite fail against the pre-fix gate.

**The load harness.** #47 and #48 ported the v1 k6 harness, and FSM1/cipher-box#657 asked for
that port. The v2 upload path needs a client-computed BLAKE3-256 CID, all crypto lives in
`crates/core` (AGENTS.md rule 4), and the engine holds the only API client. A TypeScript harness
would need a second copy of both. FSM1/cipher-box#960 built the harness as a Rust crate on the
engine's real `ApiClient` instead. The engine had no external-provider write path, so the BYO
scenario could drive only the API-side advisory rows.

**The staging sign-in.** #47 left an open edge: Core Kit interactive login stays a
staging-dispatch job. #48 said "real-Web3Auth login stay dispatch-only". FSM1/cipher-box#1821
(2026-09-14) asked for a suite that drives the deployed front, after the v2.0.2 deploy shipped two
front defects that only a real browser against the real front shows. It left the sign-in method
open. A deployed bundle refuses the hook, and the test-login route mints API tokens only, so it
cannot drive the shipped UI. FSM1/cipher-box#1831 chose the shipped wallet method. The first text
of that PR said, in `blueprint/testing.md`, that real Core Kit login stays uncovered, and said, in
`blueprint/deploy.md`, that the staging job is the real Core Kit login. FSM1/cipher-box#2005
(merged 2026-09-26) made both files agree with the code.

`blueprint/testing.md` carries the rules today in the sections named under "Relates to".
`blueprint/deploy.md` "Scheduled tier" carries the BYO scope of D7.

## Decision

**D1 — The `apps/web` host keeps a thin unit suite, and the suite blocks a merge.** Vault
correctness is not tested in the web host: it lives below the facade. The web shell owns three
seams that the facade does not own, and the suite covers those: the `useSyncExternalStore`
snapshot adapter, the login-secret handoff with its transfer and zeroization boundary (E10),
and UI-owned chrome state. Rendering and flows stay with Playwright and the mounted e2e. The suite is
merge-blocking in the PR gate. The blueprint names that gate as the workspace `Test` gate; under
ADR 0018 the suite runs as the job `Web host typecheck + tests` in the Web area and reports
through `Web Result` (E1). This reverses the #47 statement that `apps/web` gets no unit suite by
design. The rule landed with FSM1/cipher-box#899; this ADR records it.

**D2 — The introspection hook rides a dedicated build flag, not `DEV`.** The hook publishes
`window.__CIPHERBOX_ENGINE__` only when the bundle is built with `VITE_E2E_HOOK=true`
(`installIntrospection` in `apps/web/src/engine/introspection.ts`). It carries taps over the
facade snapshot and event stream, the cold start that the suite drives in place of an
interactive login, and the device-approval steps that a second session drives in place of an
interactive approval. The login secret goes one way, into the engine, through the shipped
handoff. No tap gives key material back: an approval tap reports a SHA-256 digest of a factor,
never the factor. The web e2e suite runs against the production
build served statically, and its waits poll the hook, never a sleep. The rule landed with
FSM1/cipher-box#1078; this ADR records it.

**D3 — The shipping bundle is proven hook-free, and a deployed build refuses the flag.** The web
e2e workflow builds the bundle twice from one engine module: once as it ships, once with the
flag. The suite drives the flagged bundle, and a `release` project serves the shipping bundle and
asserts that it exposes no hook. The assertion runs on the artifact, not on source text (law 2).
A `staging` or `production` build that sets `VITE_E2E_HOOK` fails at build time
(`shipsE2eHook` in `apps/web/src/engine/config.ts`, called from `apps/web/vite.config.ts`). The
rule landed with FSM1/cipher-box#1078; this ADR records it.

**D4 — Web e2e isolation uses a fresh login secret per test, and needs no test-login.** Each test
cold-starts its own vault from a fresh 32-byte login secret, which the page mints itself so that
the secret never appears as an `evaluate` argument in an uploaded trace. The API creates the
account at the first challenge-signature login, so a fresh secret is a fresh vault. The workers
then run fully parallel, and `retries: 0` stays the policy. The web e2e stack configures no
test-login secret. The API's test-login route keeps its v1 gating pattern (a timing-safe secret
check, a hard block in production mode) for the harnesses that need an API token with no
browser: the contract suite, the load harness and the nightly tier. This reverses the #47
disposition that the test-login pattern ports for web isolation. The rule landed with
FSM1/cipher-box#1078; this ADR records it.

**D5 — The engine owns a second KAT set beside core's.** `crates/core` owns the KAT regime and
its manifest. The engine owns its own KAT vectors under that regime, for the formats and
predicates that core cannot reach: the content-DAG root, and the adoption gate's stage-3 verdict
over whole scope-root head blocks, including the **one section, one signer** reject. Only
`cargo run -p cipherbox-engine --example kat_gen` writes `crates/engine/kat`. The `Engine
simulation tests` gate regenerates the whole tree and diffs it before it runs the suites, so a
verdict change that is not a deliberate re-freeze fails there. The engine set does not duplicate
a core format. So AGENTS.md "one implementation, one KAT set" holds per frozen format: no format
has a second vector set in another language or for another target. The rule landed with
FSM1/cipher-box#1120; this ADR records it.

**D6 — The load harness is the Rust crate `crates/load` on the engine's real API client.** The
harness drives `cipherbox-engine`'s `ApiClient` over the production `Http` seam of
`cipherbox-desktop-seams`, so a run measures the shipping client path and cannot drift from the
contract. It is Rust beside the contract suite, not a k6 or TypeScript package. It ports v1's
`tests/load/` scenarios onto the v2 surface. `load-test.yml` runs it on dispatch only, against
`local` or `staging`. It is never a PR gate. Target resolution is an allowlist: `local` reaches a
loopback host only, `staging` reaches only an https URL from the approval-gated `staging`
environment, and no production target exists. The harness's own unit tests block a merge in the
Rust area. This reverses the #47 and #48 statement that the k6 harness ports. The rule landed
with FSM1/cipher-box#960; this ADR records it.

**D7 — The BYO load scenario covers only the API-side advisory-pin path.** A BYO account's bytes
never touch the API, so the `byo-advisory` scenario only registers advisory pin rows, which count
for liveness and never gate. External-provider throughput waits on the engine's provider layer.
The rule landed with FSM1/cipher-box#960; this ADR records it.

**D8 — `Staging E2E` signs in through the shipped SIWE method with an injected test wallet, and so
covers the real Core Kit login.** A deployed bundle refuses the hook (D3), so the staging suite
signs in through a shipped method. The wallet method is the only one that completes with no party
outside the stack. The suite installs an EIP-1193 provider before navigation, and a fresh key is a
fresh identity subject over an empty vault. The key stays in the test process: the
provider forwards `personal_sign` to it (`tests/web-e2e/staging/wallet.ts`). The wallet method
ends in the same Core Kit `loginWithJWT` call as every method (`apps/web/src/auth/coreKit.ts`,
ADR 0008 D1 and D2). MFA enrollment and the Google and email-code methods stay uncovered by every
automated suite. They need an interactive staging run, never a PR gate. This reverses the #47
open edge and the #48 statement that real Web3Auth login stays a dispatch-only job. The rule
landed with FSM1/cipher-box#1831; FSM1/cipher-box#2005 corrected its coverage text; this ADR
records it.

## Rationale

- **A suite that runs on a different artifact proves nothing about the shipped one.** v1 tested
  the dev server. D2 and D3 test the production build, and D3 proves that the difference between
  the tested build and the shipped build is the hook alone.
- **A test seam fails closed at the build.** A deploy job that sets the flag by mistake fails
  (D3). The protection does not depend on nobody typing one variable into a deploy job.
- **Isolation without a test route removes a secret from the merge gate.** D4 needs no secret, so
  the smoke workflow runs with no secret and no environment, and the web path under test is the
  shipped challenge-signature login.
- **A frozen format needs vectors at the layer that produces it.** Core's manifest cannot
  regenerate engine bytes or enumerate engine verdicts. D5 applies core's regime where core cannot
  reach, and regenerate-and-diff makes the committed generator the only writer.
- **One API client means no drift.** D6 drives the client that ships, so a load run and a
  contract run exercise the same request code, and no crypto enters TypeScript.
- **A stated coverage limit is honest; a wrong one misleads.** D7 and D8 say what the harness and
  the staging suite do not cover. D8 records the limit that the code shows: the login mechanism
  is covered, and MFA enrollment and two methods are not.
- **The web shell owns real security code.** The login-secret handoff is key custody at the
  realm boundary. D1 gives the web part of it a merge-blocking test. The regression tests for
  both review findings on FSM1/cipher-box#899 run in `packages/client` and `packages/login`, in
  the same Web area.

## Alternatives rejected

**(a) No unit suite in `apps/web` (#47).** The handoff and the snapshot adapter have ordering and
zeroization rules that neither the browser suite in `packages/client` nor Playwright reaches. A
separate `Web Unit` job was also dropped in FSM1/cipher-box#899, because the existing test gate
already ran the suite. Law 1 asks for a named merge-blocking gate, not a new one.

**(b) Gate the hook on `import.meta.env.DEV` (FSM1/cipher-box#809).** The suite runs the
production build, so the hook would be absent from the artifact under test.

**(c) Trust the flag alone to keep the hook out of a deploy.** Before FSM1/cipher-box#1078 added
the build-time refusal, only the absence of the variable in a deploy job kept the hook out.

**(d) Port the v1 test-login helpers for web isolation (#47, FSM1/cipher-box#809).** The first
challenge-signature login already creates the account, so the route adds a secret and a fixture
for nothing.

**(e) Put the engine formats in core's manifest.** Core cannot run the engine's `assemble` or the
gate, and a core crate that depends on the engine inverts the layering. FSM1/cipher-box#1132
asked to fold the gate family into one engine manifest; it closed as not planned.

**(f) Port the k6 harness (#47, #48, FSM1/cipher-box#657).** A TypeScript or k6 harness needs a
second CID implementation and a second API client.

**(g) Use test-login or the hook for the staging suite.** A deployed bundle refuses the hook, and
the test-login route mints API tokens only, which cannot drive the shipped UI.

**(h) Use the Google or email-code method for the staging suite.** Both need a party outside the
stack: an identity provider account or a mailbox. The wallet method signs in the test process.

## Consequences

1. **`blueprint/testing.md` already carries D1 to D6 and D8.** "Host suites" carries D1. "E2E —
   flows over real stacks", the Web Playwright bullet, carries D2, D3 and D4, and the "Staging
   e2e" bullet carries the hookless sign-in of D8. "crates/engine — seam fakes and the simulation
   harness" carries D5. "CI gates", the dispatch row, carries D6. "Open edges", the Web3Auth Core
   Kit bullet, carries the coverage of D8 in the text that FSM1/cipher-box#2005 corrected. No rule
   text changes. "The contract suite — the live API gate" carries the address assertion that ADR
   0038 D6 records.

2. **`blueprint/deploy.md` already carries D6 and D7.** "Scheduled tier" names `load-test.yml`
   over `crates/load` and the BYO scope, and the v1 workflow table names `load-test.yml` as ported
   over `crates/load`. No text change is needed.

3. **`CONTEXT.md` needs no change.** "Adoption gate" and "Structure signature" name what the
   engine KAT set of D5 freezes, and neither changes.

4. **This ADR supersedes four statements of the #47 and #48 suite inventory.**
   - #47 "`apps/web`/`apps/desktop` get no unit suites by design" now reads, for `apps/web`: a
     thin merge-blocking unit suite covers the snapshot adapter, the login-secret handoff and
     UI-owned chrome state (D1).
   - #47 "k6 harness … port" and #48 "Load harness … stay dispatch-only" now read: the harness is
     the Rust crate `crates/load` on the engine's API client, dispatch-only (D6).
   - #47 "test-login pattern … port" now reads: the test-login route ports with its gating
     pattern for API-level harnesses; web e2e isolation uses a fresh login secret per test and no
     test-login (D4).
   - The #47 open edge "Core Kit interactive login as staging-dispatch only" and #48
     "real-Web3Auth login stay dispatch-only" now read: `Staging E2E` covers the real Core Kit
     login through the wallet method, and MFA enrollment and the Google and email-code methods
     stay uncovered (D8).

   The fifth row of that inventory, law 1 against dispatch-tier and scheduled suites, is not in
   this ADR.

5. **`blueprint/testing.md` section "Host suites" gains the citation (ADR 0049)** on the `apps/web`
   bullet.

6. **`blueprint/testing.md` section "E2E — flows over real stacks" gains the citation (ADR 0049)** on the Web Playwright bullet and on the "Staging e2e" bullet.

7. **`blueprint/testing.md` section "crates/engine — seam fakes and the simulation harness" gains
   the citation (ADR 0049)** on the engine KAT paragraph, and `blueprint/core.md` section "KAT
   regime" gains a one-line cross-reference to that paragraph, because its "one machine-checked
   manifest" covers the core formats only.

8. **`blueprint/testing.md` section "CI gates" gains the citation (ADR 0049)** on the load
   harness in the dispatch row, and section "Open edges" gains it on the Web3Auth Core Kit
   bullet. **`blueprint/deploy.md` section "Scheduled tier" gains the citation (ADR 0049)** on
   the dispatch-only paragraph.

9. **`blueprint/testing.md` needs an editorial pass for stale v1 text that contradicts D1, D2
   and D4.** No rule changes. The "What dies" table credits the removal of the old web unit tests
   to "web keeps no logic worth unit-testing" and credits parallel workers to "per-test vault
   isolation via test-login". The Web Playwright bullet opens with "test-login API helpers" and
   "The DEV-gated facade introspection hook". The v1 disposition table lists "test-login helpers"
   in the ported `tests/web-e2e/` row. The `apps/web` bullet names the workspace `Test` gate (E1).
   The `apps/web` bullet also puts the login-secret handoff and its transfer and zeroization
   boundary in the web shell, but that code is in `packages/login/src/secret.ts` (E10).

10. **No wire format, no KDF edge and no op queue record changes.**

## Residuals

**E1 — The blueprint names a gate that no longer exists by that name.** "Host suites" says that the
web unit suite is merge-blocking under the workspace `Test` gate. Since ADR 0018 the suite runs as
`Web host typecheck + tests` in `.github/workflows/ci-web.yml` and reports through `Web Result`,
which the "CI gates" PR-gate row already describes as "the `apps/web` host suite". The rule, a
merge-blocking suite, holds. This ADR records the blueprint rule; consequence 9 fixes the name.

**E2 — The shipping-bundle check reads the runtime global, not the bundle bytes.** The `release`
project asserts that `window.__CIPHERBOX_ENGINE__` is absent. The introspection module is still
imported by `apps/web/src/main.tsx`, and its body returns early on the build-time flag. Whether
the bundler removes the dead body is not asserted. The hook cannot install itself in the
shipping bundle, but its code can be present in it.

**E3 — The test-login route ships in the API image.** D3 keeps the web hook out of every deployed
bundle. The API's test-login route is a different seam: it is in every API build, the staging
deploy sets its secret, and only the production-mode hard block and the secret check gate it. The
contract suite asserts the hard block against a production-mode API instance
(`test_login_is_hard_blocked_in_production`). The `Contract Suite` job boots that instance and
sets `CONTRACT_API_PROD_URL`; without it the test skips.

**E4 — The engine KAT set carries more families than the blueprint names.** The blueprint names
the content-DAG root and the stage-3 verdict. `crates/engine/kat` also holds rotation reject
families (`kat/rotation`) and check-surface families (`kat/checks`), each with its own manifest,
and `kat_gen` writes all of them. The regime of D5 covers them. The blueprint list is
incomplete, not wrong. This ADR records the blueprint scope.

**E5 — The engine KAT set runs natively only.** Core's KAT suite runs natively and as WASM, which
is core's residual parity surface. The engine KAT suites run under `cargo test -p
cipherbox-engine` on the Linux runner only. A WASM-target divergence in engine code that produces
a frozen engine format has no KAT proof.

**E6 — The BYO scenario measures no provider.** D7 states the scope. The external-provider
extension waits on the engine's provider write path (FSM1/cipher-box#959 is open), and the
retained `PINATA_JWT` secret has no consumer until then.

**E7 — MFA enrollment and two sign-in methods have no automated proof.** D8 states the limit. A
defect in factor enrollment, in the Google method or in the email-code method reaches staging
with no suite red. Device approval is outside this exemption: ADR 0009 requires a harness for it.

**E8 — `apps/desktop` is outside D1.** #47 also said that `apps/desktop` gets no unit suite. The
Desktop area now runs shell frontend suites. This ADR does not record a rule for them.

**E9 — The staging verdict gates no merge.** `Staging E2E` runs after a deploy, so a regression
that only the deployed front shows is found after it ships to staging. Where the suite sits in
the gate map is not in this ADR.

**E10 — The blueprint puts the login-secret handoff in the web shell, and the code does not.**
"Host suites" says that the web shell owns "the login-secret handoff and its transfer/zeroization
boundary", and that the thin web suite covers it. Since FSM1/cipher-box#1276 the export, the
transfer and the zeroization are in `packages/login/src/secret.ts`, tested in
`packages/login/src/secret.test.ts` under the job `Shared packages typecheck + tests`.
`apps/web/src/engine/loginHandoff.ts` keeps only the failover re-export (`LoginSecretSource`). The
merge-blocking coverage holds, because both jobs are in the Web area and report through `Web
Result`. This ADR records the blueprint rule in D1; consequence 9 fixes the text.

## Gate

- **D1:** the `apps/web` unit suite runs in the job `Web host typecheck + tests`
  (`.github/workflows/ci-web.yml`), which reports through the required `Web Result` context. It
  holds `apps/web/src/engine/snapshotStore.test.ts` ("caches the engine view and returns it
  synchronously") and `apps/web/src/engine/loginHandoff.test.ts` ("re-exports the secret for a
  failover promotion", "writes no secret to origin storage"). The transfer and zeroization tests
  of the handoff are in `packages/login/src/secret.test.ts` ("zeroes the buffer when the engine
  never took it", "parks no copy of the secret in the realm-global RegExp statics"), in the job
  `Shared packages typecheck + tests` of the same Web area.
- **D2:** `apps/web/src/engine/introspection.test.ts` ("publishes nothing without the e2e build
  flag", "leaves the hook out for any value but the flag").
- **D3:** `tests/web-e2e/tests/release-bundle.spec.ts` ("the release bundle exposes no
  introspection hook"), in the `release` project of the smoke slice, behind the required `Web E2E
Smoke Result` context. `apps/web/src/engine/config.test.ts` (`describe('shipsE2eHook')`) covers
  the predicate. **Finding:** no test runs the build-time throw in `apps/web/vite.config.ts`.
- **D4:** **Finding:** no test asserts that the web suite never calls test-login. The
  configuration enforces it: `.github/workflows/web-e2e.yml` sets no `TEST_LOGIN_SECRET`, and
  `apps/api/src/auth/auth.http.itest.ts` ("is disabled when TEST_LOGIN_SECRET is unset") proves
  that the route then refuses. The per-test secret is in `VaultPage.signInHere`
  (`tests/web-e2e/page-objects/vault.page.ts`).
- **D5:** the step "Engine KAT vectors fresh (committed generator is the only writer)" in the
  `Engine simulation tests` job (`.github/workflows/ci-rust.yml`) regenerates and diffs
  `crates/engine/kat`. The suites are `crates/engine/tests/kat_content.rs`
  (`accept_vectors_reproduce_the_frozen_root_bytes`, `vector_counts_are_exact`) and
  `crates/engine/tests/kat_gate.rs` (`accept_vectors_authenticate_under_one_committed_signer`,
  `a_section_signed_by_two_committed_pseudonyms_fails_closed`,
  `manifest_header_and_counts_are_exact`).
- **D6:** the target guard tests in `crates/load/src/plan.rs` (`there_is_no_production_target`,
  `local_refuses_a_non_loopback_url`, `staging_requires_an_https_url_from_the_environment`) and the
  scenario tests over the stub `Http` seam in `crates/load/src/scenarios.rs` run in the Rust area.
  `load-test.yml` has a `workflow_dispatch` trigger only.
- **D7:** `byo_advisory_flips_the_account_then_retires_its_advisory_rows` in
  `crates/load/src/scenarios.rs`.
- **D8:** `tests/web-e2e/staging/first-login.spec.ts` ("a fresh identity mints a vault, and the
  session survives a reload") in `Staging E2E`, which `tag-staging.yml` calls after the deploy
  job. It blocks no merge (E9). No suite covers MFA enrollment or the Google and email-code
  methods, by D8.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
