# ADR 0049 — Each suite proves what it claims, and no test seam ships

- **Status:** Accepted on 2026-09-26 — retroactive; the rule shipped in FSM1/cipher-box#899,
  FSM1/cipher-box#960, FSM1/cipher-box#1078, FSM1/cipher-box#1120 and FSM1/cipher-box#1831, and
  the blueprint carries it; the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows; trimmed on 2026-09-26 to the items that pass the three ADR hurdles — the removed items live in the blueprint
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

The web e2e suite reads engine state through the hook `window.__CIPHERBOX_ENGINE__`, and it
cold-starts a vault with no interactive Core Kit login. The suite drives the production static
build, because v1 tested the Vite dev server and never tested the artifact that shipped. A hook
gated on `import.meta.env.DEV` is absent from exactly the build under test. A hook gated on any
build flag is a seam that a deploy job can switch on by one variable, because `loadEnv` reads
`VITE_` variables from the process environment and from any `.env.<mode>` file.
`blueprint/core.md` "KAT regime" puts every frozen encoding in one core manifest, but core cannot
reach two formats that the engine freezes: the content-DAG root and the adoption gate's stage-3
verdict over a whole scope-root head block.

## Decision

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

Items D1, D4, D6, D7 and D8 moved to `blueprint/testing.md` "Host suites", "E2E — flows over real stacks", "CI gates" and "Open edges", and `blueprint/deploy.md` "Scheduled tier", on 2026-09-26.

## Rationale

- **D2:** a suite that runs on a different artifact proves nothing about the shipped one, so the
  hook must be present in the production build under test.
- **D3:** a test seam fails closed at the build, so the protection does not depend on nobody
  typing one variable into a deploy job.
- **D5:** a frozen format needs vectors at the layer that produces it, and regenerate-and-diff
  makes the committed generator the only writer.

## Alternatives rejected

**(b) Gate the hook on `import.meta.env.DEV` (FSM1/cipher-box#809).** The suite runs the
production build, so the hook would be absent from the artifact under test.

**(e) Put the engine formats in core's manifest.** Core cannot run the engine's `assemble` or the
gate, and a core crate that depends on the engine inverts the layering. FSM1/cipher-box#1132
asked to fold the gate family into one engine manifest; it closed as not planned.

## Consequences

- `blueprint/testing.md` carries D2 and the shipping-bundle assertion of D3 in "E2E — flows over
  real stacks", and D5 in "crates/engine — seam fakes and the simulation harness".
- `blueprint/core.md` "KAT regime" cross-references the engine KAT paragraph.
- `CONTEXT.md` needs no change.

## Residuals

**E2 — The shipping-bundle check reads the runtime global, not the bundle bytes.** The
introspection module is still imported by `apps/web/src/main.tsx`, and its body returns early on
the build-time flag. The hook cannot install itself in the shipping bundle, but its code can be
present in it.

**E3 — The test-login route ships in the API image.** It is a test seam in every API build. Only
the production-mode hard block and the timing-safe secret check gate it, and the contract suite
asserts the hard block.

**E5 — The engine KAT set runs natively only.** A WASM-target divergence in engine code that
produces a frozen engine format has no KAT proof.

## Gate

D3 blocks a merge through `Web E2E Smoke Result`, and D5 through `Rust Result` (`Engine simulation tests`).
