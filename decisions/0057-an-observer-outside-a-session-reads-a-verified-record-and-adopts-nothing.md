# ADR 0057 — An observer outside a session reads a verified record, and the read adopts nothing

- **Status:** Accepted on 2026-09-29
- **Date:** 2026-09-29
- **Relates to:** AGENTS.md Critical Security Rules 4 (all crypto lives in `crates/core`) and 6
  (every resolved record passes the adoption gate), the `CONTEXT.md` term "Adoption gate",
  [ADR 0033](./0033-every-attacker-sized-field-has-one-canonical-form-and-a-symmetric-fail-closed-bound.md)
  (every attacker-sized field has a fail-closed bound),
  [ADR 0049](./0049-each-suite-proves-what-it-claims-and-no-test-seam-ships.md) D3 (a staging or
  production build refuses the e2e hook),
  [ADR 0053](./0053-the-staging-soak-signs-in-as-durable-accounts-whose-login-secrets-live-in-the-staging-scope.md)
  (the staging soak), the `blueprint/web-client.md` section "WASM packaging and the type
  boundary", and decision 3 of the wayfinder map
  [FSM1/cipher-box#2047](https://github.com/FSM1/cipher-box/issues/2047)
- **Implemented by:** FSM1/cipher-box#2091 (closes FSM1/cipher-box#2070)
- **Amends:** none

## Context

The staging soak (ADR 0053) must prove from Node that the public routing network serves each soak
name at or above the sequence in its ledger, that a write advances the sequence by one, and that
the republisher renews an old record with a fresh validity. The soak holds no engine session in
Node. A deployed bundle carries no introspection hook (ADR 0049 D3), and TypeScript has no codec of
its own (rule 4). So the soak needs the Rust decoder, reached from Node, with no session. Every
read in the engine passes the adoption gate (rule 6). The gate needs the floors and keys of a
session, so a read with no session cannot run it.
Amended by
[ADR 0061](./0061-a-renewal-walk-over-every-owned-scope-renews-each-name-through-the-adoption-gate.md)
on 2026-09-30: the republisher re-PUTs the same bytes and extends no validity; the engine's
renewal walk gives an old record a fresh validity.

## Decision

**D1 — A WASM module built for an observer exports one verified record read that has no session
and runs no adoption gate, and the read is an observation only.** `readIpnsRecord` in
`crates/wasm` binds the engine function `verify_record_outside_session`. `openIpnsRecordReader` in
`packages/client` is Node glue that opens such a module, and it fails with a clear error when the
module has no `readIpnsRecord`. The limits that make it safe:

1. The public key comes from the IPNS name. The core decoder verifies the record signature under
   that key, so a record signed for another name fails as a trust violation.
2. An input above `MAX_RECORD_BYTES`, the cap of the engine's record fetch, fails as malformed
   before the decoder reads it.
3. The read returns the sequence, the signed validity text, and the EOL. It checks no floor,
   does not compare the EOL with the time, opens no seal, and adopts nothing. Its result never
   enters engine state.
4. No product path calls it. The facade does not carry it, and `apps/web` does not import it.
5. A result is an observation for a person or a test outside the vault. It is never a trust
   decision for a vault. A caller that must trust a record resolves it through a session, and the
   adoption gate decides.
6. The export exists only in a module built with the `observer` cargo feature of `crates/wasm`.
   The production module is built with no such feature, so it carries no export that reads a
   record with no adoption gate. The build that the client suites load enables the feature. The
   staging soak builds its own module with the feature; that build is not landed.

## Alternatives considered

- **A decode in TypeScript, or in the test package.** Rule 4 forbids a codec outside
  `crates/core`, and a second decoder needs a second KAT set.
- **An external tool such as the Kubo CLI.** It is a second decoder in another language. The soak
  would then prove what Go accepts, not what the product decoder accepts.
- **A full session for the observer.** The gated read needs a signed-in engine on native or WASM
  seams in Node. The soak would carry the login secret into a second runtime for a check that
  needs no key.
- **A hook in the staging bundle.** ADR 0049 D3 refuses the hook in a staging or production build.
- **The production module carries the export.** No product path calls it, and an export that
  skips the gate in the production module is a surface with no user.

## Consequences

1. `blueprint/web-client.md` "WASM packaging and the type boundary" names the export and cites D1.
2. `blueprint/testing.md` "Host suites" names the `packages/client` Node suite, which runs the IPNS
   record KATs through the export, and the production module suite, which proves that the
   production module has no such export.

## Residuals

None.
