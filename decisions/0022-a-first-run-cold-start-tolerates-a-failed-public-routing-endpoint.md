# ADR 0022 — A first-run cold start tolerates a failed public routing endpoint when the registry holds no vault-pointer name for the account

- **Status:** Accepted — implemented in FSM1/cipher-box#1938, FSM1/cipher-box#1939 and
  FSM1/cipher-box#1940; `blueprint/api.md`, `blueprint/engine.md` and `CONTEXT.md` reworded there
- **Date:** 2026-09-23
- **Relates to:**
  [ADR 0007](./0007-derived-idempotent-first-run-mint.md)
  (the first-run mint is derived and idempotent),
  [#24](https://github.com/FSM1/cipher-box-next/issues/24) D3 (no client resolve path touches
  the API's record cache) and D6 (register-first on the publish path),
  [#23](https://github.com/FSM1/cipher-box-next/issues/23) D5 (fan-out GET across the endpoint
  set), the `blueprint/engine.md` "Cold start" and "Vault pointer" sections, the
  `blueprint/api.md` "Registry" section, and the `CONTEXT.md` "Vault pointer" and
  "Register-first" terms
- **Implemented by:** FSM1/cipher-box#1935 (the registry query, D1) and FSM1/cipher-box#1936
  (the first-run rule, D2 to D4), after acceptance.

## Context

A new member on staging signed in with Google from a share link on 2026-09-23. The API created
the account at 15:58:52 UTC. The account registered no name. The login screen showed
`seam error: the vault-pointer plane could not be read`. The same flow passed on another device
ten minutes later.

The cold start walks the vault pointer chain before anything else reads the network
(`resolve_vault_pointer` in `crates/engine/src/sync/pointer.rs`). Each step fans out one GET to
every routing endpoint (`crates/engine/src/net/fanout.rs`). The fan-out has three outcomes:

- `Found` when one endpoint returns a record that verifies at the name.
- `Absent` only when every endpoint answered and every answer was "no record".
- `Unavailable` when no endpoint returned a record and at least one endpoint failed. A
  network error, a non-2xx status other than 404, a refused redirect, and the 30 s deadline
  are all failures. The per-endpoint error is dropped.

`crates/engine/src/sync/boot.rs` maps `Unavailable` to a retryable seam error, and `start`
returns it. The provisioning path that follows an empty chain runs the same rule once more in
`require_vacant_vault_pointer` (`crates/engine/src/net/provision.rs`), with the same outcome.

The rule exists for one reason, and the code states it. An account that already published its
pointer must never mint a second vault over it. The overwritten record names the one root whose
owner-write blob holds a write scope seed nobody can re-derive. Unanimity makes a partial
outage distinguishable from a vacant name: one endpoint holds the pointer and is down, a peer
that never saw it answers "no record", and the walk must not conclude "absent".

A fresh account has no record at any endpoint. It is the one case that needs every endpoint
healthy at once. The staging set is the CipherBox routing front and the public
`delegated-ipfs.dev`. A content blocker, a DNS filter, or a refusal at either one fails the
sign-up. An existing account passes on a single `Found`. Vacant lookups themselves are fast:
under one second at someguy and at the public endpoint, measured from the staging host.

The registry already knows the fact the rule protects. Register-first (`#24` D6) places a
`name_inventory` row for the account before any record reaches the transport. So when the
registry holds no row for the account's vault-pointer name, the account never published a
pointer, and there is no earlier record to overwrite. The registry does not know this for
another deployment, but Core Kit derives the identity per verifier and network, so one
credential yields different identities on staging and on production, and one deployment's
pointer name never appears on another.

Two signals the engine already receives are not this fact:

- `isNewUser` on the login response is true on the first login only. A member who hits this
  failure and signs in again gets `false` with a still-vacant vault.
- The recovery endpoint serves the API's record cache. The republisher fills that cache on its
  inventory walk, so a name the account registered minutes ago is not in it. A 404 there says
  "not cached", not "never registered". `require_vacant_vault_pointer` already reads it, and
  only to refuse.

## Decision

**D1 — The registry answers whether the caller's account holds a registration for a name.**
The API gains one authenticated, rate-limited query on the registry surface. It takes an IPNS
name and answers 200 with a JSON body that carries one boolean, `registered`. The value is true
when the caller's `name_inventory` holds that name, and false when it does not. It reads the
caller's inventory only. A name registered by another account, and a malformed name, answer
false with the same bytes. The route never answers 404: a 404 from an API build without the
route, or from an intermediary, must not read as "not registered". The API inspects no record
and learns nothing it did not already hold: the caller's registered names are the registry's own
rows, and the name asked about is derived from the caller's login secret.

**D2 — A first-run walk accepts a fan-out with a failed endpoint as "absent".** Before the
pointer walk at index 0, the cold start asks D1 for the derived vault-pointer name. When the
answer is a 200 whose body says `registered: false`, the walk and the mint's vacancy probe both
use the first-run rule:

- The outcome is `Found` when one endpoint returns a record that verifies at the name. This
  arm does not change.
- The outcome is `Absent` when no endpoint returned a record, at least one endpoint answered
  "no record", and every other endpoint failed.
- The outcome is `Unavailable` when every endpoint failed.

When the answer is `registered: true`, or the query fails for any reason, the walk and the
probe keep the unanimity rule. Any other status, a 404 included, and a body without the boolean
are failures. The default is the current behaviour, so a registry outage changes nothing.
Amended by
[ADR 0034](./0034-a-degraded-settings-load-falls-back-to-the-last-verified-copy-and-never-widens-placement.md)
D10 on 2026-09-26: the first sentence of D2 now reads "Before the pointer walk at index 0, on a
device that holds no vault-pointer index floor, the cold start asks D1 for the derived vault-pointer
name."

**D3 — The registry answer permits availability only, never adoption.** A "not registered"
answer lowers the bar for "no record exists". It does not adopt a record, it does not select a
root, and it does not skip the verify or the adoption gate on a `Found`. A "registered" answer
or silence adds nothing to the current rule. The registry stays outside every trust decision on record bytes (`#24` D3).
Amended by
[ADR 0034](./0034-a-degraded-settings-load-falls-back-to-the-last-verified-copy-and-never-widens-placement.md)
D11 on 2026-09-26: the second sentence of D3 now reads "It does not adopt a record, it does not
select a root, it does not skip the verify or the adoption gate on a `Found`, and it is not stored."

**D4 — The error class does not change.** `Unavailable` stays a retryable seam error on the
cold-start path and a retryable `VaultUnprovisioned` event on the mint path. A fresh account
whose every endpoint fails still sees the seam error, and a retry still clears it.

## Trust argument

- **No earlier record of this account can be overwritten.** The registry row exists before any
  publish (`#24` D6). A "not registered" answer therefore says that this account never sent a
  pointer record to the transport. The mint that follows overwrites nothing this account owns.
- **No other account's record can be overwritten.** The vault-pointer name derives from the
  login secret. A second account cannot hold the same name unless it holds the same secret.
- **Another deployment holds no record at this name.** The identity is derived per verifier
  and network, so the name is unique to the deployment.
- **A hostile public endpoint gains nothing.** Under D2 a failure at a public endpoint is
  tolerated, and a "no record" answer from it was already accepted under the current rule. A
  record it returns still needs to verify at the name, as today.
- **A hostile or lagging registry can only refuse.** A wrong "registered" keeps the unanimity
  rule, which is the current behaviour. A wrong "not registered" is the residual E1. A build
  without the route answers 404, which is a failure, not an answer.

## Alternatives rejected

**(a) Accept "no record" from the CipherBox routing front alone.** The front is a DHT client
with no record store. Its walk can fail to reach the peers that hold a record the same
account published from another device, and the public endpoint is then the only one that
answers `Found`. This is the case the unanimity rule protects, and it needs no registry fault
to occur.

**(b) Use `isNewUser` from the login response.** It is a one-shot flag. The member who hits the
failure once signs in again as an existing user with no vault, and is refused again.

**(c) Use the recovery endpoint's 404 as the first-run signal.** The record cache lags the
republisher walk, so a registered name is absent from it for hours. It answers a different
question, and the blueprint refuses the cache as a resolve input.

**(d) Drop the public endpoint from a fresh account's set.** This is (a) with a different
spelling. The engine cannot know that the account is fresh without D1.

**(e) Retry the failed endpoint for longer.** A blocked endpoint never answers. A member on such
a network can never sign up.

**(f) Move the whole first-run decision to the API.** The API would then decide when a mint may
run. The blueprint keeps every trust decision on record bytes in the engine, and D3 keeps it
there.

## Consequences

1. **`blueprint/api.md` changes when this ADR is accepted.** The "Registry" section gains the
   per-name registration query of D1, beside register and retire, with its throttle surface.

2. **`blueprint/engine.md` changes when this ADR is accepted.** The "Cold start" section gains
   the first-run rule of D2 after the pointer walk description. The "Vault pointer" section
   gains the sentence "A first-run walk, which the registry has confirmed holds no
   registration for the pointer name, reads a fan-out with a failed endpoint and one vacant
   answer as absent (ADR 0022)."

3. **`CONTEXT.md` changes when this ADR is accepted.** The "Vault pointer" entry gains "a
   first-run walk tolerates a failed endpoint once the registry confirms the name is
   unregistered (ADR 0022)".

4. **The engine's API client gains one call.** The seam trait for the API gains the registration
   query, and the fakes in the engine testkit answer it.

5. **No wire format, no KDF edge, and no op queue record changes.**

## Residuals

**E1 — A registry that lost the account's rows permits a second mint.** The scenario needs
three conditions at once: the registry lost the `name_inventory` row, the CipherBox routing
front answered "no record" for a name it once carried, and every public endpoint failed. The
first condition is a database loss, which the platform's backups and the republisher's
inventory walk are built to notice. Account removal deletes the rows by design, and a re-signup
of the same identity then mints over the old record, which is the intended outcome of a
removal.

**E2 — The query tells the API which name the caller asks about.** The API already holds every
name the caller registered, and the name asked about is the caller's own derived pointer name.
The query adds one timing fact: the API learns when a first-run cold start happens, which the
implicit account creation at first login already discloses.

**E3 — The operator plus a blocked public endpoint can cause a second genesis mint.** One
operator runs the registry and the CipherBox routing front. Under the current rule that operator
alone cannot cause a mint over an existing pointer, because the public endpoint answers `Found`.
Under D2 the operator can answer "not registered" and "no record" while the member's own network
blocks every public endpoint, and the walk then reads the name as vacant. The member's network,
not the operator, has to supply the block. What bounds the damage: the fan-out adopts the record
with the highest sequence, and the wrong pointer carries sequence 1 while the honest pointer
carries a higher one. As soon as the member reaches a public endpoint again, the honest pointer
wins the walk and the earlier vault is back. Writes made in the window land under the wrong root
and are orphaned. The operator is already trusted for availability, and this residual is
accepted on the same terms as E1.

## Gate

- A fresh account, with the registry answering "not registered" for its pointer name, completes
  the cold start and mints its vault when one routing endpoint answers "no record" and every other
  endpoint fails.
- The same account is refused with the retryable seam error when every endpoint fails.
- An account whose registry answers "registered" keeps the unanimity rule: one failed endpoint gives the
  retryable seam error, and no mint runs.
- A registry query that fails for any reason keeps the unanimity rule. A 404 and a body without
  the boolean are failures.
- A record returned by any endpoint on a first-run walk still passes the verify at the name and
  the adoption gate before it is adopted.
- The API query answers "not registered" for a name registered by another account, with the
  same bytes as for a name nobody registered.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
