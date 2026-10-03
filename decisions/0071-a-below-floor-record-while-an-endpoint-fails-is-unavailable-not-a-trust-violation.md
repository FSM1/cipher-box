# ADR 0071 — A below-floor record while an endpoint fails is unavailable, not a trust violation

- **Status:** Accepted on 2026-10-03
- **Date:** 2026-10-03
- **Relates to:** FSM1/cipher-box#2264 (a revoke stops as a trust violation while an endpoint
  fails), [ADR 0022](./0022-a-first-run-cold-start-tolerates-a-failed-public-routing-endpoint.md)
  and [ADR 0034](./0034-a-degraded-settings-load-falls-back-to-the-last-verified-copy-and-never-widens-placement.md)
  (the first-run rule tells "every endpoint answered" from "an endpoint failed"),
  [ADR 0060](./0060-a-stated-refusal-from-every-endpoint-supersedes-the-bin-index-mint-mark.md) D1
  (a stated answer is apart from an unknown outcome),
  [ADR 0065](./0065-the-name-wave-drops-a-node-that-it-cannot-move-and-an-owed-cut-ends-within-a-bound.md)
  D3 (a record below the sequence floor is a stop that an endpoint can cause),
  [ADR 0066](./0066-a-different-record-at-the-sequence-floor-is-a-fork-not-a-trust-violation.md)
  (a record at the floor), AGENTS.md rule 6, and the `blueprint/engine.md` "Adoption gate and
  floors" section
- **Implemented by:** —
- **Amends:** —

## Context

The staging E2E revoke in `sharing.spec.ts` failed on v2.10.0 with "trust violation: descendant
record rejected by adoption gate". An engine test on main shows the cause. The `GrantScenario`
fixture has two record endpoints. A publish returns after the first ack, so endpoint B lags one
sequence on the granted scope root (`fail_put_endpoint`, then `heal_put_endpoint`). Endpoint A
then fails during the revoke (`fail_endpoint`). The fan-out GET reads only B's old record, the
sequence stage of the gate refuses it, and the revoke stops as a trust violation. With both
endpoints up, the same revoke succeeds. A second revoke after A recovers (`heal_endpoint`) also
succeeds. Staging reads `routing-staging` and the public delegated endpoint, so a lag of one
sequence on one endpoint is common. The engine already tells a statement about the name from a
statement about the endpoints (`FanoutRecord::Absent` and `Unavailable`, ADR 0022, ADR 0060), but
the sequence stage does not.

## Decision

**D1 — A below-floor pick from a fan-out with a failed endpoint is unavailable.** When a gated
read fans out to the endpoint set, at least one endpoint failed (D2), and the freshest record
that any endpoint served is strictly below the durable sequence floor of the name, the engine
reports the read as unavailable. It adopts nothing, raises no floor, keeps last-known-good, and
sends no trust event. The rule applies to each read that runs the adoption gate on a fan-out
GET: the vault-root resolve, the gated child resolve, the root admit of the boundary walk and of
the renewal walk, the drain reads, and the descendant reads of a grant, a revoke and a rotation.
The rule covers the sequence stage alone. A refusal at any other stage (record verify,
commitment, grant-section authentication, epoch, unseal) stays a trust violation, also when an
endpoint failed. A record at the floor stays under ADR 0066.

**D2 — An endpoint failed when it gave no answer about the record.** A failure is a transport
failure (no connection, a refused connection), a 5xx answer, or a timeout. A "no record" answer
(a 404) is an answer, not a failure. A served record that verifies at the name is an answer,
also when it is below the floor.

**D3 — The caller sees a retryable unavailable error.** A command returns `EngineError::Seam`,
not `EngineError::TrustViolation`. A queued op does not dead-letter. It stays in the queue, and
the next pass reads the name again. The host shows the same retry that it shows for any other
unavailable endpoint.

**D4 — When every endpoint answered, a below-floor pick stays a trust violation.** Each endpoint
answered with a record or with "no record", and the freshest record is below the floor. The
gate refuses it as a trust violation, pins last-known-good and sends the trust event, as AGENTS.md
rule 6 and the floor law require. For a command (for example a revoke), the trust violation that
the command returns as its error is the trust event, and the command sends no separate abuse event.

## Alternatives considered

- **Keep the trust violation for every below-floor pick.** No change to the gate. Rejected: a
  short outage of one endpoint, while the other lags one sequence, raises a false accusation
  and stops the op for good. On staging this occurs on ordinary use.
- **A publish waits for the ack of every endpoint.** The lag then cannot follow a publish that
  this device made. Rejected: each publish waits for the slowest endpoint, and an endpoint that
  was down at the publish, or a cold endpoint, still serves an old record later.
- **Treat a below-floor pick as staleness always.** No trust event for any below-floor record.
  Rejected: when every endpoint answered, a below-floor record is the shape of a rollback, and
  this rule hides it.

## Consequences

- `blueprint/engine.md` "Adoption gate and floors": the paragraph "A gate failure is never mere
  staleness" states the exception of D1 and D2, and the rule of D4.
- `blueprint/engine.md` "Resolve/publish pipeline": the fan-out resolve bullet states that a
  below-floor pick with a failed endpoint reads as unavailable.
- `blueprint/testing.md` engine suite: a test with two endpoints where one lags one sequence and
  the other fails gets `EngineError::Seam` and no trust event, for a revoke and for a read; the
  same test with both endpoints up, where both serve the old record, gets a trust violation; the
  revoke succeeds after the failed endpoint recovers. The fix test fails on the code before
  this ADR.
- `CONTEXT.md` "Adoption gate": the list of exceptions to "a failure is a fail-closed trust
  violation" adds D1, with the cite of this ADR.
- No ADR needs an "Amended by" sentence. ADR 0066 covers a record at the floor, and ADR 0003
  covers the epoch stage.

## Residuals

- An attacker who blocks one endpoint and serves an old copy from another now gets
  "unavailable", not a trust event. The withheld-update escalation covers shared scopes alone.
  Does such a hold need a stronger signal on an owned scope, for example after a number of
  unavailable reads in a row?
- D2 leaves some answers open. The code (`net::fanout`) now reads these as a failed endpoint: no
  answer, a timeout, a connection or TLS error, a 5xx, a 408, a 429 and a 3xx. It reads these as
  an answer: a 404, another 4xx, a body over the size cap, bytes that do not decode, and a record
  that does not verify at the name. The owner can move 408 and 429 back to "answer". Is this
  split correct?
- On the web host, a 4xx with no CORS header reaches the engine with no status, so it reads as a
  failed endpoint there and as an answer on the desktop host.
