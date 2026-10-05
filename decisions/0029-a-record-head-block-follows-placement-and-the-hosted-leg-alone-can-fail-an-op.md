# ADR 0029 — A record head block follows placement, and the hosted leg alone can fail an op

- **Status:** Accepted on 2026-09-26 — retroactive for D2 to D15, which the blueprint carries. D1
  is an owner decision of 2026-09-26 that the code follows since 2026-10-02 (E1). Trimmed on
  2026-09-26 to the items that pass the three ADR hurdles; the removed items live in the blueprint
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
  D12), FSM1/cipher-box#1585 (the in-session re-decide and the staging read leg, D13 and D14),
  FSM1/cipher-box#932 (the BYO endpoint policy, D15) and FSM1/cipher-box#2234 (D1 and D16). The
  decision source for D3, D9 and D11 is the resolution of FSM1/cipher-box#822 (2026-07-27).

## Context

The pin mode is `Hosted` (the default), `External` (the member's own provider only) or `Dual`
(both). #34 D1 fixed the three modes and decided nothing else about the byte path. The hosted
ingress refuses every upload from an account whose two-state `users.byo` flag is set. So
`PinMode` is a client-side placement policy. The drain is strict FIFO and stops at the first
failure (`blueprint/engine.md` "Sync core"). The BYO endpoint can come from a resolved record,
and the provider probe carries the member's bearer.

## Decision

**D1 — A record head block follows placement, the same as a content version.** Under `Hosted`
the head block goes to the hosted store. Under `Dual` it goes to both legs, and D3 applies.
Under `External` it goes to the member's own node only, and the API sees the registration and
nothing else. On every leg the record-plane publish compares the address the leg returns against
the head block's own address, and a mismatch publishes nothing. Owner decision of 2026-09-26; it
replaces the rule of FSM1/cipher-box#1072 (alternative (i)).

**D3 — Dual runs both legs, and only the hosted leg can fail the op.** Both legs retry inside the
op. The op completes when the hosted leg succeeds and the external leg has succeeded or used all
its attempts. The external outcome is reported once per op, and no retry is queued for it. Under
`External` the member's provider is the byte path, so its refusal is the op's. Decided on
2026-07-27 in the resolution of FSM1/cipher-box#822, section 3.

**D11 — `users.byo` has two states, and `byo=true` means exactly `External`.** `Hosted` and
`Dual` both run `byo=false`; dual has no server representation. The engine reconciles the flag
against the vaulted mode. Decided on 2026-07-27 in FSM1/cipher-box#822, sections 1 and 7.

**D15 — One BYO endpoint policy gates the whole config, and its verdict comes from the
literal.** The gate applies alike to a typed config and to a resolved one, release-active on the
encode side. `https` is required off loopback, because the probe carries the member's bearer.
Private and link-local ranges stay allowed; self-hosting on a LAN is the feature. The engine has
no resolver, so the cloud-metadata refusal is a legibility rule, not SSRF containment. The rule
list is the `blueprint/engine.md` "BYO endpoint policy" bullet (FSM1/cipher-box#932).

**D16 — The member's own node keeps what the member puts on it.** For v2.0, retire and prune
release only the registry rows. They send no unpin to the member's provider, and the member prunes
that node with their own tools. The node has no reference count, so an unpin for each op can
remove a block that a live version still names. Owner decision of 2026-10-02
(FSM1/cipher-box#2007), added in FSM1/cipher-box#2234.

Items D2, D4 to D10, D12, D13 and D14 moved to `blueprint/engine.md` "Content plane" on 2026-09-26.

## Alternatives rejected

**(a) Both legs must succeed in a dual write.** An offline home node or a rate-limited pin
service then stalls every later mutation in the strict-FIFO drain. Rejected for D3.

**(b) Either leg is enough in a dual write.** The API then has no pin row; quota and retire break.

**(c) Teach the server all three modes with a `pin_mode` column.** It costs a migration and an
edit to a live trust gate, for a mode the engine already knows. Rejected for D11.

**(d) Derive the mode from `users.byo` and the presence of a provider config.** It deletes a real
state: turning dual off would delete the provider config. Rejected for D11.

**(h) Resolve the endpoint host to classify it.** The engine has no resolver, and a resolved
verdict is a time-of-check to time-of-use gap. Rejected for D15.

**(i) Keep every record head block on the hosted ingress, and exempt heads from the `byo`
refusal.** A CipherBox outage then blocks every BYO write and uncached BYO read, and the
exemption needs a new wire signal. The owner rejected it on 2026-09-26 for D1.

**(j) Unpin on the member's Kubo when the retire ledger settles a target.** It needs a durable
member-leg flag on each ledger entry, and PSA and Pinata stay out of reach. Rejected for v2.0
by D16; FSM1/cipher-box#2244 holds it.

## Trust argument

- **D1:** a record head and its content share the legs, so a BYO read needs only the member's node.
- **D3:** no provider outside CipherBox can hold the strict-FIFO drain.
- **D11:** the server stores only what it enforces, and the client owns the three-way choice.

## Consequences

- `blueprint/engine.md` "Content plane" states every item of this ADR and cites it.
- #34 D1 is confirmed: "BYO bytes bypass it" covers the record head block too.
- D16: under `External` and `Dual` the member's node grows without bound until the member prunes it.

## Residuals

**E1 — The code lagged D1, and under `External` the device was locked out of every publish.**
`publish_record` in `net::record_publish` sent every record head block to the hosted ingress,
which refuses a `byo=true` account with a 409. After the first file write set `byo=true`, every
later op dead-lettered, every settings save failed, and the app could not clear the flag. No suite
modeled the 409. Resolved on 2026-10-02 by FSM1/cipher-box#2234: a record head block follows
placement, and a save that leaves `External` clears `byo` first.

**E3 — An assumed placement on a `Dual` account drops the mirror without a signal.** A `Dual`
account runs `byo=false` (D11). So on a fresh device whose settings record is withheld, the
assumed `Hosted` default writes one copy, and nothing tells the member that the mirror dropped.

## Gate

The Rust area of the PR gate (the workspace tests) and `Contract Suite Result` block the merge.
