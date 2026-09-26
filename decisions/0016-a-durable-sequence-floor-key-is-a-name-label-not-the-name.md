# ADR 0016 — A durable sequence-floor key is a name label, not the name

- **Status:** Accepted — implemented in FSM1/cipher-box#1760 (merged)
- **Date:** 2026-09-05
- **Relates to:**
  [#39](https://github.com/FSM1/cipher-box-next/issues/39) D8 (the frozen KDF edge catalog),
  [ADR 0015](./0015-the-device-approval-factor-seal-is-in-repo-ecies-on-secp256k1.md)
  D2 (what a catalog edge is),
  [FSM1/cipher-box#1567](https://github.com/FSM1/cipher-box/issues/1567) (the contact label
  blinds the epoch namespace), and
  [FSM1/cipher-box#1703](https://github.com/FSM1/cipher-box/issues/1703) (the defect this ADR
  settles)
- **Implemented by:** a wave-18 lane in FSM1/cipher-box, after acceptance

## Context

The engine keeps two durable floors per device. The epoch floor is keyed by scope id, and the
sequence floor is keyed by the `ipnsName` of the record it bars replay on. Both live in the
floor store, which is plaintext IndexedDB on web and a plaintext journal on desktop. The owner
view of the store prefixes every key with a 32-byte tag of the account, so two accounts in one
container never share a key.

[FSM1/cipher-box#1567](https://github.com/FSM1/cipher-box/issues/1567) found that a sharer's
epoch-floor key named the granting contact, and closed it: the sharer view prefixes the epoch
namespace with the contact label, which is the `contact-label` edge over the account's
`contactLabelSeed`. The sequence namespace passes through that view unprefixed, on purpose. One
`ipnsName` keeps one sequence ratchet, whoever reads it, and the test
`sequence_floors_stay_shared_across_sharers` pins that. A per-contact prefix would give one name
two ratchets and weaken the replay bar.

So the durable sequence key of a granted scope root is the owner tag followed by the raw
`ipnsName`. [FSM1/cipher-box#1703](https://github.com/FSM1/cipher-box/issues/1703) states the
disclosure. A reader of local storage recovers the set of scope-root names this device holds
shares for. Each name resolves on the public record plane to a scope root whose grant section
carries the owner's compact ECDSA signature, and secp256k1 permits public-key recovery from a
signature and its message. Local storage plus network access therefore names the granting
identity. The same store keys the revision marks of the owner's settings record and bin index
as a fixed prefix followed by the raw name, so those keys name the owner's own records too.

The fix is one transform of the key. It must be one-way, because the key must carry no run of
the name. It must take a secret input, because a scope-root name is public, so an unkeyed digest
is inverted by a reader who collects published names. It must not depend on the contact, so
that one name still maps to one key for every reader in the account. The catalog holds no edge
with that shape: `contact-label` takes a fixed 33-byte identity key, `blinded-tag` takes a
pairwise ECDH secret and publishes its output, and every other edge takes a fixed-length
message. The catalog is frozen under [#39](https://github.com/FSM1/cipher-box-next/issues/39)
D8, so a new edge needs this record.

## Decision

**D1 — The KDF edge catalog gains one edge, `name-label`.** Its inputs are `contactLabelSeed`
and one sequence-namespace key. Its output is a 32-byte label. Its form is
`keyed_hash(key = derive_key("cipherbox/v2/name-label", contactLabelSeed), message = key bytes)`.
The message is the whole sequence-namespace key as the engine passes it today, so a raw
`ipnsName` and a prefixed revision-mark key each label to distinct bytes. The message is
variable-length. The catalog rule forbids a variable _context_, and this edge keeps its context
fixed; BLAKE3 `keyed_hash` is a pseudorandom function over a message of any length, so a
variable message is sound.

**D2 — The seed is `contactLabelSeed`.** It is the account's alone, it is device-only, its
output never reaches the wire, and the session holds it at `Engine::start`. The `name-label`
edge extends the contact-label pair's stated property to a second kind of durable state: a key
that would otherwise name a record in the clear. No other seed gains a consumer.

**D3 — The blind sits in the owner view, on the sequence arm only.** `OwnerScopedFloorStore`
labels every sequence-namespace key before it prefixes the owner tag, so the durable key is the
owner tag followed by the label, fixed at 64 bytes. Every sequence raise in the engine passes the
owner view, on the owner path and on the sharer path, so one name keeps one durable key and one
ratchet. `SharerScopedFloorStore` keeps its contact-label prefix on the epoch namespace and
stays transparent on the sequence namespace. The epoch namespace does not change: a scope id is
sealed body content, not a public name.

**D4 — The owner view binds `contactLabelSeed` beside the encryption secret.** The bind at
`Engine::start` is the one place a session's secrets reach the store, and a read or raise before
the bind refuses, as today.

**D5 — The key shape changes with no migration.** This is the same term the epoch prefix took
under the greenfield rule: a device that holds pre-cutover floors reads none of them back and
re-seeds from the record plane. The cutover note records it.

**D6 — The engine test that pins the residual now pins its closure.** The doc block on
`SharerScopedFloorStore` drops the residual sentence #1567 added. A test asserts that no durable
sequence key carries a run of the name bytes, and `sequence_floors_stay_shared_across_sharers`
stays and gains the owner view beside the sharer views.

## Alternatives rejected

**An unkeyed digest of the name.** A scope-root name is public on the record plane. A reader of
local storage who also collects published names inverts the digest by trial, at one hash per
name. Rejected.

**A per-contact prefix, as the epoch namespace uses.** One name would hold one ratchet per
contact view and one more for the owner view, and a record replayed under one view would pass
the bar another view had already raised. That is the property
`sequence_floors_stay_shared_across_sharers` exists to keep. Rejected.

**A keyed hash under the owner tag or the encryption secret, outside the catalog.** AGENTS.md
rule 5 forbids a derivation outside the frozen catalog, and the encryption subkey is a
wire-facing key whose roles must not grow. A hidden derivation in the engine is the kind of
drift the catalog exists to stop. Rejected.

**Blind only the sharer view.** Four owner-path callers raise the sequence floor on the bound
store directly, so one name would hold two durable keys, one labelled and one raw, and the raw
one still discloses the name. Rejected.

**Defer to post-cutover.** After the cutover a key shape change needs a migration of every
device's floor store, which the greenfield rule spares now, and v2.0.0 would ship the
disclosure. Rejected.

## Consequences

1. **`blueprint/core.md` changes when this ADR is accepted.** The KDF edge catalog table gains
   the row `name-label | contactLabelSeed, sequence-namespace key | a local label for a durable
sequence key`, and the contact-label paragraph names the second consumer of the seed.

2. **The KAT manifest and its generator change.** `crates/core/src/kdf/mod.rs` gains the
   context string and the edge, the probe set gains a `name-label` vector over a fixed key
   message, and the frozen string table gains one entry.

3. **`crates/engine/src/seams/floor_store.rs` changes.** The owner view labels the sequence arm
   and binds the seed; the sharer view's doc block drops the residual sentence.

4. **`CONTEXT.md` gains one term, `name label`:** the durable label a sequence-namespace key
   takes under the account's `contactLabelSeed`.

## Residuals

**E1 — The account itself can recompute the label.** A reader who holds the login secret
derives `contactLabelSeed` and inverts nothing, because that reader is the account. The label
denies the name to a reader of local storage alone.

**E2 — The store still shows how many names a device holds and how each ratchet moves.** The
label hides which record a key names. It hides neither the key count nor the counter values.
That is the same exposure the epoch namespace keeps after #1567.

**E3 — A pre-cutover store holds raw names until it is forgotten.** D5 forgets rather than
upgrades, so a device that skips the cutover keeps the old keys in place. The cutover note
carries that.

**E4 — One seed now keys two kinds of label.** The contexts differ, so a contact label and a name
label never collide, and a compromise of the seed exposes both labels together. They were
already one secret's worth of exposure: the seed is one derivation from the login secret.

## Gate

- The KAT manifest holds `cipherbox/v2/name-label` in the frozen string table and one
  `name-label` probe vector.
- `blueprint/core.md` holds the `name-label` row in the KDF edge catalog table.
- An engine test asserts that no durable sequence-floor key carries a run of the `ipnsName`
  bytes, on the owner path and on the sharer path.
- `sequence_floors_stay_shared_across_sharers` passes with the owner view added.
- The `SharerScopedFloorStore` doc block carries no residual sentence about the sequence
  namespace.
- `CONTEXT.md` defines `name label`.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
