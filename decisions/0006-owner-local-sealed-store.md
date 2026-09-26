# ADR 0006 — Owner-local durable state is sealed under one kind-separated structure

- **Status:** Implemented — the structure landed in FSM1/cipher-box#1215 (merged), and all
  three stores sit on it after FSM1/cipher-box#1234 (merged): received shares, the contact
  book, and invite records. The invite-record store has no production caller yet, because
  `Command::CreateInviteLink` has no mint path (FSM1/cipher-box#1240)
- **Date:** 2026-08-08
- **Supersedes:** the per-store sealed format established by
  `crates/core/src/seal/received_shares.rs`, which this decision folds into the
  generic structure
- **Relates to:** [#6](https://github.com/FSM1/cipher-box-next/issues/6) (the clean break —
  why the migration is free before the staging cutover) and
  [#39](https://github.com/FSM1/cipher-box-next/issues/39) decision D8 (the separation
  discipline this decision applies to structures rather than KDF edges)
- **Implemented by:** [FSM1/cipher-box#1214](https://github.com/FSM1/cipher-box/issues/1214)
  (closed), which also migrated `received_shares` onto the structure and deleted the
  per-store module. Consumed by
  [FSM1/cipher-box#1207](https://github.com/FSM1/cipher-box/issues/1207) (closed — the
  contact book) and [FSM1/cipher-box#1165](https://github.com/FSM1/cipher-box/issues/1165)
  (open — the invite-record store is built and sealed, and waits on a mint path to call it)

## Context

Three stores hold state the owner alone authors and reads, carried over the host's
`StagingStore` seam rather than over the network. They answer the integrity question three
different ways:

| Store           | Today                                                  |
| --------------- | ------------------------------------------------------ |
| received shares | sealed HPKE-to-self, its own version and `info` string |
| contact book    | plaintext deterministic CBOR under the same seam       |
| invite records  | does not exist yet                                     |

The host is not a trusted party. It is the same posture the network gets: bytes it returns
are input to verify, not state to believe.

For the contact book the cost of getting this wrong is disclosure — the owner's whole
contact graph is readable by anything with local storage access.

For the invite store the cost is an authority break. `convert_invite_claim` matches a
claim's sender against the recorded `ephemeralIdentityPk`, re-derives the link's tag from
the recorded `ephemeralEncPk`, and reads the permission from the owner-signed commitment by
that tag. The tag binds the **encryption** half only, so `ephemeralIdentityPk` is bound by
nothing in the record. A party who can write the store pairs a real link's `ephemeralEncPk`
— which re-derives to a tag matching a real committed entry, carrying its real permission —
with an identity key it holds, and a claim signed by that key converts. The owner mints a
genuine grant at up to `Write`, with no owner key material involved. The recorded deadline
is the authority for expiry too, so an expired link is resurrected the same way.

An unauthenticated owner-local store is therefore not a deferred hardening item. It is the
authority that conversion trusts.

## Decision

**One generic owner-local sealed structure in `crates/core`, with the store kind bound into
the HPKE `info`.** Every owner-local durable store uses it: invite records, the contact
book, and received shares.
Amended by ADR 0030 D11 on 2026-09-26: every owner-local durable store and every per-owner staging
surface seals on the owner-local structure, in auth mode to the owner, each under its own kind. The
kind list is not closed: at the time of the blueprint it is `received-shares`, `contact-book`,
`retire-ledger` and `doomed-journal`, and the manifest holds three more (ADR 0030 E8).

`received_shares` migrates onto it and its per-store module is deleted.

## Alternatives rejected

**A third per-store module, copied from `received_shares.rs`.** Domain separation would be
correct by construction, since each store's `info` string differs — a real advantage, and
the reason this alternative is close. Rejected because it multiplies the fail-closed load
logic across three modules that then drift. That logic is not trivial and has already been
got right twice under review pressure: a stored list this build cannot read must surface as
an error and never as an empty list, because the next persist would overwrite bookmarks it
never saw. Three copies means three chances to lose that property, and it is exactly the
kind of rule that decays in the copy rather than in the original.

**Leaving the contact book in the clear and the invite store unsealed.** Fastest, and it
ships the authority break described above. The invite store cannot be added unsealed even
temporarily: it is created and consumed by the same slice.

**Sealing under the owner's existing per-record formats.** The op-record and grant-blob
structures are network-shaped: they carry sender authentication and recipient binding that
owner-local state has no use for, and their versions are governed by wire compatibility this
state does not participate in.
Amended by ADR 0030 D11 on 2026-09-26: the op-record and grant-blob structures are network-shaped,
and the reason not to reuse them is their framing and their versioning, which wire compatibility
governs and owner-local state does not share.

## Consequences

1. **The kind discriminator is the new failure mode, so it is pinned by a KAT.** A blob
   sealed under one kind must fail to open under another, proven by a vector rather than by
   a unit test alone. Separate `info` strings gave this property for free; a discriminator
   has to earn it. Binding the kind into the `info` rather than only into the payload is
   what makes the failure a decryption failure instead of a parse failure.
2. **The migration is free now and is not free later.** v2 has never been deployed, and #6
   makes the staging cutover a redeploy rather than a migration, so redefining the
   received-shares format today costs nothing beyond the edit. After the cutover the same
   change is a data migration on real accounts.
3. **`blueprint/core.md` gains the new structure and loses the per-store entry** it
   replaces.
4. **Encode/decode symmetry applies.** Every invariant the open path hard-rejects gets a
   release-active check on the seal path returning an error, never a `debug_assert!`, so a
   release build cannot seal bytes its own opener refuses.
5. **The seam count does not change.** These stores are carried at the layer that owns them
   over the `StagingStore` seam every host already provides, on the `RetireLedger`
   precedent. This decision is about the bytes, not about where they live.
   Amended by ADR 0030 D11 on 2026-09-26: the retire ledger is not a precedent for the seam only,
   because its values now seal on the owner-local structure too.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The
`blueprint/` copies in this repository are the as-charted archive and are not edited by this
ADR.
