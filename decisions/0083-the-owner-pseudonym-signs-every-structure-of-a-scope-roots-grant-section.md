# ADR 0083: The owner pseudonym signs every structure of a scope root's grant section

- **Status:** Proposed
- **Date:** 2026-10-29
- **Relates to:** [FSM1/cipher-box#2537](https://github.com/FSM1/cipher-box/issues/2537),
  [ADR 0082](./0082-a-grantee-cannot-move-a-node-across-the-edge-of-a-received-share.md),
  [ADR 0077](./0077-a-scope-root-stops-being-one-by-a-re-seal-into-new-node-ids.md)
- **Implemented by:** [FSM1/cipher-box#2544](https://github.com/FSM1/cipher-box/pull/2544)
- **Amends:** [ADR 0032](./0032-the-owner-signs-each-grant-row-and-the-commitment-names-every-recipient.md)
  D6, D8, Alternative (k), the "Trust argument" items on the veto and the ascent swap, E6 and E7;
  [ADR 0052](./0052-the-stage-3-section-predicate-lives-in-core-behind-a-verified-commitment-witness.md)
  Context and D3; [ADR 0025](./0025-revocation-under-the-link-first-model.md) E3;
  [ADR 0030](./0030-a-record-the-owner-alone-authors-and-that-seals-hpke-to-the-owner-seals-in-auth-mode.md)
  D10, the "Trust argument" item "#39 D2 does not conflict" and E6;
  [ADR 0033](./0033-every-attacker-sized-field-has-one-canonical-form-and-a-symmetric-fail-closed-bound.md)
  Context, E3 and E4;
  [ADR 0074](./0074-a-personal-grantee-takes-the-scope-pointer-name-from-the-owner-signed-share-pointer.md)
  the alternative "The grant blob carries the name"

## Context

Stage 3 of the adoption gate accepts a grant section from any committed write-capable pseudonym
(ADR 0032 D8). So a modified write grantee can sign a flat cut of a received scope root, and every
owner device adopts it. The cut can move the read epoch to `u64::MAX`. Then no owner read cut of
that scope can run, and a revoke cascade stops at that scope. Thus a grantee vetoes its own
revocation, which ADR 0032 "Trust argument" does not permit. No honest path signs a section with a
grantee pseudonym: every production re-seal signer is the owner pseudonym, and a grantee write at a
scope root carries the section verbatim.

## Decision

**D1 — Stage 3 accepts a scope-root grant section only when its one pinned signer is
`commitment.ownerPseudonymPk`.** Core's `authenticate_section_structures` pins the owner pseudonym
that the verified commitment names. Every structure of the section must verify under that key. A
section that any other pseudonym signs is a whole-record trust violation
(`structure-signature-invalid`, class trust). This includes a section that a committed write
grantee signs. The wire format does not change. Each `pseudonymPk` of a `write` entry stays in the
commitment, but no structure of a scope root verifies under it.

## Alternatives considered

- **No gate change, and one line in the corpus (Option A).** Rejected. A write grantee keeps the
  power to raise the read-epoch floor of every device to `u64::MAX`, so the revocation veto stays.
- **The commitment carries the read epoch (Option C, ADR 0032 Alternative (k)).** Rejected. It
  changes the commitment preimage and its KAT vectors, and it needs a migration of every scope root.
  It also leaves open a seed swap at the same epoch.
- **An engine rule on the epoch rise by a non-owner signer (Option D).** Rejected. It depends on
  device state and still accepts a grantee seed swap at the same epoch.
- **A rule that bounds every epoch rise to + 1 (a variant of Option D).** Rejected. It gives false
  trust violations on a cold device and on a device that missed two owner cuts.

## Consequences

- KAT `grant` family: the vector `single-signer-committed-grantee` moves from `sectionSignerAccept`
  to `sectionSignerReject` (`structure-signature-invalid`). This makes the frozen acceptance domain
  smaller, so it is a change to the frozen contract. `build_section_signer_vectors` in the KAT
  generator mints the vector, and the vector counts change.
- The produce side `check_scope_root` calls the same core predicate, so it refuses a non-owner
  section release-active (AGENTS.md rule 8).
- `blueprint/core.md` "One section, one signer" and "Structure signatures" state that the pinned
  signer is the owner pseudonym, and name the KAT change.
- `blueprint/engine.md` "Adoption gate and floors" stage 3 states the same rule.
- `CONTEXT.md` "Structure signature" and "Writer pseudonym" state that the owner pseudonym signs
  the structures of a scope root.
- ADR 0032 D8 carries an "Amended by" sentence. ADR 0032 "Trust argument" ("A write grantee cannot
  veto its own revocation") holds again. ADR 0032 D6, Alternative (k), "An ascent swap is
  attributable", E6 and E7 carry "Amended by" sentences, and the D8 gate tests take the new names.
- ADR 0052 Context and D3 carry "Amended by" sentences: stage 3 work is linear in the number of
  structures, and core exposes no membership test of the committed write-capable set.
- ADR 0025 E3 and the `blueprint/engine.md` sharing residual: a grantee cannot edit
  `directChildScopeIndex`, but can replay an older owner-signed write body of the same epoch.
- ADR 0030 D10, its "#39 D2 does not conflict" item and E6, ADR 0033 Context, E3 and E4, ADR 0074
  "The grant blob carries the name", `CONTEXT.md` "Grant ledger" and `docs/SHARING.md` "Revoke a
  person" drop the claim that a write grantee signs a write body or a grant blob.
- ADR 0077 alternative "Any epoch rise re-seals every node again (D4)" cites this ADR.
- The engine's `report_unattested_row` signer attribution always names the owner. A later change
  can simplify it.
- Cost: a future grantee re-seal of a scope root needs an owner step or a new ADR. An old client
  accepts a grantee-signed section and a new client refuses it, so a later relaxation splits old and
  new clients.
- `decisions/README.md` lists ADR 0083.

## Residuals

- [FSM1/cipher-box#2542](https://github.com/FSM1/cipher-box/issues/2542): a write grantee can drop
  the grant blob of a peer from a carried section. Each remaining signature stays valid. Is a rule
  "one grant blob per committed entry" necessary?
