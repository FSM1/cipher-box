# ADR 0052 — The stage-3 section predicate lives in core behind a verified-commitment witness

- **Status:** Proposed
- **Date:** 2026-09-26
- **Relates to:**
  [core: move the adoption gate's stage-3 section authentication into crates/core behind a verified-commitment witness (#1131)](https://github.com/FSM1/cipher-box/issues/1131)
  (the owner decision of 2026-08-20 in its comment),
  [engine: close the residual stage-3 trial-verify amplification by pinning the section's signer (#1102)](https://github.com/FSM1/cipher-box/issues/1102)
  (the pin, landed by FSM1/cipher-box#1120),
  [ADR 0032](./0032-the-owner-signs-each-grant-row-and-the-commitment-names-every-recipient.md)
  D8 (one section, one signer),
  [ADR 0033](./0033-every-attacker-sized-field-has-one-canonical-form-and-a-symmetric-fail-closed-bound.md)
  D2 (the section bounds and their reason; moved to `blueprint/core.md` "Grant section"), the `blueprint/core.md` "Grant section" and
  "Structure signatures" sections, the `blueprint/engine.md` "Adoption gate and floors" section
  (stage 3 and "One section, one signer"), and the `CONTEXT.md` "Adoption gate" term
- **Amends:** ADR 0032 D8 (the home of the predicate) and ADR 0033 D2 (the citation of the
  bound's reason)

## Context

Stage 3 of the adoption gate authenticates every seed-bearing structure of a `GrantSection`
under one committed write-capable pseudonym (ADR 0032 D8). The predicate lives in
`crates/engine/src/gate/adoption.rs`: `authenticate_section_structures`, the walk
`for_each_structure`, the set `committed_write_pseudonyms`, and the pin `StructureAuthenticator`.
The header of that module states that the gate holds "no crypto, no codec, and no cryptographic
error code of its own". Stage 3 contradicts that statement.

The layers are inverted in four places:

- **Core justifies its bounds with an algorithm it cannot see.** `MAX_HISTORY_LINKS` and
  `MAX_GRANT_BLOBS` in `crates/core/src/seal/section.rs`, and `blueprint/core.md`, cite the
  engine's `pseudonyms + structures` bound. No gate couples them. A change to the engine scan
  falsifies two core surfaces with no signal.
- **The verdict is core's.** `structure-signature-invalid` is a `TrustViolation` check that core
  defines and the KAT manifest names. The engine emits a core verdict for a condition that core
  does not define.
- **The stage-2 precondition is prose.** The predicate authenticates structures against the
  pseudonyms that the section's own commitment names. It is a trust verdict only after
  `verify_grant_set` anchored that commitment to the owner identity. Today a doc comment on a
  `pub fn` carries that order.
- **The walk is exported for tests only.** `for_each_structure` and `committed_write_pseudonyms`
  are `#[doc(hidden)] pub` so that the engine KAT generator and suite can reach them.

The set of engine readers of the committed write-capable set grew after the issue was filed.
`write_body_signer` names the party that an abuse event over a rewritten row charges, and the
cascade plane stores its result. `is_committed_write_pseudonym` binds a re-seal's own signer to
the set on the produce side. Both recompute the same set as stage 3 and must not disagree with it.

The issue recorded a counter-argument: stage 3 is gate policy, not a primitive, and a move
drags "which entries are write-capable" into core. The owner weighed it on 2026-08-20 and
declined it. Core already owns `Permission`, `GrantSetCommitment`, `GrantSection`, every
`STRUCT_TAG_*`, `verify_grant_set` and `verify_structure`. The data model crossed the
policy-versus-primitive line before the predicate did. What core lacks is the composition of
things it already has.

## Decision

**D1 — The stage-3 predicate lives in `crates/core`.** `authenticate_section_structures`, the
structure walk, the committed write-capable set, the single-signer pin, and the write-body signer
lookup move into a core module beside the grant section. The engine's stage 3 becomes one call.
`crates/engine/src/net/author.rs::check_scope_root` and `rotation/reseal.rs` call the same core
functions. No engine code exports a stage-3 helper.

**D2 — A verified commitment is a type.** `verify_grant_set` and `verify_grant_set_bound` return
a `VerifiedGrantSet` witness on success. The witness borrows the commitment and carries no
secret. The stage-3 predicate takes the witness, not the commitment:

```rust
pub fn authenticate_section_structures(
    commitment: &VerifiedGrantSet<'_>,
    section: &GrantSection,
    scope: [u8; 16],
    epoch: u64,
) -> Result<(), CodecError>
```

A caller cannot reach stage 3 with a commitment that stage 2 did not anchor. The witness has no
public constructor outside the two verify functions.

**D3 — The committed write-capable set is a core definition.** The set is the owner pseudonym
plus the pseudonym of every entry with `Permission::Write`, with repeats removed. Core exposes the
set and its membership test. Every reader of the set in the engine uses the core definition.

**D4 — The mixed-signer reject vector moves into the core KAT `grant` family.** The
`structure-signature-invalid` check of the mixed-signer case rides the core reject harness. The
engine gate KAT keeps only what the engine composes: the stage order, the stage that a rejection
names, and the floor comparisons.

**D5 — Each blueprint states its own bound.** `blueprint/core.md` owns "One section, one signer"
and the `pseudonyms + structures` bound, beside the section bounds that the rule justifies.
`blueprint/engine.md` keeps stage 3 in the six-stage list and points at the core predicate for its
content. `crates/core/src/seal/section.rs` cites `blueprint/core.md`, not `engine.md`.

**D6 — Stage 3 stays a stage of the engine pipeline.** The engine keeps the order of the six
stages, the `GateStage::GrantSection` name that a rejection carries, and the floor reads around
it. The move changes which crate owns the predicate, not where the gate runs it.

## Alternatives considered

**(a) Keep the predicate in the engine.** The counter-argument in the issue. Rejected by the
owner on 2026-08-20 for the reason in the context: the data model already put every constituent
in core.

**(b) A doc comment as the stage-2 precondition.** The state today. Rejected. A precondition that
the type system can enforce must not depend on a reader.

**(c) Move the predicate and keep the commitment as its input.** Rejected. Without the witness a
core caller can authenticate a section against an unverified commitment, and the predicate then
returns a trust verdict that nothing anchored.

## Consequences

1. **`blueprint/core.md` changes.** "Grant section" gains "One section, one signer" and the
   `pseudonyms + structures` bound as its own statement. "Structure signatures" states the
   witness input of D2.
2. **`blueprint/engine.md` changes.** Stage 3 in "Adoption gate and floors" becomes one sentence
   that names the core predicate. The "One section, one signer" paragraph moves to `core.md`, and a
   one-line cross-reference stays.
3. **`CONTEXT.md` does not change.** "Adoption gate" names the six stages, not their home.
4. **The code move is one PR.** It touches `crates/core` (`seal/grant.rs`, `seal/section.rs`, one
   new module, the KAT manifest and `examples/kat_gen.rs`) and the engine gate, `net/author.rs`,
   `net/rotation.rs`, `rotation/reseal.rs`, `rotation/rotate_write.rs`, `rotation/trigger.rs`, the
   engine KAT generator, and the engine gate tests. The move changes no wire format and no KDF
   edge, so no KAT vector changes its bytes.
5. **The blueprint reword lands in the code PR.** The reword follows acceptance of this ADR, in the
   same PR as the move, so the blueprint and the code cross the boundary together.
6. **`crates/core` defines which entries are write-capable.** This is the accepted cost of the
   declined counter-argument. A later permission kind that can sign a structure changes D3 in
   core, with a KAT vector.

## Residuals

**E1 — The engine still holds a copy of the committed set on the cascade plane.** `write_body_signer`
stores one pseudonym per plane. That copy is a cache of a core result, not a second definition.
