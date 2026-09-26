# ADR 0005 — The owner's writer pseudonym derives from a dedicated `owner-pseudonym-seed` edge

- **Status:** Accepted — implemented in FSM1/cipher-box#1211 (merged)
- **Date:** 2026-08-08
- **Amends:** [#39](https://github.com/FSM1/cipher-box-next/issues/39) decision D2
  ("The primitive: committed writer pseudonyms") — makes concrete the trailing clause
  "the owner's own pseudonym derives from her root secret", which names no field and has
  no implementable referent
- **Relates to:** [#39](https://github.com/FSM1/cipher-box-next/issues/39) decision D8
  (the frozen KDF edge catalog and its separation KAT) and
  [#34](https://github.com/FSM1/cipher-box-next/issues/34) (the contact-code-anchored
  owner identity)
- **Implemented by:** [FSM1/cipher-box#1163](https://github.com/FSM1/cipher-box/issues/1163)

## Context

D2 fixes the writer pseudonym for a grantee exactly:
`pseud(scope, W) = derive(ECDH(ownerEnc, wEnc) ‖ scopeId, "pseudonym-sign")`. The owner
half is given only as "the owner's own pseudonym derives from her root secret". The v2
KDF catalog carries that phrasing forward verbatim, as the parenthetical in

```text
| pseudonym-sign | ECDH(ownerEnc, writerEnc) ‖ scopeId (owner: root secret) | Ed25519 pseudonym keypair |
```

Nothing binds "root secret" to a concrete value. `SessionIdentity` holds four secrets —
`login_secret`, `enc_subkey`, `owner_pointer_seed` and `identity` — and none is
designated the pseudonym input. `SessionIdentity::writer_pseudonym_signer` already
composes the edge, but takes the pairwise material as a parameter, so the composition
exists and its owner-side input does not.

The consequence is not cosmetic. `OwnerScopeKeys` has **no production implementor**: its
only two are inside `#[cfg(test)]`, and both feed `pseudonym_sign` a test constant. The
owner arm of the rotation net is otherwise production code, so this one undefined input
is what keeps `Command::RotateNow`, `Command::Revoke` and `Command::Downgrade` from
reaching a rotation primitive at all.

These bytes are permanent. They key the Ed25519 pair that detached-signs every
seed-bearing structure the owner re-seals, and a mismatch is a whole-record trust
violation at the adoption gate, not a recoverable staleness.

## Decision

**Add a dedicated catalog edge, `owner-pseudonym-seed`, from the login secret, and make
it the owner's `pseudonym-sign` input.**

```text
| owner-pseudonym-seed | login secret | ownerPseudonymSeed |
| pseudonym-sign | ECDH(ownerEnc, writerEnc) ‖ scopeId (owner: ownerPseudonymSeed) | Ed25519 pseudonym keypair |
```

It takes the same shape as its neighbour `owner-pointer-seed`: a fixed edge context over
the login secret, with the per-scope split supplied by `pseudonym_sign`'s existing
`scopeId` argument. D8's separation KAT extends to cover it, so it cannot collide with
`owner-pointer-seed`, `enc-subkey` or any other edge on equal inputs.

The grantee half of D2 is untouched.

## Alternatives rejected

**Self-ECDH — `ECDH(ownerEnc, ownerEnc)`.** Superficially the tidiest: the owner becomes
a degenerate writer whose `writerEnc` is its own subkey, the catalog line loses its
parenthetical, and no new edge is needed. Rejected for two reasons.

1. _Key separation._ It makes the owner's structure-**signing** authority a function of
   its **encryption** secret. `enc_subkey` is the highest-exposure secret the owner
   holds: it is the HPKE static sender for op records and the ECDH half against every
   grantee. Under self-ECDH, compromising it also yields the pseudonym signing key for
   every scope. A grantee's pseudonym already derives from encryption material, so this
   looks like mere consistency — but the exposure is asymmetric. A grantee's compromise
   costs one grantee's scope; the owner's costs the whole tree.
2. _Self-grant collision._ `create_read_grant` validates that the recipient key is usable
   but **does not** refuse a recipient equal to the owner. The invite path does carry
   that guard (`ClaimantIsTheOwner`), so the omission on the direct path is asymmetric.
   Under self-ECDH an owner who grants to their own encryption key derives pairwise
   material identical to their own, so the self-grant's pseudonym _is_ the owner's. Same
   principal, so it is not an authority break — but it silently merges two identities the
   commitment format keeps separate (`ownerPseudonymPk` beside per-entry `pseudonymPk`),
   through a path with no guard. A dedicated seed cannot collide, because the owner's
   input is not in the grantee input space at all.

The missing self-grant guard is a defect on its own terms and is filed separately; this
decision does not depend on it being fixed.

**Reuse `owner_pointer_seed`.** Already derived and already narrow, but it exists to key
per-scope pointer signers and pointer read keys. Reusing it gives one seed two unrelated
duties and couples pointer-plane compromise to structure-signing authority.

**Use `login_secret` directly.** Simplest, and the weakest. It makes the pseudonym a
direct function of the master secret, against the standing rule that a stored or passed
capability should be the narrowest derived one rather than a broad seed.

## Consequences

1. **`blueprint/core.md`'s KDF catalog gains a row** for `owner-pseudonym-seed`, and the
   `pseudonym-sign` row's parenthetical changes from `(owner: root secret)` to
   `(owner: ownerPseudonymSeed)`.
2. **`CONTEXT.md`'s "Writer pseudonym" entry is tightened.** It currently reads "derived
   from the same pairwise ECDH secret as the blinded tag", which is true of grantees and
   false of the owner. It must say the grantee case derives from that pairwise ECDH and
   the owner case from `ownerPseudonymSeed`.
3. **A KAT vector pins the owner's input**, so the owner arm cannot drift silently, and
   the D8 separation KAT extends to the new edge.
4. **`OwnerScopeKeys` gains its first production implementor** over `SessionIdentity`
   alone, which is what unblocks the owner rotation arm and its facade commands.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The
`blueprint/` copies in this repository are the as-charted archive and are not edited by
this ADR.
