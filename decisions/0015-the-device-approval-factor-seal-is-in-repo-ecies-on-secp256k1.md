# ADR 0015 — The device-approval factor seal is in-repo ECIES on secp256k1

- **Status:** Accepted — the primitive is in the code, from
  [FSM1/cipher-box#1606](https://github.com/FSM1/cipher-box/pull/1606)
- **Date:** 2026-09-03
- **Relates to:**
  [ADR 0009](./0009-device-approval-is-a-bound-rendezvous.md)
  D3 (both devices compare a value derived from the requester's ephemeral public key) and D5 (an
  approval seals a fresh factor to that key),
  [#27](https://github.com/FSM1/cipher-box-next/issues/27) D3 (the one primitive set: HPKE
  replaced the library-defined ECIES envelope, and secp256k1 was confined to identity signing),
  [#39](https://github.com/FSM1/cipher-box-next/issues/39) D8 (the frozen KDF edge catalog), and
  [FSM1/cipher-box#1692](https://github.com/FSM1/cipher-box/issues/1692) (the blueprint conflict
  and the incomplete reject family)
- **Implemented by:** [FSM1/cipher-box#1606](https://github.com/FSM1/cipher-box/pull/1606)
  (primitive) and [FSM1/cipher-box#1738](https://github.com/FSM1/cipher-box/pull/1738) (blueprint and
  KAT follow-up, which closed [FSM1/cipher-box#1692](https://github.com/FSM1/cipher-box/issues/1692))

## Context

The device-approval rendezvous relays one key. The requesting device mints an ephemeral
secp256k1 keypair, the API holds the compressed public key as opaque text, and the approving
device seals a fresh factor to that key (ADR 0009 D3 and D5). The API fixes that field to
secp256k1, so the seal runs on a secp256k1 point.

HPKE cannot serve this seal. The KEM of the HPKE suite in `blueprint/core.md` is
DHKEM(X25519-HKDF-SHA256). Every other seal addresses a CipherBox encryption subkey, which is
X25519 by derivation. This one seal addresses a bare curve point that another device minted
before it holds any CipherBox key material.

`crates/core/src/suite/ecies.rs` is the primitive that
[FSM1/cipher-box#1606](https://github.com/FSM1/cipher-box/pull/1606) added for it. It runs ECDH
on secp256k1, derives an AEAD key and an AEAD nonce with BLAKE3 `derive_key` over the
transcript, and seals with XChaCha20-Poly1305. The ephemeral scalar is an injected parameter.
Its module comment states the claim this ADR records: the key schedule is internal to the
primitive, in the same class as the HPKE key schedule, and is not a KDF-catalog edge.

Three statements in the normative corpus disagree with that code today, and
[FSM1/cipher-box#1692](https://github.com/FSM1/cipher-box/issues/1692) lists them. The
crypto-suite table says that secp256k1 stays confined to identity signing. The blueprint assigns
BLAKE3 `derive_key` to the whole edge catalog, and AGENTS.md rule 5 says that no key derives
outside that frozen catalog. The catalog fixes the context-string form as `cipherbox/v2/<edge>`,
and the two ECIES contexts do not take that form.

The "Gone" table of `blueprint/core.md` retires an `eciesjs`-default ECIES envelope, and it
names the reason: the layout was library-defined, so a library major version could silently
orphan stored ciphertexts. That reason is about who defines the envelope. This primitive is
defined in the repository, and a full-envelope KAT under a fixed ephemeral key freezes its
bytes, so it agrees with the intent of that row. The secp256k1 confinement sentence is the
statement that conflicts directly.

A code comment carries the argument today, and a comment cannot amend a normative document. A
reviewer who follows the blueprint reads the module as a rule break.

## Decision

**D1 — secp256k1 covers identity signing and the device-approval rendezvous seal, and nothing
else.** The confinement of [#27](https://github.com/FSM1/cipher-box-next/issues/27) D3 gains
exactly one consumer, under a fixed external constraint: the API fixes the type of the
rendezvous key field. Every other seal stays on HPKE, and every other pairwise secret stays on
X25519.

**D2 — A key schedule that is internal to one primitive is not a catalog edge.** The rule is
general. A catalog edge derives key material that other code holds, names, and passes on. The
HPKE key schedule derives a symmetric key inside RFC 9180, and the ECIES key schedule derives an
AEAD key and an AEAD nonce inside the primitive. Neither output leaves its primitive, so neither
is a catalog member. The frozen catalog of
[#39](https://github.com/FSM1/cipher-box-next/issues/39) D8 and AGENTS.md rule 5 both stay
exact.

**D3 — The two ECIES context strings freeze in the KAT manifest, beside `suite.ecies`.** They
are `cipherbox/device-factor-seal/v1 aead-key` and
`cipherbox/device-factor-seal/v1 aead-nonce`. They are not catalog edges, so they keep their own
form and they do not join the catalog string table. They are frozen strings, so the manifest
holds them, and a change to either string breaks every stored envelope.

**D4 — The primitive does not change.** The construction, the two contexts, the transcript that
both derivations bind, and the injected ephemeral scalar are correct as written. This ADR
records the exception; it does not re-open the design.

**D5 — Both reject families of the primitive are complete in vectors.** `blueprint/core.md`
asks for accept and reject vectors for every codec, and AGENTS.md rule 8 asks for a
release-active encode-side check wherever a decode path hard-rejects. The open-reject family
gains a recipient scalar outside the group and a ciphertext shorter than its tag. A seal-reject
family lands for the two produce-side refusals: an off-curve recipient and an out-of-group
scalar.

## Alternatives rejected

**Derive the AEAD key through a catalog edge.** The catalog would gain edges whose inputs are
one primitive's transcript. This breaks the parallel that holds the catalog together, because
the HPKE key schedule is not a catalog member and no argument separates it from this one. The
catalog would then grow with every primitive rather than with every key that CipherBox names and
passes on. Rejected.

**Convert the identity key to an X25519 key and use HPKE.** The two keys live on different
curves, and no defined mapping carries a scalar from one to the other. The API also fixes the
type of the rendezvous key field, so the requesting device cannot present an X25519 key.
Rejected.

**Keep the code comment as the record.** A comment is not a normative document, no review gate
reads it, and the blueprint keeps a sentence that the code contradicts. Rejected.

## Consequences

1. **`blueprint/core.md` changes when this ADR is accepted.** The crypto-suite table gains an
   ECIES row for the device-approval factor seal, and the secp256k1 sentence under that table
   narrows to identity signing and the device-approval rendezvous. The KDF edge catalog section
   states that a primitive-internal key schedule is not a catalog edge, and names HPKE and ECIES
   as the two cases.

2. **The KAT manifest and its generator change.** `crates/core/examples/kat_gen.rs` writes the
   two context strings beside `suite.ecies`, `build_ecies_open_reject` gains two vectors,
   `openRejectCount` and `ECIES_REQUIRED_REJECTS` rise with it, and a seal-reject family and its
   count join the manifest.

3. **`CONTEXT.md` needs no new term.** The glossary already defines the device-approval
   rendezvous and the factor. This ADR records which primitive seals the factor.

## Residuals

**E1 — secp256k1 ECDH now has two consumers.** The identity key signs, and the same curve
carries the rendezvous seal. The key schedule keeps the two apart: the seal derives its AEAD key
and nonce under a context string that names the device-factor seal, over a transcript that binds
the encapsulated key and the recipient key.

**E2 — The rendezvous key is a bare point, so the seal authenticates nobody.** ADR 0009 D3 and
D4 carry that load: both devices compare a value derived from the ephemeral public key, and both
halves of the exchange are signed by device identity keys. The seal keeps a relayed factor
secret from the API. It does not decide whose key it sealed to.

**E3 — A library major version can still change the curve implementation under the primitive.**
The full-envelope KAT under a fixed ephemeral key bounds that exposure: a bump that changes any
byte of a sealed envelope, or any verdict of the reject families, fails the Core KATs. That is
the `eciesjs` lesson applied to this primitive.

**E4 — The caller owns ephemeral-scalar uniqueness.** Core samples no entropy, so the calling
seam supplies a fresh scalar on every call. A repeated scalar against one recipient re-derives
the same AEAD key and the same nonce. No vector catches that, because a KAT fixes the scalar.

## Gate

- The KAT manifest holds `cipherbox/device-factor-seal/v1 aead-key` and
  `cipherbox/device-factor-seal/v1 aead-nonce` beside `suite.ecies`.
- The manifest `openRejectCount` and `ECIES_REQUIRED_REJECTS` cover a recipient scalar outside
  the group and a ciphertext shorter than its tag.
- A seal-reject family covers an off-curve recipient and an out-of-group scalar, and the seal
  path refuses both in a release build.
- `blueprint/core.md` holds an ECIES row in the crypto-suite table, a secp256k1 sentence that
  names identity signing and the device-approval rendezvous and nothing else, and a statement
  that a primitive-internal key schedule is not a catalog edge.
- The KDF edge catalog holds the same edges as before this ADR.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
