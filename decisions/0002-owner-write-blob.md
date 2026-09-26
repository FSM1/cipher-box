# ADR 0002 — Owner write blob for cold-start write-seed recovery

- **Status:** Accepted — implemented in FSM1/cipher-box#792 (merged)
- **Date:** 2026-07-23
- **Extends:** [#27](https://github.com/FSM1/cipher-box-next/issues/27) (v2 metadata
  schemas and crypto envelope) — adds a sealed structure to the grant section; conforms
  to [#39](https://github.com/FSM1/cipher-box-next/issues/39) (seal authentication and
  floor re-anchor for seed-bearing structures)
- **Relates to:** [#26](https://github.com/FSM1/cipher-box-next/issues/26) (key rotation
  model) — the write-plane seed/epoch this structure carries
- **Implemented by:** [FSM1/cipher-box#791](https://github.com/FSM1/cipher-box/issues/791)

## Context

The v2 KDF catalog fixes `write_scope_seed` as **random per-write-scope material** — a
non-edge with no derivation path from the login secret. This is deliberate: flat
derivation means a node's write seed cannot derive its children's, so each write-scope
cut _mints_ a fresh random seed. Every per-node write artifact — `writeSeed`, `writeKey`,
and the Ed25519 IPNS keypair used to sign records — is a pure KDF output **from** that
seed. "The write plane is fully derived" (the decision that killed per-node
`ipnsPrivateKey` storage and `reconstruct_write_body`) is a statement about the subtree
**under** a scope seed, not about the scope seed itself: the seed is the random root of
that derivation, not a derived value.

A **grantee** recovers a scope's `write_scope_seed` from the write grant blob
(`GrantBlobPayload`, HPKE-sealed to the grantee's X25519 enc-subkey; write grants carry
both the read and write scope seeds). The **owner** has no such source. The owner blob
and owner seed cache carry only the **read-plane** override seed — the owner recovers the
read plane and can decrypt everything, but on a fresh device has **no network source for
their own scopes' `write_scope_seed`**. Consequently a cold-started owner cannot rebuild
the per-name IPNS signer, and cannot renew (sub-EOL, sequence+1) the records of scopes
they own. Their actively-used records lapse at the 90-day EOL — a direct violation of the
"actively-used vaults keep their own records alive" liveness contract. No mechanism for
owner write-seed recovery was specified anywhere in the blueprint corpus; this is a
genuine gap, not an under-implementation.

## Decision

Introduce an **owner write blob**: the write-plane mirror of the read-plane owner blob.

A dedicated grant-section structure carrying `{writeScopeSeed, writeEpoch}`,
HPKE-sealed (X25519-HKDF-SHA256 + XChaCha20-Poly1305) to the owner's **own** X25519
enc-subkey, structure-signed by the rotator pseudonym like every other seed-bearing
structure, and **authored in `reseal_scope_root`** — the reseal path already holds
`write_scope_seed` as a mandatory input (it seals the write-body with it), so authoring
the blob there introduces no new rotator-capability precondition.

Concretely:

- New struct tag `STRUCT_TAG_OWNER_WRITE_BLOB = 0x09` (registry `0x08` → `0x09`,
  count 8 → 9).
- `OwnerWriteBlobPayload { writeScopeSeed: 32 bytes, writeEpoch: u64, unknown }`,
  deterministic-CBOR, scrubbed at the terminal owner on encode/decode.
- Carried as `GrantSection.owner_write_blob: Option<SignedOwnerWriteBlob>` (optional for
  additive wire evolution; present in practice at every write scope root).
- AAD binds `(v, id = rootNodeId, scope = scopeId, epoch = writeEpoch,
struct_tag = OWNER_WRITE_BLOB)`. The **write** epoch is bound, not the read epoch — the
  write plane's clock is authored by write rotation only — so a transplant across
  scope, epoch, or struct tag fails the HPKE tag.
- The adoption gate verifies the structure signature; a missing or invalid signature on a
  present `owner_write_blob` is a whole-record **trust violation** (fail-closed), never
  staleness.

The owner opens the blob at cold start with its enc-subkey secret, derives the per-name
signer, and holds it for liveness renewal. The recovered `write_scope_seed` is transient
— it is dropped after deriving the signer and is never persisted; the held-record set
stores only the narrow per-name `Ed25519Signer`, never the scope seed (which would grant
scope-wide content-and-record forge capability for every node in the scope).

## Consequences

- **Additive wire change, no migration.** `GrantSection` gains one optional field; v2 is
  mid-build and unreleased, so no deployed records exist to migrate. Readers without the
  field ignore it; the field is always authored going forward.
- **New KAT set.** An `owner-write-blob` vector set is added: accept (seal/open
  round-trip under fixed `enc` + fixed ephemeral), reject (struct-tag / epoch / scope AAD
  transplant, truncation, tampered ciphertext or tag, wrong `writeEpoch`), plus
  structure-signature accept/reject. Native and WASM run the same vectors; TypeScript
  holds no codec, so there is no separate JS vector set. Registry and anti-vacuity counts
  are bumped with the fixture.
- **Blueprint update in the code repo.** `blueprint/core.md` (struct-tag registry, the
  `OwnerWriteBlobPayload` wire format, the `GrantSection` field) and `blueprint/engine.md`
  (reseal authorship, gate verification, owner cold-start write recovery) are updated in
  the FSM1/cipher-box#791 code PR — the live blueprint is maintained there.
- **Least privilege preserved.** The write seed lives in an owner-only structure and is
  held only as the narrow derived signer; see the held-record least-privilege rule
  (store the narrowest derived capability, never a parent seed).
- **Consumer wiring lands separately.** This slice **authors and verifies** the blob. The
  owner cold-start **read/consume** path (opening the blob in the resolve/hold flow to
  source the renewal signer) rides on the facade live-session PR
  ([FSM1/cipher-box#789](https://github.com/FSM1/cipher-box/pull/789)) once this core
  slice merges. Until then, owner records are held keyless (kept alive on endpoints, EOL
  not yet extended).

## Alternatives considered

- **Fold `writeScopeSeed` into the existing owner blob (`OverrideSeedPayload`).**
  Rejected: `OverrideSeedPayload` is shared with the ascent link, so adding the write seed
  would leak write capability to **ancestor read-only readers** who legitimately open the
  ascent link. The write seed must live in an owner-only structure.
- **Owner self-grant write blob keyed by a self-blinded tag.** Rejected: it forces the
  owner into the grant-set commitment and ledger (owner capability is currently implicit),
  and grantee rotators re-wrap committed blobs — a read-only grantee cannot re-wrap a
  write-bearing blob, creating a rotation wall.
- **Owner seed manifest at the root scope.** A single owner-authored list mapping each
  owned scope to `{writeScopeSeed, writeEpoch}`, sealed under the owner's root read plane.
  Viable, but adds a manifest-sync law and makes recovery root-gated. Not chosen: the
  per-scope owner write blob reuses the owner-blob machinery verbatim and keeps recovery
  local to each scope root, with no cross-scope dependency.

## References

- [#26](https://github.com/FSM1/cipher-box-next/issues/26) — key rotation model
- [#27](https://github.com/FSM1/cipher-box-next/issues/27) — v2 metadata schemas and
  crypto envelope
- [#39](https://github.com/FSM1/cipher-box-next/issues/39) — seal authentication and
  floor re-anchor for seed-bearing structures
- [FSM1/cipher-box#791](https://github.com/FSM1/cipher-box/issues/791) — implementing
  issue
- [FSM1/cipher-box#789](https://github.com/FSM1/cipher-box/pull/789) — facade PR that
  consumes the blob at owner cold start
- `crates/core/src/seal/grant.rs`, `crates/core/src/seal/section.rs`,
  `crates/core/src/seal/aad.rs`, `crates/engine/src/rotation/reseal.rs`,
  `crates/engine/src/gate/adoption.rs`
