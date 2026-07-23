# crates/core — v2 blueprint

Resolved by [Blueprint: core](https://github.com/FSM1/cipher-box-next/issues/43).
Normative for the v2 build. Upstream inputs: the
[schema/envelope](https://github.com/FSM1/cipher-box-next/issues/27),
[sync/refresh](https://github.com/FSM1/cipher-box-next/issues/33),
[rotation completeness](https://github.com/FSM1/cipher-box-next/issues/38), and
[seal authentication](https://github.com/FSM1/cipher-box-next/issues/39) designs,
scoped by the [component decomposition](https://github.com/FSM1/cipher-box-next/issues/28)
(D2/D3). The schema amendment pile those tickets accumulated is folded in here as
base structure — nothing below is an "amendment" anymore.

## Doctrine

`crates/core` is the **pure, deterministic** layer: wire formats, the crypto
suite, seal/unseal, the KDF edge catalog, and IPNS record create/sign/verify —
one Rust implementation, linked natively by desktop and compiled to WASM for the
web. It performs no I/O, holds no state, reads no clock, and generates no
randomness of its own: entropy, timestamps, and TTL/EOL policy values enter as
explicit parameters (KATs pin them). Everything stateful — floors, caches, the
adoption-gate _pipeline_, transports — lives one crate up in `engine`; core
exports the pure checks the gate composes.

What dies relative to v1 — with the design that killed it:

| Gone                                                                      | Killed by                                                |
| ------------------------------------------------------------------------- | -------------------------------------------------------- |
| TS/Rust twin implementations, lockstep KATs, the 8-row divergence table   | #27 D2 — one Rust core, TS keeps no codec or crypto      |
| JSON fixed-field-order determinism, base64 fields, decimal-string bigints | #27 D1 — deterministic CBOR everywhere                   |
| AES-256-GCM/CTR suite, 45-byte AAD, role bytes                            | #27 D3/D4 — XChaCha20-Poly1305, structured AAD           |
| eciesjs-default ECIES envelope (library-defined layout)                   | #27 D3 — RFC 9180 HPKE, spec-defined, full-envelope KATs |
| Per-node `ipnsPrivateKey` storage + `reconstruct_write_body` recovery     | #26/#27 D6 — write plane fully derived                   |
| `readKeySealed` child wraps, kind-blind child refs                        | #27 D7 — derivation + immutable `kind` in the ref        |
| VaultKeyBlob v3, vault-init/export endpoints                              | #27 D9 — derived vault pointer + owner blob              |
| `deny_unknown_fields` vs tolerant-decode contradiction                    | #27 D10 — tolerate + round-trip, one policy              |
| Three validity parsers at two strictness levels across five packages      | #28 D2/D3 — one strict codec, exported from core         |
| Content self-seal role `0x03` (built, vector-locked, dormant)             | not carried — no v2 analog                               |

## Module map

Functional decomposition, not final file layout:

- **codec** — the deterministic CBOR profile; envelope, body, and structure
  codecs; unknown-field round-trip.
- **suite** — primitive bindings: XChaCha20-Poly1305, BLAKE3, X25519/HPKE,
  secp256k1 ECDSA, Ed25519. Pure RustCrypto; constant-time; key material in
  `Zeroizing` owning types (type-enforced, never comment-enforced).
- **kdf** — the frozen edge catalog (below); nothing derives a key outside it.
- **seal** — AAD construction, seal/unseal, structure signatures, the pure
  verify functions the adoption gate composes.
- **ipns** — record create/sign/marshal/unmarshal/verify, name codec.
- **kat** — the vector manifest and fixtures (regime below).

## Wire format

- **DAG-CBOR** for every published block (envelope, pointer payload); the same
  deterministic profile (RFC 8949 §4.2) for sealed-body plaintext and every
  signed structure. Native byte strings and u64s; determinism is a property of
  the encoder, not a field-order convention.
- **One strictness policy, everywhere.** Decoders accept deterministic-profile
  CBOR only: duplicate map keys, non-canonical integer/length encodings, and
  wrong major types reject fail-closed. The single tolerance is **unknown
  fields**: accepted, ignored for logic, preserved byte-stable, and re-emitted
  canonically on rewrite — an old client rewriting under shared write never
  strips newer fields (#27 D10).
- **Uniqueness fail-closed** (#39 D7): duplicate `id`s anywhere, and duplicate
  `ipnsName`s within a scope, reject at decode.
- **Versioning**: a single small-int `v` on the envelope covers format + crypto
  suite, bound into the AAD so downgrade fails the tag. Additive changes never
  bump it; any breaking change bumps and forces re-seal — expensive by design.
  No body-level schema strings (#27 D5).

## Crypto suite

| Role                       | Algorithm                                               | Used for                                                                        |
| -------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------- |
| Symmetric sealing          | XChaCha20-Poly1305 (24-byte nonce)                      | All sealed bodies and structures, content bytes                                 |
| Key derivation             | BLAKE3 `derive_key` / `keyed_hash`                      | The whole edge catalog                                                          |
| Sealing to a person        | RFC 9180 HPKE (X25519-HKDF-SHA256 + XChaCha20-Poly1305) | Grant blobs, owner blob, ascent links, mailbox payloads                         |
| Pairwise secrets           | X25519 ECDH                                             | Blinded tags, pseudonym derivation                                              |
| Identity signing           | secp256k1 ECDSA (RFC 6979) over det-CBOR                | Grant-set commitment, subkey binding, re-point object, mailbox sender signature |
| Pseudonym + record signing | Ed25519                                                 | Structure signatures; IPNS records                                              |

- Every user derives an **X25519 encryption subkey** from their login secret;
  the identity key only signs, the subkey only seals. The **subkey binding**
  (ECDSA over det-CBOR `{identityPk, encSubkey}`) and the **contact code**
  codec (`{identityPk, encSubkey, bindingSig}`, ~130 bytes, QR/URL-encodable,
  binding verify mandatory and fail-closed at import) are core exports.
- Writer pseudonyms sign with **Ed25519** (deterministic derivation from the
  pairwise secret; secp256k1 stays confined to identity signing per #27 D3).
- HPKE envelopes are spec-defined with a full-envelope KAT under a fixed
  ephemeral key — the eciesjs lesson (a library major bump must never be able
  to silently orphan stored ciphertexts).

## Envelope and structures

Kind-uniform envelope (#27 D4): `{v, id, epochTag{scope, epoch}, readSealed,
writeSealed?, grantSection?}` — `kind` lives inside the sealed read-body, so
observers cannot distinguish files from folders. Scope id = the scope root's
node UUID.

- **AAD** = `(v, id, scope, epoch, structTag)` under a fresh `cipherbox/v2`
  domain separator. `ipnsName` is deliberately **not** in the AAD (#39 D7 —
  the name wave republishes epoch-lagged bodies under fresh names; transplant
  is closed by duplicate rejection instead).
- **Read-body**: tagged union `folder {children[]}` | `file {versions[]}` plus
  `createdAt`/`modifiedAt` (injected timestamps). Versions are one inline
  newest-first list `[{contentCid, contentKey, size, modifiedAt}]`, head =
  current. Content keys are random per version — never derived, rotation
  re-wraps them via the metadata re-seal.
- **Child refs**: `{id, name, ipnsName, kind, linkCounter}` — immutable fields
  plus the monotonic link counter that picks the deterministic loser in
  dual-link repair (#33 D5). No key wraps, no size/mtime mirrors: child writes
  never republish the parent.
- **Write-body** (scope roots only, #27 D6): `{grant ledger, write-plane
history link, directChildScopeIndex}` sealed under the root's writeKey. The
  ledger is `(recipientIdentityPk, recipientEncPk, permission, tag)`; the
  child-scope index enumerates directly-descendant scope roots for the F-4
  rotation cascade (#38 D6). Interior nodes publish no write-body at all.
- **Grant section** (scope roots only): grant blobs keyed by blinded tag
  (`tag → HPKE{readScopeSeed[, writeScopeSeed], epoch, pointerReadKey}`), the
  epoch-free grant-set commitment (ECDSA over det-CBOR `{ipnsName,
ownerPseudonymPk, [(tag, permission, pseudonymPk)]}`), owner blob, ascent
  link (public half plaintext, derive-and-verified by ancestor readers),
  per-epoch history links, and a detached **structure signature** per
  seed-bearing structure.
- **Structure signatures** (#39 D2/D3): the rotator's pseudonym Ed25519
  signature over det-CBOR `{scopeId, epoch, structTag, recipientTag?,
H(ciphertext)}` — covering grant blobs, owner blob, ascent link, history
  links, and the write-body. Verification is per-structure and pure; the
  whole-record fail-closed policy is the engine's gate stage.
- **Pointer payloads**: the re-point object `{scopeId, currentRootName,
writeEpoch, minReadEpoch, prevRootName}`, owner-identity-signed inside the
  record, sealed under the scope's stable `pointerReadKey`. The vault pointer
  carries the same object for the root scope (#39 D5). Mailbox payloads are
  HPKE-sealed with a sender identity signature inside the seal (#39 D9), whose
  preimage binds the recipient key
  (`[domain, v, recipientEncPk, senderIdentityPk, payload]`) so a relayed item
  fails verification for any other recipient (#712); core owns their codecs and
  verify functions.

### Structure-tag registry

The `structTag` byte-space is the domain-separation registry, frozen in the KAT
manifest: `read-body`, `write-body`, `grant-blob`, `owner-blob`, `ascent-link`,
`history-link`, `pointer-payload`, `mailbox-payload`. Every new tag extends the
manifest and its vectors before merge.

## KDF edge catalog

Frozen per #39 D8 (F-9). Per-node material takes the shape
`keyed_hash(key = derive_key("<edge context>", seed), message = id16)` — ids
are fixed-length message input, **never** variable context. Context strings
follow `cipherbox/v2/<edge>`; the exact string table and input layouts freeze
in the KAT manifest.

| Edge                | Inputs                                                   | Output                             |
| ------------------- | -------------------------------------------------------- | ---------------------------------- |
| node-seed           | scopeSeed, node id                                       | nodeSeed (flat within scope)       |
| read-key            | nodeSeed                                                 | readKey                            |
| structure-key       | nodeSeed or scope seed, structTag                        | per-structure sealing keys         |
| write-seed          | writeScopeSeed, node id                                  | writeSeed (flat)                   |
| write-key           | writeSeed                                                | writeKey                           |
| ipns-keypair        | writeSeed                                                | Ed25519 keypair → ipnsName         |
| ascent-keypair      | parent nodeSeed                                          | X25519 keypair for the ascent link |
| enc-subkey          | login secret                                             | X25519 encryption subkey           |
| blinded-tag         | ECDH(ownerEnc, recipientEnc) ‖ scopeRootIpnsName         | grant-blob tag                     |
| pseudonym-sign      | ECDH(ownerEnc, writerEnc) ‖ scopeId (owner: root secret) | Ed25519 pseudonym keypair          |
| owner-pointer-seed  | login secret                                             | ownerPointerSeed                   |
| scope-pointer       | ownerPointerSeed, scope id                               | per-scope pointer Ed25519 keypair  |
| pointer-read-key    | ownerPointerSeed, scope id                               | pointerReadKey                     |
| vault-pointer-index | login secret, index i (0 default)                        | pointer Ed25519 keypair chain      |

Non-edges, stated to stay non-edges: content keys (random per version), scope
override seeds (random at rotation), scope seeds at grant cuts (random).

## IPNS records

Core owns records end-to-end on both platforms (#28 D2); transports are dumb
byte movers injected by the engine.

- **Create/sign**: spec-compliant V2 records (`signatureV2` over the CBOR data
  field; V1 fields emitted for ecosystem compatibility), `Value =
/ipfs/<CID>` of the DAG-CBOR envelope. First publish embeds sequence 1; CAS
  publishes embed the exact expected sequence. Validity = 90-day client-signed
  EOL (#24); TTL always explicitly set, value injected from the sync timing
  profile (#33 D3) — core never defaults it.
- **Verify**: the full chain, pure — Ed25519 pubkey extracted from the name
  itself (identity multihash; never a side channel or DB column), `signatureV2`
  verify, data-field/Value consistency, EOL and sequence extraction for the
  gate's comparators. Verdict-vector KATs pin the acceptance domain.
- **Name codec**: `ipnsName` = base36 CIDv1 libp2p-key of the Ed25519 public
  key. Encode + strict decode are core exports; everything downstream treats
  names as opaque.
- **Content-CID string codec**: a scope's IPNS record value `/ipfs/<head_cid>`
  carries the head block's binary CIDv1 in base32-lowercase multibase (`b…`).
  Encode + strict decode are core exports; decode fail-closes on a wrong/missing
  `b` prefix, a non-base32 or non-canonical body, or any bytes that are not the
  frozen content-plane CIDv1 framing — the Adopter recovers the trust anchor from
  the record string before `read_block` verifies the fetched head.
- **Keyless re-PUT** is a first-class shape: marshal/unmarshal round-trips a
  foreign signed record byte-stable without key material (the republisher and
  every accelerator depend on this).

## KAT regime

Single-implementation scope (#27 D2): KATs no longer defend cross-language
parity — they defend the **frozen contract** against future drift (refactors,
dependency majors, WASM-target divergence) and pin the acceptance domain.

- **One machine-checked manifest** enumerates every frozen encoding — envelope
  and structure codecs, AAD layout, the KDF edge catalog with exact context
  strings, HPKE envelope, structure-signature preimages, IPNS record and name
  codecs, the structure-tag registry — and the vector files that lock each.
  Tests and CI consume the manifest; "what is KAT-locked" is never folklore
  (the v1 lesson).
- **Accept and reject vectors for every codec**: malformed-input verdicts are
  part of the frozen contract from day one — duplicate keys, non-canonical
  encodings, wrong types, truncations, AAD transplants, bad signatures.
- **Separation KAT**: no two catalog edges may produce equal output for equal
  inputs — asserted mechanically over the whole edge table.
- **Fixed-parameter full-envelope KATs**: symmetric seals under fixed key +
  nonce; HPKE under a fixed ephemeral key; IPNS records under fixed keys and
  injected timestamps. Purity makes every path KAT-able.
- **Anti-vacuity**: vector counts and tag/edge coverage are hard-asserted and
  bumped with the fixture; vectors with real crypto material come from
  committed generators, never hand-edits.
- **WASM is the residual parity surface**: the same suite runs natively and as
  WASM in CI — one implementation, two compilation targets; boundary risks
  (u64/BigInt, getrandom wiring) are covered by running the KATs there, not by
  a second vector set.

## Error surface

Two classes, disjoint types, no reused codes (v1 defect): **trust violations**
(signature, commitment, structure-signature, AAD, uniqueness, canonicality
failures — the engine treats these fail-closed) and **malformed/availability**
errors. Unseal failure never silently degrades; every rejection names the
check that fired.

## Open edges

- Content chunking format and version-retention policy — client policy, owned
  by the [engine blueprint](https://github.com/FSM1/cipher-box-next/issues/44);
  core ships the content-seal primitive over caller-framed chunks.
- Exact context-string table, structure-tag bytes, and vector fixtures freeze
  in the KAT manifest at build time; CI wiring for the manifest check belongs
  to the [testing strategy](https://github.com/FSM1/cipher-box-next/issues/47).
- WASM packaging, worker hosting, and the JS type boundary —
  [web client blueprint](https://github.com/FSM1/cipher-box-next/issues/45)
  over `crates/wasm` + `packages/client`.
