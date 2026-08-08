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

| Gone                                                                      | Killed by                                                                      |
| ------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| TS/Rust twin implementations, lockstep KATs, the 8-row divergence table   | FSM1/cipher-box-next#27 D2 — one Rust core, TS keeps no codec or crypto        |
| JSON fixed-field-order determinism, base64 fields, decimal-string bigints | FSM1/cipher-box-next#27 D1 — deterministic CBOR everywhere                     |
| AES-256-GCM/CTR suite, 45-byte AAD, role bytes                            | FSM1/cipher-box-next#27 D3/D4 — XChaCha20-Poly1305, structured AAD             |
| eciesjs-default ECIES envelope (library-defined layout)                   | FSM1/cipher-box-next#27 D3 — RFC 9180 HPKE, spec-defined, full-envelope KATs   |
| Per-node `ipnsPrivateKey` storage + `reconstruct_write_body` recovery     | FSM1/cipher-box-next#26/FSM1/cipher-box-next#27 D6 — write plane fully derived |
| `readKeySealed` child wraps, kind-blind child refs                        | FSM1/cipher-box-next#27 D7 — derivation + immutable `kind` in the ref          |
| VaultKeyBlob v3, vault-init/export endpoints                              | FSM1/cipher-box-next#27 D9 — derived vault pointer + owner blob                |
| `deny_unknown_fields` vs tolerant-decode contradiction                    | FSM1/cipher-box-next#27 D10 — tolerate + round-trip, one policy                |
| Three validity parsers at two strictness levels across five packages      | FSM1/cipher-box-next#28 D2/D3 — one strict codec, exported from core           |
| Content self-seal role `0x03` (built, vector-locked, dormant)             | not carried — no v2 analog                                                     |

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
  strips newer fields (FSM1/cipher-box-next#27 D10).
- **Uniqueness fail-closed** (FSM1/cipher-box-next#39 D7): duplicate `id`s anywhere, and duplicate
  `ipnsName`s within a scope, reject at decode.
- **Versioning**: a single small-int `v` on the envelope covers format + crypto
  suite, bound into the AAD so downgrade fails the tag. Additive changes never
  bump it; any breaking change bumps and forces re-seal — expensive by design.
  No body-level schema strings (FSM1/cipher-box-next#27 D5).

## Crypto suite

| Role                       | Algorithm                                               | Used for                                                                                     |
| -------------------------- | ------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Symmetric sealing          | XChaCha20-Poly1305 (24-byte nonce)                      | All sealed bodies and structures, content bytes                                              |
| Key derivation             | BLAKE3 `derive_key` / `keyed_hash`                      | The whole edge catalog                                                                       |
| Sealing to a person        | RFC 9180 HPKE (X25519-HKDF-SHA256 + XChaCha20-Poly1305) | Base mode: grant blobs, owner blob, ascent links, mailbox payloads; auth mode: the op record |
| Pairwise secrets           | X25519 ECDH                                             | Blinded tags, grantee pseudonym derivation                                                   |
| Identity signing           | secp256k1 ECDSA (RFC 6979) over det-CBOR                | Grant-set commitment, subkey binding, re-point object, mailbox sender signature              |
| Pseudonym + record signing | Ed25519                                                 | Structure signatures; IPNS records                                                           |

- Every user derives an **X25519 encryption subkey** from their login secret;
  the identity key only signs, the subkey only seals. The **subkey binding**
  (ECDSA over det-CBOR `{identityPk, encSubkey}`) and the **contact code**
  codec (`{identityPk, encSubkey, bindingSig}`, ~130 bytes, QR/URL-encodable,
  binding verify mandatory and fail-closed at import) are core exports.
- Writer pseudonyms sign with **Ed25519** (deterministic derivation from the
  pairwise secret, or from `ownerPseudonymSeed` for the owner; secp256k1 stays
  confined to identity signing per FSM1/cipher-box-next#27 D3).
- HPKE envelopes are spec-defined with a full-envelope KAT under a fixed
  ephemeral key — the eciesjs lesson (a library major bump must never be able
  to silently orphan stored ciphertexts).

## Envelope and structures

Kind-uniform envelope (FSM1/cipher-box-next#27 D4): `{v, id, epochTag{scope, epoch}, readSealed,
writeSealed?, grantSection?}` — `kind` lives inside the sealed read-body, so
observers cannot distinguish files from folders. Scope id = the scope root's
node UUID.

- **AAD** = `(v, id, scope, epoch, structTag)` under a fresh `cipherbox/v2`
  domain separator. `ipnsName` is deliberately **not** in the AAD (FSM1/cipher-box-next#39 D7 —
  the name wave republishes epoch-lagged bodies under fresh names; transplant
  is closed by duplicate rejection instead).
- **Read-body**: tagged union `folder {children[]}` | `file {versions[]}` plus
  `createdAt`/`modifiedAt` (injected timestamps). Versions are one inline
  newest-first list `[{contentCid, contentKey, size, modifiedAt}]`, head =
  current. Content keys are random per version — never derived, rotation
  re-wraps them via the metadata re-seal.
- **Child refs**: `{id, name, ipnsName, kind, linkCounter}` — immutable fields
  plus the monotonic link counter that picks the deterministic loser in
  dual-link repair (FSM1/cipher-box-next#33 D5). No key wraps, no size/mtime mirrors: child writes
  never republish the parent. The one exception is the write-plane name wave,
  which moves every child's `ipnsName` at once and so rewrites the parent's
  child refs, re-sealing its read body under its **unchanged** read key at its
  **unchanged** read epoch — a metadata rewrite, never a read rotation
  ([ADR 0004](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0004-read-body-child-names-on-the-name-wave.md)).
  A node's own body still
  moves names untouched, since `ipnsName` is not in the AAD (FSM1/cipher-box-next#39 D7).
- **Write-body** (scope roots only, FSM1/cipher-box-next#27 D6): `{grant ledger, write-plane
history link, directChildScopeIndex}` sealed under the root's writeKey. The
  ledger is `(recipientIdentityPk, recipientEncPk, permission, tag)`; the
  child-scope index enumerates directly-descendant scope roots for the F-4
  rotation cascade (FSM1/cipher-box-next#38 D6). Interior nodes publish no write-body at all.
- **Grant section** (scope roots only): grant blobs keyed by blinded tag
  (`tag → HPKE{readScopeSeed[, writeScopeSeed], epoch, pointerReadKey}`), the
  epoch-free grant-set commitment (ECDSA over det-CBOR `{ipnsName,
ownerPseudonymPk, [(tag, permission, pseudonymPk)]}`), owner blob, the optional
  owner-write-blob (below), ascent link (public half plaintext,
  derive-and-verified by ancestor readers), per-epoch history links, and a
  detached **structure signature** per seed-bearing structure. On the wire the
  grant-section map carries `ownerWriteBlob` as `{enc, ciphertext, sig}`
  (`GrantSection.owner_write_blob: Option<SignedOwnerWriteBlob>`, `Option` = an
  additive evolution: records predating the tag, and read-only records, decode
  with `None`). Every repeated collection in the grant section is bounded
  fail-closed at decode and
  encode — `historyLinks` at 256, `grantBlobs` and the commitment's `entries`
  both at 1024 (`too-many-structures`) — and two history links may not carry
  equal sealed bytes (`duplicate-history-link`): the gate's stage-3 work is
  `pseudonyms + structures` (engine.md "One section, one signer"), so an
  unbounded collection on **either** side of that sum is a reader-CPU amplifier,
  and each epoch mints one link under a fresh nonce, so a repeat is an authored
  anomaly. The two 1024 ceilings
  are one number: the ledger must match the committed set exactly and a re-seal
  wraps one blob per ledger row, so a commitment past the ceiling could only mint
  a section its own encoder refuses. `historyLinks` is ordered **oldest epoch
  first** — an invariant the
  codec cannot check, since a link's epoch lives in its untransmitted AAD and
  inside its ciphertext, leaving `crates/core` an opaque sealed blob.
- **History-link retention**: a link minted at epoch `e` is sealed under **its
  own** epoch's structure key and carries the _preceding_ epoch's seed, so the
  ratchet is a **contiguous chain** walkable only backward, one epoch per step.
  A **rotation** holds the one key that starts that walk — the previous epoch's
  seed — so it keeps the newest 64 links (`MAX_RETAINED_HISTORY_LINKS`) that
  actually walk and drops the rest. Order is therefore proven, not assumed, and
  the chain is bounded by design rather than by the 4 MiB block ceiling; the two
  constants are coupled, retention staying under the decode bound so that bound
  remains a malformed-input guard an honest rotator never approaches. An
  unwalkable remainder is **truncated, never refused**: the carried set is
  attacker-influenced, so failing the cut would let a committed write-grantee
  block the rotation that revokes them. A **sweep** publishes at the floor epoch
  without minting a link, so the record's epoch label can outrun the newest
  link's minting epoch — the AAD a walk needs — leaving it unable to walk or
  prune; it appends nothing, so the set cannot grow there, but it no longer
  trims an oversized one either. The window is the deepest epoch lag a backward
  walk can cover; a node past it is not lost, since the sweep re-seals it
  forward from the scope's _current_ seed.
- **Owner-write-blob** (`structTag` `owner-write-blob`): the write-plane mirror
  of the owner blob — the scope's random `writeScopeSeed` (a KDF non-edge, not
  derivable from the login secret) HPKE-sealed to the owner's **own** enc subkey,
  payload det-CBOR `{writeEpoch, writeScopeSeed}`. It hands an owner
  cold-starting on a fresh device the one write-plane input they cannot
  re-derive, so they can source `write_name_signer` and renew their own records
  (the read/consume wiring lands later, on the facade slice). It carries a
  deliberate dual-epoch binding: its HPKE **AAD** binds the **writeEpoch** (the
  write plane's own clock), while its **structure signature** binds the
  **read/envelope epoch** like every other structure, so the adoption gate
  authenticates it uniformly at `envelope.epoch`. The seed is never folded into
  the ascent link's shared override-seed payload (that would leak write
  capability to ancestor read-only readers).
- **Structure signatures** (FSM1/cipher-box-next#39 D2/D3): the rotator's pseudonym Ed25519
  signature over det-CBOR `{scopeId, epoch, structTag, recipientTag?,
H(ciphertext)}` — covering grant blobs, owner blob, owner-write-blob, ascent
  link, history links, and the write-body. Verification is per-structure and
  pure; the whole-record fail-closed policy is the engine's gate stage.
- **Pointer payloads**: the re-point object `{scopeId, currentRootName,
writeEpoch, minReadEpoch, prevRootName}`, owner-identity-signed inside the
  record, sealed under the scope's stable `pointerReadKey`. The vault pointer
  carries the same object for the root scope (FSM1/cipher-box-next#39 D5). Mailbox payloads are
  HPKE-sealed with a sender identity signature inside the seal (FSM1/cipher-box-next#39 D9), whose
  preimage binds the recipient key
  (`[domain, v, recipientEncPk, senderIdentityPk, payload]`) so a relayed item
  fails verification for any other recipient (#712); core owns their codecs and
  verify functions.

### Structure-tag registry

The `structTag` byte-space is the domain-separation registry, frozen in the KAT
manifest: `read-body` (`0x01`), `write-body` (`0x02`), `grant-blob` (`0x03`),
`owner-blob` (`0x04`), `ascent-link` (`0x05`), `history-link` (`0x06`),
`pointer-payload` (`0x07`), `mailbox-payload` (`0x08`), `owner-write-blob`
(`0x09`), `op-record` (`0x0a`), `settings-record` (`0x0b`), `content-key`
(`0x0c`). Every new tag extends the manifest and its vectors before merge; the
`owner-write-blob` KAT set is `owner_write_blob_accept` (seal/open round-trip
under a fixed enc + ephemeral) and `owner_write_blob_reject` (decode: wrong-length
seed, missing `writeEpoch`; HPKE fail-closed: tampered ciphertext/tag,
truncation, and struct-tag / scope / writeEpoch AAD transplants), with the tag's
structure-signature accept/reject riding the shared `structure_sig` families. The
`op-record` KAT set is `op_record_accept` (a metadata record with no content root
and a content record with one, each reproducing its exact bytes from a fixed
enc + ephemeral, then reading its header keylessly and opening) and
`op_record_reject` (tampered ciphertext, tampered `ownerTag`, a swapped
`contentRootCid`, a malformed `contentRootCid`, a foreign recipient, a missing
`ownerTag`, a forward `v`, and a **base-mode forgery** — a correctly framed,
correctly AAD-bound record sealed to the owner's own clear tag by a writer who
lacks the enc secret). That last vector is the sender-authentication gate: the
op record seals HPKE **auth mode** (RFC 9180 §5.1.1) with the owner's enc subkey
as both static sender and recipient, because the recipient half is public by
construction and stamped in the clear beside the records, so base mode would let
any writer sharing the per-origin queue enqueue an op that publishes under the
owner's write keys. The clear header — `v`, `ownerTag`,
`contentRootCid`, `enc`, `ciphertext` — is **frozen across format versions**: a
later `v` may change the sealed body, the suite, or the AAD layout, but never
these five keys, so any build can read any record's header. That is what lets a
reader hold a record it cannot open instead of mistaking it for corruption; the
version is bound into the AAD too, so rewriting the clear copy fails the tag.

The `settings-record` KAT set is `settings_record_accept` (an empty and a
config-shaped body, each reproducing its exact bytes from a fixed enc +
ephemeral, then opening) and `settings_record_reject` (tampered ciphertext, a
foreign recipient, a **cross-family transplant** of the op record's KEM output
into settings framing, a short and a low-order `enc`, a missing `enc` and a
missing `ciphertext`, a forward `v`, an unknown clear-header field, and the same
base-mode forgery). It seals HPKE **auth mode** to the owner's own enc subkey
for the same reason the op record does, but over a three-key clear header — `v`,
`enc`, `ciphertext`: the owner tag is bound into the AAD and **never
serialized**, because this record is published and therefore server-visible,
while the enc-subkey public half is otherwise disclosed only by out-of-band
contact-code exchange. The opener rebuilds the tag from its own key, so a record
another identity could open is unrepresentable rather than compared away, and
the transplant vector is what proves tag `0x0b` plus the distinct HPKE info
string — not the framing — keep the two families apart.

The `content-key` KAT set is `content_key_accept` (a genesis-epoch and a
max-epoch blob, each reproducing its exact bytes from a fixed enc + ephemeral,
then opening back to the version's content key) and `content_key_reject`
(tampered ciphertext, tampered `enc`, a truncated blob, a foreign recipient, the
same base-mode forgery, `scope` and `epoch` transplants, a **swapped
`contentCid`** — the binding that stops a key being moved onto another version's
blocks — a forward `v` with and without an unknown clear-header field, an
unknown clear-header field alone, a missing `enc`, and a wide and a low-order
`enc`). It seals HPKE **auth mode** to the owner's own enc subkey over the same
three-key clear header as the settings record, with `{scope, epoch}` bound in
the AAD and the `contentCid` bound inside the seal. Both directions refuse a
malformed `contentCid` release-actively (AGENTS.md rule 8): a blob whose CID the
open path would refuse is a version whose key is gone.

## KDF edge catalog

Frozen per FSM1/cipher-box-next#39 D8 (F-9). Per-node material takes the shape
`keyed_hash(key = derive_key("<edge context>", seed), message = id16)` — ids
are fixed-length message input, **never** variable context. Context strings
follow `cipherbox/v2/<edge>`; the exact string table and input layouts freeze
in the KAT manifest.

| Edge                  | Inputs                                                          | Output                                    |
| --------------------- | --------------------------------------------------------------- | ----------------------------------------- |
| node-seed             | scopeSeed, node id                                              | nodeSeed (flat within scope)              |
| read-key              | nodeSeed                                                        | readKey                                   |
| structure-key         | nodeSeed or scope seed, structTag                               | per-structure sealing keys                |
| write-seed            | writeScopeSeed, node id                                         | writeSeed (flat)                          |
| write-key             | writeSeed                                                       | writeKey                                  |
| ipns-keypair          | writeSeed                                                       | Ed25519 keypair → ipnsName                |
| ascent-keypair        | parent nodeSeed                                                 | X25519 keypair for the ascent link        |
| enc-subkey            | login secret                                                    | X25519 encryption subkey                  |
| blinded-tag           | ECDH(ownerEnc, recipientEnc) ‖ scopeRootIpnsName                | grant-blob tag                            |
| owner-pseudonym-seed  | login secret                                                    | ownerPseudonymSeed                        |
| pseudonym-sign        | ECDH(ownerEnc, writerEnc) ‖ scopeId (owner: ownerPseudonymSeed) | Ed25519 pseudonym keypair                 |
| owner-pointer-seed    | login secret                                                    | ownerPointerSeed                          |
| scope-pointer         | ownerPointerSeed, scope id                                      | per-scope pointer Ed25519 keypair         |
| pointer-read-key      | ownerPointerSeed, scope id                                      | pointerReadKey                            |
| vault-pointer-index   | login secret, index i (0 default)                               | pointer Ed25519 keypair chain             |
| settings-ipns-keypair | login secret                                                    | vault settings Ed25519 keypair → ipnsName |

Non-edges, stated to stay non-edges: content keys (random per version), scope
override seeds (random at rotation), scope seeds at grant cuts (random).

## IPNS records

Core owns records end-to-end on both platforms (FSM1/cipher-box-next#28 D2); transports are dumb
byte movers injected by the engine.

- **Create/sign**: spec-compliant V2 records (`signatureV2` over the CBOR data
  field; V1 fields emitted for ecosystem compatibility), `Value =
/ipfs/<CID>` of the DAG-CBOR envelope. First publish embeds sequence 1; CAS
  publishes embed the exact expected sequence. Validity = 90-day client-signed
  EOL (FSM1/cipher-box-next#24); TTL always explicitly set, value injected from the sync timing
  profile (FSM1/cipher-box-next#33 D3) — core never defaults it.
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

Single-implementation scope (FSM1/cipher-box-next#27 D2): KATs no longer defend cross-language
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
