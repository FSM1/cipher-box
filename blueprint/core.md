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

| Role                       | Algorithm                                               | Used for                                                                                                                                                                                         |
| -------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Symmetric sealing          | XChaCha20-Poly1305 (24-byte nonce)                      | All sealed bodies and structures, content bytes                                                                                                                                                  |
| Key derivation             | BLAKE3 `derive_key` / `keyed_hash`                      | The whole edge catalog                                                                                                                                                                           |
| Sealing to a person        | RFC 9180 HPKE (X25519-HKDF-SHA256 + XChaCha20-Poly1305) | Base mode: grant blobs, owner blob, owner-write-blob, ascent links, mailbox payloads; auth mode (owner to owner): op record, settings record, content key, owner-local, write-plane history link |
| Pairwise secrets           | X25519 ECDH                                             | Blinded tags, grantee pseudonym derivation                                                                                                                                                       |
| Identity signing           | secp256k1 ECDSA (RFC 6979) over det-CBOR                | Grant-set commitment, subkey binding, re-point object, mailbox sender signature                                                                                                                  |
| Pseudonym + record signing | Ed25519                                                 | Structure signatures; IPNS records                                                                                                                                                               |

- Every user derives an **X25519 encryption subkey** from their login secret;
  the identity key only signs, the subkey only seals. The **subkey binding**
  (ECDSA over det-CBOR `{identityPk, encSubkey}`) and the **contact code**
  codec (`{identityPk, encSubkey, bindingSig}`, ~130 bytes, QR/URL-encodable,
  binding verify mandatory and fail-closed at import) are core exports.
- An **X25519 public key** is adopted only as the **canonical encoding of a
  prime-order point** — the u-coordinate is lifted to Edwards, tested for
  torsion, and re-encoded back to the input. Both halves close one attack: ECDH
  decides on the point while HPKE binds the supplied bytes into `kem_context`,
  so any second encoding reaching one point lets a blob be addressed to a key
  whose real holder can never open it, under a blinded tag that still verifies.
  A small-order blacklist is not sufficient for the first half — clamping
  collapses every cofactor twin `P + t` (`t` in `E[8]`) onto `P` in the shared
  secret — and masking bit 255 is not sufficient for the second, since the
  ignored bit and the mod-`p` wraparound both survive into `to_bytes`.
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
- **Carried unknown fields** (FSM1/cipher-box-next#27 D10): a rewrite preserves every top-level
  and `epochTag` field it does not type, byte-stable, so an old client never
  strips a newer one's. The set comes off a resolved record and so runs to the
  same 2 MiB block ceiling every read enforces — which makes it
  attacker-influenced, since anyone who can publish at a name could otherwise
  push every later re-author of that node past the ceiling and stop the owner's
  own publishes there, the revoking rotation included. So the produce side
  **truncates, never refuses**: an encode over the ceiling cuts carried fields
  until the block fits, and refuses only what the typed fields alone overflow.
  `grantSection` and `writeSealed` are never cut — losing either publishes a
  record the reader rejects outright, which is the refusal the cut exists to
  avoid. Cuts run largest first, so the fewest fields go and one pass relieves
  the pressure; that bounds the _count_, not the bytes, and a party padding a
  record below the size of an honest field can aim the first cut at it. What
  keeps that from mattering is that a field carrying a trust decision **says so
  on the wire**, rather than relying on every already shipped reader knowing its
  name. A cut is reported, never silent.
  The declaration is a reserved one-byte key prefix, `!`: a carried field whose
  key begins with it is **critical**, and a rewrite keeps it or refuses, never
  silently drops it. Membership in the uncuttable set is frozen when each binary
  ships, so it cannot express a field minted later; a marker rides the bytes and
  can. The canonical map-key comparator is length-first over the encoded key, so
  a one-byte prefix perturbs no ordering semantics, and the marker is honoured
  inside `epochTag` as well as at top level. `grantSection` and `writeSealed`
  stay uncuttable under their own **reserved names**, from before the marker;
  those names are frozen in the manifest beside the prefix
  (`seal.uncuttableKeys`), since honouring the marker alone would cut them and
  publish a record every reader rejects.
  A critical field must be **kind-uniform** — present, or absent, independently
  of whether the node is a file or a folder. Its key name is plaintext on an
  envelope whose whole purpose is kind-uniformity, so a kind-correlated marker
  would hand the untrusted server the one bit the envelope exists to withhold.
  The marker ships with a frozen **critical-bytes budget**,
  `MAX_CRITICAL_CARRIED_BYTES` = 16 KiB, over the encoded cost of every marked
  field plus `writeSealed`, at both levels. Without it a hostile publisher marks
  padding critical and wedges the name for good — strictly worse than the refusal
  the cut replaced, since no rotation clears an uncuttable field. Decode and
  encode refuse an over-budget envelope with the same `too-many-structures`
  verdict, release-active on the encode side. `grantSection` is the budget's one
  exclusion, and only because it carries its own `MAX_GRANT_SECTION_BYTES`: a
  budget large enough to hold a grant section would be no budget at all. The
  budget stays well under the write-body's 64 KiB re-seal headroom, so a maximal
  critical set cannot make a maximal write-body's re-seal unencodable. The value
  is frozen in the KAT manifest (`seal.criticalCarriedMaxBytes`, beside
  `seal.criticalKeyPrefix`).
  What the budget bounds is the **size** of that wedge, not its permanence: a
  publisher who fills the budget exactly still claims it for as long as the name
  lives, because a marked field is carried verbatim by every later re-author and
  only a fresh node id sheds it. Whether a re-author may drop a marked field it
  has never seen adopted is open, and has to be settled before a `!` field ships.
- **Envelope size bounds**: the decoder refuses on the **raw length before it
  walks anything**, at the same 2 MiB block ceiling every read enforces
  (`seal.envelopeMaxBytes`). The input is attacker-supplied and the carried set
  it holds is preserved by construction, so the total is the only cap on the
  walk itself — the same shape the grant section already refuses in, rather than
  two decode paths guarding one class of malformed input differently.
  `readSealed` carries a bound of its own, `MAX_READ_SEALED_BYTES` = the block
  ceiling minus a frozen 32 KiB envelope headroom, so 2,064,384 bytes. It is the
  envelope's one attacker-sized typed field and, unlike the carried set, it is
  uncuttable: bounding it lets the refusal **name the field that broke** instead
  of reporting only that the record was too big, which a whole-record ceiling
  applied before any structure is known cannot do. Its floor is honest use —
  `seal_read_body` mints whatever a folder's child listing needs, so a bound near
  the framing headroom would refuse folders this codec's own encoder produces,
  the produce-side wedge one layer up that the grant section's floor also
  avoids.
  **What each bound is charged against is part of the frozen number**, because
  the bounds around it disagree: `seal.envelopeMaxBytes` is charged on the
  **whole encoded envelope**, det-CBOR head included; `seal.readSealedMaxBytes`
  on the **byte-string payload alone**, its head excluded, as
  `grant.grantSectionMaxBytes` also is; `seal.criticalCarriedMaxBytes` on the
  encoded cost of each entry, **key and framing included**. An implementation
  that picks a neighbouring convention refuses at a byte this one accepts, and a
  head published in that few-byte window is a node the other client can never
  open — so the charge is stated here rather than left to be inferred.
  Decode and encode refuse an over-bound envelope, on any of these bounds, with
  the same `too-many-structures` verdict, release-active on the encode side; the
  values are frozen in the KAT manifest rather than in two-megabyte reject
  vectors. The block ceiling never turns the carried set's **truncate, never
  refuse** law into a refusal: an encode within a limit measures its candidate
  and cuts against the lower of that limit and the ceiling before it mints
  anything, so only what the uncuttable fields alone overflow is refused.
  A maximal `readSealed` and a maximal grant section are not jointly reachable
  inside one block, exactly as the section's and write-body's maxima are not; the
  envelope's own total is what refuses the combination, surfaced to the engine as
  `HeadTooLarge` — naming the bound that refused, so a blocked publish is charged
  as a head-size refusal rather than an encoder fault.
- **Write-body** (scope roots only, FSM1/cipher-box-next#27 D6): `{grant ledger, write-plane
history link, directChildScopeIndex}` sealed under the root's writeKey. The
  ledger is `(recipientIdentityPk, recipientEncPk, permission, tag)`; the
  child-scope index enumerates directly-descendant scope roots for the F-4
  rotation cascade (FSM1/cipher-box-next#38 D6). That index is writer-authored
  and owner-signature-free like the history link, so it is bounded fail-closed at
  decode and encode at 1024 entries, each entry's opaque `ipnsName` at the name
  codec's own ceiling (`too-many-structures`) — unbounded, a committed writer
  grows it until the head block the revoking rotation re-seals it into no longer
  fits the block ceiling every read enforces. The ledger's row count is bounded
  the same way, at `MAX_GRANT_BLOBS` (1024), the ceiling its own commitment
  already carries. Interior nodes publish no write-body at all.
  Those per-field bounds narrow the byte lever but cannot close it: the
  preserved unknown maps at every level are the one thing a decoder must keep
  byte-stable, so refusing a body for the size of what it preserves would refuse
  honest forward-compatible bodies too. What closes it is a **total encoded-size
  bound**, `MAX_WRITE_BODY_BYTES` = the block ceiling (2 MiB) minus a frozen
  64 KiB re-seal headroom for the seal, section and envelope framing a re-seal
  wraps the body in. The headroom reserves nothing for the grant section's own
  contents, which are bounded far above it, so the bound narrows the head-size
  lever rather than closing it — the whole-record ceiling stays the engine's
  `HeadTooLarge` backstop. Decode and encode refuse an over-bound body with the
  same `too-many-structures` verdict, release-active on the encode side; the
  value is frozen in the KAT manifest (`grant.writeBodyMaxBytes`) rather than in
  a multi-megabyte reject vector.
  The measured length **charges `writeHistoryLink` at its own 512-byte ceiling**
  whatever the body actually carries. That field is the one thing a re-seal
  replaces, so charging it flat is what makes "this body decodes" imply "this
  body still encodes after a cut swaps its link" — otherwise a committed writer
  pads to exactly the bound with an empty link, and the freshly minted link of
  the rotation that revokes them pushes the re-encode over, a permanent refusal
  at a size the attacker chose. A re-seal that still cannot author its body
  refuses under its own name (`write-body-too-large`) rather than the generic
  encode fold.
  None of this weakens the strict-preserve rule: that law governs field
  **treatment** — never strip, keep unknowns byte-stable — not total size, and a
  size constant every client shares refuses the same bodies everywhere, so a body
  an old client re-emits stays conforming by construction.
  The write-plane history link departs from the read plane's ratchet
  construction and carries its own struct tag, `write-history-link` (`0x0e`): it
  is **HPKE auth-mode sealed by the owner to the owner**
  (`enc(32) || ciphertext||tag`), not symmetrically sealed under the fresh
  `writeScopeSeed`'s structure key. That seed ships in every write grantee's
  grant blob, while the retiring seed the link carries derives the IPNS signing
  key of every pre-rotation name in the scope, and the link's only consumer —
  the resumed name wave — is owner-only. Auth mode rather than base because the
  field lives inside a body every committed writer can author and the owner's
  enc subkey is public: base mode would let a writer hand the resumed wave a
  seed of their choosing to derive signing keys from. Only a re-sealer holding
  the owner encryption subkey can mint one, so a write-grantee re-seal carries
  the existing link and never cuts. The field is bounded fail-closed at decode
  and encode at 512 bytes (`too-many-structures`); over-length bytes make the
  record undecodable, so — like a duplicate ledger tag — a committed writer can
  stall the scope's rotations until the owner republishes the root from a
  gate-passed earlier record. A re-seal handed an over-length link drops it
  rather than failing, so the produce side can never emit a body its own
  decoder refuses.
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
  Those ceilings bound counts, not bytes. Every sealed blob in the section is
  opaque, every level carries a preserved `unknown` map, and none of those bytes
  is covered by the grant-set commitment or by a per-structure signature — which
  sign specific fields and `H(ciphertext)`, not the framing. Unbounded, a
  committed writer inflates the framing once and every later re-author of that
  root carries it verbatim, because the section rides an uncuttable carried
  field. What closes that is a **total encoded-size bound**,
  `MAX_GRANT_SECTION_BYTES` = the block ceiling (2 MiB) minus a frozen 48 KiB
  envelope headroom, so 2,048,000 bytes. Decode and encode refuse an over-bound
  section with the same `too-many-structures` verdict, release-active on the
  encode side; the value is frozen in the KAT manifest
  (`grant.grantSectionMaxBytes`) rather than in a two-megabyte reject vector.
  The value sits in the one band the surrounding constants leave. Its **floor**
  is `MAX_WRITE_BODY_BYTES`: the sealed write-body rides in the section, so a
  smaller bound would refuse a body the write-body codec mints — a produce-side
  wedge one layer up. Its **ceiling** is the block every envelope must fit, less
  the framing of the envelope the section rides in — which is what the 48 KiB
  headroom reserves, and what the critical-bytes budget above draws from. Like
  the write-body's, this bound narrows the head-size lever rather than closing
  it, so the whole-record ceiling stays the engine's `HeadTooLarge` backstop.
  The bound is therefore also a **joint ceiling**, and deliberately so: a section
  carrying a write-body at `MAX_WRITE_BODY_BYTES` has about 16 KiB left for
  everything else, which is roughly 51 grant blobs or 70 history links — far
  under the 1024 and 256 the per-collection bounds allow. Those maxima were never
  jointly reachable inside one block; what changes is that the section codec now
  refuses the combination outright instead of minting a head that no later write
  at that root could fit. Honest use is nowhere near it: producers prune history
  links to a far smaller retained window, and a body only approaches its bound
  through preserved unknowns.
- **History-link retention**: a link minted at epoch `e` is sealed under **its
  own** epoch's structure key and carries the _preceding_ epoch's seed, so the
  ratchet is a **contiguous chain** walkable only backward, one epoch per step.
  A **rotation** holds the one key that starts that walk — the previous epoch's
  seed — so it keeps the newest 64 links (`MAX_RETAINED_HISTORY_LINKS`) that
  actually walk and drops the rest. Order is therefore proven, not assumed, and
  the chain is bounded by design rather than by the 2 MiB block ceiling; the two
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
  of the owner blob — the scope's `writeScopeSeed` HPKE-sealed to the owner's
  **own** enc subkey, payload det-CBOR `{writeEpoch, writeScopeSeed}`. The seed
  is random and a KDF non-edge at every scope and epoch but one: the vault root's
  genesis epoch derives it from the login secret (`genesis-write-scope-seed`,
  ADR 0007), and the first write rotation draws its replacement like every
  rotation after it. It hands an owner cold-starting on a fresh device a
  write-plane input they otherwise cannot re-derive, so they can source
  `write_name_signer` and renew their own records
  (the read/consume wiring lands later, on the facade slice). It carries a
  deliberate dual-epoch binding: its HPKE **AAD** binds the **writeEpoch** (the
  write plane's own clock), while its **structure signature** binds the
  **read/envelope epoch** like every other structure, so the adoption gate
  authenticates it uniformly at `envelope.epoch`. The seed is never folded into
  the ascent link's shared override-seed payload (that would leak write
  capability to ancestor read-only readers).
- **Structure signatures** (FSM1/cipher-box-next#39 D2/D3): the rotator's pseudonym Ed25519
  signature over det-CBOR `{scopeId, epoch, structTag, recipientTag?,
H(signed bytes)}` — covering grant blobs, owner blob, owner-write-blob, ascent
  link, history links, and the write-body. The signed bytes are the structure's
  `ciphertext`, with one exception: an **ascent link** signs over the det-CBOR
  binding `{ascentPublic, ciphertext, enc}`, so its plaintext public half is
  covered too. Outside the signature that field is authenticated by possession of
  `writeScopeSeed` alone — a holder could republish the root with `ascentPublic`
  swapped for a key it holds, leaving every ciphertext, signature and commitment
  byte-identical, and the next honest scope-exit rotation would seal a freshly
  minted override seed to the planted key. The binding does not make the field
  unforgeable — a **committed** writer can plant its own key and sign the swapped
  body — but it makes the swap attributable to a pseudonym the owner committed,
  and an owner cut overwrites it by deriving the public half from the parent seed
  instead of carrying it. Verification is per-structure and pure; the
  whole-record fail-closed policy is the engine's gate stage.
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
(`0x0c`), `owner-local` (`0x0d`), `write-history-link` (`0x0e`), `bin-index`
(`0x0f`). Every new tag extends the manifest and its vectors before merge; the
`write-history-link` KAT set is `write_history_link_accept` (the flat
`enc || ciphertext||tag` envelope
reproduced from a fixed owner keypair and ephemeral, then reopened) and
`write_history_link_reject` (tampered ciphertext/tag, truncation, and
read-plane-struct-tag / scope / writeEpoch AAD transplants, plus a
**base-mode-shaped forgery** — a correctly framed link sealed to the owner by a
write grantee, which auth mode refuses). The `owner-write-blob` KAT set is
`owner_write_blob_accept` (seal/open round-trip
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
(tampered ciphertext, a substituted `enc`, a truncated blob, a foreign recipient,
the same base-mode forgery, `scope` and `epoch` transplants, a **swapped
`contentCid`** — the binding that stops a key being moved onto another version's
blocks — a forward `v` with and without an unknown clear-header field, an
unknown clear-header field alone, a missing `enc`, and a wide, a low-order, a
non-prime-order and a non-canonical `enc`). It seals HPKE **auth mode** to the owner's own enc subkey over the same
three-key clear header as the settings record, with `{scope, epoch}` bound in
the AAD and the `contentCid` bound inside the seal. Both directions refuse a
malformed `contentCid` release-actively (AGENTS.md rule 8): a blob whose CID the
open path would refuse is a version whose key is gone.

The `owner-local` structure carries **every durable store the owner alone
authors and reads** — received shares, the contact book, the invite records, and
the engine's per-owner staging bookkeeping (the retire ledger and the
doomed-name journal) — under one format rather than one module per store
(FSM1/cipher-box-next ADR 0006). It seals HPKE **auth mode** to the owner's own
enc subkey over the same three-key clear header as the settings record (`v`,
`enc`, `ciphertext`), with the owner tag bound into the AAD and never
serialized. What is new is the **store kind**: a frozen registry of
`(name, discriminator)` pairs — `received-shares` (`0x01`), `contact-book`
(`0x02`), `invite-records` (`0x03`), `retire-ledger` (`0x04`), `doomed-journal`
(`0x05`) — whose discriminator rides the AAD and whose name completes the HPKE
`info` string `cipherbox/v2/owner-local/<name>`. The kind is a key-schedule input and
**never a wire field**, so a blob offered as the wrong store is refused by the
AEAD rather than by a comparison: a decryption failure, not a parse failure. The
KAT set is `owner_local_accept` (an empty body, plus one populated body per kind,
each reproducing its exact bytes from a fixed enc + ephemeral, then opening) and
`owner_local_reject` (the settings record's reject family — tampered ciphertext,
a foreign recipient, a cross-family transplant, a short and a low-order `enc`, a
missing `enc` and a missing `ciphertext`, a forward `v`, an unknown clear-header
field, and a base-mode forgery — plus a **cross-kind negative for every ordered
pair of kinds**, which is what proves the discriminator earns the separation that
distinct per-store `info` strings used to give for free).

### Bin index

The recycle bin is one owner-sealed, vault-level index record
([ADR 0010](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0010-recycle-bin-is-an-owner-sealed-index.md)).
It is published at the `bin-index-ipns-keypair` name and sealed
**symmetrically** under `bin-index-seal-key`. That follows the rule the record
family runs on: a structure whose readership is exactly one, forever, seals
symmetrically under its own login-secret edge, because possession of the key is
already the author proof; a structure a public half must address seals
HPKE-to-self. Its clear header is two keys, `v` and `sealed`, frozen across
format versions; the version is bound into the AAD
`[cipherbox/v2/aad, v, 0x0f]`, so rewriting the clear copy fails the tag.

The body is `{entries[], pad, revision}`. Each entry carries `nodeId`,
`ipnsName`, `kind`, `originParent`, `originName`, `deletedAt`, `scopeId`, and
`heldKey`, which the codec takes as optional. `ipnsName` is the only remaining
route to a record no folder names, and `heldKey` is the scope-seed-shaped key
the delete re-keyed the doomed subtree under: every node of that subtree keys at
`readKey(nodeSeed(held, nodeId))`, so the one key opens the whole subtree. Every
soft delete re-keys, so every entry this build writes carries one. `revision` is
what the floor law orders two records by when the outer IPNS sequence cannot
tell them apart. Duplicate
`nodeId` is fail-closed at decode: two entries for one node would let restore and
purge pick a winner by position.

**The body pads to a fixed rung before the seal.** The record is published, so
its ciphertext length is server-visible, and an unpadded body would disclose the
soft-delete count to within one entry. That is a deletion-activity count, not a
size. The rungs are 4 KiB,
16 KiB, 64 KiB, 256 KiB, 1 MiB, and the block ceiling less the seal, so the
ladder steps by 4x until the last rung, which the block ceiling cuts short. It
starts at 4 KiB, which holds roughly two dozen entries at the ~170 bytes a
populated entry costs: a floor that already covers the great majority of vaults,
against a cost paid on every publish and every 90-day re-PUT. Its top rung is the
largest body a published block admits, so a body no rung takes is refused rather
than published unpadded.

Each rung admits bodies only up to its **cap**, which sits below the rung by the
largest distance the pad cannot span. Where the CBOR byte-string head steps
width, a handful of totals are unreachable, and without the caps a body that grew
one byte across such a gap would climb a whole rung. That 4x jump in the
published length would name the body size to the byte — worse than the bounded
leak the padding closes, and steerable by a write grantee, who chooses the file
names that become `originName`. The caps make the rung a body takes rise
monotonically with the body, which is the property the KAT walks.

`pad` is schema, not payload: a decode drops it rather than preserving it, so a
rewrite re-pads to the rung its own body needs. Both halves of the padded form
are fail-closed and symmetric across encode and decode — a plaintext whose length
is off every rung, and a `pad` byte that is not zero, are both
`non-canonical-padding`, a trust violation. The zero rule is what makes the
padded form canonical and deterministic, which the fixed-parameter KAT regime
needs; it is also fail-safe, because an unwiped buffer could otherwise carry
`heldKey` bytes into a published record. The decoder tests rung membership, not
minimality: an over-padded body opens and the next rewrite pads it back down, so
a later encoder change is not a hard break.

The ladder is scoped to the record version. A reader refuses an off-rung length
as a trust violation, not as an unsupported version, so **any change to the rungs
is a `BIN_INDEX_V` bump** — otherwise an older client reads a newer record as
tampering.

Three channels the padding does not close, stated so the freeze does not imply
otherwise. The bin record's IPNS **sequence** is signed cleartext, so one resolve
bounds the number of bin publishes the owner ever made — a cumulative count along
the same axis as the one the pad hides. A bin publish also **coincides** with the
re-key's own republishes. Those name the exact set of records the delete binned,
not merely its size, and the republisher inventory holds that set for the EOL
term. Blunting it needs decoy re-keys or a wave spread over ticks, which is
engine work. And the record's **existence**
says the bin is non-empty, so the client publishes an empty bin index at vault
genesis whatever the retention setting. Mitigating the first two is engine work:
a fresh nonce per seal makes a no-op republish byte-indistinguishable from a real
edit, so a decoy publish blunts both.

The KAT set is `bin_index_accept` (an empty index, a populated one, and the two
**rung edges** — a body at the first rung's cap and the one character more that
climbs to the second — each reproducing its exact plaintext
and record from a fixed seal key and nonce, then opening) and `bin_index_reject`
(tampered ciphertext, a foreign seal key, a **structure-tag transplant** of the
same plaintext under the read-body tag, a tampered nonce prefix, an off-rung
length, a non-zero pad byte, a missing `pad`, a duplicate `nodeId`, a short
sealed blob, a wrong-length `heldKey`, a missing `originParent`, a missing
`sealed` and a missing `v`, an unrecognised `kind`, an over-bound `ipnsName`, a
forward `v`, and an unknown clear-header field). The accept family also asserts
the property the padding buys: two bodies on one rung seal to records of one
length, whatever their entry counts. Each vector that seals a distinct plaintext gets its own
nonce, so the corpus models the nonce rule the seal path states rather than the
reuse it forbids.

## KDF edge catalog

Frozen per FSM1/cipher-box-next#39 D8 (F-9). Per-node material takes the shape
`keyed_hash(key = derive_key("<edge context>", seed), message = id16)` — ids
are fixed-length message input, **never** variable context. Context strings
follow `cipherbox/v2/<edge>`; the exact string table and input layouts freeze
in the KAT manifest.

| Edge                     | Inputs                                                          | Output                                          |
| ------------------------ | --------------------------------------------------------------- | ----------------------------------------------- |
| node-seed                | scopeSeed, node id                                              | nodeSeed (flat within scope)                    |
| read-key                 | nodeSeed                                                        | readKey                                         |
| structure-key            | nodeSeed or scope seed, structTag                               | per-structure sealing keys                      |
| write-seed               | writeScopeSeed, node id                                         | writeSeed (flat)                                |
| write-key                | writeSeed                                                       | writeKey                                        |
| ipns-keypair             | writeSeed                                                       | Ed25519 keypair → ipnsName                      |
| ascent-keypair           | parent nodeSeed                                                 | X25519 keypair for the ascent link              |
| enc-subkey               | login secret                                                    | X25519 encryption subkey                        |
| blinded-tag              | ECDH(ownerEnc, recipientEnc) ‖ scopeRootIpnsName                | grant-blob tag                                  |
| owner-pseudonym-seed     | login secret                                                    | ownerPseudonymSeed                              |
| pseudonym-sign           | ECDH(ownerEnc, writerEnc) ‖ scopeId (owner: ownerPseudonymSeed) | Ed25519 pseudonym keypair                       |
| owner-pointer-seed       | login secret                                                    | ownerPointerSeed                                |
| scope-pointer            | ownerPointerSeed, scope id                                      | per-scope pointer Ed25519 keypair               |
| pointer-read-key         | ownerPointerSeed, scope id                                      | pointerReadKey                                  |
| vault-pointer-index      | login secret, index i (0 default)                               | pointer Ed25519 keypair chain                   |
| settings-ipns-keypair    | login secret                                                    | vault settings Ed25519 keypair → ipnsName       |
| bin-index-ipns-keypair   | login secret                                                    | bin index Ed25519 keypair → ipnsName            |
| bin-index-seal-key       | login secret                                                    | the bin index body's sealing key                |
| bin-held-key             | login secret, node id, deletedAt                                | the key one soft delete re-keys a subtree under |
| genesis-read-scope-seed  | login secret                                                    | the genesis scope's read (override) seed        |
| genesis-write-scope-seed | login secret                                                    | the genesis writeScopeSeed                      |

The three bin edges are the owner's alone: no grant carries them, which is what
makes a soft delete cut a grantee's access that key regression cannot undo
(ADR 0010). No scope seed of any epoch is an input, so no grantee can reach one.
`bin-held-key` binds `deletedAt` as well as the node id, so a node that is
binned, restored, and binned again re-keys under fresh bytes and a disclosed
held key opens one bin generation rather than every later one.

`bin-index-seal-key` takes no epoch input, so it never rotates. Every publish of
the bin index, on every device, seals under it, and two devices publish that
record concurrently under one CAS guard. Each seal's nonce must therefore be
drawn from a CSPRNG: a counter or a `revision`-derived nonce is unique on one
device and collides across two, and reuse discloses every held key the two
bodies carry. The padding raises that stake: most of a padded plaintext is known
zeros at a known offset, so a colliding pair yields raw keystream and decrypts
the other body outright rather than leaving an XOR to separate.

Non-edges, stated to stay non-edges: content keys (random per version), and
every scope seed a rotation or a grant cut mints (random). The genesis pair is
the one exception, because genesis alone has no predecessor to be idempotent
against: deriving it is what makes two mint attempts by one account reproduce
one vault rather than fork two (ADR 0007). A KAT pins the derived genesis root
name, so that property cannot drift silently.

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
