# ADR 0030 — A record the owner alone authors and that seals HPKE to the owner seals in auth mode

- **Status:** Accepted on 2026-09-26 — retroactive; the rule shipped in FSM1/cipher-box#874,
  FSM1/cipher-box#878, FSM1/cipher-box#891, FSM1/cipher-box#903, FSM1/cipher-box#907,
  FSM1/cipher-box#1215, FSM1/cipher-box#1285 and FSM1/cipher-box#1521, and the blueprint
  carries it; the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-26
- **Relates to:**
  [ADR 0006](./0006-owner-local-sealed-store.md)
  (the owner-local sealed structure; amended by D11),
  [ADR 0002](./0002-owner-write-blob.md)
  (the owner write blob, a to-self structure that stays in base mode),
  [ADR 0020](./0020-the-durable-op-queue-reads-the-previous-release.md)
  (the durable op queue reads the previous release),
  [ADR 0023](./0023-the-invite-link-is-the-primary-sharing-path-and-conversion-runs-by-itself.md)
  D2 and consequence 2 (owner-local kind `0x03` stays reserved),
  [ADR 0010](./0010-recycle-bin-is-an-owner-sealed-index.md)
  and
  [ADR 0031](./0031-the-bin-index-seals-symmetrically-under-a-login-secret-key-and-exists-from-genesis.md)
  (the bin index, the one owner-only structure that does not seal HPKE),
  [#27](https://github.com/FSM1/cipher-box-next/issues/27) D3 (the crypto suite) and D6 (the
  write-body; amended by D10),
  [#39](https://github.com/FSM1/cipher-box-next/issues/39) D2 (committed writer pseudonyms, which
  reject auth mode for many-writer attribution), the `blueprint/core.md` sections "Crypto
  suite", "Envelope and structures" (the "Write-body" bullet), "Structure-tag registry" and
  "KDF edge catalog", the `blueprint/engine.md` "Sync core" section (the "Ops" bullet), and the
  `CONTEXT.md` terms "Vault settings record", "Op record", "Owner tag", "Structure tag",
  "History link" and "Encryption subkey"
- **Implemented by:** FSM1/cipher-box#874 (the settings name edge, D2), FSM1/cipher-box#878
  (the op record format, D5 and D6), FSM1/cipher-box#891 (auth mode for the op record, D1 and
  D7), FSM1/cipher-box#903 (the settings record, D3 and D4), FSM1/cipher-box#907 (the content
  key blob, D8 and D9), FSM1/cipher-box#1215 (the owner-local structure in auth mode, under
  ADR 0006, D11), FSM1/cipher-box#1285 (the write-plane history link, D10) and
  FSM1/cipher-box#1521 (per-owner staging bookkeeping, D11).

## Context

Six structures have one author and one reader, and both are the owner. Five of them seal HPKE
to the owner's own `enc-subkey`: the durable op record, the vault settings record, the staged
content key, the owner-local store blob, and the write-plane history link. The sixth, the bin
index, seals symmetrically under a login-secret key (ADR 0031) and is outside this ADR. Each of
the five needs confidentiality. Each one also needs a second property
that is easy to miss: nobody but the owner can have written it.

The obvious seal for such a record is HPKE base mode to the owner's own `enc-subkey`. Base mode
gives confidentiality only. The recipient key is public by construction: every contact code
carries it inside the subkey binding, and the op record stamps it in the clear as the owner tag
beside every queued record. Any party that holds the public half can seal a record
that the owner opens. The open succeeds, and it proves nothing about who sealed it.

Three incidents showed that this gap is reachable in normal operation:

- **The op queue.** The durable op queue is per origin, not per account
  (FSM1/cipher-box#832 section 1), so two identities on one browser profile share one store.
  FSM1/cipher-box#878 sealed the op body in base mode. FSM1/cipher-box#879 then showed the
  forgery: account A reads the owner tag from B's own records, seals a `delete` or `relink` to
  it, and enqueues it. On B's next boot the record classifies as B's, rides the pending-op
  overlay, and publishes under B's own write keys. A same-origin script, a browser extension,
  or a desktop process with write access to the journal has the same reach.
- **The write-plane history link.** FSM1/cipher-box#1191 found that a write cut sealed the link
  under the structure key of the fresh `writeScopeSeed`. Every write grantee holds that seed,
  and the link opens to the retiring seed, which derives the IPNS signing key of every
  pre-rotation name in the scope. The first cut of the fix in FSM1/cipher-box#1285 sealed the
  link to the owner in base mode. The crypto-privacy review rejected it: the link is a field
  of a write-body that every committed writer can author, so base mode lets a writer mint a
  link that the owner's resumed name wave opens, and hand that wave a seed of the writer's
  choice.
- **Owner-local stores.** ADR 0006 records how an unauthenticated invite store let a party who
  can write the store convert a forged claim into a genuine grant. The staging store is the
  same shared, host-held store as the op queue. FSM1/cipher-box#1513 found that the retire
  ledger and the doomed-name journal still wrote clear values there.

HPKE auth mode (RFC 9180 section 5.1.1) closes the gap with no new key material. The owner's
`enc-subkey` is both the static sender and the recipient. A party that opens the record must
re-derive the sender's static DH, so an open proves that the holder of the `enc-subkey` secret
produced the bytes. `crates/core/src/suite/hpke.rs` carries `hpke_seal_auth` and
`hpke_open_auth`, asserts the RFC 9180 Appendix A.1.3 vectors byte for byte, and states the
caller invariant: the opener supplies the sender key from its own trust, never from the
framing around the ciphertext.

The owner's choices behind the individual records are on wayfinder map FSM1/cipher-box#813:
FSM1/cipher-box#818 (2026-07-27) sealed the staged content key HPKE-to-self,
FSM1/cipher-box#832 (2026-07-28) gave the op record its owner tag and a sealed body, and
FSM1/cipher-box#825 section 4 (2026-07-28) moved the vault settings off the API onto a
login-secret-derived name. No record decides auth mode. FSM1/cipher-box#879 preferred it, and
FSM1/cipher-box#891 landed it. This ADR records the mode as one rule for the whole family.

The blueprint carries the rule today. The `blueprint/core.md` "Crypto suite" table lists the
auth-mode structures. The "Structure-tag registry" section gives each one its tag, its KAT
sets and its base-mode forgery vector. The "Write-body" bullet states the write-plane history
link construction. The `blueprint/engine.md` "Sync core" section states what auth mode proves
for the op record and what it does not.

## Decision

**D1 — A structure that seals HPKE to the owner's own `enc-subkey`, and that the owner alone
legitimately authors, seals in auth mode with the owner as sender and recipient.** D1 decides
the HPKE mode only, not the choice between an HPKE seal and a symmetric seal. The seal is RFC
9180 auth mode, X25519-HKDF-SHA256 with XChaCha20-Poly1305.
The owner's `enc-subkey` is both the static sender and the recipient. The open path takes the
static sender key from the opener's own key, never from a tag or a field in the framing. The
family is named: the op record, the vault settings record, the content key blob, the
owner-local blob, and the write-plane history link. The bin index is the one owner-only
structure that does not seal HPKE: it seals symmetrically under `bin-index-seal-key`, a
login-secret edge, and ADR 0031 records that seal. Each member binds its own structure tag into
the AAD, and each member's KAT reject set carries a base-mode forgery vector: a correctly framed, correctly AAD-bound blob sealed to the
owner's public half by a party without the secret. A structure that only the owner reads but
that another party legitimately authors is outside the family and stays in base mode, with its
authorship proven by the structure signature. The owner blob and the owner write blob are the
two such structures: a rotator, who can be a write grantee, re-seals both to the owner's public
half (ADR 0002). The rule landed with FSM1/cipher-box#891; this ADR records it.

**D2 — Edge `settings-ipns-keypair` derives the vault settings record's name from the login
secret, and the record seals to the owner, free of the server.** The edge is
`ed25519_from_seed(derive_key("cipherbox/v2/settings-ipns-keypair", loginSecret))`, one row of
the frozen KDF edge catalog. The name has no index and no epoch dimension. The record body
seals HPKE-to-self under the existing `enc-subkey`, so no sealing edge is added. Both inputs
are pure functions of the login secret, so the record resolves at cold start before any vault
resolve and without CipherBox infrastructure: a self-hosting owner never needs CipherBox to find
their own node. The API holds no settings endpoint. Decided on 2026-07-28 in
FSM1/cipher-box#825 section 4, which overturned the `PUT/GET /account/settings` endpoint of
FSM1/cipher-box#822; the edge landed with FSM1/cipher-box#874.

**D3 — Structure tag `settings-record` (`0x0b`) seals the vault settings record HPKE-to-self.**
The record is its own family: tag `0x0b` and the HPKE `info` string
`cipherbox/v2/settings-record`. The HPKE-to-self seal was decided on 2026-07-28 in
FSM1/cipher-box#825 section 4; the tag and the `info` string landed with FSM1/cipher-box#903.

**D4 — The settings record seals in auth mode over a three-key clear header, and a published
self-sealed record binds the owner tag into the AAD and never serializes it.** The clear header
is `v`, `enc` and `ciphertext`. The AAD is `[cipherbox/v2/aad, v, 0x0b, ownerTag]`. The owner
tag is not on the wire, because the record is published and the server sees its bytes, while
the `enc-subkey` public half otherwise leaves the device only through a contact code exchange.
The opener rebuilds the tag from its own key, so a record that another identity could open is
unrepresentable rather than compared away. The distinct `info` string and tag, not the framing,
keep the settings family apart from the op record family. The rule landed with
FSM1/cipher-box#903; this ADR records it.

**D5 — Structure tag `op-record` (`0x0a`) seals the op body to the owner under the
`enc-subkey`, and the owner tag and the content root CID stay clear.** The durable record is
`v ‖ ownerTag ‖ contentRootCid? ‖ sealed(op)`, det-CBOR, HPKE `info`
`cipherbox/v2/op-record`, with the clear header as the AAD. The owner tag is the
`enc-subkey` public half verbatim, with no derivation and no new KDF edge, so the tag names
exactly the key that opens the body. The engine compares the tag byte for byte before any
decode. A record bearing another identity's tag is retained: never replayed, never surfaced,
never removed. The content root CID stays clear so that orphan GC expands a staged root without
a key. The body holds the intent (names, kinds, parents, sizes, base sequences), so the queue
is ciphertext at rest. Decided on 2026-07-28 in FSM1/cipher-box#832, on the HPKE-to-self
pattern that FSM1/cipher-box#818 set on 2026-07-27; the format landed with
FSM1/cipher-box#878.

**D6 — The five clear-header keys of the op record are frozen across format versions, and `v`
is bound into the AAD.** The keys are `v`, `ownerTag`, `contentRootCid`, `enc` and
`ciphertext`. A later `v` may change the sealed body, the suite or the AAD layout, but never
these five keys or their CBOR types. The keyless header read therefore enforces types only;
every value-level grammar runs behind the version gate. Any build can read any record's
header, so a reader holds a record it cannot open instead of mistaking it for corruption.
Because `v` is also in the AAD, a rewrite of the clear copy fails the tag. The rule landed with
FSM1/cipher-box#878; this ADR records it.

**D7 — The op record seals in auth mode, with the owner's `enc-subkey` as sender and
recipient, and this authenticates the author only.** Authoring a queued op requires the
`enc-subkey` secret, not the public tag stamped beside the record. Auth mode does not
authenticate a record's freshness or its position: a store co-tenant can still copy, delete or
reorder whole records. The format version moved from 2 to 3 with the mode, so a base-mode
record from an earlier build classifies as retained at an unsupported version rather than
failing the auth open and being dead-lettered. The rule landed with FSM1/cipher-box#891; this
ADR records it.

**D8 — Structure tag `content-key` (`0x0c`) seals the per-version content key HPKE-to-self,
with `{scope, epoch}` in the AAD and the `contentCid` inside the seal.** The content key is a
random KDF non-edge, so it cannot be re-derived if it is lost. It seals under the
`enc-subkey`, not under the epoch-derived read key, so a rotation between the command and the
drain cannot orphan a staged key. The blob rides the op it belongs to. The epoch enters the
AAD as a value, never as a key input. The `contentCid` inside the payload binds the key to the
exact bytes it opens, so a blob moved onto another version's blocks fails closed. Both the seal
and the open refuse a malformed `contentCid` with a release-active error (AGENTS.md rule 8): a
blob whose CID the open path refuses is a version whose key is gone. A blob that does not open
dead-letters its op and releases the op's staged blocks. Decided on 2026-07-27 in
FSM1/cipher-box#818; the structure landed with FSM1/cipher-box#907.

**D9 — The content key blob seals in auth mode.** The clear header is the settings record's
three keys, `v`, `enc` and `ciphertext`, and the HPKE `info` is `cipherbox/v2/content-key`. The
rule landed with FSM1/cipher-box#907; this ADR records it.

**D10 — The write-plane history link seals to the owner in auth mode under its own tag, and
only a re-sealer that holds the owner's `enc-subkey` secret can mint one.** The link is a field
of the scope root's write-body, and the write-body stays sealed under the root's `writeKey`
(#27 D6). The link itself is no longer sealed under the structure key of the fresh
`writeScopeSeed`, as the read-plane ratchet is. It is `enc(32) ‖ ciphertext‖tag`, HPKE auth
mode with the owner as sender and recipient, under structure tag `write-history-link`
(`0x0e`), with the write epoch in the AAD. A write cut without the owner key is refused before
any seal (`ResealError::OwnerKeyRequiredForWriteCut`), so a write-grantee re-seal carries the
existing link and never cuts. The separate tag keeps the two planes' AADs distinct when the
read epoch equals the write epoch. The rule landed with FSM1/cipher-box#1285, which closed
FSM1/cipher-box#1191; this ADR records it.

**D11 — The owner-local structure seals in auth mode, and every per-owner staging surface
joins it.** The owner-local blob seals HPKE auth mode to the owner over the settings record's
three-key clear header, with the owner tag bound into the AAD and never serialized. The store
kind is a key-schedule input, bound into the AAD and completing the HPKE `info` string
`cipherbox/v2/owner-local/<name>`, and never a wire field. The kind registry is open: a new
store takes a new kind. The kinds that `blueprint/core.md` names are `received-shares`
(`0x01`), `contact-book` (`0x02`), `retire-ledger` (`0x04`) and `doomed-journal` (`0x05`);
`0x03` stays reserved (ADR 0023 D2). The KAT manifest holds three more kinds (E8), and this
rule covers them the same way. A per-owner staging surface seals its value under a new
kind rather than a clear encoding. Two shapes stay clear: every store key, because orphan GC
enumerates keys, and values that associate no two identifiers and name nothing outside the
store (the op-id high-water marks, the per-op attempt counts, and the notices of versionless
dead letters). A sealed value carries the identifier it is keyed by and refuses a mismatch, so
a value moved onto another key reads as nothing. An entry that does not open reads as
unwritten, never as a dead letter and never as a delete. The auth-mode seal landed with the
structure in FSM1/cipher-box#1215 (ADR 0006). The staging kinds and the staging-surface rule
landed with FSM1/cipher-box#1521, which closed FSM1/cipher-box#1513. This ADR records both.
The home of the staging rule in the code is the module header of
`crates/engine/src/sync/bookkeeping.rs`.

## Trust argument

- **Base mode proves nothing about the sender.** The recipient key is public. A base-mode open
  succeeds for a blob that anyone sealed to that key. For each record in the family, a forged
  blob is an authority break: a forged op publishes under the owner's write keys, a forged
  history link hands the resumed wave an attacker-chosen seed, and a forged owner-local entry
  is state the engine acts on.
- **Auth mode ties authorship to the one secret the owner alone holds.** An outsider who forges
  an auth-to-self blob must compute the static DH of the owner key with itself, `[a²]G`. That
  is square-CDH, which is equivalent to CDH. No party other than the owner holds the
  `enc-subkey` secret, so no party other than the owner can author a member of the family.
- **The opener cannot be steered to a wrong sender.** The open path takes the sender key from
  its own `enc-subkey`, never from the declared owner tag. A rewritten tag cannot steer the
  static DH of the open.
- **Families do not cross.** Each member has its own structure tag in the AAD, and four members
  have their own HPKE `info` string. A cross-family transplant vector proves that the key
  schedule, not the field set, refuses an op record ciphertext in settings framing, and a
  cross-kind vector for every ordered pair of owner-local kinds proves the kind separation.
- **The rule adds no key material.** Auth mode reuses the `enc-subkey`. No KDF edge is added for
  authorship, and the frozen catalog is unchanged by D1.
- **#39 D2 does not conflict.** #39 D2 rejects "HPKE auth-mode keyed to the write plane" for the
  seed-bearing structures of a shared scope. Those structures have many authors: any committed
  writer can rotate and re-seal them. Auth mode keyed to a write-plane key proves only that a
  write-key holder sealed the blob, which the IPNS record signature already proves, and it
  attributes nothing to one writer. #39 D2 therefore uses per-writer structure signatures.
  This ADR keys auth mode to the owner's `enc-subkey`, not to the write plane, and uses it only
  where the owner is the one legitimate author. The proof it gives, "the owner sealed this", is
  not available from the structure signature. For the write-plane history link, the write-body
  signature names the committed writer who authored the body, and a write grantee legitimately
  authors a body that carries the owner's link. So that signature cannot say who minted the
  link. The link keeps the write-body signature of #39 D2, and auth mode is a second check on
  the field. D1 excludes the owner blob and the owner write blob, which a rotator authors
  (#39 D6 calls the owner blob "grantee-maintained"), so #39 D2 stays the only rule for them.
- **Two members carry auth mode as a second layer.** The settings record is published at a name
  whose Ed25519 key derives from the login secret, so the record signature already proves the
  owner. The content key blob rides inside an op record, which is itself auth-sealed. For both,
  auth mode keeps the opened body self-authenticating apart from the path that carried it, and
  keeps one rule for the family.

## Alternatives rejected

**(a) Base mode to the owner's own `enc-subkey`.** This was the op record's first format
(FSM1/cipher-box#878) and the first cut of the write-plane history link fix
(FSM1/cipher-box#1285). Both lost to the forgery that the Context describes.

**(b) A signature over the sealed record.** FSM1/cipher-box#891 weighed it for the op record.
It needs a new wire field and a new signature preimage, it brings the identity key into every
enqueue, and it gives nothing that auth mode does not give.

**(c) A new KDF edge for a dedicated authorship key.** FSM1/cipher-box#891 weighed it. Auth
mode reuses the `enc-subkey`, so an edge would change the frozen catalog for no gain.

**(d) Accept and document the residual.** FSM1/cipher-box#879 option 2. It lost because two
accounts on one store is a requirement (FSM1/cipher-box#832), so the forgery is reachable in
normal operation.

**(e) Seal the staged content key under the read key.** FSM1/cipher-box#818 weighed it. The
read key derives from the epoch's scope seed, and a rotation draws a fresh seed, so a queued
upload would not survive a rotation that lands before the drain. The same decision rejected a
clear key at rest and an in-memory key: the first defeats the rule that no plaintext content is
staged, and the second loses the queued upload on any crash or reload.

**(f) A per-account store namespace instead of an owner tag in the op record.**
FSM1/cipher-box#832 weighed it. The account is unknown when a host names its store, and a
namespace puts the check outside Rust, once per platform, where a stale prefix gives
contamination with no signal.

**(g) The vault settings on the API.** FSM1/cipher-box#822 chose `PUT/GET /account/settings`.
FSM1/cipher-box#825 overturned it: a self-hosting owner would need CipherBox to find their own
node, and the network is canonical.

**(h) A reserved id on the `scope-pointer` and `pointer-read-key` edges instead of a new
settings edge.** FSM1/cipher-box#825 weighed it. It gives the same properties with no catalog
change, but a named edge states the intent, and the catalog is frozen against drift, not
against completion.

**(i) Keep the write-plane history link under the fresh `writeScopeSeed`, or publish no link.**
FSM1/cipher-box#1191 named both. The first gives every write grantee, including one granted
after the cut, the signing keys of every pre-rotation name in the scope. The second defers the
problem to the reclaim path that needs the link.

**(j) Keep the retire ledger and the doomed-name journal in the clear.** FSM1/cipher-box#1513
weighed an exemption for public-plane identifiers. It lost: an entry outlives the operation that
wrote it, the association it holds (this name is pending retirement) survives the delete, and a
store writer could forge an entry that the engine then spends.

## Consequences

1. **`blueprint/core.md` already carries the rule.** The "Crypto suite" table lists the
   auth-mode family (D1). The "Structure-tag registry" section states D3 to D9 and D11, and the
   base-mode forgery vector of each member. The "Envelope and structures" section's
   "Write-body" bullet states D10. The "KDF edge catalog" table carries the
   `settings-ipns-keypair` row (D2). No text change is needed.

2. **`blueprint/engine.md` already carries the rule.** The "Sync core" section's "Ops" bullet
   states D5 and D7, the retained-record rule, and the limit of what auth mode proves. No text
   change is needed.

3. **`CONTEXT.md` already carries most of the rule.** "Vault settings record" states D2.
   "Op record" and "Owner tag" state D5 and the frozen framing of D6. "Structure tag" lists
   every tag of the family. No text change is needed for these terms.

4. **ADR 0006 now reads with D11.** ADR 0006's decision names three owner-local stores and does
   not state the HPKE mode. Under this ADR, the decision reads: every owner-local durable store
   and every per-owner staging surface seals on the owner-local structure, in auth mode to the
   owner, each under its own kind. The kind list is not closed; at the time of the blueprint it
   is `received-shares`, `contact-book`, `retire-ledger` and `doomed-journal`, and the manifest
   holds three more (E8). ADR 0006 consequence 5 treats the retire ledger as a precedent for the
   seam only; the retire ledger's values now sit on the structure too. ADR 0006's third
   rejected alternative says that the op-record and grant-blob structures "carry sender
   authentication and recipient binding that owner-local state has no use for". Owner-local
   state has sender authentication since FSM1/cipher-box#1215, and the Context of this ADR shows
   why it needs it. That sentence now reads: the op-record and grant-blob structures are
   network-shaped, and the reason not to reuse them is their framing and their versioning,
   which wire compatibility governs and owner-local state does not share.

5. **#27 D6 now reads with D10.** #27 D6 says that scope roots seal
   `{grant ledger, write-plane history link}` under the root's `writeKey`. That stays true for
   the write-body. The write-plane history link inside it is, in addition, sealed to the owner
   in auth mode under tag `0x0e`, and it is not a copy of the read-plane ratchet construction. #27 D3 lists the
   HPKE uses by recipient; the auth-mode family of D1 is added to it.

6. **`CONTEXT.md` "History link" gains the write-plane construction.** The entry describes the
   read-plane ratchet only. It gains one sentence: "The write-plane link is sealed to the owner
   in HPKE auth mode under its own tag, so only the owner mints one (ADR 0030 D10)."

7. **`blueprint/core.md` section "Crypto suite" gains the citation (ADR 0030).** The citation
   goes on the auth-mode half of the "Sealing to a person" row.

8. **`blueprint/core.md` section "Envelope and structures" gains the citation (ADR 0030).** The
   "Write-body" bullet cites #27 D6 today; the write-plane history link sentence gains
   "(ADR 0030 D10)".

9. **`blueprint/core.md` section "Structure-tag registry" gains the citation (ADR 0030).** The
   op record, settings record, content key and owner-local paragraphs each cite it where they
   state the auth-mode seal. The owner-local paragraph keeps its ADR 0006 citation beside it.

10. **`blueprint/engine.md` section "Sync core" gains the citation (ADR 0030).** The "Ops"
    bullet cites it after "**auth mode**".

11. **A new member of the family needs its own tag, its own key-schedule separation, and a
    base-mode forgery vector before merge.** A new structure that seals HPKE to the owner but
    that another party can author is not a member; it stays in base mode and takes a structure
    signature. A new owner-only structure that seals symmetrically, as the bin index does, is
    outside D1 (ADR 0031).

## Residuals

**E1 — Auth mode authenticates the author, not freshness or order.** A party that can write the
op queue or the staging store can copy, delete or reorder whole records that the owner sealed.
A deleted op is lost work; a replayed or reordered op meets rebase and the conditional-delete
rule. This ADR does not cover queue integrity.

**E2 — The owner tag is in the clear in the op queue.** Anyone who reads the device's store
learns that a given `enc-subkey` public half used this device. Routing precedes decryption, so
this is the chosen trade (FSM1/cipher-box#832 section 3). A corrupted owner tag is also
indistinguishable from a foreign record, so that record is retained for ever.

**E3 — The write-plane history link shares the grant family's HPKE `info` string.**
`seal_owner_history_link` in `crates/core/src/seal/grant.rs` uses `GRANT_HPKE_INFO`. The
separation from the grant family rests on the structure tag `0x0e` in the AAD and on the mode.
The other four members have their own `info` string. The blueprint does not claim a distinct
`info` for the link, so the blueprint and the code agree; the asymmetry is recorded here.

**E4 — The KAT manifest does not pin the mode of the write-plane history link.**
`crates/core/kat/manifest.json` pins `hpkeMode: 2` for the op record, the settings record, the
content key and the owner-local structure, and `crates/core/tests/kat_manifest.rs` asserts it.
It records no mode for `write-history-link`. The base-mode forgery reject vector in
`write_history_link_reject` still proves the mode, but the mode is not a pinned manifest fact
for that member.

**E5 — `CONTEXT.md` "Encryption subkey" says "the subkey only seals".** The first bullet under
the `blueprint/core.md` "Crypto suite" table says the same: "the identity key only signs, the
subkey only seals". Under D1 the subkey also authenticates the owner's own self-sealed records.
The session module's doc comment was changed in FSM1/cipher-box#891; the glossary and that
bullet were not. The ADR records the crypto suite table and the code, which agree on D1; the
two "only seals" lines are imprecise.

**E6 — A committed writer can stall the scope's write rotations with an over-length link.** The
link field is bounded at decode, so a body whose link is over the bound does not decode. This is
the same lever as a duplicate ledger tag. `blueprint/core.md` "Write-body" states it; the bound
itself is outside this ADR.

**E7 — The settings name has no index dimension.** Unlike the vault pointer chain, the
`settings-ipns-keypair` edge cannot re-point. FSM1/cipher-box#874 accepts this: a leak that
exposes this signer implies a login-secret leak, which exposes every login-secret edge. If an
index is needed later, it is a new additive edge.

**E8 — The blueprint's owner-local kind list lags the KAT manifest by three kinds.**
`blueprint/core.md` "Structure-tag registry" names four kinds. `crates/core/kat/manifest.json`
(`ownerLocal.kinds`) also holds `scope-exit-debt` (`0x06`, FSM1/cipher-box#1755),
`pending-conversions` (`0x07`, FSM1/cipher-box#1988) and `grantee-names` (`0x08`,
FSM1/cipher-box#1987). The ADR records the blueprint list. D11's general rule covers the three
new kinds, and the manifest's cross-kind vectors cover every ordered pair of all seven.

## Gate

The suites run under the **Rust** gate: `Core KATs (native + WASM)` and
`Workspace tests (Linux)` for `crates/core` and its KAT manifest, and
`Engine simulation tests` (`cargo test -p cipherbox-engine`) for `crates/engine`.

- **D1:** `crates/core/src/suite/hpke.rs` —
  `rfc9180_a13_auth_kem_and_key_schedule`, `auth_open_fails_closed_on_a_wrong_sender`,
  `a_base_mode_ciphertext_never_opens_as_auth_mode` and
  `an_auth_mode_ciphertext_never_opens_as_base_mode`. The base-mode forgery vector of each
  member runs in `crates/core/tests/kat_manifest.rs`
  (`op_record_reject_vectors_fire_the_named_check`,
  `settings_record_reject_vectors_fire_the_named_check`,
  `content_key_reject_vectors_fire_the_named_check`,
  `owner_local_reject_vectors_fire_the_named_check` and
  `write_history_link_reject_vectors_fire_the_named_check`). No test asserts that the owner
  blob and the owner write blob stay in base mode; their mode is proven only by their accept
  vectors.
- **D2:** `crates/core/tests/kat_manifest.rs` — `kdf_catalog_freezes_names_contexts_and_layouts`
  and `kdf_edge_outputs_are_frozen_and_pairwise_separated`; `crates/engine/tests/vault_settings.rs`
  — `the_settings_name_is_derived_from_the_login_secret_alone` and
  `settings_written_on_one_device_resolve_on_a_second_device_of_the_account`. The test load
  helper passes no API client. No test asserts that a settings load makes no API call.
- **D3:** `settings_record_accept_vectors_seal_reproduce_and_open` in
  `crates/core/tests/kat_manifest.rs`; `a_settings_record_round_trips_under_the_owners_enc_subkey`
  in `crates/core/src/seal/settings_record.rs`;
  `a_second_account_cannot_open_the_first_accounts_settings` in
  `crates/engine/tests/vault_settings.rs`.
- **D4:** `crates/core/src/seal/settings_record.rs` — `the_wire_record_names_no_key`,
  `a_record_forged_from_the_public_owner_tag_never_opens`,
  `a_reframed_op_record_ciphertext_fails_the_settings_key_schedule` and
  `an_unknown_field_at_this_version_is_malformed`.
- **D5:** `crates/core/src/seal/op_record.rs` — `a_metadata_record_round_trips_and_tags_its_owner`,
  `a_content_record_exposes_its_root_cid_without_a_key`, `a_foreign_record_never_opens` and
  `a_tag_naming_a_key_that_does_not_open_the_record_is_refused`;
  `crates/engine/src/sync/record.rs` — `a_foreign_record_is_retained_rather_than_undecodable`.
- **D6:** `crates/core/src/seal/op_record.rs` —
  `a_forward_version_record_reads_its_header_but_never_opens`,
  `a_forward_version_survives_this_builds_suite_and_content_grammar` and
  `a_swapped_header_fails_closed` (the header is the AAD). No test rewrites the clear `v` and
  asserts a tag failure: any `v` other than 3 is refused before the AEAD, so the AAD binding of
  `v` is not exercised today. That is a finding.
- **D7:** `crates/core/src/seal/op_record.rs` —
  `a_record_forged_from_the_public_owner_tag_never_opens`; `crates/engine/src/sync/record.rs` —
  `a_record_forged_from_our_public_owner_tag_is_never_replayed`; the `op_record_reject`
  base-mode forgery vector; `op_record_accept_vectors_seal_reproduce_open_and_decode` asserts
  `hpkeMode` 2. The author-only limit (E1) has no test by nature.
- **D8:** `crates/core/src/seal/content_key.rs` —
  `a_blob_replayed_at_another_epoch_fails_closed`, `a_blob_replayed_in_another_scope_fails_closed`,
  `a_blob_moved_onto_another_version_fails_closed` and
  `a_malformed_content_cid_is_refused_at_seal_in_every_build`;
  `crates/engine/tests/write_plane.rs` —
  `a_version_whose_content_key_will_not_open_dead_letters_and_releases_its_blocks`. No
  engine test lands a rotation between the commit and the drain; the property rests on the
  core transplant tests.
- **D9:** `crates/core/src/seal/content_key.rs` —
  `a_blob_forged_from_the_public_enc_key_never_opens`;
  `content_key_accept_vectors_seal_reproduce_and_open` asserts `hpkeMode` 2.
- **D10:** `crates/core/src/seal/grant.rs` —
  `owner_history_link_opens_only_for_the_owner_and_only_at_its_own_aad` and
  `a_link_sealed_to_the_owner_by_anyone_else_never_opens`;
  `crates/engine/src/rotation/reseal/tests.rs` —
  `a_write_cut_mints_its_history_link_to_the_owner_alone` and
  `a_write_cut_without_the_owner_key_is_refused_before_any_seal`;
  `write_history_link_accept_vectors_seal_reproduce_and_open` and the reject vectors in
  `crates/core/tests/kat_manifest.rs`. The mode is not pinned in the manifest (E4).
- **D11:** `crates/core/src/seal/owner_local.rs` —
  `a_blob_forged_from_the_public_owner_tag_never_opens`,
  `a_blob_sealed_under_one_kind_never_opens_under_another` and
  `the_stored_blob_names_no_key_and_no_kind`; `crates/core/tests/kat_manifest.rs` —
  `owner_local_kind_registry_is_frozen` (which also asserts `hpkeMode` 2) and
  `owner_local_cross_kind_vectors_cover_every_ordered_pair`;
  `crates/engine/src/sync/bookkeeping.rs` —
  `a_stranger_and_a_sibling_kind_both_read_it_as_unwritten`; `crates/engine/src/net/retire.rs`
  — `a_ledger_entry_is_sealed_at_rest` and
  `a_ledger_value_transplanted_onto_another_target_reads_as_nothing`;
  `crates/engine/src/sync/doomed.rs` — `an_entry_is_sealed_at_rest`.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
