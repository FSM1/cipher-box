# ADR 0038 — The hosted store pins content only under the address the client declares

- **Status:** Accepted on 2026-09-26 — retroactive; the rule shipped in FSM1/cipher-box#877 and
  FSM1/cipher-box#912, and the blueprint carries it; the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-26
- **Relates to:**
  [#34](https://github.com/FSM1/cipher-box-next/issues/34) D1 (the provider layer, and hosted
  uploads ride the API to Kubo) and D7 (the read path is a trustless gateway with client-side CID
  verification), [#27](https://github.com/FSM1/cipher-box-next/issues/27) D1 (DAG-CBOR for every
  published block) and D8 (the content chunking format is left to the storage blueprint),
  [#26](https://github.com/FSM1/cipher-box-next/issues/26) D6 (a fresh content key for each
  version), [#43](https://github.com/FSM1/cipher-box-next/issues/43) (the core blueprint hands the
  chunking format to the engine), ADR 0029 (placement, and the hosted leg alone can fail an op),
  the map FSM1/cipher-box#813 resolution on FSM1/cipher-box#820, AGENTS.md rules 4, 6 and 8, the
  `blueprint/api.md` "Content plane" section, the `blueprint/engine.md` "Content plane" section
  ("Chunking and retention"), the `blueprint/testing.md` sections "The contract suite — the live
  API gate" and "crates/engine — seam fakes and the simulation harness", the `blueprint/core.md`
  "IPNS records" section (the content-CID string codec), and the `CONTEXT.md` terms "Content key",
  "Version history" and "Adoption gate"
- **Implemented by:** FSM1/cipher-box#877 (the frozen framing, D7 and D8) and
  FSM1/cipher-box#912 (the declared-address ingress, D1 to D6). FSM1/cipher-box#1310 later
  aligned the record ceiling with the block ceiling (see D8).

## Context

The engine addresses every block that it writes. A sealed content leaf is a CIDv1 with the `raw`
codec and a BLAKE3-256 multihash. A DAG root and a record head block are a CIDv1 with the
`dag-cbor` codec and the same multihash (`crates/core/src/content/cid.rs`,
`crates/engine/src/content/dag.rs`). A published IPNS record carries `/ipfs/<head CID>`, and a
version in the sealed read-body carries its `contentCid`. The reader fetches each block by that
address and verifies it before it decodes it (`read_block` in
`crates/engine/src/content/read.rs`).

Before FSM1/cipher-box#912, the hosted pin store uploaded through Kubo's `/api/v0/add`. Kubo then
chunked the body as UnixFS and returned a CIDv0 `dag-pb` SHA2-256 address. That address can never
equal the engine's address. FSM1/cipher-box#906 recorded three results:

- Every published record pointed at a block the accelerator did not hold, so the gateway GET of
  the read path returned nothing.
- `publish_record` compares the address the API returns with the head block's own address. It
  failed closed with `HeadCidMismatch` on every publish, and the drain retried without end. No
  metadata write could confirm against real infrastructure.
- The registry's `contentCids` carried engine addresses, but the pinned bytes sat under Kubo
  addresses, so the refcount rows named nothing.

The engine tests did not see the defect, because the fake block plane indexed each block under
its own address. The contract suite did not see it, because it never compared the returned
address with an address that the caller computed.

The fix had to keep two properties. First, TypeScript holds no codec and no crypto (AGENTS.md
rule 4), so the API cannot compute a BLAKE3 content address or decode a block to choose a codec.
Second, the API is zero-knowledge about content and is not a trust root for bytes: the reader
verifies every block against its address.

The security and crypto review passes on FSM1/cipher-box#912 found four more defects in the
first version of the fix. `block/put` writes the block before the address can be checked, and
the daemon runs without `--enable-gc`, so a refused upload left a block that nothing reclaims
while the quota charge was refunded. An authenticated account could add about 120 MiB of
unmetered storage each minute. `MAX_UPLOAD_BYTES` was 50 times the block ceiling, so an
over-size body became a retryable 503 that wrote one more orphan block on each retry. The
declared address was a query parameter, so edge proxies logged it. And `block/put --pin` makes a
recursive pin: Kubo's repo GC then walks the block, and one `dag-cbor` block whose bytes are not
valid CBOR aborts GC for the whole node. Any authenticated account could put one there.

The content framing is a separate, earlier question. #27 D8 left the chunking format to the
storage blueprint, and #43 handed it to the engine. The map FSM1/cipher-box#813 put the freeze in
scope on 2026-07-27, and the resolution on FSM1/cipher-box#820 decided it on 2026-07-28. The
framing has to be frozen before the write plane ships, because the chunk size is stamped into
every published root and pinned by the engine KAT set, and published roots are immutable.

`blueprint/api.md` carries the ingress rule in the "Content plane" section, in the bullets "The
caller declares the address" and "One request, one block". `blueprint/testing.md` carries the
contract assertion in "The contract suite — the live API gate". `blueprint/engine.md` carries
the framing in the "Content plane" section, in the bullet "Chunking and retention".

## Decision

**D1 — The client declares the content address, and the API pins under exactly that address.**
`POST /content/upload` carries the caller's own content address for the body. The API computes
no content address of its own. It accepts only the two frozen content-plane shapes: a CIDv1 in
base32 with a BLAKE3-256 multihash, and the codec `raw` (a sealed leaf) or `dag-cbor` (a DAG root
or a record head). It reads the codec from the fixed CID prefix (`bafkr4i` is `raw`, `bafyr4i` is
`dag-cbor`) and decodes nothing (`apps/api/src/common/content-cid.ts`). It writes the block with
`block/put` under the declared codec and a BLAKE3-256 multihash, compares the address that Kubo
returns with the declared string, and pins only when they are equal. When the store addresses
the bytes differently, or the declared string is not one of the two shapes, the API refuses with
400, and the refusal is permanent: a retry of the same body can never succeed. Kubo's
re-derivation binds the bytes to the address; the declared string is only a routing hint until
it matches. The engine client refuses a non-canonical address, or a codec outside the two, before
any request leaves the client (`ApiClient::upload` in `crates/engine/src/api/client.rs`). The rule
landed with FSM1/cipher-box#912, which took the option that FSM1/cipher-box#906 preferred; this
ADR records it.

**D2 — The declared address travels in the `X-Content-Cid` header, never in the URL.** Content
addresses correlate across accounts, and edge proxies log request URLs. The declared address
therefore stays out of the URL plane, as the registry's `contentCids` stay inside JSON bodies.
The API reads the address from the header only, and a request without it gets 400. The rule
landed with FSM1/cipher-box#912 as a review-gate fix; this ADR records it.

**D3 — One request carries one block, and every path that does not pin the block removes it.**
The declared address takes the per-CID advisory lock and keys the pin row, so a refusal
compensates the row exactly as a pin failure does. A refused declaration, a failed pin, and any
other path that ends without a pin remove the block that `block/put` wrote, because an unpinned
block is not reclaimed and a refused upload must not grow the datastore without a quota charge.
The removal cannot release another account's content, because Kubo refuses to remove a pinned
block. The rule landed with FSM1/cipher-box#912; this ADR records it.

**D4 — The transport cap is the block ceiling, and an over-size body is a permanent 413.** The
default of `MAX_UPLOAD_BYTES` is the IPFS single-block ceiling. The value of that ceiling is an
external constant, not a decision of this ADR: the Bitswap specification, section 3 "Block
Sizes", sets 2 MiB, and Kubo applies it at `block/put` as `SoftBlockLimit`. A body over the cap
gets 413 with the body code `UPLOAD_TOO_LARGE`, which is permanent for that body, not a retryable
pin-store failure. The code tells it apart from the quota 413, `QUOTA_EXCEEDED`, which clears
when the account frees space (`apps/api/src/content/upload-error-codes.ts`). The drain
dead-letters `UPLOAD_TOO_LARGE` as `PayloadRefused`. The body code came earlier, with
FSM1/cipher-box#848, and the drain classification with FSM1/cipher-box#898. The cap at the block
ceiling landed with FSM1/cipher-box#912; this ADR records it.

**D5 — Blocks are pinned direct, not recursive.** The API writes each block unpinned and then
pins it with `pin/add?recursive=false`. Every block is uploaded and registered individually, so a
recursive pin adds nothing, and a recursive pin makes repo GC walk sealed bytes that it cannot
interpret. The rule landed with FSM1/cipher-box#912; this ADR records it.

**D6 — The contract suite proves the binding against a real API and a real Kubo.** The live
contract suite asserts that the pinned address equals the caller-computed address under both
content-plane codecs, and that a declared address the bytes do not hash to is refused and
compensated. The proof is a gateway round-trip: the suite fetches `/ipfs/<declared>` back and
compares the bytes, because the API only echoes the address it was given. The rule landed with
FSM1/cipher-box#912; this ADR records it.

**D7 — The 1 MiB budget belongs to the block, so a plaintext chunk is 1,048,536 bytes.** The
engine frames content into fixed-size chunks and seals each one with core's content-seal
primitive, under the fresh content key of the version (#26 D6). The seal adds a 24-byte nonce and
a 16-byte tag, so a 1,048,536-byte plaintext chunk seals to a leaf of exactly 1,048,576 bytes
(`ContentProfile::PRODUCTION` in `crates/engine/src/content/profile.rs`). The block gets the round
number because the ecosystem sets its limits on blocks: if the 1 MiB guidance becomes a limit, a
plaintext-round chunk would fail on every block ever produced, and the chunk size is frozen in
every published root. The framing is frozen and pinned by the engine KAT manifest. This was
decided on 2026-07-28 in the FSM1/cipher-box#820 resolution under the map FSM1/cipher-box#813,
and landed with FSM1/cipher-box#877.

**D8 — The DAG is a flat root that carries an explicit format version, and its link list caps
the file size.** The root is one deterministic-CBOR block that inlines the CID of every leaf, so
the map from a byte range to its leaves is one division and ranged block and CAR fetches stay
chunk-aligned. The root carries a format version `v`, which is 1 today
(`ROOT_FORMAT_VERSION` in `crates/engine/src/content/dag.rs`). A reader reads the version first,
and a root with any other version is refused as `UnsupportedFormat`, never as a trust violation:
the content is not suspect, the client is out of date. Because the link list is inline, the root
block size caps a single file. The root must fit the record ceiling, `MAX_RESOLVED_RECORD_BYTES`,
which is the 2 MiB block ceiling (`crates/engine/src/content/limits.rs`). At the production chunk
size the cap is 55,187 links, 57,865,556,232 bytes, about 53.89 GiB
(`crates/engine/kat/vectors/content/dag_capacity_accept.json`). The figure is derived from the
record ceiling, not decided. The resolution stated about 107.78 GiB, from 110,375 links under the
4 MiB record ceiling of that date. FSM1/cipher-box#1310 set the record ceiling to the block
ceiling, and the figure fell with it (consequence 9). The encode side refuses a root over the
cap with a release-active `Err` (`DagError::RootTooLarge`), so the engine never publishes a root
that its own reader refuses (AGENTS.md rule 8). This was decided on 2026-07-28 in the
FSM1/cipher-box#820 resolution, and landed with FSM1/cipher-box#877.

## Trust argument

- **The API learns nothing that it did not already see.** It computes no address and decodes no
  block. It reads the codec from a fixed prefix of a string that the client sent, so no codec and
  no crypto enter TypeScript (AGENTS.md rule 4). A wrong prefix cannot open a hole: the codec is
  part of the address that Kubo returns, so a wrong codec fails the comparison.
- **The binding of bytes to address does not rest on the API.** Kubo re-derives the address from
  the bytes (D1). A reader then verifies every fetched block against its address before it
  decodes it, and the head address comes from a signed IPNS record that passes the adoption gate
  (AGENTS.md rule 6). An API or a Kubo that pins wrong bytes can make a block unavailable. It
  cannot make a reader adopt wrong bytes.
- **A refused upload costs the attacker quota or nothing, never free storage.** Every path that
  does not pin removes the block (D3), and the quota charge is compensated. The removal cannot
  release a block that another account pinned.
- **One account cannot stop garbage collection for the node.** Direct pins (D5) keep repo GC from
  walking a block whose bytes an attacker chose.
- **A size failure cannot loop.** A body over the block ceiling is refused before the pin store
  with a permanent 413 and its own code (D4), so the drain dead-letters it and no retry writes an
  orphan.
- **Content addresses stay out of the log plane.** The header (D2) keeps the address out of the
  request URL that edge proxies log. The API itself still sees the address, which is the accepted
  exposure of the registry.
- **A future format is not reported as a forgery.** The format version (D8) turns a root this
  build cannot read into "upgrade your client". Without it, the root would fail the invariant
  checks and read as a trust violation, and routine trust violations train members and operators
  to ignore real ones.

## Alternatives rejected

**(a) Keep Kubo's UnixFS addressing and store the engine address beside it.** This was the
defect. The published record names the engine address, and the accelerator holds the block
under another address, so no read through the accelerator can succeed.

**(b) The API derives the codec from the block.** FSM1/cipher-box#906 rejected this: the API
cannot choose between `raw` and `dag-cbor` without interpreting the bytes, and that puts a codec
in TypeScript.

**(c) The API computes the address before the write (`PinStore.hash`).** FSM1/cipher-box#912
removed it. An address computed in TypeScript is a second implementation of core's CID framing.
Kubo's re-derivation at `block/put` already gives the same binding with no code in the API.

**(d) The declared address in a query parameter.** The first version of FSM1/cipher-box#912 did
this. The review found that it exports per-account address and timing edges to the edge log
plane. D2 moved it to a header.

**(e) `block/put --pin`, a recursive pin.** One `dag-cbor` block that is not valid CBOR aborts
repo GC for the whole node, which was reproduced on the local stack. D5 pins direct.

**(f) A transport cap far above the block ceiling.** The first version of FSM1/cipher-box#912
kept a cap 50 times the ceiling. An over-size body then failed at `block/put` as a retryable 503,
and each retry re-ran the row insert and wrote another orphan.

**(g) The API checks that a `dag-cbor` body is valid CBOR.** That needs a CBOR codec in
TypeScript. Kubo refuses an undecodable `dag-cbor` block at `pin/add`.

**(h) A 256 KiB chunk.** FSM1/cipher-box#820 rejected it. The read path fetches leaves in
sequence, and each chunk costs one POST, one pin row, three advisory locks and one pin-queue
slot, so a 256 KiB chunk multiplies the latency and the server rows by four. The finer seek
granularity serves a streaming consumer that does not exist yet.

**(i) A 2 MiB chunk.** It seals to 2 MiB plus 40 bytes, which is over the block ceiling.

**(j) The round number on the plaintext.** A 1 MiB plaintext chunk seals to 1 MiB plus 40 bytes.
If the ecosystem enforces 1 MiB as a block limit, every block ever produced fails, and the chunk
size cannot change because it is frozen in every published root.

**(k) A fan-out DAG.** A tree turns the byte-to-leaf map into a walk. Flat is a wire commitment,
and FSM1/cipher-box#820 made it knowingly: fan-out is only needed above the flat cap, and a later
fan-out writer can ship behind the format version, with read support first.

**(l) No format version, as speculative generality.** A wire format cannot gain a version later
for the clients already in the field, and v2.0 had not shipped, so adding it then covered every
client.

## Consequences

1. **`blueprint/api.md` already carries D1 to D5.** The "Content plane" section states them in the
   bullets "The caller declares the address" and "One request, one block". No text change is
   needed.

2. **`blueprint/testing.md` already carries D6.** The section "The contract suite — the live API
   gate" lists the hosted-upload coverage. No text change is needed.

3. **`blueprint/engine.md` already carries D7 and D8.** The "Content plane" section states them in
   the bullet "Chunking and retention", and `blueprint/testing.md` "crates/engine — seam fakes and
   the simulation harness" states the engine KAT set that pins them. The file-size figure in that
   bullet is stale (consequence 9).

4. **`CONTEXT.md` needs no change.** The glossary has no term for the hosted ingress. "Content
   key" and "Version history" name what the framing seals and lists, and neither changes.

5. **No existing ADR changes.** This ADR records the result of two thread hand-offs. #27 D8 left
   the chunking format to the storage blueprint; D7 and D8 are that format. #34 D1 says that
   hosted uploads ride the API to Kubo; D1 to D5 are the ingress contract of that path.

6. **`blueprint/api.md` section "Content plane" gains the citation (ADR 0038)** on the bullets "The
   caller declares the address" and "One request, one block".

7. **`blueprint/testing.md` section "The contract suite — the live API gate" gains the citation
   (ADR 0038)** on the hosted-upload clause.

8. **`blueprint/engine.md` section "Content plane" gains the citation (ADR 0038)** in the bullet
   "Chunking and retention", in place of the bare "(#820)", which names a FSM1/cipher-box issue
   without its repository.

9. **`blueprint/engine.md` section "Content plane", bullet "Chunking and retention", replaces
   "~107.78 GiB" with "~53.89 GiB".** This is an editorial fix of a derived figure, not a change
   to D8. The FSM1/cipher-box#820 resolution computed 107.78 GiB as 110,375 links under the 4 MiB
   `MAX_RESOLVED_RECORD_BYTES` of that date. FSM1/cipher-box#1310 (2026-08-19) set that ceiling to
   the 2 MiB block ceiling, because a root between the two values is authorable but unpinnable, and
   it regenerated the KAT capacity vectors to 55,187 links. The code value is the only one the
   hosted store can hold: `block/put` refuses the root of a larger file.

10. **No wire format, no KDF edge and no op queue record changes.**

## Residuals

**E1 — A re-upload of an address that the account already holds skips the byte check.** When the
account holds a charged pin row for the declared address, the API answers success and calls no
pin store (`registerPin` in `apps/api/src/content/content.service.ts`). A body that does not hash
to that address therefore gets 201, not the 400 of D1. No byte is written and the stored block is
unchanged, so the store still holds only bytes that match their address, and a reader still
verifies every block. Only a client bug can send such a body.

**E2 — A removal can drop a block that a concurrent upload has written and not yet pinned.** D3
removes the block under the address that Kubo returned, but the per-CID locks key on the declared
address. A mismatched upload whose bytes address to a block that another upload has put and not
yet pinned can remove that block. The other upload's `pin/add` then fails, it compensates, and it
answers a retryable 503. The effect is availability only, and the attacker must hold the exact
ciphertext of the other upload.

**E3 — The engine does not dead-letter the 400 at once.** The API stamps no `code` on the mismatch
400, so the drain cannot tell it from a 400 that an intermediary answered, and it charges the
refusal against the attempt budget (`classify_upload` in `crates/engine/src/sync/drain.rs`; the
unit test `a_refusal_of_these_bytes_costs_an_attempt_and_never_dead_letters_on_sight`). The op
dead-letters when the budget is spent, not at the first 400. The client refuses a malformed
address before the wire (D1), so only a bytes-to-address mismatch, which is a client bug, reaches
this path.

**E4 — The operator can move the transport cap.** `MAX_UPLOAD_BYTES` is configuration. A value
above the block ceiling brings back the retryable 503 for a body between the two values, and a
value below the 1 MiB sealed leaf refuses every full production leaf as permanent. D4 holds at the
default only.

**E5 — Three rules rest on Kubo behaviour, and only the contract suite runs the real daemon.** The
block ceiling at `block/put`, the refusal to remove a pinned block, and the refusal of an
undecodable `dag-cbor` block at `pin/add` are Kubo behaviour at the version CI runs. A Kubo
upgrade can change them, and the API unit tests stub Kubo.

**E6 — The ingress and the plaintext root disclose shape.** The API and Kubo see the address, the
size and the account of every hosted block, which is the registry's accepted exposure. The DAG
root is plaintext deterministic CBOR, so anyone who holds a `contentCid` can read the chunk count
and the plaintext size. FSM1/cipher-box#820 stated this and did not change it.

## Gate

- **D1:** the Contract Suite test `upload_pins_under_the_caller_computed_content_address`
  (`crates/contract/tests/contract.rs`) proves the round-trip and the permanent 400 against a real
  Kubo. The API unit tests in `apps/api/src/registry/pin-store.test.ts` ("removes the block and
  refuses when Kubo addresses the bytes differently", "refuses a CID outside the frozen
  content-plane shapes before any RPC") and `apps/api/src/common/content-cid.test.ts` cover the
  shape check. The API integration test in `apps/api/src/content/content.http.itest.ts` ("maps a
  declared cid that does not address the bytes to a 400, compensating the charge", "rejects a
  request with a malformed cid (400), reaching neither pin store") covers the HTTP mapping. The
  engine unit test `upload_refuses_a_non_canonical_content_cid_before_the_wire` in
  `crates/engine/src/api/client.rs` covers the client-side refusal, and
  `upload_refuses_a_codec_the_ingress_does_not_accept` covers a codec outside the two. No unit
  test asserts the `cid-codec`, `mhtype=blake3` and `mhlen=32` parameters of `block/put`: the
  stub in `pin-store.test.ts` records the path only. The Contract Suite round-trip covers them.
- **D2:** the engine unit test `upload_declares_the_block_address_on_the_wire` asserts that the
  request URL carries no address and that the header does. The API integration test "rejects a
  request with no declared CID (400), reaching neither pin store" covers the server side.
- **D3:** `pin-store.test.ts` ("removes the block and refuses when Kubo addresses the bytes
  differently", "removes the block when the pin itself fails") asserts the `block/rm` call against
  a stubbed Kubo. `apps/api/src/content/content.service.itest.ts` ("rolls back to no durable state
  when the post-commit pin fails (compensation)") covers the row compensation. The Contract Suite
  proves that the quota charge is compensated. **Finding:** no test against a real Kubo proves
  that a refused block leaves the datastore.
- **D4:** `content.http.itest.ts` ("answers an over-cap authenticated upload with a real 413 JSON
  body discriminated by code UPLOAD_TOO_LARGE") covers the permanent 413, and the drain unit test
  `each_413_verdict_rests_on_the_apis_own_code` in `crates/engine/src/sync/drain.rs` covers the
  dead-letter. **Finding:** that integration test sets `MAX_UPLOAD_BYTES` to 16 bytes, so no test
  pins the default cap to the block ceiling.
- **D5:** `pin-store.test.ts` ("puts the block under the declared codec, then pins it direct")
  asserts the call order `block/put` then `pin/add`. **Finding:** no test asserts
  `recursive=false`, because the stub records the path only, and no live test checks the pin type.
  D5 has no test that fails when the pin becomes recursive.
- **D6:** the Contract Suite test `upload_pins_under_the_caller_computed_content_address` is the
  rule itself, and the Contract Suite job blocks the merge. It proves compensation through the
  quota figure only (see D3).
- **D7:** the engine KAT suite `crates/engine/tests/kat_content.rs`
  (`manifest_header_pins_the_frozen_content_format`,
  `every_accept_vector_frames_at_the_production_chunk_size`,
  `accept_vectors_reproduce_the_frozen_root_bytes`). The Engine simulation tests gate regenerates
  `crates/engine/kat` with `kat_gen` and diffs it before the suites run.
- **D8:** the same suite (`every_accept_vector_carries_the_frozen_format_version`,
  `an_unreadable_format_version_is_never_a_trust_verdict`,
  `the_flat_dag_ceiling_assembles_and_stays_readable`,
  `one_link_past_the_ceiling_fails_closed_at_assemble`). The capacity tests pin 55,187 links, the
  figure D8 states.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
