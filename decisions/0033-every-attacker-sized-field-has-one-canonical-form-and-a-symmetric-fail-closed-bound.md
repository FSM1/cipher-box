# ADR 0033 — Every attacker-sized field has one canonical form and a symmetric fail-closed bound

- **Status:** Accepted on 2026-09-26 — retroactive; the rule shipped in FSM1/cipher-box#789,
  FSM1/cipher-box#1049, FSM1/cipher-box#1098, FSM1/cipher-box#1285, FSM1/cipher-box#1286,
  FSM1/cipher-box#1299, FSM1/cipher-box#1368, FSM1/cipher-box#1454, FSM1/cipher-box#1496,
  FSM1/cipher-box#1748 and FSM1/cipher-box#1834, and the blueprint carries it; the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-26
- **Relates to:**
  [#27](https://github.com/FSM1/cipher-box-next/issues/27) "Pinned structure formats" (history
  links "pruned as the sweep converges", amended by D12) and D10 (tolerate and round-trip unknown
  fields),
  [#38](https://github.com/FSM1/cipher-box-next/issues/38) D6 (the direct-child-scope index),
  [ADR 0012](./0012-the-drain-carries-the-write-wave-forward.md)
  D4 (an epoch the ratchet cannot reach is charged, not refused),
  [ADR 0021](./0021-a-read-opens-an-epoch-lagged-interior-record.md)
  (a node outside the retained window is `ContentUnavailable`),
  [ADR 0026](./0026-a-scope-root-takes-many-grants.md)
  D6 (a new grantee walks the history links back), AGENTS.md rule 8 in FSM1/cipher-box
  (encode/decode fail-closed symmetry), the `blueprint/core.md` "Crypto suite", "Envelope and
  structures", "IPNS records" and "KAT regime" sections, the `blueprint/engine.md` "sweep"
  section, and the `CONTEXT.md` "History link", "Write-body" and "Scope root" terms
- **Implemented by:** FSM1/cipher-box#1049 (grant-section counts, duplicate history links,
  retention), FSM1/cipher-box#1098 (commitment entries), FSM1/cipher-box#1285 (write-plane
  history link bound), FSM1/cipher-box#1748 (the re-seal refusal of an over-length carried
  write-plane history link), FSM1/cipher-box#1299 (child-scope index), FSM1/cipher-box#1368
  (ledger rows, write-body total), FSM1/cipher-box#1454 (grant-section total), FSM1/cipher-box#1496 (envelope
  total, `readSealed`, charged measures), FSM1/cipher-box#1834 (the manifest `bounds` table),
  FSM1/cipher-box#789 (content-CID string codec) and FSM1/cipher-box#1286 (X25519 key adoption).

## Context

A scope root carries fields that a party other than the owner authors. Any committed write
grantee authors the write-body: the grant ledger, the write-plane history link and the
direct-child-scope index. No owner signature covers them. The grant section carries opaque
sealed blobs, and every level of every structure carries a preserved `unknown` map. Anyone who
can publish at a name controls the size of these fields, up to the block ceiling.

The block ceiling is an external value, not a decision of this ADR: 2 MiB (2,097,152 bytes), the
IPFS single-block limit of the Bitswap specification, section 3 "Block Sizes", which Kubo
enforces at `block/put` as `SoftBlockLimit` (`v0.42.0`). Kubo v0.42.0 refused a 4 MiB block with
`produced block is over 2MiB` in the FSM1/cipher-box#915 measurement. `crates/core` holds the
value once as `MAX_BLOCK_BYTES` (`crates/core/src/seal/envelope.rs`), and the engine aliases it.

The review gates found the same defect class many times, one field at a time:

- **Reader CPU.** The adoption gate authenticates each structure against the committed pseudonym
  set. With no count bound, a committed writer could pack about 28,000 history links into one
  record under the 4 MiB record ceiling of that time, and every co-reader would pay for them on
  every poll (FSM1/cipher-box#1047). The commitment's
  `entries` was the second, unbounded factor of the same product (FSM1/cipher-box#1050).
- **A permanent refusal at a size the attacker chose.** A rotation re-seals the fields that a
  revoked writer authored. The re-seal is not size-preserving: it adds an owner-write-blob, an
  ascent link and a fresh history link. A writer who inflated the child-scope index, the
  write-plane history link or a preserved map to just under the ceiling made every later owner
  rotation fail, the revoking rotation included (FSM1/cipher-box#1192, FSM1/cipher-box#1292,
  FSM1/cipher-box#1301).
- **A permanent refusal with no attacker.** History links grew by one per read rotation and were
  never pruned, so a long-lived scope root would eventually pass the ceiling and never publish
  again (FSM1/cipher-box#1047). An owner who committed 1,025 grantees minted a section the encoder
  refused, long after the signature (FSM1/cipher-box#1050).
- **Encode and decode that disagree.** A decoder that refuses a value, beside an encoder that
  emits it, lets a release build sign bytes its own decoder rejects (AGENTS.md rule 8).
- **A refusal that names nothing.** A whole-record ceiling, applied before the decoder knows any
  structure, cannot say which field broke it (FSM1/cipher-box#1475, FSM1/cipher-box#1476).
- **Two implementations that disagree at one byte.** The byte bounds do not all charge the same
  measure. A reader that honours the numbers without the measures refuses at a byte this
  implementation accepts (FSM1/cipher-box#1498).
- **Two spellings of one value.** X25519 clamps the scalar and ignores bit 255, so several byte
  strings reach one shared secret while HPKE binds the supplied bytes. A committed writer filed a
  cofactor twin of a victim's key under the victim's tag, and the owner's rotation re-minted a
  grant blob the victim could never open (FSM1/cipher-box#1142). The record value names its head
  block as a string, and the adopter recovers the trust anchor from that string, so it needs one
  canonical spelling too (FSM1/cipher-box#789).

`blueprint/core.md` carries each rule today, in the bullets that define each structure.

## Decision

**D1 — Every attacker-sized field has a frozen bound that decode and encode enforce alike.** A
field that a party other than the owner can size, and a collection that such a party can grow,
has a frozen bound. The decoder refuses a value past the bound fail-closed. The encoder refuses
the same value with the same verdict, `too-many-structures`, through a release-active check that
returns `Err` (AGENTS.md rule 8). A count bound fires before the decoder walks the collection, so
an over-declared input costs one length check. When a value breaks a count bound and a
uniqueness invariant, both sides check the count bound first and report the same verdict
(`encode_grant_section` in `crates/core/src/seal/section.rs`, `encode_write_body` in
`crates/core/src/seal/write_body.rs`). A total-size bound does not share this order (E8). The
helper is `assert_within_bound` in `crates/core/src/seal/body.rs`. The rule landed with FSM1/cipher-box#1049; this ADR records it.

**D2 — The grant section bounds its collections and refuses a repeated history link.**
`historyLinks` has a bound of 256 (`MAX_HISTORY_LINKS`) and `grantBlobs` a bound of 1024
(`MAX_GRANT_BLOBS`). Two history links may not carry equal sealed bytes
(`duplicate-history-link`): each epoch mints one link under a fresh nonce, so a repeat is an
authored anomaly. The reason is the gate's stage-3 work, which is `pseudonyms + structures`
(`blueprint/engine.md` "One section, one signer"): an unbounded collection on either side of that
sum lets one record set another reader's CPU budget. `historyLinks` is ordered oldest epoch
first. The rule landed with FSM1/cipher-box#1049; this ADR records it.

**D3 — The commitment's entries share the grant-blob bound.** The grant-set commitment refuses
more than 1024 `entries` (`MAX_GRANT_BLOBS`) at decode, at encode and at `sign_grant_set`. The two
1024 ceilings are one number: the ledger must match the committed set exactly, and a re-seal
wraps one blob per ledger row, so a larger commitment could only mint a section its own encoder
refuses. The refusal lands at the mint, where the owner can act, and not at a later publish. The
rule landed with FSM1/cipher-box#1098; this ADR records it.

**D4 — The direct-child-scope index is bounded in entries and in name length.** The index refuses
more than 1024 entries (`MAX_DIRECT_CHILD_SCOPES`), and each entry's `ipnsName` refuses past the
name codec's own ceiling (`MAX_IPNS_NAME_BYTES`), at decode and at encode. The index is
writer-authored and carries no owner signature. Unbounded, a committed writer grows it until the
head block that the revoking rotation re-seals it into no longer fits the block ceiling. The rule
landed with FSM1/cipher-box#1299; this ADR records it.

**D5 — The grant ledger's row count shares the grant-blob bound.** The write-body's `grantLedger`
refuses more than `MAX_GRANT_BLOBS` (1024) rows at decode and at encode, in the same order as its
sibling collections. The rule landed with FSM1/cipher-box#1368; this ADR records it.

**D6 — The write-plane history link is bounded at 512 bytes.** `writeHistoryLink` refuses past
512 bytes (`MAX_WRITE_HISTORY_LINK_BYTES`) at decode and at encode. A minted link is about 103
bytes. Over-length bytes make the record undecodable, so, like a duplicate ledger tag, a
committed writer can stall the scope's rotations until the owner republishes the root from a
gate-passed earlier record. A re-seal handed an over-length carried link refuses before any
seal draws a byte (`ResealError::CarriedWriteHistoryLinkTooLarge`,
`crates/engine/src/rotation/reseal.rs`). It does not drop the link: an empty link in its place
would publish, above write epoch 1, the value that the `WriteHistory::Genesis` arm refuses, and
would cut the write-plane regression chain from that epoch on. The bound is the decoder's own, so
no gate-passed record reaches this refusal, and D11 holds. The bound landed with
FSM1/cipher-box#1285, and the refusal replaced an earlier drop in FSM1/cipher-box#1748; this ADR
records both.

**D7 — The write-body has a total encoded-size bound under the block ceiling.**
`MAX_WRITE_BODY_BYTES` is the block ceiling less a frozen 64 KiB re-seal headroom, so 2,031,616
bytes. The headroom holds the seal, section and envelope framing that a re-seal wraps the body
in. The decoder refuses an over-bound body before it walks either collection. The encoder refuses
the same length with the same verdict. The measure charges `writeHistoryLink` at its 512-byte
maximum, whatever the body carries: the link is the one field a re-seal replaces, so a flat charge
makes "this body decodes" imply "this body still encodes after a cut swaps its link". A re-seal
that still cannot author its body refuses under its own name, `write-body-too-large`. The total
bound does not conflict with the strict-preserve rule of #27 D10: that rule governs the
treatment of a field (never strip, keep unknowns byte-stable), not the total size, and one size
constant that every client shares refuses the same bodies everywhere. The shape (the ceiling less
a frozen headroom, with equal verdicts on both sides) was decided on 2026-08-20 in
FSM1/cipher-box#1301, as an agent record of a decision in the owner-approved wave-13 plan.
The 64 KiB and 512-byte values are the sizing of FSM1/cipher-box#1368.

**D8 — The grant section has a total encoded-size bound, which is also a joint ceiling.**
`MAX_GRANT_SECTION_BYTES` is the block ceiling less a frozen 48 KiB envelope headroom, so
2,048,000 bytes. The per-collection bounds of D2 cap counts, not bytes: the sealed blobs are
opaque, every level carries a preserved map, and no commitment or structure signature covers
those bytes. The section rides an uncuttable carried field, so a committed writer who inflated it
once would pass the bytes to every later re-author. The bound's floor is `MAX_WRITE_BODY_BYTES`,
because the sealed write-body rides in the section. Its ceiling is the block less the framing of
the envelope. The bound is therefore also a joint ceiling: a section that carries a write-body at
its bound has about 16 KiB left, which is about 51 grant blobs or 70 history links. The codec
refuses that combination outright. The existence of the bound was decided on 2026-08-25 in
FSM1/cipher-box#1355, which made the section bound a prerequisite of the critical-bytes budget.
The 48 KiB value and the joint-ceiling clause are the sizing of FSM1/cipher-box#1454.

**D9 — The envelope refuses on raw length before the walk, and `readSealed` has its own bound.**
The envelope decoder refuses on the raw input length before it walks anything, at the block
ceiling (`seal.envelopeMaxBytes`). The input is attacker-supplied and the carried set in it is
preserved by construction, so the total is the only cap on the walk. `readSealed` has a bound of
its own, `MAX_READ_SEALED_BYTES`, the block ceiling less a frozen 32 KiB envelope headroom, so
2,064,384 bytes. It is the envelope's one attacker-sized typed field, and it is uncuttable, so its
bound lets the refusal name the field that broke. Its floor is honest use: the read-body codec
mints what a folder's child listing needs, so a bound near the framing headroom would refuse
folders the codec's own encoder produces. A maximal `readSealed` and a maximal grant section are
not jointly reachable in one block; the envelope total refuses the combination and reaches the
engine as `HeadTooLarge`, which names the bound that refused. Each bound states the bytes it
charges, and the measure is part of the frozen number:

| Bound                          | Charged measure                                                        |
| ------------------------------ | ---------------------------------------------------------------------- |
| `seal.envelopeMaxBytes`        | the whole encoded envelope, det-CBOR head included                     |
| `seal.readSealedMaxBytes`      | the byte-string payload alone, head excluded                           |
| `grant.grantSectionMaxBytes`   | the whole encoded section, which is the envelope's byte-string payload |
| `grant.writeBodyMaxBytes`      | the whole encoding, with `writeHistoryLink` charged at 512             |
| `seal.criticalCarriedMaxBytes` | the encoded cost of each entry, key and framing included               |

The rule landed with FSM1/cipher-box#1496; this ADR records it.

**D10 — The headrooms are one reservation, held by compile-time relations.** Every total bound is
the block ceiling less a frozen headroom, so each bound follows from one external value and one
choice:

| Constant                     | Value     | Headroom below the block |
| ---------------------------- | --------- | ------------------------ |
| `MAX_BLOCK_BYTES` (external) | 2,097,152 | —                        |
| `MAX_READ_SEALED_BYTES`      | 2,064,384 | 32 KiB                   |
| `MAX_GRANT_SECTION_BYTES`    | 2,048,000 | 48 KiB                   |
| `MAX_WRITE_BODY_BYTES`       | 2,031,616 | 64 KiB                   |

The chain is `MAX_WRITE_BODY_BYTES` < `MAX_GRANT_SECTION_BYTES` < `MAX_BLOCK_BYTES`. The gap
between the write-body and the section bounds, 16 KiB, is the gap between their two headrooms, so
the section framing above a carried write-body stays inside the write-body's re-seal headroom.
The critical-bytes budget (16 KiB) draws from the same band and stays under the 32 KiB, 48 KiB and
64 KiB headrooms, so a maximal critical set cannot make a maximal write-body's re-seal
unencodable. Only a relation that constrains a free choice is asserted, at compile time, so a
build that breaks the chain does not run: `MAX_GRANT_SECTION_BYTES >= MAX_WRITE_BODY_BYTES + 1024`
and `MAX_CRITICAL_CARRIED_BYTES < GRANT_SECTION_ENVELOPE_HEADROOM_BYTES`
(`crates/core/src/seal/section.rs`), and
`MAX_CRITICAL_CARRIED_BYTES < READ_SEALED_ENVELOPE_HEADROOM_BYTES`
(`crates/core/src/seal/envelope.rs`). A relation that is an
identity of a definition is not asserted. The arithmetic landed with FSM1/cipher-box#1368,
FSM1/cipher-box#1454 and FSM1/cipher-box#1496; this ADR records it.

**D11 — An attacker-influenced size never causes a permanent produce-side refusal.** A bound
refuses malformed input on the read side. On the produce side, a size that another party chose
must not stop an owner's publish for good, and most of all the rotation that revokes that party. The
produce side therefore follows four rules:

- It truncates a carried set and never refuses for it. The cut target and the refusal clause
  are ADR 0042 D1.
- It charges a field that it replaces at the field's maximum (D7), so a body at the bound still
  encodes after the swap.
- It drops an over-long or unwalkable carried read-plane history link, with every older link,
  rather than refusing it: a link past the engine's per-link retention budget (E6) and an
  unwalkable remainder (D12).
- The engine charges a head-size refusal (`HeadTooLarge`) against the op's attempt budget as a
  head-size halt, never as a permanent verdict and never as an uncharged encoder fault. A fresh
  nonce moves the sealed bytes but not their count, so the budget bounds the retries and the
  dead letter keeps the staged version (`classify_author` and the `Halt::HeadOversized` arm in
  `crates/engine/src/sync/drain.rs`).

The law landed with FSM1/cipher-box#1049 ("truncated, never refused"), and the
FSM1/cipher-box#1292 resolution of 2026-08-19 applied it to decline a permanent `HeadTooLarge`
verdict; this ADR records it. ADR 0012 D4 applies the same law to an unreachable epoch.

**D12 — A rotation keeps the newest 64 walkable history links; a sweep neither mints nor
prunes.** This replaces "pruned as the sweep converges" in #27 "Pinned structure formats". A link
minted at epoch `e` is sealed under its own epoch's structure key and carries the preceding
epoch's seed, so the chain is contiguous and walks backward one epoch per step. A rotation holds
the seed that starts that walk. It keeps the newest 64 links (`MAX_RETAINED_HISTORY_LINKS`) that
actually walk and drops the rest, oldest end first, before it re-signs, so the order is proven and
not assumed. An unwalkable remainder is truncated, never refused (D11). The retention constant
stays under the decode bound of D2 (64 ≤ 256, and at least 1, both asserted at compile time), so
the decode bound stays a malformed-input guard that an honest rotator never approaches, and the
chain is bounded by design rather than by the block ceiling. A sweep publishes at the floor epoch
without minting a link, so it cannot walk the carried chain; it appends nothing, so the set cannot
grow there, and it does not trim an oversized set either. A node that the retained window does
not reach is readable by nobody; the sweep reports it unreachable and neither sweeps nor descends
into it. The rule landed with FSM1/cipher-box#1049, after FSM1/cipher-box#1047 asked for a
retention decision; this ADR records it.

**D13 — The KAT manifest freezes each bound with its measure and an at-the-bound recipe.** The
manifest's `bounds` table carries, for each byte bound: the measure's label, the wire key the
refusal reports, and an at-the-bound artifact as a recipe (a base encoding, the top-level field to
pad, the largest pad the bound admits, the resulting length and its BLAKE3). The bound must admit
the rebuilt artifact on both the decode and the encode side, and refuse it one byte larger. The
values are frozen as manifest numbers, not as multi-megabyte reject vectors. The rule landed with
FSM1/cipher-box#1834; this ADR records it.

**D14 — The record value's content CID has one string form.** A scope's IPNS record value
`/ipfs/<head_cid>` carries the head block's binary CIDv1 in base32-lowercase multibase (`b…`).
Encode and strict decode are `crates/core` exports. Decode refuses, fail-closed, a wrong or missing
`b` prefix, a non-base32 or non-canonical body, and any bytes that are not the frozen
content-plane CIDv1 framing. The decoder re-encodes the recovered bytes and demands the input
string back, so a second spelling of one CID never survives. The adopter recovers the trust
anchor from this string before `read_block` verifies the fetched head. The rule landed with
FSM1/cipher-box#789; this ADR records it.

**D15 — An X25519 public key is adopted only as the canonical encoding of a prime-order point.**
`X25519Public::from_bytes` lifts the u-coordinate to Edwards, tests the lift for torsion, and
re-encodes it back to the input. The lift refuses the twist, the torsion test refuses the
identity, every small-order point and every cofactor twin `P + t` (`t` in `E[8]`), and the
re-encode refuses every second spelling (bit 255 set, a value at or above `p`). Every consumer
inherits the check through the one constructor. The rule landed with FSM1/cipher-box#1286; this
ADR records it.

## Trust argument

- **A record cannot set another reader's CPU budget.** Stage-3 work is `pseudonyms + structures`,
  and D2 and D3 bound both terms before the gate verifies anything.
- **No release build emits bytes its own decoder refuses.** Each bound is enforced on both sides
  with one verdict, release-active on the encode side (AGENTS.md rule 8).
- **A revoked writer cannot block the rotation that revokes them.** The write-body headroom holds
  a re-seal's additions (D7), the flat charge covers the one replaced field (D7), the carried set
  is cut rather than refused (D11), and a head-size refusal is charged and bounded, not permanent
  (D11).
- **Honest growth never meets a bound.** Retention keeps history links far under their decode bound
  (D12). Every total bound sits above the largest value the neighbouring encoder mints (D8, D9).
- **Two implementations agree at every byte.** The charged measure is part of the frozen number
  (D9), and the manifest recipe fails a reader that charges a neighbouring measure (D13).
- **A second spelling cannot pass a binding.** One canonical form for an X25519 key (D15) means
  the ECDH decision and the HPKE `kem_context` see the same key. One canonical form for the content
  CID (D14) means the trust anchor that the adopter recovers is the one the signature covers.
- **Retention loses no revocation boundary.** Revocation withholds the new seed, and no history
  link ever restores it, so a dropped link reveals nothing and a hostile rotator gains nothing it
  could not get by publishing zero links (D12).

## Alternatives rejected

**(a) A count cap on history links with no retention.** It moves the no-attacker cliff nearer,
from about 28,000 rotations to the cap. The cap and the retention window are chosen as a pair
instead (FSM1/cipher-box#1049).

**(b) A bound on each preserved map.** Each new field becomes a new lever, and the bound refuses
exactly the forward-compatible fields that #27 D10 protects. Declined in FSM1/cipher-box#1301.

**(c) An encode-only headroom check.** It leaves the rotation denial standing and only makes it
readable. Declined in FSM1/cipher-box#1301.

**(d) A permanent trust verdict for `HeadTooLarge`.** On the revoking rotation, a permanent verdict
on an attacker-influenced size is the wedge that D11 forbids, and an owner's own re-seal can push
a legitimate body over. Declined in the FSM1/cipher-box#1292 resolution.

**(e) A 256 KiB grant-section bound.** It refuses a write-body that the write-body codec mints, the
symmetry defect one layer up (FSM1/cipher-box#1356 sketch, rejected in FSM1/cipher-box#1454).

**(f) A `readSealed` bound inside the 48 KiB band.** It would prove that the maxima fit one block,
but it refuses a folder of about 300 children at a size no attacker chose
(FSM1/cipher-box#1496).

**(g) A small-order blacklist, or a mask of bit 255.** Clamping collapses every cofactor twin onto
one shared secret, so a blacklist misses the whole class; the ignored bit and the mod-`p`
wraparound both survive into `to_bytes` (FSM1/cipher-box#1142, FSM1/cipher-box#1286).

**(h) Multi-megabyte reject vectors for the byte bounds.** A vector at a 2 MiB bound is about 4 MB
of committed hex. Manifest numbers with a recipe freeze the same fact
(FSM1/cipher-box#1368, FSM1/cipher-box#1834).

## Consequences

1. **`blueprint/core.md` already carries every rule; no text change is needed for D1 to D5, D7
   to D11 and D13 to D15.** D6 and D12 each need one editorial fix (consequence 6). The "Crypto suite" section carries D15 (the X25519 bullet). "Envelope and
   structures" carries D7 to D11 in the "Carried unknown fields", "Envelope size bounds",
   "Write-body" and "Grant section" bullets, D2 and D3 in "Grant section", D4 to D6 in
   "Write-body", and D12 in "History-link retention". "IPNS records" carries D14 in the
   "Content-CID string codec" bullet. "KAT regime" carries D13 in "Every byte bound names its
   charged measure".

2. **`blueprint/engine.md` already carries the unreachable window of D12** in the "sweep" section:
   "A node the retained window no longer reaches is readable by nobody".

3. **No `CONTEXT.md` term carries a bound, and none needs to; one glossary sentence needs a
   fix.** The bounds are wire detail of `crates/core`. The "History link" term says "So a new
   grantee of a scope reads every earlier epoch (ADR 0026 D6)". Under D12 a new grantee reads
   only the epochs inside the 64-rotation window. The sentence becomes "reads every earlier epoch
   that the retained window reaches (ADR 0033 D12)". This is the same overstatement that E5
   records for ADR 0026 D6.

4. **#27 "Pinned structure formats" is amended.** "History links: per-epoch chain, pruned as the
   sweep converges" now reads as D12: a rotation prunes to the newest 64 walkable links, and a
   sweep neither mints nor prunes. #27 D10 is not amended: its "never strip" governs field
   treatment, and D7 states how a total size bound sits beside it. The cut of carried fields over
   the ceiling is outside this ADR.

5. **Citations the blueprint must gain.** `blueprint/core.md` section "Envelope and structures"
   gains the citation (ADR 0033) in the "Envelope size bounds", "Write-body", "Grant section" and
   "History-link retention" bullets; "History-link retention" cites it in place of #27.
   `blueprint/core.md` section "Crypto suite" gains the citation (ADR 0033) in the X25519 bullet.
   `blueprint/core.md` section "IPNS records" gains the citation (ADR 0033) in the "Content-CID
   string codec" bullet. `blueprint/core.md` section "KAT regime" gains the citation (ADR 0033) in
   "Every byte bound names its charged measure".

6. **Two `blueprint/core.md` sentences are wrong and get an editorial fix (E1, E2).**
   - "Write-body": "A re-seal handed an over-length link drops it rather than failing, so the
     produce side can never emit a body its own decoder refuses" becomes "A re-seal handed an
     over-length carried link refuses before any seal, because an empty link in its place would
     publish the state the genesis arm refuses; the bound is the decoder's own, so no gate-passed
     record reaches the refusal" (D6).
   - "History-link retention": "a node past it is not lost, since the sweep re-seals it forward
     from the scope's _current_ seed" becomes "a node past it is readable by nobody; the sweep
     reports it unreachable and does not re-seal it", which is the `blueprint/engine.md` "sweep"
     text (D12).

7. **No wire format, no KDF edge, no KAT vector and no op queue record changes.**

## Residuals

**E1 — The `blueprint/core.md` "Write-body" sentence on an over-length carried link is out of
date.** It says a re-seal drops the link. Since FSM1/cipher-box#1748, `reseal_scope_root`
(`crates/engine/src/rotation/reseal.rs:821`) returns `ResealError::CarriedWriteHistoryLinkTooLarge`
before any seal. The code is right: an empty link above write epoch 1 advertises a predecessor
epoch with no link, which is the value the `WriteHistory::Genesis` arm refuses, and it truncates
the write-plane regression chain. The decoder refuses such a link first, so no gate-passed record
reaches the refusal, and D11 still holds. D6 records the refusal; consequence 6 rewords the
sentence.

**E2 — The `blueprint/core.md` "History-link retention" sentence on a node past the window is
wrong.** It says: "a node past it is not lost, since the sweep re-seals it forward from the
scope's _current_ seed". A re-seal must open the node's body with the old seed, and no retained
link reaches that seed, so the sweep cannot re-seal the node. `blueprint/engine.md` "sweep" is
right: the node "is readable by nobody: it is reported unreachable and neither swept nor descended
into". The code (`seed_at_epoch` and the `MAX_RETAINED_HISTORY_LINKS` doc in
`crates/engine/src/rotation/reseal.rs`) and ADR 0021 agree with `engine.md`. D12 records the
`engine.md` text; consequence 6 fixes the `core.md` sentence.

**E3 — The bounds narrow the head-size lever; they do not close it.** The headrooms reserve
nothing for the grant section's own contents, and the per-field maxima are not jointly reachable
in one block. A committed writer can still fill a scope root to the envelope total, and an
ordinary write at that root then dead-letters as `HeadTooLarge`. A rotation builds a fresh
grant section, which clears bloat in the section's own framing. The whole-record ceiling stays
the engine's backstop.

**E4 — An over-bound value makes the record undecodable, which a committed writer can use.** A
committed writer can publish an over-bound write-body field, or a duplicate ledger tag, and stall
the scope's rotations until the owner republishes the root from a gate-passed earlier record
(D6). The bound turns a permanent wedge into a recoverable stall; it does not remove the stall.

**E5 — The retention window limits the backward walk.** A node that lags more than 64 rotations
is unreachable for every reader, and ADR 0021 reports it as `ContentUnavailable`. ADR 0026 D6
says the links walk "back to every earlier epoch"; under D12 that is every epoch inside the
window.

**E6 — The engine has a per-link retention budget that the blueprint does not state.**
`MAX_RETAINED_HISTORY_LINK_BYTES` (256 bytes, `crates/engine/src/content/limits.rs`) drops a
carried read-plane history link past 256 bytes, with every older link, when a re-seal keeps it.
It landed with FSM1/cipher-box#1594. D11 cites it as the drop of an over-long carried link, but
no blueprint sentence states it.

**E7 — A committed write grantee can make every reader of a file panic.**
`encode_content_cid_str` (`crates/core/src/content/cid.rs`) guards the framing with a
release-active `assert!`, not an `Err` (AGENTS.md rule 8). The input can come from a peer.
`Version::from_value` (`crates/core/src/seal/body.rs:212`) accepts any `contentCid` bytes, and the
file read path passes the adopted head version to `open_content_root`
(`crates/engine/src/content/mod.rs:220`), which encodes the CID with no wellformedness check. A
committed write grantee can therefore publish a file version with a malformed `contentCid`, and
every reader who opens that file panics. The rotation path checks first; the read path does not.
D14 holds for the string on the wire, but its encoder is reachable with bytes that D14's framing
refuses. The defect is FSM1/cipher-box#2008.

**E8 — Encode and decode can report different verdicts for a value that breaks a total-size bound
and another invariant.** This applies to all three total bounds: the envelope, the grant section
and the write-body. The decoder checks the total first; the encoder needs the assembled value and
checks the total last. A value that is over the total and also malformed in another way reports
the other defect from the encode side (FSM1/cipher-box#1496; the comment in
`encode_grant_section`, `crates/core/src/seal/section.rs`).

**E9 — A code comment on the retention budget has been false since FSM1/cipher-box#1748.** The
doc comment on `MAX_RETAINED_HISTORY_LINK_BYTES` (`crates/engine/src/content/limits.rs:59-61`)
says "An over-long link is dropped rather than refused, exactly as an over-long write history link
already is". Since FSM1/cipher-box#1748 an over-long write history link is refused (D6, E1). The
comparison must go.

**E10 — Most values are sizing, not decisions.** Only the shapes of D7 and D8 have an owner
decision. The values 256, 1024, 512, 64, 64 KiB, 48 KiB and 32 KiB are the sizing of the
implementing PRs, each argued in its PR body.

## Gate

The `crates/core` tests run in the Rust area's workspace tests; `crates/core/tests/kat_manifest.rs`
runs in `Core KATs (native + WASM)`; the engine tests run in the workspace tests.

- **D1** — each bound below; `assert_within_bound` is the one helper.
- **D2** — `history_links_past_the_bound_reject_at_decode_and_encode`,
  `grant_blobs_past_the_bound_reject_at_decode_and_encode`,
  `duplicate_history_link_rejects_at_decode_and_encode` and
  `distinct_history_links_at_the_bound_round_trip` (`crates/core/src/seal/section.rs`); KAT
  reject vectors `history-links-past-the-bound` and `duplicate-history-link`.
- **D3** — `entries_past_the_bound_reject_at_decode_encode_and_sign` and
  `distinct_entries_at_the_bound_round_trip` (`crates/core/src/seal/grant.rs`); KAT reject vector
  `entries-past-the-bound`.
- **D4** — `a_child_scope_index_past_its_entry_bound_is_refused_by_both_sides` and
  `a_child_scope_ipns_name_past_its_byte_bound_is_refused_by_both_sides`
  (`crates/core/src/seal/write_body.rs`); KAT reject vectors `child-scope-index-over-bound` and
  `child-scope-ipns-name-over-bound`.
- **D5** — `a_grant_ledger_past_its_entry_bound_is_refused_by_both_sides`
  (`crates/core/src/seal/write_body.rs`); KAT reject vector `grant-ledger-over-bound`.
- **D6** — `a_write_history_link_past_its_byte_bound_is_refused_by_both_sides`
  (`crates/core/src/seal/write_body.rs`), `a_minted_owner_history_link_fits_the_write_bodys_byte_bound`
  (`crates/core/src/seal/grant.rs`); KAT reject vector `write-history-link-over-bound`;
  `a_carried_write_history_link_past_the_codec_bound_is_refused_before_any_seal`
  (`crates/engine/src/rotation/reseal/tests.rs`) proves the re-seal refusal.
- **D7** — `a_write_body_past_its_total_size_bound_is_refused_by_both_sides` and
  `a_body_at_the_bound_still_encodes_after_a_cut_swaps_its_history_link`
  (`crates/core/src/seal/write_body.rs`), `an_over_bound_write_body_is_named_apart_from_every_other_encode_fault`
  (`crates/engine/src/rotation/reseal/tests.rs`), `the_write_body_size_bound_is_frozen_in_the_manifest`
  (`crates/core/tests/kat_manifest.rs`).
- **D8** — `a_section_past_the_byte_bound_is_refused_symmetrically`,
  `a_maximal_write_body_still_frames_inside_the_section_bound` and
  `a_maximal_write_body_and_a_full_history_window_are_not_jointly_reachable`
  (`crates/core/src/seal/section.rs`), `the_grant_section_size_bound_is_frozen_in_the_manifest`
  (`crates/core/tests/kat_manifest.rs`).
- **D9** — `an_envelope_past_the_block_ceiling_is_refused_symmetrically`,
  `a_read_sealed_past_its_bound_is_refused_symmetrically`,
  `each_envelope_bound_admits_exactly_its_last_byte` and
  `a_refusal_that_is_not_a_size_bound_is_not_charged_as_one` (`crates/core/src/seal/envelope.rs`),
  `the_envelope_size_bounds_are_frozen_in_the_manifest` (`crates/core/tests/kat_manifest.rs`).
- **D10** — the compile-time assertions in `crates/core/src/seal/section.rs`,
  `crates/core/src/seal/envelope.rs` and `crates/engine/src/rotation/reseal.rs`; a build that
  breaks one does not compile.
- **D11** — `a_carried_set_past_the_block_ceiling_is_still_cut_rather_than_refused` and
  `a_limit_above_the_block_ceiling_still_cuts_rather_than_refusing`
  (`crates/core/src/seal/envelope.rs`), `a_chain_that_does_not_walk_is_truncated_never_refused`
  and `a_carried_history_link_past_the_retained_bound_is_dropped_with_everything_older`
  (`crates/engine/src/rotation/reseal/tests.rs`),
  `an_authored_head_over_the_block_ceiling_dead_letters_with_its_version_intact`
  (`crates/engine/tests/write_plane.rs`).
- **D12** — `retention_keeps_the_newest_window_and_drops_the_oldest`,
  `a_chain_that_does_not_walk_is_truncated_never_refused`,
  `sweep_seed_source_mints_no_new_history_link`, `a_sweep_carries_its_chain_through_unpruned` and
  `an_epoch_older_than_the_retained_window_is_unreachable`
  (`crates/engine/src/rotation/reseal/tests.rs`).
- **D13** — `the_charged_measure_of_every_byte_bound_is_frozen_in_the_manifest`
  (`crates/core/tests/kat_manifest.rs`).
- **D14** — `content_cid_str_round_trips_and_is_lowercase_b_prefixed`,
  `decode_rejects_foreign_and_non_canonical_strings` and
  `decode_rejects_wrong_framing_even_when_base32_canonical` (`crates/core/src/content/cid.rs`),
  `content_cid_str_accept_vectors_round_trip` and `content_cid_str_reject_vectors_fail_closed`
  (`crates/core/tests/kat_manifest.rs`).
- **D15** — `cofactor_twins_are_rejected_yet_share_the_shared_secret`,
  `no_second_encoding_of_an_accepted_key_is_ever_accepted`,
  `a_mod_p_wraparound_encoding_is_rejected` and `every_derived_public_key_survives_its_own_decoder`
  (`crates/core/src/suite/x25519.rs`); KAT reject vectors `non-prime-order-enc`,
  `non-canonical-enc`, `enc-subkey-non-prime-order` and `enc-subkey-non-canonical`.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
