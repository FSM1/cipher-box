# ADR 0033 — Every attacker-sized field has one canonical form and a symmetric fail-closed bound

- **Status:** Accepted on 2026-09-26 — retroactive; the rule shipped in FSM1/cipher-box#789,
  FSM1/cipher-box#1049, FSM1/cipher-box#1098, FSM1/cipher-box#1285, FSM1/cipher-box#1286,
  FSM1/cipher-box#1299, FSM1/cipher-box#1368, FSM1/cipher-box#1454, FSM1/cipher-box#1496,
  FSM1/cipher-box#1748 and FSM1/cipher-box#1834, and the blueprint carries it; the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows; trimmed on 2026-09-26 to the items that pass
  the three ADR hurdles — the removed items live in the blueprint
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

A committed write grantee authors the write-body with no owner signature, and every structure
carries opaque blobs and a preserved `unknown` map. So a party other than the owner sizes these
fields, up to the 2 MiB block ceiling. A rotation re-seals what a revoked writer authored and adds
bytes, so an inflated field made every later owner rotation fail. History links were never
pruned, so a scope root would pass the ceiling with no attacker. Two implementations that charge
different measures disagree at one byte.

## Decision

**D6 — The write-plane history link is bounded at 512 bytes.** `writeHistoryLink` refuses past
512 bytes at decode and at encode. A re-seal handed an over-length carried link refuses before
any seal (`ResealError::CarriedWriteHistoryLinkTooLarge`), and does not drop it. An empty link
would publish, above write epoch 1, the value that the `WriteHistory::Genesis` arm refuses, and
would cut the write-plane regression chain. The bound is the decoder's own, so no gate-passed
record reaches this refusal, and D11 holds (FSM1/cipher-box#1285, FSM1/cipher-box#1748).

**D7 — The write-body has a total encoded-size bound under the block ceiling.**
`MAX_WRITE_BODY_BYTES` is the block ceiling less a frozen 64 KiB re-seal headroom, with equal
verdicts on both sides. The measure charges `writeHistoryLink` at its 512-byte maximum, because
it is the one field a re-seal replaces: "this body decodes" then implies "this body still encodes
after a cut swaps its link". #27 D10 governs the treatment of a field, not the total size. The
shape was decided on 2026-08-20 in FSM1/cipher-box#1301, in the owner-approved wave-13 plan.

**D8 — The grant section has a total encoded-size bound, which is also a joint ceiling.**
`MAX_GRANT_SECTION_BYTES` is the block ceiling less a frozen 48 KiB envelope headroom. Count
bounds do not cap the opaque blobs or the preserved maps, and the section rides an uncuttable
carried field. The floor is `MAX_WRITE_BODY_BYTES`, because the sealed write-body rides in the
section, so a section with a maximal write-body has about 16 KiB left. The existence of the
bound was decided on 2026-08-25 in FSM1/cipher-box#1355.

**D9 — The envelope refuses on raw length before the walk, and `readSealed` has its own bound.**
The envelope decoder refuses at the block ceiling before it walks anything. `readSealed` has a
bound 32 KiB below the block, so the refusal names the field that broke, and its floor is a
folder's honest child listing. The measure that each bound charges is part of the frozen number
(FSM1/cipher-box#1496).

**D10 — The headrooms are one reservation, held by compile-time relations.** Every total bound
is the block ceiling less a frozen headroom: 32 KiB for `readSealed`, 48 KiB for the grant
section, 64 KiB for the write-body. The 16 KiB critical-bytes budget stays under every headroom,
so a maximal critical set cannot make a maximal write-body's re-seal unencodable. A relation that
constrains a free choice is asserted at compile time, so a build that breaks the chain fails.

**D11 — An attacker-influenced size never causes a permanent produce-side refusal.** A bound
refuses malformed input on the read side. On the produce side, a size that another party chose
must not stop an owner's publish for good, and most of all the rotation that revokes that party:

- It truncates a carried set and never refuses for it (ADR 0042 D1).
- It charges a field that it replaces at the field's maximum (D7).
- It drops an over-long or unwalkable carried read-plane history link, with every older link.
- The engine charges `HeadTooLarge` against the op's attempt budget, never as a permanent verdict.

The law landed with FSM1/cipher-box#1049 and FSM1/cipher-box#1292; ADR 0012 D4 applies it too.

**D12 — A rotation keeps the newest 64 walkable history links; a sweep neither mints nor
prunes.** This replaces "pruned as the sweep converges" in #27 "Pinned structure formats". A
rotation keeps the newest 64 links that actually walk and drops the rest before it re-signs, so
the order is proven, not assumed. Retention stays under the `historyLinks` decode bound, so that
bound stays a malformed-input guard. A sweep mints no link, so it cannot walk the chain: it
appends nothing and trims nothing. A node past the window is readable by nobody.

Items D1, D3, D4 and D5 moved to `blueprint/core.md` "Envelope and structures" on 2026-09-26.
D2 moved to `blueprint/core.md` "Grant section"; amended by ADR 0052 D5 on 2026-09-26: the bound's reason is stated there.
Items D13, D14 and D15 moved to `blueprint/core.md` "KAT regime", "IPNS records" and "Crypto suite" on 2026-09-26.

## Alternatives rejected

**(a) A count cap on history links with no retention.** It moves the no-attacker cliff to the cap.

**(b) A bound on each preserved map.** It refuses the fields that #27 D10 protects (D7).

**(c) An encode-only headroom check.** It leaves the rotation denial standing (D7).

**(d) A permanent trust verdict for `HeadTooLarge`.** It is the wedge that D11 forbids.

**(e) A 256 KiB grant-section bound.** It refuses a write-body that its own codec mints (D8).

**(f) A `readSealed` bound inside the 48 KiB band.** It refuses a folder of about 300 children.

## Trust argument

- **D6, D7, D10, D11:** a revoked writer cannot block the rotation that revokes them.
- **D8, D9, D12:** honest growth never meets a bound, and two implementations agree at every byte.

## Consequences

- `blueprint/core.md` carries every kept and moved item and cites this ADR.
- `blueprint/engine.md` "sweep" carries the unreachable window of D12.
- `CONTEXT.md` "History link" limits a new grantee to the retained window (D12).
- #27 "Pinned structure formats" is amended by D12; #27 D10 is not amended (D7).

## Residuals

**E3 — The bounds narrow the head-size lever; they do not close it.** A committed writer can
still fill a scope root to the envelope total, and a write at that root dead-letters as
`HeadTooLarge`.

**E4 — An over-bound value makes the record undecodable.** A committed writer can stall the
scope's rotations until the owner republishes the root from a gate-passed earlier record (D6).

**E8 — Encode and decode can report different verdicts at a total-size bound.** The decoder
checks the total first, and the encoder checks it last, so a value that also breaks another
invariant reports that defect from the encode side.

## Gate

The Rust area's workspace tests and `Core KATs (native + WASM)` block the merge.
