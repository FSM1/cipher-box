# ADR 0031 — The bin index seals symmetrically under a login-secret key and exists from genesis

- **Status:** Accepted on 2026-09-26 — retroactive; the rule shipped in FSM1/cipher-box#1560,
  FSM1/cipher-box#1582, FSM1/cipher-box#1658 and FSM1/cipher-box#1742, and the blueprint
  carries it; the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-26
- **Relates to:**
  [ADR 0010](./0010-recycle-bin-is-an-owner-sealed-index.md)
  item 1 (the seal shape of the bin index) and item 3 (the source of the bin-held key), which
  this ADR amends,
  [ADR 0007](./0007-derived-idempotent-first-run-mint.md)
  (the derived first-run terms, which this ADR extends to the bin index genesis publish),
  [ADR 0030](./0030-a-record-the-owner-alone-authors-and-that-seals-hpke-to-the-owner-seals-in-auth-mode.md)
  D1 (every other owner-only structure seals in HPKE auth mode to the owner itself, and the bin
  index is the one exception, which this ADR decides),
  [ADR 0006](./0006-owner-local-sealed-store.md)
  (the HPKE-to-self shape that ADR 0010 item 1 named),
  [ADR 0013](./0013-a-lapsed-bin-index-record-is-rewritten-not-refused.md)
  (the lapsed bin index record),
  [ADR 0012](./0012-the-drain-carries-the-write-wave-forward.md)
  D6 (a strict-FIFO stall with no dead letter is a liveness defect),
  [#33](https://github.com/FSM1/cipher-box-next/issues/33) D4 and D7 (a trust violation is not
  staleness; an adoption-gate failure fails closed),
  [#39](https://github.com/FSM1/cipher-box-next/issues/39) D8 (the frozen KDF edge catalog),
  [#27](https://github.com/FSM1/cipher-box-next/issues/27) D3 (XChaCha20-Poly1305 with 24-byte
  random-safe nonces; it states no rule on how a caller draws a nonce), the `blueprint/core.md`
  sections "Bin index", "KDF edge catalog" and "Structure-tag registry", the
  `blueprint/engine.md` sections "Bin index record" and "Vault settings load", and the
  `CONTEXT.md` terms "Bin index", "Bin rung", "Bin entry" and "Bin-held key"
- **Implemented by:** FSM1/cipher-box#1560 (the three bin edges, the grammar, the seal and the
  padding), FSM1/cipher-box#1582 (the publish and the load, the nonce draw, the rewrite guard
  and the verdict split), FSM1/cipher-box#1658 (the genesis publish and the accepted
  disclosures) and FSM1/cipher-box#1742 (`StrandedMint`). The padding decision is recorded on
  FSM1/cipher-box#1561, and the stranded-mint question on FSM1/cipher-box#1675.

## Context

ADR 0010 decided that the recycle bin is one owner-sealed, vault-level index, published and
CAS-guarded like the vault settings record. It left the bytes open. Item 1 said only that the
bin "takes the sealed-store shape of ADR 0006", which is HPKE-to-self. Item 3 said that a soft
delete from a shared scope re-keys the doomed subtree under "a fresh key held only in the bin
index". Nothing said when the record first exists, what its length discloses, or what a load
may build a rewrite on. The slices that built the bin under FSM1/cipher-box#1399, and
FSM1/cipher-box#1675 after them, found six problems.

**The seal shape.** The bin index has one reader, the owner, for ever. It also has one author:
a grantee's delete reaches the bin only through owner capture (ADR 0010 item 5), so no other
party seals to this record. HPKE-to-self exists for a structure that a public half must
address. On an owner-only record it adds a KEM output to every publish and needs auth mode to
refuse a base-mode forgery by a party that knows the public half. A key that only the login
secret derives already proves the author.

**The key source.** The drain writes the bin entry ahead of the re-key, and the queued op
drives any retry. A retry must reach the same key as the first attempt, or it re-keys the
subtree under a key that the standing entry does not name (`record_bin_entry` in
`crates/engine/src/sync/drain.rs`). A key drawn from entropy must therefore be stored before
its first use and survive a crash. A key derived from values the entry already carries needs no
such store.

**The length.** The record is published, so the server sees the length of its ciphertext.
FSM1/cipher-box#1561 measured it: an empty index sealed to 60 bytes, a two-entry index to 400
bytes, and one entry cost about 170 bytes. An unpadded record therefore disclosed the
soft-delete count to within one entry. That is a deletion-activity count, not a size.

**The first appearance.** Before FSM1/cipher-box#1658, the record first appeared at the first
soft delete. The register-first step then told the API that this account had binned something,
and when.

**The whole rewrite.** A publish carries the entries the caller supplies and nothing else. A
rewrite built on a copy behind another device's publish drops that device's entries. That was
the named data-loss bug of v1, and the CAS guard alone does not close it: the bytes of the
losing writer are well-formed and win the next round.

**The stranded mint.** `publish_bin_index` raises the durable mint counter before it seals.
FSM1/cipher-box#1675 found that a publish that failed behind that mint left the counter as the
only durable mark on the device. The load read the mark as a withheld record and refused the
rewrite. The queue head then took a hold whose only exit was the record resolving, and a
single-device account had no device left to publish it. That account could never soft-delete
again, and nothing told the member why.

The rules below are what the four PRs landed. `blueprint/core.md` "Bin index" and "KDF edge
catalog" and `blueprint/engine.md` "Bin index record" carry them today.

## Decision

**D1 — The bin index seals symmetrically under a login-secret key.** The record is published
at the name that the `bin-index-ipns-keypair` edge derives from the login secret, and its body
is sealed with XChaCha20-Poly1305 under the key that the `bin-index-seal-key` edge derives
from the login secret. The reason is specific to this record. Possession of a key that only the
login secret derives is already the author proof, and no public half addresses the record: no
party other than the owner seals to it, because a grantee's delete reaches the bin only through
owner capture (ADR 0010 item 5). The bin index is therefore the one owner-only structure that
seals symmetrically; every other owner-only structure seals in HPKE auth mode to the owner
itself (ADR 0030 D1). The clear header is two keys, `v` and `sealed`, frozen across
format versions. The AAD is `[cipherbox/v2/aad, v, 0x0f]`, so a rewrite of the clear version
fails the tag, and tag `bin-index` (`0x0f`) separates this structure from every other. No grant
carries either edge, so no grantee of any scope reads the owner's bin. The rule landed with
FSM1/cipher-box#1560; this ADR records it.

**D2 — The seal key never rotates.** `bin-index-seal-key` takes no epoch input and no
per-record input. One key seals every publish of the bin index that the account ever makes, on
every device. Two devices publish the record under one CAS guard (ADR 0010 item 1), so a
counter nonce, or a nonce derived from the body revision or the IPNS sequence, is unique on one
device and collides across two; each seal therefore draws its 24-byte nonce from the injected
entropy seam. The rule landed with FSM1/cipher-box#1560 and FSM1/cipher-box#1582; this ADR
records it.

**D3 — A seam that cannot supply a nonce fails the publish closed.** When the entropy seam
reports a failure, the publish returns an error and no byte reaches an endpoint. The engine
never falls back to another nonce source. The rule landed with FSM1/cipher-box#1582; this ADR
records it.

**D4 — The bin-held key derives from the login secret, the node id and `deletedAt`.** The
`bin-held-key` edge is `keyed_hash(derive_key(ctx, loginSecret), nodeId[16] || deletedAt[8
BE])`. The session holds the account half, `bin_held_root`, in place of the login secret, and
that half never enters a bin entry, an export or a log. The key is scope-seed shaped: every
node of the doomed subtree keys at `readKey(nodeSeed(held, nodeId))`, so one key opens the
whole subtree. No scope seed of any epoch is an input, so no grantee can reach the key. The
`deletedAt` input makes the key per delete: a node that is binned, restored and binned again
re-keys under fresh bytes, and a disclosed held key opens one bin generation. The bin entry
also carries the key as `heldKey`. The rule landed with FSM1/cipher-box#1560; this ADR records
it.

**D5 — The body pads to a fixed bin rung, and each rung has a cap.** The body is `{entries[],
pad, revision}`. Before the seal it pads to one of six bin rungs: 4 KiB, 16 KiB, 64 KiB,
256 KiB, 1 MiB, and the block ceiling less the seal (2096128 bytes). A rung admits a body only
up to its cap, which sits below the rung by the largest distance the pad cannot span, so the
rung that a body takes rises monotonically with the body and never jumps at a gap in the CBOR
byte-string head. A body that no rung takes is refused, never published unpadded. The choice to
pad to fixed rungs was decided on 2026-08-31 in FSM1/cipher-box#1561; the rung sizes and the
caps are the sizing that FSM1/cipher-box#1560 landed, and this ADR records them.

**D6 — The pad is zero, the padded form is canonical, and a rung change bumps the version.**
Every pad byte is zero. A plaintext whose length is off every rung, and a pad byte that is not
zero, are both `non-canonical-padding`, a trust violation, on encode and on decode. `pad` is
schema, not payload: a decode drops it, and a rewrite pads again to the rung its own body
needs. The decoder tests rung membership, not minimality, so an over-padded body opens. The
ladder belongs to the record version: a reader refuses an off-rung length as a trust violation,
not as an unsupported version, so any change to the rungs is a `BIN_INDEX_V` bump. The rule
landed with FSM1/cipher-box#1560; this ADR records it.

**D7 — The record exists from vault genesis.** The client publishes an empty bin index at vault
genesis, whatever the retention setting, because the existence of the record would otherwise
say that the bin is non-empty, and the register-first step would time the first soft delete.
An empty index is the last step of the degradation ladder, not an error: a vault that never
soft-deleted anything loads an empty index. The genesis publish runs on the derived first-run
terms of ADR 0007. The name comes from the login secret alone. Only a load that finds neither
a record nor any durable mark on the device publishes the empty index, and a device that holds a
mark decides from its own store and sends no network request. The engine attempts the publish
at every session start with a configured API, so a genesis attempt that did not land is not the
account's only one: a device that holds no mark publishes the record at its next start. A device
whose own attempt minted a revision holds a mark and does not try again (E4). A repeated first
run leaves the standing record alone. The first soft delete then
revises the genesis record and does not mint one. The rule landed with FSM1/cipher-box#1560 and
FSM1/cipher-box#1658; this ADR records it.

**D8 — The index is rewritten whole, so only an established index feeds a rewrite.** Two load
outcomes establish the index: a resolved record, and the unproven-first-run outcome, where no
endpoint served a record and the device holds no durable mark. Every other outcome — stale,
suppressed, timed out, rolled back, unreadable, stranded — refuses the rewrite. The caller
tries again on a later tick, except where D9 charges the attempt or D10 dead-letters the op.
ADR 0010 item 1 gave the CAS guard; the refusal of a degraded load
landed with FSM1/cipher-box#1582, and this ADR records it.

**D9 — A gate refusal is a trust verdict, reported apart from staleness, and never takes the
availability retry.** Three load outcomes refuse bytes that the plane actually served: a
replayed sequence, a same-sequence fork below the adopted revision, and a body that does not
open under the key only this account holds, or that does not decode. The load names each one
apart from an absent or a slow record. A lapsed record is not a verdict here: ADR 0013 makes it
establish the index. A caller that retries on availability does not
retry on a verdict: the drain charges a verdict against the attempt budget of the op and holds
the op uncharged only for availability. The separation of trust from staleness is #33 D4 and
D7; the rule that a verdict takes no availability retry landed with FSM1/cipher-box#1582, and
this ADR records it.

**D10 — A mint counter with no adoption mark is its own verdict, `StrandedMint`.** When no
endpoint serves a record, the load reads the durable marks of the device. Either adoption mark
— the per-name sequence floor or the adopted body revision — proves a record this device took,
so the absent record is `Suppressed`. The mint counter alone proves only an attempt this device
made, or a publish that confirmed and then lost its floor write. The load reports that state as
`StrandedMint` and refuses the rewrite, because of the second case. The queue op that meets it
dead-letters under `BinIndexStrandedMint`, so the member reads the state and may hard-delete
instead. The state is local to the device: another device of the account holds no mark, so it
publishes the record and clears the state. The verdict is stated once in
`crates/engine/src/record_plane.rs` (`unresolved_reason`), and the vault settings load reads the
same verdict. The rule landed with FSM1/cipher-box#1742; this ADR records it.

**D11 — Three disclosures stay open, and v2.0.0 accepts them.** The bin rungs coarsen the entry
count to one of six bands; they do not hide it. The published block length names the band and
every crossing between bands. The IPNS sequence is signed cleartext and monotone, so one
resolve gives a lower bound on the lifetime count of bin publishes. Nothing hides when a
revision lands: the first bump off the genesis record times the first soft delete, and a bin
publish coincides with the republishes of the re-key, which name the exact records the delete
binned. A decoy publish cadence would close the timing channel, and D2 is what makes a decoy
work, because a fresh nonce makes a no-op republish byte-indistinguishable from a real edit.
v2.0.0 schedules no decoy publish. The rule landed with FSM1/cipher-box#1658; this ADR records
it.

## Trust argument

- **Only the login secret opens or authors the bin.** The name, the seal key and the held-key
  root derive from the login secret alone (D1, D4). No grant carries them, and no scope seed of
  any epoch is an input. A body that opens under the seal key was sealed by a holder of the
  login secret, which is the owner.
- **A soft delete cuts access that key regression cannot restore.** The held key sits outside
  every scope's derivation (D4). A grantee who holds every epoch seed of the source scope
  still derives nothing that opens a re-keyed node.
- **A disclosed held key opens one generation of one subtree.** `deletedAt` is an input (D4),
  so a later binning of the same node uses different bytes.
- **Two devices never reuse a nonce under the fixed key.** Each seal draws 192 random bits of
  nonce (D2). No per-device state feeds the nonce, so two devices that publish the same body at
  the same revision still seal under different nonces. A reused nonce would disclose every
  `heldKey` in both bodies; the zero pad makes a reuse worse, because a colliding pair then
  yields raw keystream.
- **No publish goes out on a failed draw.** D3 refuses the publish, so a missing nonce never
  becomes a zero or a repeated nonce.
- **The length discloses a band, not a count.** D5 and D6 make the ciphertext length a
  function of the rung alone. The caps keep a write grantee, who chooses the file names that
  become `originName`, from steering a body one byte across a gap to a byte-exact length.
- **The padded form cannot carry key bytes out.** A pad byte that is not zero is refused on both
  paths (D6), so an unwiped buffer cannot carry `heldKey` bytes into a published record.
- **The existence of the record says nothing.** D7 publishes the record for every vault at
  genesis, and the empty index pads to the first rung like every small bin.
- **A stale or hostile copy never overwrites the index.** D8 admits only a resolved record or a
  device with no mark at all. A replay, a fork or a withheld record refuses the rewrite, so a
  party who controls the record plane cannot make a device drop another device's entries.
- **A verdict is never retried as availability.** D9 charges it and the op dead-letters on the
  budget. A hostile plane cannot keep the head of the queue waiting by serving refused bytes.
- **A stranded device refuses and tells the member.** D10 keeps the refusal, because the mint
  mark can hide a landed publish, and gives the queue head an exit that no other device is
  needed to reach.

## Alternatives rejected

**(a) Seal HPKE-to-self, the shape ADR 0010 item 1 named.** It adds a KEM output to every
publish, and it needs auth mode to refuse a base-mode forgery, to prove what possession of a
login-secret key already proves. No party other than the owner seals to this record, so no
public half has to address it.

**(b) A counter nonce, or a nonce derived from the revision or the sequence.** Each is unique on
one device and collides across two devices that publish under the same key (D2).

**(c) A held key drawn from entropy, as ADR 0010 item 3 read.** The key would have to be stored
durably before the re-key uses it, and a crash between the draw and the store would leave nodes
sealed under a key that nothing holds. The derived key re-derives from the `nodeId` and
`deletedAt` that the entry and the purge journal already carry.

**(d) Accept the length leak.** FSM1/cipher-box#1561 offered it with a written rationale. The
owner chose to pad on 2026-08-31.

**(e) Pad to the next multiple of 4 KiB.** FSM1/cipher-box#1561 gave this as its example. A
linear bucket discloses the entry count to within about two dozen entries at every size. The
4x ladder keeps the disclosure logarithmic in the entry count.

**(f) Rungs without caps.** A body that grows one byte across a gap in the CBOR head climbs a
whole rung. That 4x jump names the body size to the byte, and a write grantee can steer it.

**(g) Publish the record at the first soft delete.** This was the behaviour before
FSM1/cipher-box#1658. The register-first step then discloses that the account binned something,
and when.

**(h) Rewrite over the last-known-good copy when the record does not resolve.** This is the v1
data-loss bug. The CAS guard does not stop it, because the stale bytes are well-formed.

**(i) Read a mint mark with no record as a first run.** FSM1/cipher-box#1675 listed it. It lets
a device publish an empty index while another device's record may exist and be withheld. The
index is rewritten whole, so that publish drops every entry, and an entry's `ipnsName` is the
only route to a record that no folder names.

**(j) Keep the stranded state as an unbounded hold.** The hold's only exit is the record
resolving, and a single-device account has no device to publish it. ADR 0012 D6 names such a
stall a liveness defect.

**(k) Schedule a decoy publish in v2.0.0.** It closes the timing channel of D11, but it is
engine work with its own cost on every vault. v2.0.0 accepts the disclosure instead (D11).

## Consequences

1. **`blueprint/core.md` already carries D1, D2, D4, D5, D6 and the existence half of D7.** The
   "Bin index" section states the symmetric seal, the clear header and the
   AAD, the rungs and the caps, the zero pad, the version bump, the nonce rule and the genesis
   publish. The "KDF edge catalog" section lists the three bin edges and states that they are
   the owner's alone, that `bin-held-key` binds `deletedAt`, and that `bin-index-seal-key` never
   rotates. The "Structure-tag registry" section lists `bin-index` (`0x0f`). No text change is
   needed for these rules; consequence 7 changes one sentence of the section.

2. **`blueprint/engine.md` already carries D2, D3, D7, D8, D9, D10 and D11.** The "Bin index
   record" section states each of them as a bullet. No text change is needed.

3. **`CONTEXT.md` already carries D1, D4 and D5.** The "Bin index" entry names the symmetric
   seal under `bin-index-seal-key`. The "Bin rung" entry defines the rung and the cap. The
   "Bin-held key" entry names the `bin-held-key` edge. No text change is needed.

4. **ADR 0010 item 1 now reads:** the bin is one owner-sealed, vault-level index, sealed
   symmetrically under `bin-index-seal-key` (D1), and published and CAS-guarded like the vault
   settings record, so that two devices cannot lose each other's writes. The phrase "the
   sealed-store shape of ADR 0006" no longer applies.

5. **ADR 0010 item 3 now reads, for its key only:** the soft delete re-keys the subtree under
   the key that the `bin-held-key` edge derives from the login secret, the node id and
   `deletedAt` (D4), and the bin entry carries that key. The phrase "a fresh key held only in the
   bin index" no longer applies. Which deletes re-key, and the key that a restore uses (ADR 0010
   item 4), are not in this ADR; a separate ADR on the soft-delete and restore flow amends them.

6. **ADR 0007 now covers a third genesis record.** Its derived-idempotent first-run terms apply
   to the bin index genesis publish as D7 states. The genesis publish is not part of the mint's
   success condition: the mint completes on its re-openable re-point as ADR 0007 D2 says, and
   the bin index publish follows it. A later session start tries the publish again only on a
   device that holds no mark (D7, E4). Two concurrent first runs publish two different empty
   records at sequence 1, because D2 gives each seal a fresh nonce; ADR 0007 consequence 6
   already covers this case, because the two records decode to the same empty index.

7. **`blueprint/core.md` section "Bin index" changes when this ADR is accepted.** The sentence
   "That follows the rule the record family runs on: a structure whose readership is exactly
   one, forever, seals symmetrically under its own login-secret edge, because possession of the
   key is already the author proof; a structure a public half must address seals HPKE-to-self."
   states a general law that the corpus does not follow: the `settings-record`, the
   `content-key` blob and the `owner-local` structure are owner-only too, and they seal in HPKE
   auth mode (ADR 0030 D1). It is reworded to the narrow rule of D1: "It is the one owner-only
   structure that seals symmetrically: a key that only the login secret derives already proves
   the author, and no public half addresses this record (ADR 0031); every other owner-only
   structure seals in HPKE auth mode to the owner itself (ADR 0030)." The owner accepts this
   rewording by accepting this ADR.

8. **`blueprint/core.md` section "Bin index" gains the citation (ADR 0031)** at the paragraph
   "The body pads to a fixed rung before the seal".

9. **`blueprint/core.md` section "KDF edge catalog" gains the citation (ADR 0031)** at the
   paragraph "The three bin edges are the owner's alone".

10. **`blueprint/engine.md` section "Bin index record" gains the citation (ADR 0031)** in its
    opening paragraph.

11. **D9 is stated here in full, and the separate ADR on the soft-delete and restore flow cites
    it.** That ADR records the rule "the queue head never waits on the bin plane in silence",
    and it cites ADR 0031 D9 for the split between a charged verdict and an uncharged hold
    rather than stating the split again.

12. **No wire format, no KDF edge and no KAT vector changes.**

## Residuals

**E1 — The login secret opens every bin generation.** The seal key and the held-key root derive
from it. A holder of the login secret, or of the `bin_held_root` that a session carries, opens
every held key of every generation. That party already holds the whole account, and ADR 0007
consequence 4 accepts the same property for the genesis seeds.

**E2 — The nonce rule covers a seam that reports failure, not a seam that lies.** `fresh_nonce`
(`crates/engine/src/entropy.rs`) also refuses a draw that leaves the buffer all zero, but an
entropy seam that returns repeated non-zero output without an error passes D3. The engine tests
prove distinct nonces from the test seam only. The host's entropy source is trusted.

**E3 — The fail-closed draw is stated for the bin plane only.** Every draw in the engine goes
through the same `Entropy` seam, whose `fill` returns a `Result`, so every caller receives the
error. No blueprint sentence states the general rule. One rule for every entropy
draw would need its own decision.

**E4 — A failed first publish strands a device for good, and the owner has not accepted it.
This residual is open.** The mechanism:

- `publish_bin_index` raises the durable mint counter (`crates/engine/src/bin_index.rs:322`)
  before it draws the nonce (`:323`), seals, preflights, and runs the PUT (`:334`).
- A publish that fails after `:322`, for any reason, leaves the mint counter as the only mark on
  the device. An entropy failure at `:323` is one such reason, so D3 can also strand the device.
- `holds_a_bin_index_mark` (`:253`-`:264`) then reads the mark, and every later genesis attempt
  on that device stops before it sends a request
  (`the_device_whose_genesis_publish_minted_a_revision_retries_nothing`).
- `unresolved_reason` (`crates/engine/src/record_plane.rs`) gives `StrandedMint` (D10), and
  `halt_for_bin_load` (`crates/engine/src/sync/drain.rs:210`) dead-letters every soft delete on
  that device under `BinIndexStrandedMint`. Nothing on the device clears the mint mark.

The genesis publish runs on every first run (D7), so a single failed PUT at vault genesis is
enough. The member can hard-delete, or sign in on a second device, which holds no mark,
publishes the record and clears the state.

`blueprint/engine.md` (lines 455 to 458) accepts the outcome for a stranded single-device
account: "the member is told the state and may hard-delete instead". It does not say that a
failed genesis publish leads to the state, that the state is permanent for every soft delete on
the device, or that an entropy failure after the mint also strands it. No decision source
exists: FSM1/cipher-box#1675 lists options and decides none. The owner must accept this
residual, or order a fix. Two changes narrow the window:

- Draw the nonce before the mint, so an entropy failure leaves no mark.
- Read the next revision without a write, and persist it only just before the PUT, so every
  failure before the PUT leaves no mark.

Neither change removes the residual case that D10 exists for, a publish that confirmed and then
lost its floor write.

**E5 — The two blueprint files list different disclosure triples.** `blueprint/core.md` lists
the IPNS sequence, the coincidence with the re-key republishes, and the existence of the record,
which the genesis publish closes. `blueprint/engine.md` lists the rung band, the IPNS sequence,
and the timing of each revision. D11 records the union that stays open: the band, the sequence,
and the timing with its coincidence. The republisher inventory holds the set of re-keyed names
for the EOL term.

**E6 — Nothing forces the version bump of D6.** The KAT manifest freezes the rung list and the
version as two separate values. A change to the rungs that also edits the manifest passes
without a `BIN_INDEX_V` bump.

**E7 — "No retry" means no uncharged retry.** `blueprint/engine.md` says that a caller that
retries on availability must not retry on a verdict, and a later bullet of the same section
says that the drain charges a verdict against the attempt budget. The code matches both
(`halt_for_bin_load` maps a verdict to `Halt::Attempt`): the op may run again inside its budget,
then dead-letters. D9 records that reading. The dead-letter exit itself belongs to the separate
ADR on the soft-delete and restore flow.

## Gate

The core tests run in the `Core KATs (native + WASM)` job and the engine tests in the `Engine
simulation tests` job, both inside the **Rust** area of the PR gate.

- **D1:** `bin_index_accept_vectors_seal_reproduce_and_open` and
  `bin_index_reject_vectors_fire_the_named_check` (`crates/core/tests/kat_manifest.rs`)
  reproduce each record from a fixed seal key and nonce, and refuse a foreign seal key, a
  read-body structure-tag transplant, a forward `v` and an unknown clear-header field.
  `a_second_account_cannot_open_the_first_accounts_bin` and
  `the_bin_name_is_derived_from_the_login_secret_alone` (`crates/engine/tests/bin_index.rs`)
  and `the_bin_publishes_at_a_name_the_settings_record_never_takes`
  (`crates/engine/src/bin_index.rs`) prove the name and the key.
- **D2:** `consecutive_publishes_never_reuse_the_seal_nonce` and
  `the_seal_nonce_comes_from_the_entropy_seam_and_not_from_the_record`
  (`crates/engine/tests/bin_index.rs`).
- **D3:** `a_publish_without_entropy_never_reaches_the_network`
  (`crates/engine/tests/bin_index.rs`).
- **D4:** `the_bin_edges_separate_by_secret_node_and_delete_time`
  (`crates/core/src/kdf/mod.rs`), the frozen edge probe outputs of the KAT manifest, and
  `a_purge_entry_round_trips_the_stamp_its_held_key_derives_from`
  (`crates/engine/src/sync/doomed.rs`).
- **D5:** `bodies_on_one_rung_seal_to_equal_lengths`,
  `the_rung_a_body_takes_never_falls_as_it_grows`,
  `the_pad_gaps_are_exactly_the_unreachable_totals` and
  `a_body_at_a_rung_cap_pads_and_one_past_it_climbs` (`crates/core/src/seal/bin_index.rs`), the
  two rung-edge accept vectors, and
  `a_bin_past_the_top_rung_is_refused_as_a_full_bin_and_not_as_a_codec_fault`
  (`crates/engine/tests/bin_index.rs`).
- **D6:** `an_off_rung_length_is_refused`, `a_non_zero_pad_byte_is_refused`,
  `a_missing_pad_field_is_malformed`, `the_pad_never_survives_into_the_preserved_set` and
  `a_body_padded_to_a_larger_rung_opens_and_re_pads_down`
  (`crates/core/src/seal/bin_index.rs`), and the `off-rung-length` and `non-zero-pad` reject
  vectors. No test ties a rung change to a `BIN_INDEX_V` bump (E6). The encode-side checks in
  `encode_bin_index` are plain `if` arms that return `Err`, not `debug_assert!`, so they hold in
  a release build. But no bin index case runs in the release-build `encode_refusals` suites of
  core or engine, which AGENTS.md rule 8 asks for.
- **D7:** `a_first_run_vault_publishes_its_empty_bin_index_at_genesis`,
  `the_first_soft_delete_revises_the_genesis_bin_index_rather_than_minting_one`,
  `a_repeated_first_run_leaves_the_bin_index_the_last_run_published`,
  `a_genesis_bin_index_that_did_not_land_is_published_by_a_later_start`,
  `the_device_whose_genesis_publish_minted_a_revision_retries_nothing` and
  `a_start_that_holds_the_bin_index_spends_no_publish_and_no_resolve`
  (`crates/engine/tests/write_plane.rs`), and
  `a_cold_start_with_no_published_record_loads_an_empty_bin`
  (`crates/engine/tests/bin_index.rs`).
- **D8:** `only_an_established_index_is_writable` (`crates/engine/src/bin_index.rs`),
  `a_withheld_record_refuses_the_rewrite_rather_than_minting_a_first_bin` and
  `a_replayed_sequence_is_refused_and_the_cached_copy_answers`
  (`crates/engine/tests/bin_index.rs`).
- **D9:** `only_a_refusal_of_bytes_the_plane_served_is_charged_against_the_bin_index`
  (`crates/engine/src/sync/drain.rs`), `a_same_sequence_fork_below_the_adopted_revision_is_refused`
  (`crates/engine/tests/bin_index.rs`) and
  `the_bin_read_refuses_a_replayed_index_rather_than_reading_it_as_stale`
  (`crates/engine/tests/write_plane.rs`).
- **D10:** `a_publish_that_fails_behind_its_mint_reads_as_a_stranded_mint` and
  `a_second_device_publishes_the_record_a_stranded_mint_could_not`
  (`crates/engine/tests/bin_index.rs`), and the `StrandedMint` arm of
  `only_a_refusal_of_bytes_the_plane_served_is_charged_against_the_bin_index`. The dead letter
  is proven at the halt mapping; no integration test drives a queued soft delete to the
  `BinIndexStrandedMint` dead letter.
- **D11:** no test. The rule accepts three disclosures and schedules nothing, so no behaviour
  exists to assert. The property a later decoy would need is the fresh nonce, which D2's tests
  prove.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
