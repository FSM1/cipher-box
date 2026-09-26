# ADR 0017 — The epoch tag is a key-selection label, not an attestation

- **Status:** Accepted — `CONTEXT.md` and `blueprint/engine.md` reworded in FSM1/cipher-box#1770 (merged); the `Envelope::epoch` doc line landed in FSM1/cipher-box#1777 (merged)
- **Date:** 2026-09-05
- **Relates to:**
  [FSM1/cipher-box#1203](https://github.com/FSM1/cipher-box/issues/1203) (the design question
  this ADR settles),
  [ADR 0012](./0012-the-drain-carries-the-write-wave-forward.md)
  D2 (the two sanctioned readers below the read-epoch floor) and E1 (the cheaper trigger),
  [ADR 0003](./0003-sweep-population-and-below-floor-scope-roots.md)
  (the sweep's population is interior nodes),
  [ADR 0004](./0004-read-body-child-names-on-the-name-wave.md)
  (the name wave rewrites read-body child names),
  the `CONTEXT.md` "Forgery window" entry, and the `blueprint/engine.md` "sweep" section
- **Implemented by:** two doc rewordings in FSM1/cipher-box, after acceptance. No code changes.

## Context

Every sealed body carries a plaintext epoch tag `{scope, epoch}` (`CONTEXT.md` "Epoch"). The
tag is one of the five AAD members of the read-body seal, `(v, id, scope, epoch, structTag)`
(`crates/core/src/seal/aad.rs`), so a body opens only under the read key of the epoch its tag
names. That is the tag's whole job: it tells a reader which epoch's seed derives the key.

[FSM1/cipher-box#1203](https://github.com/FSM1/cipher-box/issues/1203) raises a design question
about that tag. The sweep reads an interior node without the read-epoch floor, and re-seals
the body at the scope's current epoch. A party who holds an old epoch's read seed and still
holds a node's write key can author a body at that old epoch. The sweep later promotes that
body to the current epoch. The issue asks whether the sweep should bind the promoted body to
the epoch its author could prove, so a promotion cannot launder an old-epoch authorship into
the current one. Any answer changes the frozen record shape, so it needs this record.

An audit of the engine on `main` shows that the premise does not hold as a capability gain.
The epoch tag never carried authorship, so the relabel launders nothing.

### What authenticates an interior record

An interior node publishes no grant section and no writer-pseudonym signature. Two checks
authenticate it, and only two:

- **The IPNS record signature under the node's write-name key.** The name _is_ the key: stage 1
  of the adoption gate derives the `ipnsName` from the signing key it verifies
  (`crates/core/src/ipns/record.rs`). That key derives from the scope's write scope seed and
  the node id (`SessionIdentity::write_name_signer`, `crates/engine/src/session.rs`).
- **The AEAD tag under the read key of the epoch the tag names.** A body relabelled to another
  epoch opens under no seed, because the AAD carries the epoch.

Neither check names a writer. Whoever holds the write scope seed of a name can sign at that
name. Whoever holds the read seed of an epoch can seal at that epoch. The epoch tag adds no
third check: a committed writer chooses any label at or below the scope root's epoch freely,
and the sweep treats a label above the root's epoch as its own read failure, not as a trust
verdict (`interior_node` in `crates/engine/src/net/rotation.rs`).

### What bounds insertion

A revoked writer's power to insert a record rests on names, not on epochs. `rotateScopeWrite`
mints a fresh write scope seed, republishes the subtree under freshly derived names, rewrites
every `ChildRef.ipnsName` in the parents' read bodies (ADR 0004), and re-points the root last
(`crates/engine/src/rotation/rotate_write.rs`). After the re-point, three facts hold on `main`:

- The sweep anchors on the gated scope root, and its frontier is that root's read-body
  children (`body_children` in `crates/engine/src/rotation/sweep.rs`). Those refs name the
  rewritten names. A root that resolves below its own floor is a superseded name, and the
  walk re-resolves it through the pointer consult to `currentRootName` (ADR 0003).
- Every sweep publish signs with the write scope seed of the root this pass gated:
  `publish_node` passes `SweptScopeSource.write_scope_seed` to `publish_interior_head`, and
  that source is parked from `gated_root` (`crates/engine/src/net/rotation.rs`). The revokee
  holds the superseded seed, which derives none of the new names.
- The drain's re-author signs the same way, from the pass's own gated root (ADR 0012).

So insertion is possible only during the name wave, at an old name the wave has not yet
rotated. `CONTEXT.md` "Forgery window" records that as an accepted residual. A body inserted
inside the wave rides the wave to its new name like every honest body. After the re-point, no
path signs at a name the revokee can derive, so the sweep cannot widen insertion. What the
sweep and the drain do later is relabel: they open the body under the seed the ratchet reaches
and re-seal it at the current epoch. The relabel is what the lazy wave does to every honest
lagging node too.

The issue's "old epoch" framing is also the narrow case. A write-to-read downgrade runs
`rotateScopeWrite` alone, with no read rotation (`blueprint/engine.md` "Triggers"). The
downgraded writer keeps the current read seed. Inside the wave, such a party seals at the
current epoch with no relabel needed. The epoch tag never stood between that party and the
current epoch. The name did.

### The readers of the epoch tag in the engine

The engine flattens `epochTag` into `Envelope::scope` and `Envelope::epoch`
(`crates/core/src/seal/envelope.rs`). Every non-test reader of `Envelope::epoch` in
`crates/engine/src` falls into three roles, and none of them is a writer-identity check:

**Key selection.** The tag names the seed that opens the body, or the epoch a seed belongs to.

- `gate/adoption.rs`: the AAD context for the grant blob, the seed blob and the ascent link
  (an ascent link whose payload epoch differs from the envelope is refused as a mismatch).
- `net/child.rs` `open_interior_under`: the AAD alone, under the seed the caller ratcheted to.
- `net/rotation.rs` `open_interior_record`: `seed_at_epoch` walks the ratchet to the tag's
  epoch, and a tag above the root's epoch is `Unreadable`.
- `net/rotation.rs` scope-root readers: `CascadeTarget.current_read_epoch`,
  `grant_blob_aad`, `GranteePlan.read_epoch`, `PromotedScopeRoot.read_epoch`,
  `WaveSource.read_epoch`, and the `DescendantScopeRoot` adopted epoch.
- `grants/accept.rs` and `grants/received_status.rs`: the grant blob AAD.
- `rotation/reseal.rs` `walkable_chain_start`: the head epoch of the history-link walk.
- `sync/drain.rs`: the pass epoch, the ratchet target for a lagging node.
- `facade.rs` `deposit_seed`: the epoch stamp of a recovered scope seed.

**The floor law.** The tag is compared with a durable floor, or bound to the floor a publish
must clear.

- `gate/adoption.rs` stage 5 and `gate/floor.rs`: epoch at or above the durable read-epoch
  floor.
- `net/child.rs` `adopt` and the at-floor re-open: `floor::check` with the envelope epoch.
- `sync/drain.rs` root load: `floor::check` at the floor.
- `net/record_publish.rs` `preflight`: the envelope epoch must equal the head binding, and
  the `EpochBar` is the encode side of stage 5.
- `grants/revocation.rs` `classify`: `record_epoch < epoch_floor` is `EpochLag`, never a
  revocation and never an authorship verdict.

**The lag operand.** The tag says how far a node lags its scope.

- `rotation/sweep.rs` `SweptNode.current_read_epoch` and `LaggingNode.read_epoch`, and the
  release-active check in `publish_node` that a node seals only at the epoch of the gated
  root.

No reader in the list treats the tag as evidence of who sealed the body or of when. The
`net/rotation.rs` comment at the sweep's read states it in place: "the epoch is only AAD".

## Decision

**D1 — The epoch tag is an AAD-bound key-selection label.** It tells a reader which epoch's
read seed derives the key that opens the body, and it lets the floor law bar an old-epoch
record past a revocation boundary. It attests nothing about who sealed the body. Authorship of
an interior record is the IPNS signature under the node's write-name key, and nothing else. The
engine holds that rule today, and this ADR records it so no future reader adds a fourth role.

**D2 — A sanctioned below-floor reader may relabel a record's epoch tag, and the relabel
attests nothing.** The two readers of ADR 0012 D2, the sweep's `interior_node` and the drain's
`open_interior_under`, open a lagging body under the seed the ratchet reaches and re-seal it at
the epoch of the scope root the pass gated. The new label states where the body now opens. It
does not state that a current writer sealed it. A promotion is not a laundering, because there
is no attestation to launder.

**D3 — The forgery window is wave-bounded for insertion, and sweep-length only for the
label.** A revoked writer inserts only inside the name wave, at an old name. After the
re-point, no path signs at a name that party can derive. An inserted body keeps its old epoch
label until the sweep or an ordinary write reaches the node, which is the same sweep-length
window every honest lagging node sits in. `CONTEXT.md` "Forgery window" and the
`blueprint/engine.md` "sweep" section are reworded to say so, in FSM1/cipher-box, after
acceptance. The residual the issue observed is the label's window, not a longer insertion
window.

**D4 — No field is added to the envelope.** The alternative below adds an `authoredEpoch` and
a detached writer-pseudonym signature to `epochTag`. Rejected. The decision is recorded before
the cutover on purpose: a post-cutover adoption of that field costs a `v` bump and a
sweep-driven re-seal of every interior node, and this ADR closes the question while that cost
is still zero.

## Alternatives rejected

**An `authoredEpoch` plus a detached writer-pseudonym signature over
`(id, scope, authoredEpoch, body)`, carried as a typed `epochTag` field.** This is the only
fix the issue's framing admits. It adds a struct tag to the registry in
`crates/core/src/seal/aad.rs` with a KAT family, extends `EPOCH_TAG_KNOWN` in
`crates/core/src/seal/envelope.rs`, has `author_child_envelope` sign at authoring time, has the
sweep carry the field verbatim and the drain re-sign at the pass epoch, and adds an
adoption-gate stage that verifies the signature against the commitment's pseudonym set. Two
faults, either one fatal:

- It closes no window. An honest pre-cut record by the revokee and an in-wave insertion carry
  the same `authoredEpoch` and the same valid pseudonym signature, because the revokee was a
  committed writer at that epoch. A verifier must accept the first, so it accepts the second.
  The field makes the relabel visible and nothing else.
- Its cost lands on the frozen record shape. Before the cutover the field could be mandatory.
  After the cutover every interior record on the network lacks it, so a reader must either
  tolerate absence, which lets an attacker omit the field and fail open, or the format takes
  a `v` bump and every interior node re-seals through the sweep. That is why this decision is
  recorded now, while no record exists.

**Keep the old label at promotion.** The sweep would re-seal the body at the old epoch, or
not at all. Then the node stays below the floor for ever, stage 5 refuses it for every ordinary
reader, and the lazy wave cannot converge. The issue itself notes that refusing a lagging
node makes the pass a no-op. Rejected.

**Refuse a lagging record the sweep cannot attribute.** There is nothing to attribute it by.
An interior record carries no writer identity, and adding one is the first alternative.
Rejected.

**Sign every interior body with the writer pseudonym, as scope-root structures are.** This is
the first alternative under another name, with the same two faults, and it puts a pseudonym
signature on every ordinary write. Rejected.

## Consequences

1. **`CONTEXT.md` changes when this ADR is accepted.** The "Forgery window" entry gains one
   sentence: the bound applies to _insertion_; an inserted record keeps its old epoch label
   until the lazy wave reaches the node, and the label attests nothing (ADR 0017).

2. **`blueprint/engine.md` changes when this ADR is accepted.** The "sweep" section, after
   "its body opens under the seed the scope's history-link ratchet walks back to", gains: the
   re-seal relabels the node's epoch tag; the tag is a key-selection label and no reader
   treats it as authorship (ADR 0017). The "Residuals" list gains one line: revoked writers
   insert only inside the wave; an insertion keeps its label for a sweep-length window, and
   the label attests nothing.

3. **`crates/core/src/seal/envelope.rs` gains one doc line on `Envelope::epoch`.** The line
   names the rule and cites this ADR, so a reader who adds a consumer meets it at the field.

4. **The record shape does not change.** No struct tag, no KAT family, no gate stage, and no
   engine code changes. The reader inventory above is the as-built state.

5. **FSM1/cipher-box#1203 closes on acceptance.** The design question is settled with no
   implementation.

## Residuals

**E1 — Insertion inside the name wave stays.** That is the residual `CONTEXT.md` already
accepts. After the sweep or a member write reaches the node, the inserted body is sealed at
the current epoch under a signature the pass made, and no reader can tell it from an honest
lagging node. This ADR accepts that, on the ground that no reader could tell them apart before
the relabel either.

**E2 — The label states nothing about when a body was sealed.** A committed writer picks any
label at or below the root's epoch. A reader who wants a time of authorship must not read the
tag for it.

**E3 — The tag stays plaintext.** An observer learns each scope's rotation count and each
node's lag position. That is the existing exposure of `CONTEXT.md` "Epoch", unchanged here.

**E4 — The write-to-read downgrade keeps the current read seed at the downgraded party.**
Inside the wave that party seals at the current epoch. The name wave, not the epoch, is the
whole bound. `CONTEXT.md` "Forgery window" already states the bound in names.

## Gate

- `CONTEXT.md` "Forgery window" states that the bound applies to insertion, and that an
  inserted record's epoch label follows the lazy wave and attests nothing.
- `blueprint/engine.md` "sweep" states that the re-seal relabels the epoch tag and that no
  reader treats the tag as authorship; its "Residuals" list carries the revoked-writer line.
- `Envelope::epoch` in `crates/core/src/seal/envelope.rs` carries the one-line rule.
- The reader inventory in this ADR matches `crates/engine/src` at review time. A review of any
  PR that adds a reader of `Envelope::epoch` re-runs the inventory. This is a review check,
  not a CI gate: a grep gate would assert source text, which `blueprint/testing.md` forbids.
- The two tests that pin the mechanism stay green:
  `a_seed_from_another_epoch_opens_no_lagging_record` (`crates/engine/src/net/child.rs`),
  which shows a relabelled record opens under no seed, and
  `a_swept_node_republishes_at_the_scopes_epoch_under_the_current_seed`
  (`crates/engine/src/net/rotation.rs`), which shows the relabel seals at the gated root's
  epoch.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
