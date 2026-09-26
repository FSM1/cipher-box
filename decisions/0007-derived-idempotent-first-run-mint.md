# ADR 0007 — The first-run vault mint is derived and idempotent, not drawn and remembered

- **Status:** Accepted — implemented in FSM1/cipher-box#1219 and FSM1/cipher-box#1274 (both
  merged)
- **Date:** 2026-08-09
- **Amends:** [#39](https://github.com/FSM1/cipher-box-next/issues/39) decision D8
  (the frozen KDF edge catalog) — adds two edges, and narrows the catalog's
  "scope seeds are non-edges" statement to rotations and grant cuts
- **Relates to:** [#26](https://github.com/FSM1/cipher-box-next/issues/26) decision
  D8 ("published records are the sole source of truth — no job records, no
  checkpoints"), which is why this decision adds no local state;
  [#28](https://github.com/FSM1/cipher-box-next/issues/28) decision D5 (the
  register-first, never-orphan publish ordering); and ADR 0005, whose edge shape
  this one copies
- **Implemented by:** [FSM1/cipher-box#1220](https://github.com/FSM1/cipher-box/issues/1220),
  [FSM1/cipher-box#1221](https://github.com/FSM1/cipher-box/issues/1221) and
  [FSM1/cipher-box#1222](https://github.com/FSM1/cipher-box/issues/1222) — all three closed,
  and this decision subsumes all three

## Context

The first-run mint draws two random scope seeds, derives the genesis root's
write-plane name from the write seed, publishes the root record, then publishes
the vault pointer naming it. Everything else about the run is already a pure
function of the login secret: the pointer name and its signer, the pointer read
key, the owner identity and encryption subkey, the writer pseudonym, and the root
scope id (the anchored bootstrap constant). The two entropy draws are the only
reason two attempts by one account differ at all — and every failure shape below
is a consequence of that difference.

**A crashed mint leaves a name nothing can ever name again.** A crash between the
root publish and the pointer publish leaves a registered name, a pinned head block
and possibly a root record that no pointer names. The record itself is
self-retiring: it carries a 90-day client-signed EOL and the API republisher is a
keyless re-PUT that cannot extend one, so it lapses. What persists is the registry
row and its pin, and the reason nothing reclaims them is precise — the only value
that could name that row was the drawn write scope seed, which the failed run
discarded.

**Two concurrent mints diverge without either device learning it.**
FSM1/cipher-box#1222 records the loser's verdict as `Unconfirmed` and its `start`
as failed. That is one interleaving, and it is the benign one. The publish
pipeline PUTs, then confirms by re-resolve; `fanout_get_verify` keeps a record
only on a **strictly greater** sequence, so at one sequence the winner is whichever
endpoint answers first in iteration order. The interleaving PUT(A), GET(A),
PUT(B), GET(B) therefore hands **both** devices `Published`: A reads its own bytes
back before B's PUT lands, and B reads its own back after. Both complete `start`,
both deposit seeds, and both write — under two different roots, with two different
read _and_ write scope seeds, at one scope id and one epoch. Neither is told. The
brief for this decision supposed the loser might already have written; it is worse
than that, because in the shape where writes are at stake there is no loser to
notify.

**No adoption rule can settle it.** Both pointer records are signed by the same
account-derived key at the same sequence and are equally valid; both root records
are equally valid at their own names. A tie-break — lowest root name, or the
network's own record-selection order — is evaluated over the records a device can
_see_, and a device that sees only its own concludes it won. Collapsing the fork
by re-pointing at sequence 2 forks again at sequence 2 for the same reason. The
fork has to be prevented or made empty; it cannot be adjudicated.

Both failures reduce to one question — what is authoritative when a mint did not
finish — and both answers follow from removing the draw.

## Decision

**D1 — the genesis scope seeds are derived, not drawn.** Two catalog edges over
the login secret, shaped like their neighbour `owner-pointer-seed`:

```text
| genesis-read-scope-seed  | login secret | the genesis scope's read (override) seed |
| genesis-write-scope-seed | login secret | the genesis writeScopeSeed               |
```

Genesis alone derives, because genesis alone has no predecessor to be idempotent
against. Every later scope seed is still drawn: rotation override seeds, write
rotations, and the scope seeds minted at grant cuts. D8's separation KAT extends
to both new edges.

**D2 — the mint's success condition is a re-openable re-point, not a landed PUT.**
After the pointer publish, resolve the pointer name and open the re-point under
the owner's own pointer read key.

- It names the derived root → the mint is complete, whatever byte-level verdict
  this run's own PUT came back with.
- It names a different root → this account has published and moved on; the mint
  publishes nothing further and `start` cold-starts from that re-point.
- Nothing resolvable → indeterminate: retryable, nothing deposited, no loop
  spawned.

No server answer authorises any branch. The re-point is owner-signed and sealed
under an owner-derived key; a withheld or lying answer can only push the run into
the indeterminate branch, which refuses. This is the discipline
`require_vacant_vault_pointer` already follows, applied to the other end of the
mint.
Amended by ADR 0031 D7 on 2026-09-26: the first-run terms of this ADR also cover the bin index
genesis publish, which is not part of the mint's success condition. The mint completes on its
re-openable re-point, the bin index publish follows it, and a later session start tries that publish
again only on a device that holds no mark.

**D3 — the root publish confirms by adopt.** A record at the derived root name
that this session's read key opens and the adoption gate admits completes the root
step, whether this run published it or a crashed earlier attempt did. A retry that
finds one publishes no second record and uploads no second head block.

**D4 — the residual leak is one head block, and it is accepted.** A crash between
the head upload and the record PUT leaves an unreferenced pinned block whose CID no
later run can name. That is the shape every publish already has, handled by the
existing orphan-head path; it gains no new mechanism here.
Amended by ADR 0047 D3 on 2026-09-26: the orphan-head path reaches only a failure that a live pass
observes, because the pending set lives for one session. So the one-block leak of a process that
dies between the head upload and the record PUT stays leaked, and no path retires it; this ADR still
accepts that leak.

Together these retire the orphan as a category. A crashed mint's root record is
not an orphan — it is this account's own genesis root, re-derived and adopted by
the retry. And on the one path that could still strand a name, a reclaiming party
learns that name by **re-deriving it**, which needs no journal, no listing and no
server work-list.

## Alternatives rejected

**An owner-local provisioning journal** — ADR 0006's structure with a new
`provisioning` kind, recording the drawn seeds and the published names until the
pointer lands. This is the strongest of the rejected options. 0006 already defines
exactly the right container: kind-separated, sealed, authenticated, carried over a
seam every host provides, so the real cost is one new kind and no new format. It
also reclaims strictly more than this decision does — it can name the orphaned
_head block_, which D4 concedes as leaked.

It is rejected on two grounds, in order. First on its own terms: a journal is
per-device, and half the problem is cross-device. The second device provisioning
concurrently has no journal to read and never will, so the mechanism is
structurally blind to FSM1/cipher-box#1222 and would still need the adoption rule
the Context shows does not exist. Second on #26 D8, "published records are the sole
source of truth — no job records, no checkpoints": a resumption note is a
checkpoint by construction, consulted before the network and believed when the
network is silent.

The argument for an exemption — that D8 governs _trust_, so a journal that merely
names bytes for re-checking against the network is not an authority — does not
survive its first failure mode. A journal that is empty when it should not be
(a fresh device, a cleared store, the first run on a host whose staging seam is
not yet durable) sends the mint down the "nothing was published" branch. Its
absence decides behaviour, which makes it authoritative in exactly the direction
that leaks, and it is least likely to exist at precisely the moment it matters
most. Derivation reaches the same recovery with nothing to be lost, be stale, or
be believed.

**Registry serialization** — let `POST /registry/register` refuse a second claim on
the vault-pointer name, and treat the conflict as the loser's signal. It is the one
true serialization point in the system, it is the mechanism v1 shipped (the
duplicate-key error FSM1/cipher-box#1222 cites), and a server answer used to
_refuse_ is the permitted direction. Rejected because there is nothing to conflict
with: registration is idempotent by contract, and both devices are the **same
account**, so both claims are the same claim. Manufacturing a conflict means the
server issues a per-device mint token — at which point a server answer authorises
a mint rather than refusing one, and a hostile or merely broken registry decides
which of an account's devices owns its vault.

**A deterministic winner for the fork, with the loser adopting.** No new key
material, no catalog change, and the adoption is genuinely cheap: either device can
open either root's owner-write blob and recover the other's seeds, so the loser is
never locked out of the winner's vault. Rejected because the rule cannot be
evaluated — see the Context. `fanout_get_verify` makes the failure concrete: it
retains a record only on a strictly greater sequence, so a same-sequence tie is
settled by endpoint iteration order, a per-read accident rather than an agreement
between devices.

**A registry listing plus a retire sweep.** Fetch the account's registered names
after a successful mint and retire everything the new vault does not reference. It
is the only proposal that reclaims a name whose seed is already gone, and it is
safer than it looks: retirement touches nothing but the server's own rows, which a
hostile server can drop unilaterally anyway, so a lying list grants it no new
power. Rejected because the population it serves is empty — under
[#6](https://github.com/FSM1/cipher-box-next/issues/6)'s clean break v2 has never
been deployed, so there is no accumulated orphan to reclaim — and the price is a
new API surface plus a first-run-only special case whose work-list is
server-authored.

**Accept the orphan and keep the straight-line mint**, documenting the leak. Very
nearly right, and it is why FSM1/cipher-box#1221 was filed as a resource issue: the
leak is one name row and one head block per crashed first run, an event that
happens once per account and only on a crash, and a loser that _does_ fail its
`start` recovers on the next one — the pointer walk finds the winner's pointer and
cold-starts from it with no new mechanism at all. It fails on the shape that
matters: in the both-`Published` interleaving neither device fails its `start`, so
"recovers on the next start" describes only the harmless case.

## Consequences

1. **`blueprint/core.md`'s KDF catalog gains two rows**, and its closing "Non-edges,
   stated to stay non-edges" sentence must be narrowed: scope seeds are random at
   every rotation and every grant cut, and derived at genesis only. A KAT pins the
   derived genesis root name, so the property the whole decision rests on — two
   runs of one account mint one name — cannot drift silently.
2. **`CONTEXT.md`'s "Scope" entry is corrected.** It reads "keyed from one random
   scope seed", which after this decision is false of the vault root's first epoch
   and true everywhere else.
3. **The engine's provisioning contract inverts.** `sync/provision.rs` documents
   itself as straight-line with no resume and no cross-device coordination; it
   becomes idempotent with no stored state, and its success condition moves from
   the publish verdict to the re-openable re-point. The engine test asserting that
   both scope seeds are drawn rather than derived is replaced by its opposite for
   the genesis pair, plus a rotation-side assertion that every later seed is still
   drawn.
4. **The login secret becomes an offline route to the genesis seeds.** It was
   already an online one: `enc-subkey` opens the owner blob and the owner-write blob
   at every epoch, so a holder of the login secret could always recover both seeds
   given the published root. What is removed is the "and fetch the record" hop, for
   one epoch, for a party who by then holds the whole account. Rotation restores the
   property in full — no post-genesis seed is recoverable from the login secret
   alone.
5. **Two concurrent mints converge on one vault with identical keys.** Their
   concurrent _writes_ then behave like any other concurrent write at one name,
   which is the rebase problem and is not solved here.
6. **Two semantically identical records may sit at each genesis name** until the
   first publish at sequence 2 collapses the tie. They decode to the same re-point
   and the same empty root, so no reader is affected by which one an endpoint serves.
7. **The vacancy probe is unchanged** and remains the mint's one precondition. So
   does the standing consequence of a fixed account-derived pointer name: an account
   whose vault is deleted cannot be re-provisioned while any record survives at that
   name. This decision neither causes nor worsens that.

## Gate

- Two provisioning runs for one login secret, over independent entropy streams,
  produce the same root name and the same re-point object, and each opens the
  other's published root record. Asserted on the values, not on the derivation
  code.
- A run interrupted after its root record lands, re-run: publishes no second root
  record, uploads no second head block, and completes. Exactly one root name is
  registered for the account.
- Two concurrent runs against one account both complete `start`. One root name and
  one pointer name exist, and each device's session opens the record the other
  published — the both-`Published` interleaving specifically, not only the
  `Unconfirmed` one.
- A pointer publish that comes back unconfirmed, at a name that nonetheless serves
  a re-point naming the derived root, completes the mint; one that serves nothing
  resolvable fails retryable, deposits nothing and spawns no loop. Distinct,
  asserted outcomes.
- A re-point naming a root this mint did not derive stops the mint and cold-starts
  from it, with no record published after the point of discovery.
- The separation KAT covers both new edges on equal inputs, and a write rotation on
  a provisioned vault mints a seed that differs from the genesis derivation —
  proving the derivation did not escape its one epoch.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The
`blueprint/` copies in this repository are the as-charted archive and are not edited
by this ADR.
