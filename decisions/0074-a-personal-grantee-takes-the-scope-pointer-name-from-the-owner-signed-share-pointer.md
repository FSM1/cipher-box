# ADR 0074: A personal grantee takes the scope pointer name from the owner-signed share pointer

- **Status:** Accepted on 2026-10-07
- **Date:** 2026-10-07
- **Relates to:** [#2327](https://github.com/FSM1/cipher-box/issues/2327),
  FSM1/cipher-box-next#38 D3, ADR 0004, ADR 0020, ADR 0024, ADR 0063
- **Implemented by:** the PR that closes #2327
- **Amends:** ADR 0024 D1, as the amendment of 2026-09-25 states it

## Context

A write cut moves the scope root to a new name. A grantee with no write seed
must then follow the scope pointer to the new root (`blueprint/engine.md`
"rotateScopeWrite", ADR 0004). To do that, the grantee must hold the scope
pointer name. Today only a link holder holds it, from the invite fragment. A
personal grantee, and a writer that the owner downgrades to read, hold no name.
They keep the tree from before the cut, with no error, until the old names
lapse.

## Decision

**D1. The share pointer carries the scope pointer name, and the bookmark keeps
it.** The `SharePointer` mailbox payload gets an optional `scopePointerName`
key. The owner sets it on each post (`post_share_pointer`). The accept stores it
in the personal bookmark, under the `scopePointerName` key that a link hold
uses now. That key is then valid without `linkSecret`. The conversion persist
of ADR 0024 D2 deletes `linkSecret` and `linkDeadline`, and keeps
`scopePointerName`. Only an owner-identity-signed source supplies the name: the
share pointer, which the accept verifies against the contact-anchored sharer
key, or the invite fragment, under its owner signature. A grant blob and a
scope root record never supply it. The reason: no check binds a name to the
owner. A name that a writer controls can serve again an old owner-signed
re-point object, sealed under the `pointerReadKey` that every grantee holds.
That pins the grantee to the root from before the cut.

**D2. A bookmark with no name follows nothing until the owner posts again.**
This applies to a bookmark stored before D1, and to a share pointer from an
older owner build. An accept of a share pointer for a held bookmark with no
name adds the name to that bookmark. A direct grant to an existing personal
grantee at the same permission posts the share pointer again. It adds no row
and runs no cut. This gives the owner one repair path. A permission change of a
personal grantee, up or down, posts the share pointer to that grantee. So a
downgraded writer gets the name at the cut that needs it. That is one post to
one grantee. A write cut posts nothing to the other survivors.

## Alternatives considered

- **The grant blob carries the name.** This changes the `crates/core` grant
  blob codec and its KAT vectors. Each re-seal mints each blob again
  (`rotation::reseal`), and any committed writer re-seals. So the name in a
  blob is writer-authored, and the pin of D1 applies. An owner signature over
  the name in the blob stops the pin. But each writer re-seal must then carry
  the signed name without change, and an older writer build drops it. The
  share pointer already has the owner signature, at no core cost.
- **The grantee derives the name.** The KDF catalog derives the pointer
  keypair from `ownerPointerSeed` and the scope id. `pointerReadKey` is a
  sibling edge of the same seed, not its parent. An Ed25519 public key comes
  only from its private key. A new edge from `pointerReadKey` gives the pointer
  signing key to each grantee and each link holder, so each of them can publish
  at the pointer. It also moves each scope pointer name that exists.
- **The scope root record carries the name.** Any committed writer authors
  the read body, so the pin of D1 applies. In the forgery window, a revoked
  writer can plant the name at the old root name.
- **A write cut posts the new root name to each survivor.** FSM1/cipher-box-next#38
  D3 replaced the mailbox re-point with the scope pointer (ADR 0004). The bound
  for a read-only survivor then becomes mailbox delivery, not one pointer
  consult interval. Each cut also sends a burst of posts, and the burst shows
  the mailbox API the set of grantees of one scope.
- **One re-post to each personal grantee after the upgrade.** The same burst,
  plus a durable mark per scope to stop a second run. No production data
  exists before D1, so D2 is sufficient.

## Consequences

- `CONTEXT.md` "Scope pointer": a grantee holds the name from the share pointer
  or from the invite fragment.
- `blueprint/engine.md` "Grants and ledger": the "Accept flow" persist adds
  `scopePointerName`, and the link-held arm keeps the name at conversion.
  "Pointer planes" states that the bookmark keeps the name with
  `pointerReadKey`. The pointer consult runs for each bookmark that holds a
  name, not only for a link hold. The same-permission direct grant, now
  "nothing" ("already has access"), posts the share pointer again, and a
  permission change posts it to that grantee.
- ADR 0024 gets an "Amended by ADR 0074 D1" sentence at its amendment of
  2026-09-25.
- `blueprint/core.md`: no change. The grant blob, the KDF catalog and the KAT
  manifest stay as they are.
- The mailbox payload: an older build ignores the new key, because
  `SharePointer::decode` reads only the keys it knows.
- The stored list keeps version 2 (ADR 0024 consequence 1). The previous
  release refuses `scopePointerName` without `linkSecret`, so the reader change
  lands one release before the first write, as `blueprint/deploy.md` "A new
  durable staging prefix" does for a prefix.
- `blueprint/testing.md` names the engine tests and the web-e2e test of the
  personal read grantee and the downgraded writer, each in its required gate.

## Residuals

- Must the engine tell a host that a bookmark has no name, so that the user can
  ask the owner to share again?
- Staging holds the only data. Does the owner accept the one-release delay of
  the reader change, or does the owner prefer one step and a refused list on a
  rollback?
