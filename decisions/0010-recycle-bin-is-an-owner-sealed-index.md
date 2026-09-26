# ADR 0010 — The recycle bin is an owner-sealed index, and deletion cuts access by re-key

- **Status:** Accepted — implemented; all six sub-issues of
  [FSM1/cipher-box#1399](https://github.com/FSM1/cipher-box/issues/1399) (engine) are closed and
  [FSM1/cipher-box#1400](https://github.com/FSM1/cipher-box/issues/1400) (web `/bin`) is closed
- **Date:** 2026-08-25
- **Relates to:** ADR 0006 (the owner-local sealed store family),
  [FSM1/cipher-box#1434](https://github.com/FSM1/cipher-box/issues/1434) (delete reclaims
  nothing), [FSM1/cipher-box#1094](https://github.com/FSM1/cipher-box/issues/1094) (version
  retention), and [#5](https://github.com/FSM1/cipher-box-next/issues/5) — which the blueprint
  cites for bin semantics but which only records that the bin was kept, not how it works

## Context

The blueprint commits to a bin twice — `web-client.md` promises `/bin` with "restore/purge ops
via facade", `desktop.md` calls the bin "vault-level engine behavior" — and specifies it
nowhere. No frozen decision constrains the design.

Today's delete is already half a bin, and a revocation hole. `publish_delete` drops the
`ChildRef` and republishes the parent; the child's record is never retired, its content never
unpinned (FSM1/cipher-box#1434). The unlinked node leaves the eager set, so no sweep and no
lazy wave ever re-seals it: **a revoked grantee holding the old scope seed keeps reading every
deleted node forever.**

The fact that shapes every option is key regression: a newer epoch seed derives every older
epoch key by design. No scope rotation can therefore hide an already-sealed node from a
current grantee, or from a revoked-then-reminted one. The only operation that cuts an existing
reader's access to an existing node is re-sealing that node under a key outside the scope's
derivation entirely.

v1's bin is the structural precedent: a standalone per-user sealed blob at a derived IPNS
name, whose entries carry the origin path, the deletion time, and the re-encrypted key
material for the binned subtree. Two v1 flaws must not be inherited: the index was rewritten
whole with no compare-and-swap (a documented data-loss bug), and retention was enforced only
when the bin happened to be loaded, so it was advisory.

### Alternatives rejected

- **A bin root inside each scope (relink-based trash).** Keeps binned nodes on the lazy wave,
  but every grantee of a scope sees that scope's bin, and "vault-level" degrades to a facade
  aggregation. The bin must be the owner's.
- **A tombstone flag on `ChildRef`.** Every read path must filter it; one missed filter is a
  fail-open disclosure, and the vault-level listing has no index.
- **A single vault-level bin scope.** Every delete becomes a scope exit, which is refused at
  two layers today and costs a rotation per delete by the floor law.
- **Revoking the whole scope's grants on delete.** Punishes every collaborator for one file's
  deletion, and after the remint, key regression hands the re-granted set the old epoch keys
  anyway — it does not even achieve the cut.

## Decision

1. **The bin is one owner-sealed, vault-level index.** It takes the sealed-store shape of ADR
   0006, but it is published and CAS-guarded like the vault settings record — not the
   per-device staging store — so two devices cannot lose each other's writes.
   Amended by ADR 0031 D1 on 2026-09-26: the bin is one owner-sealed, vault-level index, sealed
   symmetrically under `bin-index-seal-key`, and published and CAS-guarded like the vault settings
   record, so that two devices cannot lose each other's writes. The sealed-store shape of ADR 0006
   no longer applies.
2. **One `Delete` command; the facade branches on the owner's retention setting.** The
   setting lives in `VaultSettings`. Retention `0`: every delete is a hard delete, with
   reclamation. Retention `> 0`: deletes are soft. Hosts and the web client never decide —
   this is engine behavior, the v2 home of what v1 put in the SDK. The knob is actuated at
   delete time by construction, so it cannot become a dead setting.
3. **A soft delete from a scope with live or historical grants re-keys the deleted subtree**
   under a fresh key held only in the bin index, before the unlink. That is the access cut;
   rotation cannot provide it. Unshared scopes skip the re-key and keep the cheap unlink. The
   conditional-delete rebase rule is unchanged — nothing relinks into a tree location.
   Amended by ADR 0031 D4 on 2026-09-26: the soft delete re-keys the subtree under the key that the
   `bin-held-key` edge derives from the login secret, the node id and `deletedAt`, and the bin entry
   carries that key; "a fresh key held only in the bin index" no longer applies. Amended by ADR 0043
   D5 on 2026-09-26: every soft delete, from a shared or an unshared scope, re-keys the whole doomed
   subtree under the bin-held key before the unlink, and unshared scopes no longer skip the re-key.
4. **Restore into a shared parent re-seals under the destination scope's current epoch**, so
   the current grantee set reads it again by scope membership. An individual restore mints a
   fresh key and is shared manually.
   Amended by ADR 0043 D9 on 2026-09-26: a restore into a destination in the entry's own scope
   re-seals the subtree at that scope's current epoch, whether the scope is shared or not, and an
   individual restore no longer mints a fresh key. A destination in another scope stays open
   (ADR 0043 E2).
5. **A grantee's delete is captured owner-side.** The owner's engine observes the unlink
   (carried-set diff on the poll tick) and adopts the orphan into the bin, re-keying at
   adoption — without the re-key, the deleting grantee keeps the node key.
6. **Retention defaults to 30 days.** Expiry is evaluated on the poll tick against the
   journaled `deletedAt` using the injected scheduler seam, and every purge is emitted as a
   journaled op — replay reproduces the purge exactly, and retention is enforced rather than
   advisory.
7. **Purge and hard delete owe every doomed root to the retire ledger before publishing**
   (the `plan_prune` convention), with a new no-live-record debt class so that removing a
   record cannot strand permanently unsettleable pin debt. The reclamation for the existing
   hard delete (FSM1/cipher-box#1434) lands first and standalone.
8. **Platform junk never enters the bin.** The FUSE junk sweep hard-deletes on both branches.

## Consequences

- A soft delete from a shared scope costs one re-seal and republish per node of the subtree —
  the price of an access cut that key regression cannot undo.
  Amended by ADR 0043 D5 on 2026-09-26: every soft delete costs one re-seal and republish per node
  of the subtree, from a shared or an unshared scope.
- Restore requires a new op: materialize an unlinked node into a tree location. No current op
  addresses a node absent from the snapshot.
- The index write path is CAS-guarded; v1's whole-list rewrite is the named anti-pattern.
- Owner-side capture adds machinery to the poll path (carried-set diff, adoption, re-key).
- Vaults at retention `0` keep today's delete cost; the only change for them is that
  reclamation starts working.
- Documentation owed by the implementation: `blueprint/engine.md` (delete branch, bin index,
  purge, retention actuation), `blueprint/web-client.md` (`/bin`), and `CONTEXT.md` (bin
  index, bin key, soft delete, owner capture as named terms).
