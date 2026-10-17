# ADR 0077: A scope root stops being one by a re-seal into new node ids

- **Status:** Proposed
- **Date:** 2026-10-17
- **Relates to:** [#2298](https://github.com/FSM1/cipher-box/issues/2298),
  [#2241](https://github.com/FSM1/cipher-box/issues/2241),
  [ADR 0010](./0010-recycle-bin-is-an-owner-sealed-index.md),
  [ADR 0025](./0025-revocation-under-the-link-first-model.md),
  [ADR 0043](./0043-a-delete-writes-the-bin-entry-before-the-unlink-and-every-bin-op-journals-first.md),
  [ADR 0063](./0063-a-rotation-step-that-stops-leaves-a-durable-owed-record-that-the-sync-pass-finishes.md),
  `blueprint/engine.md` "Delete branch" and "Rotation primitives"
- **Implemented by:** not landed
- **Amends:** —

## Context

The delete command refuses a known scope root, and a folder stays a scope root after the owner
revokes its last grant. So the owner can never delete a folder that was shared one time. A revoke
does not make a plain folder: the root keeps its grant section and its random scope seed, which the
parent plane cannot derive. The delete, bin, restore and purge paths read the subtree under the
parent plane, and the parent's `directChildScopeIndex` keeps the entry, so every later ancestor
rotation fails closed in its eager set. `blueprint/engine.md` names "scope dissolution" as an op
that changes scope parentage, but no code implements it. The owner ruled on 2026-10-13 and on
2026-10-17.

## Decision

**D1 — A scope root stops being one by a re-seal of its subtree into new node ids.** The dissolve
authors each node of the subtree again as a new node of the parent scope: a fresh node id, the name
that the parent write seed derives for that id, the parent scope id in the AAD, and the parent's
current epoch. The parent folder then names the new plain folder in place of the old root. The
records of the old root and of its subtree are not re-authored. Then the old scope and its scope
pointer retire. The root gate does not change: a record at a scope root's id with no grant section
stays a `MissingGrantSection` refusal. Each device keeps the ids of its known scope roots durably, so
a plain record at the old id is a forged downgrade to every device that knew the root. New ids make
it unnecessary to tell an owner dissolve from a forged downgrade.

**D2 — A separate owner command dissolves a scope root, and the delete, bin, restore and purge
paths do not change.** The command cuts the scope, re-seals it under D1, and stops there. A dissolve
alone is the "stop sharing" function. To delete a shared folder, the host sends the dissolve, then
the ordinary delete on the new folder, under one confirmation. The rule "a scope root is neither
binned nor hard-deleted" stays true on every drain path, and the delete keeps its refusal of a
known scope root.

## Alternatives considered

- **In-place demotion (D1).** Keep the node ids, and add a root gate rule that accepts a scope root
  that becomes a plain folder. No re-seal, and ids and names stay. Rejected: the rule must tell an
  owner dissolve from a forged downgrade of a root that each device knows durably. That is a new
  trust rule on the root gate. Also, after a write grant the root publishes at a name that the
  parent write seed does not derive, so the boundary walk still reads the folder as a scope root.
- **A scope-aware delete (D2).** The delete of a scope root revokes each grant, then reads the
  root under the material of its own scope. Rejected: the soft delete, hard delete, restore and
  purge each read under the parent plane (`rekey_subtree`, `enumerate_doomed`, `publish_restore`),
  so all four change, and a restore gives back a scope root whose grants are cut.
- **Revoke every grant and keep the root (D2).** No new command. Rejected: the root keeps a seed
  that the parent plane cannot derive, so the delete refusal stays, and the stale
  `directChildScopeIndex` entry stops each later ancestor rotation in `enumerate_eager_set`.

## Consequences

- `CONTEXT.md` gains the term "Scope dissolution". It does not have the term now.
- `blueprint/engine.md` "Delete branch": the refusal of a known scope root names the dissolve as
  the path to a delete.
- `blueprint/engine.md` "Restore, purge, and expiry": a restore of a dissolved and then deleted
  folder gives back a plain folder.
- `blueprint/engine.md`: the confirmation lists each nested shared folder, and the dissolve cuts
  each one.
- `blueprint/engine.md`: a link claim that waits for conversion delays the cut.
- `blueprint/engine.md`: the dissolve runs online only, as a revoke does.
- `blueprint/engine.md` per-op rebase rules: a concurrent grant wins, as in "Delete vs concurrent
  grant". The dissolve refuses and the host reports it.
- `blueprint/engine.md`: the cut includes every grant, write grant and invite link, in one cut,
  before any re-seal. Otherwise a write grantee can republish a scope-sealed root.
- `blueprint/engine.md`: the re-seal does not run together with the cut sweep.
- `blueprint/engine.md` "Rotation primitives": the order is cut, re-seal, removal from the
  parent's `directChildScopeIndex`, retirement of the scope pointer. An owed record carries each
  step across a restart, as ADR 0063 D1 does.
- `blueprint/engine.md`: the dissolve retires the scope pointer name and the old root names in the
  registry.
- `blueprint/engine.md`: the uploads of a write grantee stay in the new folder, as an accepted
  residual.
- The re-seal shares the walk of a subtree from a source plane to a destination plane with
  FSM1/cipher-box#2241. It differs in one point: it mints new ids and names, and the restore of
  FSM1/cipher-box#2241 keeps them.
- `blueprint/desktop.md` "Conflicts, dead letters, and rotation": a delete of a shared folder is a
  dissolve, then a delete. The tray reports a refused dissolve.
- `blueprint/testing.md` names the tests for D1 and D2 in the code PR.

## Residuals

- **R1.** What does a grantee see after a dissolve? The old ids and names stop. The scope pointer
  retires, so the grantee holds a bookmark that resolves to no live scope.
- **R2.** The dissolve cuts each nested scope root in the subtree. After the cut, does each nested
  root also re-seal into a plain folder with new ids, or does it stay a scope root under the new
  folder, so that the later delete refuses? Or does the command refuse until the owner dissolves
  each nested root first?
