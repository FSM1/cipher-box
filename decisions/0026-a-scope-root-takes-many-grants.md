# ADR 0026 — A scope root takes many grants

- **Status:** Accepted on 2026-09-25; the `blueprint/*.md` and `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-25
- **Relates to:**
  [wayfinder: sharing as a link-first flow with no approve step (#1945)](https://github.com/FSM1/cipher-box/issues/1945),
  [sharing: add a second person to a folder that is already shared (#1951)](https://github.com/FSM1/cipher-box/issues/1951),
  ADR 0023 (conversion appends a row), ADR 0025 D6 (permission change), the `blueprint/engine.md`
  "Grants and ledger" section ("Grant creation"), the `blueprint/web-client.md` "Composition
  (apps/web)" section, and the `CONTEXT.md` "History link", "Grant ledger" and "Epoch-converged" terms

## Context

A folder takes one share today. A second direct grant on a scope root is refused with
`grant-target-already-names-a-scope`, and a link on a directly granted folder with
`invite-target-already-names-a-scope` (`crates/engine/src/facade.rs:3589-3611`). A contact grant
always mints a new scope with one row (`crates/engine/src/grants/create.rs:1049-1061`), and the
standing check refuses an existing scope (`facade.rs:3614-3618`). Only `convert_invite_claims`
appends a row to an existing scope (`crates/engine/src/grants/invite.rs:861-876`,
`facade.rs:9361-9398`).

The blueprint "Grant creation" bullet mints the scope with a fresh seed at epoch 1 and says "the
new grantee needs no history". That is true only for the first grant. The link-first flow
(ADR 0023) adds people to one folder over time, so the refusal blocks its main use. File and line
citations come from the research reports (`main` at `d30509e48`).

## Decision

**D1 — A grant or a link on a scope root appends.** The engine adds one row to the existing scope:
one more grant blob, the commitment re-signed, and the root published once at the current epoch.
There is no new seed, no re-seal of the subtree, and no converge step. The contact-code grant
gains the append that conversion has today.

**D2 — Links and direct grants coexist on one folder.**

**D3 — A folder can have any number of live links.** Each link has its own permission and its own
lifetime.

**D4 — A grant to an existing grantee is a permission change or nothing.** When the permission
differs, the grant is a permission change (ADR 0025 D6). When it is the same, nothing changes, and
the dialog says "already has access".

**D5 — Ancestors and descendants stay as today.** Sharing a folder that holds a shared subfolder
keeps the subfolder as a nested scope (`facade.rs:3631-3649`, `create.rs:1072-1334`). Sharing a
folder inside a shared folder creates a nested scope under the enclosing one
(`facade.rs:7866-7931`, `:8508-8510`).

**D6 — A new grantee reads the whole history of the scope.** This is a fact of the design, not a
choice. A grant blob carries the current seed, and the history links walk it back to every
earlier epoch of the scope. A person who is admitted again reads what was sealed while the person
was out. Convergence stays a concern of a fresh mint only.

**D7 — The refusal set after the change.** `grant-target-already-names-a-scope` and
`invite-target-already-names-a-scope` retire for the append case. These refusals stay:

- the target is the vault root;
- the index lost a root;
- the parent envelope version is not supported;
- the display name is too long;
- the engine cannot place a child scope;
- the recipient is the owner;
- the recipient key is not usable;
- the parent scope is superseded;
- the subtree is not converged (a fresh mint only);
- the resume is not this grant.

## Alternatives considered

**(a) Keep one grant per folder.** Rejected. The owner then must create a new folder to add a
person, and the link-first flow adds people to one folder all the time.

**(b) Hide the earlier history from a new grantee.** Rejected. The history links make the current
seed reach every earlier epoch, so a hidden history needs a separate scope. A folder is one scope root
and cannot hold a second scope beside it.

**(c) Rotate the scope at each append.** Rejected. A rotation cuts nobody here, it costs a
republish of every descendant scope root, and by (b) it still does not hide history.

## Consequences

1. **`blueprint/engine.md` changes.** In "Grants and ledger", "Grant creation" splits into a fresh
   mint, which keeps the current text, and an append, which states D1. The phrase "the new
   grantee needs no history" becomes "a fresh mint needs no history; an append gives the new
   grantee the whole history of the scope (D6)".
2. **`blueprint/web-client.md` changes.** "Composition (apps/web)" shows the people table of an
   already shared folder with the "create link" row and the advanced contact-code path, and it
   drops the two retired refusals from its refusal copy.
3. **`CONTEXT.md` changes.** "History link" gains "so a new grantee of a scope reads every earlier
   epoch". "Grant ledger" states that a scope root holds any number of rows, links and personal
   rows together. "Epoch-converged" says that a fresh mint, not an append, converges the subtree.
4. **No wire format, no KDF edge and no op record changes.** The append uses the row mint that
   conversion already uses.
5. **Conversion never changes an existing row.** A write link does not upgrade an existing read
   grantee, and a read link does not downgrade an existing write grantee. D4 covers a direct
   grant only; conversion is a no-op on a known identity (ADR 0023 D3).

## Residuals

**E1 — A conversion that hits the 1024-row cap is refused.** The op entry dead-letters and does
not block the queue. The people list shows the refusal.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
