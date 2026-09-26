# ADR 0025 — Revocation under the link-first model

- **Status:** Accepted on 2026-09-25; the `blueprint/*.md` and `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-25
- **Relates to:**
  [wayfinder: sharing as a link-first flow with no approve step (#1945)](https://github.com/FSM1/cipher-box/issues/1945),
  [sharing: what revocation means under the link-first model (#1949)](https://github.com/FSM1/cipher-box/issues/1949),
  [sharing: prototype the share dialog with the link as the main path (#1948)](https://github.com/FSM1/cipher-box/issues/1948)
  (the revoke confirmation and the "can" control),
  [engine: two owner devices can publish different records at one sequence (#1959)](https://github.com/FSM1/cipher-box/issues/1959)
  (the expired-link sweep depends on its fix),
  [Design: sharing and grant delivery architecture (#25)](https://github.com/FSM1/cipher-box-next/issues/25)
  D4 (the immediate cut), ADR 0023 (the entry kind, the deadline and the via-link reference),
  ADR 0024 (link holders), the `blueprint/engine.md` "Grants and ledger" ("Revocation is
  discovered, not delivered") and "Rotation primitives" ("Triggers") sections, the
  `blueprint/web-client.md` "Composition (apps/web)" section, and the `CONTEXT.md` "Cut epoch",
  "Revocation floor" and "Write-scope cut" terms

## Context

A person revoke runs `revoke_grant`, then `cut_recipient`, and finds the recipient only in the
device-local contact book (`crates/engine/src/facade.rs:8079-8093`, `:8223-8233`). So a person
that device A converted cannot be revoked from device B. `cut_and_rotate` steps the cut epoch and
republishes the scope root and every descendant scope root under a fresh seed
(`facade.rs:8249-8313`, `crates/engine/src/rotation/trigger.rs:795`). "Revoke link" cuts the link
row only, and the grants that came from its claims stay (`facade.rs:9018-9055`). Nothing cuts a
link at its deadline. The deadline sits in the sealed ledger, where a read holder cannot see it.

ADR 0024 adds link holders, who read through a key that every holder of one link shares. This ADR
states what each revoke removes and what the removed side sees. The engine word for a revoke
stays **cut**. File and line citations come from the research reports (`main` at `d30509e48`).

## Decision

**D1 — "Revoke link" cuts the link row.** Every link holder of that link loses access at once,
because the rotation leaves no blob at the link tag. A grantee who came through the link keeps
access by default. The confirmation carries one checkbox, "also remove the N people who joined
through this link", for a leaked link. The engine finds those grantees by their via-link
reference (ADR 0023 D2).

**D2 — An owner sweep cuts expired links.** The owner engine runs a slow sweep, slower than the
30 s tick. The sweep walks `directChildScopeIndex` from the vault root, with one resolve and one
unseal per scope root. It reads each root's commitment for link entries whose deadline
(ADR 0023 D2) is not later than the injected `now`, and it cuts each such link. The cut is a
rotation, the same as a manual revoke. The sweep first converts pending claims and never cuts a
link with a pending op entry (ADR 0023 D4). This replaces the blueprint rule "the next owner
session observing it acts — no scheduler".

Two devices that cut one link in one window publish two records at one sequence, the open
two-device publish bug (FSM1/cipher-box#1959). The sweep depends on its fix: re-resolve, then
sign above the highest sequence seen. An honest grantee engine reads the same deadline and stops reading through
the link at it, so the UI says "expired" before the owner's sweep runs.

**D3 — Revoke runs on any owner device.** The engine reads the person's encryption key from the
owner-signed ledger row in the folder record, after the row signature verifies
(`crates/core/src/seal/write_body.rs:202-255`). It does not read the contact book. The contact
book becomes a grantee name cache (ADR 0027).
Amended by ADR 0032 D2 on 2026-09-26: the engine finds the person's rows through the owner-attested
ledger row, and names the recipient key from the commitment entry. For a row whose label the owner
did not attest, the engine matches the encryption subkey that this device's contact book binds to
the identity against the commitment entry.

The revocation floor and the grant floor are device-local and key on the recipient key. So after
device B cuts P and device A converts P again, B withholds P's blob at each of its re-keys, P sees
a false "The owner removed you", and access flaps. The rule: an owner-signed commitment that
commits P, at a cut epoch not below the cut that this device recorded, clears this device's local
cut for P. The reverse case, a device that never saw the cut, is the accepted residual of the
`CONTEXT.md` "Revocation floor" term (no cold-seed anchor).

**D4 — One revoke is one cut.** Every row that one revoke removes leaves in one cut set, with one
cut-epoch step and one rotation. The set is a person and the link that admitted the person
(ADR 0024 D3), or a link and the grantees that the checkbox of D1 names.

**D5 — The removed side sees one of three messages.**

| Message               | When the engine shows it                                           |
| --------------------- | ------------------------------------------------------------------ |
| The owner removed you | A grantee finds no blob at the personal tag                        |
| The link expired      | The deadline of the link entry it last verified is not after `now` |
| The link was revoked  | A link holder finds no blob at the link tag before the deadline    |

The engine knows whether it read as a link holder or as a grantee from its bookmark
(ADR 0024 D2).

**D6 — The owner can change a grantee's permission.** The "can" column of the people table is a
control with view and edit.

- An upgrade mints write material for that person. When the folder is not a write scope yet, a
  write-scope cut runs first.
- A downgrade is a write revoke: a write rotation renames the subtree. The person keeps read, with
  a read row minted at the new name.

**D7 — A link's permission is fixed at creation.** To change it, the owner revokes the link and
creates a new one. The link chips carry no permission control.

## Alternatives considered

**(a) A link revoke also removes its grantees by default.** Rejected. Most link revokes end a link
that did its job. The checkbox covers a leaked link.

**(b) Keep the deadline in the sealed ledger.** Rejected. A read holder cannot see it, and a
committed write grantee can change it.

**(c) Sync the contact book so that any device finds the recipient.** Rejected. The owner-signed
row already carries the key, and ADR 0023 D8 keeps the contact book local.

**(d) One cut per removed row.** Rejected. It costs one rotation of the scope and every
descendant scope root for each row, and it steps the cut epoch more than once for one owner act.

## Consequences

1. **Each expired link costs one rotation.** D2 rotates the scope and every descendant scope root,
   as a manual revoke does. Each sweep also costs one resolve and one unseal per scope root.
2. **`blueprint/engine.md` changes.** In "Grants and ledger", "Revocation is discovered, not
   delivered" states D1, D3, D4 and D5, and D6 and D7 join it. In "Rotation primitives",
   "Triggers" gains the expired-link sweep of D2 in place of "no scheduler".
3. **`blueprint/web-client.md` changes.** "Composition (apps/web)" gains the "can" control, the
   inline revoke confirmation that names the link and the other people who keep access, the
   checkbox of D1, and the three messages of D5.
4. **`CONTEXT.md` changes.** "Cut epoch" gains "one step per owner revoke, whatever the number of
   rows". "Write-scope cut" gains the upgrade of D6. "Revocation floor" does not change.
5. **The contact book stops being a trust input.** Revoke and conversion read only the record.
   Amended by ADR 0032 D2 on 2026-09-26: the contact book is no trust input for a grant, and it is a
   match input only for a revoke of a row whose label the owner did not attest.

## Residuals

**E1 — A hostile link holder can read past the deadline until the owner's sweep runs.** Its engine
ignores the deadline. The owner's next sweep cuts the link. An owner who stays offline keeps the
window open.

**E2 — A person who is removed keeps what the person saw.** This is the promise of #25 D4: "they
keep what they saw; they lose everything new, now."

**E3 — A committed write grantee of an enclosing scope can hide a nested scope from the sweep.**
`directChildScopeIndex` is writer-authored and carries no owner signature. The grantee can remove
a nested scope from the index, and its expired links then stay uncut.

**E4 — A cut person who holds another live link rejoins with no owner step.** ADR 0023 E5 states
the bound.

**E5 — A cut link still opens what the holder already has.** ADR 0024 E5 states the bound.

**E6 — A write revoke moves the scope root.** A revoke of a write grantee, a downgrade (D6) and
the D1 checkbox on a write grantee each run a name wave. Every live link on the scope survives only
through the scope pointer path of ADR 0024 D5.

**E7 — A person revoke ends the link for every holder not yet converted.** The revoke also cuts
the link that admitted the person (D4), so the owner must issue a group link again.

**E8 — A public observer sees when links exist and when they expire.** The link kind and deadline
are in the clear, and each deadline causes a rotation. The owner accepted this for the
record-derived design on 2026-09-25.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
