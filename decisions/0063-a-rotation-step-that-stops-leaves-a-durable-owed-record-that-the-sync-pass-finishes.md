# ADR 0063 — A rotation step that stops leaves a durable owed record, and the sync pass finishes it

- **Status:** Accepted on 2026-10-01
- **Date:** 2026-10-01
- **Relates to:** `blueprint/engine.md` "Rotation primitives" (rotateScopeWrite, Triggers),
  "Grants and ledger" and "Host seams", `blueprint/core.md` owner-local kind registry, the
  `CONTEXT.md` terms "Name wave", "Write-scope cut", "Forgery window", "Cut epoch" and "Sync pass",
  [ADR 0006](./0006-owner-local-sealed-store.md),
  [ADR 0020](./0020-the-durable-op-queue-reads-the-previous-release.md),
  [ADR 0025](./0025-revocation-under-the-link-first-model.md),
  [ADR 0026](./0026-a-scope-root-takes-many-grants.md) D1, and
  [ADR 0061](./0061-a-renewal-walk-over-every-owned-scope-renews-each-name-through-the-adoption-gate.md),
  FSM1/cipher-box#1923, FSM1/cipher-box#2123, FSM1/cipher-box#2124, FSM1/cipher-box#2134
- **Implemented by:** FSM1/cipher-box#2159 (the staging prefix, consequence 7) and FSM1/cipher-box#2165
  (D1 to D5, consequences 1 to 6 and 8)
- **Amends:** ADR 0061 D3 step 2 (the names the walk skips)

## Context

An owner rotation runs in steps: a cut set publish, a read cut, a write cut with its name wave, a
promotion and its interior move. Each step publishes on its own. When a step stops part of the
way, no durable record says that work is still owed, so nothing finishes it. A write revoke then
leaves the revoked writer with a live write seed (FSM1/cipher-box#1923, FSM1/cipher-box#2123). A
promoted scope whose write-scope cut did not run lapses, because the renewal walk holds no seed
that derives its names (FSM1/cipher-box#2124). A stalled interior move strands its nodes once the
parent sweep repairs the index (FSM1/cipher-box#2134). The scope-exit debt (owner-local kind
`0x06`) already solves this shape for the grantee read cut. The owner decided on 2026-09-30:
one durable local owed-work record, which the engine retries from the sync pass and at cold start.

## Decision

**D1 — One owner-local kind, `owed-rotation` (`0x0a`), holds all owed owner rotation work.** One
record for each identity, under the owner-scoped staging key, as the scope-exit debt has. Each entry
keys on the scope id. It holds the cut epoch of the published cut that it finishes, and the steps
still owed, in the order that the command runs them: a read cut, a write cut, an interior move (with
the scope that the folder left), and the delivery of a grant. An entry holds no seed and no key. A
re-drive recovers an in-flight write seed from the published records (`recover_wave`), and refuses a
resume that targets another write epoch. A re-drive that finds a step already landed clears it and
cuts nothing again. The scope-exit debt stays its own kind.

**D2 — The entry is durable before the first publish that can leave work owed, and it clears
only after the last step.** The first publish is the cut set publish of a revoke or a downgrade,
or the promotion publish of a grant or a link mint. The last step includes the cut-epoch floor
record, the write-epoch floor raise, and the index re-point. The record advances as each step
lands. When the staging store refuses the entry, the command stops with `Err` before any publish.

**D3 — Each sync pass re-drives every owed entry after the drain, and the first pass of a session
does this before the renewal walk.** The re-drive runs the steps still owed, then the post-steps of
D2. The interior move re-drives through the resume path of a grant (`resume_grantee_scope`) against
the promoted root, so an append (ADR 0026 D1) stays an append. The delivery of a grant re-drives
after its other steps land, so a share that returned `Ok` under D5 still reaches its recipient. A
failure keeps the entry and sends `Event::RotationWorkOwed` with the scope root, a key-material-free
check, and whether a retry can clear it.

**D4 — The renewal walk renews no name in a scope that has an owed entry.** Such a scope has names under a
seed that a revoked writer still holds, or names that no current seed derives. The finished work republishes
every name of the scope at a fresh EOL, and that is the renewal of the scope. While the owed record of the
device does not open, the walk renews every name, and its report names the unread record for each scope at
each pass. It still signs no name under a seed that does not derive it (ADR 0061 D4): the cause is local,
and a revoked writer already holds each seed from before the cut, so the renewal gives no new access.
Amended by ADR 0065 D4 on 2026-10-02: after the bound of ADR 0065 D3, the walk renews in an owed
scope each name that the scope root's current write seed derives.

**D5 — After its first publish, a command whose step stops returns `Ok`, and the work is owed.**
The published cut cannot be taken back, so `Err` would state that the command did not run. The
engine sends `Event::RotationWorkOwed` at once and on each pass while the entry stands. The same
command on the same scope while its entry stands re-drives the entry. It does not report
`rot-revoke-not-granted`. A failure before the first publish returns `Err` and leaves no entry.

## Alternatives considered

- **Derive the owed work from the published state on each pass.** Every owner device could then
  finish the work. But each pass must probe every owned scope over the network, each work type
  needs its own probe, and the interior-move probe reads every interior node. The owner rejected
  it on 2026-09-30.
- **One owner-local kind for each work type.** The steps of one scope have an order, and three
  kinds give three records that can disagree about it. They also add three rows to the kind
  registry and to the cross-kind KAT.
- **Fold the scope-exit debt into the new kind.** The scope-exit debt is a flat read cut with its
  own settle rule, and a device writes it for a scope that it does not own. A fold also needs a
  migration of the `0x06` records (ADR 0020 D3), for no gain.
- **Keep the in-flight write seed in the entry.** A re-drive then needs no network read, but a seed
  lives in the staging store. The resume already reads it from the published records.
- **Return `Err` when a step stops.** The host then shows a failure for a cut that is published,
  and a retry of a revoke finds no grant row.
- **Renew a promoted scope under the enclosing scope's write seed (FSM1/cipher-box#2124).** The
  walk then signs under a seed that does not derive the scope root's name, which ADR 0061 D4
  refuses.
- **Finish a stranded interior move in `append_share`, in the granted-scope sweep, or by a parent
  sweep that does not repair the index** (FSM1/cipher-box#2134 options 1, 3 and 4). The first
  waits for a second share. The second widens what the granted-scope sweep admits. The third
  removes the index repair that the link flow uses.

## Consequences

1. `blueprint/engine.md` "Rotation primitives" states D1 to D5. "rotateScopeWrite" replaces "stays
   incomplete and resumable" with the owed entry. "Triggers" names the re-drive of D3. "Host
   seams" names `owed-rotation` on the `StagingStore` seam.
2. `blueprint/engine.md` "Grants and ledger" states that a stalled interior move is owed (D1, D3),
   and "Residuals" bounds the forgery window by the next sync pass on the device that started the
   cut, not by the wave alone.
3. `blueprint/core.md` adds `owed-rotation` (`0x0a`, after `renewal-cursor` `0x09`) to the
   owner-local kind registry and to the KAT set: one populated accept body, and a cross-kind
   reject for each ordered pair.
4. `CONTEXT.md` adds the term "Owed rotation work", and "Forgery window" states the bound of
   consequence 2.
5. ADR 0061 D3 step 2 carries an "Amended by ADR 0063 D4" sentence.
6. `blueprint/engine.md` "Sharing residuals" states the cost of a local record: only the device
   that holds the entry re-drives the work. On another owner device, a revoked writer keeps the
   old write seed until the first device runs a pass, and an owner action runs a write-scope cut
   from the published state. When the first device is lost, a revoke and an interior move stay
   owed for ever. A manual "rotate write keys now" action, which any owner device runs from the
   published state, was built on 2026-10-05: `RotateWriteNow` runs one write wave on any owner
   device, below the vault root, by the re-drive of that device's own entry or by a new cut. Work
   owed before the cut refuses retryably; a wave that stops after the cut set lands is owed (D5).
7. `blueprint/deploy.md` "Release management" states the two-step landing of ADR 0020: the new
   staging prefix enters the orphan-sweep bookkeeping list (`is_bookkeeping`) one release before
   the first entry is written, so a one-release rollback keeps the record.
8. `blueprint/engine.md` "Rotation primitives" states an event that the renewal walk sends when it
   meets an owned scope root whose name its write seed does not derive, so any owner device shows
   a write cut that did not finish.

## Residuals

None.
