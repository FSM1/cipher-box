# ADR 0047 — A failed or abandoned publish retires exactly what it charged

- **Status:** Accepted on 2026-09-26 — retroactive; the rule shipped in FSM1/cipher-box#923,
  FSM1/cipher-box#944, FSM1/cipher-box#1046 and FSM1/cipher-box#1862, and the blueprint carries
  it; the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows; trimmed on 2026-09-26 to the items that pass
  the three ADR hurdles — the removed items live in the blueprint
- **Date:** 2026-09-26
- **Relates to:**
  [#34](https://github.com/FSM1/cipher-box-next/issues/34) D2 (register-first, fail-closed), D3
  (per-account rows, union liveness) and D4 (retire = remove my row; the timing is client
  policy), [#24](https://github.com/FSM1/cipher-box-next/issues/24) D6 (coverage is structural;
  retirement is inventory removal), [#33](https://github.com/FSM1/cipher-box-next/issues/33) D6
  (a dead letter keeps its staged bytes),
  [#26](https://github.com/FSM1/cipher-box-next/issues/26) D6 (a fresh random content key per
  version),
  [ADR 0007](./0007-derived-idempotent-first-run-mint.md)
  D4 (the accepted one-head-block crash leak),
  [ADR 0011](./0011-quarantine-release-rests-on-the-doomed-manifest.md)
  D4 and its Context (no pass that journals an entry may decide it),
  [ADR 0019](./0019-file-version-retention-is-count-based-keep-latest-n.md)
  D3 and D4 (a retained version stays referenced by its own entry),
  [ADR 0046](./0046-the-registry-counts-references-per-record-and-caps-every-batch-at-1000.md)
  D1, D2 and E4 (the per-record reference count, the two retire forms, and why these retires use
  the account-wide form), the decision of 2026-08-20
  on FSM1/cipher-box#1226 (a spent attempt budget keeps the bytes), the `blueprint/engine.md`
  "Resolve/publish pipeline" section ("Retirement" bullet), the "Content plane" section
  ("Referenced equals kept" bullet) and the "Sync core" dead-letter paragraph, the
  `blueprint/api.md` "Pin/name registry" section ("Batch bounds", "Register-first,
  fail-closed" and "Per-referencing-record refcount"), and the `CONTEXT.md` "Register-first",
  "Union liveness", "Dead-letter" and "Version history" terms
- **Implemented by:** FSM1/cipher-box#923 (the abandoned op retires every charged block, D1 and
  D2), FSM1/cipher-box#944 (the per-attempt orphaned-head retire, D3 and D4),
  FSM1/cipher-box#1046 (the same retire for the vault settings publish),
  FSM1/cipher-box#1762 (a name wave carries every version's root and leaves to the new name, D5)
  and FSM1/cipher-box#1862 (retained roots register again on each publish, D5).

## Context

Every block that a publish uploads is its own charged pin row, which the quota gate counts. A
record publish uploads its head block through the same charged ingress, and each retry authors a
new head under a fresh seal nonce. Before FSM1/cipher-box#944, no path retired an orphaned head,
so an op that retried three times and then succeeded leaked three charged heads. The retire is
destructive: the registry unpins a CID when its global reference count reaches zero. An op whose
record PUT was acknowledged may already be resolvable at its name, so a retire there turns a quota
leak into content loss. A fan-out that no endpoint acknowledged does not prove that no endpoint
stored the record. A retained file version must stay referenced, or orphan GC collects its root,
and the drop of a version cannot be undone.

## Decision

**D2 — An op whose record PUT was acknowledged retires nothing.** The record may be resolvable at
its name. Unpinning content that a live record still references is loss, and leaving the rows
charged is only a leak. So a spent attempt budget on an acknowledged-but-unconfirmed publish
(`Halt::Attempt`) dead-letters the op and retires neither the name nor a block. An unattributable
upload refusal, which fails before any PUT, is a separate halt, `Halt::UploadAttempt`.

**D3 — A publish that fails before its record reaches the transport retires its head block, on
each attempt.** Such a failure leaves a head block that is already uploaded and charged, and no
record can name it. The retry authors a new head under a fresh seal nonce, so the old head is
permanently unreachable. The qualifying failures are exactly those that `orphaned_head`
(`crates/engine/src/net/retire.rs`) names, and it matches every publish error variant
exhaustively, so a new variant does not compile until someone classifies it. The engine retires
the pending set at the end of the pass that orphaned it, independent of the op's fate: an op that
later succeeds still retires what its failed attempts charged. The pending set (`OrphanHeads`) is
session-lived and capped at 1000 entries. In the drain, a head that the live held set still names
never enters it. The vault settings publish and the bin index publish use the same predicate.

**D4 — A fan-out that acknowledged nothing does not qualify under D3.** `AllEndpointsFailed` says
that no endpoint acknowledged the PUT. It does not say that no endpoint stored the record. A lost
ack can leave a record resolvable at the name that points at this head, and D2's reason applies.

**D5 — Each publish of a file registers every retained version's root again under the file's own
name, and a dropped version's debt is journaled before the shortened history publishes.** A
write-rotation name wave registers every version's root and leaves at the node's new name before
the record moves. A version that falls outside the retention rule loses its reference, and what it
owes the registry goes to the durable retire ledger first. A debt that the ledger does not take
leaves the history standing, and the pass publishes no shortened history. This is the mechanism
behind ADR 0019 D3: the entry is the reference, and the re-registration is how the registry
learns it.

Item D1 moved to `blueprint/engine.md` "Resolve/publish pipeline" ("Retirement" bullet) and
`blueprint/api.md` "Pin/name registry" on 2026-09-26.

## Alternatives rejected

- **Route the whole attempt arm through the abandonment (D2).** The arm included the
  acknowledged-but-unconfirmed publish, so the change would unpin a version that a live record may
  name. The arm was split instead.
- **Keep a durable per-op list of every head the op minted, and retire it at abandonment (D3).**
  It misses an op that retries and then succeeds, and it needs a new staging key, a format tag and
  a pruning pass. The per-pass retire covers strictly more.
- **Re-PUT the bytes of the earlier attempt instead of authoring a new head (D3).** Reuse needs
  durable record bytes and a publish plan pinned across passes. The drain re-derives its plan from
  the current gate-passing base on each pass, so this is a change to the publish pipeline.
- **Retire the head on `AllEndpointsFailed` (D4).** A lost ack leaves a resolvable record that
  names the head, so the retire would make that node unreadable.
- **Keep a retained version by a separate reference count on its root (D5).** ADR 0019 rejected
  this. The version's entry in the read-body is the reference.

## Rationale

- **D2, D4:** a retire too few is a bounded leak, and a retire too many is a loss that no later
  pass can undo, so the engine keeps a row that a live record may name.
- **D3:** a failure before the transport means that no record names the head, and the fresh nonce
  means that no later record of this op names it; a per-pass retire needs no new durable format.
- **D5:** the entry is the reference and the re-registration tells the registry; journal first
  makes the drop crash-safe.

## Consequences

1. `blueprint/engine.md` "Resolve/publish pipeline" ("Retirement") and "Content plane"
   ("Referenced equals kept") carry every item, kept and moved.
2. `blueprint/api.md` "Pin/name registry" carries the batch cap and the retire forms, and
   `CONTEXT.md` "Register-first" and "Version history" define the rows the retire removes.
3. ADR 0007 D4 reads more narrowly: the D3 path does not reach a process that dies between the
   head upload and the record PUT, so the accepted one-block crash leak stays leaked.
4. ADR 0019 D3 reads with D5 as its mechanism.

The **Rust** gate and the `Contract Suite` gate block the merge.

## Residuals

**E1 — The blueprint does not say which exits are an abandonment.** In the code, a permanent
refusal and a terminally unrebasable op retire the whole set (`Drain::abandon`). A spent attempt
budget on a failure before the transport is not one of them. The decision of 2026-08-20 on
FSM1/cipher-box#1226 made it a dead letter that keeps its version and every row it charged. A
spent budget on `Halt::UnwritableScope`, and a spent unattributed budget, keep the version, the
name and every row. The "Retirement" bullet does not carry these carve-outs. The owner should
decide whether the carve-outs join this ADR as a Dn and the "Retirement" bullet.

**E4 — An acknowledged PUT that never becomes live leaks everything it charged.** D2 keeps the
name, the head and every content row of such an op, and no later pass learns that the record
never landed. The attempt budget per op bounds the cost.

**E5 — A version whose root the name wave cannot fetch carries its root alone.** Its leaves lose
their reference edges when the old name retires. They stay pinned only because the registry
deletes a pin row only for a CID that the batch names as a target (ADR 0046 D1). If that registry
behaviour changes, this case turns from a lost edge into a lost pin.
