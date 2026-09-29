# ADR 0056 — The bin index mint mark is raised just before the PUT, and a seal counter gives the revision

- **Status:** Proposed
- **Date:** 2026-09-29
- **Relates to:**
  [ADR 0031](./0031-the-bin-index-seals-symmetrically-under-a-login-secret-key-and-exists-from-genesis.md)
  D2 (a fresh nonce from the entropy seam for each seal), D3 (a failed draw fails the publish
  closed), D7 (the genesis publish and the durable marks), D8 (only an established index feeds a
  rewrite), D10 (`StrandedMint`) and E4 (a failed first publish strands a device),
  [ADR 0007](./0007-derived-idempotent-first-run-mint.md) (the derived first-run terms),
  [ADR 0034](./0034-a-degraded-settings-load-falls-back-to-the-last-verified-copy-and-never-widens-placement.md)
  D5 (the three settings marks that refuse the first-run defaults), the
  `blueprint/engine.md` sections "Vault settings load" (the per-attempt body revision) and "Bin
  index record", and the `CONTEXT.md` term "Bin index"
- **Implemented by:** FSM1/cipher-box#2090 (closes FSM1/cipher-box#2035)
- **Amends:** ADR 0031 D7, D10 and E4, and its Context paragraph "The stranded mint"

## Context

`publish_bin_index` raised the durable mint counter before it drew the nonce, sealed, uploaded
the head block, registered the name and sent the PUT. A failure at any of those steps left the
counter as the only mark on the device, so a single failed step at genesis stranded the device
for good (ADR 0031 E4). The owner ruled on 2026-09-26 that the mint counter must mark only a PUT
that can have landed. The counter did two jobs: it gave each seal its body revision, and it was
the durable mark that a load reads when no record resolves. The two jobs need different moments.

## Decision

**D1 — On the bin index plane, the mint counter marks only a PUT that left the engine.** The
publish port raises the mint counter (`bin-index-revision-mint/<name>`) to the body revision
after register-first, the sequence floor read, the signature and the size check, directly before
the PUT (`PutMark` in `net::publish`). If the store does not take the mark, or reports a value
below it, the publish stops with `PublishError::MarkUnrecorded` and no PUT goes out. A failure
before the mark leaves no mark, so the next session start publishes the genesis record again. A
PUT that went out keeps its mark whatever its outcome (consequence 7). Mark before PUT is the fail-closed order: a PUT never lands without a
mark, so a withheld record never reads as a first run on the device that sent it.

**D2 — A separate owner-local seal counter gives the body revision.** The seal counter
(`bin-index-revision-seal/<name>`) is raised before each seal. The next revision is one above the
highest of the seal counter, the mint counter and the adopted revision (`floor::mint_revision`).
The seal counter is not a mark: no load reads it. So each seal takes a revision that no other
body took, also after a failure between the seal and the PUT, and a mint counter that the
previous release wrote still bars the next revision.

## Alternatives considered

- **Keep one counter, raised before the seal.** This was the state before FSM1/cipher-box#2090.
  Every failure after the raise leaves a mark, so one failed upload, registration or entropy
  draw at genesis strands the device (ADR 0031 E4).
- **Read the next revision without a write, and persist it only just before the PUT (ADR 0031
  E4).** It leaves no mark on a failure before the PUT, as D1 does. But a failure after the head
  block upload and the registration gives the same revision to the next body, while the failed
  body's head block can already stand on the content plane. The blueprint rule that each attempt
  mints its own revision then no longer holds. D2 keeps that rule at the cost of one more
  durable key.
- **Raise the mark after the PUT.** A PUT can land and the mark write can then fail or never run.
  With no mark, a withheld record reads as a first run, and the device publishes an empty index
  over the landed one. The index is rewritten whole, so that publish drops every entry.

## Consequences

1. `blueprint/engine.md` "Bin index record" states D1 and D2 once in a new first bullet, and
   its opening paragraph names the mint counter and the revision as differences.
2. `blueprint/engine.md` "Bin index record", the `StrandedMint` bullet, says that the mint
   counter alone proves a PUT that left the engine.
3. ADR 0031 Context, D7 and D10 carry an "Amended by" sentence, and ADR 0031 E4 narrows to
   consequence 7 and E1 below.
4. The decision is for the bin index plane only. The vault settings plane keeps its mint counter
   raised before the seal: its first-run defaults name `PinMode::Hosted`, so a placement choice
   that never landed must still refuse them (ADR 0034 D5), and a mark raised after the head
   upload and the register, which the API answers, would let a hostile API erase that choice.
5. The value format and the key of the mint counter do not change. A counter that the previous
   release wrote still reads as a mark.
6. One new key prefix in the sequence namespace of the floor store, `bin-index-revision-seal/`.
7. A PUT that each routing endpoint refused or did not answer keeps its mark, so the device is
   in the stranded state. The owner decided on 2026-09-29 that a stated refusal from each
   endpoint must not strand the device; that change is not landed, and it needs its own ADR,
   because it changes the durable shape of the mark.
8. The nonce is drawn before the revision, so an entropy failure (ADR 0031 D3) uses no revision.
9. `CONTEXT.md` does not change. No wire format, KDF edge or KAT vector changes.

## Residuals

**E1 — A device that the previous release stranded stays stranded.** Its mint counter is a mark,
and the counter cannot show whether its PUT went out. The member can hard-delete or sign in on a
second device. The owner has not decided whether this state is accepted or needs a recovery
path.
