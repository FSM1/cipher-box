# ADR 0060 — A stated refusal from every endpoint supersedes the bin index mint mark

- **Status:** Accepted on 2026-09-29
- **Date:** 2026-09-30
- **Relates to:**
  [ADR 0056](./0056-the-bin-index-mint-mark-is-raised-just-before-the-put-and-a-seal-counter-gives-the-revision.md)
  D1 (the mint counter marks a PUT that left the engine), D2 (the seal counter) and
  consequence 7 (a refused PUT still strands the device),
  [ADR 0031](./0031-the-bin-index-seals-symmetrically-under-a-login-secret-key-and-exists-from-genesis.md)
  D8 (only an established index feeds a rewrite) and D10 (`StrandedMint`),
  [ADR 0034](./0034-a-degraded-settings-load-falls-back-to-the-last-verified-copy-and-never-widens-placement.md)
  D5 (the settings marks), [ADR 0020](./0020-the-durable-op-queue-reads-the-previous-release.md)
  (a build reads the durable state that the previous release wrote), and the
  `blueprint/engine.md` sections "Resolve/publish pipeline" and "Bin index record"
- **Implemented by:** FSM1/cipher-box#2106 (closes FSM1/cipher-box#2096)
- **Amends:** ADR 0056 D1, ADR 0031 D10

## Context

The mint counter marks a PUT that left the engine, whatever its outcome (ADR 0056 D1). When
each routing endpoint refuses the genesis PUT, the counter is the only mark on the device, the
load gives `StrandedMint`, and each soft delete dead-letters. The engine cannot clear the mark
for two reasons: `fanout_put` drops the kind of each failure, and the counter only goes up. The
owner decided on 2026-09-29 that a stated refusal from each endpoint must not strand the device.

## Decision

**D1 — A 4xx answer to a PUT is a stated refusal, and any other answer that is not 2xx is an
unknown outcome.** The `RecordTransport` seam reports the HTTP status of a PUT answer, and the
engine alone classifies it (`net::fanout`, `PutOutcome`). The class rule holds for each hop that
can answer. A 4xx from the endpoint or from a proxy in front of it says that the hop did not act
on the request, so the record did not go on through that endpoint. The delegated routing server
answers 400 or 406 before its routing put and 500 after it, so a 5xx can follow a partial put.
A proxy 502 or 504 can follow a forwarded request. Both hosts follow no redirect, so a 3xx is a
final answer that states nothing. No answer, a timeout, a closed connection, and a seam failure
with no status are unknown outcomes. An answer the engine cannot classify is unknown.

**D2 — Only a PUT that every endpoint refused leaves no mark.** The publish port reports
`AllEndpointsRefused` only when each endpoint of the set gave a stated refusal. One ack, or one
unknown outcome beside any number of refusals, keeps the ADR 0056 D1 rule: the mark stays.

**D3 — A second monotonic value, the refusal counter, supersedes the mint mark at or below
it.** On `AllEndpointsRefused`, `publish_bin_index` raises the refusal counter
(`bin-index-revision-refused/<name>`) to the body revision of the refused PUT. The mint counter
is a mark only while it is above the refusal counter (`record_plane::live_mint`). The load and
`holds_a_bin_index_mark` read both values, and a refusal counter that the store cannot read is
`FloorUnreadable`, never an absent one. A refusal write that fails leaves the mark, which is
the fail-closed side. The mint counter, the seal counter and their keys do not change, so the
next seal still takes one above the seal counter (ADR 0056 D2), and no revision seals two
bodies. A later PUT raises the mint above the refusal and is a mark again.

## Alternatives considered

- **A mark that is a record with a state, in place of the counter.** A state change from
  "sent" to "refused" is a write that lowers a mark. The floor store is monotonic-max by
  contract, so it needs a new seam method that can lower a value, and a lowering write can
  erase a real mark. The previous release's bare counter also needs a migration to the new
  shape.
- **The state in the counter value, for example 2N for a sent PUT and 2N+1 for a refused
  one.** It stays monotonic, but a counter that the previous release wrote then reads as half
  its revision, and the next revision can repeat one that a landed body took (ADR 0056
  consequence 5).
- **The transport classifies the answer.** Three hosts (desktop, the WASM bridge, the browser
  seam) then each carry the policy. The engine owns every fan-out decision
  (`blueprint/engine.md` "Resolve/publish pipeline"), so the seam reports the status only.
- **A refusal from the CipherBox endpoint, or from most endpoints, is enough.** An endpoint
  that did not state a refusal can hold the record, and a new genesis would then publish an
  empty index over it (ADR 0031 D8).
- **A 5xx is also a refusal.** A delegated routing server answers 500 after a partial routing
  put, so the record can be on the network.

## Consequences

1. `blueprint/engine.md` "Resolve/publish pipeline", the Publish bullet, adds D1 and D2 in
   two sentences, and the `RecordTransport` row of the host seam table says that a PUT
   answer carries its status.
2. `blueprint/engine.md` "Bin index record", the first bullet, replaces "a PUT that went out
   keeps its mark whatever its outcome" with D3, and the `StrandedMint` bullet says that the
   mint counter is a mark only above the refusal counter.
3. ADR 0056 D1 and ADR 0031 D10 carry an "Amended by" sentence.
4. One new key prefix in the sequence namespace of the floor store,
   `bin-index-revision-refused/`. A mint counter that the previous release wrote has no
   refusal counter beside it, so it still reads as a mark (ADR 0020). A previous build that
   reads state from this build ignores the refusal counter and reads `StrandedMint`, the
   restrictive side.
5. `blueprint/engine.md` "Retirement": the head block of a refused publish stays charged, and
   ADR 0047 D4 applies, because an endpoint that states a refusal can keep the record.
6. The vault settings plane keeps its mint counter and its mark rule (ADR 0034 D5), so no PUT
   outcome clears a settings mark.
7. `CONTEXT.md` does not change. No wire format, KDF edge or KAT vector changes.
8. A hostile or broken endpoint can state a refusal and keep the record. The device has no
   adopted record, so the retry is built from the same base and carries every entry of the
   kept body. If the endpoint later serves the kept body, the confirm reads a tie as a lost
   race, and the device is in the `StrandedMint` state of today. No entry is lost. The owner
   accepted it on 2026-09-29.
9. A process stop between the mark write and the PUT leaves a mark with no PUT. D3 does not
   cover it, and no change follows now. The owner accepted it on 2026-09-29.
