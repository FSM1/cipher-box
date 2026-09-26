# ADR 0046 — The registry counts references per record and caps every batch at 1000

- **Status:** Accepted on 2026-09-26 — retroactive; the rule shipped in FSM1/cipher-box#848,
  FSM1/cipher-box#898, FSM1/cipher-box#923, FSM1/cipher-box#946 and FSM1/cipher-box#1578, and the
  blueprint carries it; the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-26
- **Relates to:**
  [#24](https://github.com/FSM1/cipher-box-next/issues/24) D2 and D3 (the republisher walks a
  name inventory, and the API serves no record) and D6 (coverage derives from pin registration),
  [#34](https://github.com/FSM1/cipher-box-next/issues/34) D2 (the incremental batch registry,
  register-first), D3 (per-account rows, union liveness), D4 (retire removes my row, and timing is
  client policy) and the table list of its resolution, ADR 0011 (the reclaim rests on the owner's
  doomed manifest), ADR 0012 D4 and D6 (a charged verdict spends a bounded attempt budget, and a
  strict-FIFO stall with no dead letter is a defect), ADR 0019 (count-based version retention),
  ADR 0038 D4 and E3 (the `UPLOAD_TOO_LARGE` 413, and the upload 400 that carries no code), the
  `blueprint/api.md` sections "Pin/name registry" and "Data model (complete)", the
  `blueprint/engine.md` sections "API client" and "Resolve/publish pipeline" ("Retirement"), the
  `blueprint/testing.md` section "The contract suite — the live API gate", and the `CONTEXT.md`
  terms "Name inventory", "Register-first", "Union liveness" and "Dead-letter"
- **Implemented by:** FSM1/cipher-box#848 (the two 413 codes), FSM1/cipher-box#898 (the 413
  classification), FSM1/cipher-box#923 (the batch cap in the blueprint and the chunked retire,
  D3), FSM1/cipher-box#946 (the split registration and the register refusal code, D3 to D5), and
  FSM1/cipher-box#1578 (the reference rows, the retire shape and the exposure, D1, D2 and D6).

## Context

The registry is the one API surface that every publish flow crosses. It feeds the quota and the
republisher inventory (#24 D6, #34 D2). Four defects shaped the rules in this ADR.

**The batch had a cap that no client respected.** The registry refused a retire array over
`MAX_BATCH = 1000` with a 400 before any database work, and the controller published the cap as
`maxItems`. The blueprint did not state it. FSM1/cipher-box#916 found that an abandoned version
retired its root only, so every leaf it had uploaded stayed charged against the quota. The fix,
FSM1/cipher-box#923, retires the whole block set. A version at the flat DAG ceiling has tens of
thousands of leaves, so the retire had to be bounded. The issue weighed two options: chunk on the
client, or give the endpoint a limit. The limit already existed. FSM1/cipher-box#923 wrote it into
the blueprint and made the engine's retire chunk to it at one chokepoint (`net::retire`).

**The registration crossed the per-entry cap and stalled the queue.** The register endpoint caps
`contentCids` at 1000 for each entry. The engine sent one entry with the version root and every
leaf. At the production framing a file over about 1 GiB has more than 1000 leaves, so the registry
refused its registration (FSM1/cipher-box#920). The drain classified the 400 as unclassified. It
charged nothing and retried on each tick. The queue is strict FIFO, so the op held the head for
ever, and each pass uploaded and registered again. FSM1/cipher-box#946 split the registration
into several entries under one name, and made a refused registration dead-letter.

**A permanent verdict needs positive evidence.** The upload route answers 413 for two causes that
need opposite treatment: the transport cap, which is permanent for the body, and the quota gate,
which clears when the account frees space. FSM1/cipher-box#848 gave each cause a stable `code` in
the body. FSM1/cipher-box#898 then made the drain classify a 413 on that code only. A proxy body
cap also answers 413, with an HTML body and no code, and it did not inspect the bytes. A dead
letter for an abandoned op retires the op's registry rows and releases its staged ciphertext, so
a dead letter on an intermediary's answer destroys a queued write. FSM1/cipher-box#946 applied the
same rule to the register 400: the batch gate stamps its own code, and a 400 without it is not
evidence.

**A doomed root could unpin a live leaf of another node.** The registry held one pin row for each
`(account, cid)`, so a retire dropped the account's whole claim on the CID. A DAG root is
plaintext, so a write-grantee in a shared scope can read the leaf CIDs of the owner's file B and
publish a version of file A whose links are those leaves. When the owner's device prunes that
version of A, it retires B's leaves under the owner's own token, and the bytes unpin at global
refcount zero (FSM1/cipher-box#1176, residual 1). No client can decide this case. A `Version`
carries no author binding, and a sealed leaf carries no AAD that binds it to a root. An IPNS read
answers "the newest record that reached me", never "nothing newer exists", so a client has no
linearization point. Two client-side account-wide designs failed review on FSM1/cipher-box#1289.
Only the registry holds an account-wide live view and a lock that orders register against
retire. On 2026-08-31 the owner decided that residual 1 lands as a per-referencing-record pin
row in `apps/api`. FSM1/cipher-box#1578 implemented it and chose the retire shape, the target cap
and the exposure statement.

`blueprint/api.md` carries the rules in the section "Pin/name registry", in the bullets
"Endpoints", "Batch bounds", "Per-referencing-record refcount" and "Accepted exposure", and in the
section "Data model (complete)".

## Decision

**D1 — The registry counts references per referencing record.** A register call writes one
reference row `(account, ipnsName, cid)` for each CID that an entry names, the head CID included.
The account's pin row `(account, cid, size)` stays while any record of the account still names
the CID. A retire entry that carries an `ipnsName` drops only the references of that record. A
retire of a name drops every reference that the name anchored. A retire drops the pin row of a
target CID only when no record of the account still names that CID: `RegistryService.retire`
deletes a pin row only for a CID that the batch names as a target. So when a name retire drops
the last reference to a CID that no target of the batch names, the pin row of that CID stays
until a later retire names the CID as a target. The physical unpin still
waits for global refcount zero across accounts, so union liveness does not change. Every
reference read and write runs in the transaction that holds the per-token advisory lock of the
pin rows, and the lock set covers each entry's `ipnsName` as well as its targets. This makes the
registry the linearization point for the question "does any record of this account still name
this CID". The rule was decided on 2026-08-31 in FSM1/cipher-box#1176 and landed with
FSM1/cipher-box#1578 (`apps/api/src/registry/services/registry.service.ts`,
`apps/api/src/registry/entities/pin-reference.entity.ts`).

**D2 — Retire takes `[{ipnsName?, targets[]}]`, and the batch caps its total target count at 1000.** Each target is an `ipnsName` or a CID. The API does not know which, so it removes the
caller's matching row from both tables; the two namespaces do not collide. An entry with an
`ipnsName` is record-scoped: its targets are CIDs that the record stops naming, and it never
removes a name row. An entry with no `ipnsName` drops every reference of the account to each
target, and it is the only form whose targets can name a record to retire. That is the
account-wide path that an orphaned head block and a name wave need. The batch caps the total
target count across all entries at 1000, so a batch split into more entries buys no more work.
Each target is at most 256 characters. A retire is idempotent: a target that is already gone is
a no-op. The rule landed with FSM1/cipher-box#1578; this ADR records it.

**D3 — Both batches cap at 1000 entries, a register entry caps `contentCids` at 1000, and a
refusal is a whole-batch 400.** The register batch and the retire batch each take at most 1000
entries. The API refuses an over-cap batch with 400, fail-closed: it writes no row, and it never
truncates or partly applies the batch. The API enforces the caps before the per-item validation
(E2 records where the code differs). The caps are published as `maxItems` in the OpenAPI document.
A bulk caller, such as a name wave or an abandoned version whose leaves all need retiring, chunks
to the cap. The engine owns the chunking in `crates/engine/src/net/register.rs` and
`crates/engine/src/net/retire.rs`, against one shared constant, `REGISTRY_BATCH_MAX`. Because a
retire is idempotent, a replayed chunk is a no-op. The cap predates FSM1/cipher-box#923.
FSM1/cipher-box#923 wrote it into the blueprint and made the retire chunk, and
FSM1/cipher-box#946 made the registration chunk; this ADR records it.

**D4 — A version past the per-entry cap registers as several entries under one `ipnsName`.** The
head rides the first entry. Each continuation entry omits `headCid`. The server collapses the
entries of one name to one name row. A register entry without `headCid` leaves the stored head
unchanged. An explicit `headCid: null` is refused with the batch-gate 400, because it would clear
the stored head and a continuation entry cannot express that. Register-first still holds: every
chunk lands before the record PUT, and the PUT waits for all of them. The rule landed with
FSM1/cipher-box#946; this ADR records it.

**D5 — The engine dead-letters a registry or upload refusal only when the refusal carries the
gate's own code.** The registry batch gate stamps `code: REGISTRY_BATCH_REFUSED` on every 400 it
answers, over-cap or malformed. The upload transport cap stamps `code: UPLOAD_TOO_LARGE` on its
413 (ADR 0038 D4), and the quota gate stamps `code: QUOTA_EXCEEDED` on its 413. The drain reads
these codes as follows (`classify_register` and `classify_upload` in
`crates/engine/src/sync/drain.rs`):

- A register 400 with `REGISTRY_BATCH_REFUSED`, or an upload 413 with `UPLOAD_TOO_LARGE`, is
  permanent. The op dead-letters with the reason `PayloadRefused` on the first answer.
- An upload 413 with `QUOTA_EXCEEDED` holds the queue head as blocked. It is not a failure.
- A 400 or a 413 that carries neither code is not evidence of a permanent verdict. It is charged
  one attempt against the attempt budget, and the op dead-letters as `AttemptsExhausted` only
  when the budget is spent. Every other answered status, a 5xx included, is charged the same way.
- A 429, a 401 and a 403 judge the caller, not the bytes, so they are never charged against the
  attempt budget. They count against the separate `UNATTRIBUTED_BUDGET` of 120 halted passes
  instead, and that budget also ends in an `AttemptsExhausted` dead letter when it is spent.

The upload codes landed with FSM1/cipher-box#848, the 413 rule with FSM1/cipher-box#898, and the
register code and its rule with FSM1/cipher-box#946; this ADR records them.

**D6 — The registry holds the name-to-CID association durably, and this exposure is accepted.**
The server already reads each account's names and CIDs on every register. The reference rows make
that association durable. The server can therefore count the content set of each record and see
which CIDs two records share. It still sees no tree structure and no kinds. A reference row holds
a random row id, an account id, an IPNS name and a CID, and nothing else. It
goes with its retire and with the account's hard delete. The rule landed with
FSM1/cipher-box#1578; this ADR records it.

## Rationale

- **Only the registry can decide an alias.** The client has no author binding on a version, no
  AAD that binds a leaf to its root, and no linearization point on an IPNS read. The registry
  has the account-wide view and the lock (D1). A record-scoped retire cannot remove a reference
  that another record holds, whoever authored the doomed root.
- **A fault costs a leak, never a loss.** A reference that the client fails to drop keeps a pin
  row, which is a quota leak. A reference dropped by mistake cannot unpin a CID that another
  record of the account still names. The engine keeps its own subtraction of the node's live
  CIDs as defence in depth.
- **Each request does bounded work.** The caps of D3 and the total-target cap of D2 bound the
  statements of one call. The retire reads the touchable references once and deletes them in one
  statement, so the cost does not grow with the number of entries. Bulk writes slice under the
  Postgres bind-parameter ceiling.
- **Fail-closed keeps register-first true.** A partly applied registration could let a publish
  go out with part of its CIDs unregistered. A truncated retire would leak silently. A
  whole-batch 400 does neither.
- **The split registration keeps one name row and one head.** The head rides the first entry and
  a continuation entry cannot move it (D4), so a chunked registration and a single one leave the
  same state.
- **A permanent verdict rests on positive evidence.** A dead letter destroys the queued write.
  An intermediary that answered 400 or 413 did not inspect the bytes, so its answer cannot
  justify that. The attempt budget still ends the op, so no refusal stalls the strict-FIFO queue
  (ADR 0012 D6).
- **The exposure is small and stated.** The server already saw every name and CID on each
  register. D6 adds duration, not new values.

## Alternatives rejected

**(a) An account-wide live view built on the client from the base snapshot.** Rejected in the
review of FSM1/cipher-box#1289. The base holds no projected counts at cold start, so the view is
empty on the pass most likely to hold a debt. It is fail-open.

**(b) A no-cache walk of every record in the vault before a retire.** Also rejected on
FSM1/cipher-box#1289. It is O(vault) on every pass that holds a debt, and one version root that no
source serves, which any write-grantee can author, stops all reclaim for the account.

**(c) The owner's doomed manifest with a settle-time liveness check as the fix for the alias.**
The comment of 2026-08-26 on FSM1/cipher-box#1176 first held that this pair covered residual 1. The
analysis on the same date showed that the check reads one node, and the alias is across nodes.
The decision of 2026-08-31 replaced it. The pair stays for what ADR 0011 decides.

**(d) Prove provenance by opening each leaf under the doomed version's content key.** It needs a
full download of every pruned version on the settling pass, leaf by leaf, because a crafted root
can put one honest leaf first.

**(e) Register every retained version's leaves again on each publish.** Proposed on
FSM1/cipher-box#920. It grows the registration from O(leaves) to O(versions × leaves), so a small
file with a few versions crosses the per-entry cap, and before D1 it bought no durability.

**(f) Classify every register 400 as permanent.** Any proxy 400 would then destroy a queued write
on sight (FSM1/cipher-box#946).

**(g) Leave a register 400 unclassified.** This was the state before FSM1/cipher-box#946. The op
held the queue head for ever.

**(h) Cap the retire batch on its entry count alone.** An entry carries a target list, so the
entry count bounds nothing (FSM1/cipher-box#1578).

**(i) Let an explicit `headCid: null` clear the stored head.** A continuation entry omits the head
to keep it, and no entry could then express both intents without ambiguity
(FSM1/cipher-box#946).

## Consequences

1. **`blueprint/api.md` already carries D1 to D4 and D6.** The section "Pin/name registry" states
   them in the bullets "Endpoints", "Batch bounds", "Per-referencing-record refcount" and
   "Accepted exposure", and "Data model (complete)" lists `pin_references`. The "Batch bounds"
   bullet also carries the registry half of D5. No text change is needed.

2. **`blueprint/api.md` section "Content plane" and ADR 0038 D4 carry the upload half of D5.** The
   bullet "One request, one block" states the permanent 413. It does not name the code, which ADR
   0038 D4 records. No text change is needed.

3. **`CONTEXT.md` needs no change.** "Union liveness" still reads true: physical unpin fires at
   global refcount zero. The reference row is a layer under the account's pin row, and the
   glossary has no term for either row. "Register-first" and "Name inventory" do not change,
   because a record-scoped retire never removes a name row.

4. **The #34 decisions read as extended, not changed.** Under this ADR, #34 D3 reads: the
   account's pin row stays while any record of the account still names the CID. #34 D4, "retire =
   remove my row", reads: a retire removes my record's references, and a retire that targets the
   CID removes my row when it drops the last of them. The #34 table list gains `pin_references`,
   which `blueprint/api.md` already lists.

5. **ADR 0019 does not change.** Its rejected alternative is a client-side reference count on a
   content root for retention. D1 is a registry count for reclaim safety, and retention stays
   count-based on the version entries.

6. **`blueprint/engine.md` section "API client" gains the retire shape and the engine half of
   D5.** The bullet "Surface consumed" names "batch retire" without its shape; it gains
   `[{ipnsName?, targets[]}]`. The bullet list gains one sentence: "The drain dead-letters a
   registry or upload refusal only on the gate's own `code`; a 400 or 413 without it is charged
   against the attempt budget (ADR 0046)." The blueprint does not carry that rule in words today.

7. **`blueprint/api.md` section "Pin/name registry" gains the citation (ADR 0046)** on the
   bullets "Batch bounds", "Per-referencing-record refcount" and "Accepted exposure".

8. **`blueprint/testing.md` section "The contract suite — the live API gate" gains "the batch
   bounds and the record-scoped retire" in its coverage list, with the citation (ADR 0046).** The
   suite runs both today, and the list does not name them.

9. **No wire format, no KDF edge and no op queue record changes.**

## Residuals

**E1 — The API's JSON body limit binds a register call before the item caps do.** This is a
finding, from inspection; no test has reproduced it. The API sets no body-parser limit, so the
Express default of 100 KiB applies (`apps/api/src/main.ts`, `configureApp` in
`apps/api/src/app-setup.ts`). A production content CID is 59 characters, about 62 bytes in the
JSON array, so one full entry of 1000 CIDs is about 62 KB. `net::register` chunks by entry count
only, so a registration that names 1648 or more content CIDs (the new root, its leaves and the
retained roots) sends two entries in one request of more than 100 KiB. That is a file of about
1.6 GiB of plaintext. The body parser answers 413 with no `code`. Under D5 the drain charges it
as an attempt, and the op dead-letters as `AttemptsExhausted`. The flat DAG admits files up to
about 53.89 GiB (ADR 0038 D8), so files between the two sizes cannot publish. The carry of a
moved record in a rotation wave registers up to 8192 CIDs in one call (`MOVED_CONTENT_BATCH_CIDS`
in `crates/engine/src/net/rotation.rs`), so a moved file whose retained versions hold 1648 or
more blocks in total also crosses the limit. The wave reads that failure as retryable
(`WritePublishError::NotLanded`). The engine tests do not see it, because the fake registry
enforces the item caps and not the body size, and the Contract Suite sends short synthetic CIDs.
This ADR records the blueprint rule of D4. The fix is a body limit sized to the caps, or a
chunker that also bounds the request size. FSM1/cipher-box#2018 tracks the defect on both paths.

**E2 — The per-entry `contentCids` cap runs inside the per-item validation, and the OpenAPI
document does not publish it.** The blueprint says
that the caps are enforced before the per-item validation. The entry-count and total-target
checks are (`BatchSizePipe`, `TargetCountPipe` in `apps/api/src/registry/registry.pipes.ts`). The
`contentCids` cap is `ArrayMaxSize` on the entry DTO, so it runs with the per-item validation. The
answer is the same whole-batch 400 with the code. The cost is that the API validates the batch
before it refuses it, which E1's body limit bounds. This ADR records the blueprint rule.

The blueprint and D3 also say that the caps are published as `maxItems` in the OpenAPI document.
The two top-level batch arrays carry `maxItems: 1000`, and `RetireEntryDto.targets` carries the
per-entry 1000. `RegisterEntryDto.contentCids` in `apps/api/openapi.json` carries no `maxItems`,
because its `@ApiProperty` in `apps/api/src/registry/dto/registry.dto.ts` sets none. A reader of
the OpenAPI document cannot see the per-entry cap that D4 splits around. This ADR records the
blueprint rule. FSM1/cipher-box#2018 tracks this gap with E1.

**E3 — A reference is per record, not per version.** All versions of one file share the file's
record name. A record-scoped retire of a doomed version's leaves therefore drops the references of
that name even when the live head of the same file still names a leaf. D1 closes the alias across
records only. The alias within one record rests on the engine's subtraction of the leaves that the
node's current record still reaches (`live_owing_record` in `crates/engine/src/sync/drain.rs`),
which reads that record with no cache on the retiring pass. A crafted head that names every
historical leaf of its own file still pins that history (FSM1/cipher-box#1176, residual 3a). That is
a leak, not a loss.

**E4 — Only the owed-retire path names the record today.** The settle of an owed retire sends
record-scoped entries (`send_retire` in `crates/engine/src/net/retire.rs`). The abandoned op, the
orphaned head block, the name wave and a name retire send the account-wide form. Their targets
are names, or blocks that this device sealed under a fresh content key or a fresh seal nonce, so
no honest record of the account names the same CID. D1 protects only the calls that name a
record.

**E5 — A chunked registration is not atomic across chunks.** Each register call is all or
nothing, but a version split across two calls can leave the first chunk registered when the second
fails. The record PUT waits for every chunk, and a replay is idempotent, so the partial state is
a charged leak until the retry converges or the op is abandoned.

**E6 — The refusal code is authenticated only by the TLS session to the API origin.** The edge
that terminates TLS in front of the API can stamp `REGISTRY_BATCH_REFUSED` or `UPLOAD_TOO_LARGE`
on any answer and cause a dead letter. That edge is the operator's, and the operator is trusted
for availability. A network attacker outside TLS cannot forge the code.

**E7 — An upload 400 carries no code, so a bytes-to-address mismatch is charged, not permanent.**
This agrees with ADR 0038 E3. The API stamps no `code` on the upload mismatch 400, so the drain
cannot tell it from an intermediary's 400 and charges it under D5. Only a client bug reaches that
path.

## Gate

- **D1:** the API unit tests in `apps/api/src/registry/services/registry.service.test.ts`
  ("records one reference edge per referencing record, head CID included", "a record-scoped
  retire keeps a leaf a DIFFERENT record of the same account still names", "retiring a name also
  drops the edges that name anchored, so its sole leaf unpins", "a scoped entry never retires a
  name row, only that record edges"). The real-Postgres tests in
  `apps/api/src/registry/services/registry.service.itest.ts` ("a doomed record retiring an aliased
  leaf leaves it pinned for the live record that also names it", "a register anchoring a SECOND
  record to the CID blocks the scoped retire, which then keeps the pin"). The HTTP test in
  `apps/api/src/registry/registry.http.itest.ts` ("a record-scoped retire leaves a CID another
  record of the same account names pinned"). The Contract Suite test
  `a_record_scoped_retire_keeps_a_cid_another_record_still_names`
  (`crates/contract/tests/contract.rs`). On the engine side, the unit test
  `retire_sends_entries_and_names_the_record_only_when_scoped` (`crates/engine/src/api/client.rs`)
  and the Engine test `a_delete_retires_the_nodes_name_and_reclaims_the_content_it_held`
  (`crates/engine/tests/write_plane.rs`), which asserts that the owed retire names the owning
  record and the name retire names none.
- **D2:** `registry.service.test.ts` ("an unscoped retire drops every record reference the account
  holds", "retires a pin row no record references — the orphaned head an aborted publish left",
  "is idempotent: retiring an already-gone target succeeds as a no-op"). `registry.http.itest.ts`
  ("refuses a batch whose TOTAL target count exceeds the cap, however it is split", "rejects an
  over-length target at the pipe (256-char cap)").
- **D3:** the Contract Suite tests `an_oversize_retire_batch_is_refused_fail_closed` and
  `an_oversize_register_entry_is_refused_fail_closed`. `registry.http.itest.ts` ("refuses an
  over-cap contentCids and stamps the batch-refused code", "fail-closed: a malformed entry is
  refused wholesale, writing no rows"). `apps/api/src/registry/registry.pipes.test.ts` ("retire
  refuses more entries than the batch cap", and the bare-string and bare-object refusals for both
  routes). The engine unit tests `an_oversize_batch_splits_into_chunks_the_server_accepts` in
  `crates/engine/src/net/register.rs` and in `crates/engine/src/net/retire.rs`. **Finding:** no
  test sends a register batch of 1001 entries to the API. The entry-count cap of the register
  route is untested at the API; only the retire route's is.
- **D4:** `registry.http.itest.ts` ("splits an over-cap version across entries under one name,
  keeping the head", "refuses an explicit null headCid rather than clearing the stored head").
  `registry.service.test.ts` ("advances the head on re-publish without duplicating the name row").
  The engine unit test `an_entry_past_the_per_entry_cap_splits_under_one_name` in
  `crates/engine/src/net/register.rs`, and the Engine test
  `a_version_past_the_registration_cap_registers_in_chunks_and_publishes` in
  `crates/engine/tests/write_plane.rs`. The Contract Suite test
  `an_oversize_register_entry_is_refused_fail_closed` proves that the chunked shape is accepted.
  **Finding:** every test uses short CIDs or the CI framing, so no test crosses the body limit of
  E1.
- **D5:** the Engine tests in `crates/engine/tests/write_plane.rs`
  `a_registration_the_registry_refuses_dead_letters_instead_of_holding_the_queue_head`,
  `a_registration_400_from_an_intermediary_is_charged_not_permanent`,
  `an_over_cap_413_is_permanent_and_its_reason_reaches_the_host` and
  `a_413_the_api_did_not_stamp_neither_blocks_nor_abandons_the_op`. The drain unit tests
  `each_413_verdict_rests_on_the_apis_own_code` and
  `a_refusal_of_these_bytes_costs_an_attempt_and_never_dead_letters_on_sight` in
  `crates/engine/src/sync/drain.rs`. The Contract Suite test
  `an_oversize_register_entry_is_refused_fail_closed` asserts the code on the live refusal.
- **D6:** no test. An exposure statement has no behaviour to assert. The Migration Drift gate pins
  the columns of `pin_references` to the entity, and the real-Postgres test "takes the
  account reference edges with it, so no record survives to hold a pin open"
  (`apps/api/src/registry/services/account.service.itest.ts`) covers the account cascade.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
