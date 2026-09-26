# ADR 0042 — A rewrite over the ceiling cuts an uncritical carried field largest first

- **Status:** Accepted on 2026-09-26 — retroactive; the rule shipped in FSM1/cipher-box#1343,
  FSM1/cipher-box#1454 and FSM1/cipher-box#1843, and the blueprint carries it. D8 is the one
  exception: it answers a question that the blueprint records as open.; the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-26
- **Relates to:**
  [#27](https://github.com/FSM1/cipher-box-next/issues/27) D10 (tolerate and round-trip unknown
  fields, amended here),
  [ADR 0033](./0033-every-attacker-sized-field-has-one-canonical-form-and-a-symmetric-fail-closed-bound.md)
  D8 (the grant-section bound), D9 (the charged measure of each bound), D10 (the headroom
  arithmetic) and D11 (an attacker-influenced size never causes a permanent produce-side
  refusal), AGENTS.md rule 8 in FSM1/cipher-box (encode/decode fail-closed symmetry), the
  `blueprint/core.md` "Envelope and structures" section ("Carried unknown fields" bullet), and the
  `CONTEXT.md` "Envelope", "Cross-scope move", "Adoption gate" and "KAT manifest" terms
- **Implemented by:** FSM1/cipher-box#1343 (the cut, its largest-first order, the reserved names
  and the cut report, D1 to D3), FSM1/cipher-box#1454 (the `!` marker, the critical-bytes budget,
  the kind-uniform rule and the manifest freeze, D3 to D6), FSM1/cipher-box#1843 (the
  scope-transplant duty, D7).

## Context

The decision #27 D10 fixed the unknown-field policy as "tolerate and round-trip". A decoder
accepts a field it does not type, ignores it for logic, and re-emits it byte-stable on a rewrite,
"so an old client rewriting under shared write never strips newer fields". The engine keeps two
such sets per envelope: the top-level carried set and the carried set inside `epochTag`.

Both sets come off a resolved record. That record can run to the 2 MiB block ceiling. Before
FSM1/cipher-box#1343, `crates/engine/src/net/author.rs::encode` copied both sets verbatim and
then refused a block over the ceiling. Anyone who can publish at a name (a committed write
grantee, or a compromised sibling device) could therefore pad the carried set once and push every
later re-author of that node past the ceiling. The owner's publishes at that name then stopped,
and the rotation that revokes the padding party stopped with them. The only exit was the attacker
shrinking their own record. FSM1/cipher-box#1327 found this, and FSM1/cipher-box#1343 replaced
the refusal with a cut: the encode drops carried fields until the block fits.

The cut breaks part of the #27 D10 promise. An old client no longer always keeps a newer client's
field. The crypto-privacy gate on FSM1/cipher-box#1343 found the second problem. The engine
protected the two fields that carry protocol meaning today by a frozen list of names
(`UNCUTTABLE` in `crates/core/src/seal/envelope.rs`). That list is frozen when each binary ships.
A v2.0 client cannot learn that a later field, for example a `revocationPin`, carries a trust
decision, so every shipped reader would drop it under pressure, and a newer reader that reads
absence as "no pin" would be downgraded with nothing to detect. The fix has to ride the bytes, not
the reader's build date, and so it is a wire reservation. An old binary cannot learn a new key
name, so the reservation had to exist before the v2.0 wire freeze. FSM1/cipher-box#1355 put the
question on the owner's wave-15 agenda, and the owner decided it on 2026-08-25 (Option A).

A third problem came from FSM1/cipher-box#1619. The interior re-seal under a new scope root
(`reseal_interior_node` in `crates/engine/src/net/rotation.rs`) was the first authoring path that
copies a carried set from a record sealed under one scope's AAD into a record sealed under another
scope's AAD. Preservation there moves an unknown, possibly scope-bound structure into a different
scope. FSM1/cipher-box#1711 asked for the rule, and FSM1/cipher-box#1843 wrote it.

`blueprint/core.md` section "Envelope and structures", bullet "Carried unknown fields", carries
every rule below today. It still cites #27 D10 as its only source.

## Decision

**D1 — A rewrite over the ceiling cuts uncritical carried fields, largest first, and never refuses
for them.** This is the carried-field case of the ADR 0033 D11 law. A rewrite preserves every
top-level and `epochTag` carried field byte-stable while the block fits. When the encoded envelope
is over the author's limit, the encode cuts carried fields until the block fits. The target is the
lower of the author's limit and the block ceiling. The produce side refuses only what the typed
fields and the uncuttable carried fields (D3, D4) overflow alone. The cut ranks the cuttable fields
of both levels in one list by encoded cost, key and framing included, largest first. Fields of
equal cost fall in the set's canonical order, so two builds cut the same field. One pass covers
the whole excess and takes no more fields than the excess needs. The envelope that the encode
returns holds exactly what the block encodes, so no caller can pair a cut block with an uncut
envelope. The one core entry point is `encode_envelope_within` in
`crates/core/src/seal/envelope.rs`. The truncation landed with FSM1/cipher-box#1343; this ADR
records it. The largest-first order was decided on 2026-08-25 in FSM1/cipher-box#1355 ("The
largest-first cut ranking stays"), which accepts the cut by implication.

**D2 — A cut is reported, never silent.** The encode returns the keys it dropped, in the order it
dropped them (`CarriedCut`). Every engine publisher that authors from a carried set passes the cut
to `report_carried_cut` (`crates/engine/src/net/author.rs`). A non-empty cut emits one
trust-violation event (`Event::AttributableAbuse`) at the IPNS name, which names every key taken.
An empty cut emits nothing. The keys come off a published record, so the report discloses nothing
that the wire does not already carry. The rule landed with FSM1/cipher-box#1343; this ADR records
it.

**D3 — `grantSection` and `writeSealed` are uncuttable under their reserved names.** Both carry
protocol meaning. A record without either one is a record that every reader refuses, which is the
refusal the cut exists to avoid. The two names are reserved at the top level of the envelope,
where a reader looks for them. The same name inside `epochTag` carries no protocol and is cuttable
like any other field. The names are frozen in the KAT manifest beside the marker
(`seal.uncuttableKeys`). A reader that honours the marker alone would cut both names and publish a
record every reader rejects. The owner decided on 2026-08-25 in FSM1/cipher-box#1355 that the
uncuttable test is "the two grandfathered names or the marker test". The manifest freeze landed
with FSM1/cipher-box#1454.

**D4 — A `!` key prefix marks a carried field critical, and a rewrite keeps a critical field or
refuses.** A carried field whose key begins with the reserved one-byte prefix `!` is critical. A
rewrite never cuts it and never drops it silently. If the block cannot fit with the critical
field, the encode returns the over-limit block, and the author or the block-ceiling check refuses
it. The marker is honoured at top level and inside `epochTag`. The canonical map-key comparator
is length-first over the encoded key, so the prefix changes no ordering semantics. The prefix is
frozen in the KAT manifest (`seal.criticalKeyPrefix`). The marker was decided on 2026-08-25 in
FSM1/cipher-box#1355 (Option A); it landed with FSM1/cipher-box#1454.

**D5 — A frozen critical-bytes budget bounds the critical set.** `MAX_CRITICAL_CARRIED_BYTES` is
16 KiB. It bounds the sum of the encoded cost of every marked field at both levels plus
`writeSealed` at top level. `grantSection` is the one exclusion, because it has its own bound,
`MAX_GRANT_SECTION_BYTES` (ADR 0033 D8). A budget large enough to hold a grant section would bound
nothing. An unmarked carried field is not budgeted; the cut governs it. The decoder and the encoder
both refuse an over-budget envelope with the same `too-many-structures` verdict, and the encode
check is release-active (AGENTS.md rule 8). The decoder charges the budget off the decoded maps
before it copies the carried set, so the path an attacker aims at allocates once. The value is
frozen in the KAT manifest (`seal.criticalCarriedMaxBytes`). The measure the budget charges is
ADR 0033 D9, and the relation of the budget to the envelope and write-body headrooms is ADR 0033
D10; this ADR does not restate them. The owner decided on 2026-08-25 in FSM1/cipher-box#1355 that
the marker ships with a frozen critical-bytes budget, enforced on both sides, as a non-negotiable
part of the marker. The 16 KiB value is the sizing of FSM1/cipher-box#1454.

**D6 — A critical field is kind-uniform.** A critical field is present or absent independently of
whether the node is a file or a folder. Its key name is plaintext on the envelope, and the envelope
exists to be kind-uniform (`CONTEXT.md` "Envelope"). A critical field that correlates with the
node kind would give the untrusted server the one bit the envelope exists to withhold. The duty
falls on the author of the field. The rule landed with FSM1/cipher-box#1454; this ADR records it.

**D7 — A new envelope-level or `epochTag`-level structure is scope-transplant-safe or refused by
name.** Preservation also moves a carried field across a scope change, wherever an authoring path
re-seals a carried record under another scope's AAD. Every new structure at either level is
therefore one of two things. It is scope-transplant-safe: it binds no scope id, no AAD and no
per-scope key, so the move claims nothing in the destination. Or the authoring path that changes
the scope refuses it by name, as `author_child_envelope` already refuses the grant section with
`grant-section-on-child`. The duty falls on the structure's author, because the client that
preserves the field cannot type it. The one authoring path where the scope changes while carried
fields travel is `reseal_interior_node`, which authors through `author_child_envelope`. The rule
landed with FSM1/cipher-box#1843; this ADR records it.

**D8 — A re-author keeps every critical field it carries, whether or not it saw the field
adopted.** A rewrite never drops a marked field on the ground that it has not seen that field in
a record it adopted earlier. The re-author cannot tell a newer client's honest critical field from
a hostile publisher's marked padding: both arrive as an unknown key in a record that passed the
adoption gate, and the gate checks no field that it cannot type. D5 bounds what this costs. This
is the behaviour that ships today (`is_uncuttable` in `crates/core/src/seal/envelope.rs` has no
adopted state). The blueprint records the question as open and requires an answer before a `!` field
ships. This ADR proposes this answer for the owner to accept; no earlier decision records it.

## Trust argument

- **No party that can publish at a name can stop the owner's publishes there.** Under D1 the
  carried set, which another party sizes, is cut and not refused. The revoking rotation always
  authors. This is the carried-field case of ADR 0033 D11.
- **The cut removes only bytes that no reader acts on.** An uncritical field carries no trust
  decision. The fields that do carry one are uncuttable by name (D3) or by marker (D4).
- **An aimed cut cannot reach a trust decision.** Largest-first bounds the count of fields a cut
  takes, not the bytes. A party that pads with fields smaller than an honest field can aim the
  first cut at that field. D4 makes this safe: a field that carries a trust decision says so on the
  wire, so the aimed cut can reach only an uncritical field.
- **A field minted after a build ships still protects itself.** The marker rides the bytes, so a
  v2.0 binary keeps a v2.1 critical field it cannot type. A frozen name list cannot do this.
- **Marked padding cannot wedge a name without a size limit.** Without D5, a hostile publisher
  marks padding critical, and no rotation clears an uncuttable field. D5 limits that claim to
  16 KiB, and ADR 0033 D10 keeps a maximal critical set inside every re-seal headroom, so the
  claim never makes an honest re-seal unencodable.
- **The decoder and the encoder agree.** Both sides refuse an over-budget critical set with one
  verdict, so a release build never publishes an envelope its own decoder refuses.
- **The marker leaks no node kind.** D6 keeps every plaintext critical key independent of the
  node kind.
- **A carried structure claims nothing in a scope it did not come from.** D7 makes every new
  structure either scope-free or refused on the path that changes the scope, as the grant section
  already is.
- **A cut is visible.** D2 reports every cut as an attributable event at the name. The data loss
  that another party forced is not silent.
- **A re-author cannot be tricked into shedding a newer client's critical field.** Under D8 no
  "not seen adopted" state exists for a padding publisher to exploit.

## Alternatives rejected

**(a) Refuse an encode over the ceiling.** This was the behaviour before FSM1/cipher-box#1343.
It gives anyone who can publish at a name a lasting wedge on every later publish there, the
revoking rotation included.

**(b) Protect a field by name only.** The list of names is frozen when each binary ships, so it
cannot express a field minted later. Every shipped reader drops such a field under pressure
(FSM1/cipher-box#1355).

**(c) A reserved sub-map for critical fields.** FSM1/cipher-box#1355 listed it as an option. The
one-byte key prefix is the cheapest shape in the strict det-CBOR profile, and the length-first
comparator makes it free for key order. The decision took the prefix.

**(d) Declare that no additive field will ever carry protocol meaning.** FSM1/cipher-box#1355
listed it as an option. It closes forward evolution at the wire freeze, and it cannot be undone
after v2.0 binaries ship.

**(e) Rank the cut smallest first.** It bounds the bytes that one cut destroys, but it never
relieves the pressure, so every later edit cuts again. FSM1/cipher-box#1355 asked for the order to
be revisited, and the decision kept largest first. FSM1/cipher-box#1343 gives the reason: once a
field that carries a trust decision says so on the wire, an aimed cut reaches only an uncritical
field, so the byte bound that smallest first gives protects nothing that matters.

**(f) A marker without a budget.** A hostile publisher marks padding critical and holds the name
permanently, which is worse than the refusal the cut replaced. The decision in FSM1/cipher-box#1355
calls the budget "non-negotiable".

**(g) Remove carried keys one by one.** A removal per key moves `O(k·n)` elements against a set
that the attacker sizes. FSM1/cipher-box#1343 ranks once and compacts each set in one pass.

## Consequences

1. **`blueprint/core.md` already carries D1 to D7, with three sentences that need an editorial
   fix (consequence 2).** The "Envelope and structures" section, bullet "Carried unknown fields",
   states the cut and its order (D1), the report (D2), the reserved names and
   `seal.uncuttableKeys` (D3), the marker (D4), the budget (D5), the kind-uniform rule (D6) and
   the scope-transplant duty (D7).

2. **Three sentences in the "Carried unknown fields" bullet get an editorial fix (E3).** Each fix
   states what the code already does. No rule changes.
   - D1: "and refuses only what the typed fields alone overflow" becomes "and refuses only what
     the typed and the uncuttable fields overflow".
   - D3: "`grantSection` and `writeSealed` stay uncuttable under their own **reserved names**,
     from before the marker" becomes "`grantSection` and `writeSealed` stay uncuttable under their
     own **reserved names** at top level, from before the marker; the same names inside
     `epochTag` are cuttable and not budgeted".
   - D5: "over the encoded cost of every marked field plus `writeSealed`, at both levels" becomes
     "over the encoded cost of every marked field at either level plus `writeSealed` at top
     level".

3. **`CONTEXT.md` already carries the base of D6** in the "Envelope" term ("Kind-uniform"). No
   glossary term names the marker or the cut, and none needs to: they are wire detail of
   `crates/core`.

4. **#27 D10 is amended.** "An old client rewriting under shared write never strips newer fields"
   now reads: a rewrite keeps every carried field byte-stable while the block fits; over the
   ceiling it cuts uncritical carried fields largest first and reports the cut; it never cuts a
   critical field or a reserved name. ADR 0033 consequence 4 left the cut outside ADR 0033, and
   this ADR takes it: ADR 0033 D11 states the law, and D1 owns the cut target and the refusal
   clause.

5. **The D8 sentence in `blueprint/core.md` changes when this ADR is accepted.** "Whether a
   re-author may drop a marked field it has never seen adopted is open, and has to be settled
   before a `!` field ships" becomes "A re-author never drops a marked field, whether or not it
   saw the field adopted (ADR 0042 D8)."

6. **`blueprint/core.md` section "Envelope and structures" gains the citation (ADR 0042)** in
   the "Carried unknown fields" bullet, beside FSM1/cipher-box-next#27 D10, which it amends.

7. **No wire format, no KDF edge, no KAT vector and no op queue record changes.** D8 records the
   shipped behaviour.

## Residuals

**E1 — The budget bounds the size of the wedge, not its permanence.** A publisher who fills the
16 KiB budget holds it for as long as the name lives. Every later re-author carries a marked field
verbatim, and only a fresh node id sheds it. D8 makes this permanent by choice: the other answer
lets a padding publisher and an old re-author strip a newer client's critical field. The cost is at
most 16 KiB per name, about 0.8% of the block.

**E2 — An aimed cut can still take a valuable uncritical field.** Padding smaller than an honest
uncritical field aims the first cut at it. Under D4 such a field carries no trust decision, but a
newer client can lose data it wanted to keep. D2 reports the loss; nothing restores it.

**E3 — The blueprint does not say that the reserved names are top level only.** D3 records the
code: `UNCUTTABLE_KEYS` applies at top level, and the same names inside `epochTag` are cuttable
and not budgeted (`crates/core/src/seal/envelope.rs`,
`a_protocol_bearing_name_inside_the_epoch_tag_is_still_cuttable`). The blueprint states that the
marker is honoured inside `epochTag` but is silent on the names. Its budget sentence, "every
marked field plus `writeSealed`, at both levels", can be read to budget `writeSealed` inside
`epochTag` too; the code budgets it at top level only. This is a gap, not a disagreement. The
blueprint also says that the encode "refuses only what the typed fields alone overflow"; the next
sentence makes both reserved names uncuttable, the marker paragraph makes every marked field
uncuttable, and the code refuses what the typed and the uncuttable fields overflow together. D1
records the code, which these sentences together state.

**E4 — D6 and D7 are duties on a future author, and no check enforces them.** The codec cannot
type a field it preserves, so it cannot check that a critical field is kind-uniform or that a new
structure is scope-free. The only enforced instance of D7 is the grant-section refusal in
`author_child_envelope`.

**E5 — The cut report names the name, not the publisher.** The event says that someone else's
bytes cost this node its fields. It does not say which writer padded the record, because the
carried set carries no authorship.

**E6 — The marker has no user in v2.0.** No production code mints a `!` field. The first such
field must meet D6 and D7 and accept D8 before it ships.

**E7 — No release-build test covers the encode-side budget refusal.** The encode refuses an
over-budget critical set with a returned error, not a debug assertion, so the check is
release-active (D5). But `crates/core/tests/encode_refusals.rs`, the one suite that CI runs with
`--release`, has no envelope case. AGENTS.md rule 8 asks for a test that fires in a release build.

## Gate

The `crates/core` tests, `crates/core/tests/kat_manifest.rs` included, run in `Core KATs (native +
WASM)` and `Workspace tests (Linux)`; the `crates/engine` tests run in `Engine simulation tests`.

- **D1** — `a_carried_set_over_the_limit_is_cut_to_fit_rather_than_refused`,
  `a_cut_reports_the_carried_keys_it_dropped` (asserts the largest-first order),
  `a_budget_no_single_field_covers_takes_as_many_as_it_needs_and_no_more`,
  `an_equal_sized_pair_cuts_deterministically`,
  `an_epoch_tag_field_is_cuttable_and_ranked_against_the_top_level`,
  `a_set_already_within_the_limit_keeps_every_carried_field`,
  `a_cut_leaves_the_surviving_carried_values_intact_and_encodable`,
  `a_carried_set_past_the_block_ceiling_is_still_cut_rather_than_refused` and
  `a_limit_above_the_block_ceiling_still_cuts_rather_than_refusing`
  (`crates/core/src/seal/envelope.rs`);
  `a_carried_set_that_would_overflow_the_read_cap_is_cut_rather_than_refused` and
  `a_scope_root_padded_past_the_reservation_is_cut_rather_than_refused`
  (`crates/engine/src/net/author.rs`).
- **D2** — `a_cut_reports_the_carried_keys_it_dropped` and
  `an_encode_that_cuts_nothing_reports_nothing` (`crates/core/src/seal/envelope.rs`);
  `a_cut_is_reported_with_the_keys_it_took_and_an_empty_cut_is_silent`
  (`crates/engine/src/net/author.rs`). No test proves that each publisher in the drain and the
  rotation calls the report; that is a finding.
- **D3** — `the_protocol_bearing_carried_fields_are_never_cut` and
  `a_protocol_bearing_name_inside_the_epoch_tag_is_still_cuttable`
  (`crates/core/src/seal/envelope.rs`); `a_cut_scope_root_keeps_the_grant_section_that_marks_it`
  (`crates/engine/src/net/author.rs`); `the_critical_carried_budget_is_frozen_in_the_manifest`
  (`crates/core/tests/kat_manifest.rs`) asserts `seal.uncuttableKeys`.
- **D4** — `a_marked_carried_field_survives_a_cut_that_takes_everything_else`,
  `a_marked_epoch_tag_field_is_uncuttable` and `a_marked_key_sorts_canonically_beside_unmarked_ones`
  (`crates/core/src/seal/envelope.rs`); KAT accept vector `with-critical-field`, run by
  `envelope_accept_vectors_decode_open_and_round_trip`;
  `the_critical_carried_budget_is_frozen_in_the_manifest` asserts `seal.criticalKeyPrefix`.
- **D5** — `critical_padding_past_the_budget_is_refused_symmetrically`,
  `the_grant_section_is_outside_the_critical_budget`,
  `the_write_sealed_field_is_inside_the_critical_budget`,
  `an_unmarked_carried_field_is_not_budgeted`,
  `critical_padding_inside_the_epoch_tag_is_budgeted_too`,
  `the_critical_budget_is_shared_across_both_levels` and
  `the_critical_budget_admits_exactly_its_last_byte` (`crates/core/src/seal/envelope.rs`); KAT
  reject vectors `critical-carried-over-budget` and `critical-carried-over-budget-in-epoch-tag`,
  run by `envelope_reject_vectors_fire_the_named_check`;
  `the_critical_carried_budget_is_frozen_in_the_manifest` and
  `the_charged_measure_of_every_byte_bound_is_frozen_in_the_manifest`
  (`crates/core/tests/kat_manifest.rs`). The encode refusal is a returned error, not a debug
  assertion, but no test runs it in a release build: `crates/core/tests/encode_refusals.rs`, the
  suite that CI runs with `--release`, has no envelope case. That is a finding (AGENTS.md rule 8).
- **D6** — no test. The codec cannot type a critical field, and no field exists yet (E4, E6).
  That is a finding.
- **D7** — `a_child_envelope_carrying_a_grant_section_is_refused`
  (`crates/engine/src/net/author.rs`) proves the one named refusal. The general duty has no test
  (E4). That is a finding.
- **D8** — `a_marked_carried_field_survives_a_cut_that_takes_everything_else` proves that the
  shipped encode keeps a marked field unconditionally. No test targets a "not seen adopted" case,
  because the code has no such state.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
