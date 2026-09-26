# ADR 0032 — The owner signs each grant row, and the commitment names every recipient

- **Status:** Accepted on 2026-09-26 — retroactive; the rule shipped in FSM1/cipher-box#1120,
  FSM1/cipher-box#1344, FSM1/cipher-box#1368, FSM1/cipher-box#1594 and FSM1/cipher-box#1604,
  and the blueprint carries it; the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-26
- **Relates to:**
  [#39](https://github.com/FSM1/cipher-box-next/issues/39) D2 (the commitment shape and the
  structure-signature preimage, which this ADR supersedes in part), D3 (whole-record fail-closed
  at stage 3), D4 (the floor law) and D8 (the frozen KDF edge catalog),
  [#27](https://github.com/FSM1/cipher-box-next/issues/27) (the pinned structure formats,
  "deliberately epoch-free"), [#34](https://github.com/FSM1/cipher-box-next/issues/34) D6 (the
  commitment verifies against the contact-anchored owner identity),
  [#25](https://github.com/FSM1/cipher-box-next/issues/25) D7 (grant changes are owner-only),
  [ADR 0014](./0014-a-verified-commitments-cut-epoch-raises-the-floor-without-an-unseal.md)
  (the cut-epoch raise),
  [ADR 0015](./0015-the-device-approval-factor-seal-is-in-repo-ecies-on-secp256k1.md)
  D2 (what a catalog edge is),
  [ADR 0016](./0016-a-durable-sequence-floor-key-is-a-name-label-not-the-name.md)
  D2 (`contactLabelSeed`),
  [ADR 0023](./0023-the-invite-link-is-the-primary-sharing-path-and-conversion-runs-by-itself.md)
  D2, [ADR 0024](./0024-a-link-holder-reads-at-once-from-the-link-blob.md)
  D4 and E4,
  [ADR 0025](./0025-revocation-under-the-link-first-model.md)
  D3 and D4,
  [ADR 0027](./0027-a-grantee-name-is-not-an-identity.md)
  D3, the `blueprint/core.md` sections "Write-body", "Grant section", "Structure signatures" and
  "KDF edge catalog", the `blueprint/engine.md` sections "Adoption gate and floors" (stages 2 and
  3, "One section, one signer") and "Grants and ledger", and the `CONTEXT.md` terms "Grant
  ledger", "Grant-set commitment", "Masked recipient", "Cut epoch", "Revocation floor", "Contact
  label", "Floor law" and "Structure signature"
- **Implemented by:** FSM1/cipher-box#1120 (D8), FSM1/cipher-box#1344 (D1),
  FSM1/cipher-box#1368 (D9), FSM1/cipher-box#1594 (D7) and FSM1/cipher-box#1604 (D2 to D6, D10).

## Context

`#39` D2 froze the grant-set commitment as `{ipnsName, ownerPseudonymPk, [(tag, permission,
pseudonymPk)]}`, "still owner-identity-signed, still epoch-free". `#27` had frozen it epoch-free
for one reason: a grantee-triggered rotation must need no owner signature. The recipient keys
lived only in the grant ledger. The ledger is sealed in the write-body, and any committed write
grantee authors the write-body. Each rotator detached-signs the ciphertext of every seed-bearing
structure (`#39` D2), and stage 3 of the adoption gate verifies each structure under a committed
write-capable pseudonym (`#39` D3).

Between 2026-08-07 and 2026-09-02 the review gates found six defects in this shape. Each one
lets a party that holds less than owner authority change who holds a scope's seeds.

1. **Stage 3 had no signer pin** (FSM1/cipher-box#1102, fixed in FSM1/cipher-box#1120). Stage 3
   trial-verified each structure against every committed pseudonym. An accepted contact publishes
   a scope root whose own owner-signed commitment names 1024 write pseudonyms, and spreads the
   section's signatures across them. The measured cost on a real worst-case section was 1,316,100
   verifications and 74.6 s, and the record adopted. The same shape adopted a **structure
   splice**: a structure lifted out of a different record at the same scope and epoch recomputes
   an identical signed input.
2. **The ascent link's public half was unsigned** (FSM1/cipher-box#1334, fixed in
   FSM1/cipher-box#1368). A holder of `writeScopeSeed`, a read-revoked grantee included, could
   swap `ascentPublic` for a key it holds and leave every signed byte unchanged. The next honest
   scope-exit rotation then sealed a new override seed to the planted key.
3. **A co-writer could swap a recipient key** (FSM1/cipher-box#1143, fixed in
   FSM1/cipher-box#1344). The owner signed neither `recipientEncPk` nor `recipientIdentityPk`. A
   re-sealer that held no owner secret wrapped the next seed to whatever key the row carried.
   Where the owner-held re-seal did catch the swap, it refused the whole re-seal, which gave the
   write grantee a veto over the rotation that revokes it.
4. **A write grantee could relabel its own row before a cut** (FSM1/cipher-box#1562, fixed in
   FSM1/cipher-box#1604). The cut named its recipients from the ledger. A relabelled row named
   nobody, so every descendant that the cascade re-keyed minted the revokee a fresh blob off the
   descendant's own row. The owner saw a clean revoke.
5. **The first fix for item 4 published every recipient key** (FSM1/cipher-box#1603). The first
   cut of FSM1/cipher-box#1604 put the raw `recipientEncPk` in the commitment. The grant section
   is published in the clear, and an encryption subkey is a global identifier. An observer who
   holds a contact code could test grant membership at any scope root, and join one person across
   every scope. That is the property the blinded tag exists to deny.
6. **A pre-cut set replayed** (FSM1/cipher-box#1530 and FSM1/cipher-box#1591, fixed in
   FSM1/cipher-box#1594 and FSM1/cipher-box#1604). An epoch-free commitment that the owner signed
   before a cut verifies for ever. A committed write grantee republishes a root that carries it,
   and the next owner re-key mints the cut recipient a fresh blob. The cascade also carried an
   ancestor's cut into every descendant, which revoked an independent grant one level down.

A seventh finding is local, not on the wire (FSM1/cipher-box#1567). The sharer-scoped floor
store prefixed every durable floor key with a contact's raw identity key. Those keys are
plaintext in IndexedDB and in the desktop journal. No edge in the frozen catalog produced a
replacement label.

The fixes landed as agent-decided PR changes, except the mask of item 5. The owner approved the
mask in-wave on 2026-08-31, and the FSM1/cipher-box#1603 comment of that date records the
approval. ADR 0014, ADR 0016 D2, ADR 0024 E4 and ADR 0025 D3 and D4 already build on the cut
epoch, the mask, the revocation floor and `contactLabelSeed`, but no decision creates them.
This ADR records them. The rules live today in `blueprint/core.md` "Write-body", "Grant section",
"Structure signatures" and "KDF edge catalog", in `blueprint/engine.md` "Adoption gate and floors"
and "Grants and ledger", and in the `CONTEXT.md` terms listed above.

## Decision

**D1 — The owner signs each grant ledger row.** Each row carries an owner ECDSA signature over
the det-CBOR preimage `{ipnsName, recipientEncPk, recipientIdentityPk, tag}`. The preimage also
holds the via-link reference, the grantee name and its name source flag, each only when present
(ADR 0023 D2, ADR 0027 D3). So a row minted before those fields keeps its bytes and its
signature, and a removed field fails the verify. A row carries no deadline. Any reader of the
write-body verifies the signature with no owner secret
(`crates/core/src/seal/write_body.rs`, `verify_recipient_binding`). A missing or wrong-length
`ownerSig` refuses at decode. The signature is transferable: a co-writer can extract it and prove
to anyone who holds the owner's contact code that an identity is a grantee of this scope root.
`recipientIdentityPk` is a field that no commitment entry covers. A re-mint carries it forward
only when the row's own signature attests it, and otherwise drops it
(`UNATTESTED_IDENTITY_PK` in `crates/engine/src/net/rotation.rs::remint_grants`), so the owner
never re-signs a label that a write grantee chose. The rule landed with FSM1/cipher-box#1344;
this ADR records it. The "skip the row" policy that the FSM1/cipher-box#1344 body states for a
row whose recipient key fails the binding is replaced by D2: no re-seal reads a recipient key off
a row, so a row that fails its signature loses its unattested fields at the next re-mint, and
nothing else.

**D2 — Every re-seal and every cut names its recipients from the commitment.** Each grant-set
commitment entry carries the recipient's encryption subkey, masked by D3, under the owner's own
signature. The re-seal wraps grant blobs to the recipients that it unmasks from the commitment
entries (`crates/engine/src/rotation/reseal.rs::adopt_recipients`). The cut names the recipients
it revokes from the commitment entries it drops (`rotation/trigger.rs::drop_tags`). The write-name
re-mint walks the commitment, not the ledger. The cascade reads the commitment to find the
recipients a scope withholds (`rotation/cascade.rs::effective_revoked_recipients`). No re-seal
and no cut reads a recipient key off a ledger row that a committed write grantee authors. So a
row with a swapped recipient misdirects nothing, and a committed write grantee cannot relabel its
own row and leave a cut that names nobody. Where the re-sealer holds the owner encryption subkey, it
checks that the committed tag re-derives from the unmasked key, and fails the whole re-seal
closed before any seal when it does not. A committed key that core does not adopt also fails the
re-seal closed. The rule landed with FSM1/cipher-box#1604; this ADR records it.

**D3 — The commitment carries each recipient masked.** The entry shape is `(tag,
maskedRecipientEncPk, permission, pseudonymPk)`, plus the optional `kind`, `deadline`, conversion
permission and admission cap of ADR 0023 D2, D9 and ADR 0024 D4.
`maskedRecipientEncPk = recipientEncPk XOR committedRecipientMask(pointerReadKey, tag)`, with
the scope's `pointerReadKey` and the entry's blinded tag. `GrantSetEntry::new` in
`crates/core/src/seal/grant.rs` is the only constructor, and it masks for its caller, so no path
can publish a recipient in the clear. The owner derives `pointerReadKey`, every grant blob carries
it, and every invite link URL carries it (ADR 0024 E4). So the owner, every grantee and every
link holder of the scope recover the recipient keys, and no other observer does. The mask is
deterministic, so no entropy enters the mint and a read rotation carries the commitment
verbatim. This was decided on 2026-08-31 in FSM1/cipher-box#1603: the comment of that date is
an agent record of the owner's in-wave approval, and it covers the mask only.

**D4 — `committed-recipient-mask` is an edge of the frozen KDF catalog.** Inputs:
`pointerReadKey` and the blinded tag. Context string: `cipherbox/v2/committed-recipient-mask`.
Layout: `keyed_hash(derive_key(ctx, pointerReadKey[32]), tag[32])`. Output: the 32-byte mask of
D3. The tag is a fixed-length `keyed_hash` message, never context. The edge derives no key; its
output is a one-time pad over a public key. It joins the catalog of `#39` D8 under AGENTS.md rule
5, and the KAT manifest freezes its output beside the other edges. The owner approved the edge
with the mask (D3).

**D5 — A tag appears at most once in a commitment.** The codec refuses a repeated `tag` with
`duplicate-grant-tag`, on decode and release-active on encode and sign. The mask of D3 makes one
recipient look different in every entry, so no codec check can see a repeated recipient, and the
`duplicate-grant-recipient` check retires. The invariant that one party holds one entry now rests
on the tag: the tag is a deterministic function of the owner, the recipient and the scope root
name, and every mint derives the two together. The rule landed with FSM1/cipher-box#1604; this
ADR records it.

**D6 — The commitment carries a cut epoch.** The signed preimage is `{cutEpoch, ipnsName,
ownerPseudonymPk, [entries]}`. The owner steps `cutEpoch` by one at every cut that re-signs the
set, and at nothing else: one step per owner revoke, whatever the number of rows it removes (ADR
0025 D4). The write-scope cut that re-uses the set the owner already signed steps nothing. A step
at the counter ceiling fails closed, release-active. Stage 2 of the adoption gate refuses a
commitment below the newest cut epoch that this scope already adopted, as a whole-record trust
violation (`commitment-invalid`, `core::seal::refuse_stale_cut_epoch`). The commitment still
carries no read epoch, so a grantee-triggered rotation still needs no owner signature. The raise
of the cut-epoch floor is ADR 0014. The rule landed with FSM1/cipher-box#1604; this ADR records it.

**D7 — The engine keeps a device-local revocation floor per scope and recipient.** When the
owner cuts a recipient at a scope, the engine records that cut, durably, at that scope and nowhere
else. The owner re-key of the rotation cascade consults the record
(`rotation/cascade.rs::effective_revoked_recipients`) and mints no blob for a recipient whose
recorded cut is newer than this device's grant floor for that recipient at that scope. An
ancestor's cut never carries down to a descendant on its own, so an independent grant one level
down survives. The cut epoch of D6 is the scope-wide complement: it refuses the whole pre-cut set
at the gate, while this floor withholds one recipient's blob at a re-key. The floor only rises,
except by the clear of ADR 0025 D3. It has no cold-seed anchor: no owner-signed record carries
it. The engine raises it before the publish of the re-key that drives the cut. A floor the engine
cannot read aborts the cascade before anything is minted, with a retryable error. The rule landed
with FSM1/cipher-box#1594; this ADR records it.

**D8 — One section, one signer.** A grant section is one rotator's work. Stage 3 pins the
committed write-capable pseudonym that authenticates the section's first structure, and every
later structure must verify under that key alone. A section that two committed pseudonyms signed
is a whole-record trust violation (`structure-signature-invalid`). The pinned signer may be any
committed write-capable pseudonym, not only the owner's. The produce side runs the same predicate
release-active in `crates/engine/src/net/author.rs::check_scope_root`, so this build never signs a
section its own gate refuses. A future shape that needs per-structure signers needs a
per-structure signer index on the wire: a format change, not a relaxation of this rule. The rule
landed with FSM1/cipher-box#1120; this ADR records it.

**D9 — The ascent link's structure signature covers its public half.** For every seed-bearing
structure except the ascent link, the signed bytes are the structure's ciphertext. The ascent link
signs the det-CBOR binding `{ascentPublic, ciphertext, enc}`
(`crates/core/src/seal/structure.rs::ascent_link_sig_body`). The rule landed with
FSM1/cipher-box#1368; this ADR records it.

**D10 — The contact-label edges label contacts in device-local state.** Two catalog edges:

- `contact-label-seed`: `derive_key("cipherbox/v2/contact-label-seed", loginSecret[var])`, output
  `contactLabelSeed`.
- `contact-label`: `keyed_hash(derive_key("cipherbox/v2/contact-label", contactLabelSeed[32]),
identityPk[33])`, output a fixed-width label for one contact identity key.

The identity key is a fixed-length `keyed_hash` message, never context and never a concatenation
tail. The label keys durable device-local state that would otherwise name a contact in the clear:
the sharer-scoped floor store prefixes every epoch key with it. Its output never reaches the wire.
The seed derives from the login secret, so the label is deterministic for the account and no
observer who holds the identity key can recompute it. ADR 0016 D2 adds `name-label` as the seed's
second consumer. The rule landed with FSM1/cipher-box#1604; this ADR records it.

## Trust argument

- **A write grantee cannot redirect the next seed.** The re-seal wraps to recipients from the
  owner-signed commitment (D2). A swapped key in a row reaches no seal.
- **A write grantee cannot hide from its own cut.** The cut names its recipients from the entries
  it drops (D2). The row that the grantee authors plays no part in the harvest.
- **A write grantee cannot veto its own revocation.** No re-seal refuses because of a row. The
  owner-held leg fails closed only where the owner's own authorities disagree: the owner-signed
  entry against the tag the owner subkey re-derives. A write grantee can change neither.
- **A write grantee cannot launder a label into an owner signature.** A re-mint carries
  `recipientIdentityPk` only from a row the owner attested (D1).
- **An observer learns no membership.** The masked field is a one-time pad over the recipient key
  (D3). The pad never repeats: `pointerReadKey` is fixed for one scope, and the tag is injective
  in the recipient for a fixed owner and scope root name. Two recipients that share a tag need a
  BLAKE3 collision or a cofactor twin, and core refuses to adopt the cofactor class. D5 refuses a
  commitment that carries both halves of such a pair. A write rotation moves the name, so the tag
  and the pad move with it.
- **The mask derives in its own domain.** D4 gives it a dedicated context string, and the
  catalog's pairwise-separation KAT covers it.
- **A replayed pre-cut set is refused.** Stage 2 refuses it on every device that adopted the cut
  (D6). The revocation floor withholds the one recipient at a re-key on the device that made the
  cut (D7).
- **Stage 3 costs `pseudonyms + structures`, not their product, and adopts no splice** (D8). After
  FSM1/cipher-box#1120 the adversarial section above costs 1,026 verifications and 35 ms, and is
  refused.
- **An ascent swap is attributable** (D9). Only a committed pseudonym can sign a swapped public
  half, and an owner cut derives the half from the parent seed instead of carrying it.
- **A contact label names nobody off the account** (D10). The seed is the account's alone.

## Alternatives rejected

**(a) Put the raw `recipientEncPk` in the commitment.** FSM1/cipher-box#1143 already warned
against it, and the first cut of FSM1/cipher-box#1604 did it. It turns the commitment into a
confirmation oracle for "is this person a grantee of this scope", and it links one person across
every scope. The mask of D3 keeps the authority and removes the oracle.

**(b) Abort the re-seal on a row that fails the binding.** This was the behaviour before
FSM1/cipher-box#1344. It hands the write grantee that a rotation cuts a veto over its own
revocation, because the write-name wave is the write revocation.

**(c) Trust the row signature first on the owner-held leg.** Both review gates on
FSM1/cipher-box#1344 found that one flipped bit of a victim's `ownerSig` would then revoke the
victim silently and permanently, laundered into the owner's next signed commitment. The tag
re-derivation is the stronger authority and goes first.

**(d) A designated-verifier row signature, to keep deniability.** Every co-writer must verify
the row, which rules out a designated verifier, and contact codes already bridge an X25519-only
preimage to an identity. The leak is accepted as E1.

**(e) The revocation floor alone, with no field in the commitment.** This was option (a) of
FSM1/cipher-box#1530, and it shipped first. It has no cold-seed anchor, and three owner-side
re-seal paths did not consult it (FSM1/cipher-box#1591). Option (b), a counter in the commitment,
shipped as D6. The floor stays as the per-recipient complement.

**(f) A `FloorStore` method that clears a revocation entry.** `FloorStore` has no prefix scan,
so a clear cannot tell whether it removed the scope's last entry. A clear is also not monotone,
and the seam contract makes the store unable to regress. The grant floor reaches the same result
with the existing monotone raise.

**(g) Derive the grant floor from the resolved ledger.** A committed write grantee can republish a
pre-cut owner-signed set, so a row in a ledger is not evidence that the owner grants that
recipient now. The first draft of FSM1/cipher-box#1594 did this and lifted every standing cut at
the scope, the replayed ones included.

**(h) Per-structure trial-verify, or per-structure signers.** Trial-verify gives the product
amplification and the splice of item 1. Per-structure signers need a signer index on the wire.

**(i) Re-use an existing edge for the contact label.** The comment of 2026-08-31 on
FSM1/cipher-box#1567 checked every edge. The fixed-shape edges have the wrong message width. The
variable-input edges need an ambiguous concatenation, and their outputs are live keys. The
`blinded-tag` edge has the right shape, but its output is a published value, so a label and a tag
would share one domain.

**(j) A link-only mask key.** It would stop a link holder from unmasking the committed
recipients, but it needs a new commitment format. The owner accepted the leak on 2026-09-25
(ADR 0024 E4).

**(k) An owner signature at each read rotation, so a revoked grantee loses the unmask key.** The
commitment carries no read epoch so that a grantee-triggered rotation needs no owner signature.
This alternative gives that property up.

## Consequences

1. **`blueprint/core.md` already carries the rules.** "Write-body" carries D1. "Grant section"
   carries D3, D5 and D6 (the preimage with `cutEpoch` and `maskedRecipientEncPk`, and
   `duplicate-grant-tag`). "Structure signatures" carries D9. "KDF edge catalog" carries the rows
   and paragraphs of D4 and D10. No text change is needed.

2. **`blueprint/engine.md` already carries the rules.** "Adoption gate and floors" carries D6 at
   stage 2 and D8 at stage 3 and "One section, one signer". "Grants and ledger" carries D2 and D3
   in its lead paragraph. One bullet of "Grants and ledger" contradicts D2 and changes (item 8).

3. **`CONTEXT.md` already carries the rules.** "Grant ledger" carries D1, D2 and E1. "Grant-set
   commitment" carries D2, D3, D5 and D6. "Masked recipient" carries D3. "Cut epoch" carries D6.
   "Revocation floor" carries D7. "Contact label" carries D10.

4. **This ADR supersedes `#39` D2 in part.** The commitment shape of D2 now reads `{cutEpoch,
ipnsName, ownerPseudonymPk, [(tag, maskedRecipientEncPk, permission, pseudonymPk)]}`. "Still
   epoch-free" now reads "carries no read epoch, and carries a cut epoch" (D6). The same words in
   `#27` "Pinned structure formats" read the same way. The signed input `H(ciphertext)` now reads
   "`H` of the signed bytes, which are the ciphertext, or the ascent-link binding of D9". The rest
   of `#39` D2 stands: the pseudonym derivation, the list of signed structures, the pairwise
   attribution and the rejected alternatives.

5. **The ADRs that build on these rules now build on a decision.** ADR 0014 builds on D6. ADR
   0016 D2 builds on D10. ADR 0024 E4 builds on D3. ADR 0025 D3 builds on D1, D2 and D7, and ADR
   0025 D4 on D6. ADR 0014, ADR 0016, ADR 0024 and ADR 0025 D4 do not change. ADR 0025 D3 and ADR
   0025 consequence 5 change (item 6).

6. **ADR 0025 D3 is amended.** ADR 0025 D3 says that the engine "reads the person's encryption
   key from the owner-signed ledger row in the folder record, after the row signature verifies"
   and "does not read the contact book". The code does two different things. It finds the
   person's rows through the attested `recipientIdentityPk` of each owner-attested ledger row
   (`grants/cut_set.rs::revoked_rows`). It names the revoked recipient key from the commitment
   entry of each dropped tag (`rotation/trigger.rs::drop_tags`). For a row whose label the owner
   did not attest (E7), `revoked_rows` falls back to `RevokedPerson::contact_enc_pk`, the
   encryption subkey that this device's contact book binds to the identity, and matches it
   against the unmasked commitment entry. ADR 0025 D3 now reads: "The engine finds the person's
   rows through the owner-attested ledger row, and names the recipient key from the commitment
   entry (ADR 0032 D2). For a row whose label the owner did not attest, the engine matches the
   encryption subkey that this device's contact book binds to the identity against the
   commitment entry." The fallback can only widen the set of rows a revoke reaches. It grants
   nothing, because the key it matches must already be committed, and a revoke only removes
   access. ADR 0025 consequence 5 ("The contact book stops being a trust input") now reads with
   that fallback: the contact book is no trust input for a grant, and it is a match input for a
   revoke of an unattested row only.

7. **The frozen KDF catalog gains three edges by decision:** `committed-recipient-mask` (D4),
   `contact-label-seed` and `contact-label` (D10). Their rows already exist in `blueprint/core.md`
   and in `crates/core/src/kdf/mod.rs`, and their outputs are frozen in the KAT manifest.

8. **`blueprint/engine.md` "Grants and ledger" changes one bullet.** The revoke bullet under
   "Revocation is discovered, not delivered" says "**Any owner device** revokes: it reads the
   person's encryption key from the owner-signed ledger row after the row signature verifies".
   It changes to: "**Any owner device** revokes: it finds the person's rows through the
   owner-attested ledger row, and names the recipient key from the commitment entry (ADR 0032
   D2). For a row whose label the owner did not attest, it matches the encryption subkey that
   this device's contact book binds to the identity against the commitment entry."

9. **Citations the blueprint gains.**
   - `blueprint/core.md` section "Write-body" gains the citation (ADR 0032) on the row-signature
     sentence.
   - `blueprint/core.md` section "Grant section" gains the citation (ADR 0032) on the commitment
     preimage.
   - `blueprint/core.md` section "Structure signatures" gains the citation (ADR 0032) on the
     ascent-link exception.
   - `blueprint/core.md` section "KDF edge catalog" gains the citation (ADR 0032) on the
     `committed-recipient-mask` paragraph and on the contact-label paragraph.
   - `blueprint/engine.md` section "Adoption gate and floors" gains the citation (ADR 0032) at
     stage 2 and at "One section, one signer".
   - `blueprint/engine.md` section "Grants and ledger" gains the citation (ADR 0032).
   - `CONTEXT.md` "Grant ledger", "Grant-set commitment", "Masked recipient", "Cut epoch",
     "Revocation floor" and "Contact label" gain the citation (ADR 0032).

10. **`CONTEXT.md` "Structure signature" gains the D9 exception.** The term says the signature is
    over "a seed-bearing structure's ciphertext". `blueprint/core.md` and the code sign the
    ascent-link binding instead. The glossary gains "(the ascent link signs `{ascentPublic,
ciphertext, enc}`, ADR 0032 D9)".

## Residuals

**E1 — Grant membership is non-deniable within the grant set.** A co-writer reads the ledger and
can extract a transferable row signature (D1). Every grantee and every link holder of the scope
holds `pointerReadKey` and unmasks every committed recipient key (D3, ADR 0024 E4); the invite
link URL alone is enough. Membership stays invisible outside that set. The owner accepted the
widening from the writer set to the grant set with the mask on 2026-08-31, and the link-holder
case on 2026-09-25.

**E2 — A revoked grantee can still unmask the recipient list.** `pointerReadKey` is keyed on the
owner pointer seed and the scope id, and it never rotates, because the pointer plane depends on
it. A cut grantee keeps it for the life of the scope id. The mask gives privacy against parties
never granted, not privacy after a cut.

**E3 — The floors of D6 and D7 have no cold-seed anchor.** A device that neither made the cut nor
adopted a post-cut record takes the first commitment it is served. Two owner devices that cut
one scope at the same time sign different sets at the same cut epoch, and each device accepts
the other's set. The publish plane settles that race.

**E4 — One owner publish path signs a commitment with no cut-floor read.** The cut-epoch bar
of D6 depends on the reader's own floor, not on the bytes, so `net/author.rs::check_scope_root`
has no copy of it. The owner re-seal publish does read the floor: under the write-epoch lease,
`RootPublish::check_publishable` in `net/rotation.rs` refuses release-active when the re-sealed
commitment's `cutEpoch` is below the durable cut-epoch floor (FSM1/cipher-box#1750, 2026-09-05).
One path signs a commitment and reads no cut-epoch floor: the root arm of the write wave
(`WriteWaveNet::publish_moved` in `net/rotation.rs`), which reads only the read-epoch and
write-epoch floors before `reseal_root` re-signs the carried commitment. The grant-edit publishes
(append, invite, permission change, rename and conversion) go through
`OwnerRotationNet::publish_scope_root` and `RootPublish::run`, so they reach the same cut-epoch
check. `grants/invite.rs::check_publishable` is an earlier structural check (the grant-set
ceiling, repeated tags, and ledger-commitment agreement), not a floor check. The rule that a
rotation reads every floor again before it seals belongs to ADR 0041, and this ADR does not state
it. The gap is FSM1/cipher-box#2016.

**E5 — The revocation floor keys name the recipient in the clear.** `revocation_floor_key`,
`grant_floor_key`, `revocation_cut_epoch_key` and `cleared_floor_key` in
`crates/engine/src/rotation/cascade.rs` append the raw recipient encryption subkey to the scope
id. The owner-scoped view prefixes an owner tag and labels only the sequence namespace (ADR 0016).
A reader of local storage sees which encryption subkeys the owner cut or granted at each scope.
The `/granted/` shape covers every converted claimant. The crypto gate on FSM1/cipher-box#1594
raised this in a comment on FSM1/cipher-box#1591, and FSM1/cipher-box#1604 closed
FSM1/cipher-box#1591 without a fix. FSM1/cipher-box#2009 now tracks it. D10 blinds the sharer
prefix, not this one.

**E6 — A committed writer can still plant an ascent public half.** D9 makes the swap
attributable, not impossible. An owner cut repairs it.

**E7 — A committed writer can still damage its own rows.** It can corrupt a row signature. The
owner's next re-mint then drops the row's identity label, via-link reference and grantee name,
and a revoke by identity then reaches the row only through the encryption subkey that this
device's contact book binds to the identity, matched against the committed entry
(`grants/cut_set.rs::revoked_rows`). A duplicate tag in the write-body ledger makes the body
undecodable and stalls the scope's rotations until the owner republishes the root from an earlier
gate-passed record (`blueprint/core.md` "Write-body").

## Gate

- **D1:** `crates/core/src/seal/write_body.rs` unit tests
  `a_signed_recipient_binding_verifies`, `tampering_with_a_bound_field_breaks_the_recipient_binding`,
  `a_recipient_binding_does_not_verify_under_another_scope_root`,
  `the_recipient_binding_preimage_excludes_permission_and_unknowns`,
  `a_ledger_row_without_an_owner_sig_rejects` and `a_wrong_length_owner_sig_rejects`; the core KAT
  suite `recipient_binding_accept_vectors_reencode_and_verify` and
  `recipient_binding_reject_vectors_fail_closed` (`crates/core/tests/kat_manifest.rs`); engine
  `net/rotation.rs` `an_unattested_recipient_identity_pk_is_never_laundered_release_active` and
  `an_unattested_rows_name_and_via_link_drop`; `grants/ledger.rs`
  `only_the_owner_minted_row_at_its_own_name_is_attested`. No test is owed for transferability,
  which is a property of an ECDSA signature.
- **D2:** `rotation/reseal/tests.rs` `a_relabelled_ledger_row_cannot_redirect_the_blob`;
  `rotation/trigger/tests.rs` `a_cut_names_the_committed_recipient_though_its_row_was_relabelled`
  and `a_cut_names_the_committed_recipient_with_no_owner_signature_on_the_row`; `net/rotation.rs`
  `a_relabelled_ledger_row_cannot_redirect_the_reminted_grant`; `grants/create.rs`
  `a_relabelled_parent_row_cannot_redirect_the_parent_blob`; core `seal/grant.rs`
  `a_relabelled_recipient_fails_the_commitment_signature`.
- **D3:** core `seal/grant.rs`
  `a_committed_recipient_is_masked_per_scope_and_recovers_under_the_pointer_key` (the key is
  nowhere in the published bytes, and one recipient masks differently at two scope roots) and
  `a_commitment_entry_without_a_masked_recipient_rejects`; engine `net/rotation.rs`
  `a_grantee_cut_refuses_an_entry_masked_under_another_scope_key`; the core KAT
  `grant_set_accept_vectors_decode_and_verify`, whose vectors record the pointer read key and the
  recipients it recovers. The observer-indistinguishability test that FSM1/cipher-box#1603 asked
  for exists only as the byte-absence assertion above.
- **D4:** core `kdf/mod.rs` `edge_probe_matches_edges_table_order`, `edges_are_pairwise_separated`
  and `public_edges_agree_with_probe_material`; the core KAT
  `kdf_edge_outputs_are_frozen_and_pairwise_separated`.
- **D5:** core `seal/grant.rs` `encode_and_sign_reject_a_duplicate_grant_tag`; the core KAT
  `grant_set_reject_vectors_fail_closed` (`duplicate-grant-tag`).
- **D6:** core `seal/grant.rs` `a_commitment_below_the_cut_epoch_floor_is_refused`,
  `a_commitment_without_a_cut_epoch_rejects` and
  `a_stepped_cut_epoch_detaches_the_commitment_signature`; `rotation/trigger/tests.rs`
  `every_re_signed_cut_steps_the_cut_epoch_and_the_re_used_set_does_not` and
  `a_cut_at_the_counter_ceiling_fails_closed`; `crates/engine/tests/adoption_gate.rs`
  `a_commitment_below_the_adopted_cut_epoch_is_a_whole_record_rejection`; `net/rotation.rs`
  `a_cut_floor_rise_inside_the_owner_publish_window_refuses_the_re_seal` (the owner re-seal
  publish, FSM1/cipher-box#1750).
- **D7:** `rotation/cascade/tests.rs`
  `a_descendant_the_owner_cut_at_that_descendant_gets_no_re_keyed_grant_blob`,
  `a_descendant_that_independently_commits_the_cut_recipient_keeps_its_blob`,
  `the_cut_the_cascade_drives_is_durable_at_the_scope_it_cuts`,
  `a_recipient_the_owner_granted_again_after_the_cut_is_re_keyed`,
  `a_grant_at_the_cuts_own_epoch_lifts_it`, `a_grant_older_than_the_cut_does_not_lift_it`,
  `a_scope_with_no_recorded_cut_reads_one_floor_key` and
  `a_floor_store_that_refuses_re_keys_nothing`.
- **D8:** engine `gate/adoption.rs` `any_committed_pseudonym_can_pin_the_sections_signer`,
  `a_section_signed_by_two_committed_pseudonyms_is_unadoptable` and
  `a_signature_from_no_committed_pseudonym_is_rejected_pinned_or_not`; the engine KAT suite
  `crates/engine/tests/kat_gate.rs` `accept_vectors_authenticate_under_one_committed_signer` and
  `a_section_signed_by_two_committed_pseudonyms_fails_closed` (the splice vector included);
  `net/author.rs` `a_scope_root_envelope_whose_section_has_two_signers_is_refused` (release-active
  produce side).
- **D9:** core `seal/structure.rs` `a_swapped_ascent_public_never_verifies`; the core KAT
  `structure_sig_accept_vectors_verify` and `structure_sig_reject_vectors_fail_closed`
  (`ascent-link-binds-public-half`, `ascent-public-swapped`); `crates/engine/tests/adoption_gate.rs`
  `a_swapped_ascent_public_fails_stage_three_on_both_reader_arms`.
- **D10:** core `kdf/mod.rs` `a_contact_label_separates_contacts_and_accounts`; engine
  `seams/floor_store.rs` `no_durable_floor_key_names_the_contact_identity` and
  `a_key_cannot_spell_another_identitys_key`; the core KAT
  `kdf_edge_outputs_are_frozen_and_pairwise_separated`. No test asserts that a contact label is
  absent from every published byte.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
