# ADR 0027 — A grantee name is not an identity

- **Status:** Accepted on 2026-09-25; the `blueprint/*.md` and `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-25
- **Relates to:**
  [wayfinder: sharing as a link-first flow with no approve step (#1945)](https://github.com/FSM1/cipher-box/issues/1945),
  [sharing: what label names a person in the people list (#1958)](https://github.com/FSM1/cipher-box/issues/1958),
  [Design: API residual role and surface (#34)](https://github.com/FSM1/cipher-box-next/issues/34)
  D6 (no people directory), ADR 0023 (the via-link reference in the same row signature),
  ADR 0025 (every owner act reads the owner-signed row), the `blueprint/engine.md` "Grants and
  ledger" section ("Contact import" and "Invites"), the `blueprint/web-client.md` "Composition
  (apps/web)" section, and the `CONTEXT.md` "Grant ledger", "Contact code" and "Contact label"
  terms

## Context

No v2 account has a name that the person chose or that the server knows
(`apps/api/src/auth/entities/user.entity.ts:20-49`). There is no people directory (#34 D6). A
contact code carries keys only. A claim carries `{claimId, scopeRootName, contactCode}` and
nothing else (`crates/engine/src/grants/invite.rs:537-600`). The web client shows other people as
a full hex key with no short form (`apps/web/src/stores/sharing.store.ts:21-23`,
`apps/web/src/routes/SharedPage.tsx:80-81`).

The people table of the share dialog needs a name on each row. ADR 0023 D8 keeps the contact book
on one device, so a name that lives only there shows on one owner device. The owner signature on
a ledger row covers `{ipnsName, recipientEncPk, recipientIdentityPk, tag}` only, the keys and the
tag (`crates/core/src/seal/write_body.rs:203-225`). File and line citations come from the research
reports (`main` at `d30509e48` or `ee147eac9`).

`CONTEXT.md` already uses "contact label" and "name label" for device-local storage keys. This ADR
names the new concept **grantee name** so that the words stay apart.

## Decision

**D1 — The claimant suggests a name inside the sealed claim.** The invite page shows a name field
before "join". The field starts with the display name that the sign-in supplies, or empty when it
supplies none. The email is never the default, because the name enters a signed row that every
co-writer reads (D3). The person can edit it. The claim payload gains the name, inside
the seal, with the same length bound as a share display name. The owner sees it at conversion.

**D2 — The owner names a contact-code grantee at import.** The import form takes a name. The row
shows it.

**D3 — The grantee name lives in the ledger row, under the owner's row signature.** The row
signature preimage becomes `{ipnsName, recipientEncPk, recipientIdentityPk, tag}` plus the via-link
reference (ADR 0023 D2), the grantee name and a signed name source flag. Each added field enters
the preimage only when it is present (ADR 0023 Consequence 1). At conversion the owner engine
copies the claimant's name into the grantee name with the flag `claimant`. The owner can overwrite
any grantee name, the owner's edit wins, and the flag becomes `owner`. The row signature is
transferable, so the flag makes it attest "K asked for the name N", never "the owner names K N". An
edit re-signs the row and publishes the root. The grantee name syncs with the record to every owner
device. The same person in two folders has one grantee name per row.

**D4 — The contact book is a pre-fill cache.** Each owner device caches the last grantee name it saw for
an identity. It pre-fills that grantee name when the owner names the same person on another folder. The
cache is not an authority.

**D5 — The link fragment carries the owner's name and the folder name, under an owner
signature.** The signature covers `{scopePointerName, ownerName, folderName}`. The invite page
verifies it against the fragment's owner contact code before it shows the names. A link with a bad
signature shows no names, and the link still works. The fragment is plain det-CBOR with no MAC,
and the names do not depend on the secret, so without the signature a forwarder could relabel a
working link. Everything fits in the 2048-byte cap. The person's shared list shows the folder and
"from <name>".

**D6 — A grantee name is not an identity.** A revoke and a permission change bind to the identity key from
the owner-signed row, never to a name. The dialog shows the key fingerprint next to the name on
hover and in every confirmation.

**D7 — A short fingerprint replaces the full hex key.** `crates/core` derives it from the identity
key in a named function with a KAT, so both hosts show the same value and no TypeScript code hashes
a key. The fingerprint shows at least 80 bits. Contact codes are self-made, so a match on a
targeted n-bit fingerprint costs about 2^n key generations.

## Alternatives considered

**(a) A separate owner signature over the grantee name.** Rejected. It adds a second signature path on
each row, and an edit costs one owner signature either way. One preimage, with the source flag of
D3, keeps one verify.

**(b) Keep the grantee name in the contact book only.** Rejected. The contact book does not sync
(ADR 0023 D8), so each owner device shows a different name.

**(c) Use the claimant's name as the identity.** Rejected. The claimant chooses it, so anyone can
send "alice".

**(d) A name that the server holds for each account.** Rejected. It is a people directory, and
the decision #34 D6 rejects one.

**(e) The fingerprint only.** Rejected. A table of fingerprints does not tell the owner who is who.

**(f) The sign-in email as the default name.** Rejected by D1.

**(g) Unsigned names in the fragment.** Rejected by D5.

## Consequences

1. **`crates/core` wire formats change.** The claim payload gains the name. The row signature
   preimage gains the grantee name and its source flag. The fragment gains the owner signature of
   D5, and the fingerprint of D7 is a new function. New KAT vectors pin each change, and the
   existing vectors stay valid (ADR 0023 Consequence 1). Each decode refusal of a bad grantee name
   has a release-active encode check (AGENTS.md rule 8).
2. **Co-writers see the grantee names.** The ledger is in the sealed write-body, so each write
   grantee of the folder reads the grantee names. A read-only grantee cannot open the write-body
   (`write_body.rs:6-8`). `CONTEXT.md` "Grant ledger" already states that membership is not
   deniable inside the grant set, and the grantee name adds a name for each grantee. The owner and
   every co-writer see the claimant-chosen name until the owner edits it. A write claimant can
   extract its signed row.
3. **A claimant can pick a misleading name.** D6 is the defence: the fingerprint is on every
   confirmation, and the owner can rename the row.
4. **`blueprint/engine.md` changes.** In "Grants and ledger", "Invites" states the claim payload of
   D1, "Contact import" states D2 and D4, and the ledger text states D3.
5. **`blueprint/web-client.md` changes.** "Composition (apps/web)" gains the name field of the
   invite page, the grantee name edit in the people table, the fingerprint on hover and in confirmations,
   and "from <name>" on the shared list.
6. **`CONTEXT.md` changes.** It adds **grantee name**: the owner-signed, owner-editable name on a
   grantee's ledger row, for which a claimant's name is a suggestion. "Grant ledger" gains the
   grantee name and its source flag in the signed row. "Contact code" states that the contact book
   caches grantee names and is no trust input.

## Residuals

**E1 — The fragment signature is only as strong as the fragment's owner code.** Nothing anchors
that code (ADR 0024 E2), so a forger who mints a link under its own code can sign any names.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
