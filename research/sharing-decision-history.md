# Decision history behind the v2 sharing flow

22 ADRs exist in `FSM1/cipher-box-next/decisions/`. Seven touch sharing, grants, the mailbox, pseudonyms or device approval (0001, 0002, 0005, 0006, 0009, 0015, 0022); 0010 touches sharing through the bin. The sharing decisions themselves live in issues cipher-box-next #25, #34, #35 and #39. Line numbers for `CONTEXT.md` and the blueprint are from `d30509e48`.

## 1. Decision table

| id | title | property it buys | mechanism | rejected alternative |
|---|---|---|---|---|
| [next#25](https://github.com/FSM1/cipher-box-next/issues/25) D1 | grant locus | Observers see only blob count; the relay holds no grant rows. | Grant blobs in the envelope keyed by `HKDF(ECDH(recipient, owner) \|\| ipnsName)`; ledger in the write-body. | The v1 relay grant store: "The relay's `/shares` and `share_invites` tables cease to exist." |
| next#25 D2 | discovery | The relay sees "transient `{sender, recipient, timestamp}` edges — never a durable graph, never key material". | Sealed one-shot pointer in a relay mailbox, kept until acked. | A decentralized inbox (substrate ruled out for v2.0 in #3). |
| next#25 D3 | durable share state | Revocation is "discovered, not delivered". | Each party keeps a sealed share list in their own vault; metadata is the authority. | Server-held share state. |
| next#25 D4 | revocation | "they keep what they saw; they lose everything new, now." | Read revoke = immediate cut; write revoke = write rotation. | The lazy stance of old v1 ADR 0002. |
| next#25 D6 | invites | An invite is honestly a bearer link; more than one person can claim it. | Grant blob wrapped to an ephemeral key; claim through the mailbox; owner converts. | "v1's single-claim CAS was theater". Write links allowed, "chosen over the read-only recommendation". |
| next#25 D7 | grant authority | Only the owner can grant, enforced by crypto; a write-grantee cannot re-share. | Owner-signed grant-set commitment. | Server check `assertRootOwnership`; no mediation ("a leaked write URL could silently mint durable grants"). |
| [next#35](https://github.com/FSM1/cipher-box-next/issues/35) F-6 | adversarial crypto review | A malicious directory cannot redirect a grant. | Binding verification mandatory; identity key authenticated out-of-band "before a first grant". | Lookup by default with optional fingerprints: "a malicious directory returns an attacker identity key + self-consistent subkey binding and grants are wrapped to the attacker." |
| [next#34](https://github.com/FSM1/cipher-box-next/issues/34) D6 | no people directory — contact codes | "identity keys only ever arrive out-of-band; there is no in-band lookup to substitute". | Contact code `{identityPk, encSubkey, bindingSig}`, verified at import, fail-closed. | "Chosen over email or handle lookup, then over even a minimal resolver: the directory component is never built." |
| next#34 D5 | mailbox | The server keeps no durable sharing graph. | Post to a recipient pubkey, poll, ack; poll shows no sender in the clear. | Accepts "an accepted, rate-limited exact-pubkey existence oracle". |
| [next#39](https://github.com/FSM1/cipher-box-next/issues/39) D1 | seal authentication | Relay substitution "structurally impossible". | Record-verify chain + blinded tag + commitment checked "against a contact-code-anchored owner identity". | — |
| next#39 D2 | committed writer pseudonyms | Every seal traces to its writer; observers cannot link a writer across scopes. | Per-(scope, writer) Ed25519 pseudonym from the same pairwise ECDH as the tag. | Sealed-inside identity signatures; public identity signatures ("ecrecover leaks the rotating grantee's identity key across scopes"); HPKE auth-mode. |
| next#39 D9 | mailbox sender authentication | Junk and impersonated pointers are dropped before any resolve. | Sender-identity signature inside the seal, checked against the contact-code-anchored key. | Unauthenticated items. |
| [ADR 0001](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0001-mailbox-recipient-binding.md) | mailbox recipient binding | A malicious recipient cannot pass a signed item on. | `recipientEncPk` in the signed preimage. | Enforce at higher layers; bind in HPKE AAD. |
| [ADR 0002](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0002-owner-write-blob.md) | owner write blob | A read-only ancestor reader never gets the write seed. | Separate owner-only write blob. | Fold into the owner blob. |
| [ADR 0005](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0005-owner-pseudonym-seed.md) | owner pseudonym seed | Grant identities and the owner identity cannot merge. | Dedicated KDF edge. | Self-ECDH; reuse `owner_pointer_seed`; `login_secret` directly. |
| [ADR 0006](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0006-owner-local-sealed-store.md) | owner-local sealed store | A local-storage writer cannot forge an invite conversion; the contact graph stays private. | One sealed structure for invite records, contact book, received shares. | Contact book in the clear; invite store unsealed. |
| [ADR 0009](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0009-device-approval-is-a-bound-rendezvous.md) | device approval | Same rule in another flow: a server-relayed key is not trusted without an out-of-band check. | Both devices compare a value; both sign; approver mints a fresh factor. | "Port v1's design" — "That reasoning treats a server-relayed public key as trustworthy." |
| [ADR 0015](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0015-the-device-approval-factor-seal-is-in-repo-ecies-on-secp256k1.md) | factor seal | Not sharing. | ECIES on secp256k1. | X25519 + HPKE. |
| [ADR 0022](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0022-a-first-run-cold-start-tolerates-a-failed-public-routing-endpoint.md) | first-run cold start | Not sharing; incident was a sign-up from a share link; status Proposed. | Registry query + first-run absent rule. | (a)–(f). |
| ADR 0010 | bin index | "closes the revoked-grantee-reads-deleted-nodes-forever hole". | Delete = re-seal under a key outside the scope. | A bin folder. |

## 2. Threat model the sharing design defends

| adversary | property | source |
|---|---|---|
| Malicious API/relay substituting keys | A grant never goes to an attacker key. | next#35 F-6; next#34 D6; `api.md` "Contact exchange — no directory" |
| Malicious relay forging grants | Cannot forge. | next#39 D1 |
| API as graph observer | "the server is zero-knowledge about the grant graph" (`api.md:126`); mailbox edges transient. | next#25 D2; next#34 D5 |
| Mailbox transport | "integrity-untrusted", "nothing load-bearing for safety". | `CONTEXT.md:100` |
| Public IPNS observer | "Observers learn only blob count" (`CONTEXT.md:36`); masked recipient (`:40`); pseudonyms unlinkable (`:42`). | next#25 D1; next#39 D2 |
| Rogue or revoked write-grantee | Writers "cannot change the set; grant changes are owner-only" (`:38`); cut epoch stops restoring a pre-cut set (`:41`). | next#39 D1–D3; next#25 D7 |
| Revoked grantee | "they keep what they saw; they lose everything new, now." | next#25 D4 |
| Malicious recipient relaying items | Fails closed as `identity-signature-invalid`. | ADR 0001 |
| Holder of a leaked invite URL | Bearer capability; a leaked write URL cannot mint grants; only a write rotation revokes a write link. | next#25 D6/D7 |
| Writer to the owner's local storage | Cannot mint "a genuine grant at up to `Write`". | ADR 0006 |
| MITM on the channel | Fingerprint comparison is "optional client-side hardening". | next#34 D6 |
| Co-grantee | Membership non-deniable within the set, invisible outside it. | `CONTEXT.md:38` |

## 3. Why the grantee acts first, and why the owner converts

No decision says "the grantee acts first". It follows from keys arriving only out-of-band (next#34 D6; next#35 F-6 "before a first grant"); the tag needs the recipient enc key (next#25 D1); the mailbox rejects unknown recipients (next#34 D5); the recipient needs the owner's code to self-locate the blob (#1870 diagnosis: "it takes that subkey from the verified contact, never from the pointer").

Owner conversion: next#25 D6 "the owner converts it to a personal grant (and may upgrade to write there)"; next#25 D7 "Sharing and revoking are owner-only acts"; ADR 0006 `convert_invite_claim` matches the sender against the recorded `ephemeralIdentityPk`. Inference: the personal entry needs the owner's identity signature on the commitment and a tag from the owner's ECDH.

## 4. Open sharing bugs and issues (cipher-box, 2026-09-24)

[#1870](https://github.com/FSM1/cipher-box/issues/1870) is closed (PR #1881, 2026-09-18). The diagnosis found no engine or API fault: the staging test exchanged codes in one direction; the recipient's `ShareInbox::pull` dropped the pointer with a bare `continue`; the item stays 90 days. The UX gap is #1896.

| # | title | status |
|---|---|---|
| [#1937](https://github.com/FSM1/cipher-box/issues/1937) | web: the owner gets no signal that invite claims wait for conversion | Open; conversion works only on the minting browser |
| [#1896](https://github.com/FSM1/cipher-box/issues/1896) | web: tell the recipient that a share needs the contact code of the owner | Open |
| [#1880](https://github.com/FSM1/cipher-box/issues/1880) | fix(engine): a write grantee cannot build inside the granted folder | Open until the staging writable-share profile runs green |
| [#643](https://github.com/FSM1/cipher-box/issues/643) | web: ship sharing, bin, settings, and invite views over the facade | Open tracker |
| [#635](https://github.com/FSM1/cipher-box/issues/635) | engine: rotation primitives, sweep, name wave, grants | Open tracker |
| [#1702](https://github.com/FSM1/cipher-box/issues/1702) | engine hardening track | Open |
| [#1735](https://github.com/FSM1/cipher-box/issues/1735) | engine: unproved scope boundary reads as no boundary | Open |
| [#1923](https://github.com/FSM1/cipher-box/issues/1923) | engine: interrupted name wave leaves an old name alive | Open |
| [#1920](https://github.com/FSM1/cipher-box/issues/1920) | fix(engine): failed vault-pointer vouch locks out a one-device owner | Open |
| [#1131](https://github.com/FSM1/cipher-box/issues/1131) | core: move stage-3 section authentication into crates/core | Open |
| [#1262](https://github.com/FSM1/cipher-box/issues/1262) | identity: implement ADR 0009 | Open |

## 5. Decisions a "look up the recipient key, no grantee pre-step" model contradicts

- next#34 D6: the directory is "never built"; email or handle lookup rejected.
- next#35 F-6: a server lookup cannot be the sole trust root; out-of-band authentication required before a first grant.
- next#25 D7 and next#39 D2: a plain wrapped key has no commitment entry, masked recipient or writer pseudonym.
- next#25 D1: a single folder key does not fit per-scope seeds in blinded-tag blobs.
- next#39 D1, D9, ADR 0001: the recipient checks the commitment and the mailbox sender against a contact-code-anchored key; with no recipient pre-step #1870 recurs unless the recipient also looks up the owner.
- [specs/flows/sharing-grants.md](https://github.com/FSM1/cipher-box-next/blob/main/specs/flows/sharing-grants.md) v1 trust fact 1: "a compromised relay that substitutes that key would cause the owner to wrap a fresh post-rotation key to the attacker".
- ADR 0009: rejects trusting "a server-relayed public key".
- `api.md:126` "zero-knowledge about the grant graph" (inference: a lookup tells the server the intended recipient before any share exists).
