# ADR 0001 — Bind the mailbox recipient into the sender-signature preimage

- **Status:** Accepted — implemented in FSM1/cipher-box#731 (merged)
- **Date:** 2026-07-22
- **Amends:** [#39](https://github.com/FSM1/cipher-box-next/issues/39) decision D9
  ("Mailbox payloads are sender-authenticated")
- **Implemented by:** [FSM1/cipher-box#712](https://github.com/FSM1/cipher-box/issues/712)

## Context

Decision D9 of [#39](https://github.com/FSM1/cipher-box-next/issues/39) froze mailbox
payloads as **sender-authenticated**: every item carries a sender-identity ECDSA
signature inside the HPKE seal, verified against the contact-code-anchored key, and
unauthenticated items are dropped at the mailbox. Its goal was to kill junk and
impersonation before a wasted resolve — uniform with the re-point object.

As built (`crates/core/src/payload/mailbox.rs`), the sender signs the preimage
`[MAILBOX_SIG_DOMAIN, v, senderIdentityPk, payload]`. This is domain-, version-, and
sender-bound but **recipient-agnostic**: nothing in the signed bytes ties the item to
the recipient it was sealed to.

D9's threat model covered forgery and junk, but not **cross-recipient relay lift**: a
malicious recipient R1 who HPKE-opens a valid item can extract the inner
`{payload, senderIdentityPk, senderSig}` verbatim, re-HPKE-seal it to a second recipient
R2, and R2's verify succeeds — R2 concludes the sender authored that payload _to R2_.
HPKE sealing binds the ciphertext to a recipient at the AEAD layer, but the **signed
inner blob** carries no such binding, so it survives a reseal. The untrusted API alone
cannot mount this (it cannot open R1's seal); the attacker must be a malicious recipient,
which bounds impact — but "I received a validly-signed item" implying "the sender
addressed it to me" is a latent confused-deputy footgun for any higher layer that treats
mailbox delivery as addressing (grant hand-off, share pointers).

## Decision

Add the recipient's X25519 encryption public key to the sender-signature preimage:

```text
[MAILBOX_SIG_DOMAIN, v, recipientEncPk, senderIdentityPk, payload]
```

The sealer already holds `recipientEncPk` (it seals to it); the opener derives it from
its own recipient secret and recomputes the same preimage. A relayed item reaches R2
with a signature over R1's key, so R2's recomputed preimage differs and verification
fails closed as `identity-signature-invalid`.

This **strengthens** D9's sender-authentication property rather than reversing it: the
"no implicit addressing" contract is now enforced in the bytes, not left as a caller
obligation.

## Consequences

- **No wire-format or API change.** The block stays `{ct, enc}` and the inner plaintext
  stays `{payload, senderIdentityPk, senderSig}`. Only the _signed preimage_ gains a
  field; `seal_mailbox_payload` and `open_mailbox_payload` signatures are unchanged
  (the recipient key is already available on both sides).
- **Conscious KAT break.** The mailbox-accept vector
  `relay-to-other-recipient-still-verifies` — which froze the old recipient-agnostic
  property and was pre-marked in `kat_gen.rs` for removal when FSM1/cipher-box#712
  lands — is deleted and
  replaced by a mailbox-reject vector proving the relay now fails
  `identity-signature-invalid`.
- **Blueprint update.** `blueprint/core.md` "Pointer payloads — Mailbox" (maintained in
  [FSM1/cipher-box](https://github.com/FSM1/cipher-box)) is updated in the
  FSM1/cipher-box#712 code PR to state the recipient-bound preimage.
- **Domain separator unchanged.** `MAILBOX_SIG_DOMAIN` stays `cipherbox/v2/mailbox-sig`;
  the preimage array shape differs, so there is no cross-protocol collision.
- **Pre-release, no migration.** v2 is mid-build and unreleased; no deployed mailbox
  items exist to migrate.

## Alternatives considered

- **Keep recipient-agnostic, enforce at higher layers only.** Document that no mailbox
  consumer may treat delivery as addressing, and require every action-triggering payload
  to carry its own recipient binding. Rejected: leaves a sharp edge that every future
  caller must remember, when the core layer can enforce it once for free.
- **Bind recipient in the HPKE `info`/AAD instead of the signature.** The AAD already
  binds the seal to the recipient key schedule, but that protects the _ciphertext_, not
  the _signed inner blob_ that the relay lifts — it does not close the attack.

## References

- [#39](https://github.com/FSM1/cipher-box-next/issues/39) D9 — mailbox payloads are
  sender-authenticated
- [FSM1/cipher-box#712](https://github.com/FSM1/cipher-box/issues/712) — implementing
  issue
- `crates/core/src/payload/mailbox.rs`, `crates/core/examples/kat_gen.rs`
