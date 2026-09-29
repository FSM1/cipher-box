# ADR 0058 — The identity subject binds to the account at login, and a device registration reads the bind

- **Status:** Accepted on 2026-09-29
- **Date:** 2026-09-29
- **Relates to:**
  [ADR 0039](./0039-a-device-key-registers-to-one-account-and-desktop-only-requests-approval.md)
  D1 (`identity_subjects` holds no account), D3 (one identity subject reaches at most one
  account) and E4 (a leaked identity token lets another account claim a member's subject first),
  [ADR 0008](./0008-cipherbox-issues-the-identity-token.md) D1 (CipherBox issues the identity
  token), [ADR 0009](./0009-device-approval-is-a-bound-rendezvous.md) D3 (the comparison value)
  and D4 (device keys sign both halves), and the `blueprint/api.md` section "Identity and auth"
- **Implemented by:** not built; one later slice under FSM1/cipher-box#2012. The spend at
  registration landed with FSM1/cipher-box#2092.
- **Amends:** ADR 0039 D2

## Context

The account is the secp256k1 identity key, and the engine adopts the Core Kit export as that
key. `POST /auth/login` takes a public key, a challenge and a signature, and no identity token.
So the API learns the identity subject of an account only when a device registers, and it cannot
compute the key that a subject derives. A registration therefore cannot tell a member's own
identity token from a leaked one: an account with a full session and another member's unspent
token claims that member's subject first (ADR 0039 E4). The spend of FSM1/cipher-box#2092 stops
a replay of a spent token, not the first claim. The claim stays open from the mint to the
member's first registration, which can come days after the sign-in, or never.

## Decision

**D1 — `users.identity_subject_id` holds the one identity subject of an account.** The column is
nullable, unique, and a foreign key to `identity_subjects`. The bind writes it once, nothing
rewrites it, and the account hard delete removes it with the row. It holds the subject id only:
no hash and no display form of the provider identifier. One account holds one subject, because
the Core Kit derives the key from the pair (verifier, subject): a second subject derives a
second key, which is a second account. A method link points another provider identity at the
same subject (ADR 0039 D1), so the rule refuses no real method. `identity_subjects` still holds
no `user_id`.

**D2 — A login that follows an identity exchange presents the identity token, and binds an
unbound account to an unbound subject.** `POST /auth/login` takes an optional `identityToken`,
which the API verifies as a registration does. A token that does not verify refuses the login
with 401. When the account and the subject are both unbound, the login writes the bind in the
transaction that creates or touches the account, under the subject lock that registration also
takes. When either one is already bound elsewhere, the login proceeds and changes no bind. A
start that follows no exchange presents no token and binds nothing: a restored Core Kit session,
a desktop relaunch, and the staging-gated test-login.

**D3 — A device registration reads the bind.** The API refuses a registration from an unbound
account, and a registration whose identity token names a subject other than the bound subject.
Both refusals answer 409 and write nothing. The row records the bound subject. The registration
still spends the token.

## Alternatives considered

- **Keep the claim at registration, as ADR 0039 D2 built it.** The claim stays open until the
  member's first registration, and a member who never registers keeps a claimable subject.
- **Refuse a registration whose subject differs from the subject of the account's devices.** An
  attacker makes a new account with no device, so the check never fires.
- **A `user_id` on `identity_subjects`, or a separate bind table.** ADR 0039 alternative (b)
  rejects the first. A table earns its place only for many subjects per account, which D1 rules
  out.
- **A hash of the subject id in place of the id.** A database reader hashes every subject id and
  joins. It hides nothing, and it loses the foreign key.
- **Bind the token to the login key at mint, as a claim with the hash of the public key.** The
  login key is the Core Kit export, which exists only after `loginWithJWT` redeems the token. At
  mint the API knows the subject and nothing of the key.
- **The login signature covers the token's `jti`.** That proves the signer held the token, not
  that the token's subject derives the signer's key. An attacker signs with an own key.
- **Refuse the login when the subject is bound to another account.** A member who lost the
  first-claim race is then locked out of the vault, not only out of device registration.
- **Spend the token at login.** The web presents one token at login and then at registration, so
  every registration would fail. The unique bind already makes the token useless at every other
  account.

## Consequences

1. `blueprint/api.md` "Identity and auth" gains the bind, the login rule and the registration
   rule in the slice that builds them. This PR adds only the single-use line, which is true today.
2. `blueprint/api.md` "Data model (complete)" names the `users` column in the same slice.
3. `POST /auth/login` takes the optional `identityToken`, and `POST /devices` gains the two 409
   refusals. The OpenAPI document carries both.
4. The engine API client sends the optional token in `login_identity`, and the engine start
   command takes it as an optional parameter.
5. `packages/client` carries the optional token from the facade start to the worker.
6. `packages/login` hands the token of the identity credential to the start that follows an
   exchange, and no token to the start of a restored session.
7. `apps/web` registers only in a sign-in that holds the token, as it does today. `apps/desktop`
   carries the optional token in its Tauri start command beside the raw secret.
8. The contract suite proves the bind at the first login, no rebind on a conflict, and both
   registration refusals. The web e2e device-approval legs sign in through an exchange.
9. Single use: a registration spends the token by its `jti` in `spent_identity_tokens`, which
   holds the `jti` and the expiry only. Login does not spend it. `POST /device-approval/session`
   accepts it more than once.
10. The token lifetime stays 300 seconds. A spent row lives until its token expires, plus a grace.
11. No backfill: an existing account stays unbound until its next login that follows an
    exchange, and until then its registrations are refused. The rendezvous session still maps a
    subject to an account through `account_devices`.
12. Privacy: today the API links an account to a subject, and so to the unsalted hash of its
    provider identifier, only when a device registers. After the bind it links every account that
    signs in through an exchange.
13. ADR 0039 D1 holds as written. ADR 0039 E4 narrows to the window before the member's bind.

## Residuals

**E1 — Should the identity token bind at mint to a key that the client holds before the mint?**
The bind does not close the first-claim race. An attacker with a leaked, unspent token who logs
in with a fresh key before the member does binds the member's subject. The member's account then
stays unbound and cannot register a device, and no key is disclosed. The window shrinks from
"until the first registration" to the seconds between the mint and the member's first login.
For an account that existed before the bind, it lasts until its next login through an exchange.
A proof-of-possession claim, checked by a signature at login and at registration, closes it for
a leaked token string. The web holds a device identity key before reconstruction (ADR 0009 D4);
desktop holds none (ADR 0039 E1). The owner decides whether to close it, and with which key.

**E2 — How does a member whose subject is bound to another account recover?** D1 never rewrites
a bind, and no unbind path exists. The owner decides whether an operator unbind exists, and what
proves the member to the operator.
