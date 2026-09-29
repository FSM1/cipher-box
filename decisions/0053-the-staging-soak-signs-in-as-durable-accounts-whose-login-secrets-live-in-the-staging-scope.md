# ADR 0053 — The staging soak signs in as durable accounts whose login secrets live in the staging scope

- **Status:** Accepted on 2026-09-29
- **Date:** 2026-09-27
- **Relates to:**
  [ADR 0008](./0008-cipherbox-issues-the-identity-token.md) (CipherBox issues the identity token;
  wallet login is web-only, D2),
  [ADR 0039](./0039-a-device-key-registers-to-one-account-and-desktop-only-requests-approval.md)
  D1 (the identity token's subject id is the `verifierId` that `loginWithJWT` takes, so the login
  secret is the Web3Auth TSS key for the pair verifier plus subject id),
  [ADR 0049](./0049-each-suite-proves-what-it-claims-and-no-test-seam-ships.md) D3 (a staging or
  production build refuses the e2e hook), and
  [ADR 0006](./0006-owner-local-sealed-store.md) (owner-local stores ride the host staging seam,
  so an empty profile starts without them)
- **Implemented by:** the staging soak build, not landed. The wayfinder map is
  [FSM1/cipher-box#2047](https://github.com/FSM1/cipher-box/issues/2047), and the build slice is
  [FSM1/cipher-box#2042](https://github.com/FSM1/cipher-box/issues/2042)
- **Amends:** none

## Context

The nightly staging soak must prove, across days and from a cold client, three things: the vault
of an end user on staging still opens, names still resolve after the republisher took over, and a
share made one day still reads the next day. That needs the same account night after night, on
the web and on three desktop legs. On the web, a wallet private key signs in through SIWE, and
Web3Auth reconstructs the login secret. The desktop reaches no wallet (ADR 0008 D2), has no device
approval built, and its `e2e-hook` host takes the 32-byte login secret on standard input. No code
path exports the login secret from a signed-in session. The secret is the Web3Auth TSS key for the
pair verifier plus subject id (ADR 0039 D1), not a derivation of the wallet signature.

## Decision

**D1 — The soak signs in as two durable wallet accounts.** An operator mints the soak owner and
the soak grantee once. They are the only durable accounts on staging. Every other staging spec
mints its own accounts and removes them.

**D2 — An operator tool exports each login secret once, into the `staging` environment scope.**
The tool runs Web3Auth Core Kit in Node against the staging verifier with the wallet key: the SIWE
challenge, the identity JWT from the API, `loginWithJWT`, `commitChanges`, and
`_UNSAFE_exportTssKey`. The login secret is held as a secret in the `staging` environment scope,
beside the wallet key. There are four secrets: `SOAK_OWNER_WALLET_KEY`, `SOAK_OWNER_LOGIN_SECRET`,
`SOAK_GRANTEE_WALLET_KEY` and `SOAK_GRANTEE_LOGIN_SECRET`. 1Password is the source of truth. The
tool prints a value once and never writes it to disk.

**D3 — The web leg signs in with the wallet key, and the desktop legs with the login secret.**
A desktop leg gives the login secret to the `e2e-hook` host on standard input. That host is built
for the soak from the staging tag, with the hook feature on. The shipped desktop bundle never
carries the hook.

**D4 — The soak accounts never enroll a factor, and the soak never removes them.** Neither account
enrolls a recovery phrase or any other factor. No code guard enforces this. The nightly sign-in
from an empty profile is the proof, because an enrolled factor stops a fresh context at the
required-share step.

**D5 — A staging reset keeps the wallet keys and re-exports the login secrets.** After a reset, a
wallet maps to a new subject id and so to a new login secret. The operator re-exports the two
login secrets only. New wallets are minted only when an enrolled factor that nobody holds locks an
account.

## Alternatives considered

**(a) Desktop device approval (ADR 0009).** Rejected. The desktop requester is not built, and the
path needs a registered device and a factor policy.

**(b) A separate desktop account from the staging `test-login` endpoint.** Rejected. It is a
different account, so the desktop and the web do not open one vault, and the shipped web bundle
cannot sign in to it.

**(c) No desktop legs.** Rejected. The soak loses the cross-platform proof.

**(d) A secret export control in the product.** Rejected. It is a permanent export path, in the
build of every member, for the one value that the architecture exists to protect.

## Consequences

1. **`blueprint/deploy.md` changes.** "Scheduled tier" gains the Staging Soak slot.
2. **`blueprint/testing.md` changes.** Law 1 and the dispatch and scheduled row name
   `Staging Soak`.
3. **`blueprint/web-client.md` changes.** "Composition" states the IPNS name row in the details
   dialog and the epoch row in the share dialog. The soak reads the name and the epochs from
   product surfaces, never from a hook (ADR 0049 D3), and reads the record sequence by resolving
   that name through the public routing path.
4. **`tests/web-e2e/staging/README.md` is new.** It carries the account rules and the reset
   runbook.
5. **The soak issue body changes.** It is rewritten to the settled design.

## Residuals

**E1 — A Node export was not compared with a browser export of the same wallet.** The sources say
that the two must match.

**E2 — The desktop legs and device approval.** The owner decides whether the desktop legs move to
device approval when the desktop requester lands.
