# Staging E2E and the staging soak

The specs in this directory run against a deployed front, never in a merge
gate. This page holds the staging profiles, the soak accounts, the tool that
exports their login secrets, and the reset runbook.

Normative sources: [`blueprint/testing.md`](../../../blueprint/testing.md) and
[ADR 0053](../../../decisions/0053-the-staging-soak-signs-in-as-durable-accounts-whose-login-secrets-live-in-the-staging-scope.md).

## The staging profiles

`E2E_BASE_URL` switches the whole run onto a deployed front: no local server,
the `staging` project only, and one worker. The specs live in `staging/` and
never run in a merge gate — the `e2e` and `release` projects keep their gates,
and a red staging run is the verdict on a deploy.

```sh
E2E_BASE_URL=https://app-staging.cipherbox.cc pnpm --filter @cipherbox/web-e2e test:e2e
```

The workflow is `Staging E2E` (`.github/workflows/staging-e2e.yml`), dispatchable
with a base URL and called by `tag-staging.yml` after the deploy job.

A deployed bundle refuses the introspection hook, so these specs sign in through
a shipped method: an injected test wallet for SIWE (`wallet.ts`). Each page
holds its own key, so each spec is a fresh identity subject over an empty vault;
nothing is shared, and nothing outlives the run except the account the run
minted. The specs wait on what the chrome renders — the per-row queue mark and
the staleness rung — because no introspection hook is there to poll.

Staging rate-limits its auth surface per caller address and raises the limit
only on an undeployed profile, so the run stays serial and every spec logs in
once.

`front-contract.spec.ts` holds the two defects the v2.0.2 deploy shipped: a
record publish the browser never completes, and a read answer carrying a cache
lifetime. Two further cases answer the same requests with the broken headers and
assert the checks refuse them, so the checks cannot silently stop failing.

`media.setup.ts` writes the fixture media into `staging/.media`. The bytes are
generated and deterministic, so a read-back assertion compares against what the
upload sent and the repository carries no binaries.

`journey-timing.spec.ts` measures login-to-vault and upload-to-visible against
`baselines/staging-journey-timing.json` and writes what it measured to
`test-results/staging-journey-timing.json`, which the workflow uploads.

## The staging soak

The soak signs in as two durable wallet accounts, the soak owner and the soak
grantee (ADR 0053 D1). They are the only durable accounts on staging. Every
other staging spec mints its own accounts and removes them.

The wallet key is the durable identity. The web leg signs in with it through
SIWE. The desktop legs give the login secret to the `e2e-hook` host on standard
input (ADR 0053 D3). The login secret is the Web3Auth TSS key for the pair
verifier plus subject id, so a staging reset changes it and leaves the wallet
key valid.

The `Staging Soak` workflow is not landed yet. The steps below that dispatch it
apply when it lands.

### The four secrets

The four secrets live in the `staging` environment scope:

| Secret                      | Holds                                   |
| --------------------------- | --------------------------------------- |
| `SOAK_OWNER_WALLET_KEY`     | the soak owner's wallet private key     |
| `SOAK_OWNER_LOGIN_SECRET`   | the soak owner's login secret, 64 hex   |
| `SOAK_GRANTEE_WALLET_KEY`   | the soak grantee's wallet private key   |
| `SOAK_GRANTEE_LOGIN_SECRET` | the soak grantee's login secret, 64 hex |

### The 1Password rule

1Password is the source of truth. Each account has one item, "CipherBox Soak
Owner" and "CipherBox Soak Grantee", with two fields, `walletKey` and
`loginSecret`. A secret is set only from 1Password, through a pipe, so no value
is printed or written to disk:

```sh
op read "op://<vault>/CipherBox Soak Owner/loginSecret" \
  | gh secret set SOAK_OWNER_LOGIN_SECRET --env staging
```

The export tool prints a value once to the terminal, for the copy into
1Password. Never redirect its output to a file; the tool refuses a file on
standard output.

### The account rules

- The soak never enrolls a recovery phrase or any other factor on either
  account, and never removes either account (ADR 0053 D4). No code guard
  enforces this. The nightly sign-in from an empty profile is the proof: an
  account with a factor stops at the required-share step, and the run fails.
- A scheduled run that finds no `soak/` folder or no manifest fails with the
  reason "unbootstrapped or wiped" and writes nothing.
- The bootstrap runs only when the soak is dispatched with the input
  `bootstrap`. If a `soak/` folder exists, the bootstrap renames it to
  `soak-archived-<date>` and starts a new ledger.

### What a wedge is

A wedge is a state where the account itself can no longer serve the soak:

- The sign-in stops. A recovery phrase was enrolled, or the staging DB was wiped
  or the verifier changed, so the stored login secret no longer opens the vault.
- The vault does not carry the ledger. The sign-in works, but the vault is empty
  or the manifest cannot be parsed after a bad write.

A failed soak assertion is not a wedge. It is a defect in the product or in
staging, and it gets a diagnosis.

## Export a login secret

`tools/exportLoginSecret.ts` signs in to staging as one wallet and prints its
login secret: the SIWE challenge and signature, the identity token from the
API, then Web3Auth Core Kit in Node through `loginWithJWT`, `commitChanges` and
`_UNSAFE_exportTssKey`. It writes nothing to disk, and it prints diagnostics to
standard error only.

Set the staging configuration first. These values are public:

```sh
export VITE_API_URL="$(gh variable get API_URL --env staging)"
export E2E_BASE_URL=https://app-staging.cipherbox.cc
export VITE_WEB3AUTH_CLIENT_ID="$(gh variable get VITE_WEB3AUTH_CLIENT_ID --env staging)"
export VITE_WEB3AUTH_VERIFIER="$(gh variable get VITE_WEB3AUTH_VERIFIER)"
```

`E2E_BASE_URL` names the SIWE domain. The API accepts only a domain in its
`CORS_ALLOWED_ORIGINS`.

Export the login secret of a stored wallet. The tool reads the key from standard
input and prints the secret alone. Standard input is the preferred input:

```sh
op read "op://<vault>/CipherBox Soak Owner/walletKey" \
  | pnpm --filter @cipherbox/web-e2e exec tsx tools/exportLoginSecret.ts --stdin
```

The tool also reads the key from `SOAK_WALLET_KEY`. Every child process of the
shell can read that variable, so `unset SOAK_WALLET_KEY` after the run.

With neither input, the tool mints a fresh wallet and prints both values once,
as `walletKey=<key>` and `loginSecret=<secret>`. A mint prints to a terminal
only:

```sh
pnpm --filter @cipherbox/web-e2e exec tsx tools/exportLoginSecret.ts
```

After a mint, put the two values in 1Password and clear the terminal
scrollback.

Use `pnpm exec`, not a package script: a script run prints a banner to
standard output. A second export of the same wallet prints the same secret.

Before the first bootstrap, check once that the web and the desktop open one
vault (ADR 0053 residual E1). Sign in on the staging web app with the owner
wallet and make a folder. Then start a desktop leg with the exported login
secret and look for that folder. No tool does this comparison.

## The reset runbook

### After a staging reset

A DB wipe or a verifier change gives each wallet a new subject id, and so a new
login secret. The wallet keys stay. Nothing is removed, because the wipe removed
the accounts.

1. Run the export tool once for each account, with the stored wallet key.
2. Put each new value in the `loginSecret` field of its 1Password item.
3. Set `SOAK_OWNER_LOGIN_SECRET` and `SOAK_GRANTEE_LOGIN_SECRET` from
   1Password.
4. Dispatch the soak with `bootstrap`.

### After a bad manifest with an intact vault

Dispatch the soak with `bootstrap`. The bootstrap archives the old folder in the
vault.

### A recovery phrase locks an account

The export tool stops on such an account with the message that the account
carries a factor policy.

1. If an operator holds the phrase, recover with it and remove the factor. The
   stored values stay valid.
2. If nobody holds the phrase, run the export tool with no key twice, once for
   each account. Put all four new values in 1Password, set all four secrets, and
   dispatch the soak with `bootstrap`. The old account stays on staging, because
   nobody can open it.
