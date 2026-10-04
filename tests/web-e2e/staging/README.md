# Staging E2E and the staging soak

The specs in this directory run against a deployed front, never in a merge
gate. This page holds the staging profiles, the soak accounts, the tool that
exports their login secrets, and the reset runbook.

Normative sources: [`blueprint/testing.md`](../../../blueprint/testing.md) and
[ADR 0053](../../../decisions/0053-the-staging-soak-signs-in-as-durable-accounts-whose-login-secrets-live-in-the-staging-scope.md).

## The staging profiles

`E2E_BASE_URL` switches the whole run onto a deployed front: no local server,
the `staging` and `staging-link-first` projects, and one worker. The `e2e` and
`release` projects keep their gates, and a red staging run is the verdict on a deploy.

```sh
E2E_BASE_URL=https://app-staging.cipherbox.cc pnpm --filter @cipherbox/web-e2e test:e2e
```

The workflow is `Staging E2E` (`.github/workflows/staging-e2e.yml`), dispatchable
with a base URL and called by `tag-staging.yml` after the deploy job. Its two
matrix jobs run serially, even if one fails: `staging-link-first` runs the long
link-first scenario, and `staging` runs all remaining profiles. Each job has its
own retry window and uploads `staging-e2e-report-<project>`. To run one group
locally, append `--project=staging` or `--project=staging-link-first`.

A deployed bundle refuses the introspection hook, so these specs sign in through
a shipped method: an injected test wallet for SIWE (`wallet.ts`). Each page
holds its own key, so each spec is a fresh identity subject over an empty vault;
nothing is shared, and nothing outlives the run except the account the run
minted. The specs wait on what the chrome renders — the per-row queue mark and
the staleness rung — because no introspection hook is there to poll.

Staging rate-limits its auth surface per caller address and raises the limit
only on an undeployed profile, so the run stays serial.

Known Web3Auth devnet refusals, including the explicit busy-node response,
retry the same wallet within eight minutes per login, without an attempt cap.
The first retry waits 15–20 seconds; subsequent retries wait 25–30 seconds.
Jitter spreads callers out, and a wait must leave time for the next attempt.
Retries stop at the end of a run window that starts at the first login of each
job; that deadline survives Playwright worker replacement. Each Playwright
project sets its window below the hard limit of its step: 60 minutes for
each staging group under its 80-minute test step, and 220 minutes for `soak` under
the 240-minute soak step. Every later login still gets its first attempt, and
one login exhausting its allowance does not disable another's retries.
Unrecognized refusals fail immediately. These rules also apply to each web soak
job through the shared sign-in fixture.

The staging run prints a sign-in summary. It counts observed faults, including
terminal ones, and separates the per-login deadline from retries suppressed by
the job's deadline. The soak run does not print this summary.

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

The workflow is `Staging Soak` (`.github/workflows/staging-soak.yml`). The
`Staging Soak` slot of `nightly.yml` calls it with the newest
`staging-<date>-release-<n>` tag as `ref`. A dispatch takes `base-url`, `ref`
and `bootstrap`. The `ref` must be such a tag or a commit SHA, and the commit
must be on main. Every job checks out that commit, not the name. The
`base-url` must be the
`STAGING_APP_URL` variable of the `staging` environment, which is also its
default. The web leg is two jobs, `web-vault` and `web-shares`. The desktop legs
follow on macOS, Linux and Windows, one at a time. The report job joins the
result lines of every leg.

### The soak suite

The suite is in `soak/`. Only `E2E_SUITE=soak` selects it, and it needs
`E2E_BASE_URL`. The `staging` project ignores the folder.

```sh
E2E_SUITE=soak E2E_BASE_URL=https://app-staging.cipherbox.cc \
  pnpm --filter @cipherbox/web-e2e test:e2e
```

The fixtures sign in with `SOAK_OWNER_WALLET_KEY` and
`SOAK_GRANTEE_WALLET_KEY`. A missing key stops the run; the fixtures never mint
a wallet. The owner ledger is `soak/ledger.txt`, and the grantee ledger is
`soak/desktop/ledger.txt`. The first line is `cipherbox-soak-ledger 1`, and each
marker line is `<date> <marker IPNS name> <record sequence>`. A marker that the
cap moved to the bin stays as `binned <marker date> <bin date>` until its purge
is proven. `SOAK_BOOTSTRAP=true` archives an existing `soak/` folder and builds
both ledgers.

The vault checks read each name through `https://delegated-ipfs.dev` and the
engine's record read (ADR 0057). They load a WASM module built with the
`observer` feature from `SOAK_OBSERVER_WASM_DIR`. With no value, they load the
module that `pnpm --filter @cipherbox/client build:wasm-conformance` writes.

The purge check needs a saved bin retention, because bin expiry runs only on a
saved retention. The bootstrap saves the Settings form once when the vault reads
the default settings. A scheduled night writes no settings: when it reads the
defaults, it fails as `settings-unread`.

The republish check treats a validity as fresh when the EOL is more than 30
days ahead. That value copies the engine renewal threshold,
`EOL_RENEW_THRESHOLD` in `crates/engine/src/net/eol.rs`.

The share checks use two folders in `soak/`, both read links. `soak/shared`
holds one long-running link. The first night with no `shared-link` line in the
owner ledger mints it and records the line `shared-link <read epoch> <URL>`. The
dialog offers no "never" lifetime, so the mint sets a deadline 100 years ahead.
Every night the owner adds a marker and moves the markers past the newest 30 to
the bin. A fresh signed-in grantee context opens the URL, and the preview must
list the marker of the night. The preview reads through the link, not through
the person grant that an earlier night converted. The context then joins and
opens each marker in the folder, and the read epoch must stay at the recorded
value.

`soak/cycle` first revokes any grant that a failed night left. It then mints a
30-day read link. A fresh grantee context previews and joins, and it opens the
marker of the night. The owner converts the claim and revokes the grantee, and
a third context sees the link revoked.

The link URL is a bearer capability. It lives only in the owner ledger. A fact
shows the URL up to its fragment. The navigation to the link and the ledger
text in the editor use no step whose title prints them. The soak takes no
trace, screenshot or video.

The leg markers live in the grantee vault. Each leg (`macos`, `linux`,
`windows` or `web`) writes `soak/desktop/<leg>/marker-<date>.txt` with the
bytes of an owner marker of the same day, and adds the line
`marker <leg> <date>` to the grantee ledger. A mount shows no IPNS name or
sequence, so the line carries neither. A leg reads the newest 14 markers of
each other leg that the ledger or a leg folder listing names, byte for byte.
The web leg then writes its own marker and line.

The counter checks read Grafana Cloud through the Mimir query endpoint. The
base URL is `GRAFANA_PROMETHEUS_URL` without its `/push` suffix, and the basic
authentication is `GRAFANA_PROMETHEUS_USERNAME` with
`STAGING_GRAFANA_READ_TOKEN`. The republisher walks first 12 hours after the
API starts, and then every 12 hours. So each check starts only after the API
uptime covers the walks it counts: 25 hours for the two walks in 24 hours, 13
hours for the names of the last walk, and 12 hours for the other counters.
Before that, the check records a skip with the reason `post-deploy-window`. The
first reading past 25 hours records its stale-names increase in the owner
ledger as `stale-names-baseline <count>`. Until then, the stale-names check
skips, and later nights compare with that baseline.

Each marker test has a 90-minute timeout, so that a slow night fails with its
own reason code. The two ledger tests keep the 10-minute project timeout. The
share tests have 80 and 120 minutes, the grantee web leg 60 and the counter
test 30. The timeouts of the whole suite sum to 490 minutes. That is more than
the 360-minute limit of one GitHub-hosted job, so one hosted job cannot hold
every test at its full timeout.

Playwright runs the files in name order, so the ledger tests, and a bootstrap,
run before every other spec.

A workflow that splits the suite across jobs must run the jobs one after the
other, never at the same time. The owner ledger has three writers: the marker
tests, the share tests and the counter test. Each job writes its own
`soak-results.jsonl`. A report job joins those files into one before it renders
the summary.

Each check names a reason code from `soak/reasons.ts` and appends its outcome to
`test-results/soak-results.jsonl`. The summary writer prints that file as
markdown:

```sh
pnpm --filter @cipherbox/web-e2e exec tsx staging/soak/writeSummary.ts >> "$GITHUB_STEP_SUMMARY"
```

### The five secrets

The five secrets live in the `staging` environment scope. The first four are
the account secrets:

| Secret                       | Holds                                                          |
| ---------------------------- | -------------------------------------------------------------- |
| `SOAK_OWNER_WALLET_KEY`      | the soak owner's wallet private key                            |
| `SOAK_OWNER_LOGIN_SECRET`    | the soak owner's login secret, 64 hex                          |
| `SOAK_GRANTEE_WALLET_KEY`    | the soak grantee's wallet private key                          |
| `SOAK_GRANTEE_LOGIN_SECRET`  | the soak grantee's login secret, 64 hex                        |
| `STAGING_GRAFANA_READ_TOKEN` | a Grafana Cloud access-policy token, `metrics:read` scope only |

The soak sends the read token with HTTP basic authentication to the Grafana
Cloud Mimir query endpoint, to read the republisher counters. The token cannot
write metrics, and it cannot read logs or traces. 1Password is its source of
truth too (ADR 0053 D2).

### The 1Password rule

1Password is the source of truth. Each account has one item, "CipherBox Soak
Owner" and "CipherBox Soak Grantee", with two fields, `walletKey` and
`loginSecret`. A secret is set only from 1Password, through a pipe, so no value
is printed or written to disk:

```sh
op read "op://<vault>/CipherBox Soak Owner/loginSecret" \
  | gh secret set SOAK_OWNER_LOGIN_SECRET --env staging
```

Never redirect the output of the export tool to a file; the tool refuses a
file on standard output.

### The account rules

- The soak never enrolls a recovery phrase or any other factor on either
  account, and never removes either account (ADR 0053 D4). No code guard
  enforces this. The nightly sign-in from an empty profile is the proof: an
  account with a factor stops at the required-share step, and the run fails.
- A run that is not a bootstrap and finds no ledger fails with the reason
  `unbootstrapped-or-wiped` and writes nothing.
- The bootstrap runs only when the soak is dispatched with the input
  `bootstrap`. If a `soak/` folder exists, the bootstrap renames it to
  `soak-archived-<date>` and starts a new ledger.

### What a wedge is

A wedge is a state where the account itself can no longer serve the soak:

- The sign-in stops. A recovery phrase was enrolled, or the staging DB was wiped
  or the verifier changed, so the stored login secret no longer opens the vault.
- The vault does not carry the ledger. The sign-in works, but the vault is empty
  or the ledger cannot be parsed after a bad write.

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

After a DB wipe, the first sign-in runs the first-run provisioning, an
idempotent genesis publish. It makes no `soak/` folder and no ledger, so each
run fails as `unbootstrapped-or-wiped` until a bootstrap.

A staging reset does not change `STAGING_GRAFANA_READ_TOKEN`: the token belongs
to Grafana Cloud, not to the staging database.

1. Run the export tool once for each account, with the stored wallet key.
2. Put each new value in the `loginSecret` field of its 1Password item.
3. Set `SOAK_OWNER_LOGIN_SECRET` and `SOAK_GRANTEE_LOGIN_SECRET` from
   1Password.
4. Dispatch the soak with `bootstrap`.

### After a bad ledger with an intact vault

Dispatch the soak with `bootstrap`. The bootstrap archives the old folder in the
vault.

### A recovery phrase locks an account

The export tool stops on such an account with the message that the account
carries a factor policy.

1. If an operator holds the phrase, recover with it and remove the factor. The
   stored values stay valid.
2. If nobody holds the phrase, run the export tool with no key twice, once for
   each account. Put all four new values in 1Password, set the four account
   secrets, and dispatch the soak with `bootstrap`. The old account stays on
   staging, because nobody can open it.
