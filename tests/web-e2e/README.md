# Web E2E

The PR gate's smoke slice: `apps/web` driven in a real browser against a real
API, a real engine, and the hermetic `/routing/v1` record store. Wired as the
merge-blocking `Web E2E Smoke` job (`.github/workflows/web-e2e.yml`), reported
through the stable `Web E2E Smoke Result` context in `ci.yml`.

Normative source: [`blueprint/testing.md`](../../blueprint/testing.md).

## What it covers

- the front door renders every built login method
- an unauthenticated deep link is returned to the front door and lists no vault
  contents
- a cold start reaches a settled, empty vault at its root; the chrome renders
  it, and the event taps saw the snapshot that produced it
- folder create, rename, move and delete, each ending on a drained queue that
  carries no dead letter — so a write that never published fails the gate
- an upload and the file read back off the network, asserted byte for byte
- signing out returns the tab to the front door
- the settings route opens from the sidebar and names the signed-in account
- a session end — a sign-out or a forget-this-device — reaches every tab of the
  origin, and no promoted sibling re-exports a secret to cold-start a
  replacement engine with
- a folder's share dialog reads the engine's grant list, and the invite link it
  mints names the claim route, is shown once, and leaves a scope behind that
  the engine then refuses a second link on
- the contact import refuses what it cannot read, and leaving the step retires
  the refusal
- an invite link minted by one vault is claimed by a second account in its own
  browser context, and the minter converts that claim into a read grant
- a write grant made by a hand exchange of contact codes lets the recipient
  upload, create a folder and delete inside the granted folder; the owner reads
  the writes back, and the delete lands in the owner's bin
- a saved settings record reads back off the vault field by field, with the
  provider credential offered for clearing rather than shown
- two sessions carry a device approval end to end: both devices derive the same
  comparison value, an approval hands the requester the exact factor the
  approver minted, a denial and an abandon each end the rendezvous, and a
  substituted ephemeral key shows other digits and seals a factor the honest
  device cannot open
- the shipping bundle exposes no introspection hook
- the link-first flow across two owner devices (`link-first.spec.ts`), in these
  steps:
  1. device A mints a read link with the owner name on a folder of two entries
  2. the holder previews the owner and the folder, joins, and reads both entries
     through the link's keys
  3. device B converts the claim on its tick, and the holder's row turns to a
     grant
  4. a write link holder writes after device B converts, and device A reads the
     write
  5. device A revokes the write link with its joiners: the writer fails closed
     and the reader keeps access
  6. device B cuts the reader, the reader joins again through a new link that
     device A converts, and the next re-key on device B serves it (ADR 0025 D3,
     E4)
  7. the sweep on device B cuts an expired link, and its chip leaves device A

The slices split on the `@full` tag. The smoke slice keeps login, CRUD, the
session-end pair, the device approval, one share-dialog spec, the contact, write and
cross-client grant specs, and steps 1 to 3 of the link-first flow — the
bounded-minutes budget the PR gate holds. Everything above that lands `@full`,
in the main gate's whole suite.

## How the suite logs in

There is no interactive Core Kit login in CI. The `e2e` build carries the
introspection hook (`apps/web/src/engine/introspection.ts`), which hands the
engine a login secret the test generates. Challenge-signature login creates the
account on first contact, so a fresh 32-byte secret is a fresh, isolated vault —
no fixture setup and no shared state to serialize around. A test mints a fresh
secret for every account it signs in, and a device that signs in again reuses
its account's secret (`devices.ts`).

The `release` project runs the same specs' counterpart against a bundle built
**without** the flag, and asserts `window.__CIPHERBOX_ENGINE__` is absent.

## How the suite drives two devices

`device-approval.spec.ts` gives each device its own browser context: its own
engine, and its own identity key in its own IndexedDB. One context signs in and
registers as an approver; the other stays cold, which is the state of a device
that cannot yet reconstruct.

The suite drives the shipped relay client
(`apps/web/src/auth/deviceApprovalApi.ts`) from the test process rather than from
the requester's tab, so a spec can carry something other than what the requester
cut. The rendezvous binds an account to an identity subject, so the specs mint
one real identity token through the wallet method and sign the EIP-4361 message
themselves.

Every rendezvous secret stays behind the introspection seam: a tap answers with
the public transcript and, for a factor, a SHA-256 of it.

`link-first.spec.ts` signs two devices in on one account. `devices.ts` holds the
account's login secret in the test process, and each device's context reads it
through a binding, so no `evaluate` argument and no trace carries it. A device
that must not act goes offline (its tabs close), so each conversion, cut and
sweep has exactly one owner device that can run it. A holder is a device too,
so it can sign in again on a second link.

## Running it locally

Both bundles must be built before Playwright starts; the config only serves
them.

1. Bring up Postgres, Kubo and the record store:

   ```sh
   docker compose -f docker/docker-compose.yml up -d postgres ipfs mock-ipns-routing
   ```

2. Apply migrations and boot the API:

   ```sh
   export DB_HOST=localhost DB_PORT=5432 DB_USERNAME=postgres \
     DB_PASSWORD=postgres DB_DATABASE=cipherbox NODE_ENV=test \
     JWT_SECRET=web-e2e-jwt-secret THROTTLE_AUTH_LIMIT=200 \
     KUBO_API_URL=http://localhost:5001 \
     CORS_ALLOWED_ORIGINS=http://localhost:4173,http://localhost:4174
   pnpm --filter @cipherbox/api migration:run
   pnpm --filter @cipherbox/api build
   node apps/api/dist/main.js > /tmp/api.log 2>&1 &
   curl -fsS --retry 60 --retry-connrefused --retry-delay 1 http://localhost:3000/health
   ```

   The API holds the shell it runs in, so it is started in the background here
   and steps 3 and 4 continue in the same terminal. Run it in the foreground
   instead and the rest needs a second one.

   Without `KUBO_API_URL` the API refuses every hosted upload with a 503, and
   the write specs dead-letter rather than fail on an assertion.

3. Build both bundles:

   ```sh
   export VITE_ENVIRONMENT=ci VITE_API_URL=http://localhost:3000 \
     VITE_ROUTING_ENDPOINTS=http://localhost:3001 \
     VITE_READ_ACCELERATOR_URL=http://127.0.0.1:8080
   pnpm --filter @cipherbox/web run build:wasm
   pnpm --filter @cipherbox/web run build:bundle
   mv apps/web/dist apps/web/dist-release
   VITE_E2E_HOOK=true pnpm --filter @cipherbox/web run build:bundle
   ```

4. Run the suite:

   ```sh
   pnpm --filter @cipherbox/web-e2e test:e2e
   ```

   The script is `test:e2e`, not `test`: the area unit-test gates run no
   suite that needs a live stack.

Rebuild the bundle after any `apps/web` change — the suite serves `dist/`, not
a dev server.

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
a shipped method: an injected test wallet for SIWE (`staging/wallet.ts`). Each
page holds its own key, so each spec is a fresh identity subject over an empty
vault; nothing is shared, and nothing outlives the run except the account the
run minted. The specs wait on what the chrome renders — the per-row queue mark
and the staleness rung — because no introspection hook is there to poll.

Staging rate-limits its auth surface per caller address and raises the limit
only on an undeployed profile, so the run stays serial and every spec logs in
once.

`front-contract.spec.ts` holds the two defects the v2.0.2 deploy shipped: a
record publish the browser never completes, and a read answer carrying a cache
lifetime. Two further cases answer the same requests with the broken headers and
assert the checks refuse them, so the checks cannot silently stop failing.

`staging/media.setup.ts` writes the fixture media into `staging/.media`. The
bytes are generated and deterministic, so a read-back assertion compares against
what the upload sent and the repository carries no binaries.

`journey-timing.spec.ts` measures login-to-vault and upload-to-visible against
`baselines/staging-journey-timing.json` and writes what it measured to
`test-results/staging-journey-timing.json`, which the workflow uploads.
