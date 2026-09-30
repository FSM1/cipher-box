# Desktop E2E

The mounted desktop suite: a real `cipherbox-desktop` process, a real mount, a
real API, and the hermetic `/routing/v1` record store. It runs as the
`Desktop E2E (<platform>)` job in `.github/workflows/desktop-e2e.yml`.

Normative source: [`blueprint/testing.md`](../../blueprint/testing.md).

## What it covers

- `mount-lifecycle` — a headless shell starts on a dev key, mints the vault,
  projects it as a filesystem, answers a manual refresh, and gives the mount
  back on `quit`
- `write-round-trip` — a folder and a file at the mount root reach the engine
  and render at the vault root, and the file reads back the bytes that were
  written; a file written inside the folder reaches the engine, lists inside
  the folder, and leaves the root count alone; a platform-junk name is refused
  and stays out of every listing
- `conflict-outcomes` — a call that conflicts with the vault reaches the caller
  as an error and leaves the vault as it was
- `cross-client-convergence` — two mounts of one vault each serve what the
  other writes, in both directions, over the network alone
- `offline-replay` — a write taken while the API is down reads back at once on
  the instance that took it, and reaches a second instance once the API returns

The macOS, Linux, and Windows legs each run every scenario.

## How the suite logs in

There is no interactive login in CI. The `e2e-hook` build of
`cipherbox-desktop` takes `--dev-key-stdin` and `--control-file <path>`, reads
the 64 hex characters of the login secret from standard input, starts headless,
and writes `<port> <token>` to the control file. The secret crosses on standard
input rather than in an argument, because every local user can read a process
argument vector. The suite then sends `<token> <verb>` over loopback and reads one
JSON line back. The verbs are `status`, `refresh` and `quit`.

Challenge-signature login creates the account on first contact, so each
scenario's fresh 32-byte secret is a fresh, isolated vault. Two instances of
one scenario share one secret, because one secret is one vault.

`src/control.ts` holds every wire detail. A change to the endpoint moves that
one file.

## No sleeps

Every wait is `poll(probe, accept, options)` in `src/poll.ts`. It re-reads a
real signal — the control file, a `status` answer, a directory entry — and a
wait that runs out reports the last value it saw. The deadlines derive from the
CI sync timing profile in `src/profile.ts`, which mirrors
`crates/engine/src/profile.rs`.

The deadline bounds the read itself, not only the gap between two reads. A
kernel call on a mount carries no timeout of its own, so a mount that stops
answering would otherwise hold the read, and with it the whole run, to the job
cap. The wait names that read, the platform and the last value it saw, and a
wait that reads a mount takes the instance away before it reports: only the
shell going away returns a call the kernel holds.

## The two scripts

- `pnpm --filter @cipherbox/desktop-e2e run test` — the vitest unit suite over
  the pure helpers. It needs no stack, no binary and no network, so it runs
  under the merge-blocking `Desktop` area.
- `pnpm --filter @cipherbox/desktop-e2e run test:e2e` — the live orchestrator.
  The area unit-test gates run no suite that needs a live stack, so this
  one is deliberately not called `test`.

## Run it locally

1. Bring up Postgres, Kubo and the record store:

   ```sh
   docker compose -f docker/docker-compose.yml up -d postgres ipfs mock-ipns-routing
   ```

2. Apply the migrations and build the API. Do not start it — the orchestrator
   owns the API process, because the offline scenario stops it:

   ```sh
   export DB_HOST=localhost DB_PORT=5432 DB_USERNAME=postgres \
     DB_PASSWORD=postgres DB_DATABASE=cipherbox NODE_ENV=test \
     JWT_SECRET=desktop-e2e-jwt-secret THROTTLE_AUTH_LIMIT=200 \
     KUBO_API_URL=http://localhost:5001 ROUTING_V1_URL=http://localhost:3001
   pnpm --filter @cipherbox/api migration:run
   pnpm --filter @cipherbox/api build
   ```

3. Build the `e2e-hook` binary. `tauri-build` embeds the frontend, so the
   bundle must exist first. The engine reads its endpoints at compile time, so
   a built binary cannot be repointed later:

   ```sh
   pnpm --filter "@cipherbox/desktop..." run build
   VITE_ENVIRONMENT=ci VITE_API_URL=http://localhost:3000 \
     VITE_ROUTING_ENDPOINTS=http://localhost:3001 \
     VITE_READ_ACCELERATOR_URL=http://127.0.0.1:8080 \
     cargo build -p cipherbox-desktop --features e2e-hook
   ```

4. Run the suite:

   ```sh
   CIPHERBOX_DESKTOP_BINARY=target/debug/cipherbox-desktop \
     pnpm --filter @cipherbox/desktop-e2e run test:e2e
   ```

`--help` lists the options and the environment variables. `--list` names the
scenarios, and `--scenario <name>` runs one of them.

## The remote-stack mode

`pnpm --filter @cipherbox/desktop-e2e run test:soak` runs one desktop leg of
the staging soak (ADR 0053, `blueprint/deploy.md` "Scheduled tier"). It starts
no API and no Kubo. The `e2e-hook` host carries the endpoints of its build, and
the leg reads the same `VITE_API_URL` and `VITE_ROUTING_ENDPOINTS` to check the
API before it starts the host. The host signs in as the soak grantee with
`SOAK_GRANTEE_LOGIN_SECRET`, which the leg writes to its standard input only.
The leg removes every `SOAK_*` variable from the environment the host inherits.

A build without `VITE_ENVIRONMENT` runs the production timings, so every wait
polls against a budget of many 30-second ticks (`src/soak/plan.ts`). The leg
runs these steps, and each one names its own reason code:

1. `sign-in`: the API serves a login, the mount opens, the first refresh lands.
2. `ledger`: `soak/desktop/ledger.txt` opens and parses.
3. `markers`: every marker of the other legs under `soak/desktop/<leg>/`
   opens byte for byte, from the ledger lines and the folder listings both.
4. `marker write`: the marker of today goes to
   `soak/desktop/<leg>/marker-<date>.txt`, and `marker <leg> <date>` goes to
   the ledger. A second run on one day writes neither again.
5. `cold sign-in` and `marker published`: a second instance on an empty home
   serves the marker and its ledger line, so only a publish can pass.

The legs are `macos`, `linux`, `windows` and `web`. The marker bytes, the
ledger format, the reason codes and the result lines are the web soak's own
(`tests/web-e2e/staging/soak`). The leg appends its result lines to
`SOAK_RESULTS_FILE` and its summary to `GITHUB_STEP_SUMMARY`. Run it only from
the soak workflow, against staging.

## Not in this suite

Rotation under mount needs a granted scope, and the desktop facade exposes no
sharing command. The cross-client harness owns that flow.
