# Desktop E2E

The mounted desktop suite: a real `cipherbox-desktop` process, a real mount, a
real API, and the hermetic `/routing/v1` record store. It runs as the
`Desktop E2E (<platform>)` job in `.github/workflows/desktop-e2e.yml`.

Normative source: [`blueprint/testing.md`](../../blueprint/testing.md).

## What it covers

- `mount-round-trip` — one instance writes a folder and a file through its
  mount, the mount serves the same bytes back, and the root renders the folder
- `cross-client-sync` — two instances of one host share one vault; A writes, B
  refreshes with nocache, and B reads the bytes A wrote. This is where the
  suite proves a publication: B holds its own engine and reads the network
- `conflict-outcomes-at-the-mount` — the outcomes the projection renders: a
  duplicate name, a case twin, a Unicode-normalization twin, a platform-junk
  name, and a rename that replaces a file atomically
- `offline-replay` — the orchestrator stops the API; the mount still acks a
  write, the staleness ladder reaches `offline`, and the write reaches the
  other instance after the API returns

The payload is multi-byte and multi-line, so no transfer that mangles either
passes.

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

## The two scripts

- `pnpm --filter @cipherbox/desktop-e2e run test` — the vitest unit suite over
  the pure helpers. It needs no stack, no binary and no network, so it runs
  under the merge-blocking workspace `Test` gate.
- `pnpm --filter @cipherbox/desktop-e2e run test:e2e` — the live orchestrator.
  The workspace-wide `Test` gate runs no suite that needs a live stack, so this
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

## Not in this suite

- **Rotation under mount.** It needs a granted scope, and the desktop facade
  exposes no sharing command. The cross-client harness owns that flow.
- **The Windows leg.** The shell does not project through the WinFsp adapter
  yet, so no Windows process can mount.
