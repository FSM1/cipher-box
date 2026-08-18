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
- the shipping bundle exposes no introspection hook

## How the suite logs in

There is no interactive Core Kit login in CI. The `e2e` build carries the
introspection hook (`apps/web/src/engine/introspection.ts`), which hands the
engine a login secret the test generates. Challenge-signature login creates the
account on first contact, so each test's fresh 32-byte secret is a fresh,
isolated vault — no fixture setup and no shared state to serialize around.

The `release` project runs the same specs' counterpart against a bundle built
**without** the flag, and asserts `window.__CIPHERBOX_ENGINE__` is absent.

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

   The script is `test:e2e`, not `test`: the workspace-wide `Test` gate runs no
   suite that needs a live stack.

Rebuild the bundle after any `apps/web` change — the suite serves `dist/`, not
a dev server.
