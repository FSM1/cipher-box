# Cross-client E2E

The marquee v2 suite: the built web artifact headless beside a mounted desktop,
both against **one** stack. It rides the desktop mounted matrix rather than a
runner class of its own, and reports as `Cross-Client E2E (<platform>)` in
`.github/workflows/desktop-e2e.yml`.

Normative source: [`blueprint/testing.md`](../../blueprint/testing.md).

## The shape of a scenario

A **host** is one login secret. The owner runs two hosts on one vault — a
mounted desktop and a browser tab — because only the browser carries a share
surface and only the mount carries a filesystem. A grantee is a second account,
so it takes a browser context of its own: two tabs of one context are one
session, not two hosts.

The **nocache manual refresh** is the only barrier. There are no sleeps: every
wait re-reads a real signal and stops on a deadline derived from the CI sync
timing profile.

## What it covers

- a grant minted in the owner's tab, claimed by a second account, converted to a
  read grant, and read back at the owner's mount across the scope cut the grant
  made
- the revocation the grantee discovers on its own next pass, and the rotation the
  owner's mount reads across
- a node the owner's tab publishes **inside** the scope root the grant promoted,
  read at the owner's own mount on one nocache pass, and at the grantee too
- a write made at the mount while the API is away, and the tab that converges on
  it once the API is back
- the leader tab dying mid-flow: a follower is promoted, its work still reaches
  the record plane, and the mount reads it

## The leg that is not here yet

The rotation-under-mount acceptance line is the remaining scenario: the mount
moves a node out of a granted scope, or deletes one from it, and the engine
rotates the scope as one transaction with the mutation.

It was blocked on the write plane of a promoted scope root. A device that did
not cut the grant proved the scope for reading and opened no write plane, so the
mount's change reached no other host. `ScopeWalk::recover_write_plane_from_pointer`
now recovers that plane from the owner-vouched scope pointer, and a proved root
that still opens no write plane reports `WritePlaneDark` rather than a silent
`fresh`. The scenario lands next, on that footing.

A related limit shapes the offline scenario: a tab that cold-starts onto a vault
a mount already published does not converge on it. The scenario therefore holds
its second host up across the outage.

One further cross-client scenario lives in the web suite rather than here:
`tests/web-e2e/tests/cross-client.spec.ts` holds the timing-profile slice the
merge-blocking `Web E2E Smoke` gate runs, which needs no mount.

## Running it locally

The suite starts the API and the preview server itself. Everything else must be
up, and both the desktop binary and the web bundle must be built.

1. Bring up Postgres, Kubo and the record store, then apply migrations and build
   the API — the steps
   [`tests/web-e2e/README.md`](../web-e2e/README.md) lists, with
   `CORS_ALLOWED_ORIGINS=http://localhost:4175`. Do **not** start the API: this
   suite owns that process, because a scenario takes it away.

2. Build the web bundle carrying the introspection hook:

   ```sh
   export VITE_ENVIRONMENT=ci VITE_API_URL=http://localhost:3000 \
     VITE_ROUTING_ENDPOINTS=http://localhost:3001 \
     VITE_READ_ACCELERATOR_URL=http://127.0.0.1:8080
   pnpm --filter @cipherbox/web run build:wasm
   VITE_E2E_HOOK=true pnpm --filter @cipherbox/web run build:bundle
   ```

3. Build the desktop binary with the e2e hook. The same four `VITE_` values must
   be set for this build: the binary reads them at compile time.

   ```sh
   cargo build -p cipherbox-desktop --features e2e-hook
   ```

4. Run it:

   ```sh
   CIPHERBOX_DESKTOP_BINARY=target/debug/cipherbox-desktop \
     pnpm --filter @cipherbox/cross-client-e2e run test:e2e
   ```

   `--list` names the scenarios and `--scenario <name>` runs one of them.

The `test` script is the unit suite over the pure helpers, which the
workspace-wide `Test` gate runs. It needs no stack.
