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
- a node the owner's **mount** creates and then deletes inside that same
  promoted root, on the device that minted no grant, read both ways at the
  owner's tab and at the grantee
- a write made at the mount while the API is away, and the tab that converges on
  it once the API is back
- the leader tab dying mid-flow: a follower is promoted, its work still reaches
  the record plane, and the mount reads it

## The leg that is not here yet

The rotation-under-mount acceptance line is the remaining scenario: the mount
moves a node out of a granted scope, and the engine rotates the scope as one
transaction with the mutation.

A move that takes a node **out of** a granted scope never publishes. The mount
applies it to its own render and reports `staleness: fresh`, `deadLetters: 0`
and no warning, while the owner's tab keeps the node inside the granted folder
and lists nothing at the root.

The promoted scope's write plane is not the cause:
`mount-write-in-promoted-scope` publishes a create and a delete inside the
granted folder on that same mount. The engine owes a scope-exit rotation for a
move that leaves a granted scope, and it does not classify the crossing that
owes it. That blocks the leg, and there is no scenario for it yet.

## A limit the offline scenario works around

A tab that cold-starts onto a vault a mount already published does not converge
on it. The offline scenario therefore holds its second host up across the
outage.

## The slice that lives elsewhere

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

2. Build the web bundle carrying the introspection hook. Clear `NODE_ENV`
   first: `vite` reads it, and `test` builds a bundle that still points at the
   dev Service Worker, which never installs from a built directory.

   ```sh
   unset NODE_ENV
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
