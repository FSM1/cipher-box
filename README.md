<p align="center">
  <img src="./cipherbox logo.png" alt="CipherBox Logo" width="450"/>
</p>

<h3 align="center">Privacy-first, zero-knowledge encrypted cloud storage on IPFS</h3>

---

## What is CipherBox

CipherBox is a personal cloud storage system where privacy is structural rather than a policy
promise. All encryption happens on the client — the server never sees plaintext data, file
names, or usable keys. Encrypted content lives on IPFS and encrypted metadata on IPNS, so the
network — not CipherBox's infrastructure — is the canonical store: clients verify every record
cryptographically, and a vault remains readable and recoverable with the owner's key alone,
without any CipherBox service. Keys derive deterministically from a Web3Auth login, so the same
user gets the same vault on any device and login method.

You can store, organize, and share files and folders across a web app and a desktop app that
mounts the vault as a native drive, with multi-device sync and cryptographic revocation of
shared access.

## Project status: v2 rewrite

The system is mid-rewrite. **v2 is being built on `main`** against the blueprint corpus in
[`blueprint/`](blueprint/); v1 is frozen on branch `v1` (tag `v1-freeze`) and receives no
changes. v1 was a working technology demonstrator (staging-only, never in production) whose
TypeScript/Rust twin-engine architecture and TEE-based republishing are replaced wholesale in
v2. `main` now carries the v2 workspace skeleton, filled in slice by slice against the
blueprints — when code and blueprint disagree, the blueprints win.

## Design at a glance

- **One Rust core.** All codec, crypto, and state logic lives in two crates: `crates/core`
  (wire formats, sealing, key derivation) and `crates/engine` (the one stateful brain — sync,
  rotation, grants, trust decisions). Desktop links it natively; the web app runs the same
  crates as WASM in a worker. One implementation, one set of known-answer tests.
- **Zero-knowledge API.** The NestJS API is a thin residual surface: account registry, pin
  relay, and a grant mailbox. It stores only ciphertext and routes IPFS/IPNS operations; it
  never serves records and never holds material that could decrypt anything.
- **Seeded key hierarchy with cheap revocation.** Keys derive per _scope_ (a derivation
  domain) from a single seed via a BLAKE3 tree KDF. Sharing a folder anchors a new scope;
  revoking is an O(1) root cut that mints a fresh seed and a new _epoch_, with descendants
  re-sealed lazily by ordinary writes rather than an eager cascade.
- **Verified reads, fail-closed.** Every resolved IPNS record passes an adoption gate —
  signature, epoch, and structure checks — before the engine trusts it. A gate failure is
  treated as a trust violation, never as mere staleness.
- **Pull-only sync.** Clients poll a focus window over IPNS, cache-first, with an offline
  operation queue. No push channel in v2.0 (the seam for one is in place).
- **Keyless republishing.** IPNS records expire; a republisher module inside the API re-PUTs
  client-signed records (90-day end-of-life) without ever holding a key — v1's hardware-enclave
  (TEE) republisher is gone.

## Tech stack

| Component   | Technology                                                                                     |
| :---------- | :--------------------------------------------------------------------------------------------- |
| **Core**    | Rust — `crates/core` + `crates/engine`, compiled natively and to WASM                          |
| **Crypto**  | XChaCha20-Poly1305 sealing, BLAKE3 tree KDF, X25519 + HPKE wrapping, Ed25519/secp256k1 signing |
| **Web**     | React + TypeScript (`apps/web`), engine hosted in a worker via `packages/client`               |
| **Desktop** | Tauri v2 + FUSE mount — FUSE-T (macOS), libfuse3 (Linux), WinFsp (Windows)                     |
| **API**     | NestJS + PostgreSQL                                                                            |
| **Storage** | IPFS (Kubo) + IPNS, with self-hosted delegated routing (someguy)                               |
| **Auth**    | Web3Auth MPC Core Kit — email OTP, OAuth, external wallet                                      |

## Documentation

The normative source of truth for the v2 build lives in this repo:

| Document                                             | Purpose                                                      |
| :--------------------------------------------------- | :----------------------------------------------------------- |
| [`CONTEXT.md`](CONTEXT.md)                           | The v2 ubiquitous language — every domain term, defined once |
| [`blueprint/core.md`](blueprint/core.md)             | Wire formats, crypto, KDF catalog, known-answer tests        |
| [`blueprint/engine.md`](blueprint/engine.md)         | The engine — seam traits, sync, rotation, adoption gate      |
| [`blueprint/api.md`](blueprint/api.md)               | API residual surface, registry, mailbox, republisher         |
| [`blueprint/web-client.md`](blueprint/web-client.md) | WASM hosting, tab leadership, web client                     |
| [`blueprint/desktop.md`](blueprint/desktop.md)       | FS projection, host adapters, Tauri shell                    |
| [`blueprint/testing.md`](blueprint/testing.md)       | Suite map, CI gates, coverage policy                         |
| [`blueprint/deploy.md`](blueprint/deploy.md)         | Freeze mechanics, release management, staging pipeline       |

For researchers: the as-built v1 specification corpus, ADRs, and the complete design-decision
history behind v2 live in [FSM1/cipher-box-next](https://github.com/FSM1/cipher-box-next) —
its wayfinder map (issue 1) indexes every decision. The [`docs/`](docs/) folder here is v1
legacy and is being rewritten during the build.

## Repository layout

The v2 workspace (see the blueprints; `apps/desktop` and `tests/` land with their build phases):

```text
cipher-box/
├── crates/
│   ├── core/             # Wire formats, sealing, KDF catalog — all crypto lives here
│   ├── engine/           # The one stateful engine: sync, rotation, grants, trust
│   ├── wasm/             # wasm-bindgen bindings over the engine for the web
│   └── fuse/             # FS projection core + per-OS host adapters
├── packages/
│   └── client/           # Worker hosting for the WASM engine, browser seams, tab leadership
├── apps/
│   ├── web/              # React UI — renders engine state, forwards intent
│   ├── desktop/          # Tauri v2 shell around the natively linked engine
│   └── api/              # NestJS zero-knowledge API
├── blueprint/            # The normative v2 design corpus
└── tests/                # Cross-cutting suites, incl. the live client↔API contract suite
```

## Getting started

Prerequisites: Node.js 22+, pnpm 10+, Docker, and the Rust toolchain (pinned by
`rust-toolchain.toml`).

There are no `.env` files to copy. Every variable the stack needs is exported inline
below, so the recipe is read in the same breath as the commands that consume it.

### 1. Start the infrastructure

```bash
docker compose -f docker/docker-compose.yml up -d
pnpm install
```

That brings up Postgres (5432), Kubo (5001 RPC, 8080 gateway), someguy (8190), and the
mock record store (3001). Wait for them to report healthy:

```bash
docker compose -f docker/docker-compose.yml ps
```

### 2. Configure and start the API

```bash
export DB_HOST=localhost DB_PORT=5432 DB_USERNAME=postgres \
  DB_PASSWORD=postgres DB_DATABASE=cipherbox \
  NODE_ENV=development JWT_SECRET=local-dev-jwt-secret \
  TEST_LOGIN_SECRET=local-dev-test-secret \
  KUBO_API_URL=http://localhost:5001 \
  ROUTING_V1_URL=http://localhost:3001 \
  CORS_ALLOWED_ORIGINS=http://localhost:5173

pnpm --filter @cipherbox/api migration:run
pnpm --filter @cipherbox/api dev
```

`KUBO_API_URL` is the one the hosted pin store reads. Without it every write answers
503 — uploads and folder creates alike, since a record's head block is uploaded through
the same endpoint. The API logs an error at boot when it is unset.

### 3. Build and serve the web app

In a second shell, with the same `docker compose` stack up:

```bash
export VITE_API_URL=http://localhost:3000 \
  VITE_ENVIRONMENT=local \
  VITE_ROUTING_ENDPOINTS=http://localhost:3001 \
  VITE_READ_ACCELERATOR_URL=http://localhost:8080

pnpm --filter @cipherbox/web dev
```

- API: <http://localhost:3000> (OpenAPI at `/api-docs`)
- Web: <http://localhost:5173>

`VITE_ROUTING_ENDPOINTS` must be set: unset it defaults to the public
`https://delegated-ipfs.dev`, which will not see records this stack publishes.
`VITE_READ_ACCELERATOR_URL` is optional — left unset the content gateway stays dormant,
which is its fail-closed state, and reads fall back to the endpoints the engine already
has.

### Which record store the local stack uses

Compose starts two `/routing/v1` backends, and a local stack should use
**`mock-ipns-routing` on port 3001** — the setting above for both `ROUTING_V1_URL` (API
republisher) and `VITE_ROUTING_ENDPOINTS` (web client). It is hermetic and in-memory, so
a record published locally resolves immediately and deterministically, and no test
vault's IPNS names reach the public network. CI and the web-e2e suite make the same
choice.

`someguy` on 8190 participates in the real accelerated DHT. It is there for staging
parity and for deliberately testing public-network propagation; point the two variables
above at `http://localhost:8190` only when that is what you are testing. Both must name
the same backend, or the republisher re-PUTs into a store the client never reads.

### What this stack can demonstrate today

The API's write path is live end to end: authenticate and `POST /content/upload`
returns 201 with bytes pinned in the local Kubo.

Interactive login through the web UI needs `VITE_WEB3AUTH_CLIENT_ID` and
`VITE_WEB3AUTH_VERIFIER`, which a clean checkout does not carry — the UI boots and
renders without them, but a Core Kit session cannot be created. The suites that need an
authenticated session use the build-time introspection hook instead; see
[`tests/web-e2e/README.md`](tests/web-e2e/README.md).

A first folder create does not yet publish, because nothing provisions a fresh account's
first vault pointer, so its writes are accepted, rendered pending, and reach no endpoint.
That is the remaining gap between this stack and a full demo.

## Security model

- The server never holds plaintext data, file names, or unencrypted keys, and never serves
  IPNS records — clients resolve and verify them against the network.
- Private keys and seeds are never stored in browser storage or sent to the server.
- All cryptography is implemented once, in `crates/core`, with a frozen catalog of key
  derivations; TypeScript contains no crypto of its own.
- Sharing wraps scope seeds to recipients with X25519 + HPKE; revocation is cryptographic
  (key rotation), not access-list bookkeeping.
- Sensitive material is zeroized after use.

See [`blueprint/core.md`](blueprint/core.md) for the primitives and
[`blueprint/engine.md`](blueprint/engine.md) for the trust model.

## Acknowledgements

This project is inspired by discussions and planning while working on
[ChainSafe Files](https://github.com/chainsafe/ui-monorepo). A massive shout-out to all the
colleagues who worked on the original ChainSafe Files project.

## License

[MIT](LICENSE)
