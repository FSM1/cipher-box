# API residual role — v2 blueprint

Resolved by [Design: API residual role and surface](https://github.com/FSM1/cipher-box-next/issues/34).
Normative for the v2 build. Upstream inputs: the
[resolution/publish](https://github.com/FSM1/cipher-box-next/issues/23),
[record liveness](https://github.com/FSM1/cipher-box-next/issues/24),
[sharing](https://github.com/FSM1/cipher-box-next/issues/25),
[rotation](https://github.com/FSM1/cipher-box-next/issues/26), and
[schema/envelope](https://github.com/FSM1/cipher-box-next/issues/27) designs;
client and contract strategy amended by the
[component decomposition](https://github.com/FSM1/cipher-box-next/issues/28)
(D5/D6).

## Doctrine

The v2 API is a **bookkeeping and accelerator service**, not a data plane. It never
serves IPNS records on any resolve path, never sees plaintext or unencrypted keys,
and holds no state a client cannot rebuild from the network plus its own vault.
Everything it does falls into five roles: authentication, pin/name bookkeeping
(quota + republish inventory), hosted content pinning, record liveness backstop,
and an integrity-untrusted mailbox.

What left the API relative to v1 — with the design that removed it:

| Gone                                                                | Removed by                                                                                                  |
| ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| IPNS publish/resolve relay endpoints                                | FSM1/cipher-box-next#23 — clients fan out `/routing/v1` PUTs directly                                       |
| Record serving from the DB                                          | FSM1/cipher-box-next#23/FSM1/cipher-box-next#24 — record cache is non-canonical, no client resolve path     |
| `/shares`, `share_invites`                                          | FSM1/cipher-box-next#25 — grants live in metadata; discovery rides the mailbox                              |
| People directory                                                    | FSM1/cipher-box-next#34 — never built; contact codes are self-authenticating                                |
| All TEE endpoints, `tee_key_state`, connection-test                 | FSM1/cipher-box-next#24 — TEE dropped, designed-for re-signer seam only                                     |
| Vault init/export endpoints, `vaults` table                         | FSM1/cipher-box-next#27 — bootstrap is the derived vault pointer; export is client-side                     |
| `pin_migrations`                                                    | BYO re-pin is a client-side sweep over its own pin set                                                      |
| Download streaming through the API process                          | FSM1/cipher-box-next#34 — reads go to the trustless gateway                                                 |
| Generated `api-client` packages and the `api:generate` codegen loop | FSM1/cipher-box-next#28 D5/D6 — one hand-written Rust client in the engine; contract enforced by live tests |

## Identity and auth

- Account = the Web3Auth-derived secp256k1 **identity key**; challenge-signature
  login. **CipherBox issues the identity token the Core Kit consumes** (FSM1/cipher-box-next#5 as
  amended by ADR 0008): each verified method mints a CipherBox JWT, and the Core Kit
  logs in against a CipherBox custom verifier over the API's own JWKS. The account
  model is unchanged by this — the Core Kit yields the same key whichever provider
  vouched.
- **Method set**: Google, passwordless email, and wallet. Passwordless email is
  CipherBox's own — the API issues and verifies the code and owns its delivery.
  Wallet is a **first-class first login on web only**: a SIWE signature the API
  verifies mints the same JWT as any other method, so it reaches the same derived
  key. It is absent on desktop because that webview reaches no wallet, which is a
  platform property rather than a deferred feature (ADR 0008).
- Google's OAuth client ID is the **provider's**, distinct from the Web3Auth project
  client ID. The two are not interchangeable.
- Short-lived access JWT + rotating refresh token (HTTP-only cookie on web,
  OS keychain on desktop). Staging-gated test-login endpoint for e2e.
- Tables: `users` (keyed by `publicKey`; carries quota-limit override and BYO flag),
  `auth_methods`, `refresh_tokens`.

## Pin/name registry

The one surface every publish flow traverses. It feeds **both** quota and the
republisher inventory; its invariant is the central v1 lesson (silent enrollment
decay) inverted into structure.

- **Endpoints**: batch register `[{ipnsName, headCid?, contentCids[]}]` and batch
  retire `[ipnsName | cid]`. Ordinary writes send single-item batches; name waves
  and sweeps send bulk. v1's BYO-only `register-cid` folds into the same register
  call.
- **Batch bounds**: both batches cap at **1000 items** (register additionally
  caps `contentCids` at 1000 per entry), enforced fail-closed with `400` before
  per-item validation and published as `maxItems` in the OpenAPI document. A bulk
  caller — a name wave, or an abandoned version whose leaves all need retiring —
  chunks to the cap; retire is idempotent, so a replayed chunk is a no-op. A
  version with more leaves than the per-entry cap registers as several entries
  under one `ipnsName`, the head riding the first; the server collapses them to
  one name row, and a bare re-register carrying no `headCid` leaves the stored
  head untouched. The refusal carries `code: REGISTRY_BATCH_REFUSED`, so a
  client classifies on the gate's own discriminator rather than on a bare `400`
  an intermediary could have answered.
- **Register-first, fail-closed**: registration precedes the first publish of a
  name, and publish is blocked on it. A live-but-uninventoried name is
  structurally impossible; the worst failure is a registered-never-published
  orphan, which the republisher's resolve-failure alert surfaces for GC.
- **Per-account rows, union liveness**: inventory row = `(account, ipnsName)`,
  pin row = `(account, cid, size)`. Whoever publishes registers under their own
  account — the server is zero-knowledge about the grant graph and authorizes
  nothing across accounts. The republisher walks **distinct** names; a name
  leaves the inventory when its last row is retired; physical unpin fires at
  global refcount zero (v1's `guardedUnpin` survives).
- **Shared scopes**: a write-grantee's uploads register (and count) under the
  grantee's account until the owner's client syncs, sees the new children, and
  registers them too — rows then coexist. Self-healing, permissionless.
- **Quota**: per-account sum over that account's pin rows. Hosted rows are
  authoritative and gate uploads; BYO accounts' rows are **advisory** (quota
  always allows, `advisory: true` in the quota response). Limit = env default
  plus per-account override column; no billing (out of scope).
- **Accepted exposure**: the server sees each account's flat name/CID counts,
  sizes, and churn timing — never tree structure, kinds, or names' relationships.

### Write-rotation name churn

- New names enroll automatically: the wave's publishes traverse register-first.
- Content CID rows are untouched by rotation (same CIDs re-referenced; upserts
  are idempotent). Old + new metadata head CIDs transiently double-count —
  metadata-scale only, accepted.
- **Interior fast, root lingers**: interior old names are batch-retired at wave
  completion (a resumed wave enumerates them via the write-plane history link).
  The old **scope-root** name stays registered, serving the owner-signed
  `movedTo` forwarding record, until the migration window closes — window
  length and closure signal are owned by
  [rotation completeness (FSM1/cipher-box-next#38)](https://github.com/FSM1/cipher-box-next/issues/38)
  — then retired. The API stays dumb: retire removes the caller's row; timing is
  client policy.

## Content plane

- **Provider layer, registration always** (BYO-IPFS is first-class, carried from
  v1): the client's pin-provider abstraction decides where bytes go — hosted
  (default), external (own Kubo/PSA/Pinata endpoint), or dual. Every mode's
  publish flow still traverses the registry above; only the byte path varies.
  `ByoIpfsConfig` stays sealed in vault settings; provider connection testing is
  client-side (the TEE tester is gone).
- **Ingress (hosted)**: authenticated upload endpoint, quota-gated, pins to
  CipherBox Kubo, registers pins in the same traversal. BYO/dual bytes bypass
  the API entirely.
- **The caller declares the address.** `POST /content/upload` carries the
  client's own content address for the body in an `X-Content-Cid` header — a
  header, not a query parameter, because content addresses correlate across
  accounts and edge proxies log request URLs; they stay out of the URL plane just
  as the registry's `contentCids` stay inside JSON bodies. The API pins under
  exactly that CID and computes none of its own. It writes the block under the
  declared CID's multicodec (`raw` for sealed leaves, `dag-cbor` for DAG roots
  and record heads) with a BLAKE3-256 multihash, and refuses — **400,
  permanent** — when the store addresses the bytes differently or the declared
  CID is not one of those two frozen shapes. Kubo's re-derivation is what binds
  bytes to CID; the declared string is only a routing hint until it matches.
  Without this the ingress addresses blocks by its own UnixFS chunking, every
  published record points at a CID the accelerator does not hold, and the
  engine's head-CID check fails closed forever.
- **One request, one block.** The declared CID takes the per-CID advisory lock
  and keys the pin row, so a refusal compensates the row exactly as a pin failure
  does — and every path that will not pin the block **removes** it, since an
  unpinned block is not reclaimed and a refused upload must not grow the
  datastore off the quota's books. The transport cap is the block ceiling
  (`block/put` refuses over 2 MiB), so an over-size body is a permanent 413 here
  rather than a retryable pin-store failure. Blocks are pinned **direct**, not
  recursive: every block is uploaded and registered individually, and a recursive
  pin would make repo GC walk sealed bytes it cannot interpret.
- **Egress**: the API process serves no bytes. CipherBox runs a Kubo-backed
  **trustless gateway** (block/CAR responses, client-side CID verification)
  gated by a CipherBox auth token — an accelerator for members. Any public
  trustless gateway is the no-auth fallback; reads survive CipherBox infra loss.
  Media streaming uses ranged block/CAR fetches through the existing
  service-worker decryption layer.

## Republisher module and recovery

Per the liveness design (FSM1/cipher-box-next#24), restated here as API surface:

- In-process, worker-shaped, cleanly extractable module. Walks distinct
  inventory names on a ~12 h cadence: resolve from the network, re-PUT the same
  bytes (keyless). Alert when a name goes >24 h without a successful re-PUT.
- Non-canonical record cache table — rebuildable from the network, consulted by
  no client resolve path; refuses sequence-regressing records as
  unrelied-upon depth.
- **Recovery endpoint**: authenticated, rate-limited fetch of cached (possibly
  expired) record bytes by name — the revival aid after a >EOL lapse; a
  key-holder extracts the last CID and mints a fresh record.

## Mailbox

Integrity-untrusted, swappable transport for one-shot sealed pointers
(share pointers, write-rotation root re-points, invite claims, courtesy
notifications). Nothing on it is load-bearing for safety: root migration has
the `movedTo` record (FSM1/cipher-box-next#38), revocation is discovered in metadata.

- **Post**: any authenticated account → recipient identity pubkey; body is the
  HPKE-sealed blob (≤ ~8 KB), sender supplies an idempotency key. Posts to
  unknown recipient pubkeys are rejected — an accepted, rate-limited,
  exact-pubkey existence oracle.
- **Poll**: recipient-authenticated; returns `{id, receivedAt, blob}` — no
  sender metadata in the clear (the sealed payload is owner-signed inside).
  Clients poll on the sync design's 30 s cadence; no push in v2.0 (push-ready
  seam per FSM1/cipher-box-next#33).
- **Ack**: delete by id. Retention: until acked, bounded — per-recipient
  pending cap (reject-new when full) and a 90-day unacked TTL aligned with
  record EOLs. Rate limits per sender account and per recipient mailbox.
- **Accepted exposure**: transient `{sender, recipient, timestamp}` edges;
  never a durable graph, never key material.

## Contact exchange — no directory

There is **no people directory**. This supersedes the sharing design's
directory component (FSM1/cipher-box-next#25) and resolves crypto-review finding F-6 structurally:

- A **contact code** (QR / URL / pasted string) carries the self-authenticating
  bundle `{identityPk, encSubkey, bindingSig}` (~130 bytes). The engine verifies
  the binding signature against the carried identity key at import,
  **fail-closed and mandatory**. Invite URLs carry the owner's bundle the same
  way.
- Identity keys therefore only ever arrive out-of-band — there is no in-band
  lookup for a directory substitution attack to poison. Optional
  fingerprint-comparison UX remains available client-side for channel-MITM
  paranoia, but no server component is involved.

## Account lifecycle

- Accounts are created implicitly at first login; there is no vault-init
  endpoint — the first publish of the pointer and root rides the normal
  register-first flow.
- **Deletion: immediate hard-delete.** One authenticated call, client-confirmed;
  cascade: retire all inventory/pin rows (refcounted physical unpin), purge
  mailbox rows, delete auth rows. Sole-registered names stop being republished
  and decay from the DHT (~48 h); co-registered shared content survives via
  other accounts' rows. Nothing lingers server-side; keys still derive from the
  login secret, so a BYO self-hoster loses nothing they pin themselves.

## Contract and clients

Decomposition outcomes (FSM1/cipher-box-next#28 D5/D6), restated here as API surface:

- **The spec is server-owned.** The NestJS API keeps emitting its OpenAPI
  document from decorators, committed as a review/docs artifact. It is
  documentation, not a build input.
- **No generated clients, anywhere.** The sole first-party consumer is the
  engine's single hand-written Rust client (engine.md); v1's generated
  `api-client` packages, the `api:generate` loop, and the staged-client
  pre-commit check all die with it.
- **Enforcement is live, not lexical.** The contract is enforced by the live
  contract-test suite — the engine's client exercised against a real API
  instance in CI, the sdk-e2e descendant. Drift between server behavior and
  client expectation fails a test run, not a grep or a codegen diff. Suite
  shape and gating are owned by
  [`blueprint/testing.md`](testing.md).

## Ops

Health endpoint; Prometheus metrics; a **working** global throttler with
per-surface limits (v1's inert `@Throttle` decorators are a named defect —
rate limiting must be verified effective in e2e); staging test hooks
(test-login) gated by environment.

## Data model (complete)

`users`, `auth_methods`, `refresh_tokens`, `name_inventory (account, ipnsName)`,
`pinned_cids (account, cid, size, advisory)`, `mailbox_messages`,
`record_cache` (non-canonical). Nothing else. No crypto-bearing rows outlive
their consumer; revocation-adjacent state is hard-deleted, never soft-flagged.

## Hosted infra outside the API process

- **someguy** — self-hosted `/routing/v1` delegated routing accelerator
  (resolve + publish target; public endpoints are fallback).
- **Kubo** — pin store and the token-authed trustless gateway.

Nothing breaks if either vanishes: resolution falls back to public endpoints,
reads to public gateways, and the republisher is a liveness optimization, not a
correctness dependency.

## Open edges

- `movedTo` migration-window length and closure signal (drives when the old
  scope-root name is retired) → [FSM1/cipher-box-next#38](https://github.com/FSM1/cipher-box-next/issues/38).
- Module boundaries are fixed by
  [FSM1/cipher-box-next#28](https://github.com/FSM1/cipher-box-next/issues/28) D3 (NestJS residual
  surface + in-process, extractable republisher module); the gateway/someguy
  deployment shape →
  [deployment blueprint (FSM1/cipher-box-next#48)](https://github.com/FSM1/cipher-box-next/issues/48).
