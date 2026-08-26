# Web client — v2 blueprint

Resolved by [Blueprint: web client](https://github.com/FSM1/cipher-box-next/issues/45).
Normative for the v2 build. Upstream inputs: the
[component decomposition](https://github.com/FSM1/cipher-box-next/issues/28)
(D3–D5), the
[sync/refresh/offline](https://github.com/FSM1/cipher-box-next/issues/33)
design, and the seam contracts and facade law in
[`blueprint/engine.md`](engine.md); the
[feature set](https://github.com/FSM1/cipher-box-next/issues/5) fixes what
ships. This doc covers the three web-side units of the FSM1/cipher-box-next#28 D3 layout —
`crates/wasm`, `packages/client`, `apps/web`. Where the engine blueprint
already fixes behavior (adoption gate, sync core, rotation, grants, API
client), this doc adds only the browser hosting around it, never a second
copy of it.

## Doctrine

The web client is a **thin shell around the worker-hosted engine**:
`crates/wasm` compiles core + engine to one WASM artifact, `packages/client`
hosts that artifact in a dedicated worker and implements every browser seam,
and `apps/web` renders engine state and forwards intent. Every trust decision
already happened below the facade (engine.md); the UI renders, it never
decides. Key material exists only inside the engine worker's WASM memory —
nothing key-shaped ever crosses the facade, structurally rather than by
discipline. There is exactly **one engine instance per origin** (FSM1/cipher-box-next#28 D4): the
leader tab hosts it; every other tab is a thin mirror.

What dies relative to v1 — with the design that killed it:

| Gone                                                                                                                   | Killed by                                                                                                                                             |
| ---------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| Zustand `folderTree` mirror, the `children`/`rawChildren` two-plane split, sequence-clock store guards                 | FSM1/cipher-box-next#33 D6 — snapshot ⊕ pending-op overlay computed in the engine; the UI is a projection with no independent writers                 |
| Three ad-hoc freshness legs (nav re-resolve, root-only 30 s poll, post-upload refresh) and the `forceResolve` foot-gun | engine sync core + event stream; the UI only asks the engine to refresh                                                                               |
| Web-side crypto: ShareDialog ECIES, invite key wrapping, the encrypt Web Worker, download decrypt in services          | FSM1/cipher-box-next#28 D1 — TS keeps no engine logic; grants live in metadata                                                                        |
| Generated `api-client` axios singleton, web-side token injection/refresh                                               | FSM1/cipher-box-next#28 D5 — the engine's hand-written API client owns the token lifecycle                                                            |
| Kind resolution maps (`isFileRefResolved`), kind-blind refs, folder-safe defaults                                      | FSM1/cipher-box-next#27 D7 — `kind` is an immutable field of the child ref                                                                            |
| `'root'` sentinel + `ipnsName` route params and store keys                                                             | FSM1/cipher-box-next#27 D9 + FSM1/cipher-box-next#26 D3 — names rotate; routes and identity key on the stable node id                                 |
| Rotation driver, job checkpoints, badge state machine, Web Locks rotation lock                                         | FSM1/cipher-box-next#26 D8 — no job records; tab leadership subsumes the lock                                                                         |
| The per-depth shared-nav state machine and its manual key zeroization choreography                                     | keys never enter JS; shared scopes are ordinary snapshot state                                                                                        |
| In-memory floor fallback + degraded-cache toast (v1 D-08)                                                              | FSM1/cipher-box-next#26 D4 / FSM1/cipher-box-next#39 D4 — FloorStore is required; the cold-seed floor law makes a wiped store staleness, not exposure |
| The decrypt Service Worker as a crypto layer, CTR streaming                                                            | chunk-sealed content gives native random access; the SW is demoted to a dumb byte pipe                                                                |
| MiniSearch encrypted index, search palette                                                                             | FSM1/cipher-box-next#5 — client-side search deferred, designed-for                                                                                    |

## Component map

- **`crates/wasm`** — wasm-bindgen bindings over `engine` (which links
  `core`): the facade's commands and event stream, plus the generated TS
  types. No logic of its own.
- **`packages/client`** — everything between the WASM boundary and React:
  engine worker lifecycle, tab leadership, the two facade transports, every
  browser seam implementation (IndexedDB, OPFS, `fetch`), the login handoff,
  and the Service Worker brokerage. It wraps the facade, never extends it
  (engine.md facade law); it holds no vault semantics.
- **`apps/web`** — React 18 + Vite SPA (FSM1/cipher-box-next#28 D7 — the repo's existing web
  toolchain, edited in place): routes, views, dialogs over facade state. No
  crypto, no seams, no tokens, no direct WASM imports — its only vault-facing
  dependency is `packages/client`.

## WASM packaging and the type boundary

- **One artifact**: `crates/wasm` builds a single wasm-bindgen module
  exposing the engine facade (core is linked inside; nothing exports core
  directly to JS). Built as an ES module, dynamically imported inside the
  engine worker; Vite fingerprints and serves it immutable. Single-threaded —
  no wasm threads or SharedArrayBuffer in v2.0; the worker already keeps all
  engine work off the UI thread.
- **Types are generated, not hand-mirrored**: the wasm-bindgen `.d.ts` output
  is the boundary contract; `packages/client` re-exports those types through
  its facade proxy. No hand-maintained TS mirror of engine structures — the
  v1 twin-type drift class has no home to grow in.
- **Boundary hygiene**: IPNS sequence numbers and sizes cross as `bigint`;
  binary payloads cross as transferred `ArrayBuffer`s (UI→worker) or `Blob`
  handles (cross-tab). The WASM KAT run in CI covers the `u64`/BigInt and
  getrandom boundary risks (core.md); `getrandom`'s JS backend wires to
  `crypto.getRandomValues` in the worker scope.
- **Memory hygiene**: key material lives in WASM linear memory inside core's
  `Zeroizing` types. The facade's event/query surface exposes no key bytes by
  construction, so UI-thread JS never holds a key; the login secret is the
  single inbound exception (below).

## Engine hosting and tab leadership

One long-lived engine instance in a dedicated module worker, hosted by the
**leader tab** (FSM1/cipher-box-next#28 D4). Leadership and failover (engineering judgment on the
mechanism; the invariant — one engine writer per origin — is D4's):

- **Election**: every tab's `packages/client` requests an exclusive Web Lock
  (`cipherbox-engine`). The holder is the leader: it spawns the engine worker
  and runs everything — sync ticks, background jobs, the op-queue drain,
  publishes. Web Locks auto-release on tab close, crash, or discard, which is
  exactly the failover primitive needed.
- **Followers are thin mirrors, not engines**: a non-leader tab spawns no
  worker and holds no keys. It renders view projections served by the leader
  and sends commands as data. Election and the port rendezvous ride a
  `BroadcastChannel` as plain structured-clone data — every context on the
  origin holds that channel, so nothing that names or measures vault content may
  touch it: no plaintext, no key material, no user-supplied name, and no node id,
  IPNS name, routing key or block count. Everything else takes a different wire:
  each follower dials the leader a private `MessagePort` through the Service
  Worker (the only cross-tab route for a transferable) and drives commands,
  uploads, reads and its focus report over that, buffers transferred rather than
  cloned, with the one-way `EventDescriptor` stream fanned back down the same
  ports. A follower therefore mirrors events only once its port is adopted; it
  brokers eagerly at each leadership change, and a missed event costs staleness,
  never correctness. The leadership token gating the port is itself broadcast, so
  it bounds accidental and passive delivery, never a same-origin context that
  read the beacon — same origin remains the trust boundary. A tab with no Service
  Worker mirrors nothing: it fails closed rather than fall back to the shared
  channel.
- **Follower death is structural, not a heartbeat**: every tab holds a Web Lock
  naming itself (`cipherbox-presence:<clientId>`) from before it greets the
  leader until it dies, and the leader requests that same lock for each follower
  it adopts. The browser grants that request at exactly the moment the tab
  closes, crashes or is discarded, so the leader reclaims the follower's focus
  entry, write handles and read streams on that turn — a frozen tab, which
  answers no probe, is never a false positive, and no crashed follower pins a
  content version, and its key, for the rest of the leadership. The watch is
  keyed on the client, so a tab that re-brokers a port keeps its handles. Holding
  that lock costs the tab back/forward-cache eligibility — a browser does not
  restore a page that held a Web Lock — and that is the intended trade: a back
  navigation re-elects and re-brokers from a fresh page, which a restored mirror
  would have had to do anyway.
- **Failover**: the lock releases → some follower acquires it, spawns a fresh
  engine worker, and rehydrates from the durable seams (floors, op queue,
  staged bytes, snapshot cache — all origin-shared). Ops journal durably
  before they are acked to the UI, so failover loses no accepted work;
  commands in flight at the instant of leader death time out and surface a
  retry. A backgrounded leader keeps ticking (worker timers degrade
  gracefully); focused followers report focus over their private port so
  user-visible freshness follows the focused tab, and the leader's focus
  window is the union of all tabs' open folders.
- **The facade is transport-agnostic**: `packages/client` exposes one typed
  async facade; underneath it selects the local transport (UI ↔ own worker
  `postMessage`, transferables allowed) on the leader and the broadcast
  transport on followers. Leadership changes swap the transport without the
  UI noticing.

The RPC protocol is a hand-written, promise-correlated command/response layer
plus the one-way event stream — request ids, no codegen, wasm-bindgen types
end to end. Commands are the engine facade's commands verbatim; the client
adds transport, never semantics.

## Browser seams

The web implementations of the engine's constructor seams (engine.md table),
all living in `packages/client` and running inside the engine worker realm:

| Seam                | Web implementation                                                                                                                                                                                                                                                                                                                                                                         |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **FloorStore**      | IndexedDB. Durable across logout by design. No in-memory fallback tier: an unavailable IndexedDB is an unsupported-browser hard error at login, not a degraded mode. Ephemeral storage (private windows) is safe: floors cold-seed from the re-point object's owner-vouched epochs (FSM1/cipher-box-next#39 D4), so a wiped store costs staleness, never a rolled-back revocation boundary |
| **RecordTransport** | `fetch` against the configured `/routing/v1` endpoint set (someguy + at least one public endpoint), each GET bounded by the caller's `maxBytes` and the whole request by a deadline — the set includes untrusted public endpoints                                                                                                                                                          |
| **Http**            | `fetch`, with `credentials` and the request deadline carried per request: `'include'` on the API origin so the HTTP-only refresh cookie rides it — which is why web's CredentialStore is a no-op — and `'omit'` everywhere else, so a gateway or BYO provider gets no ambient authority                                                                                                    |
| **Scheduler**       | Worker timers. Background throttling is tolerated: the 30 s tick and the ~hourly re-PUT job both survive coarse timers, and every wake-relevant transition already forces a pass                                                                                                                                                                                                           |
| **StagingStore**    | Op-queue rows in IndexedDB; staged upload bytes in OPFS (per-op files, sync access handles in the worker), behind the sync-timing-profile budget                                                                                                                                                                                                                                           |
| **SnapshotCache**   | IndexedDB, ciphertext-only at rest — cached records/metadata unseal in the engine on read; plaintext never lands in browser storage                                                                                                                                                                                                                                                        |
| **CredentialStore** | No-op (see Http)                                                                                                                                                                                                                                                                                                                                                                           |

## UI state law

- **Rendered state = the engine's word, verbatim** (FSM1/cipher-box-next#33 D6): the facade emits
  snapshot updates with the pending-op overlay already applied plus per-node
  pending/dead-letter flags. The UI holds one mechanically derived
  subscription store (a `useSyncExternalStore` adapter over the event stream)
  with **no independent writers** — the v1 two-store desync class has no
  second store to desync. UI-owned state (selection, dialogs, route) carries
  node ids only.
- **Listings hydrate progressively**: name and kind render instantly from the
  parent's child refs (FSM1/cipher-box-next#27 D7); size/mtime arrive as child resolves land in
  the snapshot — no blocking resolution pass, no kind-flip UX.
- **Routes key on the stable node id** — never `ipnsName` (names rotate under
  write rotation) and no `'root'` sentinel; the root is just the vault
  pointer's current root node.
- **Staleness ladder rendering** (FSM1/cipher-box-next#33 D4): fresh → quiet reconciling
  indicator → stale badge ("last synced X ago") → offline banner. Trust
  violations and withheld-update escalations render as a distinct warning
  class, never as staleness; dead-letters get a persistent, actionable
  notice. Manual refresh is a facade command with nocache semantics, and a
  refresh it could not land reports back as a failure rather than a repaint.
- **Sharing UI is facade commands end to end**: contact-code import (QR /
  paste, verified in the engine), grant issue/revoke/downgrade, invite links
  (the URL fragment carries the ephemeral secret; the page hands it to the
  facade unread), received-shares list from the vault share list in the
  snapshot, revocation states from the engine's
  revocation-signal/unresolvable/epoch-lag classification. The UI renders the
  engine's flag that a write link is a bearer capability.

## Login and identity

- **Web3Auth Core Kit runs on the UI thread** (it owns its DOM/redirect
  flows and MFA enrollment — UI-side, outside the engine's sight). Login or
  session restore exports the login secret; the
  client passes it through the facade to the engine **once**, as a
  transferred buffer, and zeroes its own copy. Everything derives in-engine
  via the KDF catalog: identity key, encryption subkey, pointer chain, vault
  entry.
- **The engine owns the token lifecycle** (FSM1/cipher-box-next#28 D5): challenge-signature login
  through its API client; access JWT in engine memory; refresh cookie rides
  the Http seam. This is a distinct authentication from unlocking the Core Kit,
  and only the latter involves an identity provider ([ADR 0008](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0008-cipherbox-issues-the-identity-token.md)).
- **The login orchestration is shared, the credential collection is not**
  (ADR 0008 D3). `packages/login` (`@cipherbox/login`) is host-agnostic — no
  browser API, no React — and sequences provider credential → API exchange →
  Core Kit login → secret export → `start(secret)`; both hosts import it,
  parameterise it over their own facade, and inject their own collector. On web
  that collector is the Google popup, the emailed code and wagmi; desktop's is
  its own (desktop.md). The boundary is credential collection, not the bearer
  token — v1 drew it at the token and the two hosts drifted.
- **Wallet is a first login here** (ADR 0008 D2): wagmi collects the signature on
  the UI thread, the API verifies it and mints the identity token, and the Core
  Kit login proceeds as for any other method. Web only.
- **Device approval is not Core Kit UX** ([ADR 0009](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0009-device-approval-is-a-bound-rendezvous.md)). The Core Kit has no native
  cross-device share transfer, so approval is a server-mediated rendezvous with
  its own API surface (api.md) — the client's part is minting the ephemeral key,
  displaying the comparison value both devices must match, signing both halves
  with the device identity key, and sealing a **fresh** factor to the requester.
  The recovery phrase is the guaranteed path and needs none of this.
- **Cold start**: facade `start(secret)` → vault-pointer resolve, floor
  cold-seed, root adoption (the engine's non-circular cold-start sequence) →
  first snapshot event. The UI shows exactly two cold-start states: an
  empty-cache "loading vault" and the trust-violation error class — cached
  views otherwise render immediately (FSM1/cipher-box-next#33 D4).
- **Logout**: facade command — the engine zeroizes WASM state; the client
  tears down the worker and releases the leader lock. Floors, the op queue,
  staged bytes, and the ciphertext snapshot cache survive by design (durable
  seams, ciphertext-only); an explicit "forget this device" wipes them.

## Content paths

- **Upload**: UI hands `File` handles to the facade (transfer or Blob-clone —
  never a byte copy through React state). The engine stages into the
  StagingStore, seals chunk-wise via core, uploads through the pin-provider
  layer, and publishes — one journaled op regardless of online state (FSM1/cipher-box-next#33
  D6). Per-file progress/error is event-stream state on the upload's op id;
  cancel is a facade command killing the op before publish.
- **Download**: the engine fetches blocks (token-authed trustless gateway,
  public-gateway fallback), CID-verifies, unseals, and returns a `Blob`; the
  UI object-URLs it. Same path for previews.
- **Streaming media — the SW is a dumb pipe** (the FSM1/cipher-box-next#28 D4 open point,
  resolved): the media element requests an opaque `/stream/…` ticket URL; the
  Service Worker intercepts and forwards the Range to the engine worker over
  a `MessageChannel` port brokered at registration; the engine maps the range
  onto chunk boundaries (content is chunk-sealed with a chunk-aligned DAG —
  engine.md), fetches and unseals exactly those chunks, and streams plaintext
  back through the port. The SW holds no keys, no crypto, and no state worth
  keeping — a killed SW or broken port just re-brokers and re-buffers.
  Follower tabs route media through the leader the same way.
- **The same Service Worker brokers the follower read port**: it names a client
  back to itself and forwards one end of a `MessageChannel` to the client a tab
  addresses. It reads neither end and keeps no state, so a killed worker costs a
  re-broker, never a channel already open.
- **The same Service Worker precaches the app shell** (engineering judgment,
  implied by FSM1/cipher-box-next#33 D6's full offline parity): a vault you can mutate offline is
  a vault whose UI must boot offline. Cached snapshots + the op queue then
  give full offline function; the SW never caches vault data itself
  (ciphertext caching is the SnapshotCache's job).

## Composition (apps/web)

| Route             | View                                                                                                                                                                                |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/`               | Login (Core Kit methods + SIWE), recovery/approval UI                                                                                                                               |
| `/files/:nodeId?` | Vault browser (absent id = current root)                                                                                                                                            |
| `/shared`         | Received shares; browsing shared scopes is the same browser over the same snapshot                                                                                                  |
| `/bin`            | Recycle bin (kept per FSM1/cipher-box-next#5), restore/purge ops via facade                                                                                                         |
| `/settings`       | Auth methods, MFA enrollment and recovery phrase (Core Kit UX), authorized devices and approval (ADR 0009), BYO pinning (sealed `ByoIpfsConfig` via facade), vault settings, export |
| `/invite#…`       | Invite claim — fragment secret handed to the facade unread                                                                                                                          |

Cross-cutting chrome renders event-stream state only: sync/staleness
indicator, quota (advisory-aware for BYO), dead-letter and escalation
notices, offline banner. No route guard framework — unauthenticated pages
redirect on facade auth state, as in v1.

## Testing hooks

Structural change from v1's posture (the least-verified-layer trap): engine
logic is Rust-tested below the facade, and `packages/client` — leadership,
failover, both transports, the seams — is a **CI-blocking** browser test
surface, not an unblockable side suite. `apps/web` stays thin enough that
Playwright e2e covers it. A DEV-gated facade introspection hook (snapshot and
event-stream taps, no key access) replaces `window.__ZUSTAND_FOLDER_STORE__`
as the e2e seam. Suite shape, gating, and the leader-failover e2e scenarios
belong to the
[testing strategy](https://github.com/FSM1/cipher-box-next/issues/47).

## Open edges

- **Leader-failover UX polish** — the retry surface for commands caught
  in flight at leader death; settle alongside the failover e2e work
  ([#47](https://github.com/FSM1/cipher-box-next/issues/47)).
- **Media container edge cases** — range-to-chunk mapping is fixed above, but
  seek-heavy formats need the chunk size / DAG-shape numbers frozen with the
  engine's open edge (engine.md).
- **PWA install surface** — the app-shell precache is decided; whether v2.0
  advertises installability (manifest, install prompt) is deployment
  territory ([FSM1/cipher-box-next#48](https://github.com/FSM1/cipher-box-next/issues/48)).
- **Designed-for, deliberately unbuilt**: push overlay (API WebSocket hints),
  whose handler forces a pass through `Command::ManualRefresh` (FSM1/cipher-box-next#33 D1);
  client-side search re-entry feeding an index from the snapshot event stream
  (FSM1/cipher-box-next#5).
