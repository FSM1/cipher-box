# crates/engine — v2 blueprint

Resolved by [Blueprint: engine](https://github.com/FSM1/cipher-box-next/issues/44).
Normative for the v2 build. Upstream inputs: the
[resolution/publish](https://github.com/FSM1/cipher-box-next/issues/23),
[record liveness](https://github.com/FSM1/cipher-box-next/issues/24),
[sharing](https://github.com/FSM1/cipher-box-next/issues/25),
[rotation](https://github.com/FSM1/cipher-box-next/issues/26),
[sync/refresh](https://github.com/FSM1/cipher-box-next/issues/33),
[API residual role](https://github.com/FSM1/cipher-box-next/issues/34),
[rotation completeness](https://github.com/FSM1/cipher-box-next/issues/38), and
[seal authentication](https://github.com/FSM1/cipher-box-next/issues/39) designs,
scoped by the [component decomposition](https://github.com/FSM1/cipher-box-next/issues/28)
(D1–D5). Where an earlier resolution was amended (FSM1/cipher-box-next#26 by FSM1/cipher-box-next#38/FSM1/cipher-box-next#39, FSM1/cipher-box-next#25's
directory and canonical re-point channel by FSM1/cipher-box-next#34/FSM1/cipher-box-next#38, FSM1/cipher-box-next#23's per-host library
picks by FSM1/cipher-box-next#28), the **amended** form is what appears below. The engine sits on
[`blueprint/core.md`](core.md) — everything core owns (codecs, crypto suite,
KDF catalog, record create/sign/verify, KATs) is referenced here, never
re-specified.

## Doctrine

`crates/engine` is the **single stateful brain**: every decision between core's
pure functions and a host surface — trust (the adoption gate and floors), state
(snapshot cache, op queue, floors), scheduling, and side effects (publish, API
traffic, mailbox) — implemented once in Rust, linked natively by the desktop
app and loaded as a worker-hosted WASM instance on web (FSM1/cipher-box-next#28 D1/D4). TS keeps no
engine logic. The engine owns IPNS end-to-end over dumb `/routing/v1`
transports (FSM1/cipher-box-next#28 D2) and contains the single hand-written API client (FSM1/cipher-box-next#28 D5).
Hosts inject every capability as a constructor seam trait; a missing seam is a
compile error, not a silent behavior gap (FSM1/cipher-box-next#26 D8).

What dies relative to v1 — with the design that killed it:

| Gone                                                                             | Killed by                                                                                            |
| -------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Twin TS/Rust engines (`sdk-core`/`sdk` + `crates/sdk`), 13 ungated resolve sites | FSM1/cipher-box-next#28 D1 — one Rust engine, both hosts                                             |
| `@helia/ipns` and per-host IPNS stack picks                                      | FSM1/cipher-box-next#28 D2 — core records + dumb transports                                          |
| Generated `api-client` packages, codegen loop                                    | FSM1/cipher-box-next#28 D5/D6 — one hand-written client, live contract tests                         |
| Optional floor injection (omit `rotationHighWater`, get nothing)                 | FSM1/cipher-box-next#26 D4 / FSM1/cipher-box-next#33 D7 — floors are a required constructor argument |
| Rotation job records, checkpoints, recovery machinery                            | FSM1/cipher-box-next#26 D8 — published records are the sole source of truth                          |
| `nodeKeySource` and Gap-B host divergence in key sourcing                        | FSM1/cipher-box-next#26 D1/D3 — every key derived in-engine from seeds                               |
| Grant re-mint as a separate relay step (the Gap B/C class)                       | FSM1/cipher-box-next#25 D1 — grant re-seal rides the republish                                       |
| Republish enrollment side-car (`requiresReEnroll`, `'stale'` rows)               | FSM1/cipher-box-next#24 D6 — register-first on the publish path                                      |
| TEE enrollment client, key epochs, grace-window machinery                        | FSM1/cipher-box-next#24 D4 — TEE dropped, designed-for re-signer seam only                           |
| Two-plane store/tree state desync                                                | FSM1/cipher-box-next#33 D6 — snapshot ⊕ pending-op overlay, single owner                             |
| mkdir+uploads-only offline journal                                               | FSM1/cipher-box-next#33 D6 — every mutation rides the durable op queue                               |
| State-union merge and the delete-resurrection class                              | FSM1/cipher-box-next#33 D5 — op-rebase, uniformly                                                    |
| Web one-level scope-exit coverage hole                                           | FSM1/cipher-box-next#26 D7 — full-depth detection, one implementation                                |

## Module map

Functional decomposition, not final file layout:

- **gate** — the adoption pipeline, durable floors, trust-violation policy.
- **sync** — focus-window scheduler, staleness ladder, op queue, rebase.
- **rotation** — the three primitives and the sweep work-list.
- **grants** — ledger, commitment, pseudonyms, invites, share lists, contact
  import.
- **pointer** — scope pointers and the vault pointer chain.
- **mailbox** — sealed-pointer traffic over the mailbox seam.
- **net** — resolve/publish pipeline, CAS, fan-out, liveness jobs.
- **content** — chunk framing, staging, the pin-provider layer.
- **api** — the hand-written API client and token lifecycle.
- **seams** — the host trait definitions below.

## Host seams

The constructor takes the seam set whole; the six load-bearing seams are fixed
by the decomposition (FSM1/cipher-box-next#28 D3) and the rotation design's mandatory-seam rule
(FSM1/cipher-box-next#26 D8). Traits move opaque bytes and events — no seam holds logic.

| Seam                | Contract                                                                                                  | Web (`packages/client`)                      | Desktop       |
| ------------------- | --------------------------------------------------------------------------------------------------------- | -------------------------------------------- | ------------- |
| **FloorStore**      | Durable monotonic-max per-scope epoch floors and per-name sequence floors; regression rejects fail-closed | IndexedDB                                    | Local journal |
| **RecordTransport** | Dumb `/routing/v1` byte mover: GET/PUT of opaque signed record bytes against a configured endpoint set    | `fetch`                                      | `reqwest`     |
| **Http**            | Plain HTTP for the API client, trustless gateway, and BYO providers                                       | `fetch`                                      | `reqwest`     |
| **Mailbox**         | Post/poll/ack of sealed blobs to/from a recipient pubkey                                                  | API mailbox via the engine's own API client  | Same          |
| **Scheduler**       | Timers, background task execution, wall clock                                                             | Worker timers                                | Tokio         |
| **StagingStore**    | Durable op queue + staged upload bytes (storage-policy budget)                                            | IndexedDB + OPFS                             | Local journal |
| **SnapshotCache**   | Durable last-known-good record/metadata cache backing cache-first reads                                   | IndexedDB                                    | Local store   |
| **CredentialStore** | Refresh-token persistence                                                                                 | No-op (HTTP-only cookie rides the Http seam) | OS keychain   |

Notes:

- The transport endpoint set is CipherBox someguy plus at least one independent
  public `/routing/v1` endpoint; nothing breaks if CipherBox infra vanishes
  (FSM1/cipher-box-next#23 D1). A desktop embedded rust-libp2p kad backend is designed-for behind
  `RecordTransport` (FSM1/cipher-box-next#23 D2). The `Mailbox` trait keeps a decentralized inbox
  swappable behind the same abstraction (FSM1/cipher-box-next#25 D2).
- Entropy and timestamps are engine inputs to core's pure functions: the clock
  comes from `Scheduler`, entropy from per-target `getrandom` wiring (core.md).
- `SnapshotCache` as a distinct seam, and the exact `CredentialStore` split,
  are engineering judgment — implied by FSM1/cipher-box-next#33 D4's indefinitely-usable cached
  views and FSM1/cipher-box-next#34's per-platform token storage, but not named by any resolution.
- There is deliberately **no** tab-leadership seam: the engine assumes it is
  the single writer. Leader election and the RPC facade belong to
  `packages/client` (FSM1/cipher-box-next#28 D4); the engine's side of that contract is the facade
  section below.

## Resolve/publish pipeline

The engine owns IPNS end-to-end; core signs and verifies, transports move
bytes (FSM1/cipher-box-next#28 D2).

- **Resolve**: cache-first — the UI never blocks on network resolution;
  last-known-good renders immediately and resolves reconcile in the background
  (FSM1/cipher-box-next#23 D5). Fan-out GET across the endpoint set, core record verify, then the
  adoption gate; only gate-passing records touch the snapshot. Cold-resolve
  tails (~11 s median, up to ~60 s) are tolerated as background reconciliation.
- **Publish**: register-first, fail-closed — the API registration call
  precedes a name's first publish and publish blocks on it; ordinary writes
  send single-item batches, name waves and sweeps send bulk (FSM1/cipher-box-next#34 D2). Core
  signs (first publish embeds sequence 1; CAS publishes embed the exact
  expected sequence), then parallel PUT to all endpoints; success = any ack,
  remaining PUTs retry in the background; confirm by re-resolve; a lost race
  re-resolves and rebases (FSM1/cipher-box-next#23 D3/D4).
- **TTL/EOL**: every record sets TTL explicitly from the sync timing profile
  (production 1 minute; dev/CI 1–5 s; never a library default) and a 90-day
  client-signed EOL; TTL and EOL are independent (FSM1/cipher-box-next#33 D3, FSM1/cipher-box-next#24 D1).
- **Liveness — the engine's half of the two re-PUT layers** (FSM1/cipher-box-next#24 D2/D5): an
  ~hourly Scheduler job keyless-re-PUTs every record the session holds, so
  actively used vaults keep themselves alive; on session start and
  periodically, the engine checks the EOLs of names it holds keys for and
  below ~30 days remaining republishes the same CID at seq+1 through the
  normal CAS path. The API republisher (~12 h inventory walk) backstops
  dormant vaults only — no client depends on the background re-PUT loop, and
  no client resolve path ever touches the API's record cache (FSM1/cipher-box-next#24 D3).
- **Revival**: after a >EOL lapse, a key-holding session fetches cached bytes
  from the authenticated recovery endpoint and extracts the last-known CID —
  or recovers it from the pin set's name→CID mapping — then mints a fresh
  record with a fresh signature; lapse is an availability event, never loss
  (FSM1/cipher-box-next#24 lapse semantics). The adoption gate therefore does **not** reject on
  EOL; the one carve-out is the vault settings resolve, whose reader is always
  its own signer (see "Vault settings load").
- **Retirement**: retire = remove my registry rows; timing is engine policy
  (FSM1/cipher-box-next#34 D4). Interior old names batch-retire at name-wave completion; the old
  scope-root name lingers serving the tombstone until the migration window
  closes (open edge below). An abandoned op retires the **whole** set its
  publish charged — the name it registered and every block it uploaded, root
  and leaves — because each upload is its own accountable pin row (api.md);
  batches chunk to the registry's batch cap, and retirement is idempotent, so a
  target that never landed costs nothing. An op whose record PUT was
  **acknowledged** retires nothing: the record may be resolvable at its name, and
  unpinning content a live record still references is loss, where leaving the
  rows charged is only a leak. A publish that fails **before the record reaches
  the transport** — register-first, the floor read, the head-CID echo, or an
  upload whose ack never came back — is the mirror case: its head block may
  already be pinned under its own charged row, no record can name it, and the
  retry re-authors under a fresh seal nonce, so the drain retires that head at
  the end of the pass that orphaned it, per attempt. A fan-out that
  acknowledged nothing does **not** qualify: no ack is not proof nothing stored.

## Adoption gate and floors

The gate runs on every resolve, no exceptions (FSM1/cipher-box-next#33 D7). Stage order composes
the FSM1/cipher-box-next#33 pipeline with the FSM1/cipher-box-next#39 D3 seal-auth stage and the D4 floor law:

1. **Record verify** — core's full chain: Ed25519 pubkey from the name itself,
   `signatureV2`, data-field/Value consistency, EOL/sequence extraction.
2. **Commitment verify** (scope roots) — the owner-signed grant-set commitment
   against the contact-code-anchored owner identity (FSM1/cipher-box-next#34 D6, FSM1/cipher-box-next#39 D1).
3. **Grant-section authentication** (scope roots) — every seed-bearing
   structure (grant blobs, owner blob, the optional owner-write-blob, ascent
   link, history links, write-body) verifies under **one** committed
   write-capable pseudonym via core's pure per-structure checks; any failure
   rejects the **whole record** as a trust violation (FSM1/cipher-box-next#39 D3). The
   owner-write-blob is optional on the wire, but a **present** one with a
   missing or invalid structure signature is a whole-record trust violation,
   never staleness (its signature is recomputed at the authenticated envelope
   epoch like every other structure, though its sealed AAD binds the write
   epoch).
4. **Sequence** — strictly newer than the durable per-name floor.
5. **Epoch** — epoch tag at or above the scope's durable epoch floor.
6. **Unseal** — success required; core's trust-violation error class carries
   through fail-closed.

**One section, one signer** (stage 3). A section is a single rotator's work: it
re-seals and detached-signs every structure with its own writer pseudonym,
re-signing at the record's read epoch even the history links it carries forward
verbatim (`rotation/reseal.rs`). The gate therefore **pins** the pseudonym that
authenticated the section's first structure and requires every later structure
to verify under that key alone; a section signed by two committed pseudonyms is
unadoptable, not merely unusual.

It closes a **structure splice**: a structure lifted verbatim out of a different
record at the same scope and epoch, authored by a different committed writer,
recomputes an identical signed input — `scope`, `epoch`, `structTag`,
`recipientTag` and `H(ciphertext)` all match — so per-structure trial-verify
adopted it. It is also what bounds stage 3's work at `pseudonyms + structures`
rather than their product: without it an accepted contact commits 1024 write
pseudonyms of their own and spreads a section's signatures across them, buying
~1000x reader-CPU amplification for ~1284 signatures. The produce side runs the
same predicate release-active (`net/author.rs::check_scope_root`), so this build
never signs a section its own gate rejects.

The pinned signer may be **any** committed write-capable pseudonym, not the
owner's specifically: the commitment is epoch-free so that grantee-triggered
rotation needs no owner signature (`CONTEXT.md`). Per-structure signers would
need a per-structure signer index on the wire, since the gate cannot otherwise
avoid the product — a format change, not a relaxation of this rule.

A gate failure is never mere staleness: the engine pins last-known-good,
raises the withheld-update escalation where applicable, and never renders the
rejected record. Duplicate `id`s and duplicate `ipnsName`s within a scope
reject at decode in core (FSM1/cipher-box-next#39 D7); the gate surfaces them as trust violations.

The **floor law** (FSM1/cipher-box-next#39 D4, superseding FSM1/cipher-box-next#26 D4's blob-seeded floors): floors
advance only on an AAD-confirmed unseal and cold-seed from the re-point
object's owner-vouched epochs (`writeEpoch`, `minReadEpoch`); a grant blob's
epoch field is an advisory routing hint. Additionally, a pointer `writeEpoch`
above the durable floor advances it the moment it is seen (FSM1/cipher-box-next#38 D4) — from that
instant every old-epoch record at the old name fails the gate. `FloorStore` is
a required constructor argument, fail-closed on regression.

**Cold start adopts nothing** until the floor store seeds from the
owner-signed anchor. The sequence is non-circular by construction (FSM1/cipher-box-next#38 D3):
own vault → scope/vault pointer (first act) → floors seeded → current root
name → envelope grant blob → seeds → render. Residual, honestly scoped
(FSM1/cipher-box-next#39 D4): a cold device can be shown a view missing at most grantee-triggered
epochs (which revoke nobody — pure staleness) plus within-epoch staleness;
revocation boundaries cannot be rolled back.

## Vault settings load

The vault settings record (`CONTEXT.md`) resolves at cold start, ahead of any
vault resolve, and never blocks it: every failure degrades inside the sync
timing profile's settings budget, measured on the Scheduler seam. What it
degrades _to_ is a trust decision, because unlike every other resolve its
degraded outcome applies a different policy rather than showing stale data.

- **Last-known-good before defaults.** The head block of a settings record
  that cleared its sequence floor and opened is cached in `SnapshotCache` —
  ciphertext only, like every other value in that store. A degraded load
  prefers that copy over the built-in defaults and reports it as stale
  alongside the reason it degraded. Being cached buys the bytes nothing: the
  copy clears the same seal open and the same body grammar a freshly fetched
  head block does, or it is discarded.
- **A degraded load never widens placement.** Withholding the record, running
  the budget out, making its head block unreadable, or failing the floor read
  must not move a member from `External` onto CipherBox's hosted store.
  Reverting an explicit placement choice to the hosted default is precisely
  what an adversary who controls the record plane gains, so a load that cannot
  authenticate the member's current choice must not invent a wider one. The
  guarantee is relative to this device: the widest placement a degraded load
  can report is the one this device last authenticated, never the built-in
  default. A rollback takes the same path — pinning last-known-good is what
  the gate already owes a rejected record.
- **No last-known-good copy fails the placement decision closed.** Under every
  reason but one, with no cached copy to fall back on, a placement decision
  refuses the hosted upload rather than resolving to `PinMode::Hosted`; the
  member is told their settings are unavailable. A consumer that branches only
  on the resolved case, letting the degraded ones fall through to the defaults,
  reintroduces exactly the widening this policy exists to prevent.
- **The one arm that still authorises a write is named for what it assumes.**
  The built-in defaults stand in for a first run, and the reason carrying them
  says so: `UnprovenFirstRun`. It is reached only when no endpoint served a
  record _and_ this device holds none of the three durable marks a settings
  record leaves: the per-name sequence floor, the adopted body revision, and the
  publish mint counter. An unreadable mark is never read as an absent one. Two
  of the three are what the sequence floor alone misses. The mint counter is
  raised before the PUT, so it outlives any save that got as far as minting a
  revision — a member who expressed a placement choice this device could not
  authenticate is never talked back onto the default, which is precisely when
  that reversal is cheapest. The adopted revision is raised by a store write
  separate from the sequence floor's and not atomic with it, so it outlives a
  lost one. Absence is a verdict about _this device_ only, so an assumed
  placement must never latch account-scoped state, and the account's advisory
  BYO flag may only ever be read in the restricting direction — `advisory` set
  means never assume the default. The inverse would be a server-controlled
  widening on an untrusted signal.
- **A lapsed EOL is refused here, and only here.** Plane-wide an EOL lapse is
  an availability event recovered by revival (above), because a gate-level
  rejection would lock every grantee out of a dormant owner's vault — a read
  regression, not a hardening. The settings record is the one record whose
  reader is always its signer, so refusing a lapsed one strands nobody: the
  session holding the login secret can republish on the spot. That is the
  principled carve-out, and it is what bounds replay on a device with no floor
  to compare against — a fresh install otherwise admits any owner-signed
  record the network serves, including one captured before the member rotated
  a BYO `access_token` the engine would then present as a bearer credential.
  The lapse degrades through the last-known-good path like every other
  reason. The encode side needs no matching guard: the EOL is `now + 90 days`
  off the injected clock, so a publish structurally cannot mint an
  already-expired record. Residual until the settings record joins the held set
  the sub-EOL renewal loop walks: an account whose settings have not been
  re-saved inside the window lapses on its own, and the placement decision then
  fails closed for want of a copy it can authenticate.
- **The sealed body carries a monotonic revision.** The outer sequence cannot
  order two records at the _same_ sequence, and an unconfirmed publish
  followed by a retry mints exactly that: two owner-signed records at one
  sequence, either of which a chosen-record adversary can serve forever. The
  revision is minted **per publish attempt, advanced before the PUT** — one
  derived from the confirm-gated sequence floor re-mints the same value on the
  retry and disambiguates nothing. A reader refuses a revision below the
  highest it has adopted **at that sequence**, which is a trust violation and
  not staleness; a record at a strictly higher sequence won its own CAS and is
  never held to a device-local counter, or a second device's legitimate publish
  would be refused forever. The writer's mint counter and the reader's adopted
  high-water are separate durable values: an attempt that never landed advances
  only the former, so it never makes a device refuse the live record it failed
  to replace. A confirmed publish raises the reader's bar and seeds
  last-known-good with what it published, so a record withheld right after a
  settings change cannot pin the device to the generation it replaced —
  including a BYO credential the member has just rotated away from.
- **The cold-device anchor is the EOL, and only the EOL.** Every durable seam
  is device-local, so a fresh install has neither a sequence floor nor an
  adopted revision to hold a record to; the revision closes the fork residual
  on a device with state, not on one without. Chaining the settings head CID
  into the vault pointer would give a cold device an anchor, but it inverts
  the record's whole purpose — settings resolve _before_ any vault resolve
  precisely so a self-hosting owner never needs CipherBox to tell them where
  their own node is, and a BYO member would have to reach the network they
  configured in settings in order to read those settings. An API-held counter
  is refused outright: no client resolve path touches the API's record cache.
  So a cold device's bound is the 90-day EOL window, stated rather than
  closed.
- **Residual: the cached copy has no freshness bound.** It is bound to the
  account by its seal alone — no sequence, no name, no time — so a party who
  can write this device's durable store can pin it to any settings generation
  the account ever published; every historical head block is a public,
  content-addressed object, so only the store write is privileged. The
  per-name sequence floor and the adopted revision are no defence here: both
  are device-local and live beside the cache, so the same party moves all
  three. That party can equally _delete_ the entry and force the defaults
  path, which is the pre-cache behaviour — so the anti-downgrade property
  holds against a record-plane adversary, not against one already inside the
  device's storage. The same staleness arrives with no adversary at all: a
  device stuck degraded keeps its copy indefinitely, including a BYO
  credential the member has since rotated, which is why the reason is reported
  rather than swallowed.

## Sync core

One model, two trigger sources (FSM1/cipher-box-next#33 D2): web drives it from navigation and the
poll timer, desktop from FUSE-op TTL checks — the core is identical.

- **State law**: rendered state = last-known-good remote snapshot ⊕
  pending-op overlay, single owner; the op queue is the only local divergence
  (FSM1/cipher-box-next#33 D6). Every op but a delete authors its target's next record, so the
  overlay stamps `mtime = authored_at` — overwriting the projected time, not
  filling it — and a content op also stamps its version's plaintext size,
  through the one function the drain's publish plan shares.
- **Focus-window tick**, 30 s: refresh the vault pointer, the open
  folder, and its full ancestor chain to root; the scope-pointer resolves for
  open shared scopes (FSM1/cipher-box-next#38 D4) and the mailbox poll (FSM1/cipher-box-next#34 D5) ride the same
  tick. `Command::ManualRefresh` brings the next pass forward immediately and
  resolves it nocache, and reports back what that pass reconciled. Any other cached folder
  refreshes on access past the staleness threshold — no background churn over
  the whole tree; cached shared scopes consult their scope pointer on access.
- **Sync timing profile** (environment-scoped): record TTL, poll cadence,
  staleness thresholds, escalation window, and the pointer-consult interval
  that bounds the read-only-survivor residual (FSM1/cipher-box-next#38 residuals). The profile is
  the CI-DX hook — dev/CI values make cross-client e2e flows testable at speed
  (FSM1/cipher-box-next#33 D3). It is a _named_ constant set, so measured per-device byte counts
  live in the storage policy instead.
- **Storage policy** (device-scoped): the staging budget and the read-cache
  ceiling, split from a headroom figure the host measures once and injects at
  construction — never a live host query inside a staging read-modify-write.
  The cache ceiling comes off headroom before the staging fraction; there is no
  floor-up, so a small headroom yields a small budget and an honest
  over-budget rejection. A host that cannot measure headroom at all is a
  distinct state, not a measured zero: uploads are refused as _unmeasurable_
  rather than reported as a full device.
- **Staleness ladder** (FSM1/cipher-box-next#33 D4): fresh → reconciling (quiet indicator) →
  stale (badge + "last synced X ago" after ~3 missed cycles) → offline banner.
  Availability staleness keeps cached views usable indefinitely. Errors are
  exactly two things: trust violations and an empty-cache cold start. Manual
  refresh resolves with nocache semantics everywhere.
- **Ops**: every mutation is an intent op — `create`, `delete`, `rename`,
  `relink`, `move`, `updateContent` — carrying its base sequence and its authored
  time, journaled FIFO in the durable op queue (all mutations, both platforms)
  as a versioned, owner-tagged record whose intent body seals HPKE-to-self in
  **auth mode**, so authoring one requires the owner's enc secret rather than
  the public tag stamped beside it. That authenticates a record's _author_, not
  its freshness or its position: a store co-tenant can still copy, delete, or
  reorder whole records, which queue-integrity work covers separately. The queue
  is per device, not per account, and is shared with whatever build wrote it: a
  record bearing another identity's tag, or a format version this build does not
  implement, is **retained** — never replayed, never surfaced, never removed,
  and its staged bytes stay pinned. Only a record that fails to decode at all is
  dead-lettered and dropped. An intra-scope
  `relink` is a pure relink; a cross-scope `relink` re-seals the moved subtree
  at the destination scope's epoch, and one that leaves a granted source scope
  is a scope-exit rotation trigger for the source (FSM1/cipher-box-next#26 D1/D7). A `move` is a
  relink and a rename in one entry, optionally vacating the node already at the
  destination name — one POSIX rename is exactly one `move`, so the whole
  operation is journaled or none of it is. Replay is FIFO
  in performed order through the standard rebase, and rebases only onto
  gate-passing state (FSM1/cipher-box-next#33 D5–D7).
- **Withheld-update escalation**: shared scopes only — a name pinned past a
  profile window while other resolves succeed raises the stronger warning
  (FSM1/cipher-box-next#33 D7); it also covers the network-suppression residual on the pointer
  plane (FSM1/cipher-box-next#38 D2).

Per-op rebase rules (FSM1/cipher-box-next#33 D5):

| Race                        | Rule                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Delete vs concurrent edit   | **Conditional delete**: the op snapshots the target's own record sequence; if the target advanced by rebase time, the delete is dropped — edit wins in both directions (a rebased edit resurrects a concurrently deleted node)                                                                                                                                                                                                                                                                                                                                        |
| Edit vs edit                | **Conditional edit**: the op names the head version it was formed against, taken when the write handle opens; a head that is not that one by rebase or publish time is another writer's, so the edit **dead-letters** with its staged version preserved instead of superseding it. An identity, never a count — a queued predecessor and a concurrent writer advance a count alike. A device holding no head for the target resolves one at `beginWrite` rather than writing unanchored; no read path surfaces a non-head version, so a superseded one is unreachable |
| Rename vs rename            | Serialized by the parent CAS; last writer at higher sequence wins                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Add vs add (name collision) | Always visible; the rebasing loser auto-suffixes (`name (2).ext`). Uniqueness = one strict comparator everywhere — NFC-normalized + case-folded, identical at create and merge on all platforms, names stored as-entered                                                                                                                                                                                                                                                                                                                                              |
| Move                        | Dest-first publish, then a presence-conditional source-remove — orphans structurally impossible; a race loser compensates by undoing its dest-add                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Dual-link (crash residue)   | **Observed repair**: any write-capable client seeing one child id in two loaded parents publishes the fix; the child ref's monotonic link counter picks the deterministic loser                                                                                                                                                                                                                                                                                                                                                                                       |

Terminally unrebasable ops (e.g. access revoked while offline) **dead-letter**
with a visible notice and staged bytes preserved; nothing is silently dropped
(FSM1/cipher-box-next#33 D6). Web reaches full offline parity: uploads stage into OPFS/IndexedDB
behind the profile budget (past it, only new uploads fail fast; metadata ops
queue unbounded).

## Rotation primitives

Three primitives, no recovery machinery (FSM1/cipher-box-next#26 D8): no job records, no
checkpoints — published records are the sole source of truth. A pre-publish
crash changed nothing durable; a post-publish crash recovers the override seed
from the published root itself; a resumed name wave enumerates old names via
the write-plane history link.

### rotateScope

Read-plane rotation: mint a random override seed at the scope root, republish
the eager set, enqueue the sweep. The **eager set law** (FSM1/cipher-box-next#26 D2 as amended
by FSM1/cipher-box-next#38 D5):

- **Owner revocation rotations**: the rotated scope root plus **every
  transitively-reachable descendant scope root**, each **fully rotated** —
  fresh override seed, grant blobs re-sealed for the committed set (empty and
  cheap for grant-less scopes), owner blob, history link, ascent link under
  the parent's new derivation. Cached descendant seeds are why ascent-re-seal
  alone is insufficient. Cost: O(descendant scope count), never tree size.
- **Grantee scope-exit rotations**: flat, self-contained, offline — every
  old-seed holder is a live grantee who receives the new seed, so no cascade;
  the single root still republishes the full per-scope-root list — blobs
  re-wrapped for the committed set verbatim, ascent link re-sealed to its
  public half, owner blob and history link refreshed (FSM1/cipher-box-next#26 D5, preserved by
  FSM1/cipher-box-next#38 D5).

Enumeration walks the write-body's **direct-child-scope index** (FSM1/cipher-box-next#38 D6),
maintained by the ops that change scope parentage (grant, scope dissolution,
cross-scope moves of a scope root) under the same dest-first + observed-repair
semantics as any move. The rotator detached-signs every seed-bearing structure
it re-seals with its writer pseudonym (FSM1/cipher-box-next#39 D2); a grantee re-wraps blobs for
the committed tag set verbatim and can neither extend nor shrink it (FSM1/cipher-box-next#26 D5).

### sweep

Idempotent lazy-wave advancement over a scope's **interior nodes** — not its
descendant scope roots, which the cascade rotates eagerly (FSM1/cipher-box-next#26 D2,
[ADR 0003](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0003-sweep-population-and-below-floor-scope-roots.md)).
The work-list is the epoch-lag predicate: an interior node whose envelope epoch
is behind its scope's current epoch. Reading one is the single path that runs
the sequence floor without the read-epoch floor — a lagging node sits below that
floor by construction, and carries no seed, grant blob or commitment for the
stage to protect; its body opens under the seed the scope's history-link ratchet
walks back to. A node the retained window no longer reaches is readable by
nobody: it is reported unreachable and neither swept nor descended into, never
treated as a trust violation of its own record. Runnable by any write-capable
client; ordinary writes advance it for free. It also converges the granted folder's own
subtree before a grant (the epoch-converged requirement, FSM1/cipher-box-next#26 D2 — the folder's
subtree, not the whole scope it sits in) and self-heals the direct-child-scope index —
a scope root encountered but missing from its parent's index is repaired and
flagged (FSM1/cipher-box-next#38 D6), a walk-time repair that runs whether or not any node is being
re-sealed. Only a name the walk resolved current may be written to an index: a
below-floor root is classified and re-resolved first (below), so the repair can
never persist the superseded name that caused it. Sweeps re-seal metadata only;
content bytes are never re-encrypted
by any rotation path (FSM1/cipher-box-next#26 D6). Scheduling is engineering judgment (FSM1/cipher-box-next#26 handed
it to FSM1/cipher-box-next#33, which did not fix it): the sweep runs as an idle-cadence Scheduler
job; idempotence plus CAS make concurrent sweepers safe — a lost race drops
that node from the work-list on re-resolve.

A **scope root** below its own read-epoch floor is not a sweep target and is
never repaired. Rotations publish before they raise the floor, so the condition
cannot mean the root lags — it means the record fetched is not the current one,
typically a `directChildScopeIndex` entry naming a root a `rotateScopeWrite`
has since moved. It resolves to a distinct _superseded_ verdict, handled by the
pointer consult (FSM1/cipher-box-next#38 D4) and a re-resolve at `currentRootName`, failing closed
if the fresh record is still below the floor. Admitting such a record would
republish the scope's existing override seed at the current epoch — a
revocation bypass, not a repair
([ADR 0003](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0003-sweep-population-and-below-floor-scope-roots.md)).

### rotateScopeWrite

Owner-only write rotation: commitment re-sign, fresh write override seed, a
background, parallel, **child-first name wave** republishing the subtree under
freshly derived names, root re-pointed last (FSM1/cipher-box-next#26 D3). Surviving
write-grantees derive every new name locally — zero re-discovery; read-only
survivors follow the owner-signed re-point object to the new root, then descend
through **rewritten child refs**. A read-only grantee holds no `writeScopeSeed`
and can derive no name, so the wave rewrites each `ChildRef.ipnsName` to the
child's freshly derived name and re-seals that parent's read body under its
unchanged read key at its unchanged read epoch; without it they reach the new
root and stop ([ADR 0004](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0004-read-body-child-names-on-the-name-wave.md)).
The republish is therefore **not** byte-stable, and the wave touches read-plane
_metadata_ while never re-keying it — the **read** override seed, read keys and
`minReadEpoch` still carry verbatim, and the read-epoch floor never moves.

The wave carries one envelope epoch across the whole subtree, so every republish
re-reads both durable floors immediately before it seals and refuses below
either: a concurrent read rotation lifting the read floor mid-wave would
otherwise leave the subtree gate-rejected at its new names and retired at its old
ones.

The re-point publishes to three channels (FSM1/cipher-box-next#38 D3): the scope pointer record
(canonical), the mailbox
(accelerator, verifiable), and the old root name's final tombstone
(accelerator, feeding FSM1/cipher-box-next#33's silent depth-guarded `movedTo` chase). Inventory
swap rides the normal paths: wave publishes enroll new names via
register-first; interior old names batch-retire at completion; the old root
lingers until the migration window closes (FSM1/cipher-box-next#34 D4).

### Triggers

Per FSM1/cipher-box-next#26 D7:

| Trigger                                                                                                                                                    | Action                                                                                                                            |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Scope exit — full-depth coverage detection, both hosts, one engine; includes a cross-scope move out of a granted source scope (FSM1/cipher-box-next#26 D1) | `rotateScope` (grantee-triggered, flat)                                                                                           |
| Read revoke                                                                                                                                                | Immediate revoking rekey: blob + ledger + commitment entry removed, `rotateScope` with the full cascade — one atomic owner action |
| Write revoke / downgrade                                                                                                                                   | `rotateScopeWrite`; plus read rotation on full revoke                                                                             |
| Discovered link expiry                                                                                                                                     | Expiry is a ledger field; the next owner session observing it acts — no scheduler                                                 |
| Manual hygiene rotate-now                                                                                                                                  | Per scope, same primitives                                                                                                        |

Non-triggers: intra-scope rename/move, content writes, adding a grant to an
existing scope root. Scheduled hygiene is deferred, designed-for — the same
primitive on a timer.

### Residuals (as amended by FSM1/cipher-box-next#38)

- Write-grantee survivors: the forgery window stays wave-bounded.
- Read-only survivors: a revokee can pin their view for at most ~one
  pointer-consult interval after the re-point publish — "bounded by wave
  duration" was wrong and is retired.
- Revoked readers: stale interior metadata for a sweep-length window, never a
  live grant, never anything sealed after the cut.

## Pointer planes

The three-plane model (FSM1/cipher-box-next#38 D1): owner plane (stable pointer names, owner-only
keys), write plane (rotating derived names), read plane (seeds). The engine
publishes to the owner plane **only in owner sessions**.

- **Scope pointer** — one per shared scope, keyed from `ownerPointerSeed` via
  the core catalog; its record carries the owner-identity-signed **re-point
  object** `{scopeId, currentRootName, writeEpoch, minReadEpoch,
prevRootName}` sealed under the scope's stable `pointerReadKey` (carried in
  grant blobs and persisted in each grantee's vault share list) — cold start
  is non-circular and public observers cannot link old↔new roots; revokee
  readability is accepted (FSM1/cipher-box-next#38 D3, FSM1/cipher-box-next#39 D4). `writeEpoch` moves on owner-only
  write rotation; `minReadEpoch` bumps only on owner-triggered read rotations,
  so grantee rotations need no owner signature and each plane's clock is
  authored by the authority that owns it.
- **Consult discipline: polled, not fallback** (FSM1/cipher-box-next#38 D4). A revokee's forged
  old-epoch records pass every other gate stage — valid old-key signature,
  fresh sequence, floor-level epoch, old-seed unseal — so staleness never
  fires and a fallback-only pointer is never consulted. Therefore the pointer
  resolve joins the focus-window tick for open shared scopes, runs on access
  for cached ones, and is the first act on cold start.
- **Vault pointer** — the same re-point object for the root scope, on an
  indexed key chain from day one: `pointerKey_i = KDF(secret,
"vault-pointer" ‖ i)`, index 0 default. Clients probe one index past the
  highest known, adopt the highest index bearing a valid owner-signed payload,
  and stop at the first unresolvable index — which only the owner can extend;
  an owner-side index bump is the pointer-key-compromise recovery. Cost: one
  extra resolve on cold start and per tick (FSM1/cipher-box-next#39 D5).
- Pointer names ride pin registration into the republisher inventory and get
  the same 90-day EOL + lease renewal as every name (FSM1/cipher-box-next#24 as amended by FSM1/cipher-box-next#38).

## Grants and ledger

Grants-in-metadata (FSM1/cipher-box-next#25 D1): key material lives in the published scope root —
grant blobs keyed by blinded tags, the authoritative ledger
`(recipientIdentityPk, recipientEncPk, permission, tag)` in the write-body,
and the epoch-free owner-signed grant-set commitment. The engine maintains all
three plus the per-(scope, writer) pseudonyms; re-mint does not exist as a
separate step — every rekey re-seals surviving committed grants uniformly in
the republish it already does.

- **Authority** (FSM1/cipher-box-next#25 D7, FSM1/cipher-box-next#26 D5): sharing, revoking, and every commitment
  change are owner-only. Write-grantees write content and re-wrap blobs for
  committed tags during re-seals but cannot change the set — tags are
  name-bound, so read rotation leaves the commitment untouched.
- **Contact import** (FSM1/cipher-box-next#34 D6): the engine verifies a contact code's binding
  signature against the carried identity key at import — mandatory,
  fail-closed. Identity keys only ever arrive out-of-band; there is no
  directory. Fingerprint comparison stays optional host UX.
- **Grant creation**: converge the subtree (sweep) → mint the scope (fresh
  random seed, epoch 1, subtree swept in — the new grantee needs no history) →
  for write grants, the write-scope cut (fresh write scope seed + name wave
  over the subtree) → update the parent scope's direct-child-scope index →
  publish → post the sealed share pointer to the recipient's mailbox.
- **Accept flow**: mailbox pointer (sender-signature verified inside the seal,
  FSM1/cipher-box-next#39 D9) → resolve the name → gate (commitment verified against the
  contact-anchored owner identity) → self-locate the blob by blinded tag →
  unseal seeds → append `{name, sharerPub, displayName, permission}` to the
  sealed received-shares list in the recipient's own vault, persisting the
  `pointerReadKey`; the owner keeps a denormalized sent-index in theirs. Both
  lists are self-healing bookmarks — the metadata is the authority (FSM1/cipher-box-next#25 D3).
- **Revocation is discovered, not delivered** (FSM1/cipher-box-next#25 D3/D4): a fresh
  owner-signed record with no blob at your tag is the definitive revocation
  signal; an unresolvable name is merely unknown/stale. The engine classifies
  revocation-signal vs unresolvable vs epoch-lag and surfaces the distinction
  to hosts. Read revoke = the immediate-cut trigger above; the promise is
  "they keep what they saw; they lose everything new, now." Write
  revoke/downgrade = write rotation; old names are hijackable by the revokee
  and therefore dead to survivors — tombstones advisory only.
- **Invites** (FSM1/cipher-box-next#25 D6): a grant blob wrapped to an ephemeral keypair, placed
  in the envelope and ledger-tracked; the URL fragment carries the ephemeral
  private key and the owner's contact bundle. Links are honestly bearer and
  multi-claim; claim = a sealed, ephemeral-key-signed mailbox request the
  owner converts to a personal grant (upgradeable to write). Expiry is a
  ledger field, lazily pruned via the discovered-expiry trigger. Write links
  carry extractable subtree signing keys: revoking or expiring one is only
  real via write rotation — which is why cheap, routinely-runnable write
  rotation is a hard requirement the primitives above satisfy — and the
  engine flags write links as bearer capabilities for host UI.
- **Files are first-class grant targets** (FSM1/cipher-box-next#25 D5): envelope blobs +
  write-body ledger like any node; ancestor rotations re-seal
  independently-shared descendants' grants as part of republishing them.
- **Owner entry** (FSM1/cipher-box-next#39 D6): the own-vault **owner seed cache** — the
  last-confirmed `{seed, epoch}` per granted scope, refreshed on every
  confirmed owner read — is canonical; the grantee-maintained owner blob is an
  accelerator. Ancestor readers derive the expected ascent keypair from the
  parent node seed and reject a mismatched plaintext half. Cross-check
  discipline: owner-blob seed vs ascent-link seed vs actual unseal — any
  disagreement is an attributable abuse event surfaced to the host, never a
  silent failure. Residual, documented: content sealed only under a
  rogue-withheld epoch is recoverable only from a valid-seed holder —
  equivalent to the destructive power a write-grantee already holds; the
  guarantee is that a write-grantee can never lock the owner out of content
  the owner could already reach, and can never act deniably.
- **Owner write-seed cold start**: a per-scope `writeScopeSeed` is random
  KDF-non-edge material an owner cannot re-derive from the login secret, so a
  fresh device that has lost its cache cannot renew its own records. Every
  reseal **that publishes a write-body** authors an **owner-write-blob** — the
  `writeScopeSeed` sealed to the owner's own enc subkey, beside that write-body
  (`reseal_scope_root`, so every root/interior write-scope cut, rotation, and
  cascade carries one) — the owner's recovery source for `write_name_signer`.
  The sweep's interior re-seals author none — an interior node publishes no
  write-body for a blob to sit beside (FSM1/cipher-box-next#27 D6) — while its
  index self-heal, which republishes the scope root, authors one like any other
  root re-seal. This slice authors and
  gate-verifies the blob; the owner read/consume that opens it into
  `HeldMaterial.write_scope_seed` rides a later facade slice.

## Mailbox logic

The mailbox carries discovery and courtesy traffic only — share pointers,
write-rotation re-point accelerators, invite claims, courtesy notifications.
Nothing on it is load-bearing for safety: root migration has the pointer
plane, revocation is discovered in metadata (FSM1/cipher-box-next#34 D5, FSM1/cipher-box-next#38 D3).

- **Sender authentication** (FSM1/cipher-box-next#39 D9): every payload carries a sender-identity
  signature inside the HPKE seal, verified against the contact-code-anchored
  key; unauthenticated items are dropped before a wasted resolve.
- **Lifecycle**: post via the API client with a sender-supplied idempotency
  key (≤ ~8 KB); poll rides the sync tick; ack = delete. The engine acks only
  after the pointed-at fact is durably recorded (share appended to the vault
  list, re-point applied) — an engineering judgment consistent with
  until-acked retention. Re-point mailbox items are verifiable accelerators:
  the same owner-signed re-point object as the pointer record, applied through
  the same floor law.
- Server-side caps, the 90-day unacked TTL, and rate limits are API territory
  (api.md); the engine surfaces a reject-new mailbox as a sender-visible
  failure.

## API client

One hand-written Rust client, inside the engine, over the Http seam — shared
by web and desktop; no generated clients anywhere (FSM1/cipher-box-next#28 D5). The NestJS API
keeps emitting its OpenAPI spec as a docs artifact; enforcement is the live
contract-test suite owned by the testing-strategy blueprint (FSM1/cipher-box-next#28 D6).

- **Token lifecycle** lives here; the web app never touches tokens.
  Challenge-signature login with the identity key is engine-native; SIWE stays
  a secondary method — the host supplies the wallet signature through the
  facade and the engine exchanges it (engineering judgment on the plumbing;
  the method set is FSM1/cipher-box-next#34's). The short-lived access JWT is held in engine
  memory; the rotating refresh token persists per platform via
  `CredentialStore` (HTTP-only cookie on web, OS keychain on desktop, FSM1/cipher-box-next#34).
  Refresh is single-flight with one retry-then-fail on 401 (judgment).
- **Surface consumed** (mirrors api.md): auth/refresh (+ staging-only
  test-login), batch register `[{ipnsName, headCid?, contentCids[]}]` and
  batch retire, quota query (`advisory: true` for BYO), hosted upload, mailbox
  post/poll/ack, recovery fetch, the account BYO toggle, account hard-delete.
- Register-first ordering is built into the publish pipeline, not left to
  callers. Quota enforcement lives on the API upload endpoint (FSM1/cipher-box-next#34 D1); a
  pre-flight quota-query check to fail fast before bytes move is judgment.

## Content plane

- **Pin-provider layer** (FSM1/cipher-box-next#34 D1): hosted (default), external (own
  Kubo/PSA/Pinata endpoint), or dual — the engine decides where bytes go;
  every mode's publish flow still traverses registration. `ByoIpfsConfig`
  stays sealed in vault settings; provider connection testing is engine-side
  over the Http seam (the TEE tester is gone).
- **Dispatch is concrete over the Http seam, and only content versions
  dispatch.** A record head block always takes the hosted path — the record
  plane's publish compares the ingress's returned address against the head
  block's own, and the republisher re-PUTs from the hosted store — so
  placement decides a version's blocks, not a record's.
  - The byte destinations a mode names are exactly what the provider's API
    supports. Kubo takes bytes under the caller's own address (`block/put`
    with the CID's multicodec and the frozen `blake3`/32 framing) and the
    address it answers with is held to the one it was given. PSA and Pinata
    are pin-by-CID services: they fetch the block from the network rather than
    receive it, and their own ingress re-chunks under a different multihash,
    so neither can preserve an address. They are therefore only ever a dual
    write's second leg, and **external-only over a pin-by-CID provider is a
    placement refusal** — no leg would hold the block for the service to
    fetch, so the published record would name bytes that exist nowhere.
  - **Dual runs both legs, both retrying inside the op, and only hosted can
    fail it** (FSM1/cipher-box-next#34 D1). Under strict-FIFO stop-at-first-failure a
    both-must-succeed rule would let an offline home node stall every later
    mutation in the vault, so the op completes once hosted succeeds and
    external has either succeeded or exhausted its attempts. That budget is
    the **op's, not each block's**: a node that is down refuses every block
    alike, so once it is spent the mirror is abandoned for that version rather
    than re-asked per block. The outcome is reported per op rather than
    swallowed, and no retry is queued for it. Under external, the member's
    provider _is_ the byte path, so its refusal is the op's.
  - **A partial-success report waits for the publish.** The external-pin
    shortfall says the version published and its content is retrievable, so it
    is emitted after the record lands, never at the end of block upload — a
    pass that still fails to publish has made no such promise.
  - **Durable upload progress is keyed by the destinations that took the
    bytes.** A resumed version's confirmed prefix is no longer on the device,
    so a session only skips it where the leg that can fail _this_ op already
    holds it: the hosted store, except under external-only where the member's
    provider is the only leg there is. A mark therefore records what the legs
    actually took, not what the mode named — a dual write whose mirror missed
    a block narrows its mark to the hosted leg, so a later external-only
    session re-places rather than publishing content that node never received.
  - **The destination identity is the provider, not the credential.** It
    covers the provider kind and endpoint and deliberately excludes the
    bearer: a mark that stops matching is not merely ignored, since the leaves
    it covered are already released, so keying on a rotatable secret would
    make a routine credential rotation leave the version unpublishable.
    Residual: two accounts on one multi-tenant pin service tag alike, which
    only ever reaches the best-effort mirror report.
  - The placement is decided once at start and holds for the session, so a
    provider or credential revoked elsewhere still receives blocks until the
    process restarts. Stated, not closed.
- **A publish refuses settings no reader could place under** (AGENTS.md rule
  8): the produce path runs the consumer's own placement predicate, so a
  record naming a mode with no usable byte destination — an external leg with
  no provider, or external-only over a pin-by-CID one — is never signed. Left
  unchecked it would be a durable, account-wide refusal of every content
  write, recoverable only by publishing a new record.
- **The quota pre-flight gates this write's byte path, not the account.** It
  runs at command time, where the write already waits, sized in **sealed**
  bytes: `Hosted` and `Dual` are checked, `External` is skipped. `advisory` on
  the quota response is a display hint that lags the vaulted mode — the mode
  is the source of truth and the account flag is reconciled against it, since
  `users.byo` is two-state where the mode is three and dual has no server
  representation (`byo=true` is exactly `External`). Only a placement the
  member's own record established reconciles it: an assumed one carries its
  provenance to this gate and latches nothing, and an `advisory` that
  contradicts the default it assumed refuses the write. The pre-flight can never
  be authoritative — the API upload endpoint stays the enforcement — so an
  unreachable or unconfigured API leaves the write to queue offline like any
  other, while a placement that cannot be authenticated refuses it.
- **BYO endpoint policy** (#905): one gate over the whole config, applied
  identically to a member-typed config and to one resolved back off the
  network, and release-active on the encode side so nothing is published that
  the reader would refuse. The rules: an absolute `http(s)` URL whose
  authority is host-and-port bytes only; `https` unless the host is a loopback
  address (`127.0.0.0/8`, `::1`) or the name RFC 6761 reserves for one
  (`localhost`), because the probe carries the member's bearer and plaintext
  to anything else puts it on the wire; the cloud-metadata address
  (`169.254.169.254` and its IPv6 spellings, `fd00:ec2::254`) refused
  outright, since no IPFS provider serves it; and an access token restricted
  to visible ASCII. A host that this gate would read as a name while the
  transport's URL parser would read it as an address (`0xa9fea9fe`,
  `2852039166`) is refused rather than classified twice. Private and
  link-local ranges otherwise stay **allowed** — self-hosting on a LAN is the
  feature. The engine has no resolver and does not acquire one for this: every
  other name's address is the host's to resolve at request time, so the
  verdict comes from the literal and the metadata refusal is a legibility
  rule, not an SSRF containment boundary. Each refusal is its own
  `ProviderError` verdict so the host can say which rule bit. The transport
  decision binds the whole exchange, so the `Http` seam must not follow a
  redirect that downgrades `https` to `http`.
- **Reads**: the token-authed trustless gateway is a member accelerator; any
  public trustless gateway is the no-auth fallback. The engine verifies CIDs
  client-side via core on every block/CAR response; media uses ranged fetches
  (the service-worker decryption layer is web-blueprint territory) (FSM1/cipher-box-next#34 D7).
- **Chunking and retention** — owned here per core.md's hand-off, resolved as
  engineering judgment: the engine frames content into fixed-size chunks,
  seals each with core's content-seal primitive (fresh random per-version
  content key, FSM1/cipher-box-next#26 D6), and assembles a DAG addressed by the version's
  `contentCid`, shaped so ranged block/CAR fetches map chunk-aligned.
  Retention default: keep all versions within quota, with an explicit
  user-initiated prune op. The framing is frozen (#820) and pinned by the
  engine KAT manifest: the 1 MiB budget belongs to the **block**, so a
  1,048,536-byte plaintext chunk seals to a 1 MiB leaf; the DAG is a flat root
  carrying an explicit format version, whose inlined link list caps a single
  file at ~107.78 GiB.

## Facade

The engine exposes one async command-and-event surface, designed to be
wrapped, not extended: commands (the intent ops, grant/rotation/share actions,
auth, manual refresh) and an event stream out (snapshot updates, staleness
transitions, withheld-update escalations, dead-letters, attributable abuse
events). Desktop calls it directly in the Tauri process; web wraps it via
`crates/wasm` bindings inside a dedicated worker, with the RPC facade and tab
leadership owned by `packages/client` (FSM1/cipher-box-next#28 D3/D4). The engine's contract is
only this: one live instance is the single writer, and every trust decision
already happened below the facade — hosts render, they never decide.

## Open edges

- **Migration-window closure** — how long the old scope-root name lingers
  serving the tombstone before retire. FSM1/cipher-box-next#38 fixed the channel architecture but
  not the window; proposed as a sync-timing-profile constant, to settle with
  the testing-strategy blueprint's e2e work.
- **Sweep cadence** — the idle-cadence value joins the sync timing profile.
- **Designed-for seams, deliberately unbuilt in v2.0**: push overlay (API
  WebSocket hints or desktop PubSub), whose handler forces a pass through
  `Command::ManualRefresh` (FSM1/cipher-box-next#33 D1);
  desktop embedded DHT behind `RecordTransport` (FSM1/cipher-box-next#23 D2); decentralized inbox
  behind `Mailbox` (FSM1/cipher-box-next#25 D2); the re-signer wrapped-key enrollment channel
  (FSM1/cipher-box-next#24 D4); scheduled hygiene rotation (FSM1/cipher-box-next#26 D7).
- **Worker packaging, RPC facade, tab leadership** →
  [web client blueprint](https://github.com/FSM1/cipher-box-next/issues/45);
  FUSE adapter over the facade → desktop blueprint; contract tests and the
  live-API suite → testing strategy
  ([#47](https://github.com/FSM1/cipher-box-next/issues/47)).
