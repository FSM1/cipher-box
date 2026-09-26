# ADR 0037 — No browser channel carries what names the vault, and every boundary value is bounded

- **Status:** Accepted on 2026-09-26 — retroactive; the rule shipped in FSM1/cipher-box#982,
  FSM1/cipher-box#1023, FSM1/cipher-box#1039, FSM1/cipher-box#1082, FSM1/cipher-box#1502 and
  FSM1/cipher-box#1533, and the blueprint carries it except the session-end notice of D2
  (consequence 1); the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-26
- **Relates to:**
  [#45](https://github.com/FSM1/cipher-box-next/issues/45) (the web client blueprint thread; this
  ADR supersedes its "thin mirrors over BroadcastChannel" sentence),
  [#28](https://github.com/FSM1/cipher-box-next/issues/28) D4 (one engine instance per origin),
  [#33](https://github.com/FSM1/cipher-box-next/issues/33) D6 (offline parity and the single-owner
  state law), AGENTS.md rules 3 and 8 in FSM1/cipher-box (the server never sees plaintext;
  encode/decode fail-closed symmetry), the `blueprint/web-client.md` "Doctrine", "WASM
  packaging and the type boundary", "Engine hosting and tab leadership", "Browser seams" and
  "Content paths" sections, and the `CONTEXT.md` "Focus window" term
- **Implemented by:** FSM1/cipher-box#982 (the private follower port, D1),
  FSM1/cipher-box#1039 (commands, uploads and the focus report on the port, and the reclaim, D2
  and D4), FSM1/cipher-box#1082 (the event stream on the port and the presence lock, D3 and D5),
  FSM1/cipher-box#1502 (the session-end notice on the channel, D2), FSM1/cipher-box#1023 (the
  record GET bound and the per-request deadline, D6 and D7) and FSM1/cipher-box#1533 (the
  ranged-read number rule, D8).

## Context

The web client hosts one engine per origin (`#28` D4). The leader tab holds the engine worker.
Every other tab is a follower: it spawns no worker, holds no key, and renders what the leader
serves. The baseline blueprint at `fd1d406b5c` put both directions of that traffic on one
`BroadcastChannel`: "Both directions ride a `BroadcastChannel`: projections and events are plain
structured-clone data". The `#45` resolution says the same: followers are "thin mirrors over
BroadcastChannel (projections in, data commands out)". The baseline marked the mechanism as
"engineering judgment"; `#28` D4 fixes only the invariant, one engine writer per origin.

A `BroadcastChannel` is a broadcast. Every same-origin context that opens the channel name gets
every message: every other tab, every iframe, every worker. A `clientId` on a message is a filter
at the receiver, not an access control. The review gates found four exposures in this shape
between 2026-08-02 and 2026-08-04:

- A follower's reads came back on the channel (FSM1/cipher-box#972). The ranged media read made
  this continuous: one plaintext window per 1 MiB, for the whole of a playback, in every
  follower tab.
- A follower's uploads and command arguments went out on the channel (FSM1/cipher-box#983):
  upload chunks as `Blob` handles, file names, contact codes, and the SIWE signature.
- The engine event stream stayed on the channel (FSM1/cipher-box#1052). `EventDescriptor`
  carries node ids, IPNS names, routing keys, op ids and block counts. That is enough to
  reconstruct which scopes exist, when they change, and how large each write is.
- A follower that died without a farewell message kept its stream handles in the leader's engine
  (FSM1/cipher-box#988). A stranded stream pins a content version, and the key of that version
  stays resident with it for the rest of the leadership.

Each issue states the same threat model. An exploit needs script execution on the origin, and
such a script has more direct routes. So the fix is defence in depth and a smaller exposure, not a
new privilege boundary. The channel is the right instrument for election and the wrong one
for anything of value.

The same review gates found a second class at the seam boundary. The record transport read a
`/routing/v1` answer with no size bound, and the endpoint set includes untrusted public endpoints
(FSM1/cipher-box#949). The `Http` seam sent every request with no deadline, so an engine call to
an unresponsive host parked the UI flow that awaited it (FSM1/cipher-box#939). Later, the media
head framed `Content-Range` from the ticket's mint-time size, not from the version the stream
pinned (FSM1/cipher-box#1062). The fix crossed the pinned size as a JS number, which needed a
rule for a size a JS number cannot hold.

Every issue behind this ADR is agent-written: FSM1/cipher-box#939, FSM1/cipher-box#949,
FSM1/cipher-box#972, FSM1/cipher-box#983, FSM1/cipher-box#988, FSM1/cipher-box#1038 and
FSM1/cipher-box#1052. No owner comment on the issues or on the landing PRs endorses a choice. The
rules replace the baseline "engineering judgment" text, not a `#28` D4 decision.

`blueprint/web-client.md` carries the rules today: "Engine hosting and tab leadership" (the
"Followers are thin mirrors" and "Follower death is structural" bullets), "Content paths" (the
Service Worker brokers the follower read port), "Browser seams" (the RecordTransport and Http
rows), and "WASM packaging and the type boundary" (the "Boundary hygiene" bullet). The one gap
is the session-end notice that FSM1/cipher-box#1502 put on the channel so that a logout or a
"forget this device" in one tab ends the session in every tab. The blueprint does not name it
(consequence 1).

## Decision

**D1 — Follower traffic travels on a private port that the Service Worker brokers.** Each
follower dials the leader a private `MessagePort` through the Service Worker. The Service Worker
is the only cross-tab route for a transferable, because a `BroadcastChannel` carries none. The
follower dials, so no context can push a port at a tab that did not ask for one. The follower
adopts the port only after the leader greets on it with the current leadership token. Buffers on
the port are transferred, not cloned. The Service Worker names a client back to itself and
forwards one end of a `MessageChannel` to the client a tab addresses. It reads neither end and
keeps no state, so a killed Service Worker costs a re-broker, never a port already open. The
leadership token is itself broadcast, so it bounds accidental and passive delivery only, never a
same-origin context that read the beacon: same origin remains the trust boundary. A tab with no
Service Worker mirrors nothing. It fails closed and never falls back to the shared channel. The
rule landed with FSM1/cipher-box#982 for read results; this ADR records it.

**D2 — The channel carries election, the port rendezvous and the session-end notice, and nothing
of value.** Election, the port rendezvous and the origin-wide session-end notice
(`cb:sessionEnded`) ride the `BroadcastChannel` as plain structured-clone data. The session-end
notice carries no leadership token and names no account. No plaintext, no key material and no
user-supplied name touches the channel. Everything else takes the follower's private port:
commands and their arguments, upload chunks, reads, and the focus report. The rule landed with
FSM1/cipher-box#1039, and the session-end notice with FSM1/cipher-box#1502; this ADR records
both.

**D3 — Nothing that names or measures vault content touches the channel.** Every context on the
origin holds the channel, so no node id, no IPNS name, no routing key and no block count may
touch it. The one-way `EventDescriptor` stream fans out to each follower over its private port.
A follower therefore mirrors events only after its port is adopted. It brokers eagerly at each
leadership change, and a missed event costs staleness, never correctness. The rule landed with
FSM1/cipher-box#1082 (option 1 of FSM1/cipher-box#1052); this ADR records it.

**D4 — The leader reclaims everything a dead follower held.** When a follower tab closes,
crashes or is discarded, the leader reclaims its focus entry, its write handles, its read
streams and its port on the same path. No crashed follower pins a content version, and the key
of that version, for the rest of the leadership. The reclaim is keyed on the client, not on the
port, so a tab that re-brokers a port keeps its handles. The rule landed with
FSM1/cipher-box#1039; this ADR records it.

**D5 — A per-tab presence Web Lock detects follower death, not a heartbeat.** Every tab holds
an exclusive Web Lock named `cipherbox-presence:<clientId>` from before it greets the leader until
it dies. The leader requests the same lock for each follower it adopts. The browser grants that
request at the moment the tab closes, crashes or is discarded, and the leader runs the D4 reclaim
on that turn. A frozen tab answers no probe but still holds its lock, so it is never a false
positive. A tab that greets while it holds no presence is granted at once and reclaimed, so a
greeting cannot outlive the presence. A tab whose lock is lost does not greet again. The lock
name carries a `clientId` and nothing else. Holding the lock costs the tab back/forward-cache
eligibility, because a browser does not restore a page that held a Web Lock. That is the
intended trade: a back navigation re-elects and re-brokers from a fresh page, which a restored
mirror would have to do anyway. The rule landed with FSM1/cipher-box#1082, which replaced the
port heartbeat of FSM1/cipher-box#1039; this ADR records it.

**D6 — A record GET is bounded in bytes and in time.** The web RecordTransport is `fetch`
against the configured `/routing/v1` endpoint set, which includes untrusted public endpoints.
Each GET is bounded by the caller's `maxBytes`, and the whole request by a deadline. The engine
passes `MAX_RECORD_BYTES` (10 KiB, the IPNS record limit) and keeps a release-active backstop:
the engine refuses an over-cap answer even from a transport that ignores its cap. The rule
landed with FSM1/cipher-box#1023 for FSM1/cipher-box#949; this ADR records it.

**D7 — Every `Http` request carries a deadline, set per request class.** The deadline rides the
request, not the seam. The engine sets it per class at the call site from `DeadlinePolicy`
(`crates/engine/src/deadlines.rs`): an API control call, an API upload, a leaf-block GET, a
placement on a member's own provider, and a provider reachability probe. The web seam honours it
with an `AbortSignal` over the whole exchange, the body drain included. Desktop honours it with
the `reqwest` request timeout, so one policy covers both hosts. The rule landed with
FSM1/cipher-box#1023 for FSM1/cipher-box#939; this ADR records it.

**D8 — Ranged-read numbers cross as JS numbers, and the producer refuses a size no read can
address.** IPNS sequence numbers and sizes cross the WASM boundary as `bigint`. The ranged-read
surface is the one exception: window offsets, lengths and a stream's pinned size cross as whole
JS numbers, so a range and the size it is framed against are one arithmetic. The producer refuses
a size past `Number.MAX_SAFE_INTEGER` rather than cross one that no read could address, and it
releases the stream it pinned when it refuses. The rule landed with FSM1/cipher-box#1533; this
ADR records it.

## Trust argument

- **A bystanding same-origin context sees no vault data on the channel.** Under D2 and D3 the
  channel carries per-tab `clientId`s, the leadership token, the port-host address, and a
  session-end notice that names nobody. None of these names a file, a scope or a size. The
  plaintext, the arguments and the metadata go only to the one context that asked for them.
- **Legitimate tabs no longer receive each other's data.** Before D1, every follower tab got the
  downloads of every other follower. A port delivers a result to one context.
- **A forged rendezvous moves no adopted follower.** The follower dials its own port and settles
  nothing until the greeting lands, so a context that holds the broadcast token cannot hand a
  follower a port it did not dial.
- **The Service Worker learns nothing.** It forwards a port end and reads neither end. It holds
  no key and no state.
- **No channel message can reclaim a live follower.** Under D5 the only departure signal is the
  release of a lock that no other context can give up on the tab's behalf. A forged farewell on
  the channel reclaims nothing. A forged session-end notice ends the session, not the reclaim
  path; E2 states that cost.
- **A key does not outlive the tab that pinned it.** Under D4 and D5 the reclaim runs on the turn
  the tab dies, not after a probe interval, so the pinned version and its key leave the engine at
  once.
- **Fail-closed has no downgrade.** A tab with no Service Worker cannot fall back to the channel,
  so a browser that blocks the Service Worker cannot turn private traffic back into broadcast
  traffic.
- **An untrusted endpoint cannot exhaust the tab.** D6 bounds the bytes it can send and the time
  it can hold a request. The engine backstop holds the bound even when a host transport does not.
- **No engine call parks a UI flow forever.** Under D7 an unresponsive host becomes a transport
  failure that the engine can report and retry.
- **No response head describes a range that no read can serve.** Under D8 the size that frames
  `Content-Range` and `Content-Length` is one a JS number holds exactly, so the head and the body
  agree.

## Alternatives rejected

**(a) Keep the event stream on the channel and reduce the descriptors.** FSM1/cipher-box#1052
weighed this as option 2: replace identifying fields with client-local opaque ids that the
follower resolves over its port. It is a smaller change, but it leaves a shape that invites the
next descriptor field back onto the channel unguarded. Option 1 gives an invariant that one test
can state and hold: the channel carries no vault data at all.

**(b) Fall back to the channel when no Service Worker exists.** This keeps a follower working in
a browser without a Service Worker. It also turns every exchange back into a broadcast whenever
the Service Worker is absent or blocked, so the property would hold only when an attacker allows
it. FSM1/cipher-box#982 chose to fail closed, the posture the FloorStore row already takes for an
unavailable IndexedDB.

**(c) Release a follower's handles when its port detaches.** FSM1/cipher-box#988 rejected this.
A naming timeout or a re-brokering follower is a live tab, and a release there kills in-flight
media playback and drops the version pin that the stream exists to hold. Port loss is not death.

**(d) Detect follower death with a port heartbeat.** FSM1/cipher-box#1039 shipped this first: a
follower that missed four probes was reclaimed. FSM1/cipher-box#1038 recorded its costs. A frozen
or bfcached page answers no probe, so a live tab was reclaimed after about 60 s. A dead tab's
staging reservation and pinned key stayed for up to a minute. The sweep was keyed on the port, so
a tab that died before it brokered a port left its focus entry behind. The leader already uses a
Web Lock release as its own death signal; D5 applies the same primitive to followers.

**(e) One flat deadline for every `Http` request.** FSM1/cipher-box#939 rejected this: a block
upload and a nonce fetch do not share a deadline. D7 names the class at the call site.

**(f) Cross the ranged-read numbers as `bigint`.** This keeps the boundary rule uniform. It splits
one arithmetic between two number types on the media path, where the Service Worker frames a
`Range` header against the pinned size. FSM1/cipher-box#1533 kept the numbers as JS numbers and
put the refusal at the producer.

## Consequences

1. **`blueprint/web-client.md` already carries D1, D3, D4 and D5, and D2 except its third
   role.** The "Engine hosting and tab leadership" section states them in the "Followers are thin
   mirrors, not engines" and "Follower death is structural, not a heartbeat" bullets. The "Content
   paths" section states the Service Worker half of D1 in "The same Service Worker brokers the
   follower read port". The "Followers are thin mirrors, not engines" bullet changes when this ADR
   is accepted: it says that election and the port rendezvous ride the channel and that
   "everything else takes a different wire", and it gains the session-end notice as the third
   channel role, with no leadership token and no account (ADR 0037 D2). This is a blueprint text
   change and needs the owner's acceptance of this ADR before the reword.

2. **`blueprint/web-client.md` already carries D6 to D8.** The "Browser seams" table states D6 in
   the RecordTransport row and D7 in the Http row. The "WASM packaging and the type boundary"
   section states D8 in the "Boundary hygiene" bullet. No text change is needed.

3. **`CONTEXT.md` needs no change.** No glossary term names the leader tab, the follower or the
   channel. The "Focus window" term is touched only in that the leader's focus window is the union
   of every tab's focus report, which D2 moves onto the port.

4. **This ADR supersedes the `#45` resolution sentence on the channel.** The sentence "thin
   mirrors over BroadcastChannel (projections in, data commands out; uploads ride `File`/`Blob`
   handles, which structured-clone by reference)" now reads: followers are thin mirrors over a
   private, Service-Worker-brokered port (projections, events and read results in; commands,
   upload chunks and the focus report out, buffers transferred), and the `BroadcastChannel`
   carries election, the port rendezvous and the session-end notice only. The `#28` D4 invariant
   does not change.

5. **`blueprint/web-client.md` section "Engine hosting and tab leadership" gains the citation
   (ADR 0037).** The parenthetical "engineering judgment on the mechanism; the invariant — one
   engine writer per origin — is D4's" gains it for the follower mechanism, and the two bullets
   of consequence 1 gain it.

6. **`blueprint/web-client.md` section "Browser seams" gains the citation (ADR 0037)** on the
   RecordTransport and Http rows, and **section "WASM packaging and the type boundary" gains the
   citation (ADR 0037)** on the ranged-read sentence of "Boundary hygiene".

7. **Two code headers change with D2.** The `packages/client/src/leaderRelay.ts:13` header says
   the channel "carries election and the port rendezvous only". The
   `packages/client/src/broadcast.ts:3` header says "election and the port rendezvous — nothing
   else" and then lists the session end in the same comment. Both gain the session-end notice as
   the third role.

8. **No wire format, no KDF edge, no KAT and no op queue record changes.** The `credentials`
   scope in the Http row (`'include'` on the API origin, `'omit'` everywhere else) is the
   baseline Http row made explicit by FSM1/cipher-box#1023. It is not a decision of this ADR.

## Residuals

**E1 — Same origin stays the trust boundary.** The leadership token is broadcast, so a
same-origin script that reads the beacon can replay it. Port ownership is self-asserted: the
relay serves any port that names itself, and binds a handle to a client for lifecycle
bookkeeping, not for authorization. D1 to D3 reduce passive and accidental exposure. They do not
stop a same-origin script, which can also call the facade directly.

**E2 — A forged session-end notice forces a full re-login in every tab.** The notice carries no
leadership token, because no leadership mints it, so a token could not bound it
(`packages/client/src/broadcast.ts` `SessionMessage`). A same-origin script that posts
`cb:sessionEnded` ends every tab's engine session and its provider session, and the member owes a
full re-login, not a reload. The notice is the channel's one destructive message. It stays inside
the same-origin boundary of E1: such a script already holds a context that can call logout
itself. The notice must reach every tab, including a tab with no adopted port and the leader, so
the port cannot carry it.

**E3 — A same-origin context can take or hold a presence lock name first.** The name is the
`clientId`, which the channel discloses. A context that takes the name first denies the tab its
mirroring. The tab then fails closed. FSM1/cipher-box#1082 left the name as the `clientId` on
purpose, inside the declared trust boundary.

**E4 — Web Lock names are an origin-wide surface.** `navigator.locks.query()` reads every held
and pending lock name on the origin. D5 keeps the presence name to a `clientId`. The rule does
not cover other lock names: the device identity lock in `apps/web/src/auth/deviceIdentity.ts:60`
carries a SHA-256 digest of the sign-in subject. That subject is the CipherBox-issued `verifierId`,
a random UUID (the `identity_subjects` row id), not an email address. The digest is a stable
per-member tag on the origin. It names no vault content and sits outside this ADR.

**E5 — The `Http` deadline is optional in the type.** `HttpRequest::timeout_ms` is an
`Option<u64>`, and the web seam sends a request with no deadline as unbounded (the
`carries no abort signal when the request sets no deadline` test in
`packages/client/src/seams/http.test.ts`). D7 holds because every production call site in
`crates/engine` sets `Some`, not because the type forbids `None`. A new call site that passes
`None` is not caught by any test.

**E6 — The record-transport deadline is host policy, not a seam term.** The web value is the
constant `RECORD_TIMEOUT_MS` (30 s) in `packages/client/src/seams/recordTransport.ts`. A comment
keeps it in step with desktop's `ReqwestRecordTransport` client timeout. The engine does not pass
it, and no test compares the two hosts.

**E7 — The back/forward-cache trade has a user cost.** A back navigation to a CipherBox tab loads
a fresh page and re-elects. The ADR accepts this; no test measures it.

**E8 — A tab with no Service Worker can lead but cannot follow.** It can still take the election
lock and run its own engine. While another tab leads, it mirrors nothing and its reads fail.

## Gate

- **D1:** Client Browser Suite, `packages/client/test/browser/leadership.spec.ts` —
  `a follower reads snapshot and download through the real leader engine`,
  `a follower streams plaintext while a second same-origin context sees no payload`, and
  `a forged port rendezvous carrying the observed token moves no adopted follower`. Unit suite,
  `packages/client/src/broadcastTransport.test.ts` —
  `fails a read closed when no port can be brokered, never falling back to the channel` and
  `reclaims a dialed port that never named the follower behind it`;
  `packages/client/src/portCourier.test.ts` — `refuses to broker where no worker is active`;
  `packages/client/src/sw/install.test.ts` — `names the asking client back to itself`,
  `forwards a delivered port to the addressed client and nobody else` and
  `closes a port addressed to a client that is gone`. No browser-level test runs a follower with
  no Service Worker; the fail-closed rule is proven at the unit level only.
- **D2:** Client Browser Suite —
  `a follower uploads while a second same-origin context sees no plaintext and no arguments`.
  Unit suite, `broadcastTransport.test.ts` — `keeps upload plaintext and command arguments off
the channel` and `keeps every read result off the channel: a second context sees only
rendezvous traffic`; `packages/client/src/engineClient.test.ts` — `signs a sibling out when the
leader ends the session` and `ends the session in the leader when a follower ended it`. The
  notice is the frozen `SESSION_ENDED` constant `{ type: 'cb:sessionEnded' }`, so it carries no
  token and no account by construction; no test asserts that shape.
- **D3:** Client Browser Suite — the same upload test asserts that the bystander saw none of the
  bytes and none of the distinctive strings of the `opProgress` descriptor that the follower
  received, with the needle taken from the received event. Unit suite,
  `broadcastTransport.test.ts` — `fans engine events over the private port, putting no descriptor
on the channel` and `names no account on the origin-wide channel, only on the private port`.
- **D4:** Unit suite, `broadcastTransport.test.ts` — `reclaims the handles and port of a follower
whose tab is gone` (asserts the stream close, the write abort and the port close). Client
  Browser Suite — `no channel message strands a live follower, and a real departure still
reclaims` (asserts the lock grant over real `navigator.locks`, not the handle release). No test
  asserts that a departure removes the follower's focus entry from the focus-window union.
- **D5:** Unit suite, `broadcastTransport.test.ts` — `holds its presence before it greets, so the
leader never watches a free name`, `never reclaims a live but frozen follower that answers
nothing at all`, `reclaims a follower that greets while holding no presence at all`,
  `refuses to greet again once its presence lock is lost` and `leaves an unnamed port to the
naming timeout, watching no presence for it`. Client Browser Suite — `no channel message
strands a live follower, and a real departure still reclaims` (the presence lock held and
  watched over real `navigator.locks`, and a forged `cb:bye` reclaims nothing). No test covers the
  back/forward-cache trade.
- **D6:** Unit suite, `packages/client/src/seams/recordTransport.test.ts` — `surfaces an over-cap
record as tooLarge, never as bytes`, `admits a record exactly at the cap with its bytes intact`
  and `gives an untrusted endpoint no ambient authority, no redirects, no cache, and a deadline`;
  `packages/client/src/seams/cappedBody.test.ts` for the shared drain. Rust workspace tests,
  `crates/engine/src/net/fanout.rs` —
  `get_verify_caps_the_read_and_skips_a_transport_that_ignores_it`; the encode-side symmetry,
  `crates/engine/src/net/liveness.rs` — `publish_fails_closed_on_a_record_over_the_resolve_cap`.
- **D7:** Unit suite, `packages/client/src/seams/http.test.ts` — `aborts a request that outlives
its deadline` and `treats a zero deadline as a real deadline, not as unbounded`. Rust workspace
  tests — `the_injected_control_deadline_rides_an_api_request` and
  `the_default_policy_keeps_the_shipped_control_deadline` (`crates/engine/src/api/client.rs`),
  `the_default_policy_keeps_the_shipped_block_fetch_deadline`
  (`crates/engine/src/content/read.rs`), and
  `the_default_policy_keeps_the_shipped_placement_deadline`
  (`crates/engine/src/content/provider.rs`). No test asserts that every engine `HttpRequest`
  carries a deadline (E5).
- **D8:** Unit suite, `packages/client/src/media/range.test.ts` — `rejects an offset past
MAX_SAFE_INTEGER with no window`, `rejects a last past MAX_SAFE_INTEGER with no window` and
  `rejects a suffix past MAX_SAFE_INTEGER with no window`;
  `packages/client/src/engineClient.test.ts` — `refuses an opened stream whose size no read
could address, giving the handle back` (the follower's re-check, since the producer ceiling
  does not run on the port). The producer
  refusal itself, the `MAX_SAFE_SIZE` check in `open_content_stream` in `crates/wasm/src/host.rs`,
  has no test. That is a finding.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
