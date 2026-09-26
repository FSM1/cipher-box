# ADR 0036 — The read accelerator admits an opaque session pseudonym and learns nothing about the read

- **Status:** Accepted on 2026-09-26 — retroactive; the rule shipped in FSM1/cipher-box#1449,
  FSM1/cipher-box#1461 and FSM1/cipher-box#1504, and the blueprint carries it; the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-26
- **Relates to:**
  [#34](https://github.com/FSM1/cipher-box-next/issues/34) D7 (the read path is an authed
  trustless gateway that requires a CipherBox token, with public gateways as the no-auth
  fallback), [#48](https://github.com/FSM1/cipher-box-next/issues/48) (the gateway deployment
  shape, and its open edge "gateway token detail"),
  [#28](https://github.com/FSM1/cipher-box-next/issues/28) D5 (the engine's API client owns the
  token lifecycle), [#23](https://github.com/FSM1/cipher-box-next/issues/23) (a signed IPNS
  record is its own authentication on the `/routing/v1` publish leg),
  [#24](https://github.com/FSM1/cipher-box-next/issues/24) (the republisher),
  [ADR 0008](./0008-cipherbox-issues-the-identity-token.md)
  (the access JWT and the rotating refresh token, which this ADR does not change), ADR 0035
  (the staging origin trusts only Cloudflare, proposed beside this ADR), the `blueprint/api.md`
  "Identity and auth", "Content plane" (the "Egress" bullet and the three after it) and "Hosted
  infra outside the API process" sections, the
  `blueprint/deploy.md` "Gateway deployment shape" paragraph, and the `CONTEXT.md` terms
  "Read accelerator" and "Accelerator token"
- **Implemented by:** FSM1/cipher-box#1449 (D1 to D3; it also wrote the D6 obligations into
  the blueprint), FSM1/cipher-box#1461 (the front: D4 to D9) and FSM1/cipher-box#1504 (the
  `Range`, `Accept`, `Referer` and `CF-Ray` strips of D7, the `CF-*` strip of D8, and the
  publish-leg rate of D4)

## Context

Thread #34 D7 put a CipherBox-operated trustless gateway on the read path and gated it on "a
CipherBox token". Thread #48 fixed the deployment shape: Caddy `forward_auth` to an API verify
endpoint, then a proxy to Kubo. Neither thread said which token, and #48 left "gateway token
detail" open as a build-time edge.

The first build closed the gap by omission. FSM1/cipher-box#1033 made the engine present the
session access JWT on the gateway leg, because it was the only credential the client held. The
review passes on that PR raised FSM1/cipher-box#1244 with two findings:

- **The credential was too wide.** The gateway leg is the most frequent credential
  presentation in the system: one per leaf block, so about one per MiB read. The access JWT
  authorizes the whole API surface: upload, quota, mailbox writes, pin registration, logout.
  An observer of an `Authorization` header at the gateway tier (a proxy access log, a cache
  layer, a compromised gateway node) got full session takeover, not gateway read access.
- **The gateway tier learned the reader.** The accelerator is tried first for every block. With
  an identity-bearing credential, it learns which content CIDs an account reads and when, at
  leaf granularity, including blocks that another member pinned on a shared-scope read. The pin
  table binds an account to the CIDs it uploaded, but not to read-time access or to cross-owner
  access edges.

The content itself is not what the gate protects. Every block is sealed and the engine verifies
it by CID, and a public trustless gateway serves the same blocks with no credential. The gate
protects two other things: the accelerator as a member resource, and the reader's identity
beside the read stream.

The owner decided the token on 2026-08-24 (FSM1/cipher-box#1244) and the front scope on
2026-08-25 (FSM1/cipher-box#1387). FSM1/cipher-box#1449 built the token and the verify
endpoint. FSM1/cipher-box#1461 built the front as two Caddy vhosts, `gateway-staging` in front
of Kubo (`ipfs:8080`) and `routing-staging` in front of someguy (`someguy:8190`), in
`docker/Caddyfile` (snippet `accelerator_front`). The PR did not use Caddy's `forward_auth`
directive. That directive authorizes on any 2xx and injects `X-Forwarded-Uri` and
`X-Forwarded-Method`, and this front must do neither, so the PR wrote out the expanded
`reverse_proxy` form. FSM1/cipher-box#1504 found three more egress leaks in review and closed
them.

Neither vhost writes a log, so a reviewer cannot read the obligations out of production
output. `scripts/check-accelerator-front.mjs` asserts them against Caddy's adapted JSON config,
which is what the server executes. It enumerates the accelerator upstreams, not the vhosts, so
a new vhost that proxies to Kubo or someguy is checked by default.

The blueprint carries the rule in `blueprint/api.md` "Identity and auth" (the "Read accelerator
token" bullet) and "Content plane" (the bullets "Egress", "The front covers both read legs",
"What the `forward_auth` front owes the pseudonym" and "What the verify leg costs"), and in
`CONTEXT.md` "Accelerator token".

## Decision

**D1 — The accelerator token is an opaque, read-scoped, per-session pseudonym, and never the
session JWT.** Decided on 2026-08-24 in FSM1/cipher-box#1244. The API mints it beside the access
token at every login method and at every refresh, as a third credential with the same lifetime
and rotation as the access token. It is 32 CSPRNG bytes, handed out once as 64 lowercase hex
characters, and the API stores only its SHA-256 (`accelerator_tokens`, in
`AcceleratorTokenService.mintForFamily`). It carries no claim, so the gateway tier learns
neither the account nor any capability past gateway reads. It is the only credential the
gateway leg presents. The engine holds it in a bearer cell of its own, apart from the access
JWT (`ApiClient` in `crates/engine/src/api/client.rs`), so neither leg can present the other's
credential. The engine hands the pseudonym to the configured accelerator only, never to a public
endpoint, and only over `https://` with no userinfo in the authority
(`carries_credentials_safely` in `crates/engine/src/content/read.rs`). A login body without the
pseudonym fails closed; the engine never falls back to the JWT.

**D2 — The pseudonym is valid only while its refresh family is valid, and the verify cache
bounds the revocation lag.** Decided on 2026-08-24 in FSM1/cipher-box#1244 ("Revocation is a row
delete and takes effect at cache expiry"); the family derivation landed with
FSM1/cipher-box#1449, and this ADR records it. A pseudonym verifies only while its own row is
unexpired and its family still holds a live refresh row, one that is unspent and unexpired
(`LIVE_REFRESH_ROW_SQL` in `apps/api/src/auth/refresh-liveness.ts`). Logout, refresh reuse
detection and the account hard-delete therefore revoke it through the deletes they already do,
and family expiry revokes it with no delete. There is no second revocation path. A rotation
deletes the family's previous pseudonym. The verify path caches each answer in process: an
acceptance for a configured TTL (`ACCELERATOR_TOKEN_CACHE_TTL_SECONDS`, default 10 s, at most
60 s) and never past the token's own expiry; a refusal for 1 s, in a separate map with a separate
size budget, so a spray of invented tokens cannot evict a live session. The acceptance TTL is
the revocation lag.

**D3 — The verify endpoint answers 204 or 401 and returns no identity.** The endpoint shape
(lookup plus in-process cache) was decided on 2026-08-24 in FSM1/cipher-box#1244; the two
status codes landed with FSM1/cipher-box#1449, and this ADR records them. `GET
/auth/gateway/verify` reads the `Authorization` bearer, answers 204 with no body when the
pseudonym names a live session, and 401 otherwise. It sits outside the JWT guard, because the
credential is not a JWT. A value that is not the minted shape is refused before any row lookup.
The endpoint has its own per-address throttle surface (`gatewayVerify` in
`apps/api/src/ops/throttling.ts`).

**D4 — One front gates both read legs, and the publish leg stays open.** Decided on 2026-08-25
in FSM1/cipher-box#1387. One front sits in front of Kubo's gateway leg and someguy's
`/routing/v1` GET and resolve leg, and gates both on the same pseudonym. Reads present it;
writes never do. Kubo writes go through the API under the session JWT. The `/routing/v1` PUT
publish leg (`PUT /routing/v1/ipns/*`) stays open at the front, because an IPNS record carries
its own signature; the front adds IP-keyed rate limiting there, and no credential check. The
code also caps the body at 64 KB (`docker/Caddyfile:206`-`208`). The republisher's re-PUTs route
internally (`ROUTING_V1_URL=http://someguy:8190`) and never cross the front.

**D5 — The gate admits only `GET` and `HEAD`.** The rule landed with FSM1/cipher-box#1461, from
a review finding; this ADR records it. A read credential must not become a write against an
accelerator that would accept one. Any other method gets 405, except the one publish leg of D4.
A CORS preflight (`OPTIONS`) carries no credential; the front answers it itself, and it reaches
neither the verify leg nor an accelerator.

**D6 — The front denies on any non-204, never logs the `Authorization` header, strips it before
the upstream, and logs no client address.** FSM1/cipher-box#1449 wrote these four obligations;
the owner applied them to the someguy vhost on 2026-08-25 in FSM1/cipher-box#1387, so they are
decided by extension. A verify 200, 401, 500, or no answer all deny, so a verify-side fault
fails closed. The raw pseudonym in a proxy log is a gateway credential at rest, and a client
address recorded beside a read links the account again, so both vhosts discard the access log
and the error log (the named loggers `accelerator` and `accelerator_errors`). The
`Authorization` header does not reach Kubo or someguy, so it does not reach their logs either.

**D7 — The verify subrequest names nothing about the read.** Decided on 2026-08-25 in the
FSM1/cipher-box#1387 addendum for the request URI and query; the `Range`, `Accept`, `Referer`
and `CF-Ray` strips landed with FSM1/cipher-box#1504, and this ADR records them. The API's view
of a read is a bare "is this session alive". The verify subrequest carries no original path and
no query string (the front rewrites it to `/auth/gateway/verify?`), and no `X-Forwarded-Uri`,
`X-Forwarded-Method` or `X-Forwarded-Host`; the deletes drop client-supplied copies too. It
carries no `Range` and no `Accept`, because the byte window and the block-or-CAR shape describe
the read as clearly as the path does. It carries no `Referer` and no `CF-Ray`
(`docker/Caddyfile:151`-`157`). A forwarded path would make each verify an account and a CID,
or an account and an IPNS name.

**D8 — The client address reaches no accelerator, and reaches the API only on the verify
subrequest.** The rule landed with FSM1/cipher-box#1461 (`X-Forwarded-For`) and
FSM1/cipher-box#1504 (the `CF-*` family); this ADR records it. The accelerators' own stdout
ships offsite, and an address logged beside a CID links the account again. So every leg into
Kubo or someguy, gated or open, strips `X-Forwarded-For` and the whole `CF-*` family Cloudflare
adds, and in particular `CF-Ray`: Cloudflare's own logs record the requested path under that id,
so it would join a pseudonym at the verify leg to a CID at the accelerator. The verify
subrequest is the one place the front forwards the address, so the verify throttle of D3 bounds
one member and not the whole front.

**D9 — The API learns the read cadence per account, and this is an accepted cost.** The
gateway-tier scope of the unlinkability claim was decided on 2026-08-25 in
FSM1/cipher-box#1387; the cadence statement landed with FSM1/cipher-box#1461, and this ADR
records it. On each read the API learns that a session is alive and which address asked, with no
CID and no name. It already sees that address on every other route the same member calls. What
is new is the cadence, about one presentation per leaf block: read timing, session duration and
approximate volume per account. The verify cache does not reduce it, because the request still
arrives. The unlinkability claim is scoped to a gateway-tier observer. The API necessarily
resolves pseudonym to account at verify time.

## Trust argument

- **A leaked pseudonym gives accelerator reads and nothing more.** It opens no API route (D1,
  D3). It opens no write at an accelerator (D5). It fetches only sealed blocks that the engine
  verifies by CID and that a public gateway serves with no credential. It dies at the next
  rotation, the family's revocation or the account delete, within the cache lag (D2).
- **The gateway tier cannot name the reader.** The pseudonym carries no claim (D1). The
  accelerator receives no `Authorization` header and no client address (D6, D8). The front
  writes no log (D6).
- **The API cannot name the read.** The verify subrequest carries no path, query, `Range`,
  `Accept`, `Referer` or forwarded host, method or URI (D7). The API learns liveness and
  cadence only (D9).
- **No header joins the two tiers.** `CF-Ray` is the id that could join a verify at the API
  to a fetch at the accelerator, and neither leg carries it onward (D7, D8).
- **Revocation cannot drift.** Validity is a join on the refresh family, so every session
  revocation revokes the pseudonym with it (D2). No second path exists that can disagree.
- **The gate fails closed.** Only an exact 204 admits a read. A verify fault, a verify outage, or
  a non-204 success denies (D6). A malformed token is refused before a lookup (D3).
- **The stored form is not the credential.** The API keeps only the SHA-256 of 32 random bytes
  (D1), so a database read does not yield a working pseudonym.
- **The open publish leg adds no trust.** A client adopts a record only after it verifies at the
  name and passes the adoption gate. The front bounds abuse of the leg by size and rate; it does
  not vouch for the record (D4).
- **An engine misconfiguration degrades to public reads.** A cleartext or userinfo accelerator
  URL gets no credential, and its reads go on unauthenticated (D1).

## Alternatives rejected

**(a) Keep presenting the session access JWT on the gateway leg.** This was the FSM1/cipher-box#1033
state. It puts full API authority on the most frequent credential presentation in the system,
and it gives the gateway tier the account beside every block it serves.

**(b) An audience-scoped, read-only, short-lived JWT (`aud: "gateway"`).** FSM1/cipher-box#1244
proposed this shape first. It narrows the authority, but it is identity-bearing, so the gateway
tier still learns the account per read. The opaque pseudonym narrows both.

**(c) Record the coupling in the blueprint and change nothing.** FSM1/cipher-box#1244 offered
this as the fallback if the token was not worth building. It makes the session-takeover exposure
a decision instead of an accident, but it does not remove it.

**(d) A revocation path of the pseudonym's own.** FSM1/cipher-box#1449 rejected a second path
beside the refresh family. Two paths can disagree, and one of them then honours a session that
the other revoked.

**(e) Caddy's stock `forward_auth` directive.** It authorizes on any 2xx, which breaks D6, and it
injects `X-Forwarded-Uri` and `X-Forwarded-Method`, which breaks D7.

**(f) Gate the Kubo leg only.** This was the original FSM1/cipher-box#1387 scope. The someguy
resolve leg carries the names a member resolves and their cadence, the most sensitive metadata
this tier sees, and the pseudonym's role is already read-leg-only.

**(g) Gate the publish leg too.** A signed IPNS record authenticates itself. A token on that leg
adds no trust, and the front has nothing to check there beyond size and rate.

**(h) Strip the client address on the verify subrequest too.** The verify throttle then keys on
the front's own address, one bucket for every member. The mutation table of
FSM1/cipher-box#1461 names this as a regression the checker must catch.

## Consequences

1. **`blueprint/api.md` already carries D1 to D3.** The "Identity and auth" section, bullet
   "Read accelerator token", states the opaque per-session pseudonym, the rotation with the
   access token, the 204/401 verify with no identity, the refresh-family validity and the cache
   bound. No text change is needed.

2. **`blueprint/api.md` already carries D4 to D9.** The "Content plane" section states the gate
   on the accelerator token (bullet "Egress"), the two gated read legs, the method gate, the
   open PUT leg and the internal republisher route ("The front covers both read legs"), the
   five front obligations with the address and `CF-*` strip and the verify-leg `Range` and
   `Accept` strip ("What the `forward_auth` front owes the pseudonym"), and the accepted cadence
   ("What the verify leg costs"). The verify-leg `Referer` and `CF-Ray` strips of D7 are code
   detail under the requirement that the verify subrequest names nothing about the read. The
   "Hosted infra outside the API process" section states that someguy's resolve leg sits behind
   the member front and its publish leg is open. No text change is needed.

3. **`CONTEXT.md` already carries D1 and D2.** The "Accelerator token" entry states the opaque,
   read-scoped per-session pseudonym, never the JWT, never identity-bearing, valid only while
   its refresh family is. The "Read accelerator" entry states the member-convenience role.

4. **`blueprint/deploy.md` already carries the two vhosts of D4.** The "Gateway deployment
   shape" paragraph names `gateway-staging` and `routing-staging` and sends the obligations to
   `blueprint/api.md`. Its sentence "Token format and TTL are API build-time detail" is now
   fixed by D1 and D2, which close the #48 open edge "gateway token detail".

5. **#34 D7 does not change.** This ADR fixes what "requires a CipherBox token" means and adds
   no second read path.

6. **`blueprint/api.md` section "Identity and auth" gains the citation (ADR 0036)** on the
   "Read accelerator token" bullet, and section "Content plane" gains it on the bullet "The front
   covers both read legs".

7. **`blueprint/deploy.md` section "Gateway deployment shape" gains the citation (ADR 0036)** in
   place of "Token format and TTL are API build-time detail".

8. **`CONTEXT.md` "Accelerator token" gains the citation (ADR 0036).**

9. **The `blueprint/api.md` "Data model (complete)" list must gain `accelerator_tokens`**, and
   so must the "Tables:" bullet of the "Identity and auth" section. The list ends "Nothing
   else", and the code holds the table D1 and D2 need (migration
   `apps/api/src/migrations/1787681144572-AddAcceleratorTokens.ts`). It is the only API table
   that the list omits. See E6.

10. **One engine doc comment is stale.** `carries_credentials_safely` in
    `crates/engine/src/content/read.rs` says "The token authorizes the whole API". That was true
    of the access JWT before FSM1/cipher-box#1449. The rule the function applies is still right.

## Residuals

**E1 — The API learns the per-account read cadence.** This is D9. The API can see when a member
reads, for how long, and about how much. It cannot see what.

**E2 — A revoked pseudonym still opens reads for the cache lag, and a stolen live one for the
rest of its lifetime.** The acceptance cache honours a revoked token for up to the configured
TTL (default 10 s, at most 60 s). A stolen live token works until its family is revoked or it
expires with the access token (default 900 s). The holder gets accelerator reads of ciphertext
that public gateways already serve.

**E3 — Cloudflare sees the pseudonym, the path and the client address together.** The staging
edge terminates TLS in front of the origin, so it observes every read in full, and its own logs
record the requested path under `CF-Ray`. The unlinkability claim is scoped to CipherBox's
gateway tier and to the API, not to the CDN. The origin trust model is ADR 0035.

**E4 — The public fallbacks see the address and the read.** A read that falls to a public
gateway or a public `/routing/v1` endpoint carries no pseudonym and no front. This ADR does not
cover that path; #34 D7 accepts it as the no-auth fallback.

**E5 — The front obligations are proven against the adapted config, not against live traffic
in CI.** FSM1/cipher-box#1461 ran a live Caddy harness and a thirteen-case mutation table once,
by hand. The Lint gate re-runs the config assertions on every PR, but no CI job sends a request
through the front, and the checker has no fixture test that proves each assertion fails on its
mutation.

**E6 — The blueprint's data-model list and the code disagree.** `blueprint/api.md` "Data model
(complete)" and the "Identity and auth" "Tables:" bullet list no `accelerator_tokens` table,
and the first ends "Nothing else"; the code has one
(`apps/api/src/auth/entities/accelerator-token.entity.ts`). This ADR records the blueprint's
credential rule, which needs a stored and revocable token, and does not treat the list as a ban
on the table. Consequence 9 corrects the list.

**E7 — Only staging has the front.** The two vhosts are staging names. A production deployment
must carry the same front; the checker's upstream enumeration catches a new vhost that proxies to
Kubo or someguy ungated, but production go-live is still an open edge of #48.

## Gate

- **D1:** `apps/api/src/auth/auth.http.itest.ts` (API Integration, real Postgres) "mints a
  pseudonym at login that is neither the access nor the refresh token" and "refuses the session
  access token at the gateway leg";
  `apps/api/src/auth/services/accelerator-token.service.itest.ts` "mints an opaque token that
  carries nothing about the account"; `crates/contract/tests/contract.rs` (Contract Suite)
  `the_accelerator_token_is_read_scoped_and_rotates_with_the_session`; engine tests
  `the_api_leg_presents_the_access_jwt_while_the_accelerator_holds_the_pseudonym` and
  `a_login_body_without_the_accelerator_token_fails_closed` (`crates/engine/src/api/client.rs`),
  `login_binds_the_pseudonym_to_the_accelerator_and_shutdown_drops_both`
  (`crates/engine/src/facade.rs`), `into_gateway_binds_the_session_bearer_to_the_accelerator_alone`
  and `an_accelerator_that_is_not_plain_tls_is_never_handed_a_credential`
  (`crates/engine/src/content/read.rs`), and
  `the_pseudonym_reaches_the_accelerator_and_no_public_endpoint` and
  `a_cleartext_accelerator_is_never_armed` (`crates/engine/src/net/record_accelerator.rs`).
- **D2:** `accelerator-token.service.itest.ts` "rotation replaces the family pseudonym and
  retires the previous one", "stops verifying once the session it names is gone", "stops
  verifying once every refresh row in the family has been spent", "dies with the account, by
  cascade", "serves a verified token from cache, and re-reads once the entry ages out", "never
  trusts a cache entry past the token’s own expiry", "spends its refusal budget on refusals
  alone, never on a live session" and "caches a refusal, and ages it out far sooner than an
  acceptance"; `auth.http.itest.ts` "rotates on refresh, and the superseded pseudonym stops
  verifying", "dies with the session at logout" and "dies with the family that reuse detection
  revokes"; `apps/api/src/auth/refresh-liveness.itest.ts`, which fails when the TypeScript and
  SQL readings of a live refresh row disagree.
- **D3:** `auth.http.itest.ts` "refuses a missing, malformed, or unminted credential";
  `accelerator-token.service.itest.ts` "refuses anything that is not the minted shape without
  touching the row"; the contract test above. No test asserts that the 401 body carries no
  identity. That is a finding.
- **D4:** the Lint job in `.github/workflows/ci-repo.yml` runs `pnpm lint:accelerator-front`
  (`scripts/check-accelerator-front.mjs`), which fails on "proxy to … reaches an accelerator
  ungated, and is not the PUT /routing/v1/ipns/\* publish leg" and on "the open publish leg runs
  unrated". The engine's `RecordTransport::put_record` seam takes no credential, so the type
  holds "writes never present it". No test asserts that the republisher's re-PUTs route
  internally; only `ROUTING_V1_URL` in `.github/workflows/deploy-staging.yml` sets it. That is
  a finding.
- **D5:** the same checker fails on "gated proxy to … is not held to GET/HEAD".
- **D6:** the same checker fails on "verify leg does not single out 204", "verify leg has no
  catch-all refusal for a non-204", "access logger … is not discarded",
  "http.log.error.… is not discarded" and "proxy to … does not strip Authorization before the
  upstream". No CI test drives a live front (E5).
- **D7:** the same checker fails on "verify leg does not delete …" for `X-Forwarded-Uri`,
  `X-Forwarded-Method`, `X-Forwarded-Host`, `Range`, `Accept`, `Referer` and `CF-Ray`, and on
  "verify leg forwards the original query string".
- **D8:** the same checker fails on "proxy to … does not strip …" for `X-Forwarded-For` and each
  `CF-*` and caller-naming header on every accelerator upstream, and on "verify leg drops
  X-Forwarded-For, so the surface cannot rate-limit per member".
- **D9:** an accepted cost, not a behaviour, so no test applies. The nearest guard is
  `apps/api/src/ops/ops.http.itest.ts` "counts an accepted accelerator token", which asserts that
  the metrics scrape carries no presented pseudonym, so the verify series names no session.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
