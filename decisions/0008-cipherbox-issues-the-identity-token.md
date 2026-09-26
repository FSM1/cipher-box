# ADR 0008 — CipherBox issues the Core Kit identity token, and wallet login is first-class on web

- **Status:** Accepted — implemented;
  [FSM1/cipher-box#1253](https://github.com/FSM1/cipher-box/issues/1253) and all seven of its
  sub-issues are closed
- **Date:** 2026-08-11
- **Amends:** [#5](https://github.com/FSM1/cipher-box-next/issues/5) — the clause "SIWE wallet
  login stays as a secondary auth method", restated in `blueprint/api.md` "Identity and auth"
- **Relates to:** [#28](https://github.com/FSM1/cipher-box-next/issues/28) D5 (the engine owns
  the token lifecycle; challenge-signature login) and
  [#34](https://github.com/FSM1/cipher-box-next/issues/34) (the auth method set and the
  per-platform `CredentialStore`), neither of which this decision changes
- **Implemented by:** [FSM1/cipher-box#1253](https://github.com/FSM1/cipher-box/issues/1253)

## Context

There are **two** authentications in a CipherBox login, and the v2 blueprint conflates them.

1. **Unlocking the Core Kit.** An identity provider vouches for the person; the Core Kit
   returns the TSS key the login secret derives from.
2. **Authenticating to the CipherBox API.** The engine signs a challenge with the derived
   identity key.

[#28](https://github.com/FSM1/cipher-box-next/issues/28) D5 governs (2) and is correct as written. What was never decided is (1). v2 built it as
Web3Auth's own hosted OAuth; v1 built it as a CipherBox-issued JWT against a custom verifier.

The account model does not distinguish them, because it cannot: the Core Kit produces the same
key whichever provider vouched. So `blueprint/api.md`'s "Account = the Web3Auth-derived secp256k1
identity key" is true under both designs, and the choice of issuer was made in the client wiring
rather than in a decision.

### What the v2 choice costs

- **A wallet cannot be a first login.** SIWE authenticates an account; it cannot produce a login
  secret. So the wallet affordance on the cold login page dead-ends, and the refusal surfaces as
  "engine not started" — internal state, not anything the member can act on. `#938` proposes
  moving the affordance to a started-engine surface, which accommodates the limitation rather
  than removing it.
- **Passwordless email is delegated.** v1 owned it (`apps/api/src/auth/services/email-otp.service.ts`).
  v2 uses Web3Auth's `email_passwordless` sub-verifier, so the member's code delivery, its
  deliverability, its rate limits and its branding sit outside CipherBox.
- **The provider client ID was lost.** `subVerifierDetails.clientId` must be the OAuth provider's
  client ID; v2 passes the Web3Auth project client ID, so Google answers `401 invalid_client` for
  every attempt. `deploy-staging.yml` still supplies `VITE_GOOGLE_CLIENT_ID` and no v2 source
  reads it. This is a defect either way, not an argument about design.

### What v1 established about sharing

v1 shared **no** login code between its two hosts: roughly 3,600 lines in `apps/web` against
2,400 in `apps/desktop`, implementing the same flows twice. The shared boundary was drawn at the
bearer token — `packages/sdk` took `getAccessToken`, and everything that _produced_ a token was
above the shared runtime and therefore per-host.

That boundary drifted, measurably:

- web mapped `production → MAINNET`, desktop mapped `production → DEVNET`;
- web carried a device-factor auto-recovery branch desktop lacked;
- web signed SIWE with `viem/siwe`, desktop hand-concatenated the EIP-4361 string;
- email OTP worked on web and broke in packaged desktop, because the JS half read a Vite
  compile-time variable and the Rust half read a runtime one, so two halves of one flow addressed
  two different API hosts.

Two facts bound how far sharing can go. The Core Kit **ran correctly in the Tauri webview** —
same SDK, same verifier, MFA and device approval functional — so it is not the obstacle. And
Google credential collection **cannot** be shared: Google Identity Services does not work in that
webview, the manual OAuth2 flow it falls back to needs a `redirect_uri`, and a packaged Tauri
origin is `tauri://localhost`, which Google rejects as a non-`http(s)` scheme. v1 solved it with a
loopback server on pre-registered ports.

Wallet access is the same kind of fact: the Tauri webview reaches no wallet. v1 wrote
`loginWithWallet` for desktop and never wired it — no UI trigger, never exercised.

## Decision

**D1 — CipherBox issues the identity token the Core Kit consumes.** Each verified method mints a
CipherBox JWT, and the Core Kit logs in against a CipherBox custom verifier via `loginWithJWT`,
with the API's own JWKS as the verification key. Passwordless email returns to the API, with its
delivery provider configured rather than assumed. Google keeps its own OAuth client ID, distinct
from the Web3Auth project client ID.

**D2 — Wallet login is a first-class first login, on web only.** This amends #5. A wallet signature
verified by the API mints the same CipherBox JWT as any other method, so it reaches the same
derived identity key and needs no separate account model. It is web-only because the Tauri webview
cannot reach a wallet — a platform property, not a deferred feature. Desktop offers the method set
minus wallet, and offers no affordance that cannot complete.

**D3 — One orchestration, host-specific credential collection.** The sequencing — provider
credential → API exchange → Core Kit login → secret export → `start(secret)` — lives in a single
host-agnostic package that both hosts import. Credential collection is injected per host.

The boundary is drawn at **credential collection**, one step earlier than v1 drew it. Everything
after that point converged on one path in v1 and drifted only because it was written twice.
Amended by ADR 0039 D6 on 2026-09-26: D3 now reads "one orchestration and one set of auth surfaces,
with host-specific credential collection". The sequencing stays in `packages/login`, the React
surfaces live in `packages/auth-ui`, and the boundary at credential collection does not move.

### What this decision does not change

- The account is still the Web3Auth-derived secp256k1 identity key.
- Challenge-signature login to the API, the engine-held access JWT, and single-flight refresh
  (#28 D5) are untouched.
- The `CredentialStore` split stands: HTTP-only cookie on web, OS keychain on desktop (#34).
- The Core Kit still runs on the UI thread, owning its DOM and redirect flows, MFA enrollment and
  device approval.

## Alternatives rejected

**Keep Web3Auth's hosted OAuth and move the wallet affordance to a started-engine surface (#938).**
The smallest change, and it treats the symptom. It leaves a wallet unable to start a session at
all, leaves passwordless email delegated, and leaves the two client IDs conflated. #938's linked-
methods surface is still worth building; its premise is not.

**Move the orchestration into the engine.** Superficially the strongest option: the engine is
shared by construction, since desktop links `crates/engine` natively and web loads it as WASM, and
the engine already performs challenge-signature login, SIWE challenge/login/link, refresh and
logout. Rejected on two grounds. The Core Kit is a JS SDK that owns DOM and redirect flows, so it
cannot move; the engine would have to call back into the host for each step, and a new host seam
is a breaking change to `SeamSet`'s field-struct completeness gate and every implementor. And
under D1 the API exchange happens _before_ a login secret exists, so the engine would additionally
need a command surface that works unstarted — today `command()` refuses everything pre-start. That
is more change for less gain than a shared package, and it can be revisited once the identity
phase is stable.

**Share through `packages/client`.** It is defined as one of the three web-side units, and its
whole non-type surface assumes Workers, `navigator.locks`, `BroadcastChannel`, Service Workers,
IndexedDB and OPFS. `blueprint/desktop.md` rules that machinery out on desktop — "no RPC layer,
no worker, no tab leadership".

**Draw the boundary at the bearer token, as v1 did.** Proven to drift, with the evidence listed
above.

## Consequences

1. **`blueprint/api.md`'s "Identity and auth" section changes**: CipherBox becomes the identity-token
   issuer, the wallet method becomes first-class and web-only, and the "secondary auth method"
   clause goes.
2. **`blueprint/web-client.md` and `blueprint/desktop.md` login sections** must name the shared
   orchestration package and state that credential collection is per-host. Neither file currently
   mentions the other's units.
3. **The API gains surface**: a JWKS endpoint, a JWT mint per verified method, and email OTP with a
   delivery provider. `siwe.service.ts` survives from v1 and is the starting point for the wallet
   half.
4. **Two client IDs must be configured and documented.** One environment variable for both is the
   defect above; the template that implies one is enough is how it recurs.
5. **Desktop needs a JS frontend.** `apps/desktop/frontend` is a 43-line static HTML file with no
   bundler, no TypeScript and no dependencies, and the shell links no engine. This is new build
   configuration, not a refactor, and it is the largest single cost of D3.
6. **A JWKS caching hazard is already on record** from v1, in exactly this handoff. Whoever
   implements D1 should read it before writing the verification path.
7. **The drift risk changes shape rather than disappearing.** One orchestration with two collectors
   still allows the collectors to diverge; what it removes is divergence in the sequencing, the
   verifier configuration, and the network map, which is where v1's drift actually occurred.

## Gate

- A member with no prior session signs in with a wallet on web and reaches a working vault.
- The same account signs in with Google on desktop and reaches the same vault. The wallet method is
  absent there, rather than present and unable to complete.
- Passwordless email is delivered by CipherBox, and a code it did not issue is refused.
- The Core Kit token is verified against CipherBox's JWKS; a token signed by anything else is
  refused.
- One implementation of the orchestration is imported by both hosts. The per-host code is
  credential collection and nothing else.
- A missing or wrong provider client ID fails naming which one, rather than surfacing a provider
  error the member cannot act on.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
