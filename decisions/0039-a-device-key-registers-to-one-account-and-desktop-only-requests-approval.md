# ADR 0039 — A device key registers to one account, and desktop only requests approval

- **Status:** Accepted on 2026-09-26 — retroactive; the rule shipped in FSM1/cipher-box#1273,
  FSM1/cipher-box#1312, FSM1/cipher-box#1527, FSM1/cipher-box#1577 and FSM1/cipher-box#1764, and
  the blueprint carries it. The requester role of D4 did not ship (E1); the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-26
- **Amends:**
  [ADR 0009](./0009-device-approval-is-a-bound-rendezvous.md)
  consequence 2 (the "one table" clause) and consequence 5 (desktop in scope or explicitly out,
  which this ADR settles);
  [ADR 0008](./0008-cipherbox-issues-the-identity-token.md)
  D3 (the shared boundary gains the React auth surfaces); and the `CredentialStore` row that
  [#46](https://github.com/FSM1/cipher-box-next/issues/46) charted as "the refresh token and
  last-account id only — never key material"
- **Relates to:** ADR 0008 D1 (CipherBox issues the identity token; the Core Kit logs in with
  `loginWithJWT`) and D2 (no wallet on desktop); ADR 0009 D2 (the recovery phrase is the
  guaranteed path), D4 (both halves signed by device keys) and D5 (a removed device keeps what
  it holds);
  [ADR 0015](./0015-the-device-approval-factor-seal-is-in-repo-ecies-on-secp256k1.md)
  (the factor seal, which this ADR does not change); AGENTS.md security rule 4 (the WebCrypto
  custody of the web Core Kit store); the `blueprint/api.md` "Identity and auth" and "Data model
  (complete)" sections; the `blueprint/desktop.md` "Engine wiring" seam table and "Tauri shell"
  section
- **Implemented by:** FSM1/cipher-box#1273 (the subject table, D1), FSM1/cipher-box#1312 (the
  device registry, D2 and D3), FSM1/cipher-box#1577 (the desktop copy and the absent
  affordances of D4),
  FSM1/cipher-box#1527 (the keychain custody of the Core Kit store, D5) and
  FSM1/cipher-box#1764 (the shared auth surfaces, D6). The decision source for D4, D5 and D6 is
  FSM1/cipher-box#1268 (2026-08-25 and 2026-08-26), with FSM1/cipher-box#1452 and
  FSM1/cipher-box#1453.

## Context

ADR 0008 moved the identity token to CipherBox. The Core Kit derives its TSS key from the pair
`(verifier, verifierId)`, so the API must give each provider identity one `verifierId` that
never changes. v1 did this with a `users` row per provider identity. That row carried a
placeholder `publicKey` (`pending-core-kit-<id>`), and its id was the `verifierId`. The shape
broke the invariant that an account is the derived key, and an abandoned login left a junk
account behind (FSM1/cipher-box#1273).

ADR 0009 D4 made both halves of the rendezvous carry a device-key signature. A signature is
only checkable against a key the account registered, so the API needs a device registry. The
registry must also solve a second problem. A device that cannot yet reconstruct its key holds
one credential: the CipherBox identity token. It has no access token and no account id. The
API must find the account whose devices can approve it from that token alone. v1 used
self-reported `deviceId` strings with shape checks only (FSM1/cipher-box#1264).
FSM1/cipher-box#1312 built the registry, and its PR body states the path: the registry row
records which identity subject the device signed in through.

ADR 0009 consequence 5 left desktop open: "Desktop is in scope or it is explicitly out." v1
shipped a desktop requester UI that sent a 33-byte key where the DTO required 65 bytes, so
every attempt failed. Beside it, a settings string said MFA was web-only. The owner decided the
desktop role on FSM1/cipher-box#1268. On 2026-08-25 the decision gave desktop no rendezvous
role, made enrollment web-only, and named two prerequisites. First, a keychain-backed Core Kit
store, because without it a recovered factor evaporates on quit and recovery becomes a
per-launch ritual (FSM1/cipher-box#1452). Second, the approval role arrives by reuse of the
web app's React auth components, not by a second implementation (FSM1/cipher-box#1453). On
2026-08-26 the owner changed the role to requester only for the cutover, with approval always
from a web session.

The blueprint carries these rules today in the `blueprint/api.md` "Identity and auth" section
(the `account_devices` and `identity_subjects` bullets) and in the `blueprint/desktop.md`
"Engine wiring" seam table and "Tauri shell" section. No ADR records them.
FSM1/cipher-box#2005 removed the `ADR 0008 D3` citation from the `packages/auth-ui` line,
because ADR 0008 D3 shares the login sequencing, not the React surfaces. That line has no
citation now.

## Decision

**D1 — `identity_subjects` maps a hashed provider identity to a stable subject id, and holds no
account.** A verified provider identity maps to one subject id. The identity token's `sub`
carries that id, and `loginWithJWT` takes it as its `verifierId`. The table stores the provider
identifier as a SHA-256 hash, never in the clear, under a unique index on `(kind,
identifier_hash)`. Resolution is insert-then-read, so two concurrent first logins for one
identity yield one subject. The table holds no `user_id`. The account still materializes at
`POST /auth/login` against the derived key, so this table cannot fork the account model. No
identity endpoint creates a `users` row. A later method link points another provider identity
at an existing subject; no link flow exists. The rule landed with FSM1/cipher-box#1273; this ADR
records it.

**D2 — A device identity key registers under a full session, with an Ed25519 signature over
the account id.** `account_devices` is the registry that makes the signatures of ADR 0009 D4
checkable. A registration needs a full access token, so the account is proven. A token scoped to
`device-approval` cannot register. The registration carries an Ed25519 signature by the device
key over a domain-tagged payload that binds the account id and the device key
(`cipherbox/device-registration/v1`), so possession is proven. The registration also carries
the identity token, and the row records the identity subject the device signed in through. That
subject is fixed at registration: a re-registration of the same key under another subject is
refused and changes nothing. One key registers to one account. A per-account cap bounds the
rows. Revocation is a hard delete, with the effect ADR 0009 D5 states. The rule landed with
FSM1/cipher-box#1312; this ADR records it.

**D3 — One identity subject reaches at most one account, and an identity with no registered
device gets no rendezvous.** The registry refuses a registration whose identity subject is
already linked to another account. The scoped pre-reconstruction token names the account that
the registry maps the subject to. When no registered device carries the subject, the API mints
no scoped token and opens no rendezvous. That account's path is the recovery phrase (ADR 0009
D2). The requesting device itself need not be registered: its request is self-signed, and the
responding device must be registered to the account. The rule landed with FSM1/cipher-box#1312;
this ADR records it.

**D4 — Desktop is a device-approval requester only through the cutover.** Approval always
happens in a web session. The desktop window offers no approver affordance, and its copy says
that sign-in factors and device approval are managed in CipherBox on the web, and that the
recovery phrase is the guaranteed way back with no second device. Enrollment of a factor
policy is web-only for the same reason. The approver role arrives after v2.0 by reuse of the
web app's components, never by a second implementation. The affordance and the truth agree.
The requester-only role was decided on 2026-08-26 in FSM1/cipher-box#1268, which replaced
the 2026-08-25 decision that gave desktop no rendezvous role. The web-only enrollment and the
approver role by reuse were decided on 2026-08-25 in the same issue.

**D5 — The desktop keychain `CredentialStore` also holds the key that seals the Core Kit
store.** The OS keychain (`keyring`, one service name) holds three entries: the refresh token,
the last-account id, and a 256-bit wrapping key for the login SDK's Core Kit store. It never
holds a seed or a key in the KDF catalog. The wrapping key is drawn from entropy, not
derived. Only sealed slots of the Core Kit store reach the disk. A sign-out and a
forget-this-device both purge the store. Decided on 2026-08-25 in FSM1/cipher-box#1268, which
named FSM1/cipher-box#1452 as the prerequisite of phrase-only recovery on desktop.

**D6 — Both hosts share the auth surfaces through `packages/auth-ui`.** The login form, the
recovery phrase prompt and the error banner are React components that both hosts mount. Each
component takes its host through props: no store, no router, no engine handle. Each host keeps
its own theme and its own wiring. Neither host keeps a second implementation of a shared
surface. The shell's window chrome, the vault panel and the licence footer stay in
`apps/desktop`. Decided on 2026-08-25 in FSM1/cipher-box#1268 (reuse, not duplication, through
FSM1/cipher-box#1453); FSM1/cipher-box#1764 chose the shared package over a mount of the
`apps/web` components.

## Trust argument

- **The subject table cannot attach an identity to an account.** D1 keeps `user_id` out, so no
  row in it names an account. The account is the key the Core Kit derives, as before ADR 0008.
- **A database reader does not get a member identifier in full.** D1 stores the identifier as
  a hash. The display column and the unsalted hash are the residual E2.
- **A registration proves the account and the key.** The full session proves the account. The
  signature over the account id proves possession of the device key, and a registration signed
  for one account does not verify for another. `verifyDeviceSignature` in
  `apps/api/src/device-approval/device-signature.ts` also demands a genuine Ed25519 key:
  canonical, on the curve, not of small order, and torsion-free. Without that check, a caller
  could register the identity point and sign every message with one fixed signature while it
  holds no secret (FSM1/cipher-box#1312).
- **A pre-reconstruction device cannot be steered onto an account by a race or a re-touch.**
  The subject check and the per-account cap run under advisory locks on the subject and the
  account. The subject on a row is fixed at registration, so the subject-to-account map is not
  last-writer-wins.
- **No rendezvous opens without a possible approver.** D3 refuses the scoped token when no
  registered device carries the subject. The API does not hand a scoped token to an identity
  that no approver can answer. The member keeps the recovery phrase.
- **Desktop holds no approver code, so it cannot seal a factor badly.** The approver seals a
  fresh factor and shows the comparison value of ADR 0009 D3. D4 keeps one implementation of
  that half, on web. The desktop copy tells the member the truth, so the v1 failure (a UI that
  could not work beside a settings string that said so) cannot recur.
- **The keychain entry is not a key in the vault key tree.** D5 keeps seeds and KDF catalog
  keys out of the keychain. The wrapping key is random, and it opens only the Core Kit store.
  That store holds the device factor, which reaches the login secret only together with the
  verifier share of a Core Kit login (ADR 0009 context). Each slot seals with XChaCha20-Poly1305
  from `crates/core`, and the AAD binds the slot name and the envelope version, so one slot's
  ciphertext does not open as another's (`crates/desktop-seams/src/core_kit_store.rs`).
- **One phrase prompt means one set of phrase-handling rules.** Under D6 both hosts blank the
  phrase field as they read it and normalize the phrase with one function from
  `packages/login`. A fix to that handling reaches both hosts. The shared components take no
  engine handle, so the package cannot reach a key.

## Alternatives rejected

**(a) The v1 subject shape: a `users` row per provider identity.** Its placeholder `publicKey`
breaks the rule that an account is the derived key, and each abandoned login leaves a junk
account (FSM1/cipher-box#1273).

**(b) A `user_id` on `identity_subjects`, to name the account before reconstruction.** The
subject table would then fork the account model. D2 records the link on the device row
instead, and only a full session can write it (FSM1/cipher-box#1273, FSM1/cipher-box#1312).

**(c) No rendezvous role on desktop.** This was the 2026-08-25 decision. The owner replaced it
on 2026-08-26: a desktop member who has a web session in reach can be approved from it, and the
recovery phrase still serves the member who has none.

**(d) The full approver role on desktop before the cutover.** It needs device identity key
custody in the webview, the approve and deny screens with the comparison value, and the desktop
leg of the two-session harness. The owner moved it past the cutover (FSM1/cipher-box#1514,
milestone `post-cutover`).

**(e) A `MemoryStore` for the desktop Core Kit store.** This was the shipped state. A factor
that a phrase recovery mints does not survive a quit, so every launch of an account with a
factor policy runs the full ceremony again (FSM1/cipher-box#1452).

**(f) Mount the `apps/web` components in the webview.** `apps/web` is a private application
with no export surface. Its auth components reach `useAuth`, `useEngine`, `react-router` and
`@cipherbox/client`, so the shell would pull the web engine host it does not use. The two real
differences, native Google collection and the shell's theme, would become branches in web code
(FSM1/cipher-box#1764).

**(g) Keep the framework-free DOM mirror in `apps/desktop/src/frontDoor.ts`.** Each web auth
surface then has a hand-written copy on desktop. ADR 0008 records how two copies of one login
flow drifted in v1.

## Consequences

1. **`blueprint/api.md` already carries D1 to D3.** The "Identity and auth" section holds the
   `account_devices` bullet (D2, D3) and the `identity_subjects` bullet (D1). The "Data model
   (complete)" section lists both tables. No text change is needed.

2. **`blueprint/desktop.md` already carries D4 to D6.** The "Engine wiring" seam table holds
   the `CredentialStore` row (D5). The "Tauri shell" section holds the "auth surfaces are shared
   through `packages/auth-ui`" bullet (D6) and the "Device approval is requester-only through
   the cutover" bullet (D4). No text change is needed.

3. **AGENTS.md already names `packages/auth-ui`** in Code Generation Guidelines item 1, as "the
   React auth surfaces both hosts render". `CONTEXT.md` holds no device-approval term, and this
   ADR adds none.

4. **ADR 0009 consequence 2 now reads:** "The API gains a rendezvous surface and two tables."
   `device_approvals` holds the rendezvous rows, and `account_devices` is the registry that D4
   needs (this ADR, D2 and D3). The endpoint list does not change.

5. **ADR 0009 consequence 5 is settled.** Desktop is in scope as a requester only, enrollment is
   web-only, and the copy says where factors and approval are managed (this ADR, D4). The
   approver role stays open on FSM1/cipher-box#1514, a sub-issue of FSM1/cipher-box#1262. The
   ADR 0009 status line names FSM1/cipher-box#1262 for that role.

6. **ADR 0008 D3 now reads:** one orchestration and one set of auth surfaces, with
   host-specific credential collection. The sequencing stays in `packages/login`, the React
   surfaces live in `packages/auth-ui` (this ADR, D6), and the boundary at credential collection
   does not move.

7. **The `CredentialStore` row that #46 charted now reads as D5.** "Never key material" becomes
   "never a seed, and never a key in the KDF catalog", and the Core Kit store wrapping key joins
   the refresh token and the last-account id.

8. **`blueprint/desktop.md` section "Tauri shell" gains the citation (ADR 0039)** on the
   `packages/auth-ui` bullet, and on the requester-only bullet beside "ADR 0009 consequence 5".

9. **`blueprint/desktop.md` section "Engine wiring" gains the citation (ADR 0039)** on the
   `CredentialStore` row.

10. **`blueprint/api.md` section "Identity and auth" gains the citation (ADR 0039)** on the
    `account_devices` bullet and on the `identity_subjects` bullet.

11. **The module comment of `packages/auth-ui/src/index.ts` gains the citation (ADR 0039).**
    Lines 1 and 2 still cite "(ADR 0008 D3)", which FSM1/cipher-box#2005 removed from the
    blueprint. That citation becomes ADR 0039.

## Residuals

**E1 — The desktop requester role is not built, and the cutover closed without it.** D4 holds
for "through the cutover", and the cutover closed on 2026-09-13 with the requester leg unbuilt.
At origin/main the desktop has no rendezvous role at all. `apps/desktop/src-tauri/src/main.rs`
lines 45 to 54 register no rendezvous command, and no file in `apps/desktop/src` holds a device
identity key. The body of FSM1/cipher-box#1764 states it: "The requester screen needs a
rendezvous seam this host does not have: no `deviceRendezvous` command exists in `src-tauri`,
and the webview holds no device identity key." The body of FSM1/cipher-box#1514 said that
desktop "currently ships as a device-approval requester only". That claim was false, and a
comment on FSM1/cipher-box#1514 corrects it on 2026-09-26. FSM1/cipher-box#2010 now tracks the
requester leg, and FSM1/cipher-box#1514 reuses its seam for the approver. The copy and the absent
affordance agree with each other today, so no member sees a control that cannot complete. This
ADR records the blueprint rule (D4). The owner ruled on 2026-09-26: D4 stands, and
FSM1/cipher-box#2010 is the open residual.

**E2 — The subject row keeps a partial identifier that no code reads.** Every mint writes
`identity_subjects.identifier_display` (`apps/api/src/auth/services/identity-subject.service.ts`,
from `identity-exchange.service.ts`). No code path reads it: the only `identifierDisplay`
reader, `apps/api/src/auth/services/auth.service.ts` line 204, selects from `auth_methods`. The
column keeps the full email domain and the first two characters of the local part for an email
or a Google account, and the first 6 and the last 4 characters of a wallet address. The hash
beside it is unsalted SHA-256 of Google's `sub`, a normalized email or an EIP-55 address
(`apps/api/src/auth/services/identity.service.ts`). A database reader can therefore test email
guesses in a narrow domain, and can recover a wallet address by hashing the public on-chain
addresses that match the prefix and the suffix. `account_devices.identity_subject_id` joins each
subject to a `user_id`, so the partial identifier attaches to an account.
FSM1/cipher-box#2011 tracks the removal of the column or a keyed hash.

**E3 — The operator can steer a pre-reconstruction device.** The operator issues the identity
token (ADR 0008 D1) and runs the registry. It can map a subject to any account. D2 and D3 do
not defend against the operator; ADR 0009 D3, the comparison value on both screens, is the
defence.

**E4 — A leaked identity token lets another account claim a member's subject first.** The
identity token is a 300-second bearer, and the API accepts it more than once
(`apps/api/src/auth/services/identity-token.service.ts`). At registration the registry does not
check that the presented token belongs to the account of the session
(`apps/api/src/device-approval/services/account-device.service.ts`). A holder of a full session
on their own account and a leaked identity token of another member can therefore register a
device under that member's subject first. D3 then refuses every device registration of the
member, and the member's approval requests post to the wrong account. No key is disclosed: a
factor for another TSS key does not open the member's account. FSM1/cipher-box#2012 tracks it.

**E5 — Methods do not cross-link.** Google and email for the same person yield two subjects
and two accounts. D1 leaves linking open and builds none (FSM1/cipher-box#1273).

**E6 — The keychain custody defeats a disk reader, not local code.** Only the Apple Keychain
binds an entry to the reading app. On the Secret Service and the Windows Credential Manager, any
process of the same user can read the wrapping key. The envelope does not bind freshness, so an
earlier sealed slot restored onto the disk opens as current. The store is per device, not per
account, so a forget drops what every account on the device held. The module header of
`crates/desktop-seams/src/core_kit_store.rs` states all three.

**E7 — The approver-reuse clause of D4 has no consumer yet.** The web device-approval screens
stay in `apps/web` until the desktop seam lands (FSM1/cipher-box#1764). D6 cannot move them into
`packages/auth-ui` before a second host mounts them.

## Gate

- **D1:** `apps/api/src/auth/identity.http.itest.ts` (API Integration, real Postgres): "creates
  no account row, whichever method vouched", "does not cross-link methods that share an email"
  and "mints one subject when the same identity logs in concurrently".
  `apps/api/src/auth/services/identity-subject.service.test.ts` (API Unit): "stores the
  identifier only as its hash, never in plaintext" and "keeps one identity from forking into two
  subjects across kinds". No test asserts that the table has no `user_id` column; the migration
  `apps/api/src/migrations/1784800000000-AddIdentitySubjects.ts` carries it. That is a finding.
- **D2:** `apps/api/src/device-approval/services/account-device.service.test.ts`: "refuses a
  signature bound to a different account id", "refuses a signature made by a different key",
  "refuses an identity token that does not verify", "refuses a re-touch presenting a different
  identity, and rewrites nothing", "rejects a key already registered to another account" and
  "rejects a registration past the per-account cap".
  `apps/api/src/device-approval/device-approval.http.itest.ts`: "is refused with 403 on every
  approval and registry route" (a scoped token cannot register).
  `apps/api/src/device-approval/device-signature.test.ts`: "refuses the identity-point universal
  forgery over the %s payload", "refuses %s, which proves possession of nothing" and "changes
  the registration bytes when any single field changes".
- **D3:** `account-device.service.test.ts`: "rejects an identity subject already linked to
  another account". `apps/api/src/device-approval/services/device-approval.service.test.ts`:
  "refuses an identity no registered device can approve, rather than opening an empty
  rendezvous", "scopes the token to the account the device registry names, not the identity
  subject" and "refuses a device that is not registered to this account".
  `device-approval.http.itest.ts`: "404s a session for an identity with no registered device"
  and "401s a response from a device not registered to the account".
- **D4:** `apps/desktop/src/frontDoor.test.tsx` (the `Desktop` area of `ci.yml`): "offers no
  factor or approval affordance of its own" and "says where factors are managed and that the
  recovery phrase always works". No test proves the requester role, because no code implements
  it (E1). That is a finding.
- **D5:** `crates/desktop-seams/tests/conformance.rs`:
  `nothing_the_sdk_stores_reaches_the_disk_in_the_clear`,
  `a_slot_sealed_under_one_wrapping_key_does_not_open_under_another`,
  `one_slots_ciphertext_does_not_open_as_another_slots_value`,
  `a_wrong_length_wrapping_key_fails_closed_rather_than_being_replaced` and the two
  `file_*_passes_the_core_kit_*_kit` tests, on every runner; the two
  `real_keyring_*_core_kit_*_kit` tests run with `--ignored` against the real OS keyring in the
  `Workspace tests (Linux)` and `Adapter tests` jobs of `ci-rust.yml`.
  `apps/desktop/src/auth/coreKit.test.ts`: "drops the whole store on a sign-out, not just the
  SDK session id". No test asserts that the keychain holds no seed and no catalog key; the
  keyring store in `crates/desktop-seams/src/credential_store.rs` names only the three
  accounts `refresh-token`, `last-account-id` and `core-kit-wrapping-key`. That is a finding.
- **D6:** `packages/auth-ui/src/EmailLoginForm.test.tsx` and
  `packages/auth-ui/src/RecoveryPhraseForm.test.tsx` run in the `Web` area; the
  `apps/desktop/src/frontDoor.test.tsx` cases drive the same shared surfaces in the `Desktop`
  area. A change under `packages/auth-ui/**` runs both areas. No test proves that neither host
  keeps a second implementation. AGENTS.md forbids assertions on source text, so review
  enforces this clause. That is a finding.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
