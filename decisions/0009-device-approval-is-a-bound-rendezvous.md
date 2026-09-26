# ADR 0009 — Device approval is a bound rendezvous, and the recovery phrase is the guaranteed path

- **Status:** Accepted — implemented; the rendezvous, the factor seal and both device roles
  landed, and [FSM1/cipher-box#1262](https://github.com/FSM1/cipher-box/issues/1262) stays open
  for two web hardening items and the post-cutover desktop approver role
- **Date:** 2026-08-11
- **Relates to:** [#34](https://github.com/FSM1/cipher-box-next/issues/34) (the auth method
  set), ADR 0008 (which provider unlocks the Core Kit — this decision governs what happens
  when the account has a factor policy), and [#6](https://github.com/FSM1/cipher-box-next/issues/6)
  (the clean break, which is why the v1 schema is not inherited)
- **Implemented by:** [FSM1/cipher-box#1262](https://github.com/FSM1/cipher-box/issues/1262)

## Context

v2 has no MFA and no device approval. The whole surface is one refusal in
`apps/web/src/auth/coreKit.ts`: when the Core Kit returns `REQUIRED_SHARE`, the client logs
out, clears its store, and throws, with a comment saying recovery and device approval "are
not built yet". There is no API endpoint, no engine surface, and no UI.

**The blueprint says otherwise, and its framing is what hid this.** Three files call MFA and
device approval "chrome-side" or "UI-side" Core Kit UX (`web-client.md`, `desktop.md`,
`testing.md`). Device approval cannot be UI-side. An existing device approving a new one
needs a server-mediated rendezvous — a pending record, a poll, a response — and v1 built an
API module with its own table and migration to provide exactly that. Calling it Core Kit UX
concealed an API slice, which is why nothing tracks it.

The underlying constraint is real and does not go away: **the MPC Core Kit has no native
cross-device share transfer.** v1's research recorded Web3Auth confirming it is not publicly
supported. Every device-approval design is therefore an application-level workaround, and its
security properties are ours to get right rather than the SDK's.

### What v1 built, and where it fails

The shape was sound: the API is a bulletin board that stores and relays ciphertext. The new
device mints an ephemeral secp256k1 keypair, the approver ECIES-seals a factor key to that
public key, and the API holds only opaque text. The scoped pre-reconstruction token is
properly limited — `scope: ['device-approval']`, non-refreshable, and the guard fails closed
on any route not carrying `@AllowScope`.

Four properties did not hold, and they are the reason this decision exists rather than a
port.

**The server can read the factor key.** The API stores the requester's `ephemeralPublicKey`
as opaque text and echoes it back in the approver's poll. The approver seals to whatever that
response contains, checking only that it is on-curve. A malicious or compromised API
substitutes its own public key, receives a factor key sealed to itself, and decrypts. This is
compounded by CipherBox also being the Web3Auth verifier under ADR 0008: the operator who can
substitute the key can also mint the identity JWT that yields the verifier share, and factor
key plus verifier share is the threshold. **Under an active malicious-server model the v1
flow is not zero-knowledge.**

That gap was decided into existence rather than overlooked. v1's research asked whether a
confirmation code was needed and answered: "ECIES encryption is sufficient for v1. The
ephemeral key exchange ensures only the requesting device can decrypt." That reasoning treats
a server-relayed public key as trustworthy. The word "MITM" appears nowhere in the v1 MFA
corpus.

**The approval is cryptographically unbound.** Nothing in either request is signed.
`deviceId` and `respondedByDeviceId` are self-reported strings with shape validation only, so
the self-approval check compares two values an attacker controls. v1 minted a per-device
Ed25519 keypair, wrapped it under HKDF of the vault key, and **never signed anything with
it** — no caller reads its private half anywhere in the tree. The prior security review asked
for a signed challenge proving possession; it shipped as accepted risk with a regex instead.

**A human is asked to authorise on evidence they do not have.** The approver sees a device
name, a timestamp, and a static warning. The device name is attacker-supplied and passes
validation as `Chrome on macOS`. The ephemeral public key — the only value that identifies
what is actually being authorised — is never shown to anyone. To reach the prompt an attacker
needs only the _first_ factor, which is the thing MFA exists to survive.

**The approver clones its own live factor key.** `getCurrentFactorKey()` is copied verbatim to
the requester. A later `deleteFactor` removes a share but does not rotate the TSS key, re-key
content, or notify the API; the registry's `revoked` columns are written by nothing. A removed
device keeps what it took.

One more fact bears on scope: **v1's cross-device flow was never tested end to end.** Its UAT
cases for approval, denial, expiry, and recovery login are all recorded as skipped, needing
two authenticated devices. The desktop half was wired to real buttons and could never have
worked — it sent a 33-byte compressed public key where the DTO requires 65 uncompressed, a
guaranteed rejection on every attempt, and a grep-shaped verification marked it done.

## Decision

**D1 — Device approval is an API slice, and the blueprint says so.** The rendezvous is a
server-mediated exchange with its own endpoints, its own table, and its own expiry. The
"chrome-side Core Kit UX" framing is corrected in `web-client.md`, `desktop.md` and
`testing.md`. The API remains a bulletin board: it stores and relays ciphertext and never
holds plaintext key material.

**D2 — The recovery phrase is the guaranteed path; device approval is additive.** Every
account that enrolls a factor policy can always get in with its recovery phrase alone, on any
platform, with no second device and no server rendezvous. Device approval is a convenience on
top. If D3 and D4 cannot be met, device approval does not ship and the recovery phrase
carries the release — an account that cannot be recovered is worse than one that is
inconvenient to recover.

**D3 — The approved key is verified out of band, or it is not approved.** Both devices display
a short comparison value derived from the requester's ephemeral public key, and the approver
confirms the match before sealing. A substituted key yields a different value on the two
screens, so the substitution attack becomes visible to the person authorising it rather than
invisible to everyone. This is the property v1 explicitly traded away, and it is the one that
makes the rendezvous safe against its own relay.

**D4 — Both halves of the exchange are signed by device keys.** The request is signed by the
requesting device's identity key over the ephemeral public key it is asking to have sealed
to; the response is signed by the approving device's. The device identity key stops being
inert material and becomes what binds the exchange. Self-reported identifiers are no longer
the basis of any check.

**D5 — An approval mints a fresh factor for the requester; it never transfers the approver's
own.** No live factor key is cloned. Consequently, removing a factor is stated as what it is:
it revokes that factor's ability to reconstruct going forward, and it does not retroactively
un-share anything a device already extracted. If the product wants true revocation it requires
a key rotation and a re-key, which is a separate decision and is not made here.

## Alternatives rejected

**Port v1's design.** It is the fastest path and it ships a flow whose own security review
recorded the unsigned binding as accepted risk, and whose ephemeral key the server can
substitute. Under ADR 0008 the same operator issues the identity token, so porting would
concentrate both halves of the threshold in one party. The shape is worth keeping; the
properties are not.

**Ship MFA with no device approval at all, recovery phrase only.** Genuinely attractive: it
deletes the entire rendezvous, the table, the polling, and the attack surface with it, and
v1's evidence is that the cross-device path was never exercised anyway. Rejected as the
_whole_ answer because a recovery phrase is a single artefact a member can lose, and lockout
is unrecoverable in a non-custodial system — but adopted as the floor, which is what D2 says.

**A numeric code the member types from one device into the other, instead of comparing.**
Equivalent security, worse ergonomics on the platform mix, and it invites the same
approval-fatigue pattern the throttling in v1 existed to blunt. Comparison places the burden
where the evidence is.

**TOTP or SMS as additional factors.** Ruled out on architecture rather than preference, and
v1 reached the same conclusion: a six-digit ephemeral code cannot derive a deterministic
256-bit key, so the server would have to escrow an encrypted factor — which is the custodial
model this product exists to avoid.

## Consequences

1. **`blueprint/web-client.md`, `blueprint/desktop.md` and `blueprint/testing.md` change.**
   MFA and device approval stop being described as chrome-side Core Kit UX. The API surface is
   named where the other API surfaces are.
2. **The API gains a rendezvous surface and one table.** Request, poll, respond, cancel, and a
   pending list, all under a scoped pre-reconstruction token. The v1 shape is a reasonable
   starting point for the endpoints; the DTOs change, because D4 adds signatures and D3 adds
   nothing to the wire but changes what the client must display.
   Amended by ADR 0039 D2 and D3 on 2026-09-26: the API gains a rendezvous surface and two tables.
   `device_approvals` holds the rendezvous rows, and `account_devices` is the registry that D4
   needs; the endpoint list does not change.
3. **Expired and collected rows must be deleted.** v1 never garbage-collected either, so
   sealed factor material accumulated indefinitely. A row's lifetime ends at collection or
   expiry, whichever comes first.
4. **The device identity key becomes load-bearing.** Where it lives, how it is protected, and
   what happens when its store is cleared all become real questions rather than inert ones.
   v1 kept an Ed25519 key in IndexedDB wrapped under HKDF of the vault key and never used it.
5. **Desktop is in scope or it is explicitly out.** v1 shipped a UI that could not work and a
   settings string saying MFA was web-only. Whichever v2 chooses, the affordance and the
   truth must agree — the same rule ADR 0008 applies to the wallet method.
   Amended by ADR 0039 D4 on 2026-09-26: desktop is in scope as a requester only, enrollment is
   web-only, and the copy says where factors and approval are managed. The approver role stays open
   on FSM1/cipher-box#1514, a sub-issue of FSM1/cipher-box#1262.
6. **This needs a cross-device test that actually runs.** Every v1 case for this flow was
   skipped for want of two authenticated devices, which is precisely how a guaranteed-400 bug
   reached a verified status. A harness that drives two sessions is part of the work, not a
   follow-up to it.

## Gate

- A member with a factor policy signs in on a new device using only their recovery phrase, on
  every supported platform, with no second device involved.
- A member approves a new device from an existing one, and both devices show the same
  comparison value before the approval is possible.
- A rendezvous whose relayed ephemeral key has been altered produces **different** values on
  the two devices, and the approval cannot be completed without the member overriding a
  mismatch they can see.
- An approval request carrying an invalid signature is refused, and so is a response.
- The approver's own factor key is not transferred: after approval the two devices hold
  distinct factors.
- Expired and collected rendezvous rows are gone from the table.
- The cross-device flow is exercised by an automated test that drives two sessions, not by
  inspection.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The
`blueprint/` copies in this repository are the as-charted archive and are not edited by this
ADR.
