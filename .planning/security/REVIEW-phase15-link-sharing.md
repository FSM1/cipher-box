# Security Review: Phase 15 -- Link Sharing (Ephemeral Key Bridge)

**Date:** 2026-02-23
**Reviewer:** Claude Opus 4.6 (Security Agent)
**Scope:** Pre-implementation architectural review of Phase 15 plans
**Files analyzed:** 15-CONTEXT.md, 15-RESEARCH.md, 15-01-PLAN.md, 15-02-PLAN.md, 15-03-PLAN.md, plus existing Phase 14 code for context
**Crypto operations catalogued:** 8 (ephemeral keypair generation, 2x ECIES wrap, 2x ECIES unwrap, key zeroing, token generation, URL fragment handling)

---

## Executive Summary

The ephemeral key bridge design is **cryptographically sound** and maintains the zero-knowledge property. The core pattern (generate ephemeral keypair, wrap with ephemeral pubkey, embed ephemeral privkey in URL fragment, recipient unwraps and re-wraps with own key) is a well-established approach used by Signal, Bitwarden Send, and Firefox Send.

However, the review identified **8 findings** across the planned architecture that should be addressed before or during implementation. None are critical enough to block execution, but several are HIGH severity and should be implemented as specified in the recommendations.

**Issues by severity:**

- CRITICAL: 0
- HIGH: 3
- MEDIUM: 3
- LOW: 1
- INFO: 1

---

## Findings

### [HIGH] H-01: Unauthenticated Invite Status Endpoint Enables Token Existence Oracle

**Location:** `15-01-PLAN.md` Task 2, endpoint (a): `GET /invites/:token`

**Planned behavior:**

```text
GET /invites/:token  (no auth, ThrottlerGuard only)
Returns: { status: 'active' | 'expired' | 'claimed' | 'revoked' }
```

**Issue:**
The public (unauthenticated) `GET /invites/:token` endpoint returns differentiated status values (`active`, `expired`, `claimed`, `revoked`). This creates an oracle that leaks information:

1. **Token existence oracle:** An attacker can probe random tokens to determine if any valid invite exists. While 128 bits of entropy makes brute-force infeasible, if tokens are somehow leaked (browser history, logs, clipboard monitoring), an attacker can confirm a token is valid without possessing the ephemeral key.

2. **Status differentiation leaks metadata:** Distinguishing between `claimed`, `revoked`, and `expired` tells an attacker something about the share's lifecycle. A `claimed` status reveals that a recipient successfully accepted the share. A `revoked` status reveals the sharer actively cancelled it.

**Impact:**
Low practical impact due to 128-bit token entropy making enumeration infeasible. However, if a token is partially compromised (e.g., visible in browser history without the fragment key), the status oracle confirms the token is valid and reveals lifecycle state.

**Recommendation:**
Return only two possible responses: `{ status: 'active' }` or a 404 with no body. Merge `expired`, `claimed`, and `revoked` into a single "not available" response (404). This follows the principle of minimal information disclosure.

```typescript
// Instead of differentiated statuses:
async getInviteStatus(token: string): Promise<{ status: 'active' }> {
  const invite = await this.sharesService.getInviteStatus(token);
  if (!invite || invite.status !== 'active') {
    throw new NotFoundException(); // generic 404
  }
  return { status: 'active' };
}
```

**Blocks execution:** No -- the current design is functional. This is a hardening recommendation.

---

### [HIGH] H-02: Unauthenticated Endpoint Returns Encrypted Key Material

**Location:** `15-RESEARCH.md` Open Question 1, `15-01-PLAN.md` Task 2 endpoint (b)

**Planned behavior (from RESEARCH.md recommendation):**

> Return encrypted_key in the public GET. It's encrypted with the ephemeral key and completely useless without the fragment.

**Clarification from the plan:**
The plan actually splits this into two endpoints: (a) public status check returns only status, (b) `GET /invites/:token/data` requires JwtAuthGuard and returns the full encrypted payload. This is the correct design.

**Issue:**
The RESEARCH.md Open Question 1 recommends returning `encrypted_key` in the public GET endpoint, but the 15-01-PLAN correctly overrides this by creating a separate authenticated endpoint (`GET /invites/:token/data`) for the full payload. This is the right call. However, if an implementer follows the RESEARCH.md recommendation instead of the PLAN, they would expose encrypted key material on an unauthenticated endpoint.

While the encrypted key is indeed "useless without the ephemeral private key," defense-in-depth dictates that ciphertext should only be available to authenticated parties. Reasons:

1. Offline attacks: An attacker who intercepts both the token (from server-side logs/DB breach) and the URL fragment (from browser history) could attempt to unwrap the key. Adding an auth gate means they also need valid credentials.
2. Ciphertext availability: ECIES ciphertext using eciesjs v0.4.16 includes the ephemeral public key. Exposing it unnecessarily increases the attack surface for future cryptographic weaknesses.

**Impact:**
Mitigated by the plan's actual design (authenticated data endpoint). Risk only materializes if implementation deviates from the plan.

**Recommendation:**
The 15-01-PLAN's two-endpoint design is correct. Ensure implementation follows the PLAN, not the RESEARCH.md recommendation. Add a code comment to the authenticated data endpoint explaining why ciphertext is gated behind auth:

```typescript
// SECURITY: Encrypted key material is only returned to authenticated users.
// Even though the ciphertext requires the ephemeral private key (in URL fragment)
// to decrypt, defense-in-depth requires authentication as an additional barrier.
```

**Blocks execution:** No -- the plan already has the correct design. This finding is a clarification.

---

### [HIGH] H-03: Browser History Persists Ephemeral Private Key in URL

**Location:** `15-RESEARCH.md` (URL format), `15-03-PLAN.md` (InvitePage)

**Planned URL format:**

```text
https://app.cipherbox.cc/#/invite/TOKEN?key=EPHEMERAL_PRIV_KEY_HEX
```

**Issue:**
When a user navigates to the invite URL, the browser stores the full URL (including the hash fragment with the ephemeral private key) in:

1. **Browser history** (`history.pushState` / back button) -- persists across sessions
2. **Address bar** -- visible to shoulder surfing
3. **Browser extensions** -- many extensions can read `window.location.href`
4. **Clipboard** -- the URL was auto-copied on creation; it may remain in clipboard history

The research document (Pitfall 4) identifies this risk and recommends "Immediately clears `window.location.hash` after reading." However, neither the plan (15-03-PLAN.md) nor the research's InvitePage code examples implement this clearing.

**Impact:**
If an attacker gains access to the recipient's browser history (physical access, synced history, browser extension), they can recover the ephemeral private key. Combined with the invite token (also in the URL), they could potentially claim the invite or (if already claimed) gain no additional access since the invite is single-use. However, the plaintext key material (file/folder key) is exposed during the unwrap step, so if an attacker replays the claim flow with a stolen URL before the legitimate recipient, they gain access to the shared content.

**Recommendation:**
Add explicit guidance to 15-03-PLAN.md Task 2 (InvitePage):

1. **Clear the URL fragment immediately after reading the ephemeral key:**

```typescript
// InvitePage.tsx -- on mount, after reading key
useEffect(() => {
  const key = searchParams.get('key');
  if (key) {
    ephemeralKeyRef.current = key;
    // Clear key from URL to prevent browser history persistence
    // Use replaceState to avoid adding a new history entry
    const cleanUrl = window.location.href.split('?')[0];
    window.history.replaceState(null, '', cleanUrl);
  }
}, []);
```

Note: With HashRouter, clearing the search params within the hash requires care. `window.location.hash` contains `#/invite/TOKEN?key=HEX`, so:

```typescript
// HashRouter-aware URL clearing
const hashPath = window.location.hash;
const cleanHash = hashPath.split('?')[0]; // "#/invite/TOKEN"
window.history.replaceState(null, '', window.location.pathname + cleanHash);
```

2. **Do not store the ephemeral key in React state** -- the plan already correctly uses a `useRef` for this. Good.

3. **Zero the ref after claim** -- the plan specifies this. Ensure it happens in a `finally` block.

**Blocks execution:** No, but this is a strongly recommended hardening measure that should be implemented.

---

### [MEDIUM] M-01: Referrer Header May Leak Invite URL to External Origins

**Location:** `15-03-PLAN.md` (InvitePage), `index.html`

**Issue:**
The InvitePage will include external resources:

- Google Fonts (`fonts.googleapis.com`, `fonts.gstatic.com`) loaded in `index.html`
- Google Sign-In script (`accounts.google.com/gsi/client`) loaded by `GoogleLoginButton.tsx`

When the browser loads these external resources from the invite page, the `Referer` HTTP header may include the full URL. While modern browsers typically strip the fragment from the Referer header (per the Fetch spec), this behavior is not guaranteed across all browsers and proxy configurations.

Additionally, the Caddy configuration (`docker/Caddyfile`) does not set a `Referrer-Policy` header. Without an explicit policy, browsers use the default `strict-origin-when-cross-origin`, which sends the origin + path but NOT the fragment. This is safe for the ephemeral key (which is in the fragment), but the invite token in the path portion (`/invite/TOKEN`) would be visible in Referer headers to external origins.

However, since the app uses HashRouter, the path is always `/` (or `/index.html`) and the token is within the fragment: `/#/invite/TOKEN?key=HEX`. This means the Referer header would only contain the origin, which is safe.

**Impact:**
Low -- HashRouter's fragment-based routing means the token and key never appear in Referer headers under normal browser behavior. However, misconfigured proxies or non-standard browser behavior could theoretically leak information.

**Recommendation:**
As defense-in-depth, add `Referrer-Policy: no-referrer` to the Caddy configuration for the web app, and add a `<meta>` tag to `index.html`:

```html
<meta name="referrer" content="no-referrer" />
```

Or add to Caddyfile:

```text
app-staging.cipherbox.cc {
    header Referrer-Policy "no-referrer"
    ...
}
```

**Blocks execution:** No.

---

### [MEDIUM] M-02: Claimed Invite Token Remains Valid for Data Fetch After Claim

**Location:** `15-01-PLAN.md` Task 2

**Planned behavior:**

- `claimInvite()` atomically updates status to `claimed`
- `getInviteForClaim()` returns data if status is `active`
- But there is no explicit statement about what `GET /invites/:token/data` returns after claiming

**Issue:**
After an invite is claimed, the ShareInvite record transitions to `status: 'claimed'`. However, the record still exists in the database with the encrypted key material. If `getInviteForClaim()` is called again after claiming, the behavior depends on whether it checks for `status === 'active'`.

The plan specifies the atomic UPDATE checks `status = 'active'`, which prevents double-claiming. But the authenticated GET data endpoint (`GET /invites/:token/data`) may still return the encrypted payload for a claimed invite, depending on implementation.

This is not a key compromise risk (the ephemeral key should be zeroed), but it is unnecessary data retention.

**Impact:**
Minimal -- the encrypted key material is useless without the ephemeral private key, which should be zeroed. But defense-in-depth favors deleting or hiding claimed invite data.

**Recommendation:**
Ensure `getInviteForClaim()` returns data ONLY when `status === 'active'`. After claiming, the data endpoint should return 404 or `{ status: 'claimed' }` without the encrypted key payload. Consider hard-deleting claimed invite records after a short grace period (e.g., 24 hours) or immediately converting them to a lightweight audit record without the encrypted key material.

```typescript
async getInviteForClaim(token: string): Promise<ShareInvite | null> {
  const invite = await this.inviteRepo.findOne({ where: { token } });
  if (!invite) return null;
  if (invite.status !== 'active') return null; // Not just expired check
  if (invite.expiresAt < new Date()) {
    await this.inviteRepo.remove(invite);
    return null;
  }
  return invite;
}
```

**Blocks execution:** No.

---

### [MEDIUM] M-03: Race Condition Window Between Status Check and Claim

**Location:** `15-03-PLAN.md` Task 2 and Task 3 (InvitePage flow)

**Planned client-side flow:**

1. On mount: `checkInviteStatus(token)` -- unauthenticated GET
2. User authenticates
3. After auth: `claimInvite(token, ephemeralKeyHex)` which internally calls `GET /invites/:token/data` then `POST /invites/:token/claim`

**Issue:**
There is a time-of-check-to-time-of-use (TOCTOU) gap between step 1 (status check shows "active") and step 3 (claim attempt). During this window:

- Another recipient with the same URL could claim the invite
- The sharer could revoke the invite
- The invite could expire (7-day TTL, unlikely during a single session)

The plan handles this correctly at the database level (atomic UPDATE with status check). The client will receive a ConflictException (409) or NotFoundException (404) on the claim attempt and should show an appropriate error.

**Impact:**
Not a security vulnerability per se -- the atomic claim prevents double-claiming. But the UX flow needs to handle the case where a user authenticates (potentially creating a new account) only to find the invite is no longer available.

**Recommendation:**
Ensure the InvitePage error handling in the claim flow (15-03-PLAN.md Task 3, step 2d) properly handles:

- 409 Conflict: "This link has already been claimed by someone else"
- 404 Not Found: "This link is no longer available"
- 403 Forbidden: "You cannot claim your own share link" (self-claim prevention)

Consider re-checking invite status immediately before showing the auth UI (step 2 in the flow) to minimize wasted auth effort, though this is a UX optimization, not a security requirement.

**Blocks execution:** No.

---

### [LOW] L-01: Item Name Stored in Plaintext on ShareInvite Record

**Location:** `15-RESEARCH.md` ShareInvite entity, `itemName` column

**Planned design:**

```typescript
@Column({ type: 'varchar', length: 255, name: 'item_name' })
itemName!: string;
```

**Issue:**
The `itemName` field stores the plaintext name of the shared file/folder on the server. This is consistent with the Phase 14 Share entity (which has the same `itemName` field with the comment "Privacy impact is minimal -- server already knows user IDs involved"). However, it does leak the file/folder name to the server, which is a minor zero-knowledge violation.

The existing Phase 14 codebase already accepted this trade-off. Phase 15 inherits it.

**Impact:**
The server learns file/folder names of shared items. This is a metadata leak, not a content leak. The decision was already made in Phase 14 and documented.

**Recommendation:**
No change required -- this is a known, accepted trade-off. For future hardening, consider encrypting `itemName` with the ephemeral key so the server stores ciphertext. This would require the recipient to decrypt the name after claiming, which adds complexity for minimal security gain in a technology demonstrator.

**Blocks execution:** No.

---

### [INFO] I-01: Ephemeral Key Bridge Pattern Is Cryptographically Sound

**Location:** Entire Phase 15 design

**Analysis:**
The ephemeral key bridge pattern correctly implements the following cryptographic flow:

```text
SHARER:
  1. ephPriv, ephPub = secp256k1.generateKeypair()
  2. wrappedKey = ECIES.encrypt(itemKey, ephPub)
     [internally: ECDH(ephemeral', ephPub) -> HKDF -> AES-GCM]
  3. store wrappedKey on server
  4. embed ephPriv in URL fragment (never sent to server)
  5. zero ephPriv from memory

RECIPIENT:
  6. parse ephPriv from URL fragment
  7. fetch wrappedKey from server (authenticated)
  8. itemKey = ECIES.decrypt(wrappedKey, ephPriv)
  9. reWrapped = ECIES.encrypt(itemKey, recipientPub)
  10. zero itemKey, zero ephPriv
  11. send reWrapped to server (creates Share record)
```

**Security properties verified:**

- **Zero-knowledge:** The server never sees `ephPriv` (URL fragment), `itemKey` (only ciphertext), or the recipient's private key. The server stores only ECIES ciphertext, which is indistinguishable from random without the ephemeral private key. CONFIRMED.

- **Forward secrecy of ephemeral key:** Each invite link uses a fresh ephemeral keypair. Compromise of one link's ephemeral key does not affect other links. CONFIRMED.

- **Single-use claim:** Atomic database UPDATE prevents race conditions on claiming. CONFIRMED.

- **Key separation:** The ephemeral key is used only for the bridge operation. After claiming, the share uses the recipient's own long-term key (standard Phase 14 ECIES wrapping). CONFIRMED.

- **ECIES implementation:** `eciesjs` v0.4.16 uses: ephemeral secp256k1 keypair -> ECDH -> HKDF-SHA256 -> AES-256-GCM. This is the standard ECIES construction with authenticated encryption. Each `encrypt()` call generates a fresh internal ephemeral key, so even wrapping the same plaintext twice produces different ciphertext. CONFIRMED.

- **No nonce reuse:** AES-GCM nonces are derived via HKDF from the ECDH shared secret, which is unique per encryption due to fresh ephemeral keys. CONFIRMED.

**One note on the double-ephemeral layer:** In step 2, `eciesjs.encrypt()` internally generates its own ephemeral keypair for the ECDH exchange, in addition to the ephemeral keypair the application generates for the bridge. This means there are actually TWO ephemeral keypairs in play during invite creation. This is correct and does not introduce any weakness -- it simply means the library's internal ECIES construction is independent of the application-level ephemeral key bridge.

**No action required.** The design is sound.

---

## Additional Considerations

### Clipboard Security

The plan specifies auto-copying invite URLs to clipboard. Modern clipboard APIs (`navigator.clipboard.writeText()`) are restricted to secure contexts (HTTPS) and require user gesture or permission. The plan correctly uses this API. However:

- Clipboard contents may be synced across devices (e.g., Apple Universal Clipboard, Windows clipboard history)
- Clipboard monitoring malware can intercept the URL
- Users may paste the URL into insecure channels (Slack, email, etc.)

These are inherent risks of any link-sharing system and cannot be mitigated by CipherBox. The 7-day expiry and single-claim model limit the window of exposure.

### Token Entropy

128 bits of entropy (16 bytes, base64url-encoded to ~22 chars) provides adequate protection against brute-force enumeration. At 10 requests/second (the throttler limit), exhausting the keyspace would take approximately 10^27 years. This is sufficient.

### Auto-Cleanup Pattern

The plan uses the Phase 12.4 "auto-expire on read" pattern, which is appropriate for short-lived invite records. Hard-deleting expired records on read is preferable to soft-deletion for security (reduces data retention). The plan correctly specifies hard-delete for expired invites.

### Third-Party Scripts on Invite Page

The invite landing page will load Google's Sign-In script (`accounts.google.com/gsi/client`) for OAuth authentication. This third-party script runs in the same origin and can access `window.location.hash`. However:

1. The recommendation in H-03 to clear the URL fragment immediately after reading mitigates this risk
2. Google's script is loaded for authentication purposes and is a trusted dependency already present on the Login page
3. The `fflate` CDN script on `recovery.html` is not loaded on the invite page

### Memory Zeroing Limitations

The plan correctly specifies `.fill(0)` for zeroing key material. However, in JavaScript:

- The garbage collector may retain copies of the original Uint8Array
- String representations (hex encoding) of keys cannot be reliably zeroed
- V8's optimizing compiler may eliminate `.fill(0)` calls as dead code if the array is not subsequently read

These are fundamental limitations of JavaScript's memory model. The plan's approach of zeroing is best-effort and follows the same pattern already established in the Phase 14 ShareDialog. No additional mitigation is possible without moving to a WebAssembly-based crypto module.

---

## Verification Against Security Dimensions

| Dimension                 | Assessment                                                                                                  | Status                              |
| ------------------------- | ----------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| Zero-knowledge property   | Server never sees ephemeral privkey or plaintext keys. ECIES ciphertext only.                               | PASS                                |
| Cryptographic correctness | ECIES with secp256k1 + AES-256-GCM via eciesjs. Fresh ephemeral keys per operation.                         | PASS                                |
| Key lifecycle management  | Ephemeral keys generated, used once, zeroed. Plan specifies `finally` blocks.                               | PASS (with H-03 hardening)          |
| Trust boundary analysis   | Server stores only ciphertext + metadata. Token is opaque. Key is in fragment.                              | PASS (with L-01 accepted trade-off) |
| Attack surface            | New unauthenticated endpoint adds token oracle risk (H-01). Rate-limited.                                   | PASS (with H-01 hardening)          |
| URL fragment security     | HashRouter keeps everything in fragment. Browser history risk (H-03). No Referrer leak (M-01).              | PASS (with H-03 and M-01 hardening) |
| Race conditions           | Atomic UPDATE prevents double-claim. TOCTOU gap handled at DB level.                                        | PASS                                |
| Data flow integrity       | Attacker cannot substitute wrapped keys without ephemeral privkey. Claim creates standard Phase 14 records. | PASS                                |

---

## Recommended Test Cases

### Cryptographic Correctness Tests

```typescript
describe('Ephemeral Key Bridge', () => {
  describe('Positive Cases', () => {
    it('round-trips: wrap with ephemeral pubkey, unwrap with ephemeral privkey', async () => {
      const ephKeypair = generateEphemeralKeypair();
      const itemKey = crypto.getRandomValues(new Uint8Array(32));
      const wrapped = await wrapKey(itemKey, ephKeypair.publicKey);
      const unwrapped = await unwrapKey(wrapped, ephKeypair.privateKey);
      expect(unwrapped).toEqual(itemKey);
    });

    it('re-wrap produces valid ciphertext for recipient key', async () => {
      const ephKeypair = generateEphemeralKeypair();
      const recipientKeypair = generateEphemeralKeypair(); // reuse for test
      const itemKey = crypto.getRandomValues(new Uint8Array(32));

      // Sharer wraps with ephemeral pubkey
      const wrappedEph = await wrapKey(itemKey, ephKeypair.publicKey);

      // Recipient unwraps with ephemeral privkey, re-wraps with own pubkey
      const plaintext = await unwrapKey(wrappedEph, ephKeypair.privateKey);
      const wrappedRecipient = await wrapKey(plaintext, recipientKeypair.publicKey);

      // Recipient can decrypt with own privkey
      const final = await unwrapKey(wrappedRecipient, recipientKeypair.privateKey);
      expect(final).toEqual(itemKey);
    });
  });

  describe('Negative Cases', () => {
    it('rejects unwrap with wrong ephemeral private key', async () => {
      const ephKeypair1 = generateEphemeralKeypair();
      const ephKeypair2 = generateEphemeralKeypair();
      const itemKey = crypto.getRandomValues(new Uint8Array(32));
      const wrapped = await wrapKey(itemKey, ephKeypair1.publicKey);
      await expect(unwrapKey(wrapped, ephKeypair2.privateKey)).rejects.toThrow();
    });

    it('rejects tampered ciphertext', async () => {
      const ephKeypair = generateEphemeralKeypair();
      const itemKey = crypto.getRandomValues(new Uint8Array(32));
      const wrapped = await wrapKey(itemKey, ephKeypair.publicKey);
      wrapped[wrapped.length - 1] ^= 0xff; // flip last byte (auth tag)
      await expect(unwrapKey(wrapped, ephKeypair.privateKey)).rejects.toThrow();
    });
  });

  describe('Key Zeroing', () => {
    it('ephemeral private key is zeroed after invite creation', async () => {
      // Verify that createInviteLink zeros the ephemeral private key
      // This requires inspecting the returned/captured keypair after the call
    });

    it('ephemeral private key is zeroed after claim (success)', async () => {
      // Verify ref is null after successful claim
    });

    it('ephemeral private key is zeroed after claim (failure)', async () => {
      // Verify ref is null even when claim throws
    });
  });
});
```

### API Security Tests

```typescript
describe('Invite API Security', () => {
  describe('Token Enumeration Protection', () => {
    it('returns consistent response for nonexistent tokens', async () => {
      const res = await request(app).get('/invites/nonexistent-token');
      expect(res.status).toBe(404);
    });

    it('rate-limits unauthenticated status checks', async () => {
      // Send 11 requests in 1 second (limit is 10/s)
      // Expect 429 on the 11th
    });
  });

  describe('Single-Claim Atomicity', () => {
    it('prevents concurrent double-claim', async () => {
      // Create invite, then race two claim requests
      const [res1, res2] = await Promise.all([
        claimInvite(token, user1Token, body),
        claimInvite(token, user2Token, body),
      ]);
      const successes = [res1, res2].filter((r) => r.status === 201);
      expect(successes).toHaveLength(1);
    });

    it('returns 409 for already-claimed invite', async () => {
      // Claim once, then attempt again
    });
  });

  describe('Authorization', () => {
    it('requires auth for GET /invites/:token/data', async () => {
      const res = await request(app).get(`/invites/${token}/data`);
      expect(res.status).toBe(401);
    });

    it('requires auth for POST /invites/:token/claim', async () => {
      const res = await request(app).post(`/invites/${token}/claim`);
      expect(res.status).toBe(401);
    });

    it('prevents self-claim', async () => {
      // Create invite as userA, attempt claim as userA
      const res = await claimInvite(token, userAToken, body);
      expect(res.status).toBe(409); // or 403
    });

    it('only sharer can revoke invite', async () => {
      // Create invite as userA, attempt revoke as userB
      const res = await revokeInvite(inviteId, userBToken);
      expect(res.status).toBe(403);
    });
  });

  describe('Expiry', () => {
    it('auto-expires invites past TTL', async () => {
      // Create invite with short TTL (test fixture)
      // Wait, then check status -- should be expired
    });

    it('expired invite cannot be claimed', async () => {
      // Attempt to claim an expired invite
    });
  });
});
```

### URL Fragment Security Tests

```typescript
describe('URL Fragment Security', () => {
  it('ephemeral key is within hash fragment, not query string', () => {
    const url = buildInviteUrl('test-token', 'deadbeef');
    const parsed = new URL(url);
    expect(parsed.search).toBe(''); // no server-visible query params
    expect(parsed.hash).toContain('key=deadbeef');
  });

  it('URL fragment is cleared after reading ephemeral key', () => {
    // Render InvitePage with URL containing key
    // Assert window.location.hash no longer contains ?key=
  });
});
```

---

## SECURITY REVIEW COMPLETE

**Files analyzed:** 13 (5 plan/context files + 8 existing code files)
**Crypto operations found:** 8
**Issues found:** 8 (0 Critical, 3 High, 3 Medium, 1 Low, 1 Info)

### Critical Issues

None found.

### High Priority

1. **H-01:** Unauthenticated status endpoint leaks invite lifecycle state -- return only active/404
2. **H-02:** RESEARCH.md recommends returning encrypted keys on public endpoint, but PLAN correctly uses authenticated endpoint -- ensure implementation follows PLAN
3. **H-03:** Browser history persists ephemeral private key in URL -- clear fragment after reading

### Test Cases Generated

12 test suggestions across 5 categories (crypto correctness, API security, authorization, expiry, URL fragment)

### Report Location

`.planning/security/REVIEW-phase15-link-sharing.md`

### Recommendations (Priority Order)

1. **[H-03]** Clear URL fragment immediately after reading ephemeral key on InvitePage mount (add `window.history.replaceState` call)
2. **[H-01]** Collapse unauthenticated status endpoint to return only `active` or 404 (no differentiated error states)
3. **[M-01]** Add `Referrer-Policy: no-referrer` to Caddyfile and/or `<meta name="referrer" content="no-referrer">` to index.html
4. **[H-02]** Verify implementation follows PLAN's authenticated data endpoint, not RESEARCH.md's public endpoint suggestion
5. **[M-02]** Ensure `getInviteForClaim()` returns null for non-active invites; consider clearing encrypted key material after claim
6. **[M-03]** Handle all claim error codes in InvitePage UX (409, 404, 403)
