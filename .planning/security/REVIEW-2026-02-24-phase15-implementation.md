# Security Review: Phase 15 -- Link Sharing (Post-Implementation)

**Date:** 2026-02-24
**Reviewer:** Claude Opus 4.6 (security:review command)
**Scope:** Post-implementation code review of Phase 15 (Link Sharing / Ephemeral Key Bridge)
**Prior review:** `.planning/security/REVIEW-phase15-link-sharing.md` (pre-implementation architectural review, 2026-02-23)
**Files reviewed:** 18 implementation files + 4 test files

---

## Executive Summary

The Phase 15 implementation **faithfully follows the plan and addresses all HIGH-severity findings** from the pre-implementation review. The ephemeral key bridge is correctly implemented: ephemeral keypairs are generated per invite, the private key is embedded in the URL fragment (never sent to server), plaintext key material is zeroed in `finally` blocks, and the atomic claim prevents race conditions. The implementation adds a pre-transaction check that elegantly prevents the token-existence oracle identified in H-01.

**Risk Level:** LOW

**Issues by severity:**

- CRITICAL: 0
- HIGH: 0
- MEDIUM: 2
- LOW: 4
- INFO: 2

---

## Planning Review Findings -- Disposition

| Finding                            | Severity | Status              | Notes                                                                                                                               |
| ---------------------------------- | -------- | ------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| H-01: Token existence oracle       | HIGH     | **ADDRESSED**       | Controller returns only `{ status: 'active' }` or 404. Pre-transaction check in `claimInvite` also prevents oracle via 409 leakage. |
| H-02: Authenticated data endpoint  | HIGH     | **ADDRESSED**       | `GET /invites/:token/data` behind `JwtAuthGuard`. SECURITY comment present (line 64).                                               |
| H-03: Browser history persistence  | HIGH     | **ADDRESSED**       | `navigate('/invite/${token}', { replace: true })` clears key from URL on mount.                                                     |
| M-01: Referrer policy              | MEDIUM   | **NOT IMPLEMENTED** | No `Referrer-Policy` header or `<meta name="referrer">`. Carried forward as M-01 below.                                             |
| M-02: Claimed invite data exposure | MEDIUM   | **ADDRESSED**       | `getInviteForClaim()` returns null for non-active invites. Data endpoint returns 404.                                               |
| M-03: TOCTOU error handling        | MEDIUM   | **ADDRESSED**       | InvitePage handles 409 (claimed), 404 (expired), and generic error states.                                                          |
| L-01: Plaintext item name          | LOW      | **ACCEPTED**        | Same trade-off as Phase 14, documented.                                                                                             |
| I-01: Crypto pattern sound         | INFO     | **CONFIRMED**       | Implementation matches the reviewed design.                                                                                         |

---

## New Findings

### [MEDIUM] M-01: Referrer Policy Not Implemented (Carried Forward)

**Location:** `apps/web/index.html`, `docker/Caddyfile`

**Issue:**
The pre-implementation review (M-01) recommended adding `Referrer-Policy: no-referrer` to the Caddyfile and/or a `<meta name="referrer" content="no-referrer">` tag to `index.html`. Neither was implemented.

As noted in the planning review, this is low-impact because HashRouter keeps the token and key in the URL fragment, which browsers strip from the Referer header by default. However, defense-in-depth still recommends the meta tag.

**Impact:** Low. The fragment is not sent in Referer headers under normal browser behavior.

**Recommendation:**
Add to `apps/web/index.html`:

```html
<meta name="referrer" content="no-referrer" />
```

**Effort:** Trivial (one line).

---

### [MEDIUM] M-02: OpenAPI Enum Overstates Possible Status Values

**Location:** `apps/api/src/shares/dto/invite-response.dto.ts:38-43`

**Issue:**
The `InviteStatusResponseDto` declares the swagger enum as:

```typescript
@ApiProperty({
  enum: ['active', 'expired', 'claimed', 'revoked'],
})
status!: string;
```

But the controller (`invites.controller.ts:52-57`) only ever returns `{ status: 'active' }` -- any other state throws a 404. This creates misleading API documentation and causes the generated client to include unreachable type variants (`InviteStatusResponseDtoStatus` in `apps/web/src/api/models/`).

**Impact:** No security impact. Misleading documentation could confuse future implementers into thinking the endpoint returns differentiated statuses, potentially undoing the H-01 oracle prevention.

**Recommendation:**
Change the enum to `['active']` only:

```typescript
@ApiProperty({
  enum: ['active'],
  description: 'Invite status. Only "active" is returned; all other states result in 404.',
})
status!: string;
```

---

### [LOW] L-01: Client-Side Status Types Include Unreachable States

**Location:** `apps/web/src/services/invite.service.ts:296-304`

**Issue:**
The `checkInviteStatus` function signature returns `Promise<'active' | 'expired' | 'claimed' | 'revoked'>`, but since the server only returns `{ status: 'active' }` (all other states are 404), the catch block always returns `'expired'`. The effective return type is `'active' | 'expired'`.

The `InvitePage` handles all four variants (lines 100-103), but `'claimed'` and `'revoked'` are unreachable code paths for the status check flow. They could be reached in the claim error handling (lines 141-148), which uses HTTP status codes, not the status string.

**Impact:** No security impact. Dead code that may confuse maintainers.

**Recommendation:** Simplify the return type to `'active' | 'expired'` and update InvitePage error handling to derive `ErrorReason` only from HTTP status codes in the claim flow.

---

### [LOW] L-02: No Token Format Validation at API Boundary

**Location:** `apps/api/src/shares/invites.controller.ts:52`, `:token` param

**Issue:**
The `:token` path parameter has no input validation (length, character set). Tokens are generated as `randomBytes(16).toString('base64url')` which produces a 22-character base64url string. Any string is accepted by the endpoint and passed to the database for lookup.

**Impact:** Minimal. Invalid tokens hit the database `findOne` and return null, which maps to 404. However, rejecting obviously malformed tokens (e.g., >100 chars, non-base64url characters) at the controller level avoids unnecessary database queries and reduces the attack surface for SQL/NoSQL injection (though TypeORM parameterizes queries).

**Recommendation:**
Add a validation pipe to the token parameter:

```typescript
@Param('token', new ParseTokenPipe()) token: string
```

Or use a simple regex check:

```typescript
@Matches(/^[A-Za-z0-9_-]{20,24}$/)
```

**Effort:** Low.

---

### [LOW] L-03: encryptedChildKeys Stored as JSONB Hex Strings

**Location:** `apps/api/src/shares/entities/share-invite.entity.ts:48-53`

**Issue:**
The `encryptedChildKeys` column stores ECIES ciphertext as hex strings within a JSONB column:

```typescript
@Column({ type: 'jsonb', name: 'encrypted_child_keys', nullable: true })
encryptedChildKeys!: Array<{
  keyType: 'file' | 'folder';
  itemId: string;
  encryptedKey: string; // hex
}> | null;
```

The primary `encryptedKey` column uses `bytea` (binary). The inconsistency means child key ciphertext is stored in human-readable hex format, making it more visible in database dumps, backups, and query logs.

**Impact:** Low. The data is ECIES ciphertext and is useless without the ephemeral private key. The entity comment documents this as a deliberate trade-off for short-lived invites. This is consistent with Phase 14's `ShareKey.encryptedKey` which also uses `bytea`, while the invite's child keys use JSONB for convenience.

**Recommendation:** Accept as-is. For a future hardening pass, consider storing child keys as a separate table (like `ShareKey`) rather than JSONB, but this adds complexity for minimal gain on 7-day-TTL records.

---

### [LOW] L-04: InviteLinkTab Success Message Shows Partial URL

**Location:** `apps/web/src/components/file-browser/InviteLinkTab.tsx:97-101`

**Issue:**
The success message truncates the URL for display:

```typescript
const displayUrl = url.length > 60 ? `${url.slice(0, 30)}...${url.slice(-20)}` : url;
```

The last 20 characters would include the tail of the ephemeral private key hex. This is shown to the _sharer_ who already possesses the full URL, so there is no new information disclosure.

**Impact:** None -- the sharer already has the complete URL.

**Recommendation:** No change needed. For extra caution, could truncate only showing the token portion without any key material, but this is cosmetic.

---

### [INFO] I-01: Pre-Transaction Oracle Prevention Is Well-Designed

**Location:** `apps/api/src/shares/shares.service.ts:423-435`

**Positive finding:**
The `claimInvite` method includes pre-transaction checks before the atomic UPDATE:

```typescript
// Pre-transaction expiry / status check so expired/revoked invites
// return 404 instead of leaking through to the atomic UPDATE (which
// would throw 409 and signal that the token exists).
if (invite.expiresAt < new Date()) { ... throw new NotFoundException(); }
if (invite.status !== 'active') { ... throw new NotFoundException(); }
```

This elegantly prevents the token-existence oracle: without these checks, an expired/revoked invite would reach the atomic `UPDATE ... WHERE status = 'active'`, return `affected: 0`, and throw `ConflictException` (409) -- confirming the token exists. The pre-check maps all non-active states to 404, which is indistinguishable from a nonexistent token.

**Assessment:** Correctly implements the H-01 recommendation from the planning review. The comment documents the security rationale.

---

### [INFO] I-02: Memory Zeroing Applied Consistently

**Positive finding:**
All plaintext key material is zeroed in `finally` blocks across the implementation:

| Location                 | Material Zeroed               | Pattern                       |
| ------------------------ | ----------------------------- | ----------------------------- |
| `invite.service.ts:201`  | `ephemeralKeypair.privateKey` | `.fill(0)` in finally         |
| `invite.service.ts:156`  | `itemFolderKey`               | `.fill(0)` in finally         |
| `invite.service.ts:183`  | `fileKeyPlain`                | `.fill(0)` in finally         |
| `invite.service.ts:246`  | `plaintextKey`                | `.fill(0)` in finally         |
| `invite.service.ts:269`  | `plainChildKey`               | `.fill(0)` in finally         |
| `invite.service.ts:283`  | `ephemeralPrivKey` (claim)    | `.fill(0)` in finally         |
| `key-wrapping.ts:113`    | `folderKeyBytes`              | `.fill(0)` in finally         |
| `key-wrapping.ts:142`    | `plainKey`                    | `.fill(0)` in finally         |
| `InvitePage.tsx:133,152` | `ephemeralKeyRef`             | Set to `null` in then/finally |

**Known limitation:** Hex string representations of keys (`privateKeyHex`, `ephemeralPrivKeyHex`) are JavaScript strings and cannot be zeroed. This is a fundamental JS limitation documented in the planning review.

---

## Detailed File Analysis

### Backend: `invites.controller.ts`

**Crypto operations:** None (controller delegates to service).

**Security controls verified:**

- Public status endpoint: ThrottlerGuard only, returns `active`/404 -- **correct**
- Data endpoint: JwtAuthGuard + ThrottlerGuard -- **correct**
- Claim endpoint: JwtAuthGuard + ThrottlerGuard, POST verb -- **correct**
- No internal fields leak in responses (encryptedKey, sharerId not returned from status) -- **correct**

---

### Backend: `share-invites.controller.ts`

**Security controls verified:**

- Class-level JwtAuthGuard + ThrottlerGuard -- **correct**
- Create returns token (not encrypted key material) -- **correct**
- List filters by `sharerId` from JWT (no IDOR) -- **correct**
- Revoke uses ParseUUIDPipe for inviteId -- **correct**
- Response mapping strips internal fields (test at line 90-104 confirms) -- **correct**

---

### Backend: `shares.service.ts` (Phase 15 methods)

**Crypto operations:** Token generation (`randomBytes(16)`).

**Security controls verified:**

- `createInvite`: 128-bit random token via `crypto.randomBytes` -- **correct**
- `getInviteStatus`: Auto-expires and hard-deletes past TTL -- **correct**
- `getInviteForClaim`: Returns null for non-active invites -- **correct**
- `claimInvite`: Atomic UPDATE with `status = 'active'`, `claim_count < max_claims`, `expires_at > NOW()` -- **correct**
- `claimInvite`: Self-claim prevention (`invite.sharerId === claimerId`) -- **correct**
- `claimInvite`: Transaction wraps claim + Share creation (rollback on failure) -- **correct**
- `claimInvite`: Pre-transaction oracle prevention -- **correct** (see I-01)
- `revokeInvite`: Authorization check (`invite.sharerId !== sharerId`) -- **correct**
- `getInvitesForItem`: Scoped by sharerId + ipnsName, auto-cleans expired -- **correct**

---

### Frontend: `invite.service.ts`

**Crypto operations:**

1. `generateEphemeralKeypair()`: secp256k1 keypair via `@noble/secp256k1`
2. `wrapKey()`: ECIES encrypt via `@cipherbox/crypto`
3. `unwrapKey()`: ECIES decrypt via `@cipherbox/crypto`
4. `buildInviteUrl()`: Ephemeral private key in URL fragment

**Security controls verified:**

- Ephemeral keypair uses `secp256k1.keygen()` (CSPRNG internally) -- **correct**
- Uncompressed public key (65 bytes) for ECIES compatibility -- **correct**
- All plaintext keys zeroed in finally blocks -- **correct** (see I-02)
- URL construction puts key in hash fragment (never sent to server) -- **correct**
- Claim flow: unwrap with ephemeral, re-wrap with recipient's own pubkey -- **correct**
- Claim flow: uses authenticated endpoints (`invitesControllerGetInviteData`, `invitesControllerClaimInvite`) -- **correct**

---

### Frontend: `InvitePage.tsx`

**Crypto operations:** None directly (delegates to invite.service.ts).

**Security controls verified:**

- Ephemeral key stored in `useRef` (not state) -- **correct**
- URL fragment cleared on mount via `navigate(replace: true)` -- **correct**
- Ephemeral key ref set to null after claim (both success and error paths) -- **correct**
- No ephemeral key in error messages or logs -- **correct**
- Double-claim prevention via `claimingRef` guard -- **correct**
- Error codes mapped to user-friendly messages without leaking internals -- **correct**

---

### Frontend: `InviteLinkTab.tsx`

**Security controls verified:**

- Clipboard API used in secure context -- **correct**
- Clipboard failure handled gracefully (shows URL in message for sharer) -- **correct**
- No ephemeral key stored after creation (URL auto-copied, then forgotten) -- **correct**

---

### Frontend: `key-wrapping.ts`

**Crypto operations:**

1. `reWrapEncryptedKey()`: unwrap (ECIES) + re-wrap (ECIES)
2. `collectChildKeys()`: recursive traversal + re-wrapping

**Security controls verified:**

- All plaintext keys zeroed in finally blocks -- **correct**
- Recursive subfolder key zeroed after use (line 113) -- **correct**
- Error in one child doesn't abort others (try/catch per child) -- **correct**
- Error logging does NOT include key material -- **correct**

---

### DTOs: `create-invite.dto.ts`, `claim-invite.dto.ts`

**Input validation verified:**

- `encryptedKey`: hex regex, min 258 chars, max 2048 -- **correct** (ECIES ciphertext for 32-byte key is ~130 bytes = 260 hex chars)
- `itemType`: enum validation `['folder', 'file']` -- **correct**
- `ipnsName`: string, 1-255 chars -- **correct**
- `itemName`: string, 1-255 chars -- **correct**
- `childKeys`: array of validated nested DTOs -- **correct**
- `itemId` in child keys: UUID format validation -- **correct**

---

### Migration: `1740400000000-AddShareInvites.ts`

**Schema verified:**

- `IF NOT EXISTS` for idempotency -- **correct**
- `token` unique constraint -- **correct**
- `sharer_id` FK with CASCADE on delete -- **correct**
- `claimed_by` FK with SET NULL on delete -- **correct**
- Indexes on `sharer_id` and `expires_at` -- **correct**
- `encrypted_key` as `bytea` -- **correct**

---

### Tests: Coverage Assessment

**Unit tests (invites.controller.spec.ts):**

- Status endpoint: active, null, claimed, revoked states -- **covered**
- Data endpoint: success, not found, null children -- **covered**
- Claim: delegation, exception passthrough -- **covered**

**Unit tests (share-invites.controller.spec.ts):**

- Create: response mapping, field stripping -- **covered**
- List: multiple results, empty, field stripping -- **covered**
- Revoke: delegation, exception passthrough -- **covered**

**Unit tests (shares.service.spec.ts):**

- createInvite: save, buffer conversion, child keys, null children -- **covered**
- getInviteStatus: active, null, auto-expire, claimed-no-expire -- **covered**
- getInviteForClaim: active, null, expired, claimed, revoked -- **covered**
- claimInvite: success, self-claim, not-found, expired, claimed, revoked, atomic failure, existing share -- **covered**
- getInvitesForItem: active, auto-clean, empty, no-remove -- **covered**
- revokeInvite: success, not-found, forbidden -- **covered**

**E2E tests (invite-link-workflow.spec.ts):**

- Full lifecycle: create, claim, verify shared content -- **covered**
- Tab UI, folder sharing, revocation, error states -- **covered**
- Self-claim prevention -- **covered**
- Already-claimed error -- **covered**

**Missing test coverage (recommendations):**

1. **Concurrent double-claim race**: E2E test for `Promise.all([claim1, claim2])` verifying only one succeeds
2. **Expired invite claim**: Unit test with a mocked expired invite reaching the claim endpoint
3. **URL fragment not in server logs**: Integration test verifying the token endpoint receives no `key` parameter
4. **ECIES round-trip with actual crypto**: Integration test using real `@cipherbox/crypto` wrapKey/unwrapKey (current tests mock the crypto layer)

---

## Compliance Checklist

Based on project security rules (CLAUDE.md):

- [x] No privateKey in localStorage/sessionStorage (ephemeral key in useRef only)
- [x] No sensitive keys logged (no console.log of key material anywhere in Phase 15 code)
- [x] No unencrypted keys sent to server (ephemeral private key in URL fragment only)
- [x] ECIES used for key wrapping (via `@cipherbox/crypto` wrapKey/unwrapKey)
- [x] AES-256-GCM used for content encryption (via ECIES internal construction)
- [x] Server has zero knowledge of plaintext keys (stores only ECIES ciphertext)
- [x] Binary data uses Uint8Array (all crypto operations use Uint8Array)
- [x] Key material cleared after use (`.fill(0)` in finally blocks)

---

## Recommendations Summary

| Priority | Recommendation                                                    | Effort  | Finding  |
| -------- | ----------------------------------------------------------------- | ------- | -------- |
| P1       | Add `<meta name="referrer" content="no-referrer">` to index.html  | Trivial | M-01     |
| P1       | Fix InviteStatusResponseDto swagger enum to `['active']` only     | Trivial | M-02     |
| P2       | Add token format validation pipe to invite endpoints              | Low     | L-02     |
| P2       | Simplify checkInviteStatus return type to `'active' \| 'expired'` | Low     | L-01     |
| P3       | Add concurrent double-claim E2E test                              | Medium  | Test gap |
| P3       | Add ECIES round-trip integration test                             | Medium  | Test gap |

---

## SECURITY REVIEW COMPLETE

**Files analyzed:** 22 (18 implementation + 4 test files)
**Crypto operations catalogued:** 8 (matching planning review)
**Planning review findings addressed:** 7/8 (M-01 referrer policy not implemented)
**New issues found:** 8 (0 Critical, 0 High, 2 Medium, 4 Low, 2 Info)

### Conclusion

The implementation is **security-sound** and ready for merge. All HIGH-severity findings from the architectural review were addressed. The remaining findings are hardening recommendations (referrer policy, swagger accuracy) with no exploitable vulnerabilities. The cryptographic flow is correctly implemented with proper key zeroing, authenticated endpoints, atomic single-claim, and oracle prevention.

---

_Generated by security:review command_
_Prior review: `.planning/security/REVIEW-phase15-link-sharing.md`_
_This review is automated guidance, not a substitute for professional security audit_
