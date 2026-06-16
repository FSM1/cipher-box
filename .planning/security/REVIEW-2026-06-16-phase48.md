# Security Review Report

**Date:** 2026-06-16
**Scope:** Phase 48 — SDK self-bootstrap regression fix + shared-folder consolidation (REQ-1..4), focused on the crypto/security surface (REQ-4 itemName at-rest encryption, REQ-3 shared-folder key handling). Diff base `2657740f1`.
**Reviewer:** Claude (security:review) — two parallel `security-reviewer` agents.

## Executive Summary

Phase 48 upholds CipherBox's zero-knowledge model. The server only ever stores and echoes client-produced ECIES ciphertext for `itemName` and never sees plaintext or unencrypted keys on any new code path. Cryptography is correct (same audited ECIES primitive as `encryptedKey`, fresh ephemeral key per call, authenticated AES-256-GCM, transient key material zeroed). Shared-folder key-zeroing and cross-share isolation invariants hold; the new standalone-file-share seed has no double-free / use-after-zero.

**Risk Level: LOW.** One MEDIUM availability finding was fixed in this pass; remaining items are LOW/defense-in-depth or already-tracked transitional state.

## Files Reviewed

| File | Crypto Operations | Risk |
|------|-------------------|------|
| `apps/web/src/services/share.service.ts` | ECIES wrap/unwrap of itemName, received-share decrypt, backfill | LOW |
| `apps/web/src/services/invite.service.ts` | ephemeral-key wrap on create, re-wrap to recipient on claim | LOW |
| `apps/web/src/components/file-browser/ShareDialog.tsx` | itemName wrap for direct shares | LOW |
| `apps/api/src/shares/{shares,share-invite}.service.ts` + DTOs + entities + migration | ciphertext verbatim store; no server-side crypto | LOW |
| `packages/crypto/src/ecies/*` | wrapKey/unwrapKey (ECDH + HKDF + AES-256-GCM) | LOW |
| `packages/sdk/src/state/shared-folder-tree.ts` | per-share key storage, clone-on-set, zero-on-delete | LOW |
| `packages/sdk/src/client.ts` (shared methods) | shared write context, IPNS key copy-on-read | LOW |
| `packages/sdk/src/share/shared-write.ts` | file IPNS key handling, ephemeral key zeroing | LOW |
| `apps/web/src/hooks/useSharedNavigationActions.ts` | per-depth key unwrap + zeroing, file-share seed | LOW |

## Findings

### Critical / High

None.

### Medium

1. **One bad `itemNameEncrypted` row denied the entire received-shares list — FIXED**
   - **Location:** `apps/web/src/services/share.service.ts` `fetchReceivedShares` (the `Promise.all` decrypt).
   - **Description:** `decryptItemName` throws on a corrupt / wrong-key / truncated ciphertext row; inside `Promise.all` a single rejection failed the whole page, so the recipient's entire shared-with-me list would fail to load. Availability only — no confidentiality impact.
   - **Fix applied:** per-row `try/catch` degrading just that row to its legacy plaintext `itemName` fallback (generic warning logged with `shareId` only; never the ciphertext or key).

### Low / Recommendations (not changed — rationale noted)

1. **`SharedFolderTree.set()` orphans the previous entry's key buffers without zeroing on re-seed/adopt** (`packages/sdk/src/state/shared-folder-tree.ts`). Defense-in-depth memory residue; requires local heap disclosure to exploit. **Matches the pre-existing owned-path `FolderTree.set()` convention** — changing only the shared path would be inconsistent. Deferred (codebase-wide convention decision).
2. **`getAll()` / `getSharedFolderState()` expose live internal key buffers by reference.** Latent footgun; no current consumer in the changed web code abuses it (web relies on the projection event). Documented contract; deferred.
3. **Lazy backfill (`backfillSentShareItemNames`) is a structural no-op** — no `PATCH /shares/:id { itemNameEncrypted }` endpoint exists, so legacy/pre-deploy share + invite display names remain plaintext at rest on the server. At-rest encryption is **forward-only, not retroactive**. Already tracked (T-48-18 accept; captured todo for the API endpoint). The `backfilled` counter is misleading (counts eligible, not converted) — minor.
4. **No cross-field validation** that a create DTO carries either a non-empty `itemName` or a well-formed `itemNameEncrypted`. Data-integrity/UX only; a nameless row is possible. Deferred (legacy clients still send plaintext during rollout).

## Compliance Checklist

- [x] No `privateKey` in localStorage/sessionStorage (share store is in-memory only; confirmed no persist config)
- [x] No sensitive keys logged (all changed log sites emit `Error`/static strings/`shareId` only)
- [x] No unencrypted keys sent to server (itemName wrapped client-side; plaintext field sent as `''`)
- [x] ECIES used for key wrapping (itemName uses the same `wrapKey`/`unwrapKey` as `encryptedKey`)
- [x] AES-256-GCM for content (unchanged); ECIES = ECDH + HKDF + AES-256-GCM authenticated
- [x] Server zero-knowledge for itemName (stores ciphertext `bytea` verbatim; never encrypts/decrypts/derives)
- [x] No plaintext itemName in invite URL fragment (fragment carries only the ephemeral private key)
- [x] Transient unwrapped bytes zeroed (`decryptItemName` finally `fill(0)`; `claimInvite` `plainName.fill(0)`)
- [x] Shared-folder key-zeroing on failure/teardown/revocation paths; cross-share isolation enforced

## Test Cases (suggested follow-ups)

- `fetchReceivedShares`: one row with a malformed `itemNameEncrypted` among valid rows → list still loads, bad row shows plaintext fallback (service-level test; requires `sharesControllerGetReceivedShares` mock). Behavior of the underlying throw is already covered by `share-item-name.test.ts` (wrong-key/tamper/truncate).
- API integration: `POST /shares/invites` and claim with `itemNameEncrypted` persist ciphertext verbatim (now covered by `share-invite.service.spec.ts`, added in validation pass).

## Recommendations Summary

| Priority | Recommendation | Effort |
|----------|----------------|--------|
| P1 (done) | Per-row decrypt guard in `fetchReceivedShares` | LOW |
| P2 | Add `PATCH /shares/:id { itemNameEncrypted }` + wire backfill persist (retroactive at-rest encryption) | MEDIUM |
| P3 | Zero previous key buffers in `SharedFolderTree.set()` and owned `FolderTree.set()` (codebase-wide) | LOW |
| P3 | Cross-field DTO validation (itemName OR itemNameEncrypted present) | LOW |

---
*Generated by security:review. Automated guidance, not a substitute for professional audit.*
