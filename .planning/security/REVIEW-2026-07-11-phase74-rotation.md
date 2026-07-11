# Security Review Report

**Date:** 2026-07-11
**Scope:** GSD Phase 74 "Rust and FUSE Rotation-Revocation Soundness" — rotation/crypto diff (`origin/main...HEAD`)
**Reviewer:** Claude (crypto-privacy-review) + crypto-privacy-reviewer agent

## Executive Summary

The core crypto of Phase 74 is sound. The D-09 terminal-owner zeroization
boundaries, the revocation invariant (revoked → delete, retained → re-wrap
under the NEW key), and the deep-intermediate-inode key refresh (the exact
revocation-bypass class this phase closes) are all implemented correctly. No
CRITICAL or HIGH defects were introduced. Findings are one MEDIUM inherited
trust-boundary (newly reachable on desktop) and several LOW doc/fragility/parity
items.

**Risk Level:** LOW (with one documented MEDIUM inherited trust boundary)

## Files Reviewed

| File | Crypto Operations | Risk Level |
|------|-------------------|------------|
| crates/sdk/src/rotation/engine.rs | per-node read-key map surfacing, re-mint ECIES wrap | LOW |
| packages/sdk-core/src/rotation/engine.ts | TS parity engine, re-mint wrap | LOW (1 fragility) |
| crates/fuse/src/write_ops/grant_scope.rs | intermediate inode key refresh | LOW (clean) |
| crates/fuse/src/write_ops/rotation_deps.rs | grant query, recipient pubkey hex parse, re-mint seam | MEDIUM (trust boundary) |
| crates/api-client/src/shares.rs | update_grant / delete_grant wire DTO | LOW (doc) |
| crates/api-client/src/client.rs | PATCH/DELETE auth injection | LOW (clean) |
| crates/fuse/src/platform/windows/write_ops.rs | WinFsp dest scope-exit gate | LOW (clean) |

## Findings

### Critical Issues
None.

### High Priority
None.

### Medium Priority

1. **Re-mint trusts the untrusted server for recipient public-key binding**
   - **Location:** `crates/fuse/src/write_ops/rotation_deps.rs` `query_grants_rooted_at` (~:265-285) → `crates/sdk/src/rotation/engine.rs:610` `wrap_key(new_read_key, &grant.recipient_public_key)`
   - **Description:** On scope-exit rotation the owner re-wraps the NEW read key under `recipient_public_key` returned by `GET /shares/sent` — an untrusted, zero-knowledge server. A server that substitutes an attacker pubkey causes the owner to wrap the fresh read key TO THE ATTACKER.
   - **Impact:** Confidentiality break of the rotated read scope against a malicious server.
   - **Scope:** INHERITED (grant issuance + TS owner-reconcile already trust the server for recipient identity); Phase 74 makes it reachable on desktop/FUSE for the first time. Flagged as trust-boundary, not a new defect.
   - **Disposition:** LOGGED as todo `2026-07-11-remint-trusts-server-recipient-pubkey-binding.md`.

### Low Priority / Recommendations

2. **Misleading encoding in `update_grant` doc-comment** — `shares.rs:93` said "ECIES ciphertext hex"; actual encoding is base64 (`engine.rs:617` `base64_encode`, TS `engine.ts:614` `bytesToBase64`). **FIXED** in this review (doc comment corrected to base64).

3. **TS `rotatedNodes` stores readKey by reference, not a defensive copy** — `engine.ts:2064/2235` store the same `Uint8Array` also aliased into `parentNewReadKey`. Currently SAFE (parentNewReadKey never zeroed) but a future D-09 tightening that zeroes it would zero the returned map entry → all-zeros inode key → data loss. **LOGGED** as todo `2026-07-11-ts-rotatednodes-defensive-copy-parity.md`.

4. **`query_grants_rooted_at` hex-decodes recipient key with no shape validation before `wrap_key`** — validation happens later in `wrap_key`; a malformed key fails the whole rotation closed (fail-safe, coarse). **DISCARDED** (already fail-closed; input is public; non-material).

5. **Repaired dirty-node generation/sequence surfaced may diverge Rust↔TS (uncertain)** — **DISCARDED** after verification: the ONLY consumer of `rotated_nodes` is `grant_scope.rs::refresh_rotated_inode_read_keys`, which reads `read_key` + `ipns_name` only, never `generation`/`sequence_number`. No seal/AAD path consumes the surfaced generation, so the divergence has no security impact.

6. **Test fixture comments 33-byte "0x04 + 32-byte" recipient key** (compressed length is 33, uncompressed 0x04 is 65) — **DISCARDED** (test-hygiene nit; stub never reaches `wrap_key`).

## Positive Observations (verified)

- **D-09 terminal-owner boundary correct on all three surfacing paths.** Rust clones keys into self-zeroing `Zeroizing<[u8;32]>` map entries; FUSE refresh overwrites each inode's own `Zeroizing` buffer in place and does not zero `result.rotated_nodes`; engine zeroes only its temporaries.
- **Deep stale-key class genuinely closed.** `refresh_rotated_inode_read_keys` iterates ALL `rotated_nodes` (Root/Folder/File) by `ipns_name` with no early return, before any post-rotation relink can reseal under a stale intermediate key.
- **Revocation invariant upheld.** Revoked → `delete_grant` (never re-minted); retained → re-wrap under the NEW read key + new generation. FUSE source sets `is_revoked: false` (revoked shares hard-deleted server-side, absent from `/shares/sent`).
- **ECIES only, fresh ephemeral per wrap** via `cipherbox_crypto::wrap_key`; no hand-rolled wrapping; no IV/nonce reuse introduced; `wrap_key` validates 65-byte/`0x04` and fails closed.
- **Wire DTO leaks nothing.** `UpdateGrantRequest` serializes only `encryptedReadKey` (base64 ECIES) + `rootGeneration`; write-key fields intentionally omitted (asserted absent by a wire test).
- **RotatedNodeKey shape parity locked** field-for-field (u64→bigint convention respected).
- **No key logging** anywhere (only ipns_name/child_id/share_id public identifiers).
- **`collect_sent_shares` fully paginates**, so re-mint cannot miss retained recipients beyond page 1.

## Compliance Checklist

- [x] No privateKey in localStorage/sessionStorage (n/a — Rust/FUSE + SDK engine)
- [x] No sensitive keys logged
- [x] No unencrypted keys sent to server
- [x] ECIES used for key wrapping (`wrap_key`)
- [x] AES-256-GCM used for content encryption (unchanged; rotation reseals under it)
- [x] Server has zero knowledge of plaintext (one MEDIUM trust-boundary on recipient-identity binding — logged)
- [x] IPNS keys encrypted with TEE public key (unchanged by this phase)

## High-Value Test Cases (recommended)

1. Zeroization-corruption regression (TS): assert every `rotatedNodes` readKey is non-zero and equals the expected new key after `rotateReadFromNode`.
2. Retained-recipient re-wrap decryptability: unwrap the emitted `encryptedReadKey` with recipient private key and assert it equals the NEW post-rotation read key.
3. Revoked-recipient never re-minted: `is_revoked: true` → one `delete_grant`, zero `update_grant`.
4. Recipient-key substitution (malicious server): document/assert current behavior to make the MEDIUM trust boundary explicit.
5. Malformed/compressed recipient key must fail closed (no partial re-mint).
6. Deep-tree stale-intermediate integration: assert a subsequent relink of the intermediate reseals under the NEW key.
7. Multi-page `collect_sent_shares`: >50 retained recipients across pages all re-minted.
8. Rust↔TS parity fixture: identical deep tree; assert key-sets and read-key bytes match.

## Recommendations Summary

| Priority | Recommendation | Disposition |
|----------|----------------|-------------|
| P1 | Pin/verify recipient pubkey on re-mint, or document server-trust as accepted risk | todo logged |
| P2 | TS defensive copy of readKey into rotatedNodes (Rust parity) | todo logged |
| P3 | Fix update_grant doc "hex" → "base64" | fixed in review |

---
*Generated by crypto-privacy-review command*
*This review is automated guidance, not a substitute for professional security audit*
