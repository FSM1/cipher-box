---
phase: 61-aad-bound-seal-primitive-and-cross-language-kat
audit_type: retroactive-threat-verification
asvs_level: 2
block_on: high
threats_total: 15
threats_closed: 15
threats_open: 0
verdict: SECURED
audited: 2026-06-28
---

# Phase 61 Security Audit — AAD-Bound Seal Primitive and Cross-Language KAT

Retroactive verification that every declared `T-61-*` threat mitigation across the five
plan threat models is PRESENT in the implemented code. Implementation files were treated
as read-only; only this report was written.

Verification depth: ASVS L2 (mitigation addresses the threat vector at the correct trust
boundary), with L3-style end-to-end data-flow tracing applied to the transplant/AEAD-AAD
threats (AAD construction -> `additionalData`/`Payload` -> GCM tag coverage -> unseal
rejection). Severity gate `block_on: high` (default): only open high/critical threats block.

## Verdict: SECURED

All 15 threats resolve to CLOSED. 13 `mitigate` threats are verified present in code with
file:line evidence; 2 `accept` threats (T-61-SC, T-61-15) are recorded in the Accepted
Risks Log below. `threats_open = 0`. No new attack surface went unmapped (all five
SUMMARY `## Threat Flags` sections report "None"). Two LOW hardening items from the prior
adversarial review are already tracked as a follow-up todo and are non-blocking.

## Threat Verification

| Threat ID | Category | Severity | Disposition | Status | Evidence |
|-----------|----------|----------|-------------|--------|----------|
| T-61-01 | Tampering | high | mitigate | CLOSED | `packages/crypto/src/utils/encoding.ts:58-64` — `uuidToBytes` strips hyphens, asserts 32 hex chars then `hexToBytes` (hex-field parse, never TextEncoder) -> 16 raw bytes. KAT `build-node-aad.test.ts:26-49` asserts exact 16-byte value. |
| T-61-02 | Tampering | high | mitigate | CLOSED | `packages/crypto/src/aes/seal.ts:86-112` — fail-closed throws on bad kind/role/generation, `uuidToBytes` throws on bad UUID; fixed 45-byte concat. Tests `build-node-aad.test.ts:54-57` (45 bytes) + `:107-162` (all D-03 cases, `INVALID_AAD_INPUT`). |
| T-61-03 | Tampering | medium | mitigate | CLOSED | `packages/crypto/src/aes/seal.ts:101-102` — `DataView.setUint32(0, generation, false)` (big-endian). Vector `node-aad.json` uses non-zero `generation=42` so BE/LE diverge; test `:84-87`,`:96-104`. |
| T-61-04 | Information Disclosure | medium | mitigate | CLOSED | Primitives live in named files `seal.ts`/`encoding.ts`; barrels `packages/crypto/src/aes/index.ts:8-10` and `src/index.ts:53-65,85-89` only re-export (vitest coverage excludes `src/**/index.ts`). |
| T-61-05 | Tampering | high | mitigate | CLOSED | `crates/crypto/src/aes.rs:172-173` — `Uuid::parse_str(node_id)?.as_bytes()` (16 raw RFC-4122 bytes, never `to_string()`). Cross-language KAT `cross_language.rs:289-298` pins exact bytes vs committed TS ground truth. |
| T-61-06 | Tampering | high | mitigate | CLOSED | `crates/crypto/src/aes.rs:166-171` — fail-closed `Err(InvalidAadInput)` on out-of-range kind/role and malformed UUID; 45-byte assertion `aes.rs:276`; unit tests `aes.rs:321-365`. |
| T-61-SC | Tampering (supply chain) | low | accept | CLOSED | `uuid` dep present: root `Cargo.toml:25`, `crates/crypto/Cargo.toml:18`. Pre-approved in RESEARCH Package Legitimacy Audit (crates.io, ~12y, 11.1M/wk). Recorded in Accepted Risks Log. KAT catches any behavioral mismatch. |
| T-61-07 | Tampering | high | mitigate | CLOSED | GCM tag binds AAD via `decrypt.ts:126` (`additionalData`). Transplant suite `build-node-aad.test.ts:359-465` proves unseal REJECTS wrong nodeId/role/generation/kind/forged-domain; correct-AAD unseal still succeeds (`:366-373`). |
| T-61-08 | Tampering | high | mitigate | CLOSED | `packages/crypto/src/aes/seal.ts:176-178` — `unsealAesGcmAad` rejects `sealed.length < MIN_SEALED_SIZE` (28) before decrypt. Tests `:229-234` (sub-28) + `:467-483` (tamper + truncate). |
| T-61-09 | Tampering | high | mitigate | CLOSED | `packages/crypto/src/aes/seal.ts:132-150` — `sealAesGcmAad` has no IV param; mints `generateIv()` at `:143`. Fresh-IV proven `build-node-aad.test.ts:213-225` (two seals differ). |
| T-61-10 | Tampering | high | mitigate | CLOSED | `packages/crypto/src/aes/encrypt.ts:116-120` — AAD threaded via `AesGcmParams.additionalData`. Full-seal KAT `build-node-aad.test.ts:323-353` pins exact ciphertext, which only matches if AAD enters the AEAD. |
| T-61-11 | Tampering | high | mitigate | CLOSED | `seal_vectors` in `node-aad.json`; `cross_language.rs:304-336` asserts Rust `encrypt_aes_gcm_aad` reproduces the committed ciphertext byte-for-byte; TS asserts the same hex (`:342-351`). Both sides pinned to one fixed key/iv/plaintext/AAD vector. |
| T-61-12 | Tampering | high | mitigate | CLOSED | `crates/crypto/src/aes.rs:140-149` — `unseal_aes_gcm_aad` `MIN_SEALED_SIZE` guard + `Payload{msg,aad}` decrypt. Unit tests `aes.rs:426-449` (transplant Err + truncated Err). |
| T-61-13 | Tampering | high | mitigate | CLOSED | `crates/crypto/src/aes.rs:128-135` — `seal_aes_gcm_aad` has no IV param; mints `generate_iv()` at `:129`. Fresh-IV proven `aes.rs:414-424` (two seals differ). |
| T-61-14 | Tampering | medium | mitigate | CLOSED | `docs/adr/0003-aad-bound-node-seal-encoding.md` (status: accepted) freezes byte layout/role table/AEAD params + "every new role byte must extend the KAT" + node-seal/v2 version lever. Pointers present in `METADATA_SCHEMAS.md`, `METADATA_EVOLUTION_PROTOCOL.md`, `FILESYSTEM_SPECIFICATION.md`. |
| T-61-15 | Repudiation | low | accept | CLOSED | ADR 0003 is scoped to the encoding/encryption layer only; no unified-Node-schema text added (deferred to phase 62). Recorded in Accepted Risks Log. |

## Accepted Risks Log

| Threat ID | Severity | Rationale | Reference |
|-----------|----------|-----------|-----------|
| T-61-SC | low | New `uuid` workspace crate is a build-time supply-chain dependency. Pre-approved in the phase RESEARCH Package Legitimacy Audit (official `github.com/uuid-rs/uuid`, ~12 years, ~11.1M downloads/week, crates.io). The cross-language KAT mechanically catches any behavioral divergence in the parse path. No human checkpoint required. | `61-02-PLAN.md` threat model; `Cargo.toml:25` |
| T-61-15 | low | Documenting the unified `Node` schema in phase 61 would be premature scope creep (the schema does not yet exist). D-05 scopes phase-61 docs to the encryption/encoding layer; the `Node` schema rewrite is assigned to phase 62 (ROADMAP SC#6). ADR 0003 contains no Node-schema text — verified. | `61-05-PLAN.md` threat model; `61-CONTEXT.md` D-05 |

## Unregistered Flags

None. All five plan SUMMARY `## Threat Flags` sections (`61-01`..`61-05`) report "None" —
no new attack surface emerged during implementation that lacks a threat mapping.

## Tracked Follow-Ups (non-blocking, below high threshold)

Two LOW fail-closed hardening items surfaced by the prior independent adversarial review
(verdict SHIP, 0 BLOCKER/HIGH/MEDIUM) are already captured and do NOT block ship:

- **LOW-1 — TS/Rust UUID acceptance-domain divergence.** `uuidToBytes` (TS) and
  `Uuid::parse_str` (Rust) accept slightly different sets of UUID string forms. Not
  exploitable and not a silent-decryption path: any divergent input is rejected by the
  stricter side, and the canonical pipeline (`crypto.randomUUID()` / `generate_uuid_v4`,
  always lowercase-hyphenated) never produces a divergent form.
- **LOW-2 — CryptoError-type contract nit** at the same UUID-parsing boundary. Fail-closed
  and unreachable by the canonical pipeline.

Tracked at `.planning/todos/pending/2026-06-28-harden-uuid-acceptance-parity-aad-builder.md`.

## Additional Defense-in-Depth Observations (not declared threats)

- **No oracle leakage:** all four AEAD functions catch and re-throw a generic
  `'Decryption failed' / 'Encryption failed'` (`encrypt.ts:61-64`, `decrypt.ts:66-70,132-136`);
  Rust returns opaque `AesDecryptionFailed`. No plaintext is returned on auth failure.
- **No key/plaintext logging:** grep across `seal.ts`/`encrypt.ts`/`decrypt.ts`/`encoding.ts`
  and `aes.rs` found no `console.*`/`println!`/`dbg!` in the new code.
- **Constant-time tag comparison** is delegated to Web Crypto (`crypto.subtle.decrypt`) and
  the `aes-gcm` crate — neither implementation hand-rolls tag comparison.

## Notes

- Test status per execution: 196 TS tests, 91 Rust lib + 6 cross-language tests green, vector
  parity passing (not re-run here per the static-analysis constraint; mitigations verified by
  source inspection and committed-vector inspection).
- The pre-existing repo-root `SECURITY.md` (security policy, dated 2026-06-14) was left
  untouched. This phase report is the phase-scoped audit artifact.
